/*
 * app-split: per-application split tunnelling enforcement for winws2.
 *
 * Design (see SPLIT-PLAN-DRAFT.md sections 2-3 in zapret2-gui):
 *
 * - The hook lives in win_main(), not in processPacketData(): only
 *   win_main() knows the packet direction (WINDIVERT_ADDRESS.Outbound).
 *   A DIRECT decision becomes VERDICT_PASS there, i.e. the existing
 *   "reinject unmodified" path. No desync, no Lua, no new send path.
 * - Attribution source of truth: the Windows socket tables.
 *   TCP: GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL) matched on the
 *   full 5-tuple. UDP: GetExtendedUdpTable(UDP_TABLE_OWNER_PID)
 *   matched on the local address/port only, because the UDP owner
 *   table has no remote-endpoint columns. Exact and wildcard
 *   matches attribute only for a single distinct PID: under
 *   SO_REUSEADDR several processes may share one local
 *   address + port, and that case is a miss, not a first-row guess.
 * - Attribution happens only on the first outbound packet of a flow.
 *   Inbound packets inherit the cached decision. An inbound packet
 *   with no cached flow is processed ordinarily (never attributed:
 *   unsolicited inbound traffic has no local socket to attribute).
 * - PID -> exe path via QueryFullProcessImageNameW, compared against
 *   a hash set of normalised paths, never by linear scan.
 * - Flow cache key: canonical 5-tuple (local endpoint, remote
 *   endpoint, protocol), direction-independent, so both directions
 *   of one flow hit the same entry. Value: decision, PID and the
 *   process creation time (GetProcessTimes) against PID reuse.
 *   Revalidation is NOT done on every packet: that would defeat the
 *   cache. A cached entry is revalidated at most once per
 *   APP_SPLIT_REVALIDATE_MS; a mismatch drops the entry and the
 *   next packet re-attributes. This bounds the PID-reuse window for
 *   long-lived flows instead of eliminating it, which is documented
 *   here rather than claimed away.
 * - TCP entries die on FIN/RST (either direction) or after
 *   APP_SPLIT_TCP_IDLE_MS of inactivity. UDP entries die after
 *   APP_SPLIT_UDP_TTL_MS of inactivity, refreshed by any packet.
 *   Negative entries ("not resolved") live APP_SPLIT_NEG_MS so the
 *   next packet of the flow retries attribution.
 * - The socket tables are re-read at most once per
 *   APP_SPLIT_TABLE_MIN_MS, no matter how many flows miss. Re-reading
 *   the table per packet is explicitly not done.
 * - Miss policy is the mode default, not a global fail-open/closed:
 *   allowlist miss -> DIRECT, blocklist miss -> BYPASS.
 * - Exclusions, applied before any attribution or list match:
 *   loopback (127.0.0.0/8 either endpoint) -> BYPASS, no attribution;
 *   IPv6 -> BYPASS (out of MVP scope); exclude-pid -> BYPASS.
 *   Non-TCP/UDP -> BYPASS. Subsequent IP fragments (fragment offset
 *   != 0, no transport header to parse) -> BYPASS before any cache
 *   lookup, so they do NOT inherit a cached DIRECT decision; only
 *   the first fragment (offset 0) is attributed and cached.
 * - Limits of the exclusions and of attribution (no behaviour change,
 *   documented so the defaults are not misread as guarantees):
 *   (a) tgproxy exclusion (--app-split-exclude-pid) applies only
 *   after successful attribution: the PID is compared only for an
 *   attributed flow. In a miss window (socket table has no row yet,
 *   PID lookup failed, negative cache entry) the flow gets the mode
 *   default, not BYPASS, even if the traffic is the supervisor's.
 *   (b) Protected processes: if OpenProcess or
 *   QueryFullProcessImageNameW refuses the process, attribution
 *   fails and the flow gets the mode default, not a list decision.
 *   (c) UWP apps run under a host exe, so the resolved path is the
 *   host's, not the app's: the list lookup misses and the flow gets
 *   the mode default (same outcome as an unattributed flow in the
 *   same mode), even if the UWP app itself was meant to be listed.
 * - Logging is stderr only, counters only: a startup line and a
 *   periodic aggregate report. Process paths and user PIDs are
 *   never printed.
 * - Single-threaded: win_main() is the only caller. No locks.
 *
 * Non-Cygwin builds compile this file to no-op stubs so that the
 * Makefile's "*.c" source list keeps working on Linux/BSD/Android.
 */

/*
 * The Windows headers MUST come before any Cygwin libc header here.
 * stdio.h pulls in sys/select.h, which declares POSIX select(); the
 * winsock2.h declaration of select() (const TIMEVAL) conflicts with it
 * and the old (2022-snapshot) x86 Cygwin toolchain rejects the TU with
 * "conflicting types for 'select'" (build-split run 40697928245).
 * Same pattern as win.c, which includes <windows.h> first.
 */
#ifdef __CYGWIN__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "appsplit.h"

#define APP_SPLIT_MAX_PATHS	100
#define APP_SPLIT_PATH_SLOTS	256	/* > 2x max entries: low load */
#define APP_SPLIT_PATH_MAX	4096	/* normalised bytes, incl. NUL */
#define APP_SPLIT_FLOW_SLOTS	8192
#define APP_SPLIT_UDP_TTL_MS	45000	/* within the planned 30-60 s */
#define APP_SPLIT_TCP_IDLE_MS	3600000	/* safety net; FIN/RST kills first */
#define APP_SPLIT_NEG_MS	1500	/* within the planned 1-2 s */
#define APP_SPLIT_TABLE_MIN_MS	100
#define APP_SPLIT_REVALIDATE_MS	10000
#define APP_SPLIT_REPORT_MS	60000

#define APP_SPLIT_PROTO_TCP	6
#define APP_SPLIT_PROTO_UDP	17

typedef enum
{
	APP_SPLIT_MODE_OFF = 0,
	APP_SPLIT_MODE_ALLOWLIST,
	APP_SPLIT_MODE_BLOCKLIST
} app_split_mode;

static app_split_mode g_mode = APP_SPLIT_MODE_OFF;
static unsigned long g_exclude_pid = 0;
static unsigned int g_path_count = 0;

/* ---------------- path hash set (open addressing) ---------------- */

static char *g_path_slots[APP_SPLIT_PATH_SLOTS];

static uint32_t app_split_fnv(const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	uint32_t h = 2166136261u;
	size_t i;
	for (i = 0; i < len; i++)
	{
		h ^= p[i];
		h *= 16777619u;
	}
	return h;
}

/*
 * Normalise like the Rust side (trim + lowercase), with one extension:
 * Cyrillic uppercase U+0400..U+042F is folded to lowercase, because
 * Windows user-profile paths commonly contain it and Rust's
 * to_lowercase() folds it. UTF-8 mapping: D0 80..8F -> D1 90..9F
 * (covers YO U+0401, YE U+0404, I U+0406, YI U+0407 and the rest of
 * the U+0400..U+040F block); D0 90..9F -> D0 B0..BF; D0 A0..AF ->
 * D1 80..8F. Lowercase Cyrillic (D1 ..) is already lowercase and
 * passes through byte-wise. Other scripts are copied byte-wise
 * (documented limitation).
 * Returns false if the result is empty or does not fit in out.
 */
static bool app_split_normalize(const char *in, char *out, size_t outsz)
{
	const unsigned char *s = (const unsigned char *)in;
	const unsigned char *e;
	size_t o = 0;

	if (!in || !out || outsz < 2) return false;
	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' || *s == '\v' || *s == '\f') s++;
	e = s + strlen((const char *)s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n' || e[-1] == '\v' || e[-1] == '\f')) e--;
	if (e == s) return false;

	while (s < e)
	{
		unsigned char c = *s;
		if (c < 0x80)
		{
			if (o + 2 > outsz) return false;
			out[o++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
			s++;
		}
		else if (c == 0xD0 && s + 1 < e)
		{
			/* U+0400..U+040F -> U+0450..U+045F; U+0410..U+041F ->
			 * U+0430..U+043F; U+0420..U+042F -> U+0440..U+044F. */
			unsigned char c2 = s[1];
			if (o + 3 > outsz) return false;
			if (c2 >= 0x80 && c2 <= 0x8F)
			{
				out[o++] = (char)0xD1;
				out[o++] = (char)(c2 + 0x10);
			}
			else if (c2 >= 0x90 && c2 <= 0x9F)
			{
				out[o++] = (char)0xD0;
				out[o++] = (char)(c2 + 0x20);
			}
			else if (c2 >= 0xA0 && c2 <= 0xAF)
			{
				out[o++] = (char)0xD1;
				out[o++] = (char)(c2 - 0x20);
			}
			else
			{
				out[o++] = (char)c;
				out[o++] = (char)c2;
			}
			s += 2;
		}
		else
		{
			if (o + 2 > outsz) return false;
			out[o++] = (char)c;
			s++;
		}
	}
	out[o] = 0;
	return true;
}

static bool app_split_path_lookup(const char *norm)
{
	uint32_t h = app_split_fnv(norm, strlen(norm));
	unsigned int i = h % APP_SPLIT_PATH_SLOTS;
	unsigned int k;
	for (k = 0; k < APP_SPLIT_PATH_SLOTS; k++)
	{
		char *slot = g_path_slots[i];
		if (!slot) return false;
		if (!strcmp(slot, norm)) return true;
		i = (i + 1) % APP_SPLIT_PATH_SLOTS;
	}
	return false;
}

static bool app_split_path_insert(const char *norm)
{
	uint32_t h = app_split_fnv(norm, strlen(norm));
	unsigned int i = h % APP_SPLIT_PATH_SLOTS;
	unsigned int k;
	for (k = 0; k < APP_SPLIT_PATH_SLOTS; k++)
	{
		if (!g_path_slots[i])
		{
			size_t len = strlen(norm);
			g_path_slots[i] = (char *)malloc(len + 1);
			if (!g_path_slots[i]) return false;
			memcpy(g_path_slots[i], norm, len + 1);
			g_path_count++;
			return true;
		}
		if (!strcmp(g_path_slots[i], norm)) return true; /* dedup */
		i = (i + 1) % APP_SPLIT_PATH_SLOTS;
	}
	return false; /* table full: cannot happen at <=100 entries */
}

/* ---------------- flow cache ---------------- */

typedef struct
{
	uint32_t local_ip;	/* canonical: first octet in the top byte */
	uint32_t remote_ip;
	uint16_t local_port;	/* host order */
	uint16_t remote_port;	/* host order */
	uint8_t proto;
} app_split_key;

typedef struct
{
	bool valid;
	bool deleted;		/* tombstone: was live, now invalidated.
				 * Distinct from a never-used slot: find() must
				 * skip a tombstone and keep probing, because
				 * entries inserted after it are still reachable
				 * past it; insert() may reuse a tombstone, but
				 * only after checking the rest of the chain for
				 * the same key. A slot is empty only when
				 * !valid && !deleted. */
	bool negative;		/* "not resolved", decision is mode default */
	bool direct;		/* cached decision */
	app_split_key key;
	uint32_t pid;		/* 0 for negative entries */
	uint64_t proc_created;	/* FILETIME, 0 for negative entries */
	uint64_t created_ms;
	uint64_t last_seen_ms;
	uint64_t last_validated_ms;
} app_split_flow;

static app_split_flow g_flows[APP_SPLIT_FLOW_SLOTS];

static uint32_t app_split_key_hash(const app_split_key *k)
{
	uint32_t h = 2166136261u;
	uint32_t v;
	uint8_t b;
	v = k->local_ip;
	b = (uint8_t)(v >> 24); h ^= b; h *= 16777619u;
	b = (uint8_t)(v >> 16); h ^= b; h *= 16777619u;
	b = (uint8_t)(v >> 8); h ^= b; h *= 16777619u;
	b = (uint8_t)v; h ^= b; h *= 16777619u;
	v = k->remote_ip;
	b = (uint8_t)(v >> 24); h ^= b; h *= 16777619u;
	b = (uint8_t)(v >> 16); h ^= b; h *= 16777619u;
	b = (uint8_t)(v >> 8); h ^= b; h *= 16777619u;
	b = (uint8_t)v; h ^= b; h *= 16777619u;
	b = (uint8_t)(k->local_port >> 8); h ^= b; h *= 16777619u;
	b = (uint8_t)k->local_port; h ^= b; h *= 16777619u;
	b = (uint8_t)(k->remote_port >> 8); h ^= b; h *= 16777619u;
	b = (uint8_t)k->remote_port; h ^= b; h *= 16777619u;
	h ^= k->proto; h *= 16777619u;
	return h;
}

static bool app_split_key_equal(const app_split_key *a, const app_split_key *b)
{
	return a->local_ip == b->local_ip && a->remote_ip == b->remote_ip &&
		a->local_port == b->local_port && a->remote_port == b->remote_port &&
		a->proto == b->proto;
}

static app_split_flow *app_split_flow_find(const app_split_key *key)
{
	uint32_t h = app_split_key_hash(key);
	unsigned int i = h % APP_SPLIT_FLOW_SLOTS;
	unsigned int k;
	for (k = 0; k < APP_SPLIT_FLOW_SLOTS; k++)
	{
		app_split_flow *f = &g_flows[i];
		/* Empty slot ends the chain; a tombstone does not: entries
		 * inserted after the invalidated one are still reachable
		 * past it. Stopping at a tombstone (the old behaviour)
		 * made those entries unreachable, so inbound packets lost
		 * the cached decision while outbound packets kept going
		 * DIRECT. */
		if (!f->valid && !f->deleted) return NULL;
		if (f->valid && app_split_key_equal(&f->key, key)) return f;
		i = (i + 1) % APP_SPLIT_FLOW_SLOTS;
	}
	return NULL;
}

static void app_split_flow_insert(const app_split_key *key, bool negative, bool direct,
	uint32_t pid, uint64_t proc_created, uint64_t now)
{
	uint32_t h = app_split_key_hash(key);
	unsigned int i = h % APP_SPLIT_FLOW_SLOTS;
	unsigned int oldest = i;
	uint64_t oldest_seen = (uint64_t)-1;
	int first_tomb = -1;
	unsigned int k;
	for (k = 0; k < APP_SPLIT_FLOW_SLOTS && k < 512; k++)
	{
		app_split_flow *f = &g_flows[i];
		if (f->valid && app_split_key_equal(&f->key, key))
		{
			/* Update in place: do not duplicate the key behind
			 * a tombstone. */
			oldest = i;
			break;
		}
		if (!f->valid && f->deleted)
		{
			/* Remember the first tombstone, but keep probing:
			 * the same key may live further down the chain. */
			if (first_tomb < 0) first_tomb = (int)i;
		}
		else if (!f->valid)
		{
			/* Empty slot ends the chain: reuse the first
			 * tombstone if one was seen, else this slot. */
			oldest = first_tomb >= 0 ? (unsigned int)first_tomb : i;
			break;
		}
		else if (f->last_seen_ms < oldest_seen)
		{
			oldest_seen = f->last_seen_ms;
			oldest = i;
		}
		i = (i + 1) % APP_SPLIT_FLOW_SLOTS;
	}
	if (k >= 512 || k >= APP_SPLIT_FLOW_SLOTS)
	{
		/* Probe window filled without an empty slot or a key hit:
		 * reuse a tombstone if one was seen, else evict the
		 * least-recently-seen entry in that window. */
		if (first_tomb >= 0) oldest = (unsigned int)first_tomb;
		/* else oldest already holds the LRU entry in the window. */
	}
	{
		app_split_flow *f = &g_flows[oldest];
		f->valid = true;
		f->deleted = false;
		f->negative = negative;
		f->direct = direct;
		f->key = *key;
		f->pid = pid;
		f->proc_created = proc_created;
		f->created_ms = now;
		f->last_seen_ms = now;
		f->last_validated_ms = now;
	}
}

/* ---------------- public configuration ---------------- */

static bool g_mode_set = false;

bool app_split_set_mode(const char *mode)
{
	/* A second --app-split-mode is a loud error, not a silent
	 * overwrite: the caller exits on a false return. */
	if (g_mode_set) return false;
	if (!mode) return false;
	if (!strcmp(mode, "allowlist"))
		g_mode = APP_SPLIT_MODE_ALLOWLIST;
	else if (!strcmp(mode, "blocklist"))
		g_mode = APP_SPLIT_MODE_BLOCKLIST;
	else
		return false;
	g_mode_set = true;
	return true;
}

bool app_split_add_path(const char *path)
{
	char norm[APP_SPLIT_PATH_MAX];
	if (!app_split_normalize(path, norm, sizeof(norm))) return false;
	/* Cap checked AFTER dedup: a duplicate of an already-listed
	 * path must not fail just because the list is full, so the
	 * 101st --app-split-path that repeats an earlier entry still
	 * starts up instead of aborting. */
	if (app_split_path_lookup(norm)) return true;
	if (g_path_count >= APP_SPLIT_MAX_PATHS) return false;
	return app_split_path_insert(norm);
}

void app_split_set_exclude_pid(unsigned long pid)
{
	g_exclude_pid = pid;
}

bool app_split_enabled(void)
{
	return g_mode != APP_SPLIT_MODE_OFF;
}

void app_split_log_startup(void)
{
	if (g_mode == APP_SPLIT_MODE_OFF) return;
	fprintf(stderr, "app-split: mode=%s paths=%u\n",
		g_mode == APP_SPLIT_MODE_ALLOWLIST ? "allowlist" : "blocklist",
		g_path_count);
	if (g_mode == APP_SPLIT_MODE_ALLOWLIST && g_path_count == 0)
		fprintf(stderr, "app-split: warning: allowlist is empty, all non-excluded traffic goes direct\n");
}

#ifdef __CYGWIN__

/* ---------------- counters (aggregate only, no paths/PIDs) ---------------- */

static uint64_t g_flows_attributed = 0;
static uint64_t g_flows_missed = 0;
static uint64_t g_cache_hits = 0;
static uint64_t g_pkts_direct = 0;
static uint64_t g_pkts_bypass = 0;
static uint64_t g_reported_flows = 0;
static uint64_t g_last_report_ms = 0;

static uint64_t app_split_now_ms(void)
{
	return (uint64_t)GetTickCount64();
}

static void app_split_report(uint64_t now)
{
	uint64_t flows = g_flows_attributed + g_flows_missed;
	if (now - g_last_report_ms < APP_SPLIT_REPORT_MS) return;
	g_last_report_ms = now;
	if (flows == g_reported_flows) return;
	g_reported_flows = flows;
	fprintf(stderr,
		"app-split: flows=%llu attributed=%llu missed=%llu cache_hits=%llu direct_pkts=%llu bypass_pkts=%llu\n",
		(unsigned long long)flows,
		(unsigned long long)g_flows_attributed,
		(unsigned long long)g_flows_missed,
		(unsigned long long)g_cache_hits,
		(unsigned long long)g_pkts_direct,
		(unsigned long long)g_pkts_bypass);
}

/* ---------------- socket-table snapshots ---------------- */

static PVOID g_tcp_table = NULL;
static DWORD g_tcp_table_size = 0;
static uint64_t g_tcp_table_ms = 0;
static PVOID g_udp_table = NULL;
static DWORD g_udp_table_size = 0;
static uint64_t g_udp_table_ms = 0;

static bool app_split_refresh_table(PVOID *table, DWORD *size, uint64_t *stamp, uint64_t now, bool tcp)
{
	DWORD sz;
	DWORD err;
	if (*table && now - *stamp < APP_SPLIT_TABLE_MIN_MS) return true;
	sz = *size;
	if (tcp)
		err = GetExtendedTcpTable(*table, &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	else
		err = GetExtendedUdpTable(*table, &sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	if (err == ERROR_INSUFFICIENT_BUFFER)
	{
		/* The table grew between reads: reallocate until the fill
		 * succeeds, bounded so a runaway table cannot spin here
		 * forever. The new buffer is installed in *table only
		 * after a successful fill — installing an unfilled
		 * buffer and returning true would let attribution read
		 * dwNumEntries and rows past the allocation (the old
		 * code did exactly that when the second read failed).
		 * On failure the old snapshot is kept untouched and the
		 * stamp is NOT updated, so the failed snapshot is never
		 * presented as fresh; the caller falls back to the stale
		 * snapshot, or to a miss when there is none. */
		int attempt;
		for (attempt = 0; attempt < 4; attempt++)
		{
			PVOID nb = malloc(sz);
			DWORD fill_sz;
			if (!nb)
				break;
			fill_sz = sz;
			if (tcp)
				err = GetExtendedTcpTable(nb, &fill_sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
			else
				err = GetExtendedUdpTable(nb, &fill_sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
			if (err == NO_ERROR)
			{
				free(*table);
				*table = nb;
				*size = sz;
				*stamp = now;
				return true;
			}
			free(nb);
			if (err != ERROR_INSUFFICIENT_BUFFER)
				break;
			/* Table grew again mid-retry: the API wrote the
			 * newly required size back into fill_sz. */
			sz = fill_sz;
		}
		return *table != NULL; /* stale snapshot beats nothing; else miss */
	}
	if (err != NO_ERROR)
	{
		/* Persistent read failure: stamp the attempt so the next
		 * retry waits APP_SPLIT_TABLE_MIN_MS (~100 ms) instead
		 * of happening on every packet. A stale snapshot, if
		 * any, is still used in the meantime. */
		*stamp = now;
		return *table != NULL; /* stale snapshot beats nothing */
	}
	*stamp = now;
	return true;
}

/* ---------------- PID -> path ---------------- */

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

static WCHAR *g_wpath = NULL;
static char *g_upath = NULL;

static bool app_split_pid_path(uint32_t pid, char *norm, size_t normsz, uint64_t *proc_created)
{
	HANDLE h;
	DWORD len;
	FILETIME ft_create, ft_exit, ft_kernel, ft_user;

	if (!g_wpath)
	{
		g_wpath = (WCHAR *)malloc(8192 * sizeof(WCHAR));
		g_upath = (char *)malloc(32768);
		if (!g_wpath || !g_upath) return false;
	}
	h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
	if (!h) return false;
	len = 8192;
	if (!QueryFullProcessImageNameW(h, 0, g_wpath, &len))
	{
		CloseHandle(h);
		return false;
	}
	if (!GetProcessTimes(h, &ft_create, &ft_exit, &ft_kernel, &ft_user))
	{
		CloseHandle(h);
		return false;
	}
	CloseHandle(h);
	*proc_created = ((uint64_t)ft_create.dwHighDateTime << 32) | ft_create.dwLowDateTime;
	if (!WideCharToMultiByte(CP_UTF8, 0, g_wpath, -1, g_upath, 32768, NULL, NULL))
		return false;
	return app_split_normalize(g_upath, norm, normsz);
}

static bool app_split_revalidate(app_split_flow *f)
{
	uint64_t created = 0;
	char norm[APP_SPLIT_PATH_MAX];
	if (f->pid == 0) return false;
	if (!app_split_pid_path(f->pid, norm, sizeof(norm), &created)) return false;
	return created == f->proc_created;
}

/* ---------------- attribution ---------------- */

/*
 * Returns true if the flow was attributed to a process (pid_out,
 * in_list_out and created_out set). False means "not resolved":
 * caller applies the mode default and installs a negative cache
 * entry. The exclude-pid is NOT resolved here; the caller maps it
 * to BYPASS before the list, and only for an attributed flow: in a
 * miss window the supervisor's (tgproxy) traffic gets the mode
 * default instead of BYPASS. Likewise, a protected process that
 * refuses OpenProcess/QueryFullProcessImageNameW is a miss, not a
 * list decision, and a UWP host exe resolves to the host path, so
 * its list lookup misses (see file header).
 */
static bool app_split_attribute(const app_split_key *key, uint64_t now,
	uint32_t *pid_out, bool *in_list_out, uint64_t *created_out)
{
	uint32_t pid = 0;
	bool found = false;
	char norm[APP_SPLIT_PATH_MAX];
	uint64_t created = 0;

	if (key->proto == APP_SPLIT_PROTO_TCP)
	{
		MIB_TCPTABLE_OWNER_PID *t;
		DWORD i;
		if (!app_split_refresh_table(&g_tcp_table, &g_tcp_table_size, &g_tcp_table_ms, now, true))
			return false;
		if (!g_tcp_table) return false;
		t = (MIB_TCPTABLE_OWNER_PID *)g_tcp_table;
		for (i = 0; i < t->dwNumEntries; i++)
		{
			MIB_TCPROW_OWNER_PID *r = &t->table[i];
			if (ntohl(r->dwLocalAddr) == key->local_ip &&
				ntohs((u_short)r->dwLocalPort) == key->local_port &&
				ntohl(r->dwRemoteAddr) == key->remote_ip &&
				ntohs((u_short)r->dwRemotePort) == key->remote_port)
			{
				pid = r->dwOwningPid;
				found = true;
				break;
			}
		}
	}
	else if (key->proto == APP_SPLIT_PROTO_UDP)
	{
		MIB_UDPTABLE_OWNER_PID *t;
		DWORD i;
		if (!app_split_refresh_table(&g_udp_table, &g_udp_table_size, &g_udp_table_ms, now, false))
			return false;
		if (!g_udp_table) return false;
		t = (MIB_UDPTABLE_OWNER_PID *)g_udp_table;
		/* Pass 1: exact match on local address + port. Several
		 * sockets of different processes may share one local
		 * address + port (SO_REUSEADDR), so a first match proves
		 * nothing on its own: attribute only when every exact
		 * match belongs to a single PID, and miss on distinct
		 * PIDs — the same rule as the wildcard pass below.
		 * Duplicate rows of one PID are not ambiguity. */
		{
			uint32_t exact_pid = 0;
			DWORD exact_count = 0;
			for (i = 0; i < t->dwNumEntries; i++)
			{
				MIB_UDPROW_OWNER_PID *r = &t->table[i];
				if (ntohl(r->dwLocalAddr) == key->local_ip &&
					ntohs((u_short)r->dwLocalPort) == key->local_port)
				{
					if (exact_count == 0)
						exact_pid = r->dwOwningPid;
					else if (r->dwOwningPid != exact_pid)
						return false; /* ambiguous: miss on purpose */
					exact_count++;
				}
			}
			if (exact_count > 0)
			{
				pid = exact_pid;
				found = true;
			}
		}
		if (!found)
		{
			/* Pass 2: wildcard sockets. A socket bound to
			 * INADDR_ANY appears in the table as 0.0.0.0, so
			 * pass 1 alone never finds it. Match on
			 * dwLocalAddr == 0 + port. If several wildcard
			 * rows share the port (SO_REUSEADDR), attribution
			 * is ambiguous: return a miss rather than an
			 * arbitrary first row, so the caller applies the
			 * mode default instead of some other process's
			 * list decision. */
			DWORD wild_count = 0;
			uint32_t wild_pid = 0;
			for (i = 0; i < t->dwNumEntries; i++)
			{
				MIB_UDPROW_OWNER_PID *r = &t->table[i];
				if (ntohl(r->dwLocalAddr) == 0 &&
					ntohs((u_short)r->dwLocalPort) == key->local_port)
				{
					wild_count++;
					wild_pid = r->dwOwningPid;
				}
			}
			if (wild_count == 1)
			{
				pid = wild_pid;
				found = true;
			}
			else if (wild_count > 1)
			{
				/* Ambiguous wildcard port: miss on purpose. */
				return false;
			}
		}
	}
	else
		return false;

	if (!found || pid == 0) return false;
	if (!app_split_pid_path(pid, norm, sizeof(norm), &created)) return false;
	*pid_out = pid;
	*in_list_out = app_split_path_lookup(norm);
	*created_out = created;
	return true;
}

static bool app_split_mode_default_direct(void)
{
	/* allowlist miss -> direct; blocklist miss -> bypass */
	return g_mode == APP_SPLIT_MODE_ALLOWLIST;
}

static bool app_split_decision_for(bool attributed, bool in_list, uint32_t pid)
{
	if (g_exclude_pid != 0 && pid == g_exclude_pid) return false; /* bypass */
	if (!attributed) return app_split_mode_default_direct();
	if (g_mode == APP_SPLIT_MODE_ALLOWLIST) return !in_list; /* direct iff not listed */
	return in_list; /* blocklist: direct iff listed */
}

/* ---------------- packet entry point ---------------- */

app_split_verdict app_split_decide_packet(bool outbound, const uint8_t *packet, size_t len)
{
	app_split_key key;
	uint64_t now;
	app_split_flow *f;
	size_t ihl;
	uint8_t proto, tcp_flags = 0;
	bool close_flow = false;

	if (g_mode == APP_SPLIT_MODE_OFF) return APP_SPLIT_BYPASS;
	if (!packet || len < 20) return APP_SPLIT_BYPASS;
	/* IPv4 only. win_main() already split v4/v6; the version nibble
	 * check here keeps this function safe for any other caller. */
	if ((packet[0] >> 4) != 4) return APP_SPLIT_BYPASS;
	ihl = (size_t)(packet[0] & 0x0F) * 4;
	if (ihl < 20 || len < ihl) return APP_SPLIT_BYPASS;
	/* Subsequent fragments only (fragment offset != 0): no transport
	 * header to parse, so ordinary processing, without a cache
	 * lookup and without inheriting a cached DIRECT decision. The
	 * first fragment (offset 0, MF flag aside) is parsed normally. */
	if (((packet[6] & 0x1F) << 8 | packet[7]) != 0) return APP_SPLIT_BYPASS;
	proto = packet[9];
	if (proto != APP_SPLIT_PROTO_TCP && proto != APP_SPLIT_PROTO_UDP)
		return APP_SPLIT_BYPASS;
	if (len < ihl + 4) return APP_SPLIT_BYPASS;
	if (proto == APP_SPLIT_PROTO_TCP)
	{
		if (len < ihl + 14) return APP_SPLIT_BYPASS;
		tcp_flags = packet[ihl + 13];
		if (tcp_flags & 0x01 || tcp_flags & 0x04) close_flow = true; /* FIN or RST */
	}

	/* Canonical key: local endpoint first, regardless of direction. */
	key.proto = proto;
	if (outbound)
	{
		key.local_ip = (uint32_t)packet[12] << 24 | (uint32_t)packet[13] << 16 |
			(uint32_t)packet[14] << 8 | (uint32_t)packet[15];
		key.remote_ip = (uint32_t)packet[16] << 24 | (uint32_t)packet[17] << 16 |
			(uint32_t)packet[18] << 8 | (uint32_t)packet[19];
		key.local_port = (uint16_t)((packet[ihl] << 8) | packet[ihl + 1]);
		key.remote_port = (uint16_t)((packet[ihl + 2] << 8) | packet[ihl + 3]);
	}
	else
	{
		key.local_ip = (uint32_t)packet[16] << 24 | (uint32_t)packet[17] << 16 |
			(uint32_t)packet[18] << 8 | (uint32_t)packet[19];
		key.remote_ip = (uint32_t)packet[12] << 24 | (uint32_t)packet[13] << 16 |
			(uint32_t)packet[14] << 8 | (uint32_t)packet[15];
		key.local_port = (uint16_t)((packet[ihl + 2] << 8) | packet[ihl + 3]);
		key.remote_port = (uint16_t)((packet[ihl] << 8) | packet[ihl + 1]);
	}

	/* Loopback: ordinary processing, no attribution, no cache entry. */
	if ((key.local_ip >> 24) == 127 || (key.remote_ip >> 24) == 127)
	{
		g_pkts_bypass++;
		return APP_SPLIT_BYPASS;
	}

	now = app_split_now_ms();
	f = app_split_flow_find(&key);
	if (f)
	{
		bool direct;
		uint64_t ttl = f->key.proto == APP_SPLIT_PROTO_UDP ?
			APP_SPLIT_UDP_TTL_MS : APP_SPLIT_TCP_IDLE_MS;
		if (f->negative)
		{
			if (now - f->created_ms >= APP_SPLIT_NEG_MS)
			{
				/* Tombstone, not an empty slot: entries past
				 * this one in the probe chain stay reachable. */
				f->valid = false;
				f->deleted = true; /* expired: fall through to re-attribute */
			}
			else
			{
				g_cache_hits++;
				direct = f->direct;
				if (direct) g_pkts_direct++; else g_pkts_bypass++;
				app_split_report(now);
				return direct ? APP_SPLIT_DIRECT : APP_SPLIT_BYPASS;
			}
		}
		else if (now - f->last_seen_ms >= ttl)
		{
			/* Tombstone, not an empty slot: see above. */
			f->valid = false;
			f->deleted = true; /* expired: fall through to re-attribute */
		}
		else
		{
			/* PID-reuse guard, amortised (see file header). */
			if (f->pid != 0 && now - f->last_validated_ms >= APP_SPLIT_REVALIDATE_MS)
			{
				if (!app_split_revalidate(f))
				{
					/* Tombstone, not an empty slot: see above. */
					f->valid = false;
					f->deleted = true; /* process gone or PID reused */
				}
				else
				{
					f->last_validated_ms = now;
				}
			}
			if (f->valid)
			{
				g_cache_hits++;
				f->last_seen_ms = now;
				direct = f->direct;
				if (close_flow) { f->valid = false; f->deleted = true; }
				if (direct) g_pkts_direct++; else g_pkts_bypass++;
				app_split_report(now);
				return direct ? APP_SPLIT_DIRECT : APP_SPLIT_BYPASS;
			}
			/* else: invalidated above, fall through to re-attribute */
		}
	}

	/* No usable cache entry. Only outbound packets attribute. */
	if (!outbound)
	{
		g_pkts_bypass++;
		return APP_SPLIT_BYPASS;
	}
	{
		uint32_t pid = 0;
		uint64_t created = 0;
		bool in_list = false;
		bool attributed;
		bool direct;
		attributed = app_split_attribute(&key, now, &pid, &in_list, &created);
		if (attributed)
		{
			g_flows_attributed++;
			direct = app_split_decision_for(true, in_list, pid);
			app_split_flow_insert(&key, false, direct, pid, created, now);
		}
		else
		{
			g_flows_missed++;
			direct = app_split_decision_for(false, false, 0);
			app_split_flow_insert(&key, true, direct, 0, 0, now);
		}
		if (close_flow && attributed)
		{
			/* A one-packet FIN/RST flow: do not keep the entry. */
			app_split_flow *nf = app_split_flow_find(&key);
			if (nf) { nf->valid = false; nf->deleted = true; }
		}
		if (direct) g_pkts_direct++; else g_pkts_bypass++;
		app_split_report(now);
		return direct ? APP_SPLIT_DIRECT : APP_SPLIT_BYPASS;
	}
}

#else /* !__CYGWIN__ */

app_split_verdict app_split_decide_packet(bool outbound, const uint8_t *packet, size_t len)
{
	(void)outbound;
	(void)packet;
	(void)len;
	return APP_SPLIT_BYPASS;
}

#endif /* __CYGWIN__ */
