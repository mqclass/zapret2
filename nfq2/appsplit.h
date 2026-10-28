#pragma once
/*
 * app-split: per-application split tunnelling enforcement for winws2
 * (Windows / Cygwin build only; see appsplit.c).
 *
 * Contract with the supervisor (Rust side):
 *   --app-split-mode=allowlist|blocklist
 *   --app-split-path=<path>   (repeatable, up to 100 entries)
 *   --app-split-exclude-pid=<pid>
 * If --app-split-mode is absent, split is disabled and behaviour is
 * exactly upstream: every packet takes the ordinary path.
 *
 * Paths are normalised on both sides as trim + lowercase. The C side
 * folds ASCII and Cyrillic (see appsplit.c); other scripts are compared
 * byte-wise, so a non-ASCII uppercase letter outside those ranges may
 * fail to match a lowercased list entry. That is a documented
 * limitation, not a silent behaviour change: a mismatch falls back to
 * the mode default (see appsplit.c).
 *
 * This header is deliberately free of Windows includes so that
 * nfqws.c can include it on every platform. On non-Cygwin builds
 * every function below is a no-op stub (split is a Windows feature).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum
{
	APP_SPLIT_BYPASS = 0, /* ordinary processing: desync + Lua */
	APP_SPLIT_DIRECT = 1  /* reinject the packet unmodified */
} app_split_verdict;

/* Parse --app-split-mode value. Returns false on an unknown value. */
bool app_split_set_mode(const char *mode);
/* Add one list entry (already normalised by the caller, normalised again
 * here). Returns false if the list is full or the entry is unusable. */
bool app_split_add_path(const char *path);
/* PID whose traffic (the supervisor tgproxy bridge) is excluded. */
void app_split_set_exclude_pid(unsigned long pid);
/* True only after a valid --app-split-mode was seen. */
bool app_split_enabled(void);
/* Startup line to stderr: mode + list size. No paths or PIDs. */
void app_split_log_startup(void);

/*
 * Decide the fate of one IPv4 packet seen by WinDivert.
 * outbound: wa.Outbound of the WinDivert address.
 * Returns APP_SPLIT_BYPASS for everything split does not touch:
 * split disabled, IPv6, non-TCP/UDP, subsequent fragments (which do
 * not inherit a cached DIRECT decision), loopback, inbound
 * packets with no cached flow, and flows that resolve to bypass.
 * Never prints process paths or user PIDs; only aggregate counters
 * (see app_split_log_startup / periodic report in appsplit.c).
 */
app_split_verdict app_split_decide_packet(bool outbound, const uint8_t *packet, size_t len);
