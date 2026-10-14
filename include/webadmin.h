#ifndef WEBADMIN_H
#define WEBADMIN_H

#include "types.h"

// ============================================================================
// YesOS NAS - web administration: sessions, login policy and JSON views.
// The HTTP side lives in rust_core/src/webadmin.rs.
//
// Policy:
//   - only devices admitted at the console (`nas admit <ip>`) may log in,
//   - only NAS accounts with the ADMIN role may log in (Argon2id check, the
//     per-account lockout of nas_user plus a per-IP throttle),
//   - sessions are 256-bit DRBG tokens, stored only as BLAKE2b hashes, bound
//     to the client IP, with a 15 min idle and 8 h absolute lifetime,
//   - every state-changing request must carry the session's CSRF token,
//   - the panel and its API work only over HTTPS (TLS 1.3, port 8443).
// ============================================================================

#define WA_TOKEN_HEX_LEN 64

#define WA_OK                    0
#define WA_ERR_BAD_CREDENTIALS  -1
#define WA_ERR_NOT_ADMIN        -2
#define WA_ERR_NOT_ADMITTED     -3
#define WA_ERR_THROTTLED        -4
#define WA_ERR_NO_ENTROPY       -5
#define WA_ERR_NO_SESSION       -6
#define WA_ERR_BAD_CSRF         -7

// Login. On success writes NUL-terminated hex tokens (65 bytes each).
I32 webadmin_login(const char* username, const char* password, U32 client_ip,
                   char* out_sid, char* out_csrf);

// Validates a session cookie for this IP. If `csrf` is non-NULL it must match
// the session's CSRF token (state-changing requests). On success copies the
// user name (NUL-terminated) and returns WA_OK.
I32 webadmin_check(const char* sid, const char* csrf, U32 client_ip,
                   char* out_user, size_t user_max);

U0  webadmin_logout(const char* sid, U32 client_ip);

// Seconds this IP must wait before the next login attempt (0 = none).
U32 webadmin_throttle_remaining(U32 client_ip);

// JSON view of one section ("overview", "storage", "shares", "users",
// "devices", "network", "security", "session", "audit"). Returns the length written,
// -1 for an unknown section, -2 if `max` is too small.
I32 webadmin_json(const char* section, const char* sid, char* buf, size_t max);

U32 webadmin_session_count(U0);

// State-changing actions (the caller has already checked the session and the
// CSRF token). `fields` holds WA_F_COUNT NUL-terminated strings ("" when
// absent), in the order of the WA_F_* indices. Writes a human-readable
// (Spanish) result to `msg` and returns an HTTP status: 200, 400, 403, 404,
// 409 or 500. Every attempt is recorded in the audit log.
#define WA_F_NAME      0
#define WA_F_PASSWORD  1
#define WA_F_CURRENT   2
#define WA_F_ROLE      3
#define WA_F_IP        4
#define WA_F_PATH      5
#define WA_F_COMMENT   6
#define WA_F_READONLY  7
#define WA_F_VALUE     8
#define WA_F_COUNT     9
I32 webadmin_action(const char* sid, U32 client_ip, const char* action,
                    const char* const* fields, char* msg, size_t msg_max);

// WebDAV login (HTTP Basic over HTTPS). `share` is the first path segment
// after /dav/ ("" for /dav itself); `write` is TRUE for methods that modify.
// Returns 0 (allowed), 401 (bad or missing credentials), 403 (the account may
// not use that share or may not write) or 429 (this IP is throttled).
// Verified credentials are cached for 10 minutes as a keyed BLAKE2b hash,
// bound to the client IP; any change to the accounts empties the cache.
I32 webdav_authorize(const char* user, const char* pass, U32 client_ip, const char* share, Bool write);
U0  webdav_auth_flush(U0);
U32 webdav_share_mask_bit(const char* share);   // 0 when the share needs no bit

// Replication (tools/yesos_replicate.py). The caller (rust webadmin.rs) has
// checked the admin session, HTTPS and, for imports, the CSRF token.
// export_file: raw bytes of backup/snap-NNNN/<path> (vault files as stored
// ciphertext) into a Malloc'd buffer (caller frees). Returns 0, 404 or 400.
I32 webadmin_export_file(U32 snap_id, const char* path, U8** out, size_t* out_len);
I32 webadmin_export_vault_header(const char* sid, U32 ip, U8** out, size_t* out_len);
// import: writes share/, media/ (plaintext) or vault/ (ciphertext) files and
// the vault header (only on a NAS without a vault). Returns an HTTP status.
I32 webadmin_import_file(const char* sid, U32 ip, const char* path, const U8* data, size_t len,
                         char* msg, size_t msg_max);
// Logs `user` out of the panel everywhere (e.g. after losing the admin role).
U0  webadmin_close_sessions_of(const char* user);
I32 webadmin_import_vault_header(const char* sid, U32 ip, const U8* data, size_t len,
                                 char* msg, size_t msg_max);

// HTTPS (TLS 1.3, TCP 8443): loads or creates the certificate key in
// SYS/TLS.KEY and prints the certificate fingerprint. Call after vfs,
// entropy and virtio_net are up.
#define WEBADMIN_HTTPS_PORT 8443
U0   webadmin_tls_init(U0);
Bool webadmin_tls_ready(U0);
U0   webadmin_print_tls(U0);

#endif // WEBADMIN_H
