#include "webadmin.h"
#include "nas_server.h"
#include "nas_user.h"
#include "yesos_crypto.h"
#include "timer.h"
#include "kprintf.h"
#include "memory.h"
#include "redsea_eml.h"
#include "virtio_blk.h"
#include "virtio_net.h"
#include "airgap_firewall.h"
#include "vault.h"
#include "integrity.h"
#include "keyhart.h"
#include "pmp.h"
#include "cell.h"
#include "smp.h"
#include "security_pin.h"
#include "vfs.h"
#include "snapshot.h"
#include "kprintf.h"

// rust_core/src/tls.rs
I32 yc_tls_init(const U8* key32, const U8* nas_ip4, U8* fp_out32);
I32 yc_tls_fingerprint(U8* fp_out32);

// ----------------------------------------------------------------------------
// Sessions
// ----------------------------------------------------------------------------

#define WA_MAX_SESSIONS   8
#define WA_IDLE_MS        (15ULL * 60 * 1000)
#define WA_ABSOLUTE_MS    (8ULL * 60 * 60 * 1000)
#define WA_THROTTLE_SLOTS 8
#define WA_THROTTLE_FAILS 5
#define WA_THROTTLE_MS    30000ULL

typedef struct {
    Bool used;
    U8   sid_hash[32];      // BLAKE2b-256 of the cookie token (the token itself is never stored)
    U8   csrf[32];
    U32  ip;
    char user[NAS_MAX_USERNAME_LEN];
    U64  created_ms;
    U64  last_ms;
} WebSession;

typedef struct {
    U32 ip;
    U32 fails;
    U64 until_ms;
    U64 last_ms;
} LoginThrottle;

static WebSession    g_sessions[WA_MAX_SESSIONS];
static LoginThrottle g_throttle[WA_THROTTLE_SLOTS];

static const char HEX[] = "0123456789abcdef";

static U0 to_hex(const U8* in, size_t n, char* out) {
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = HEX[in[i] >> 4];
        out[2 * i + 1] = HEX[in[i] & 15];
    }
    out[2 * n] = '\0';
}

static Bool from_hex(const char* s, U8* out, size_t n) {
    if (!s) return FALSE;
    for (size_t i = 0; i < 2 * n; i++) {
        char c = s[i];
        U8 v;
        if (c >= '0' && c <= '9') v = (U8)(c - '0');
        else if (c >= 'a' && c <= 'f') v = (U8)(c - 'a' + 10);
        else return FALSE;
        if (i & 1) out[i / 2] |= v;
        else out[i / 2] = (U8)(v << 4);
    }
    return s[2 * n] == '\0';
}

static Bool session_live(const WebSession* s, U64 now) {
    return s->used && now - s->last_ms < WA_IDLE_MS && now - s->created_ms < WA_ABSOLUTE_MS;
}

static U0 session_clear(WebSession* s) {
    yc_wipe((U8*)s, sizeof(*s));
}

static WebSession* session_find(const char* sid_hex, U32 ip) {
    U8 sid[32], h[32];
    if (!from_hex(sid_hex, sid, sizeof(sid))) return NULL;
    yc_blake2b256_2(sid, sizeof(sid), NULL, 0, h);
    yc_wipe(sid, sizeof(sid));
    U64 now = timer_get_uptime_ms();
    WebSession* found = NULL;
    for (U32 i = 0; i < WA_MAX_SESSIONS; i++) {
        WebSession* s = &g_sessions[i];
        if (s->used && !session_live(s, now)) session_clear(s);
        if (s->used && yc_ct_eq(s->sid_hash, h, 32) && s->ip == ip) found = s;
    }
    return found;
}

static LoginThrottle* throttle_slot(U32 ip, Bool create) {
    LoginThrottle* oldest = &g_throttle[0];
    for (U32 i = 0; i < WA_THROTTLE_SLOTS; i++) {
        if (g_throttle[i].ip == ip && g_throttle[i].last_ms) return &g_throttle[i];
        if (g_throttle[i].last_ms < oldest->last_ms) oldest = &g_throttle[i];
    }
    if (!create) return NULL;
    MemSet(oldest, 0, sizeof(*oldest));
    oldest->ip = ip;
    return oldest;
}

U32 webadmin_throttle_remaining(U32 ip) {
    LoginThrottle* t = throttle_slot(ip, FALSE);
    U64 now = timer_get_uptime_ms();
    if (!t || now >= t->until_ms) return 0;
    return (U32)((t->until_ms - now) / 1000) + 1;
}

// NAS/admission code keeps IPv4 as (a << 24) | (b << 16) | (c << 8) | d
// (see nas_parse_ip); virtio_net uses the opposite byte order.
static U0 fmt_ip(U32 ip, char* out) {
    ksnprintf(out, 20, "%u.%u.%u.%u", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

I32 webadmin_login(const char* username, const char* password, U32 ip, char* out_sid, char* out_csrf) {
    char ipb[20];
    fmt_ip(ip, ipb);
    if (!nas_is_client_admitted(ip)) {
        kprintf("[WEBADMIN] Login refused: %s is not an admitted device (console: nas admit %s)\n", ipb, ipb);
        return WA_ERR_NOT_ADMITTED;
    }
    if (webadmin_throttle_remaining(ip)) return WA_ERR_THROTTLED;

    NASUser* u = NULL;
    Bool ok = username && password && username[0] && nas_user_authenticate(username, password, &u);
    LoginThrottle* t = throttle_slot(ip, TRUE);
    t->last_ms = timer_get_uptime_ms();
    if (!ok || !u) {
        if (++t->fails >= WA_THROTTLE_FAILS) {
            t->until_ms = t->last_ms + WA_THROTTLE_MS;
            t->fails = 0;
            kprintf("[WEBADMIN] %u failed logins from %s: throttled for 30 s\n", WA_THROTTLE_FAILS, ipb);
        }
        return WA_ERR_BAD_CREDENTIALS;
    }
    t->fails = 0;
    if (u->role != NAS_ROLE_ADMIN) {
        kprintf("[WEBADMIN] Login refused for '%s': web administration needs the admin role\n", u->username);
        return WA_ERR_NOT_ADMIN;
    }

    U8 sid[32];
    WebSession fresh;
    MemSet(&fresh, 0, sizeof(fresh));
    if (yc_rng_fill(sid, sizeof(sid)) != YC_OK || yc_rng_fill(fresh.csrf, sizeof(fresh.csrf)) != YC_OK) {
        yc_wipe(sid, sizeof(sid));
        return WA_ERR_NO_ENTROPY;
    }
    yc_blake2b256_2(sid, sizeof(sid), NULL, 0, fresh.sid_hash);
    fresh.used = TRUE;
    fresh.ip = ip;
    StrNCpy(fresh.user, u->username, sizeof(fresh.user) - 1);
    fresh.created_ms = fresh.last_ms = timer_get_uptime_ms();

    // Free slot, else an expired one, else evict the least recently used.
    U64 now = fresh.created_ms;
    WebSession* slot = NULL;
    for (U32 i = 0; i < WA_MAX_SESSIONS && !slot; i++) {
        if (!session_live(&g_sessions[i], now)) slot = &g_sessions[i];
    }
    if (!slot) {
        slot = &g_sessions[0];
        for (U32 i = 1; i < WA_MAX_SESSIONS; i++) {
            if (g_sessions[i].last_ms < slot->last_ms) slot = &g_sessions[i];
        }
    }
    *slot = fresh;
    to_hex(sid, sizeof(sid), out_sid);
    to_hex(fresh.csrf, sizeof(fresh.csrf), out_csrf);
    yc_wipe(sid, sizeof(sid));
    yc_wipe((U8*)&fresh, sizeof(fresh));
    kprintf("[WEBADMIN] '%s' logged in from %s\n", slot->user, ipb);
    return WA_OK;
}

I32 webadmin_check(const char* sid, const char* csrf, U32 ip, char* out_user, size_t user_max) {
    WebSession* s = session_find(sid, ip);
    if (!s) return WA_ERR_NO_SESSION;
    // The account may have been removed or demoted since login.
    NASUser* u = nas_user_get_by_name(s->user);
    if (!u || !u->active || u->role != NAS_ROLE_ADMIN || !nas_is_client_admitted(ip)) {
        session_clear(s);
        return WA_ERR_NO_SESSION;
    }
    if (csrf) {
        U8 c[32];
        Bool good = from_hex(csrf, c, sizeof(c)) && yc_ct_eq(c, s->csrf, sizeof(c));
        yc_wipe(c, sizeof(c));
        if (!good) return WA_ERR_BAD_CSRF;
    }
    s->last_ms = timer_get_uptime_ms();
    if (out_user && user_max) {
        StrNCpy(out_user, s->user, user_max - 1);
        out_user[user_max - 1] = '\0';
    }
    return WA_OK;
}

U0 webadmin_logout(const char* sid, U32 ip) {
    WebSession* s = session_find(sid, ip);
    if (s) {
        kprintf("[WEBADMIN] '%s' logged out\n", s->user);
        session_clear(s);
    }
}

U32 webadmin_session_count(U0) {
    U64 now = timer_get_uptime_ms();
    U32 n = 0;
    for (U32 i = 0; i < WA_MAX_SESSIONS; i++) n += session_live(&g_sessions[i], now) ? 1 : 0;
    return n;
}

// ----------------------------------------------------------------------------
// JSON writer (bounded; strings are escaped, including < > & for safety)
// ----------------------------------------------------------------------------

typedef struct {
    char*  b;
    size_t n;
    size_t max;
    Bool   overflow;
} JW;

static U0 jw_raw(JW* w, const char* s) {
    while (*s) {
        if (w->n + 1 >= w->max) { w->overflow = TRUE; return; }
        w->b[w->n++] = *s++;
    }
    w->b[w->n] = '\0';
}

static U0 jw_str(JW* w, const char* s) {
    jw_raw(w, "\"");
    for (; s && *s; s++) {
        U8 c = (U8)*s;
        char esc[8];
        if (c == '"' || c == '\\') { esc[0] = '\\'; esc[1] = (char)c; esc[2] = 0; jw_raw(w, esc); }
        else if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == 0x7F) {
            esc[0] = '\\'; esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
            esc[4] = HEX[c >> 4]; esc[5] = HEX[c & 15]; esc[6] = 0;
            jw_raw(w, esc);
        } else { esc[0] = (char)c; esc[1] = 0; jw_raw(w, esc); }
    }
    jw_raw(w, "\"");
}

static U0 jw_u64(JW* w, U64 v) {
    char t[24];
    int i = 23;
    t[i] = '\0';
    do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    jw_raw(w, &t[i]);
}

static U0 jw_key(JW* w, const char* k) { jw_str(w, k); jw_raw(w, ":"); }
static U0 jw_ks(JW* w, const char* k, const char* v) { jw_key(w, k); jw_str(w, v); jw_raw(w, ","); }
static U0 jw_ku(JW* w, const char* k, U64 v) { jw_key(w, k); jw_u64(w, v); jw_raw(w, ","); }
static U0 jw_kb(JW* w, const char* k, Bool v) { jw_key(w, k); jw_raw(w, v ? "true," : "false,"); }

// Drop a trailing comma before closing an object/array.
static U0 jw_close(JW* w, const char* c) {
    if (w->n && w->b[w->n - 1] == ',') w->n--;
    jw_raw(w, c);
}

static U0 jw_ip(JW* w, const char* k, U32 ip) {      // virtio_net byte order
    char b[20];
    net_format_ip(ip, b, sizeof(b));
    jw_ks(w, k, b);
}

static U0 jw_nas_ip(JW* w, const char* k, U32 ip) {  // nas_parse_ip byte order
    char b[20];
    fmt_ip(ip, b);
    jw_ks(w, k, b);
}

static const char* role_name(U8 r) {
    return r == NAS_ROLE_ADMIN ? "admin" : (r == NAS_ROLE_RW ? "rw" : "ro");
}

// ----------------------------------------------------------------------------
// Sections
// ----------------------------------------------------------------------------

static U0 json_pool(JW* w) {
    RedSeaVolume* v = redsea_eml_get_volume();
    jw_key(w, "pool"); jw_raw(w, "{");
    jw_kb(w, "mounted", v && v->is_mounted);
    if (v && v->is_mounted) {
        U64 total = v->sb.total_sectors, free_s = redsea_eml_get_free_sectors();
        U32 files = 0;
        for (U32 i = 0; i < v->entry_count; i++) {
            if ((v->entries[i].flags & REDSEA_FLAG_USED) && !(v->entries[i].flags & REDSEA_FLAG_DIR)) files++;
        }
        jw_ku(w, "total_bytes", total * 512);
        jw_ku(w, "used_bytes", (total > free_s ? total - free_s : 0) * 512);
        jw_ku(w, "files", files);
        jw_ku(w, "dir_entries", v->entry_count);
        jw_ku(w, "dir_entries_max", REDSEA_DIR_ENTRIES_MAX);
        jw_ku(w, "version", v->sb.version);
        jw_ks(w, "label", v->sb.volume_label);
    }
    jw_close(w, "},");
}

static U0 json_vault(JW* w) {
    jw_key(w, "vault"); jw_raw(w, "{");
    jw_kb(w, "initialized", vault_is_initialized());
    jw_kb(w, "unlocked", vault_is_unlocked());
    jw_ku(w, "lockout_sec", vault_lockout_remaining_sec());
    jw_close(w, "},");
}

static U0 section_overview(JW* w) {
    MemStats ms = mem_get_stats();
    NASServerState* nas = nas_server_get_state();
    const IntegrityStatus* is = integrity_status();
    VirtIONetInfo* ni = virtio_net_get_info();
    jw_raw(w, "{");
    jw_ks(w, "hostname", nas ? nas->server_name : "yesos");
    jw_ku(w, "uptime_sec", timer_get_uptime_ms() / 1000);
    jw_ku(w, "harts", smp_get_online_harts());
    jw_ku(w, "ram_bytes", ms.total_ram);
    jw_ku(w, "heap_used_bytes", ms.heap_used);
    jw_ku(w, "heap_bytes", ms.heap_end > ms.heap_start ? ms.heap_end - ms.heap_start : 0);
    json_pool(w);
    json_vault(w);
    jw_ku(w, "clients", nas ? nas->active_clients_count : 0);
    jw_ku(w, "web_sessions", webadmin_session_count());
    jw_kb(w, "pmp_proven", pmp_get_state() == PMP_STATE_LOCKED_PROVEN);
    jw_kb(w, "integrity_armed", is && is->armed);
    jw_kb(w, "integrity_alarm", is && is->alarm);
    if (ni && ni->is_present) jw_ip(w, "ip", ni->ip);
    jw_close(w, "}");
}

static U0 section_storage(JW* w) {
    jw_raw(w, "{");
    jw_key(w, "disks"); jw_raw(w, "[");
    if (virtio_blk_is_present()) {
        VirtIOBlkInfo* bi = virtio_blk_get_info();
        jw_raw(w, "{");
        jw_ks(w, "device", "virtio-blk");
        jw_ks(w, "model", bi->model[0] ? bi->model : "VirtIO block device");
        jw_ks(w, "serial", bi->serial);
        jw_ku(w, "bytes", bi->capacity_bytes);
        jw_ks(w, "smart", "not available on virtio-blk");
        jw_close(w, "},");
    }
    jw_close(w, "],");
    json_pool(w);
    const RedSeaFsckReport* fr = redsea_eml_last_fsck();
    jw_key(w, "fsck"); jw_raw(w, "{");
    if (fr) {
        jw_kb(w, "data_checked", fr->data_checked);
        jw_ku(w, "errors", fr->errors);
        jw_ku(w, "warnings", fr->warnings);
        jw_ku(w, "files", fr->files);
        jw_ku(w, "shared_extents", fr->shared_extents);
        jw_ku(w, "crc_ok", fr->crc_ok);
        jw_ku(w, "crc_legacy", fr->crc_legacy);
        jw_ku(w, "crc_bad", fr->crc_bad);
        jw_ku(w, "unreadable", fr->unreadable);
        jw_ku(w, "lost_sectors", fr->lost_sectors);
        jw_ku(w, "duration_ms", fr->duration_ms);
        jw_ks(w, "first_problem", fr->first_problem);
    }
    jw_close(w, "},");
    jw_key(w, "files"); jw_raw(w, "[");
    RedSeaVolume* v = redsea_eml_get_volume();
    if (v && v->is_mounted) {
        for (U32 i = 0; i < v->entry_count && !w->overflow; i++) {
            const RedSeaFileEntry* e = &v->entries[i];
            if (!(e->flags & REDSEA_FLAG_USED) || (e->flags & REDSEA_FLAG_DIR)) continue;
            if (StrNCmp(e->name, SNAP_PREFIX, 12) == 0) continue;   // shown on the snapshots page
            jw_raw(w, "{");
            jw_ks(w, "name", e->name);
            jw_ku(w, "bytes", e->byte_size);
            jw_kb(w, "encrypted", (e->flags & REDSEA_FLAG_ENCRYPTED) != 0);
            jw_kb(w, "readonly", (e->flags & REDSEA_FLAG_READONLY) != 0);
            jw_close(w, "},");
        }
    }
    jw_close(w, "]}");
}

static U0 section_shares(JW* w) {
    NASServerState* nas = nas_server_get_state();
    jw_raw(w, "{");
    jw_key(w, "shares"); jw_raw(w, "[");
    for (U32 i = 0; nas && i < nas->shares_count && i < NAS_MAX_SHARES; i++) {
        NASShare* s = &nas->shares[i];
        if (!s->active) continue;
        jw_raw(w, "{");
        jw_ks(w, "name", s->share_name);
        jw_ks(w, "path", s->mount_path);
        jw_ks(w, "comment", s->comment);
        jw_kb(w, "readonly", s->read_only);
        jw_close(w, "},");
    }
    jw_close(w, "],");
    // WebDAV exposes these RedSea prefixes (see kernel/webui_bridge.c).
    jw_key(w, "webdav"); jw_raw(w, "[");
    jw_raw(w, "{\"path\":\"/dav/share/\",\"access\":\"read/write\",\"who\":\"admin and read/write\"},");
    jw_raw(w, "{\"path\":\"/dav/media/\",\"access\":\"read/write\",\"who\":\"every account (read-only accounts: read)\"},");
    jw_raw(w, "{\"path\":\"/dav/backup/\",\"access\":\"read-only (WORM)\",\"who\":\"admin and read/write\"}");
    jw_raw(w, "],");
    jw_kb(w, "auth_required", nas_user_is_auth_required());
    jw_close(w, "}");
}

static U0 section_users(JW* w) {
    NASUserState* us = nas_user_get_state();
    U64 now = timer_get_uptime_ms();
    jw_raw(w, "{");
    jw_kb(w, "auth_required", nas_user_is_auth_required());
    jw_key(w, "users"); jw_raw(w, "[");
    for (U32 i = 0; us && i < NAS_MAX_USERS; i++) {
        NASUser* u = &us->users[i];
        if (!u->active) continue;
        jw_raw(w, "{");
        jw_ks(w, "name", u->username);
        jw_ks(w, "role", role_name(u->role));
        char dav[64];
        dav[0] = '\0';
        if (u->allowed_shares_mask & webdav_share_mask_bit("share")) StrNCpy(dav, "share", sizeof(dav) - 1);
        if (u->allowed_shares_mask & webdav_share_mask_bit("media")) ksnprintf(dav + StrLen(dav), sizeof(dav) - StrLen(dav), "%smedia", dav[0] ? ", " : "");
        if (u->allowed_shares_mask & webdav_share_mask_bit("backup")) ksnprintf(dav + StrLen(dav), sizeof(dav) - StrLen(dav), "%sbackup", dav[0] ? ", " : "");
        jw_ks(w, "webdav", dav);
        jw_kb(w, "webdav_write", u->role != NAS_ROLE_RO);
        jw_ku(w, "failed_attempts", u->failed_attempts);
        jw_kb(w, "locked", now < u->lockout_until_ms);
        jw_close(w, "},");
    }
    jw_close(w, "]}");
}

static U0 section_devices(JW* w) {
    NASServerState* nas = nas_server_get_state();
    U64 now = timer_get_ticks();
    jw_raw(w, "{\"devices\":[");
    for (U32 i = 0; nas && i < nas->active_clients_count && i < NAS_MAX_CLIENTS; i++) {
        NASConnectedClient* c = &nas->clients[i];
        const char* st = (c->is_blocked || c->access_status == NAS_ACCESS_BLOCKED) ? "blocked" :
                         (c->access_status == NAS_ACCESS_ADMITTED ? "admitted" : "pending");
        jw_raw(w, "{");
        jw_nas_ip(w, "ip", c->ip);
        jw_ks(w, "name", c->client_name);
        jw_ks(w, "status", st);
        jw_ks(w, "user", c->is_authenticated ? c->auth_username : "");
        jw_ku(w, "idle_sec", now > c->last_seen_tick ? (now - c->last_seen_tick) / 1000 : 0);
        jw_ku(w, "bytes_read", c->bytes_read);
        jw_ku(w, "bytes_written", c->bytes_written);
        jw_close(w, "},");
    }
    jw_close(w, "]}");
}

static U0 section_network(JW* w) {
    VirtIONetInfo* ni = virtio_net_get_info();
    VirtIONetStats* st = virtio_net_get_stats();
    AirGapFirewallState* fw = firewall_get_state();
    jw_raw(w, "{");
    jw_kb(w, "present", ni && ni->is_present);
    if (ni && ni->is_present) {
        char mac[24];
        net_format_mac(ni->mac, mac, sizeof(mac));
        jw_ks(w, "mac", mac);
        jw_ip(w, "ip", ni->ip);
        jw_ip(w, "netmask", ni->netmask);
        jw_ip(w, "gateway", ni->gateway_ip);
        jw_kb(w, "link_up", ni->link_up);
    }
    if (st) {
        jw_ku(w, "rx_packets", st->rx_packets);
        jw_ku(w, "rx_bytes", st->rx_bytes);
        jw_ku(w, "tx_packets", st->tx_packets);
        jw_ku(w, "tx_bytes", st->tx_bytes);
        jw_ku(w, "rx_drops", st->rx_drops);
    }
    jw_key(w, "services"); jw_raw(w, "[");
    jw_raw(w, "{\"name\":\"NAS (Noise NK)\",\"proto\":\"udp\",\"port\":31415},");
    jw_raw(w, "{\"name\":\"HTTP (redirects to HTTPS only)\",\"proto\":\"tcp\",\"port\":8080},");
    jw_raw(w, "{\"name\":\"Admin panel + WebDAV with an account (HTTPS, TLS 1.3)\",\"proto\":\"tcp\",\"port\":8443}");
    jw_raw(w, "],");
    if (fw) {
        jw_key(w, "firewall"); jw_raw(w, "{");
        jw_kb(w, "enabled", fw->enabled);
        jw_kb(w, "lan_only", fw->strict_rfc1918);
        jw_ku(w, "wan_rx_blocked", fw->wan_rx_blocked);
        jw_ku(w, "wan_tx_blocked", fw->wan_tx_blocked);
        jw_ku(w, "lan_accepted", fw->lan_packets_accepted);
        jw_close(w, "},");
    }
    jw_close(w, "}");
}

static U0 section_security(JW* w) {
    const IntegrityStatus* is = integrity_status();
    PmpState ps = pmp_get_state();
    jw_raw(w, "{");
    jw_ks(w, "pmp", ps == PMP_STATE_LOCKED_PROVEN ? "locked, Z3-proven" :
                    (ps == PMP_STATE_LOCKED_VERIFIED ? "locked, boot-verified" : "not configured"));
    jw_ku(w, "pmp_harts", pmp_locked_hart_count());
    jw_ku(w, "cells", cell_available_count());
    jw_kb(w, "keyhart", keyhart_available());
    json_vault(w);
    jw_key(w, "integrity"); jw_raw(w, "{");
    if (is) {
        jw_ks(w, "image", is->image_state == IMG_OK ? "matches build" :
                          (is->image_state == IMG_MISMATCH ? "DOES NOT MATCH build" :
                          (is->image_state == IMG_NO_HASH ? "no build hash" : "unknown")));
        jw_kb(w, "armed", is->armed);
        jw_ku(w, "chunks", is->chunks);
        jw_ku(w, "full_passes", is->full_passes);
        jw_kb(w, "alarm", is->alarm);
    }
    jw_close(w, "},");
    jw_kb(w, "entropy_hw", entropy_is_strong());
    jw_kb(w, "console_pin", security_pin_is_set());
#ifdef YESOS_DEV_REMOTE
    jw_kb(w, "dev_remote_build", TRUE);
#else
    jw_kb(w, "dev_remote_build", FALSE);
#endif
    jw_kb(w, "transport_encrypted", TRUE);   // the API is only served over HTTPS
    jw_ks(w, "transport", "TLS 1.3 (X25519, ChaCha20-Poly1305 / AES-128-GCM), self-signed ECDSA P-256 certificate");
    jw_close(w, "}");
}

static U0 section_session(JW* w, const char* sid) {
    // Called only after webadmin_check succeeded for this sid.
    WebSession* s = NULL;
    U8 raw[32], h[32];
    if (from_hex(sid, raw, sizeof(raw))) {
        yc_blake2b256_2(raw, sizeof(raw), NULL, 0, h);
        for (U32 i = 0; i < WA_MAX_SESSIONS; i++) {
            if (g_sessions[i].used && yc_ct_eq(g_sessions[i].sid_hash, h, 32)) s = &g_sessions[i];
        }
    }
    yc_wipe(raw, sizeof(raw));
    jw_raw(w, "{");
    if (s) {
        char csrf[65];
        to_hex(s->csrf, sizeof(s->csrf), csrf);
        jw_ks(w, "user", s->user);
        jw_ks(w, "csrf", csrf);
        U64 now = timer_get_uptime_ms();
        jw_ku(w, "idle_timeout_sec", WA_IDLE_MS / 1000);
        jw_ku(w, "expires_in_sec", (WA_ABSOLUTE_MS - (now - s->created_ms)) / 1000);
        yc_wipe((U8*)csrf, sizeof(csrf));
    }
    jw_close(w, "}");
}

// ----------------------------------------------------------------------------
// Audit log (RAM ring buffer; also printed on the console)
// ----------------------------------------------------------------------------

#define WA_AUDIT_MAX 64

typedef struct {
    U64  ms;
    U32  ip;
    Bool ok;
    char user[NAS_MAX_USERNAME_LEN];
    char text[96];
} AuditEntry;

static AuditEntry g_audit[WA_AUDIT_MAX];
static U32        g_audit_next = 0;
static U32        g_audit_count = 0;

static U0 audit(const char* user, U32 ip, Bool ok, const char* text) {
    AuditEntry* e = &g_audit[g_audit_next];
    MemSet(e, 0, sizeof(*e));
    e->ms = timer_get_uptime_ms();
    e->ip = ip;
    e->ok = ok;
    StrNCpy(e->user, user ? user : "-", sizeof(e->user) - 1);
    StrNCpy(e->text, text, sizeof(e->text) - 1);
    g_audit_next = (g_audit_next + 1) % WA_AUDIT_MAX;
    if (g_audit_count < WA_AUDIT_MAX) g_audit_count++;
    char ipb[20];
    fmt_ip(ip, ipb);
    kprintf("[WEBADMIN] %s %s@%s: %s\n", ok ? "OK  " : "DENY", e->user, ipb, e->text);
}

static U0 section_audit(JW* w) {
    jw_raw(w, "{\"entries\":[");
    for (U32 k = 0; k < g_audit_count; k++) {   // newest first
        const AuditEntry* e = &g_audit[(g_audit_next + WA_AUDIT_MAX - 1 - k) % WA_AUDIT_MAX];
        jw_raw(w, "{");
        jw_ku(w, "uptime_sec", e->ms / 1000);
        jw_nas_ip(w, "ip", e->ip);
        jw_ks(w, "user", e->user);
        jw_kb(w, "ok", e->ok);
        jw_ks(w, "text", e->text);
        jw_close(w, "},");
    }
    jw_close(w, "]}");
}

static SnapshotInfo g_snap_view[128];

static U0 section_snapshots(JW* w) {
    U32 minutes, keep;
    U64 next;
    snapshot_get_auto(&minutes, &keep, &next);
    RedSeaVolume* v = redsea_eml_get_volume();
    jw_raw(w, "{");
    jw_key(w, "auto"); jw_raw(w, "{");
    jw_ku(w, "interval_minutes", minutes);
    jw_ku(w, "keep", keep);
    jw_ku(w, "next_in_sec", next);
    jw_close(w, "},");
    jw_ku(w, "dir_entries_free", redsea_eml_free_entries());
    jw_ku(w, "entries_needed", snapshot_entries_needed());
    jw_raw(w, "\"scope\":[\"share\",\"media\",\"vault\"],");
    jw_key(w, "snapshots"); jw_raw(w, "[");
    U32 n = snapshot_list(g_snap_view, 128);
    for (U32 k = n; k-- > 0 && !w->overflow;) {   // newest first
        const SnapshotInfo* si = &g_snap_view[k];
        jw_raw(w, "{");
        jw_ku(w, "id", si->id);
        jw_kb(w, "automatic", si->automatic);
        jw_ks(w, "created_by", si->created_by);
        jw_ks(w, "client_time", si->client_time);
        jw_ks(w, "note", si->note);
        jw_ku(w, "files_count", si->files);
        jw_ku(w, "bytes", si->bytes);
        jw_ku(w, "unique_bytes", si->unique_bytes);
        char dir[24];
        ksnprintf(dir, sizeof(dir), SNAP_PREFIX "%04u/", si->id);
        size_t dl = StrLen(dir);
        jw_key(w, "files"); jw_raw(w, "[");
        for (U32 i = 0; v && i < v->entry_count && !w->overflow; i++) {
            const RedSeaFileEntry* e = &v->entries[i];
            if (!(e->flags & REDSEA_FLAG_USED) || StrNCmp(e->name, dir, dl) != 0) continue;
            if (!snapshot_in_scope(e->name + dl)) continue;
            jw_raw(w, "{");
            jw_ks(w, "path", e->name + dl);
            jw_ku(w, "bytes", e->byte_size);
            jw_ku(w, "crc", e->crc_euler);
            jw_ku(w, "lba", e->start_lba);
            jw_kb(w, "encrypted", (e->flags & REDSEA_FLAG_ENCRYPTED) != 0);
            jw_close(w, "},");
        }
        jw_close(w, "]},");
    }
    jw_close(w, "]}");
}

I32 webadmin_json(const char* section, const char* sid, char* buf, size_t max) {
    if (!section || !buf || max < 4) return -2;
    JW w = { buf, 0, max, FALSE };
    buf[0] = '\0';
    if (StrCmp(section, "overview") == 0) section_overview(&w);
    else if (StrCmp(section, "storage") == 0) section_storage(&w);
    else if (StrCmp(section, "shares") == 0) section_shares(&w);
    else if (StrCmp(section, "users") == 0) section_users(&w);
    else if (StrCmp(section, "devices") == 0) section_devices(&w);
    else if (StrCmp(section, "network") == 0) section_network(&w);
    else if (StrCmp(section, "security") == 0) section_security(&w);
    else if (StrCmp(section, "session") == 0) section_session(&w, sid);
    else if (StrCmp(section, "audit") == 0) section_audit(&w);
    else if (StrCmp(section, "snapshots") == 0) section_snapshots(&w);
    else return -1;
    return w.overflow ? -2 : (I32)w.n;
}

// ----------------------------------------------------------------------------
// HTTPS certificate key
// ----------------------------------------------------------------------------

#define TLS_KEY_FILE "SYS/TLS.KEY"

static Bool g_tls_ready = FALSE;

Bool webadmin_tls_ready(U0) {
    return g_tls_ready;
}

static U0 print_fingerprint(const U8* fp) {
    char out[32 * 3];
    static const char H[] = "0123456789ABCDEF";
    for (U32 i = 0; i < 32; i++) {
        out[i * 3] = H[fp[i] >> 4];
        out[i * 3 + 1] = H[fp[i] & 15];
        out[i * 3 + 2] = (i == 31) ? '\0' : ':';
    }
    kprintf("[TLS]   SHA-256 %s\n", out);
}

U0 webadmin_tls_init(U0) {
    U8 key[32], fp[32], ip[4] = { 127, 0, 0, 1 };
    VirtIONetInfo* ni = virtio_net_get_info();
    if (ni && ni->is_present) MemCpy(ip, &ni->ip, 4);   // virtio_net keeps the address in network order

    size_t sz = 0;
    U8* data = vfs_read_file(TLS_KEY_FILE, &sz);
    Bool loaded = FALSE;
    if (data) {
        if (sz == sizeof(key)) {
            MemCpy(key, data, sizeof(key));
            loaded = TRUE;
        }
        yc_wipe(data, sz);
        Free(data);
    }
    I32 r = loaded ? yc_tls_init(key, ip, fp) : -1;
    for (U32 tries = 0; r == -1 && tries < 4; tries++) {
        // New key (an invalid scalar is astronomically unlikely; retry anyway).
        loaded = FALSE;
        if (!entropy_random(key, sizeof(key))) {
            kprintf("[TLS] ERROR: cannot generate the certificate key (entropy unavailable); HTTPS disabled.\n");
            yc_wipe(key, sizeof(key));
            return;
        }
        r = yc_tls_init(key, ip, fp);
        if (r == 0 && !vfs_write_file(TLS_KEY_FILE, key, sizeof(key))) {
            kprintf("[TLS] WARNING: could not persist %s; the certificate changes on reboot.\n", TLS_KEY_FILE);
        }
    }
    yc_wipe(key, sizeof(key));
    if (r != 0) {
        kprintf("[TLS] ERROR: TLS configuration failed (%d); HTTPS disabled.\n", r);
        return;
    }
    g_tls_ready = TRUE;
    kprintf("[TLS] HTTPS admin panel on TCP %u (TLS 1.3, %s self-signed ECDSA P-256 certificate).\n",
            WEBADMIN_HTTPS_PORT, loaded ? "persisted" : "new");
    kprintf("[TLS] Check this fingerprint in the browser before logging in:\n");
    print_fingerprint(fp);
}

U0 webadmin_print_tls(U0) {
    U8 fp[32];
    if (!g_tls_ready || yc_tls_fingerprint(fp) != 0) {
        kprintf("[TLS] HTTPS is not available.\n");
        return;
    }
    char ipb[20] = "<ip>";
    VirtIONetInfo* ni = virtio_net_get_info();
    if (ni && ni->is_present) net_format_ip(ni->ip, ipb, sizeof(ipb));
    kprintf("[TLS] Admin panel: https://%s:%u/  (TLS 1.3 only)\n", ipb, WEBADMIN_HTTPS_PORT);
    kprintf("[TLS] Self-signed certificate (key in %s). Browsers warn once; accept it only if\n", TLS_KEY_FILE);
    kprintf("[TLS] the fingerprint they show matches:\n");
    print_fingerprint(fp);
}

// ----------------------------------------------------------------------------
// Actions
// ----------------------------------------------------------------------------

static Bool valid_chars(const char* s, size_t min, size_t max, const char* extra) {
    size_t n = StrLen(s);
    if (n < min || n > max) return FALSE;
    for (const char* c = s; *c; c++) {
        Bool ok = (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9');
        for (const char* x = extra; !ok && *x; x++) ok = (*c == *x);
        if (!ok) return FALSE;
    }
    return TRUE;
}

static Bool parse_role(const char* r, U8* out) {
    if (StrCmp(r, "admin") == 0) { *out = NAS_ROLE_ADMIN; return TRUE; }
    if (StrCmp(r, "rw") == 0) { *out = NAS_ROLE_RW; return TRUE; }
    if (StrCmp(r, "ro") == 0) { *out = NAS_ROLE_RO; return TRUE; }
    return FALSE;
}

// Dotted IPv4 in the private LAN ranges the firewall accepts (no 0.x / broadcast).
static Bool parse_lan_ip(const char* s, U32* out) {
    U32 parts[4] = { 0 }, n = 0, digits = 0;
    for (const char* c = s; ; c++) {
        if (*c >= '0' && *c <= '9') {
            parts[n] = parts[n] * 10 + (U32)(*c - '0');
            if (++digits > 3 || parts[n] > 255) return FALSE;
        } else if ((*c == '.' || *c == '\0') && digits) {
            n++;
            digits = 0;
            if (*c == '\0') break;
            if (n == 4) return FALSE;
        } else {
            return FALSE;
        }
    }
    if (n != 4) return FALSE;
    U32 ip = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    if ((ip & 0xFF) == 0 || (ip & 0xFF) == 255) return FALSE;
    if (!firewall_is_lan_ip(ip) && ip != 0x0A000202) return FALSE;   // 10.0.2.2: QEMU host
    *out = ip;
    return TRUE;
}

// Closes every web session of `user` except `keep` (may be NULL).
static U0 close_sessions_of(const char* user, const WebSession* keep) {
    for (U32 i = 0; i < WA_MAX_SESSIONS; i++) {
        WebSession* s = &g_sessions[i];
        if (s->used && s != keep && StrCmp(s->user, user) == 0) session_clear(s);
    }
}

U0 webadmin_close_sessions_of(const char* user) {
    close_sessions_of(user, NULL);
}

#define RESULT(code, ...) do { ksnprintf(msg, msg_max, __VA_ARGS__); status = (code); } while (0)

I32 webadmin_action(const char* sid, U32 ip, const char* action, const char* const* f,
                    char* msg, size_t msg_max) {
    WebSession* me = session_find(sid, ip);
    if (!me || !action || !f || !msg || msg_max < 16) return 403;
    char who[NAS_MAX_USERNAME_LEN];
    StrNCpy(who, me->user, sizeof(who) - 1);
    who[sizeof(who) - 1] = '\0';
    I32 status = 500;
    char what[96];
    ksnprintf(what, sizeof(what), "%s", action);

    const char* name = f[WA_F_NAME];
    U8 role = 0;

    if (StrCmp(action, "user_add") == 0) {
        ksnprintf(what, sizeof(what), "create user '%s' (%s)", name, f[WA_F_ROLE]);
        if (!valid_chars(name, 1, NAS_MAX_USERNAME_LEN - 1, "._-")) RESULT(400, "Invalid name: 1-31 characters, letters, digits, dot, hyphen or underscore.");
        else if (!parse_role(f[WA_F_ROLE], &role)) RESULT(400, "Invalid role.");
        else if (StrLen(f[WA_F_PASSWORD]) < NAS_MIN_PASSWORD_LEN || StrLen(f[WA_F_PASSWORD]) >= NAS_MAX_PASSWORD_LEN)
            RESULT(400, "The password must have %u to %u characters.", NAS_MIN_PASSWORD_LEN, NAS_MAX_PASSWORD_LEN - 1);
        else if (nas_user_get_by_name(name)) RESULT(409, "A user '%s' already exists.", name);
        else if (nas_user_get_state()->user_count >= NAS_MAX_USERS) RESULT(409, "No room for more accounts (%u at most).", NAS_MAX_USERS);
        else if (nas_user_add(name, f[WA_F_PASSWORD], role)) RESULT(200, "User '%s' created.", name);
        else RESULT(500, "The user could not be created.");
    } else if (StrCmp(action, "user_delete") == 0) {
        ksnprintf(what, sizeof(what), "delete user '%s'", name);
        if (!nas_user_get_by_name(name)) RESULT(404, "No such user '%s'.", name);
        else if (StrCmp(name, who) == 0) RESULT(403, "You cannot delete your own account.");
        else if (nas_user_remove(name)) { close_sessions_of(name, NULL); RESULT(200, "User '%s' deleted.", name); }
        else RESULT(409, "'%s' could not be deleted (at least one admin must remain).", name);
    } else if (StrCmp(action, "user_role") == 0) {
        ksnprintf(what, sizeof(what), "change the role of '%s' to %s", name, f[WA_F_ROLE]);
        if (!nas_user_get_by_name(name)) RESULT(404, "No such user '%s'.", name);
        else if (!parse_role(f[WA_F_ROLE], &role)) RESULT(400, "Invalid role.");
        else if (StrCmp(name, who) == 0 && role != NAS_ROLE_ADMIN) RESULT(403, "You cannot remove the admin role from yourself.");
        else if (nas_user_set_role(name, role)) { if (role != NAS_ROLE_ADMIN) close_sessions_of(name, NULL); RESULT(200, "Role of '%s' updated.", name); }
        else RESULT(409, "The role could not be changed (at least one admin must remain).");
    } else if (StrCmp(action, "user_password") == 0) {
        ksnprintf(what, sizeof(what), "change the password of '%s'", name);
        Bool self = StrCmp(name, who) == 0;
        NASUser* u = nas_user_get_by_name(name);
        NASUser* chk = NULL;
        if (!u) RESULT(404, "No such user '%s'.", name);
        else if (StrLen(f[WA_F_PASSWORD]) < NAS_MIN_PASSWORD_LEN || StrLen(f[WA_F_PASSWORD]) >= NAS_MAX_PASSWORD_LEN)
            RESULT(400, "The password must have %u to %u characters.", NAS_MIN_PASSWORD_LEN, NAS_MAX_PASSWORD_LEN - 1);
        else if (self && !nas_user_authenticate(who, f[WA_F_CURRENT], &chk)) RESULT(403, "The current password is not correct.");
        else if (nas_user_change_password(name, f[WA_F_PASSWORD])) {
            close_sessions_of(name, self ? me : NULL);   // other sessions of that account end
            RESULT(200, "Password of '%s' updated.", name);
        } else RESULT(500, "The password could not be changed.");
    } else if (StrCmp(action, "auth_required") == 0) {
        Bool on = StrCmp(f[WA_F_VALUE], "on") == 0;
        ksnprintf(what, sizeof(what), "NAS protocol authentication: %s", on ? "required" : "off");
        if (!on && StrCmp(f[WA_F_VALUE], "off") != 0) RESULT(400, "Invalid value.");
        else { nas_user_set_auth_required(on); nas_config_save(); RESULT(200, "NAS protocol authentication %s.", on ? "enabled" : "disabled"); }
    } else if (StrCmp(action, "device_admit") == 0 || StrCmp(action, "device_block") == 0) {
        Bool admit = action[7] == 'a';
        U32 target = 0;
        ksnprintf(what, sizeof(what), "%s device %s", admit ? "admit" : "block", f[WA_F_IP]);
        if (!parse_lan_ip(f[WA_F_IP], &target)) RESULT(400, "Invalid IP: it must be an address on the local network.");
        else if (!admit && target == ip) RESULT(403, "You cannot block the machine you are administering from.");
        else if (admit && f[WA_F_NAME][0] && !valid_chars(f[WA_F_NAME], 1, 31, "._- ")) RESULT(400, "Invalid device name.");
        else if (admit && security_pin_is_locked()) RESULT(403, "The console is locked with the PIN: no devices can be admitted.");
        else if (admit ? nas_admit_client_ip(target, f[WA_F_NAME]) : nas_block_client_ip(target))
            RESULT(200, "Device %s %s.", f[WA_F_IP], admit ? "admitted" : "blocked");
        else RESULT(admit ? 409 : 404, admit ? "No room for more devices." : "Unknown device.");
    } else if (StrCmp(action, "share_add") == 0) {
        ksnprintf(what, sizeof(what), "create shared folder '%s' -> %s", name, f[WA_F_PATH]);
        const char* path = f[WA_F_PATH];
        Bool bad_path = path[0] != '/' || !valid_chars(path, 2, 63, "/_.-") || StrNICmp(path, "/sys", 4) == 0 ||
                        StrNICmp(path, "/vault", 6) == 0;
        for (const char* c = path; *c && !bad_path; c++) bad_path = (c[0] == '.' && c[1] == '.');
        if (!valid_chars(name, 1, 31, "_-")) RESULT(400, "Invalid name: letters, digits, hyphen or underscore.");
        else if (bad_path) RESULT(400, "Invalid path: absolute, no '..', outside /SYS and /vault.");
        else if (f[WA_F_COMMENT][0] && !valid_chars(f[WA_F_COMMENT], 1, 63, " ._-,()")) RESULT(400, "Invalid comment.");
        else if (nas_add_share(name, path, StrCmp(f[WA_F_READONLY], "on") == 0, f[WA_F_COMMENT]))
            RESULT(200, "Folder '%s' saved.", name);
        else RESULT(409, "No room for more shared folders.");
    } else if (StrCmp(action, "share_delete") == 0) {
        ksnprintf(what, sizeof(what), "delete shared folder '%s'", name);
        if (nas_remove_share(name)) RESULT(200, "Folder '%s' deleted.", name);
        else RESULT(404, "No such folder '%s'.", name);
    } else if (StrNCmp(action, "snapshot_", 9) == 0) {
        U32 id = 0;
        for (const char* c = f[WA_F_NAME]; *c >= '0' && *c <= '9' && id < 100000; c++) id = id * 10 + (U32)(*c - '0');
        if (StrCmp(action, "snapshot_create") == 0) {
            ksnprintf(what, sizeof(what), "create snapshot%s%s", f[WA_F_COMMENT][0] ? ": " : "", f[WA_F_COMMENT]);
            if (StrLen(f[WA_F_COMMENT]) > 63 || StrLen(f[WA_F_VALUE]) > 31) RESULT(400, "Note or date too long.");
            else if (snapshot_create(who, f[WA_F_COMMENT], f[WA_F_VALUE], FALSE, NULL, msg, msg_max)) status = 200;
            else status = 409;
        } else if (StrCmp(action, "snapshot_delete") == 0) {
            ksnprintf(what, sizeof(what), "delete snapshot %u", id);
            status = snapshot_delete(id, msg, msg_max) ? 200 : 404;
        } else if (StrCmp(action, "snapshot_restore") == 0) {
            ksnprintf(what, sizeof(what), "restore %s from snapshot %u", f[WA_F_PATH][0] ? f[WA_F_PATH] : "everything", id);
            status = snapshot_restore(id, f[WA_F_PATH], msg, msg_max) ? 200 : 409;
        } else if (StrCmp(action, "snapshot_auto") == 0) {
            U32 minutes = 0, keep = 0;
            const char* c = f[WA_F_VALUE];
            while (*c >= '0' && *c <= '9' && minutes < 1000000) minutes = minutes * 10 + (U32)(*c++ - '0');
            if (*c == ':') c++;
            while (*c >= '0' && *c <= '9' && keep < 1000) keep = keep * 10 + (U32)(*c++ - '0');
            ksnprintf(what, sizeof(what), "automatic snapshots: every %u min, keep %u", minutes, keep);
            status = snapshot_set_auto(minutes, keep, msg, msg_max) ? 200 : 400;
        } else {
            RESULT(404, "Unknown action.");
        }
    } else if (StrCmp(action, "export_begin") == 0 || StrCmp(action, "import_begin") == 0) {
        Bool exp = action[0] == 'e';
        U32 id = 0;
        for (const char* c = f[WA_F_NAME]; *c >= '0' && *c <= '9' && id < 100000; c++) id = id * 10 + (U32)(*c - '0');
        ksnprintf(what, sizeof(what), exp ? "replica: export snapshot %u" : "replica: restore %u files into this NAS", id);
        RESULT(200, exp ? "Export of snapshot %u recorded." : "Restore of %u files recorded.", id);
    } else if (StrCmp(action, "fs_check") == 0) {
        ksnprintf(what, sizeof(what), "check the file system");
        RedSeaFsckReport r;
        if (redsea_eml_fsck(TRUE, TRUE, &r)) {
            RESULT(200, "File system OK: %u files, %u good CRCs (%u with the old CRC), no errors.",
                   r.files, r.crc_ok + r.crc_legacy, r.crc_legacy);
        } else {
            RESULT(409, "%u error(s) found. First: %s", r.errors, r.first_problem);
        }
    } else if (StrCmp(action, "vault_lock") == 0) {
        ksnprintf(what, sizeof(what), "lock the vault");
        if (!vault_is_initialized()) RESULT(409, "The vault has not been created.");
        else if (!vault_is_unlocked()) RESULT(200, "The vault was already locked.");
        else { vault_lock(); RESULT(200, "Vault locked: the key was erased from the key hart."); }
    } else {
        RESULT(404, "Unknown action.");
    }
    audit(who, ip, status == 200, what);
    return status;
}

// ----------------------------------------------------------------------------
// WebDAV login
// ----------------------------------------------------------------------------

#define WD_CACHE_SLOTS 16
#define WD_CACHE_MS    (10ULL * 60 * 1000)

typedef struct {
    Bool used;
    U8   key[32];                      // BLAKE2b(per-boot secret || user || 0 || password)
    U32  ip;
    U64  expires_ms;
    char user[NAS_MAX_USERNAME_LEN];
} DavCacheEntry;

static DavCacheEntry g_dav_cache[WD_CACHE_SLOTS];
static U8            g_dav_secret[32];
static Bool          g_dav_secret_ready = FALSE;

U0 webdav_auth_flush(U0) {
    yc_wipe((U8*)g_dav_cache, sizeof(g_dav_cache));
}

U32 webdav_share_mask_bit(const char* share) {
    // Bits of NASUser.allowed_shares_mask: 0 = /share, 1 = /media, 2 = /backup.
    if (!share || !share[0]) return 0;
    if (StrICmp(share, "media") == 0) return 1u << 1;
    if (StrICmp(share, "backup") == 0) return 1u << 2;
    return 1u << 0;   // "share" and any other prefix (stored under share/)
}

static Bool dav_cache_key(const char* user, const char* pass, U8* out) {
    if (!g_dav_secret_ready) {
        if (yc_rng_fill(g_dav_secret, sizeof(g_dav_secret)) != YC_OK) return FALSE;
        g_dav_secret_ready = TRUE;
    }
    U8 buf[NAS_MAX_USERNAME_LEN + NAS_MAX_PASSWORD_LEN + 1];
    size_t ul = StrLen(user), pl = StrLen(pass);
    if (ul >= NAS_MAX_USERNAME_LEN || pl >= NAS_MAX_PASSWORD_LEN) return FALSE;
    MemCpy(buf, user, ul);
    buf[ul] = 0;
    MemCpy(buf + ul + 1, pass, pl);
    yc_blake2b256_2(g_dav_secret, sizeof(g_dav_secret), buf, ul + 1 + pl, out);
    yc_wipe(buf, sizeof(buf));
    return TRUE;
}

I32 webdav_authorize(const char* user, const char* pass, U32 ip, const char* share, Bool write) {
    if (!user || !pass || !user[0]) return 401;
    if (StrICmp(share ? share : "", "vault") == 0) return 403;   // never over WebDAV
    if (webadmin_throttle_remaining(ip)) return 429;

    U8 key[32];
    Bool keyed = dav_cache_key(user, pass, key);
    U64 now = timer_get_uptime_ms();
    Bool cached = FALSE;
    for (U32 i = 0; keyed && i < WD_CACHE_SLOTS; i++) {
        DavCacheEntry* e = &g_dav_cache[i];
        if (e->used && now >= e->expires_ms) yc_wipe((U8*)e, sizeof(*e));
        if (e->used && e->ip == ip && yc_ct_eq(e->key, key, 32) && StrCmp(e->user, user) == 0) cached = TRUE;
    }

    char ipb[20];
    fmt_ip(ip, ipb);
    if (!cached) {
        NASUser* u0 = NULL;
        Bool ok = nas_user_authenticate(user, pass, &u0);
        LoginThrottle* t = throttle_slot(ip, TRUE);
        t->last_ms = now;
        if (!ok) {
            if (++t->fails >= WA_THROTTLE_FAILS) {
                t->until_ms = now + WA_THROTTLE_MS;
                t->fails = 0;
                kprintf("[WEBDAV] %u failed logins from %s: throttled for 30 s\n", WA_THROTTLE_FAILS, ipb);
            }
            yc_wipe(key, sizeof(key));
            return 401;
        }
        t->fails = 0;
        if (keyed) {
            DavCacheEntry* slot = &g_dav_cache[0];
            for (U32 i = 0; i < WD_CACHE_SLOTS; i++) {
                if (!g_dav_cache[i].used) { slot = &g_dav_cache[i]; break; }
                if (g_dav_cache[i].expires_ms < slot->expires_ms) slot = &g_dav_cache[i];
            }
            MemSet(slot, 0, sizeof(*slot));
            slot->used = TRUE;
            MemCpy(slot->key, key, 32);
            slot->ip = ip;
            slot->expires_ms = now + WD_CACHE_MS;
            StrNCpy(slot->user, user, sizeof(slot->user) - 1);
        }
        kprintf("[WEBDAV] '%s' logged in from %s\n", user, ipb);
    }
    yc_wipe(key, sizeof(key));

    NASUser* u = nas_user_get_by_name(user);
    if (!u || !u->active) return 401;
    U32 bit = webdav_share_mask_bit(share);
    if (bit && !(u->allowed_shares_mask & bit)) return 403;
    if (write && u->role == NAS_ROLE_RO) return 403;
    return 0;
}

// ----------------------------------------------------------------------------
// Replication export / import
// ----------------------------------------------------------------------------

static Bool replication_path_ok(const char* path) {
    size_t n = StrLen(path);
    if (n == 0 || n + 20 >= REDSEA_MAX_FILENAME || !snapshot_in_scope(path)) return FALSE;
    for (const char* c = path; *c; c++) {
        if ((U8)*c < 0x20 || *c == 0x7F || *c == '\\') return FALSE;
        if (c[0] == '.' && c[1] == '.') return FALSE;
        if (c[0] == '/' && c[1] == '/') return FALSE;
    }
    return path[n - 1] != '/';
}

I32 webadmin_export_file(U32 snap_id, const char* path, U8** out, size_t* out_len) {
    *out = NULL;
    *out_len = 0;
    if (!snap_id || !path || !replication_path_ok(path)) return 400;
    char name[REDSEA_MAX_FILENAME + 32];
    ksnprintf(name, sizeof(name), SNAP_PREFIX "%04u/%s", snap_id, path);
    size_t sz = 0;
    U8* data = redsea_eml_read_file(name, &sz);   // raw bytes: vault files stay ciphertext
    if (!data) return 404;
    *out = data;
    *out_len = sz;
    return 0;
}

static const char* session_user(const char* sid, U32 ip, char* buf, size_t max) {
    WebSession* me = session_find(sid, ip);
    StrNCpy(buf, me ? me->user : "-", max - 1);
    buf[max - 1] = '\0';
    return buf;
}

I32 webadmin_export_vault_header(const char* sid, U32 ip, U8** out, size_t* out_len) {
    char who[NAS_MAX_USERNAME_LEN];
    session_user(sid, ip, who, sizeof(who));
    *out = vault_export_header(out_len);
    audit(who, ip, *out != NULL, "replica: export the vault header");
    return *out ? 0 : 404;
}

I32 webadmin_import_file(const char* sid, U32 ip, const char* path, const U8* data, size_t len,
                         char* msg, size_t msg_max) {
    char who[NAS_MAX_USERNAME_LEN];
    session_user(sid, ip, who, sizeof(who));
    if (!path || !replication_path_ok(path)) {
        ksnprintf(msg, msg_max, "Invalid path (share/, media/ or vault/).");
        return 400;
    }
    if (len > 16 * 1024 * 1024) {
        ksnprintf(msg, msg_max, "File too large (16 MiB at most).");
        return 400;
    }
    U32 flags = 0;
    if (StrNICmp(path, "vault/", 6) == 0) {
        if (!vault_is_initialized()) {
            ksnprintf(msg, msg_max, "Restore the vault header first.");
            return 409;
        }
        if (!vault_blob_plausible(data, len)) {
            ksnprintf(msg, msg_max, "Not an encrypted vault file.");
            return 400;
        }
        flags = REDSEA_FLAG_ENCRYPTED;
    }
    static const U8 empty = 0;
    if (!redsea_eml_write_file_path(path, len ? data : &empty, len, flags)) {
        ksnprintf(msg, msg_max, "'%s' could not be written (disk or directory full).", path);
        return 507;
    }
    kprintf("[REPLICA] %s restored '%s' (%u bytes)\n", who, path, (U32)len);
    ksnprintf(msg, msg_max, "Restored '%s'.", path);
    return 200;
}

I32 webadmin_import_vault_header(const char* sid, U32 ip, const U8* data, size_t len,
                                 char* msg, size_t msg_max) {
    char who[NAS_MAX_USERNAME_LEN];
    session_user(sid, ip, who, sizeof(who));
    VaultResult r = vault_import_header(data, len);
    I32 status = 200;
    if (r == VAULT_OK) ksnprintf(msg, msg_max, "Vault header restored: unlock it with its passphrase.");
    else if (r == VAULT_ERR_ALREADY_INITIALIZED) { ksnprintf(msg, msg_max, "This NAS already has a vault; it is not overwritten."); status = 409; }
    else { ksnprintf(msg, msg_max, "Invalid header (%s).", vault_result_str(r)); status = 400; }
    audit(who, ip, status == 200, "replica: restore the vault header");
    return status;
}
