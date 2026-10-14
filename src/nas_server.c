#include "yesos_crypto.h"
#include "vault.h"
#include "nas_server.h"
#include "nas_user.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"
#include "vfs.h"
#include "ramfs.h"
#include "redsea_eml.h"

static U0 nas_refresh_pool(U0);
#include "speaker.h"
#include "security_pin.h"

// ============================================================================
// YesOS 2.0 - Network Attached Storage (NAS) Daemon Implementation
// ============================================================================

static NASServerState g_nas_state;

static U0 nas_load_default_shares(U0) {
    StrNCpy(g_nas_state.server_name, "YesOS-Storage", 31);
    StrNCpy(g_nas_state.workgroup, "WORKGROUP", 31);
    g_nas_state.shares_count = 3;

    // Share 1: Private Encrypted Vault
    StrNCpy(g_nas_state.shares[0].share_name, "vault", 31);
    StrNCpy(g_nas_state.shares[0].mount_path, "/vault", 63);
    StrNCpy(g_nas_state.shares[0].comment, "Confidential Storage & DB", 63);
    g_nas_state.shares[0].total_mb = 1024;
    g_nas_state.shares[0].used_mb  = 92;
    g_nas_state.shares[0].read_only = FALSE;
    g_nas_state.shares[0].active = TRUE;

    // Share 2: Documents & Notes
    StrNCpy(g_nas_state.shares[1].share_name, "share", 31);
    StrNCpy(g_nas_state.shares[1].mount_path, "/home/documents", 63);
    StrNCpy(g_nas_state.shares[1].comment, "Public Documents & Notes", 63);
    g_nas_state.shares[1].total_mb = 512;
    g_nas_state.shares[1].used_mb  = 18;
    g_nas_state.shares[1].read_only = FALSE;
    g_nas_state.shares[1].active = TRUE;

    // Share 3: Media & Audio Jukebox
    StrNCpy(g_nas_state.shares[2].share_name, "media", 31);
    StrNCpy(g_nas_state.shares[2].mount_path, "/MUSIC", 63);
    StrNCpy(g_nas_state.shares[2].comment, "Music Library", 63);
    g_nas_state.shares[2].total_mb = 1024;
    g_nas_state.shares[2].used_mb  = 340;
    g_nas_state.shares[2].read_only = TRUE;
    g_nas_state.shares[2].active = TRUE;
}

Bool nas_config_save(U0) {
    char buf[2048];
    MemSet(buf, 0, sizeof(buf));
    int pos = 0;

    pos += ksnprintf(buf + pos, sizeof(buf) - pos,
                     "# ====================================================================\n"
                     "# YesOS NAS - shared folders of the NAS protocol and WebDAV (SYS/SMB.CFG)\n"
                     "# Ring-0 Bare-Metal Declarative Storage Policy\n"
                     "# ====================================================================\n\n"
                     "[server]\n"
                     "  name = %s\n"
                     "  workgroup = %s\n"
                     "  auth = %s\n\n",
                     g_nas_state.server_name[0] ? g_nas_state.server_name : "YesOS-Storage",
                     g_nas_state.workgroup[0] ? g_nas_state.workgroup : "WORKGROUP",
                     nas_user_is_auth_required() ? "on" : "off");

    for (U32 i = 0; i < g_nas_state.shares_count; i++) {
        NASShare* s = &g_nas_state.shares[i];
        if (!s->active || !s->share_name[0]) continue;
        pos += ksnprintf(buf + pos, sizeof(buf) - pos,
                         "[%s]\n"
                         "  path = %s\n"
                         "  access = %s\n"
                         "  comment = %s\n\n",
                         s->share_name, s->mount_path,
                         s->read_only ? "ro" : "rw",
                         s->comment[0] ? s->comment : "Network Share");
    }

    Bool ok = vfs_write_file(NAS_SERVER_CONFIG_FILE, buf, (size_t)pos);
    if (ok) {
        kprintf("[NAS SHARES] Configuration saved to %s (%d bytes).\n", NAS_SERVER_CONFIG_FILE, pos);
    }
    return ok;
}

Bool nas_config_load(U0) {
    if (!vfs_exists(NAS_SERVER_CONFIG_FILE)) {
        nas_load_default_shares();
        nas_config_save();
        kprintf("[NAS SHARES] Initialized default configuration at %s\n", NAS_SERVER_CONFIG_FILE);
        return TRUE;
    }

    size_t sz = 0;
    U8* data = vfs_read_file(NAS_SERVER_CONFIG_FILE, &sz);
    if (!data || sz == 0) {
        if (data) Free(data);
        nas_load_default_shares();
        return FALSE;
    }

    // Reset current configuration
    StrNCpy(g_nas_state.server_name, "YesOS-Storage", 31);
    StrNCpy(g_nas_state.workgroup, "WORKGROUP", 31);
    g_nas_state.shares_count = 0;

    char current_section[32] = {0};
    NASShare* current_share = NULL;

    size_t idx = 0;
    while (idx < sz) {
        char line[128];
        size_t lpos = 0;
        while (idx < sz && data[idx] != '\n' && data[idx] != '\r' && lpos < sizeof(line) - 1) {
            line[lpos++] = (char)data[idx++];
        }
        line[lpos] = '\0';
        while (idx < sz && (data[idx] == '\n' || data[idx] == '\r')) {
            idx++;
        }

        // Trim leading spaces
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;

        // Ignore empty lines and comments
        if (*p == '\0' || *p == '#' || *p == ';') continue;

        // Check for section header [section]
        if (*p == '[') {
            p++;
            char* end = p;
            while (*end && *end != ']') end++;
            if (*end == ']') {
                *end = '\0';
                StrNCpy(current_section, p, 31);
                if (StrICmp(current_section, "server") == 0) {
                    current_share = NULL;
                } else {
                    current_share = NULL;
                    for (U32 s = 0; s < g_nas_state.shares_count; s++) {
                        if (StrICmp(g_nas_state.shares[s].share_name, current_section) == 0) {
                            current_share = &g_nas_state.shares[s];
                            break;
                        }
                    }
                    if (!current_share && g_nas_state.shares_count < NAS_MAX_SHARES) {
                        current_share = &g_nas_state.shares[g_nas_state.shares_count++];
                        MemSet(current_share, 0, sizeof(NASShare));
                        StrNCpy(current_share->share_name, current_section, 31);
                        current_share->total_mb = 1024;
                        current_share->used_mb = 10;
                        current_share->read_only = FALSE;
                        current_share->active = TRUE;
                        StrNCpy(current_share->comment, "Network Share", 63);
                    }
                }
            }
            continue;
        }

        // Parse key = value
        char* eq = p;
        while (*eq && *eq != '=') eq++;
        if (*eq == '=') {
            *eq = '\0';
            char* key = p;
            char* val = eq + 1;

            // Trim key trailing spaces
            char* k_end = key + StrLen(key) - 1;
            while (k_end >= key && (*k_end == ' ' || *k_end == '\t')) *k_end-- = '\0';

            // Trim val leading spaces
            while (*val == ' ' || *val == '\t') val++;
            // Trim val trailing spaces
            char* v_end = val + StrLen(val) - 1;
            while (v_end >= val && (*v_end == ' ' || *v_end == '\t' || *v_end == '\r')) *v_end-- = '\0';

            if (current_share) {
                if (StrICmp(key, "path") == 0) {
                    StrNCpy(current_share->mount_path, val, 63);
                } else if (StrICmp(key, "access") == 0) {
                    if (StrICmp(val, "ro") == 0 || StrICmp(val, "readonly") == 0) {
                        current_share->read_only = TRUE;
                    } else {
                        current_share->read_only = FALSE;
                    }
                } else if (StrICmp(key, "comment") == 0) {
                    StrNCpy(current_share->comment, val, 63);
                }
            } else if (StrICmp(current_section, "server") == 0) {
                if (StrICmp(key, "name") == 0) {
                    StrNCpy(g_nas_state.server_name, val, 31);
                } else if (StrICmp(key, "workgroup") == 0) {
                    StrNCpy(g_nas_state.workgroup, val, 31);
                } else if (StrICmp(key, "auth") == 0) {
                    if (StrICmp(val, "on") == 0 || StrICmp(val, "1") == 0 || StrICmp(val, "yes") == 0) {
                        nas_user_set_auth_required(TRUE);
                    } else {
                        nas_user_set_auth_required(FALSE);
                    }
                }
            }
        }
    }

    Free(data);

    // Ensure sovereign /vault share is present as share #01
    Bool has_vault = FALSE;
    for (U32 i = 0; i < g_nas_state.shares_count; i++) {
        if (StrICmp(g_nas_state.shares[i].share_name, "vault") == 0) {
            has_vault = TRUE;
            break;
        }
    }
    if (!has_vault) {
        if (g_nas_state.shares_count >= NAS_MAX_SHARES) {
            g_nas_state.shares_count = NAS_MAX_SHARES - 1;
        }
        for (U32 i = g_nas_state.shares_count; i > 0; i--) {
            g_nas_state.shares[i] = g_nas_state.shares[i - 1];
        }
        g_nas_state.shares_count++;
        NASShare* v = &g_nas_state.shares[0];
        MemSet(v, 0, sizeof(NASShare));
        StrNCpy(v->share_name, "vault", 31);
        StrNCpy(v->mount_path, "/vault", 63);
        StrNCpy(v->comment, "Confidential Storage & DB", 63);
        v->total_mb = 1024;
        v->used_mb = 92;
        v->read_only = FALSE;
        v->active = TRUE;
        nas_config_save();
    }

    // Remove legacy 'backup' share if present (managed by Backup Center)
    for (U32 i = 0; i < g_nas_state.shares_count; i++) {
        if (StrICmp(g_nas_state.shares[i].share_name, "backup") == 0) {
            for (U32 j = i; j < g_nas_state.shares_count - 1; j++) {
                g_nas_state.shares[j] = g_nas_state.shares[j + 1];
            }
            g_nas_state.shares_count--;
            nas_config_save();
            break;
        }
    }

    kprintf("[NAS SHARES] Loaded declarative configuration from %s (%u shares active).\n",
            NAS_SERVER_CONFIG_FILE, g_nas_state.shares_count);
    return TRUE;
}

Bool nas_add_share(const char* name, const char* path, Bool read_only, const char* comment) {
    if (!name || !*name || !path || !*path) return FALSE;

    for (U32 i = 0; i < g_nas_state.shares_count; i++) {
        if (StrICmp(g_nas_state.shares[i].share_name, name) == 0) {
            StrNCpy(g_nas_state.shares[i].mount_path, path, 63);
            g_nas_state.shares[i].read_only = read_only;
            if (comment && *comment) StrNCpy(g_nas_state.shares[i].comment, comment, 63);
            g_nas_state.shares[i].active = TRUE;
            nas_config_save();
            kprintf("[NAS SHARES] Updated share '%s' -> %s [%s]\n", name, path, read_only ? "RO" : "RW");
            return TRUE;
        }
    }

    if (g_nas_state.shares_count >= NAS_MAX_SHARES) {
        kprintf("[NAS SHARES] Error: Maximum shares reached (%u)\n", NAS_MAX_SHARES);
        return FALSE;
    }

    NASShare* s = &g_nas_state.shares[g_nas_state.shares_count++];
    MemSet(s, 0, sizeof(NASShare));
    StrNCpy(s->share_name, name, 31);
    StrNCpy(s->mount_path, path, 63);
    s->total_mb = 1024;
    s->used_mb = 0;
    s->read_only = read_only;
    s->active = TRUE;
    if (comment && *comment) StrNCpy(s->comment, comment, 63);
    else StrNCpy(s->comment, "Shared Directory", 63);

    nas_config_save();
    kprintf("[NAS SHARES] Added share '%s' -> %s [%s]\n", name, path, read_only ? "RO" : "RW");
    return TRUE;
}

Bool nas_remove_share(const char* name) {
    if (!name || !*name) return FALSE;

    for (U32 i = 0; i < g_nas_state.shares_count; i++) {
        if (StrICmp(g_nas_state.shares[i].share_name, name) == 0) {
            for (U32 j = i; j < g_nas_state.shares_count - 1; j++) {
                g_nas_state.shares[j] = g_nas_state.shares[j + 1];
            }
            g_nas_state.shares_count--;
            nas_config_save();
            kprintf("[NAS SHARES] Removed share '%s'\n", name);
            return TRUE;
        }
    }
    kprintf("[NAS SHARES] Share '%s' not found.\n", name);
    return FALSE;
}

U0 nas_print_share_list(U0) {
    kprintf("\n======================== [ NAS SHARED FOLDERS ] ========================\n");
    kprintf(" #   SHARE         PATH              ACCESS    COMMENT\n");
    kprintf("------------------------------------------------------------------------\n");
    for (U32 i = 0; i < g_nas_state.shares_count; i++) {
        NASShare* s = &g_nas_state.shares[i];
        kprintf(" [%u] /%-11s %-17s [%-2s]      %s\n",
                i + 1, s->share_name, s->mount_path,
                s->read_only ? "RO" : "RW",
                s->comment[0] ? s->comment : "-");
    }
    kprintf("========================================================================\n\n");
}

U0 nas_print_share_config(U0) {
    kprintf("\n--- Contents of %s ---\n", NAS_SERVER_CONFIG_FILE);
    if (!vfs_exists(NAS_SERVER_CONFIG_FILE)) {
        kprintf("(Configuration file does not exist on disk)\n");
        return;
    }
    size_t sz = 0;
    U8* data = vfs_read_file(NAS_SERVER_CONFIG_FILE, &sz);
    if (data) {
        for (size_t i = 0; i < sz; i++) {
            serial_putc((char)data[i]);
        }
        Free(data);
    }
    kprintf("\n------------------------------------------------------\n\n");
}

U0 nas_server_init(U0) {
    MemSet(&g_nas_state, 0, sizeof(NASServerState));

    nas_user_init();

    g_nas_state.is_running = TRUE;
    g_nas_state.start_tick = timer_get_ticks();
    nas_refresh_pool();

    // Load the shared folder configuration from SYS/SMB.CFG
    nas_config_load();

    // No pre-admitted devices: every client needs physical approval at the
    // console (`nas admit <ip>`) before it can open a session.
    g_nas_state.active_clients_count = 0;

    // Initialize Edge AI Subsystem

    kprintf("[NAS_SERVER] Storage Daemon Active on UDP Port %u (Pool: %u MB, %u Shares Mounted)\n",
            NAS_SERVER_PORT, (U32)g_nas_state.total_pool_mb, g_nas_state.shares_count);
    kprintf("[NAS_SECURITY] Physical-Only Device Admission Control ACTIVE [Zero-Trust LAN Mode]\n");
}

NASServerState* nas_server_get_state(U0) {
    return &g_nas_state;
}

// Pool figures come from the mounted RedSea volume (no invented numbers).
static U0 nas_refresh_pool(U0) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted) {
        g_nas_state.total_pool_mb = 0;
        g_nas_state.used_pool_mb = 0;
        return;
    }
    U64 total = v->sb.total_sectors;
    U64 free_s = redsea_eml_get_free_sectors();
    g_nas_state.total_pool_mb = (total * 512) / (1024 * 1024);
    g_nas_state.used_pool_mb = ((total > free_s ? total - free_s : 0) * 512) / (1024 * 1024);
}

static NASConnectedClient* find_or_register_client(U32 client_ip) {
    for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
        if (g_nas_state.clients[i].ip == client_ip) {
            g_nas_state.clients[i].last_seen_tick = timer_get_ticks();
            return &g_nas_state.clients[i];
        }
    }
    NASConnectedClient* c = NULL;
    if (g_nas_state.active_clients_count < NAS_MAX_CLIENTS) {
        c = &g_nas_state.clients[g_nas_state.active_clients_count++];
    } else {
        // Full: recycle the stalest PENDING entry so spoofed hellos cannot
        // lock out real devices. Admitted and blocked entries are kept.
        for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
            NASConnectedClient* e = &g_nas_state.clients[i];
            if (e->access_status == NAS_ACCESS_PENDING && (!c || e->last_seen_tick < c->last_seen_tick)) {
                c = e;
            }
        }
    }
    if (c) {
        MemSet(c, 0, sizeof(*c));
        c->ip = client_ip;
        c->last_seen_tick = timer_get_ticks();
        c->is_blocked = FALSE;
        c->access_status = NAS_ACCESS_PENDING; // NEW DEVICE: Requires physical admission on Orange Pi!
        c->auth_username[0] = '\0';
        c->is_authenticated = FALSE;
        c->user_role = NAS_ROLE_RO;
        ksnprintf(c->client_name, sizeof(c->client_name), "Node-%02X", (U32)(client_ip & 0xFF));
        kprintf("\n[NAS ADMISSION] ⚠️ UNREGISTERED DEVICE DETECTED: IP %u.%u.%u.%u (Status: PENDING PHYSICAL APPROVAL)\n",
                (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF, (client_ip >> 8) & 0xFF, client_ip & 0xFF);
        speaker_event(BEEP_WARN);
        return c;
    }
    // Table full: unknown devices are refused (callers treat NULL as denied).
    return NULL;
}

// Login state of each Noise session (indexed by the Rust session slot).
// Authentication is bound to the encrypted session, not to the client IP.
typedef struct {
    Bool authenticated;
    U8   role;
    char username[NAS_MAX_USERNAME_LEN];
} NASSessionCtx;

static NASSessionCtx g_nas_sessions[YC_NOISE_MAX_SESSIONS];

U0 nas_server_session_reset(U32 slot) {
    if (slot < YC_NOISE_MAX_SESSIONS) {
        MemSet(&g_nas_sessions[slot], 0, sizeof(NASSessionCtx));
        g_nas_sessions[slot].role = NAS_ROLE_RO;
    }
}

Bool nas_server_check_admission(U32 client_ip, char* out_resp) {
    NASConnectedClient* client = find_or_register_client(client_ip);
    if (!client) {
        ksnprintf(out_resp, 256, "ERR: ACCESS DENIED - DEVICE TABLE FULL");
        return FALSE;
    }
    if (client->is_blocked || client->access_status == NAS_ACCESS_BLOCKED) {
        ksnprintf(out_resp, 256, "ERR: ACCESS DENIED - CLIENT PERMANENTLY BLOCKED");
        return FALSE;
    }
    if (client->access_status != NAS_ACCESS_ADMITTED) {
        ksnprintf(out_resp, 256, "ERR: ACCESS DENIED - DEVICE NOT ADMITTED (PHYSICAL APPROVAL REQUIRED ON YESOS CONSOLE)");
        return FALSE;
    }
    return TRUE;
}

static Bool nas_process_command(U16 cmd_type, const char* payload, U32 payload_len, U32 client_ip,
                                NASSessionCtx* sess, char* out_resp, U32* out_resp_len);

// Plaintext path: only NAS_INFO (and device registration for admission).
Bool nas_server_process_remote_command(U16 cmd_type, const char* payload, U32 payload_len,
                                       U32 client_ip, char* out_resp, U32* out_resp_len) {
    if (!out_resp || !out_resp_len) return FALSE;
    if (cmd_type != NAS_CMD_INFO) {
        find_or_register_client(client_ip);
        ksnprintf(out_resp, 256, "ERR: SECURE CHANNEL REQUIRED - USE NOISE NK (tools/nas_client.py)");
        *out_resp_len = (U32)StrLen(out_resp);
        return FALSE;
    }
    return nas_process_command(cmd_type, payload, payload_len, client_ip, NULL, out_resp, out_resp_len);
}

Bool nas_server_process_secure_command(U32 slot, U16 cmd_type, const char* payload, U32 payload_len,
                                       U32 client_ip, char* out_resp, U32* out_resp_len) {
    if (!out_resp || !out_resp_len || slot >= YC_NOISE_MAX_SESSIONS) return FALSE;
    return nas_process_command(cmd_type, payload, payload_len, client_ip, &g_nas_sessions[slot],
                               out_resp, out_resp_len);
}

static Bool nas_process_command(U16 cmd_type, const char* payload, U32 payload_len, U32 client_ip,
                                NASSessionCtx* sess, char* out_resp, U32* out_resp_len) {
    NASConnectedClient* client = find_or_register_client(client_ip);
    if (!client) {
        ksnprintf(out_resp, 256, "ERR: ACCESS DENIED - DEVICE TABLE FULL");
        *out_resp_len = (U32)StrLen(out_resp);
        return FALSE;
    }
    if (client->is_blocked || client->access_status == NAS_ACCESS_BLOCKED) {
        ksnprintf(out_resp, 256, "ERR: ACCESS DENIED - CLIENT PERMANENTLY BLOCKED");
        *out_resp_len = (U32)StrLen(out_resp);
        return FALSE;
    }

    // ZERO-TRUST PHYSICAL ADMISSION CHECK
    if (client->access_status != NAS_ACCESS_ADMITTED) {
        ksnprintf(out_resp, 256, "ERR: ACCESS DENIED - DEVICE NOT ADMITTED (PHYSICAL APPROVAL REQUIRED ON YESOS CONSOLE)");
        *out_resp_len = (U32)StrLen(out_resp);
        return FALSE;
    }

    // USER CREDENTIALS AUTHENTICATION CHECK (Per-User / Per-PC Accounts)
    // Protected operations: File transfer (READ/WRITE) and AI Search
    if (nas_user_is_auth_required() &&
        cmd_type != NAS_CMD_AUTH &&
        cmd_type != NAS_CMD_INFO) {
        if (!sess || !sess->authenticated) {
            ksnprintf(out_resp, 256, "ERR: AUTH REQUIRED - SEND NAS_CMD_AUTH (0x26) WITH CREDENTIALS");
            *out_resp_len = (U32)StrLen(out_resp);
            return FALSE;
        }
    }

    switch (cmd_type) {
        case 0x20: { // NAS_INFO
            nas_refresh_pool();
            ksnprintf(out_resp, 256, "NAS_OK: Pool=%u/%uMB Clients=%u Auth=%u",
                      (U32)g_nas_state.used_pool_mb, (U32)g_nas_state.total_pool_mb,
                      g_nas_state.active_clients_count, nas_user_is_auth_required() ? 1 : 0);
            *out_resp_len = (U32)StrLen(out_resp);
            return TRUE;
        }

        case 0x21: { // NAS_LIST: shares and root files (bounded, no invented entries)
            char file_list[160];
            size_t pos = 0;
            file_list[0] = '\0';
            VFSEntry entries[16];
            U32 cnt = vfs_list_dir("/", entries, 16);
            for (U32 i = 0; i < cnt; i++) {
                if (entries[i].type != VFS_TYPE_FILE) continue;
                I64 n = ksnprintf(file_list + pos, sizeof(file_list) - pos, "%s%s", pos ? ", " : "", entries[i].name);
                if (pos + (size_t)n >= sizeof(file_list) - 1) break;   // truncated: stop listing
                pos += (size_t)n;
            }
            char shares[96];
            size_t sp = 0;
            shares[0] = '\0';
            for (U32 i = 0; i < g_nas_state.shares_count && i < NAS_MAX_SHARES; i++) {
                if (!g_nas_state.shares[i].active) continue;
                I64 n = ksnprintf(shares + sp, sizeof(shares) - sp, "%s/%s", sp ? ", " : "", g_nas_state.shares[i].share_name);
                if (sp + (size_t)n >= sizeof(shares) - 1) break;
                sp += (size_t)n;
            }
            ksnprintf(out_resp, 256, "SHARES: %s | FILES: %s", shares[0] ? shares : "(none)",
                      file_list[0] ? file_list : "(none)");
            *out_resp_len = (U32)StrLen(out_resp);
            return TRUE;
        }

        case 0x22: { // NAS_READ: Real VFS File Transfer & Streaming
            const NASReadRequest* req = (const NASReadRequest*)payload;
            const char* path_to_read = NULL;
            Bool stat_only = FALSE;
            U32 offset = 0;
            U16 chunk_len = 256;

            // Detect if structured binary NASReadRequest or legacy plain ASCII path
            if (payload_len >= 8 && req->offset < 0x01000000 && req->path[0] != '\0') {
                path_to_read = req->path;
                offset = req->offset;
                chunk_len = req->chunk_len ? req->chunk_len : 256;
                if (chunk_len > 256) chunk_len = 256;
                stat_only = (req->flags & 1) ? TRUE : FALSE;
            } else if (payload && payload_len > 0 && payload[0] >= 32) {
                // Plain path string
                path_to_read = payload;
                offset = 0;
                chunk_len = 256;
                stat_only = FALSE;
            } else {
                path_to_read = "/README.TXT";
            }

            // Remote clients get an exact, absolute lookup with an explicit policy:
            //   /SYS/...   never (credential hashes, vault header, RNG seed)
            //   /vault/... only authenticated ADMIN sessions, and only while unlocked
            char remote_path[VFS_MAX_PATH];
            if (path_to_read[0] == '/') {
                StrNCpy(remote_path, path_to_read, sizeof(remote_path) - 1);
            } else {
                ksnprintf(remote_path, sizeof(remote_path), "/%s", path_to_read);
            }
            remote_path[sizeof(remote_path) - 1] = '\0';
            char canon_remote[VFS_MAX_PATH];
            if (!vfs_resolve_path(remote_path, canon_remote, sizeof(canon_remote))) {
                ksnprintf(out_resp, 256, "ERR: Invalid path");
                *out_resp_len = (U32)StrLen(out_resp);
                return FALSE;
            }
            if (StrNICmp(canon_remote, "/SYS", 4) == 0 && (canon_remote[4] == '\0' || canon_remote[4] == '/')) {
                ksnprintf(out_resp, 256, "ERR: PERMISSION DENIED - SYSTEM AREA");
                *out_resp_len = (U32)StrLen(out_resp);
                return FALSE;
            }
            if (vault_path_is_protected(canon_remote) &&
                (!sess || !sess->authenticated || sess->role != NAS_ROLE_ADMIN)) {
                ksnprintf(out_resp, 256, "ERR: PERMISSION DENIED - VAULT REQUIRES AUTHENTICATED ADMIN");
                *out_resp_len = (U32)StrLen(out_resp);
                return FALSE;
            }

            size_t file_sz = 0;
            U8* file_data = vfs_read_file_exact(canon_remote, &file_sz);
            if (!file_data) {
                ksnprintf(out_resp, 256, "ERR: File '%s' not found in VFS", path_to_read);
                *out_resp_len = (U32)StrLen(out_resp);
                return FALSE;
            }

            if (stat_only) {
                ksnprintf(out_resp, 256, "SIZE:%u", (U32)file_sz);
                *out_resp_len = (U32)StrLen(out_resp);
                Free(file_data);
                return TRUE;
            }

            if (offset >= file_sz) {
                // End of File (0 bytes transferred)
                *out_resp_len = 0;
                Free(file_data);
                return TRUE;
            }

            U32 bytes_to_copy = chunk_len;
            if (offset + bytes_to_copy > file_sz) {
                bytes_to_copy = (U32)(file_sz - offset);
            }

            MemCpy(out_resp, file_data + offset, bytes_to_copy);
            *out_resp_len = bytes_to_copy;

            g_nas_state.total_read_bytes += bytes_to_copy;
            if (client) client->bytes_read += bytes_to_copy;

            Free(file_data);
            return TRUE;
        }

        case 0x23: { // NAS_WRITE
            if (!sess || (nas_user_is_auth_required() && sess->role == NAS_ROLE_RO)) {
                ksnprintf(out_resp, 256, "ERR: PERMISSION DENIED - USER ROLE IS READ_ONLY");
                *out_resp_len = (U32)StrLen(out_resp);
                return FALSE;
            }

            // Write into RamFS volatile NAS pool
            vfs_write_file("/ram/INCOMING.DAT", payload, payload_len);

            g_nas_state.total_write_bytes += payload_len;
            if (client) client->bytes_written += payload_len;
            ksnprintf(out_resp, 256, "WRITE_OK: Saved %u bytes cleanly to /ram/INCOMING.DAT", payload_len);
            *out_resp_len = (U32)StrLen(out_resp);
            return TRUE;
        }

        case 0x24:   // former NAS_AI_SEARCH (simulated catalogue, removed)
        case 0x25: { // NAS_SMART: virtio-blk exposes no S.M.A.R.T. data
            ksnprintf(out_resp, 256, cmd_type == 0x24 ? "ERR: NOT SUPPORTED" : "ERR: SMART NOT AVAILABLE ON THIS DISK");
            *out_resp_len = (U32)StrLen(out_resp);
            return FALSE;
        }

        case NAS_CMD_AUTH: { // 0x26: Authenticate user credentials
            char username[NAS_MAX_USERNAME_LEN];
            char password[NAS_MAX_PASSWORD_LEN];
            MemSet(username, 0, sizeof(username));
            MemSet(password, 0, sizeof(password));

            const char* sep = NULL;
            for (U32 i = 0; i < payload_len && payload[i]; i++) {
                if (payload[i] == ':' || payload[i] == ' ') {
                    sep = &payload[i];
                    break;
                }
            }

            if (sep) {
                U32 ulen = (U32)(sep - payload);
                if (ulen >= sizeof(username)) ulen = sizeof(username) - 1;
                MemCpy(username, payload, ulen);
                username[ulen] = '\0';

                const char* pstart = sep + 1;
                while (*pstart == ' ') pstart++;
                U32 plen = (U32)StrLen(pstart);
                if (plen >= sizeof(password)) plen = sizeof(password) - 1;
                MemCpy(password, pstart, plen);
                password[plen] = '\0';
                while (plen > 0 && (password[plen - 1] == '\r' || password[plen - 1] == '\n' || password[plen - 1] == ' ')) {
                    password[--plen] = '\0';
                }
            }

            NASUser* auth_u = NULL;
            if (!sess) {
                // Unreachable via the plaintext path; never accept credentials in clear.
                yc_wipe((U8*)password, sizeof(password));
                return FALSE;
            }
            Bool auth_ok = nas_user_authenticate(username, password, &auth_u) && auth_u;
            yc_wipe((U8*)password, sizeof(password));
            if (auth_ok) {
                sess->authenticated = TRUE;
                sess->role = auth_u->role;
                StrNCpy(sess->username, auth_u->username, sizeof(sess->username) - 1);
                if (client) {
                    client->is_authenticated = TRUE;
                    StrNCpy(client->auth_username, auth_u->username, sizeof(client->auth_username) - 1);
                    client->user_role = auth_u->role;
                }
                const char* role_str = (auth_u->role == NAS_ROLE_ADMIN) ? "ADMIN" :
                                       ((auth_u->role == NAS_ROLE_RW) ? "READ_WRITE" : "READ_ONLY");
                ksnprintf(out_resp, 256, "AUTH_OK: Logged in as '%s' [Role: %s]", auth_u->username, role_str);
                *out_resp_len = (U32)StrLen(out_resp);
                return TRUE;
            } else {
                sess->authenticated = FALSE;
                sess->role = NAS_ROLE_RO;
                sess->username[0] = '\0';
                if (client) {
                    client->is_authenticated = FALSE;
                    client->auth_username[0] = '\0';
                }
                ksnprintf(out_resp, 256, "ERR: AUTH FAILED - INVALID CREDENTIALS OR ACCOUNT LOCKED");
                *out_resp_len = (U32)StrLen(out_resp);
                return FALSE;
            }
        }

        default:
            return FALSE;
    }
}

U0 nas_print_status(U0) {
    nas_refresh_pool();
    U64 uptime_sec = (timer_get_ticks() - g_nas_state.start_tick) / 1000;

    kprintf("\n====================================================================\n");
    kprintf("        YESOS 2.0 - NETWORK ATTACHED STORAGE (NAS) CONTROL CENTER   \n");
    kprintf("====================================================================\n");
    kprintf(" Status         : %s on UDP %u (Uptime: %u sec)\n",
            g_nas_state.is_running ? "ONLINE" : "OFFLINE", NAS_SERVER_PORT, (U32)uptime_sec);
    kprintf(" Storage Pool   : %u MB / %u MB (Used: %u%% | Free: %u MB)\n",
            (U32)g_nas_state.used_pool_mb, (U32)g_nas_state.total_pool_mb,
            g_nas_state.total_pool_mb ? (U32)((g_nas_state.used_pool_mb * 100) / g_nas_state.total_pool_mb) : 0,
            (U32)(g_nas_state.total_pool_mb - g_nas_state.used_pool_mb));
    kprintf(" Network Shares : %u active (/share, /media, /backup)\n", g_nas_state.shares_count);
    kprintf(" Active Clients : %u connected\n", g_nas_state.active_clients_count);
    for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
        NASConnectedClient* c = &g_nas_state.clients[i];
        const char* u_info = c->is_authenticated ? c->auth_username : "UNAUTHENTICATED";
        kprintf("   -> Client [%s]: IP %u.%u.%u.%u | User: %s | Read: %u KB | Write: %u KB | %s\n",
                c->client_name,
                (c->ip >> 24) & 0xFF, (c->ip >> 16) & 0xFF, (c->ip >> 8) & 0xFF, c->ip & 0xFF,
                u_info,
                (U32)(c->bytes_read / 1024), (U32)(c->bytes_written / 1024),
                c->is_blocked ? "BLOCKED" : (c->access_status == NAS_ACCESS_ADMITTED ? "ADMITTED" : "PENDING"));
    }
    kprintf(" Drive S.M.A.R.T: not available (virtio-blk exposes no SMART data)\n");
    kprintf("====================================================================\n\n");
}

U0 nas_print_shares(U0) {
    kprintf("\n--- YESOS NAS ACTIVE NETWORK SHARES ---\n");
    for (U32 i = 0; i < g_nas_state.shares_count; i++) {
        NASShare* s = &g_nas_state.shares[i];
        kprintf(" [%u] /%-8s -> %-16s | %4u MB / %4u MB | %s\n",
                i + 1, s->share_name, s->mount_path,
                (U32)s->used_mb, (U32)s->total_mb,
                s->read_only ? "READ-ONLY" : "READ-WRITE");
    }
    kprintf("---------------------------------------\n\n");
}

U0 nas_print_files(U0) {
    kprintf("\n--- YESOS NAS STORAGE POOL (RedSea directory) ---\n");
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted) {
        kprintf("  (no RedSea volume mounted)\n");
    } else {
        for (U32 i = 0; i < v->entry_count; i++) {
            const RedSeaFileEntry* e = &v->entries[i];
            if (!(e->flags & REDSEA_FLAG_USED) || (e->flags & REDSEA_FLAG_DIR)) continue;
            kprintf("  %10u B  %s%s\n", (U32)e->byte_size, e->name,
                    (e->flags & REDSEA_FLAG_ENCRYPTED) ? "  [encrypted]" : "");
        }
    }
    kprintf("----------------------------------------\n\n");
}

// ============================================================================
// Physical Device Admission Control (Local Physical Console / Screen Only)
// ============================================================================

U32 nas_parse_ip(const char* str) {
    if (!str) return 0;
    U32 a = 0, b = 0, c = 0, d = 0;
    const char* p = str;
    while (*p >= '0' && *p <= '9') a = a * 10 + (*p++ - '0');
    if (*p == '.') p++;
    while (*p >= '0' && *p <= '9') b = b * 10 + (*p++ - '0');
    if (*p == '.') p++;
    while (*p >= '0' && *p <= '9') c = c * 10 + (*p++ - '0');
    if (*p == '.') p++;
    while (*p >= '0' && *p <= '9') d = d * 10 + (*p++ - '0');
    return (a << 24) | (b << 16) | (c << 8) | d;
}

Bool nas_admit_client_ip(U32 ip, const char* name) {
    if (security_pin_is_locked()) {
        kprintf("\n[NAS ADMISSION] ❌ Admission Denied: Physical Console is LOCKED by Master PIN!\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
        if (g_nas_state.clients[i].ip == ip) {
            g_nas_state.clients[i].access_status = NAS_ACCESS_ADMITTED;
            g_nas_state.clients[i].is_blocked = FALSE;
            if (name && *name) {
                StrNCpy(g_nas_state.clients[i].client_name, name, 31);
            }
            kprintf("\n[NAS ADMISSION] ✅ Client %u.%u.%u.%u (%s) ADMITTED to Secure Storage!\n",
                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                    g_nas_state.clients[i].client_name);
            speaker_event(BEEP_SUCCESS);
            return TRUE;
        }
    }
    if (g_nas_state.active_clients_count < NAS_MAX_CLIENTS) {
        NASConnectedClient* c = &g_nas_state.clients[g_nas_state.active_clients_count++];
        c->ip = ip;
        c->last_seen_tick = timer_get_ticks();
        c->is_blocked = FALSE;
        c->access_status = NAS_ACCESS_ADMITTED;
        if (name && *name) {
            StrNCpy(c->client_name, name, 31);
        } else {
            ksnprintf(c->client_name, sizeof(c->client_name), "Node-%02X", (U32)(ip & 0xFF));
        }
        kprintf("\n[NAS ADMISSION] ✅ Client %u.%u.%u.%u (%s) registered and ADMITTED!\n",
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, c->client_name);
        speaker_event(BEEP_SUCCESS);
        return TRUE;
    }
    return FALSE;
}

Bool nas_block_client_ip(U32 ip) {
    for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
        if (g_nas_state.clients[i].ip == ip) {
            g_nas_state.clients[i].access_status = NAS_ACCESS_BLOCKED;
            g_nas_state.clients[i].is_blocked = TRUE;
            kprintf("\n[NAS ADMISSION] Client %u.%u.%u.%u BLOCKED and blacklisted.\n",
                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
            speaker_event(BEEP_WARN);
            return TRUE;
        }
    }
    return FALSE;
}

U32 nas_admit_all_pending(U0) {
    if (security_pin_is_locked()) {
        kprintf("\n[NAS ADMISSION] Admission Denied: Physical Console is LOCKED by Master PIN!\n");
        speaker_event(BEEP_WARN);
        return 0;
    }
    U32 count = 0;
    for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
        if (g_nas_state.clients[i].access_status == NAS_ACCESS_PENDING) {
            g_nas_state.clients[i].access_status = NAS_ACCESS_ADMITTED;
            g_nas_state.clients[i].is_blocked = FALSE;
            count++;
        }
    }
    if (count > 0) {
        kprintf("\n[NAS ADMISSION] Admitted %u pending devices to storage whitelist.\n", count);
        speaker_event(BEEP_SUCCESS);
    }
    return count;
}

Bool nas_is_client_admitted(U32 ip) {
    for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
        if (g_nas_state.clients[i].ip == ip) {
            return (g_nas_state.clients[i].access_status == NAS_ACCESS_ADMITTED);
        }
    }
    return FALSE;
}

U0 nas_print_devices(U0) {
    kprintf("\n================ [ YESOS PHYSICAL ADMISSION CONTROL LIST ] ================\n");
    kprintf(" Total Devices Recorded : %u\n", g_nas_state.active_clients_count);
    kprintf(" Policy Status          : ZERO-TRUST PHYSICAL ACCESS REQUIRED\n");
    kprintf(" Status Legend          : [ADMITTED] = Trusted | [PENDING] = Awaiting Physical Approval\n");
    kprintf("---------------------------------------------------------------------------\n");
    for (U32 i = 0; i < g_nas_state.active_clients_count; i++) {
        NASConnectedClient* c = &g_nas_state.clients[i];
        const char* status_str = "PENDING ";
        if (c->access_status == NAS_ACCESS_ADMITTED) status_str = "\033[32mADMITTED\033[0m";
        else if (c->access_status == NAS_ACCESS_BLOCKED) status_str = "\033[31mBLOCKED \033[0m";
        else status_str = "\033[33mPENDING \033[0m";

        char auth_str[36];
        if (c->is_authenticated) {
            const char* rstr = (c->user_role == NAS_ROLE_ADMIN) ? "ADMIN" :
                               ((c->user_role == NAS_ROLE_RW) ? "RW" : "RO");
            ksnprintf(auth_str, sizeof(auth_str), "User: %s (%s)", c->auth_username, rstr);
        } else {
            ksnprintf(auth_str, sizeof(auth_str), "User: [No Auth]");
        }

        kprintf(" [%u] IP: %u.%u.%u.%u | Host: %s | [%s] | %s | R:%uKB W:%uKB\n",
                i + 1,
                (c->ip >> 24) & 0xFF, (c->ip >> 16) & 0xFF, (c->ip >> 8) & 0xFF, c->ip & 0xFF,
                c->client_name, status_str, auth_str,
                (U32)(c->bytes_read / 1024), (U32)(c->bytes_written / 1024));
    }
    kprintf("===========================================================================\n\n");
}
