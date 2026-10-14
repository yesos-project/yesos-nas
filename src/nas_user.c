#include "webadmin.h"
#include "nas_user.h"
#include "yesos_crypto.h"
#include "vfs.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"
#include "speaker.h"

static NASUserState g_nas_users;
static const char* USERS_CONFIG_FILE = "SYS/USERS.CFG";

// Argon2id(password, per-user salt). Retries while another hart holds the
// shared Argon2 memory arena.
static Bool compute_password_hash(const char* password, const U8* salt, U8* out) {
    if (!password || !salt || !out) return FALSE;
    I32 r;
    while ((r = yc_argon2id((const U8*)password, StrLen(password), salt, 16, out, 32)) == YC_ERR_BUSY) {
    }
    return r == YC_OK;
}

static Bool set_password(NASUser* u, const char* password) {
    if (!entropy_random(u->salt, sizeof(u->salt))) return FALSE;
    return compute_password_hash(password, u->salt, u->pw_hash);
}

static U0 save_users_config(U0) {
    webdav_auth_flush();   // cached WebDAV credentials may no longer be valid
    vfs_write_file(USERS_CONFIG_FILE, &g_nas_users, sizeof(NASUserState));
}

U0 nas_user_init(U0) {
    MemSet(&g_nas_users, 0, sizeof(NASUserState));
    g_nas_users.magic = NAS_USERS_MAGIC;
    g_nas_users.version = NAS_USERS_VERSION;
    g_nas_users.auth_required = TRUE;

    size_t sz = 0;
    U8* data = vfs_read_file(USERS_CONFIG_FILE, &sz);
    if (data) {
        const NASUserState* saved = (const NASUserState*)data;
        if (sz == sizeof(NASUserState) && saved->magic == NAS_USERS_MAGIC &&
            saved->version == NAS_USERS_VERSION && saved->user_count <= NAS_MAX_USERS) {
            MemCpy(&g_nas_users, data, sizeof(NASUserState));
            yc_wipe(data, sz);
            Free(data);
            kprintf("[NAS AUTH] Loaded %u user account(s) from %s.\n", g_nas_users.user_count, USERS_CONFIG_FILE);
            return;
        }
        yc_wipe(data, sz);
        Free(data);
        // Legacy stores used an unsalted 64-bit CRC as "hash"; they cannot be
        // migrated without the passwords, so they are discarded.
        kprintf("[NAS AUTH] Discarding legacy/invalid %s (insecure credential format).\n", USERS_CONFIG_FILE);
    }

    // No default accounts: the NAS stays closed until an admin is created
    // from the physical console.
    save_users_config();
    kprintf("[NAS AUTH] No user accounts. NAS access is closed until an admin is created:\n");
    kprintf("[NAS AUTH]   user add <name> <password> admin\n");
}

NASUserState* nas_user_get_state(U0) {
    return &g_nas_users;
}

Bool nas_user_is_auth_required(U0) {
    return g_nas_users.auth_required;
}

U0 nas_user_set_auth_required(Bool req) {
    g_nas_users.auth_required = req;
    save_users_config();
    kprintf("[NAS AUTH] Authentication requirement set to: %s\n", req ? "ACTIVE (Zero-Trust)" : "DISABLED");
}

NASUser* nas_user_get_by_name(const char* username) {
    if (!username || !*username) return NULL;
    for (U32 i = 0; i < g_nas_users.user_count; i++) {
        if (g_nas_users.users[i].active && StrCmp(g_nas_users.users[i].username, username) == 0) {
            return &g_nas_users.users[i];
        }
    }
    return NULL;
}

Bool nas_user_add(const char* username, const char* password, U8 role) {
    if (!username || !*username || !password || !*password) {
        kprintf("[NAS AUTH] ❌ Error: Username and password cannot be empty.\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    if (StrLen(username) >= NAS_MAX_USERNAME_LEN || StrLen(password) >= NAS_MAX_PASSWORD_LEN) {
        kprintf("[NAS AUTH] ❌ Error: Username or password exceeds max length (31 chars).\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }
    if (StrLen(password) < NAS_MIN_PASSWORD_LEN) {
        kprintf("[NAS AUTH] ❌ Error: Password must be at least %u characters.\n", NAS_MIN_PASSWORD_LEN);
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    NASUser* existing = nas_user_get_by_name(username);
    if (existing) {
        kprintf("[NAS AUTH] ❌ Error: User '%s' already exists.\n", username);
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    if (g_nas_users.user_count >= NAS_MAX_USERS) {
        kprintf("[NAS AUTH] ❌ Error: User vault full (max %u users).\n", NAS_MAX_USERS);
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    NASUser* u = &g_nas_users.users[g_nas_users.user_count];
    MemSet(u, 0, sizeof(NASUser));
    StrNCpy(u->username, username, NAS_MAX_USERNAME_LEN - 1);
    if (!set_password(u, password)) {
        MemSet(u, 0, sizeof(NASUser));
        kprintf("[NAS AUTH] ❌ Error: could not derive password hash.\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }
    g_nas_users.user_count++;
    u->role = role;
    u->active = TRUE;
    u->allowed_shares_mask = (role == NAS_ROLE_RO) ? 0x02 : 0xFFFFFFFF;

    save_users_config();
    const char* role_str = (role == NAS_ROLE_ADMIN) ? "ADMIN" : ((role == NAS_ROLE_RW) ? "READ_WRITE" : "READ_ONLY");
    kprintf("[NAS AUTH] ✅ User '%s' created successfully (Role: %s)!\n", username, role_str);
    speaker_event(BEEP_SUCCESS);
    return TRUE;
}

Bool nas_user_remove(const char* username) {
    if (!username || !*username) return FALSE;
    for (U32 i = 0; i < g_nas_users.user_count; i++) {
        if (g_nas_users.users[i].active && StrCmp(g_nas_users.users[i].username, username) == 0) {
            // Prevent removing last admin
            if (g_nas_users.users[i].role == NAS_ROLE_ADMIN) {
                U32 admins = 0;
                for (U32 j = 0; j < g_nas_users.user_count; j++) {
                    if (g_nas_users.users[j].active && g_nas_users.users[j].role == NAS_ROLE_ADMIN) admins++;
                }
                if (admins <= 1) {
                    kprintf("[NAS AUTH] ❌ Cannot delete '%s': Must keep at least one ADMIN account.\n", username);
                    speaker_event(BEEP_WARN);
                    return FALSE;
                }
            }

            // Shift users down
            for (U32 j = i; j < g_nas_users.user_count - 1; j++) {
                g_nas_users.users[j] = g_nas_users.users[j + 1];
            }
            g_nas_users.user_count--;
            yc_wipe((U8*)&g_nas_users.users[g_nas_users.user_count], sizeof(NASUser));
            save_users_config();
            kprintf("[NAS AUTH] ✅ User '%s' removed from vault.\n", username);
            speaker_event(BEEP_CONFIRM);
            return TRUE;
        }
    }
    kprintf("[NAS AUTH] ❌ User '%s' not found.\n", username);
    speaker_event(BEEP_WARN);
    return FALSE;
}

static U32 admin_count(U0) {
    U32 admins = 0;
    for (U32 j = 0; j < g_nas_users.user_count; j++) {
        if (g_nas_users.users[j].active && g_nas_users.users[j].role == NAS_ROLE_ADMIN) admins++;
    }
    return admins;
}

Bool nas_user_set_role(const char* username, U8 role) {
    NASUser* u = nas_user_get_by_name(username);
    if (!u || role > NAS_ROLE_ADMIN) return FALSE;
    if (u->role == NAS_ROLE_ADMIN && role != NAS_ROLE_ADMIN && admin_count() <= 1) {
        kprintf("[NAS AUTH] Cannot demote '%s': at least one ADMIN account must remain.\n", username);
        return FALSE;
    }
    u->role = role;
    u->allowed_shares_mask = (role == NAS_ROLE_RO) ? 0x02 : 0xFFFFFFFF;
    save_users_config();
    kprintf("[NAS AUTH] Role of '%s' set to %s.\n", username,
            role == NAS_ROLE_ADMIN ? "ADMIN" : (role == NAS_ROLE_RW ? "READ_WRITE" : "READ_ONLY"));
    return TRUE;
}

Bool nas_user_change_password(const char* username, const char* new_pass) {
    NASUser* u = nas_user_get_by_name(username);
    if (!u) {
        kprintf("[NAS AUTH] ❌ User '%s' not found.\n", username);
        speaker_event(BEEP_WARN);
        return FALSE;
    }
    if (!new_pass || StrLen(new_pass) < NAS_MIN_PASSWORD_LEN || StrLen(new_pass) >= NAS_MAX_PASSWORD_LEN) {
        kprintf("[NAS AUTH] ❌ Password must be %u-%u characters.\n", NAS_MIN_PASSWORD_LEN, NAS_MAX_PASSWORD_LEN - 1);
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    if (!set_password(u, new_pass)) {
        kprintf("[NAS AUTH] ❌ Error: could not derive password hash.\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }
    u->failed_attempts = 0;
    u->lockout_until_ms = 0;
    save_users_config();
    kprintf("[NAS AUTH] ✅ Password for user '%s' updated successfully.\n", username);
    speaker_event(BEEP_SUCCESS);
    return TRUE;
}

Bool nas_user_authenticate(const char* username, const char* password, NASUser** out_user) {
    if (out_user) *out_user = NULL;
    if (!username || !password) return FALSE;

    NASUser* u = nas_user_get_by_name(username);
    if (!u) {
        // Spend the same Argon2id cost so response timing does not reveal
        // which usernames exist.
        static const U8 dummy_salt[16] = { 0 };
        U8 dummy[32];
        compute_password_hash(password, dummy_salt, dummy);
        yc_wipe(dummy, sizeof(dummy));
        kprintf("[NAS AUTH] ⚠️ Failed login attempt for unknown user.\n");
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    U64 now = timer_get_uptime_ms();
    if (now < u->lockout_until_ms) {
        U32 rem = (U32)((u->lockout_until_ms - now) / 1000) + 1;
        kprintf("[NAS AUTH] 🚨 Account '%s' locked out (%u s remaining).\n", username, rem);
        speaker_event(BEEP_WARN);
        return FALSE;
    }

    U8 test_hash[32];
    Bool derived = compute_password_hash(password, u->salt, test_hash);
    Bool match = derived && yc_ct_eq(test_hash, u->pw_hash, sizeof(test_hash));
    yc_wipe(test_hash, sizeof(test_hash));
    if (match) {
        u->failed_attempts = 0;
        u->lockout_until_ms = 0;
        if (out_user) *out_user = u;
        kprintf("[NAS AUTH] ✅ Successful authentication for user '%s'!\n", username);
        speaker_event(BEEP_SUCCESS);
        return TRUE;
    }

    // Failed attempt
    u->failed_attempts++;
    if (u->failed_attempts >= 5) {
        u->lockout_until_ms = timer_get_uptime_ms() + 30000; // 30s penalty
        kprintf("[NAS AUTH] 🚨 5 Failed logins! Account '%s' locked for 30 seconds.\n", username);
    } else {
        kprintf("[NAS AUTH] ⚠️ Incorrect password for '%s' (%u attempts remaining).\n",
                username, 5 - u->failed_attempts);
    }
    speaker_event(BEEP_WARN);
    return FALSE;
}

static U0 print_padded(const char* s, int width) {
    int len = s ? (int)StrLen(s) : 0;
    if (s) {
        kprintf("%s", s);
    }
    for (int i = len; i < width; i++) {
        kprintf(" ");
    }
}

U0 nas_user_list(U0) {
    kprintf("\n==================== [ YESOS NAS USER VAULT ] ====================\n");
    kprintf("  Authentication Required: %s\n", g_nas_users.auth_required ? "YES [Zero-Trust Active]" : "NO [Open LAN]");
    kprintf("  Active Accounts:         %u / %u\n", g_nas_users.user_count, NAS_MAX_USERS);
    kprintf("  Storage:                 SYS/USERS.CFG (RedSea / RamFS Persistent)\n");
    kprintf("  Password Hash:           Argon2id (8 MiB, t=3) + 128-bit salt\n");
    kprintf("------------------------------------------------------------------\n");
    kprintf("  ");
    print_padded("USERNAME", 14);
    print_padded("ROLE", 14);
    print_padded("STATUS", 10);
    kprintf("%s\n", "PERMITTED SHARES");
    kprintf("  ----------------------------------------------------------------\n");

    for (U32 i = 0; i < g_nas_users.user_count; i++) {
        NASUser* u = &g_nas_users.users[i];
        const char* role_str = (u->role == NAS_ROLE_ADMIN) ? "ADMIN" : ((u->role == NAS_ROLE_RW) ? "READ_WRITE" : "READ_ONLY");
        const char* shares_str = (u->role == NAS_ROLE_ADMIN) ? "All (/share, /media, /backup)" :
                                 ((u->role == NAS_ROLE_RW) ? "/share, /backup" : "/media (Read-Only)");
        kprintf("  ");
        print_padded(u->username, 14);
        print_padded(role_str, 14);
        print_padded(u->active ? "ACTIVE" : "DISABLED", 10);
        kprintf("%s\n", shares_str);
    }

    kprintf("==================================================================\n");
    kprintf("  Commands: user add <name> <pass> [admin|rw|ro]\n");
    kprintf("            user passwd <name> <new_pass>\n");
    kprintf("            user del <name>\n");
    kprintf("            user auth [on|off]\n");
    kprintf("==================================================================\n\n");
    speaker_event(BEEP_CONFIRM);
}
