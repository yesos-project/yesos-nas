// ============================================================================
// YesOS NAS - console commands of the NAS product (registered with the core
// shell): snapshots, the NAS service and devices, shared folders, accounts, the
// HTTPS certificate and the DNS filter.
// ============================================================================

#include "nas_shell.h"
#include "shell.h"
#include "kprintf.h"
#include "memory.h"
#include "speaker.h"
#include "nas_server.h"
#include "nas_user.h"
#include "nas_secure.h"
#include "webadmin.h"
#include "snapshot.h"
#include "virtio_net.h"

static Bool nas_shell_run(const char* cmd) {
    if (0) {
    } else if (StrCmp(cmd, "tls") == 0 || StrCmp(cmd, "https") == 0) {
        webadmin_print_tls();
    } else if (StrCmp(cmd, "backup") == 0 || StrCmp(cmd, "snapshot") == 0 || StrCmp(cmd, "snapshot list") == 0) {
        snapshot_print();
    } else if (shell_is_prefix("snapshot ", cmd)) {
        const char* sub = cmd + 9;
        while (*sub == ' ') sub++;
        char msg[192];
        msg[0] = '\0';
        if (shell_is_prefix("create", sub)) {
            const char* note = sub + 6;
            while (*note == ' ') note++;
            snapshot_create("console", note, "", FALSE, NULL, msg, sizeof(msg));
        } else if (shell_is_prefix("delete ", sub)) {
            snapshot_delete((U32)shell_parse_uint(sub + 7), msg, sizeof(msg));
        } else if (shell_is_prefix("restore ", sub)) {
            const char* p = sub + 8;
            U32 id = (U32)shell_parse_uint(p);
            while (*p >= '0' && *p <= '9') p++;
            while (*p == ' ') p++;
            snapshot_restore(id, p, msg, sizeof(msg));
        } else if (StrCmp(sub, "legacy") == 0) {
            snapshot_legacy(FALSE);
        } else if (StrCmp(sub, "legacy delete") == 0) {
            snapshot_legacy(TRUE);
        } else if (StrCmp(sub, "auto now") == 0) {
            snapshot_run_auto_now(msg, sizeof(msg));
        } else if (shell_is_prefix("auto ", sub)) {
            const char* p = sub + 5;
            U32 minutes = (U32)shell_parse_uint(p);
            while (*p >= '0' && *p <= '9') p++;
            while (*p == ' ') p++;
            snapshot_set_auto(minutes, *p ? (U32)shell_parse_uint(p) : 7, msg, sizeof(msg));
        } else {
            kprintf("Usage: snapshot [list | create [note] | delete <id> | restore <id> [path] | auto <minutes> [keep] | auto now\n");
            kprintf("                 | legacy | legacy delete]\n");
        }
        if (msg[0]) kprintf("%s\n", msg);
    } else if (StrNCmp(cmd, "storage", 7) == 0 || StrNCmp(cmd, "nas", 3) == 0) {
        const char* sub = (StrNCmp(cmd, "storage", 7) == 0) ? (cmd + 7) : (cmd + 3);
        while (*sub == ' ') sub++;
        if (*sub == '\0' || StrCmp(sub, "status") == 0) {
            nas_print_status();
            speaker_event(BEEP_SUCCESS);
        } else if (StrCmp(sub, "files") == 0 || StrCmp(sub, "ls") == 0) {
            nas_print_files();
            speaker_event(BEEP_SUCCESS);
        } else if (StrCmp(sub, "shares") == 0) {
            nas_print_shares();
            speaker_event(BEEP_SUCCESS);
        } else if (StrCmp(sub, "smart") == 0) {
            kprintf("S.M.A.R.T. not available: virtio-blk exposes no SMART data.\n");
        } else if (StrCmp(sub, "devices") == 0 || StrCmp(sub, "clients") == 0) {
            nas_print_devices();
            speaker_event(BEEP_SUCCESS);
        } else if (StrCmp(sub, "key") == 0) {
            nas_secure_print_key();
            kprintf("  Pin it on a client with: python3 tools/nas_client.py --host <ip> trust <key>\n");
        } else if (StrNCmp(sub, "admit", 5) == 0) {
            const char* ip_arg = sub + 5;
            while (*ip_arg == ' ') ip_arg++;
            if (*ip_arg == '\0') {
                kprintf("Usage: nas admit <IP_ADDRESS>\n");
            } else {
                U32 ip = nas_parse_ip(ip_arg);
                if (ip != 0) {
                    nas_admit_client_ip(ip, "Console-Admitted");
                } else {
                    kprintf("Invalid IP address: %s\n", ip_arg);
                }
            }
        } else if (StrNCmp(sub, "block", 5) == 0) {
            const char* ip_arg = sub + 5;
            while (*ip_arg == ' ') ip_arg++;
            if (*ip_arg == '\0') {
                kprintf("Usage: nas block <IP_ADDRESS>\n");
            } else {
                U32 ip = nas_parse_ip(ip_arg);
                if (ip != 0) {
                    nas_block_client_ip(ip);
                } else {
                    kprintf("Invalid IP address: %s\n", ip_arg);
                }
            }
        } else {
            kprintf("Usage: nas [status | files | shares | smart | devices | key | admit <ip> | block <ip>]\n");
        }
    } else if (StrNCmp(cmd, "share", 5) == 0 && (cmd[5] == ' ' || cmd[5] == '\0')) {
        const char* sub = cmd + 5;
        while (*sub == ' ') sub++;
        if (*sub == '\0' || StrCmp(sub, "list") == 0 || StrCmp(sub, "ls") == 0) {
            nas_print_share_list();
            speaker_event(BEEP_SUCCESS);
        } else if (StrNCmp(sub, "add ", 4) == 0) {
            const char* args = sub + 4;
            while (*args == ' ') args++;
            char name[32] = {0};
            char path[64] = {0};
            char mode[16] = {0};
            char comment[64] = {0};

            int i = 0;
            while (*args && *args != ' ' && i < 31) name[i++] = *args++;
            name[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && *args != ' ' && i < 63) path[i++] = *args++;
            path[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && *args != ' ' && i < 15) mode[i++] = *args++;
            mode[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && i < 63) comment[i++] = *args++;
            comment[i] = '\0';

            if (name[0] == '\0' || path[0] == '\0') {
                kprintf("Uso: share add <nombre> <ruta> [rw|ro] [comentario]\n");
            } else {
                Bool ro = (StrICmp(mode, "ro") == 0 || StrICmp(mode, "readonly") == 0);
                nas_add_share(name, path, ro, comment[0] ? comment : "User Share");
                speaker_event(BEEP_SUCCESS);
            }
        } else if (StrNCmp(sub, "del ", 4) == 0 || StrNCmp(sub, "rm ", 3) == 0) {
            const char* name = (StrNCmp(sub, "del ", 4) == 0) ? (sub + 4) : (sub + 3);
            while (*name == ' ') name++;
            if (*name == '\0') {
                kprintf("Uso: share del <nombre>\n");
            } else {
                nas_remove_share(name);
                speaker_event(BEEP_SUCCESS);
            }
        } else if (StrNCmp(sub, "auth", 4) == 0) {
            const char* opt = sub + 4;
            while (*opt == ' ') opt++;
            if (StrCmp(opt, "on") == 0 || StrCmp(opt, "enable") == 0 || StrCmp(opt, "1") == 0) {
                nas_user_set_auth_required(TRUE);
                nas_config_save();
                speaker_event(BEEP_SUCCESS);
            } else if (StrCmp(opt, "off") == 0 || StrCmp(opt, "disable") == 0 || StrCmp(opt, "0") == 0) {
                nas_user_set_auth_required(FALSE);
                nas_config_save();
                speaker_event(BEEP_SUCCESS);
            } else {
                kprintf("Share authentication is: %s\n",
                        nas_user_is_auth_required() ? "ACTIVE (Password Required)" : "DISABLED (Open LAN)");
                kprintf("Uso: share auth [on | off]\n");
            }
        } else if (StrCmp(sub, "reload") == 0) {
            nas_config_load();
            kprintf("[NAS SHARES] Configuration reloaded from %s.\n", NAS_SERVER_CONFIG_FILE);
            speaker_event(BEEP_SUCCESS);
        } else if (StrCmp(sub, "cfg") == 0 || StrCmp(sub, "cat") == 0) {
            nas_print_share_config();
            speaker_event(BEEP_SUCCESS);
        } else {
            kprintf("Uso de share (carpetas del protocolo NAS y de WebDAV):\n");
            kprintf("  share [list]                         - Lista carpetas compartidas y permisos\n");
            kprintf("  share add <nom> <ruta> [rw|ro] [txt] - Publica una nueva carpeta compartida\n");
            kprintf("  share del <nom>                      - Deja de publicar una carpeta\n");
            kprintf("  share auth [on|off]                  - Exige usuario o LAN libre\n");
            kprintf("  share cfg                            - Muestra el archivo %s\n", NAS_SERVER_CONFIG_FILE);
            kprintf("  share reload                         - Recarga la configuracion desde disco\n");
        }
    } else if (StrNCmp(cmd, "user", 4) == 0 && (cmd[4] == ' ' || cmd[4] == '\0')) {
        const char* sub = cmd + 4;
        while (*sub == ' ') sub++;
        if (*sub == '\0' || StrCmp(sub, "list") == 0) {
            nas_user_list();
        } else if (StrNCmp(sub, "add ", 4) == 0) {
            const char* args = sub + 4;
            while (*args == ' ') args++;
            char u[NAS_MAX_USERNAME_LEN] = {0};
            char p[NAS_MAX_PASSWORD_LEN] = {0};
            char r[16] = {0};
            int i = 0;
            while (*args && *args != ' ' && i < NAS_MAX_USERNAME_LEN - 1) u[i++] = *args++;
            u[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && *args != ' ' && i < NAS_MAX_PASSWORD_LEN - 1) p[i++] = *args++;
            p[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && *args != ' ' && i < 15) r[i++] = *args++;
            r[i] = '\0';

            if (u[0] == '\0' || p[0] == '\0') {
                kprintf("Uso: user add <nombre> <contrasena> [admin|rw|ro]\n");
            } else {
                U8 role = NAS_ROLE_RW;
                if (StrCmp(r, "admin") == 0) role = NAS_ROLE_ADMIN;
                else if (StrCmp(r, "ro") == 0 || StrCmp(r, "readonly") == 0) role = NAS_ROLE_RO;
                nas_user_add(u, p, role);
            }
        } else if (StrNCmp(sub, "passwd ", 7) == 0) {
            const char* args = sub + 7;
            while (*args == ' ') args++;
            char u[NAS_MAX_USERNAME_LEN] = {0};
            char p[NAS_MAX_PASSWORD_LEN] = {0};
            int i = 0;
            while (*args && *args != ' ' && i < NAS_MAX_USERNAME_LEN - 1) u[i++] = *args++;
            u[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && *args != ' ' && i < NAS_MAX_PASSWORD_LEN - 1) p[i++] = *args++;
            p[i] = '\0';

            if (u[0] == '\0' || p[0] == '\0') {
                kprintf("Uso: user passwd <nombre> <nueva_contrasena>\n");
            } else {
                nas_user_change_password(u, p);
            }
        } else if (StrNCmp(sub, "role ", 5) == 0) {
            const char* args = sub + 5;
            while (*args == ' ') args++;
            char u[NAS_MAX_USERNAME_LEN] = {0};
            char r[16] = {0};
            int i = 0;
            while (*args && *args != ' ' && i < NAS_MAX_USERNAME_LEN - 1) u[i++] = *args++;
            u[i] = '\0';
            while (*args == ' ') args++;
            i = 0;
            while (*args && *args != ' ' && i < 15) r[i++] = *args++;
            r[i] = '\0';
            U8 role = 0xFF;
            if (StrCmp(r, "admin") == 0) role = NAS_ROLE_ADMIN;
            else if (StrCmp(r, "rw") == 0) role = NAS_ROLE_RW;
            else if (StrCmp(r, "ro") == 0 || StrCmp(r, "readonly") == 0) role = NAS_ROLE_RO;
            if (u[0] == '\0' || role == 0xFF) {
                kprintf("Uso: user role <nombre> <admin|rw|ro>\n");
            } else if (!nas_user_get_by_name(u)) {
                kprintf("[NAS AUTH] User '%s' not found.\n", u);
            } else if (nas_user_set_role(u, role) && role != NAS_ROLE_ADMIN) {
                webadmin_close_sessions_of(u);   // no longer an admin: out of the panel now
            }
        } else if (StrNCmp(sub, "del ", 4) == 0 || StrNCmp(sub, "remove ", 7) == 0) {
            const char* name = (StrNCmp(sub, "del ", 4) == 0) ? (sub + 4) : (sub + 7);
            while (*name == ' ') name++;
            char u[NAS_MAX_USERNAME_LEN] = {0};
            int i = 0;
            while (*name && *name != ' ' && i < NAS_MAX_USERNAME_LEN - 1) u[i++] = *name++;
            u[i] = '\0';

            if (u[0] == '\0') {
                kprintf("Uso: user del <nombre>\n");
            } else {
                nas_user_remove(u);
            }
        } else if (StrNCmp(sub, "auth", 4) == 0) {
            const char* opt = sub + 4;
            while (*opt == ' ') opt++;
            if (StrCmp(opt, "on") == 0 || StrCmp(opt, "enable") == 0 || StrCmp(opt, "1") == 0) {
                nas_user_set_auth_required(TRUE);
            } else if (StrCmp(opt, "off") == 0 || StrCmp(opt, "disable") == 0 || StrCmp(opt, "0") == 0) {
                nas_user_set_auth_required(FALSE);
            } else {
                kprintf("Zero-Trust User Auth is currently: %s\n",
                        nas_user_is_auth_required() ? "ACTIVE (Zero-Trust ON)" : "DISABLED (Open LAN)");
                kprintf("Uso: user auth [on | off]\n");
            }
        } else {
            kprintf("Uso: user [list | add <name> <pass> [admin|rw|ro] | role <name> <admin|rw|ro> | passwd <name> <pass> | del <name> | auth <on|off>]\n");
        }
    } else {
        return FALSE;
    }
    return TRUE;
}

static U0 nas_shell_help(U0) {
    kprintf("  NAS\n");
    kprintf("    snapshot [list|create [note]|delete <id>|restore <id> [path]|auto <min> [keep]]\n");
    kprintf("    user [list|add <u> <p> [admin|rw|ro]|role <u> <admin|rw|ro>|passwd <u> <p>|del <u>|auth on|off]\n");
    kprintf("    nas [status|files|shares|devices|key|admit <ip>|block <ip>]\n");
    kprintf("    share [list|add|del|auth|cfg|reload]   tls (HTTPS panel URL and certificate fingerprint)\n");
}

static const ShellExtension s_nas_shell = { nas_shell_run, nas_shell_help, NULL, NULL };

U0 nas_shell_register(U0) {
    shell_register(&s_nas_shell);
}
