// ============================================================================
// YesOS NAS - remote commands on UDP 31415 (and the lab port 5555)
// ============================================================================
// Port 31415 first carries the encrypted NAS channel (Noise NK). Plain
// datagrams with REMOTE_CMD_MAGIC are the legacy command protocol: NAS
// storage commands (0x20-0x2F), beep, telemetry on request and, only in
// DEV_REMOTE builds, shell / HolyQ / package deployment.

#include "nas_remote.h"
#include "nas_secure.h"
#include "nas_server.h"
#include "virtio_net.h"
#include "kprintf.h"
#include "memory.h"
#include "speaker.h"
#include "shell.h"
#include "holyq_jit.h"
#include "ypkg.h"

static U8* g_net_pkg_buf = NULL;
static U32 g_net_pkg_alloc = 0;
static U32 g_net_pkg_received = 0;

Bool nas_remote_udp(const NetUdpDatagram* d) {
    if (d->len < sizeof(uint32_t)) return FALSE;

    // Encrypted NAS channel (Noise NK)
    if (d->dst_port == NAS_SERVER_PORT) {
        static U8 s_secure_reply[1024];
        size_t reply_len = 0;
        if (nas_secure_handle_datagram(d->src_ip, d->data, d->len, s_secure_reply, sizeof(s_secure_reply), &reply_len)) {
            if (reply_len) net_udp_reply(d, s_secure_reply, reply_len);
            return TRUE;
        }
    }

    U32 magic;
    MemCpy(&magic, d->data, sizeof(magic));
    if (magic == REMOTE_CMD_MAGIC && d->len >= sizeof(YesOSRemoteCommand) - 256) {
        // Work on a bounded, NUL-terminated copy: the wire payload_len is
        // attacker-controlled and the datagram may be shorter than the struct.
        // The trailing byte keeps payload[] NUL-terminated even when a
        // binary chunk uses all 256 bytes.
        static struct __attribute__((packed)) {
            YesOSRemoteCommand c;
            char nul;
        } s_cmd_copy;
        MemSet(&s_cmd_copy, 0, sizeof(s_cmd_copy));
        size_t copy_len = d->len < sizeof(s_cmd_copy.c) ? d->len : sizeof(s_cmd_copy.c);
        MemCpy(&s_cmd_copy.c, d->data, copy_len);
        size_t payload_avail = copy_len - (sizeof(YesOSRemoteCommand) - sizeof(s_cmd_copy.c.payload));
        if (s_cmd_copy.c.payload_len > payload_avail) s_cmd_copy.c.payload_len = (uint32_t)payload_avail;
        const YesOSRemoteCommand* cmd = &s_cmd_copy.c;

        YesOSRemoteResponse resp;
        MemSet(&resp, 0, sizeof(resp));
        resp.magic = REMOTE_RESP_MAGIC;
        resp.seq = cmd->seq;
        resp.status = 0; // OK

#ifndef YESOS_DEV_REMOTE
        // Unauthenticated remote shell, JIT evaluation and package install
        // would give anyone on the LAN full M-mode control (and the vault
        // key in RAM). They exist only in developer builds: make DEV_REMOTE=1
        if (cmd->cmd_type == REMOTE_CMD_SHELL_EXEC || cmd->cmd_type == REMOTE_CMD_HOLYQ_EVAL ||
            cmd->cmd_type == REMOTE_CMD_PKG_BEGIN || cmd->cmd_type == REMOTE_CMD_PKG_CHUNK ||
            cmd->cmd_type == REMOTE_CMD_PKG_FINISH) {
            kprintf("\n[NET] Rejected remote dev command %u (build with DEV_REMOTE=1 to enable).\n",
                    (U32)cmd->cmd_type);
            ksnprintf(resp.response, sizeof(resp.response), "ERR: REMOTE DEV COMMANDS DISABLED IN THIS BUILD");
            resp.resp_len = StrLen(resp.response);
            resp.status = 1;
        } else
#endif
        if (cmd->cmd_type == REMOTE_CMD_SHELL_EXEC) {
            kprintf("\n[NET REMOTE CMD] Executing: '%s'\n", cmd->payload);
            shell_execute_command(cmd->payload);
            ksnprintf(resp.response, sizeof(resp.response), "OK: Executed '%s'", cmd->payload);
            resp.resp_len = StrLen(resp.response);
            speaker_event(BEEP_SUCCESS);
        } else if (cmd->cmd_type == REMOTE_CMD_HOLYQ_EVAL) {
            kprintf("\n[NET REMOTE JIT] Evaluating HolyQ: '%s'\n", cmd->payload);
            holyq_jit_compile_and_run(cmd->payload);
            ksnprintf(resp.response, sizeof(resp.response), "OK: HolyQ evaluated");
            resp.resp_len = StrLen(resp.response);
            speaker_event(BEEP_SUCCESS);
        } else if (cmd->cmd_type == REMOTE_CMD_REQUEST_TELEMETRY) {
            net_telemetry_to_port(d->src_port);
            ksnprintf(resp.response, sizeof(resp.response), "OK: Telemetry broadcasted");
            resp.resp_len = StrLen(resp.response);
        } else if (cmd->cmd_type == REMOTE_CMD_BEEP) {
            speaker_event(BEEP_CONFIRM);
            ksnprintf(resp.response, sizeof(resp.response), "OK: Earcon beep triggered");
            resp.resp_len = StrLen(resp.response);
        } else if (cmd->cmd_type == REMOTE_CMD_PKG_BEGIN) {
            U32 total_sz = 0;
            if (cmd->payload_len >= 4) {
                total_sz = *(const U32*)cmd->payload;
            }
            if (total_sz == 0 || total_sz > 16 * 1024 * 1024) total_sz = 2 * 1024 * 1024;

            if (g_net_pkg_buf) Free(g_net_pkg_buf);
            g_net_pkg_buf = (U8*)Malloc(total_sz + 1024);
            g_net_pkg_alloc = total_sz + 1024;
            g_net_pkg_received = 0;

            kprintf("\n[NET DEPLOY] PKG_BEGIN received: Ready for %u bytes transfer...\n", total_sz);
            ksnprintf(resp.response, sizeof(resp.response), "OK: PKG_BEGIN ready for %u bytes", total_sz);
            resp.resp_len = StrLen(resp.response);
            speaker_event(BEEP_CONFIRM);
        } else if (cmd->cmd_type == REMOTE_CMD_PKG_CHUNK) {
            if (g_net_pkg_buf && cmd->payload_len > 0) {
                if (g_net_pkg_received + cmd->payload_len <= g_net_pkg_alloc) {
                    MemCpy(g_net_pkg_buf + g_net_pkg_received, cmd->payload, cmd->payload_len);
                    g_net_pkg_received += cmd->payload_len;
                    ksnprintf(resp.response, sizeof(resp.response), "OK: Chunk %u bytes (total: %u)",
                              cmd->payload_len, g_net_pkg_received);
                } else {
                    ksnprintf(resp.response, sizeof(resp.response), "ERROR: Buffer overflow");
                    resp.status = 1;
                }
            } else {
                ksnprintf(resp.response, sizeof(resp.response), "ERROR: Buffer not initialized");
                resp.status = 1;
            }
            resp.resp_len = StrLen(resp.response);
        } else if (cmd->cmd_type == REMOTE_CMD_PKG_FINISH) {
            kprintf("\n[NET DEPLOY] PKG_FINISH: Installing %u bytes package into RedSea-EML...\n", g_net_pkg_received);
            if (g_net_pkg_buf && g_net_pkg_received >= sizeof(YPkgHeader)) {
                Bool ok = ypkg_install_from_memory(g_net_pkg_buf, g_net_pkg_received);
                if (ok) {
                    ksnprintf(resp.response, sizeof(resp.response), "OK: Installed successfully into /APPS/");
                } else {
                    ksnprintf(resp.response, sizeof(resp.response), "ERROR: Installation failed");
                    resp.status = 1;
                }
            } else {
                ksnprintf(resp.response, sizeof(resp.response), "ERROR: Invalid package buffer");
                resp.status = 1;
            }
            if (g_net_pkg_buf) {
                Free(g_net_pkg_buf);
                g_net_pkg_buf = NULL;
            }
            g_net_pkg_alloc = 0;
            g_net_pkg_received = 0;
            resp.resp_len = StrLen(resp.response);
        } else if (cmd->cmd_type >= 0x20 && cmd->cmd_type <= 0x2F) {
            // YesOS NAS & Edge AI Storage Protocol
            U32 out_len = 0;
            Bool ok = nas_server_process_remote_command(cmd->cmd_type, cmd->payload, cmd->payload_len,
                                                       d->src_ip, resp.response, &out_len);
            resp.status = ok ? 0 : 1;
            resp.resp_len = out_len;
        } else {
            ksnprintf(resp.response, sizeof(resp.response), "UNKNOWN_COMMAND");
            resp.status = 1;
        }

        net_udp_reply(d, (const U8*)&resp, sizeof(resp));
        return TRUE;
    }
    return FALSE;
}
