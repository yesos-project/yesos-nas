#include "nas_secure.h"
#include "nas_server.h"
#include "yesos_crypto.h"
#include "vfs.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"

// ============================================================================
// YesOS 2.0 - Secure NAS channel (UDP 31415)
//
// Handshake: Noise_NK_25519_ChaChaPoly_BLAKE2s, prologue "YesOS-NAS-v1".
// The client pins the appliance's static public key (shown by `nas key`).
//
//   C -> S  HS_MAGIC | ver | 0 0 0 | noise msg1 (e, es)          56 bytes
//   S -> C  HS_MAGIC | ver | 0 0 0 | session_id | noise msg2      64 bytes
//   C -> S  DATA_MAGIC | session_id | nonce | AEAD{cmd, len, payload}
//   S -> C  DATA_MAGIC | session_id | nonce | AEAD{status, len, data}
//   S -> C  ERR_MAGIC  | code (I32) | text           (unauthenticated errors)
//
// All integers are little-endian. Nonces must strictly increase per session.
// ============================================================================

#define NAS_SEC_HS_MAGIC    0x5945534Eu  // "YESN"
#define NAS_SEC_DATA_MAGIC  0x59455345u  // "YESE"
#define NAS_SEC_ERR_MAGIC   0x59455358u  // "YESX"
#define NAS_SEC_VERSION     1
#define NAS_SEC_MSG1_LEN    48           // e (32) + tag of empty payload (16)
#define NAS_SEC_MAX_PAYLOAD 512
#define NAS_SEC_RESP_MAX    256
#define NAS_KEY_FILE        "SYS/NOISE.KEY"

typedef struct __attribute__((packed)) {
    U32 magic;
    U8  version;
    U8  reserved[3];
} NASSecHsHeader;

typedef struct __attribute__((packed)) {
    U32 magic;
    U64 session_id;
    U64 nonce;
} NASSecDataHeader;

typedef struct __attribute__((packed)) {
    U16 cmd_type;
    U16 payload_len;
} NASSecInnerReq;

typedef struct __attribute__((packed)) {
    U16 status;
    U16 data_len;
} NASSecInnerResp;

static Bool g_key_ready = FALSE;

U0 nas_secure_init(U0) {
    U8 key[32];
    size_t sz = 0;
    U8* data = vfs_read_file(NAS_KEY_FILE, &sz);
    Bool loaded = FALSE;
    if (data) {
        if (sz == sizeof(key)) {
            MemCpy(key, data, sizeof(key));
            loaded = TRUE;
        }
        yc_wipe(data, sz);
        Free(data);
    }
    if (!loaded) {
        if (!entropy_random(key, sizeof(key))) {
            kprintf("[NAS SECURE] ERROR: cannot generate static key (entropy unavailable).\n");
            return;
        }
        if (!vfs_write_file(NAS_KEY_FILE, key, sizeof(key))) {
            kprintf("[NAS SECURE] WARNING: could not persist %s; key changes on reboot.\n", NAS_KEY_FILE);
        }
    }
    g_key_ready = (yc_noise_set_static_key(key) == YC_OK);
    yc_wipe(key, sizeof(key));

    if (g_key_ready) {
        kprintf("[NAS SECURE] Noise NK channel ready on UDP %u (%s key).\n",
                NAS_SERVER_PORT, loaded ? "persisted" : "new");
        nas_secure_print_key();
    }
}

U0 nas_secure_print_key(U0) {
    U8 pub[32];
    if (yc_noise_public_key(pub) != YC_OK) {
        kprintf("[NAS SECURE] No static key installed.\n");
        return;
    }
    char hex[65];
    static const char digits[] = "0123456789abcdef";
    for (U32 i = 0; i < 32; i++) {
        hex[i * 2] = digits[pub[i] >> 4];
        hex[i * 2 + 1] = digits[pub[i] & 0xF];
    }
    hex[64] = '\0';
    kprintf("[NAS SECURE] Server public key (verify on first connect):\n");
    kprintf("[NAS SECURE]   %s\n", hex);
}

static size_t write_error(U8* out, size_t cap, I32 code, const char* text) {
    size_t tlen = StrLen(text);
    if (cap < 8) return 0;
    if (tlen > cap - 8) tlen = cap - 8;
    U32 magic = NAS_SEC_ERR_MAGIC;
    MemCpy(out, &magic, 4);
    MemCpy(out + 4, &code, 4);
    MemCpy(out + 8, text, tlen);
    return 8 + tlen;
}

static size_t handle_handshake(U32 ip, const U8* data, size_t len, U8* out, size_t cap) {
    if (!g_key_ready) return write_error(out, cap, YC_ERR_NO_KEY, "ERR: SECURE CHANNEL UNAVAILABLE");
    if (len != sizeof(NASSecHsHeader) + NAS_SEC_MSG1_LEN || data[4] != NAS_SEC_VERSION) {
        return write_error(out, cap, YC_ERR_PARAM, "ERR: BAD HANDSHAKE");
    }

    // Only devices admitted at the physical console may open sessions; this
    // also stops unknown hosts from evicting sessions of admitted ones.
    char reason[256];
    if (!nas_server_check_admission(ip, reason)) {
        return write_error(out, cap, YC_ERR_AUTH, reason);
    }

    NASSecHsHeader hdr = { NAS_SEC_HS_MAGIC, NAS_SEC_VERSION, { 0, 0, 0 } };
    size_t hdr_len = sizeof(hdr) + sizeof(U64);
    size_t msg2_len = 0;
    U32 slot = 0;
    U64 id = 0;
    I32 r = yc_noise_accept(data + sizeof(NASSecHsHeader), NAS_SEC_MSG1_LEN, out + hdr_len, cap - hdr_len,
                            &msg2_len, &slot, &id, timer_get_uptime_ms());
    if (r != YC_OK) {
        // Wrong pinned key on the client side shows up here as an AEAD failure.
        return write_error(out, cap, r, "ERR: HANDSHAKE FAILED");
    }
    nas_server_session_reset(slot);
    MemCpy(out, &hdr, sizeof(hdr));
    MemCpy(out + sizeof(hdr), &id, sizeof(id));
    return hdr_len + msg2_len;
}

static size_t handle_data(U32 ip, const U8* data, size_t len, U8* out, size_t cap) {
    if (len < sizeof(NASSecDataHeader) + 16) return write_error(out, cap, YC_ERR_PARAM, "ERR: SHORT PACKET");

    NASSecDataHeader hdr;
    MemCpy(&hdr, data, sizeof(hdr));
    const U8* ct = data + sizeof(hdr);
    size_t ct_len = len - sizeof(hdr);

    static U8 plain[sizeof(NASSecInnerReq) + NAS_SEC_MAX_PAYLOAD + 16];
    size_t plain_len = 0;
    U32 slot = 0;
    if (ct_len - 16 > sizeof(plain)) return write_error(out, cap, YC_ERR_PARAM, "ERR: PACKET TOO LARGE");
    I32 r = yc_noise_decrypt(hdr.session_id, hdr.nonce, ct, ct_len, plain, sizeof(plain), &plain_len, &slot,
                             timer_get_uptime_ms());
    if (r != YC_OK) {
        const char* msg = (r == YC_ERR_NO_SESSION) ? "ERR: UNKNOWN SESSION - HANDSHAKE AGAIN" :
                          (r == YC_ERR_REPLAY)     ? "ERR: REPLAYED NONCE" : "ERR: DECRYPTION FAILED";
        return write_error(out, cap, r, msg);
    }

    NASSecInnerReq req;
    if (plain_len < sizeof(req)) return write_error(out, cap, YC_ERR_PARAM, "ERR: BAD REQUEST");
    MemCpy(&req, plain, sizeof(req));
    if (req.payload_len > plain_len - sizeof(req) || req.payload_len > NAS_SEC_MAX_PAYLOAD) {
        return write_error(out, cap, YC_ERR_PARAM, "ERR: BAD REQUEST LENGTH");
    }

    static char payload[NAS_SEC_MAX_PAYLOAD + 1];
    MemSet(payload, 0, sizeof(payload));
    MemCpy(payload, plain + sizeof(req), req.payload_len);
    yc_wipe(plain, sizeof(plain));

    static U8 resp_plain[sizeof(NASSecInnerResp) + NAS_SEC_RESP_MAX];
    char* resp_data = (char*)(resp_plain + sizeof(NASSecInnerResp));
    U32 resp_len = 0;
    MemSet(resp_plain, 0, sizeof(resp_plain));
    Bool ok = nas_server_process_secure_command(slot, req.cmd_type, payload, req.payload_len, ip,
                                                resp_data, &resp_len);
    yc_wipe((U8*)payload, sizeof(payload));
    if (resp_len > NAS_SEC_RESP_MAX) resp_len = NAS_SEC_RESP_MAX;

    NASSecInnerResp rh = { (U16)(ok ? 0 : 1), (U16)resp_len };
    MemCpy(resp_plain, &rh, sizeof(rh));

    size_t ct_out_len = 0;
    r = yc_noise_encrypt(hdr.session_id, hdr.nonce, resp_plain, sizeof(rh) + resp_len,
                         out + sizeof(hdr), cap - sizeof(hdr), &ct_out_len);
    yc_wipe(resp_plain, sizeof(resp_plain));
    if (r != YC_OK) return write_error(out, cap, r, "ERR: ENCRYPTION FAILED");
    MemCpy(out, &hdr, sizeof(hdr));
    return sizeof(hdr) + ct_out_len;
}

Bool nas_secure_handle_datagram(U32 src_ip, const U8* data, size_t len, U8* out, size_t out_cap, size_t* out_len) {
    *out_len = 0;
    if (len < 4) return FALSE;
    U32 magic;
    MemCpy(&magic, data, 4);
    if (magic == NAS_SEC_HS_MAGIC) {
        *out_len = handle_handshake(src_ip, data, len, out, out_cap);
        return TRUE;
    }
    if (magic == NAS_SEC_DATA_MAGIC) {
        *out_len = handle_data(src_ip, data, len, out, out_cap);
        return TRUE;
    }
    return FALSE;
}
