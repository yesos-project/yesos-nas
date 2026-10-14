#ifndef NAS_SERVER_H
#define NAS_SERVER_H

#include "types.h"
#include "nas_user.h"

// ============================================================================
// YesOS 2.0 - Network Attached Storage (NAS) & Edge AI Server
// Target: Bare-Metal RISC-V M-Mode
// ============================================================================

#define NAS_SERVER_PORT         31415   // Sovereign UDP Storage Service Port (Pi Math 3.1415)
#define NAS_SERVER_CONFIG_FILE  "SYS/SMB.CFG" // shared folders (old name kept for existing disks)
#define NAS_MAX_SHARES          8
#define NAS_MAX_CLIENTS         8

// Command Types for Network Requests
#define NAS_CMD_INFO            0x20
#define NAS_CMD_LIST            0x21
#define NAS_CMD_READ            0x22
#define NAS_CMD_WRITE           0x23
#define NAS_CMD_AI_SEARCH       0x24
#define NAS_CMD_SMART           0x25
#define NAS_CMD_AUTH            0x26    // Authenticate with user credentials
#define NAS_CMD_USER_MGR        0x27    // User Account Administration

typedef struct {
    char  share_name[32];
    char  mount_path[64];
    char  comment[64];
    U64   total_mb;
    U64   used_mb;
    Bool  read_only;
    Bool  active;
} NASShare;

typedef enum {
    NAS_ACCESS_PENDING = 0,  // Detected on LAN, awaiting physical approval on YesOS
    NAS_ACCESS_ADMITTED = 1, // Admitted via physical access (trusted whitelist)
    NAS_ACCESS_BLOCKED = 2,  // Hostile / Permanently blocked
} NASAccessStatus;

typedef struct {
    U32   ip;
    U64   last_seen_tick;
    U64   bytes_read;
    U64   bytes_written;
    Bool  is_blocked;
    U8    access_status;     // NASAccessStatus
    char  client_name[32];
    char  auth_username[NAS_MAX_USERNAME_LEN];
    Bool  is_authenticated;
    U8    user_role;         // NAS_ROLE_*
} NASConnectedClient;

typedef struct {
    Bool  is_running;
    char  server_name[32];
    char  workgroup[32];
    U64   start_tick;
    U64   total_pool_mb;
    U64   used_pool_mb;
    U64   total_read_bytes;
    U64   total_write_bytes;
    U32   active_clients_count;
    U32   shares_count;
    NASShare shares[NAS_MAX_SHARES];
    NASConnectedClient clients[NAS_MAX_CLIENTS];
} NASServerState;

// Protocol Packet Formats for Remote File Operations
typedef struct __attribute__((packed)) {
    uint32_t offset;
    uint16_t chunk_len;
    uint16_t flags; // 0 = read data chunk, 1 = stat query (returns "SIZE:<bytes>")
    char     path[248];
} NASReadRequest;

// High-level NAS Interface
U0   nas_server_init(U0);
NASServerState* nas_server_get_state(U0);

// Shared folder configuration (SYS/SMB.CFG)
Bool nas_config_load(U0);
Bool nas_config_save(U0);
Bool nas_add_share(const char* name, const char* path, Bool read_only, const char* comment);
Bool nas_remove_share(const char* name);
U0   nas_print_share_list(U0);
U0   nas_print_share_config(U0);

// Client interaction & packet handling
// Secure (Noise) channel entry points, see kernel/nas_secure.c
U0   nas_server_session_reset(U32 slot);
Bool nas_server_check_admission(U32 client_ip, char* out_resp);
Bool nas_server_process_secure_command(U32 slot, U16 cmd_type, const char* payload, U32 payload_len,
                                       U32 client_ip, char* out_resp, U32* out_resp_len);
Bool nas_server_process_remote_command(U16 cmd_type, const char* payload, U32 payload_len,
                                       U32 client_ip, char* out_resp, U32* out_resp_len);

// Physical Device Admission Control (Local Console / Physical Screen Access Only)
U32  nas_parse_ip(const char* str);
Bool nas_admit_client_ip(U32 ip, const char* name);
Bool nas_block_client_ip(U32 ip);
U32  nas_admit_all_pending(U0);
Bool nas_is_client_admitted(U32 ip);
U0   nas_print_devices(U0);

// Storage Management Operations
U0   nas_print_status(U0);
U0   nas_print_files(U0);
U0   nas_print_shares(U0);

#endif // NAS_SERVER_H
