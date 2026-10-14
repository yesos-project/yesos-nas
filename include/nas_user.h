#ifndef NAS_USER_H
#define NAS_USER_H

#include "types.h"

#define NAS_MAX_USERS         8
#define NAS_MAX_USERNAME_LEN  32
#define NAS_MAX_PASSWORD_LEN  32

#define NAS_ROLE_RO           0 // Read-Only access (e.g. Media/Guest)
#define NAS_ROLE_RW           1 // Read-Write access (e.g. Workstation/Laptop)
#define NAS_ROLE_ADMIN        2 // Full Administrator (All Shares + Config)

typedef struct {
    char username[NAS_MAX_USERNAME_LEN];
    U8   salt[16];             // Per-user random salt
    U8   pw_hash[32];          // Argon2id(password, salt)
    U8   role;                 // NAS_ROLE_*
    Bool active;
    U32  allowed_shares_mask;  // Bitmask: bit 0=/share, bit 1=/media, bit 2=/backup
    U32  failed_attempts;
    U64  lockout_until_ms;
} NASUser;

#define NAS_USERS_MAGIC       0x32554E59u // "YNU2"
#define NAS_USERS_VERSION     2u
#define NAS_MIN_PASSWORD_LEN  8

typedef struct {
    U32     magic;             // NAS_USERS_MAGIC
    U32     version;           // NAS_USERS_VERSION
    U32     user_count;
    Bool    auth_required;     // TRUE: Clients must provide valid credentials
    NASUser users[NAS_MAX_USERS];
} NASUserState;

U0            nas_user_init(U0);
NASUserState* nas_user_get_state(U0);
Bool          nas_user_is_auth_required(U0);
U0            nas_user_set_auth_required(Bool req);
Bool          nas_user_add(const char* username, const char* password, U8 role);
Bool          nas_user_remove(const char* username);
Bool          nas_user_change_password(const char* username, const char* new_pass);
Bool          nas_user_set_role(const char* username, U8 role);   // keeps at least one admin
Bool          nas_user_authenticate(const char* username, const char* password, NASUser** out_user);
NASUser*      nas_user_get_by_name(const char* username);
U0            nas_user_list(U0);

#endif // NAS_USER_H
