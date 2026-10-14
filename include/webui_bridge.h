#ifndef WEBUI_BRIDGE_H
#define WEBUI_BRIDGE_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif


// Telemetry & State Queries
I32 webui_read_file(const char* filename, char* buf, size_t max_len);
I32 webui_write_file(const char* filename, const void* data, size_t size);
I32 webui_delete_file(const char* filename);
I32 webui_file_exists(const char* filename);
U64 webui_file_size(const char* filename);
U32 webui_get_dav_file_count(const char* share_name);
Bool webui_get_dav_file_info(const char* share_name, U32 index, char* out_name, size_t name_max, U64* out_size);
Bool webui_is_client_admitted(U32 ip);
I32 webui_backup_children(const char* rel, char* out, size_t max);

#ifdef __cplusplus
}
#endif

#endif // WEBUI_BRIDGE_H
