#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include "types.h"

// ============================================================================
// YesOS NAS - snapshots of the data shares into the read-only /backup area.
//
// A snapshot "backup/snap-NNNN/" links every file of share/, media/ and vault/
// (vault ciphertext, never decrypted) to the same RedSea extents: no data is
// copied, and RedSea's copy-on-write means later changes allocate new extents
// while the snapshot keeps the old ones. A snapshot therefore costs only the
// space of data that has since been changed or deleted, plus one directory
// entry per file (the RedSea directory holds 1024 entries in total).
//
// SYS/ (accounts, keys, configuration) is never included. backup/ can only be
// changed through this module (see redsea_eml_set_backup_writer).
// ============================================================================

#define SNAP_PREFIX        "backup/snap-"
#define SNAP_MANIFEST      ".snapshot"
#define SNAP_CONFIG_FILE   "SYS/SNAPSHOT.CFG"

typedef struct {
    U32  id;
    Bool automatic;
    char created_by[32];
    char client_time[32];      // time reported by the creator's browser (the NAS has no clock)
    char note[64];
    U64  created_boot_sec;     // uptime at creation (meaningful only within that boot)
    U32  files;
    U64  bytes;                // logical size of the files
    U64  unique_bytes;         // space freed by deleting this snapshot
} SnapshotInfo;

U0   snapshot_init(U0);        // loads SYS/SNAPSHOT.CFG (after RedSea and VFS)
U0   snapshot_poll(U0);        // main loop: automatic snapshots

// Each returns TRUE on success and writes a (Spanish) message to `msg`.
Bool snapshot_create(const char* who, const char* note, const char* client_time, Bool automatic,
                     U32* out_id, char* msg, size_t msg_max);
Bool snapshot_delete(U32 id, char* msg, size_t msg_max);
// `path` is the original name (e.g. "share/fotos/a.jpg"); NULL or "" restores every file.
Bool snapshot_restore(U32 id, const char* path, char* msg, size_t msg_max);
Bool snapshot_set_auto(U32 interval_minutes, U32 keep, char* msg, size_t msg_max);
U0   snapshot_get_auto(U32* interval_minutes, U32* keep, U64* next_in_sec);
Bool snapshot_run_auto_now(char* msg, size_t msg_max);

U32  snapshot_list(SnapshotInfo* out, U32 max);   // ascending id
Bool snapshot_in_scope(const char* name);         // share/, media/ or vault/
U32  snapshot_entries_needed(U0);                 // directory entries a new snapshot needs
U0   snapshot_print(U0);

// Files under backup/ that belong to no snapshot (e.g. left by the old,
// simulated backup manager). Console only: lists them, or deletes them.
U32  snapshot_legacy(Bool delete_them);

#endif // SNAPSHOT_H
