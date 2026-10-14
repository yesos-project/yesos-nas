#include "snapshot.h"
#include "redsea_eml.h"
#include "vfs.h"
#include "timer.h"
#include "kprintf.h"
#include "memory.h"

static U32 g_auto_minutes = 0;   // 0 = automatic snapshots off
static U32 g_auto_keep = 7;      // automatic snapshots kept (manual ones are never pruned)
static U64 g_last_auto_ms = 0;

#define SNAP_PREFIX_LEN 12       // "backup/snap-"

static U32 delete_prefix(const char* dir);

Bool snapshot_in_scope(const char* name) {
    return StrNICmp(name, "share/", 6) == 0 || StrNICmp(name, "media/", 6) == 0 ||
           StrNICmp(name, "vault/", 6) == 0;
}

// "backup/snap-0007/..." -> 7; 0 if the name is not inside a snapshot.
static U32 snap_id_of(const char* name, const char** rest) {
    if (StrNCmp(name, SNAP_PREFIX, SNAP_PREFIX_LEN) != 0) return 0;
    const char* p = name + SNAP_PREFIX_LEN;
    U32 id = 0, digits = 0;
    while (*p >= '0' && *p <= '9' && digits < 9) id = id * 10 + (U32)(*p++ - '0'), digits++;
    if (digits < 4 || *p != '/') return 0;
    if (rest) *rest = p + 1;
    return id;
}

static U0 snap_dir(U32 id, char* out, size_t max) {
    ksnprintf(out, max, SNAP_PREFIX "%04u/", id);
}

static Bool is_candidate(const RedSeaFileEntry* e) {
    return (e->flags & REDSEA_FLAG_USED) && !(e->flags & REDSEA_FLAG_DIR) && snapshot_in_scope(e->name);
}

U32 snapshot_entries_needed(U0) {
    RedSeaVolume* v = redsea_eml_get_volume();
    U32 n = 1;   // manifest
    for (U32 i = 0; v && v->is_mounted && i < v->entry_count; i++) n += is_candidate(&v->entries[i]) ? 1 : 0;
    return n;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

static U32 parse_u32_after(const char* text, const char* key) {
    size_t kl = StrLen(key);
    for (const char* p = text; *p; p++) {
        if ((p == text || p[-1] == '\n') && StrNCmp(p, key, kl) == 0) {
            U32 v = 0;
            for (p += kl; *p >= '0' && *p <= '9'; p++) v = v * 10 + (U32)(*p - '0');
            return v;
        }
    }
    return 0xFFFFFFFFu;
}

// Removes snapshot folders that have files but no manifest (a create or a
// delete interrupted by a power cut).
static U0 recover_incomplete(U0) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted) return;
    // One pass: which snapshot ids have files, which have a manifest.
    static U32 ids[256];
    static Bool has_manifest[256];
    U32 n = 0;
    for (U32 i = 0; i < v->entry_count; i++) {
        const char* rest = NULL;
        U32 id = (v->entries[i].flags & REDSEA_FLAG_USED) ? snap_id_of(v->entries[i].name, &rest) : 0;
        if (!id) continue;
        U32 k = 0;
        while (k < n && ids[k] != id) k++;
        if (k == n) {
            if (n == 256) continue;
            ids[n] = id;
            has_manifest[n] = FALSE;
            n++;
        }
        if (StrCmp(rest, SNAP_MANIFEST) == 0) has_manifest[k] = TRUE;
    }
    for (U32 k = 0; k < n; k++) {
        if (has_manifest[k]) continue;
        char dir[24];
        snap_dir(ids[k], dir, sizeof(dir));
        U32 removed = delete_prefix(dir);
        kprintf("[SNAPSHOT] Recovery: removed incomplete snapshot %u (%u entries; interrupted create or delete).\n",
                ids[k], removed);
    }
}

U0 snapshot_init(U0) {
    recover_incomplete();
    size_t sz = 0;
    U8* data = vfs_read_file(SNAP_CONFIG_FILE, &sz);
    if (data) {
        U32 m = parse_u32_after((const char*)data, "interval_minutes=");
        U32 k = parse_u32_after((const char*)data, "keep=");
        if (m != 0xFFFFFFFFu) g_auto_minutes = m;
        if (k != 0xFFFFFFFFu && k > 0) g_auto_keep = k;
        Free(data);
    }
    g_last_auto_ms = timer_get_uptime_ms();
    U32 n = snapshot_list(NULL, 0);
    kprintf("[SNAPSHOT] %u snapshot(s) in /backup; automatic: %s", n, g_auto_minutes ? "every " : "off");
    if (g_auto_minutes) kprintf("%u min, keep %u", g_auto_minutes, g_auto_keep);
    kprintf("\n");
}

Bool snapshot_set_auto(U32 minutes, U32 keep, char* msg, size_t max) {
    if (minutes > 60 * 24 * 31 || keep == 0 || keep > 100) {
        ksnprintf(msg, max, "Invalid values: interval 0-44640 minutes, keep 1-100.");
        return FALSE;
    }
    char cfg[96];
    ksnprintf(cfg, sizeof(cfg), "# YesOS automatic snapshots\ninterval_minutes=%u\nkeep=%u\n", minutes, keep);
    if (!vfs_write_file(SNAP_CONFIG_FILE, cfg, StrLen(cfg))) {
        ksnprintf(msg, max, "%s could not be saved.", SNAP_CONFIG_FILE);
        return FALSE;
    }
    g_auto_minutes = minutes;
    g_auto_keep = keep;
    g_last_auto_ms = timer_get_uptime_ms();
    if (minutes) ksnprintf(msg, max, "Automatic snapshots every %u min; the last %u are kept.", minutes, keep);
    else ksnprintf(msg, max, "Automatic snapshots disabled.");
    kprintf("[SNAPSHOT] %s\n", msg);
    return TRUE;
}

U0 snapshot_get_auto(U32* minutes, U32* keep, U64* next_in_sec) {
    if (minutes) *minutes = g_auto_minutes;
    if (keep) *keep = g_auto_keep;
    if (next_in_sec) {
        U64 period = (U64)g_auto_minutes * 60 * 1000, now = timer_get_uptime_ms();
        U64 due = g_last_auto_ms + period;
        *next_in_sec = (!g_auto_minutes) ? 0 : (due > now ? (due - now) / 1000 : 0);
    }
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

static U0 manifest_value(const char* text, const char* key, char* out, size_t max) {
    size_t kl = StrLen(key);
    out[0] = '\0';
    for (const char* p = text; *p; p++) {
        if ((p == text || p[-1] == '\n') && StrNCmp(p, key, kl) == 0) {
            p += kl;
            size_t n = 0;
            while (*p && *p != '\n' && n + 1 < max) out[n++] = *p++;
            out[n] = '\0';
            return;
        }
    }
}

static U16 g_refs[REDSEA_DIR_ENTRIES_MAX];

U32 snapshot_list(SnapshotInfo* out, U32 max) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted) return 0;
    if (out && max) redsea_eml_extent_refcounts(g_refs);
    U32 ids[128];
    U32 n = 0;
    for (U32 i = 0; i < v->entry_count; i++) {
        const RedSeaFileEntry* e = &v->entries[i];
        const char* rest = NULL;
        U32 id = (e->flags & REDSEA_FLAG_USED) ? snap_id_of(e->name, &rest) : 0;
        if (!id) continue;
        Bool seen = FALSE;
        for (U32 k = 0; k < n && !seen; k++) seen = (ids[k] == id);
        if (!seen && n < 128) ids[n++] = id;
    }
    for (U32 a = 1; a < n; a++) {   // ascending
        U32 key = ids[a];
        I32 b = (I32)a - 1;
        while (b >= 0 && ids[b] > key) { ids[b + 1] = ids[b]; b--; }
        ids[b + 1] = key;
    }
    for (U32 k = 0; k < n && k < max; k++) {
        SnapshotInfo* s = &out[k];
        MemSet(s, 0, sizeof(*s));
        s->id = ids[k];
        char dir[24], mpath[48];
        snap_dir(s->id, dir, sizeof(dir));
        ksnprintf(mpath, sizeof(mpath), "%s" SNAP_MANIFEST, dir);
        size_t msz = 0;
        U8* m = redsea_eml_read_file(mpath, &msz);
        if (m) {
            char tmp[24];
            manifest_value((const char*)m, "created_by=", s->created_by, sizeof(s->created_by));
            manifest_value((const char*)m, "client_time=", s->client_time, sizeof(s->client_time));
            manifest_value((const char*)m, "note=", s->note, sizeof(s->note));
            manifest_value((const char*)m, "automatic=", tmp, sizeof(tmp));
            s->automatic = (tmp[0] == '1');
            U32 up = parse_u32_after((const char*)m, "uptime_sec=");
            s->created_boot_sec = (up == 0xFFFFFFFFu) ? 0 : up;
            Free(m);
        }
        size_t dl = StrLen(dir);
        for (U32 i = 0; i < v->entry_count; i++) {
            const RedSeaFileEntry* e = &v->entries[i];
            if (!(e->flags & REDSEA_FLAG_USED) || StrNCmp(e->name, dir, dl) != 0) continue;
            if (StrCmp(e->name + dl, SNAP_MANIFEST) == 0) continue;
            s->files++;
            s->bytes += e->byte_size;
            if (g_refs[i] == 1) s->unique_bytes += e->sector_count * 512;
        }
    }
    return n;
}

// ---------------------------------------------------------------------------
// Create / delete / restore
// ---------------------------------------------------------------------------

// A snapshot is valid only while its manifest exists: create writes it last,
// delete removes it first. After a power cut, a snapshot folder without a
// manifest is incomplete and snapshot_init() removes it.
static U32 delete_prefix(const char* dir) {
    U32 removed = 0;
    redsea_eml_set_backup_writer(TRUE);
    char mpath[48];
    ksnprintf(mpath, sizeof(mpath), "%s" SNAP_MANIFEST, dir);
    if (redsea_eml_exists(mpath) && redsea_eml_delete_file(mpath)) removed++;   // durable first
    removed += redsea_eml_delete_prefix(dir);
    redsea_eml_set_backup_writer(FALSE);
    return removed;
}

static U0 clean_field(const char* in, char* out, size_t max) {
    size_t n = 0;
    for (; in && *in && n + 1 < max; in++) {
        U8 c = (U8)*in;
        if (c >= 0x20 && c != 0x7F) out[n++] = (char)c;   // no newlines: one key per line
    }
    out[n] = '\0';
}

Bool snapshot_create(const char* who, const char* note, const char* client_time, Bool automatic,
                     U32* out_id, char* msg, size_t max) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted) {
        ksnprintf(msg, max, "No hay volumen RedSea montado.");
        return FALSE;
    }
    U32 need = snapshot_entries_needed();
    U32 freee = redsea_eml_free_entries();
    if (need > freee) {
        ksnprintf(msg, max, "The RedSea directory has no room: the snapshot needs %u entries and %u are left. "
                  "Delete old snapshots.", need, freee);
        return FALSE;
    }
    U32 id = 1;
    for (U32 i = 0; i < v->entry_count; i++) {
        U32 x = snap_id_of(v->entries[i].name, NULL);
        if (x >= id) id = x + 1;
    }
    if (id > 9999) {
        ksnprintf(msg, max, "Snapshot numbers are exhausted.");
        return FALSE;
    }
    char dir[24];
    snap_dir(id, dir, sizeof(dir));

    U32 n0 = v->entry_count, files = 0, skipped = 0;
    U64 bytes = 0;
    Bool ok = TRUE;
    redsea_eml_set_backup_writer(TRUE);
    for (U32 i = 0; i < n0 && ok; i++) {
        const RedSeaFileEntry* e = &v->entries[i];
        if (!is_candidate(e)) continue;
        char dst[REDSEA_MAX_FILENAME + 32];
        ksnprintf(dst, sizeof(dst), "%s%s", dir, e->name);
        if (StrLen(dst) >= REDSEA_MAX_FILENAME) { skipped++; continue; }
        U64 sz = e->byte_size;
        if (redsea_eml_link_new(i, dst, REDSEA_FLAG_READONLY, 0)) { files++; bytes += sz; }
        else ok = FALSE;
    }
    redsea_eml_barrier();   // every link durable before the manifest makes the snapshot valid
    char who_c[32], note_c[64], time_c[32];
    clean_field(who, who_c, sizeof(who_c));
    clean_field(note, note_c, sizeof(note_c));
    clean_field(client_time, time_c, sizeof(time_c));
    char manifest[320], mpath[48];
    ksnprintf(manifest, sizeof(manifest),
              "id=%u\nautomatic=%u\ncreated_by=%s\nclient_time=%s\nnote=%s\nuptime_sec=%u\nfiles=%u\nbytes=%u\n",
              id, automatic ? 1 : 0, who_c, time_c, note_c, (U32)(timer_get_uptime_ms() / 1000), files, (U32)bytes);
    ksnprintf(mpath, sizeof(mpath), "%s" SNAP_MANIFEST, dir);
    if (ok) ok = redsea_eml_write_file(mpath, manifest, StrLen(manifest), REDSEA_FLAG_READONLY);
    redsea_eml_set_backup_writer(FALSE);
    if (!ok) {
        delete_prefix(dir);
        ksnprintf(msg, max, "The snapshot could not be created (directory or disk full); it was undone.");
        return FALSE;
    }
    if (out_id) *out_id = id;
    if (skipped) {
        ksnprintf(msg, max, "Snapshot %u created: %u files (%u skipped: name too long).", id, files, skipped);
    } else {
        ksnprintf(msg, max, "Snapshot %u created: %u files, no data copied.", id, files);
    }
    kprintf("[SNAPSHOT] %s\n", msg);
    return TRUE;
}

static Bool snapshot_exists(U32 id) {
    RedSeaVolume* v = redsea_eml_get_volume();
    for (U32 i = 0; v && v->is_mounted && i < v->entry_count; i++) {
        if ((v->entries[i].flags & REDSEA_FLAG_USED) && snap_id_of(v->entries[i].name, NULL) == id) return TRUE;
    }
    return FALSE;
}

// Hart 0 only; too large for the stack.
static SnapshotInfo g_list[128];

Bool snapshot_delete(U32 id, char* msg, size_t max) {
    if (!snapshot_exists(id)) {
        ksnprintf(msg, max, "No such snapshot %u.", id);
        return FALSE;
    }
    char dir[24];
    snap_dir(id, dir, sizeof(dir));
    U64 before = redsea_eml_get_free_sectors();
    U32 n = delete_prefix(dir);
    U64 freed = redsea_eml_get_free_sectors() - before;
    ksnprintf(msg, max, "Snapshot %u deleted (%u entries, %u KiB freed).", id, n, (U32)(freed / 2));
    kprintf("[SNAPSHOT] %s\n", msg);
    return TRUE;
}

Bool snapshot_restore(U32 id, const char* path, char* msg, size_t max) {
    if (!snapshot_exists(id)) {
        ksnprintf(msg, max, "No such snapshot %u.", id);
        return FALSE;
    }
    RedSeaVolume* v = redsea_eml_get_volume();
    char dir[24];
    snap_dir(id, dir, sizeof(dir));
    size_t dl = StrLen(dir);
    if (path && path[0]) {
        if (!snapshot_in_scope(path) || StrLen(path) + dl >= REDSEA_MAX_FILENAME) {
            ksnprintf(msg, max, "Invalid path.");
            return FALSE;
        }
        char src[REDSEA_MAX_FILENAME];
        ksnprintf(src, sizeof(src), "%s%s", dir, path);
        if (!redsea_eml_exists(src)) {
            ksnprintf(msg, max, "'%s' is not in snapshot %u.", path, id);
            return FALSE;
        }
        if (!redsea_eml_link(src, path, 0, REDSEA_FLAG_READONLY)) {
            ksnprintf(msg, max, "'%s' could not be restored (directory full).", path);
            return FALSE;
        }
        ksnprintf(msg, max, "Restored '%s' from snapshot %u.", path, id);
        kprintf("[SNAPSHOT] %s\n", msg);
        return TRUE;
    }
    U32 restored = 0, failed = 0;
    U32 n0 = v->entry_count;
    for (U32 i = 0; i < n0; i++) {
        const RedSeaFileEntry* e = &v->entries[i];
        if (!(e->flags & REDSEA_FLAG_USED) || StrNCmp(e->name, dir, dl) != 0) continue;
        const char* orig = e->name + dl;
        if (!snapshot_in_scope(orig)) continue;   // skips the manifest
        char src[REDSEA_MAX_FILENAME], dst[REDSEA_MAX_FILENAME];
        StrNCpy(src, e->name, sizeof(src) - 1);
        src[sizeof(src) - 1] = '\0';
        StrNCpy(dst, orig, sizeof(dst) - 1);
        dst[sizeof(dst) - 1] = '\0';
        if (redsea_eml_link(src, dst, 0, REDSEA_FLAG_READONLY)) restored++;
        else failed++;
    }
    if (failed) ksnprintf(msg, max, "Restored %u files from snapshot %u; %u failed (directory full).", restored, id, failed);
    else ksnprintf(msg, max, "Restored %u files from snapshot %u (files created afterwards are kept).", restored, id);
    kprintf("[SNAPSHOT] %s\n", msg);
    return failed == 0;
}

// ---------------------------------------------------------------------------
// Automatic snapshots
// ---------------------------------------------------------------------------

static U0 prune_automatic(U0) {
    SnapshotInfo* list = g_list;
    U32 n = snapshot_list(list, 128), autos = 0;
    for (U32 i = 0; i < n; i++) autos += list[i].automatic ? 1 : 0;
    for (U32 i = 0; i < n && autos > g_auto_keep; i++) {   // oldest first
        if (!list[i].automatic) continue;
        char m[128];
        snapshot_delete(list[i].id, m, sizeof(m));
        autos--;
    }
}

Bool snapshot_run_auto_now(char* msg, size_t max) {
    g_last_auto_ms = timer_get_uptime_ms();
    U32 id = 0;
    Bool ok = snapshot_create("auto", "automatic", "", TRUE, &id, msg, max);
    if (ok) prune_automatic();
    return ok;
}

U0 snapshot_poll(U0) {
    if (!g_auto_minutes) return;
    U64 now = timer_get_uptime_ms();
    if (now - g_last_auto_ms < (U64)g_auto_minutes * 60 * 1000) return;
    char msg[160];
    if (!snapshot_run_auto_now(msg, sizeof(msg))) kprintf("[SNAPSHOT] Automatic snapshot failed: %s\n", msg);
}

U0 snapshot_print(U0) {
    SnapshotInfo* list = g_list;
    U32 n = snapshot_list(list, 128);
    U32 m, k;
    U64 next;
    snapshot_get_auto(&m, &k, &next);
    kprintf("\n--- Snapshots in /backup (share, media, vault; SYS is never included) ---\n");
    if (!n) kprintf("  (none)\n");
    for (U32 i = 0; i < n; i++) {
        kprintf("  #%u  %-5s  %4u files  %8u KiB  unique %8u KiB  by %s  %s%s%s\n", list[i].id,
                list[i].automatic ? "auto" : "", list[i].files, (U32)(list[i].bytes / 1024),
                (U32)(list[i].unique_bytes / 1024), list[i].created_by,
                list[i].client_time, list[i].note[0] ? "  " : "", list[i].note);
    }
    kprintf("  Directory entries free: %u (a new snapshot needs %u)\n", redsea_eml_free_entries(), snapshot_entries_needed());
    if (m) kprintf("  Automatic: every %u min, keep %u (next in %u s)\n", m, k, (U32)next);
    else kprintf("  Automatic: off\n");
}

U32 snapshot_legacy(Bool delete_them) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted) return 0;
    U32 n = 0;
    U64 bytes = 0;
    if (delete_them) redsea_eml_set_backup_writer(TRUE);
    for (I32 i = (I32)v->entry_count - 1; i >= 0; i--) {
        if (i >= (I32)v->entry_count) continue;
        const RedSeaFileEntry* e = &v->entries[i];
        if (!(e->flags & REDSEA_FLAG_USED) || (e->flags & REDSEA_FLAG_DIR)) continue;
        if (StrNCmp(e->name, "backup/", 7) != 0 || snap_id_of(e->name, NULL)) continue;
        char name[REDSEA_MAX_FILENAME];
        StrNCpy(name, e->name, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
        U64 sz = e->byte_size;
        if (delete_them) {
            if (redsea_eml_delete_file(name)) {
                kprintf("  deleted  %s (%u bytes)\n", name, (U32)sz);
                n++;
                bytes += sz;
            }
        } else {
            kprintf("  %s (%u bytes)\n", name, (U32)sz);
            n++;
            bytes += sz;
        }
    }
    if (delete_them) redsea_eml_set_backup_writer(FALSE);
    if (!n) kprintf("No files in /backup outside the snapshots.\n");
    else if (delete_them) kprintf("[SNAPSHOT] Removed %u legacy file(s) from /backup (%u bytes).\n", n, (U32)bytes);
    else kprintf("%u legacy file(s), %u bytes. Remove them with: snapshot legacy delete\n", n, (U32)bytes);
    return n;
}
