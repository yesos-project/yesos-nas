#include "webui_bridge.h"
#include "nas_server.h"
#include "airgap_firewall.h"
#include "timer.h"
#include "smp.h"
#include "memory.h"
#include "vfs.h"
#include "ramfs.h"
#include "kprintf.h"
#include "redsea_eml.h"

static Bool str_contains(const char* haystack, const char* needle) {
    if (!haystack || !needle) return FALSE;
    size_t hlen = StrLen(haystack);
    size_t nlen = StrLen(needle);
    if (nlen > hlen) return FALSE;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (StrNICmp(haystack + i, needle, nlen) == 0) return TRUE;
    }
    return FALSE;
}

#define MAX_DAV_UPLOAD_SIZE (16 * 1024 * 1024)

static const char* webui_extract_clean_path(const char* filename, char* out_share, size_t share_max) {
    if (!filename) return NULL;
    // CWE-22: Strict rejection of directory traversal attempts
    if (str_contains(filename, "..") || str_contains(filename, "\\")) {
        kprintf("[SECURITY] WebDAV: Rejected directory traversal attempt: '%s'\n", filename);
        return NULL;
    }

    if (out_share && share_max > 0) StrNCpy(out_share, "share", share_max);
    const char* p = filename;
    if (StrNICmp(p, "/dav/share/", 11) == 0) {
        if (out_share) StrNCpy(out_share, "share", share_max);
        p += 11;
    } else if (StrNICmp(p, "/dav/vault/", 11) == 0) {
        if (out_share) StrNCpy(out_share, "vault", share_max);
        p += 11;
    } else if (StrNICmp(p, "/dav/media/", 11) == 0) {
        if (out_share) StrNCpy(out_share, "media", share_max);
        p += 11;
    } else if (StrNICmp(p, "/dav/backup/", 12) == 0) {
        if (out_share) StrNCpy(out_share, "backup", share_max);
        p += 12;
    } else if (StrNICmp(p, "/dav/", 5) == 0) {
        p += 5;
    } else if (StrNICmp(p, "/share/", 7) == 0) {
        if (out_share) StrNCpy(out_share, "share", share_max);
        p += 7;
    } else if (StrNICmp(p, "/vault/", 7) == 0) {
        if (out_share) StrNCpy(out_share, "vault", share_max);
        p += 7;
    }

    // WebDAV runs over plain HTTP with IP-based admission only: it must never
    // expose the encrypted vault (uploads would also land in RAM unencrypted).
    if (out_share && StrICmp(out_share, "vault") == 0) {
        kprintf("[SECURITY] WebDAV: access to /vault refused (use the console or authenticated NAS protocol).\n");
        return NULL;
    }

    while (*p == '/') p++;

    // /backup is a read-only tree (snapshots): keep its sub-path, validated.
    if (out_share && StrICmp(out_share, "backup") == 0) {
        if (p[0] == '\0') return NULL;
        for (const char* c = p; *c; c++) {
            if ((unsigned char)*c < 32 || (unsigned char)*c > 126) return NULL;
            if (*c == ':' || *c == '*' || *c == '?' || *c == '"' || *c == '<' || *c == '>' || *c == '|') return NULL;
            if (c[0] == '/' && (c[1] == '/' || c[1] == '\0')) return NULL;
        }
        return p;
    }

    // Extract strictly leaf filename (strip any directory slashes)
    const char* leaf = p;
    for (const char* c = p; *c; c++) {
        if (*c == '/') leaf = c + 1;
    }
    p = leaf;

    if (p[0] == '\0') return NULL;

    // Validate safe characters (no control codes or filesystem command injections)
    for (const char* c = p; *c; c++) {
        if ((unsigned char)*c < 32 || (unsigned char)*c > 126) return NULL;
        if (*c == ':' || *c == '*' || *c == '?' || *c == '"' || *c == '<' || *c == '>' || *c == '|') return NULL;
    }

    return p;
}

// ----------------------------------------------------------------------------
// WebDAV file storage: persistent RedSea files named "<share>/<leaf>".
// ----------------------------------------------------------------------------

// Builds the RedSea key for a WebDAV path. Returns FALSE for invalid paths;
// sets *too_long when the key would exceed RedSea's name limit.
static Bool dav_key(const char* filename, char* key, size_t key_len, char* share, size_t share_len,
                    Bool* too_long) {
    if (too_long) *too_long = FALSE;
    const char* clean = webui_extract_clean_path(filename, share, share_len);
    if (!clean || clean[0] == '\0') return FALSE;
    size_t need = StrLen(share) + 1 + StrLen(clean);
    if (need > REDSEA_MAX_FILENAME - 1) {
        if (too_long) *too_long = TRUE;
        return FALSE;
    }
    ksnprintf(key, key_len, "%s/%s", share, clean);
    return TRUE;
}

static RedSeaFileEntry* dav_find(const char* key) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted) return NULL;
    for (U32 i = 0; i < v->entry_count; i++) {
        RedSeaFileEntry* e = &v->entries[i];
        // Vault ciphertext (also inside snapshots) is never served over WebDAV.
        if ((e->flags & REDSEA_FLAG_USED) && !(e->flags & (REDSEA_FLAG_DIR | REDSEA_FLAG_ENCRYPTED)) &&
            StrICmp(e->name, key) == 0) return e;
    }
    return NULL;
}

// Returns bytes written, 0 when refused, -2 when the name is too long.
I32 webui_write_file(const char* filename, const void* data, size_t size) {
    char share[16] = "share";
    char key[REDSEA_MAX_FILENAME];
    Bool too_long = FALSE;
    if (!dav_key(filename, key, sizeof(key), share, sizeof(share), &too_long)) return too_long ? -2 : 0;

    if (size > MAX_DAV_UPLOAD_SIZE) {
        kprintf("[WEBDAV] Write rejected: %u bytes exceeds the 16 MiB upload limit.\n", (U32)size);
        return 0;
    }
    if (StrICmp(share, "backup") == 0) {
        kprintf("[SECURITY] WebDAV write rejected: /backup is WORM Immutable.\n");
        return 0;
    }
    redsea_eml_mkdir(share);
    static const U8 empty = 0;
    if (!redsea_eml_write_file_path(key, size ? data : &empty, size, 0)) {
        kprintf("[WEBDAV] Write of '%s' failed (disk full or no contiguous space).\n", key);
        return 0;
    }
    kprintf("[WEBDAV] Stored '%s' (%u bytes) on RedSea.\n", key, (U32)size);
    return size ? (I32)size : 1;
}

I32 webui_delete_file(const char* filename) {
    char share[16] = "share";
    char key[REDSEA_MAX_FILENAME];
    if (!dav_key(filename, key, sizeof(key), share, sizeof(share), NULL)) return 0;
    if (StrICmp(share, "backup") == 0) {
        kprintf("[SECURITY] WebDAV delete rejected: /backup is WORM Immutable.\n");
        return 0;
    }
    RedSeaFileEntry* e = dav_find(key);
    if (!e) return 0;
    char exact[REDSEA_MAX_FILENAME];
    StrNCpy(exact, e->name, sizeof(exact) - 1);
    exact[sizeof(exact) - 1] = '\0';
    return redsea_eml_delete_file(exact) ? 1 : 0;
}

Bool webui_is_client_admitted(U32 ip) {
    return nas_is_client_admitted(ip);
}

I32 webui_file_exists(const char* filename) {
    char share[16] = "share";
    char key[REDSEA_MAX_FILENAME];
    if (!dav_key(filename, key, sizeof(key), share, sizeof(share), NULL)) return 0;
    return dav_find(key) ? 1 : 0;
}

U64 webui_file_size(const char* filename) {
    char share[16] = "share";
    char key[REDSEA_MAX_FILENAME];
    if (!dav_key(filename, key, sizeof(key), share, sizeof(share), NULL)) return 0;
    RedSeaFileEntry* e = dav_find(key);
    return e ? e->byte_size : 0;
}

// Files of a share, in directory order (the RedSea directory is the listing).
static RedSeaFileEntry* dav_nth(const char* share_name, U32 index) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted || !share_name) return NULL;
    size_t pl = StrLen(share_name);
    U32 n = 0;
    for (U32 i = 0; i < v->entry_count; i++) {
        RedSeaFileEntry* e = &v->entries[i];
        if (!(e->flags & REDSEA_FLAG_USED) || (e->flags & (REDSEA_FLAG_DIR | REDSEA_FLAG_ENCRYPTED))) continue;
        if (StrNICmp(e->name, share_name, pl) != 0 || e->name[pl] != '/' || e->name[pl + 1] == '\0') continue;
        if (n++ == index) return e;
    }
    return NULL;
}

U32 webui_get_dav_file_count(const char* share_name) {
    if (!share_name || StrICmp(share_name, "vault") == 0) return 0;
    U32 n = 0;
    while (dav_nth(share_name, n)) n++;
    return n;
}

Bool webui_get_dav_file_info(const char* share_name, U32 index, char* out_name, size_t name_max, U64* out_size) {
    if (!share_name || StrICmp(share_name, "vault") == 0) return FALSE;
    RedSeaFileEntry* e = dav_nth(share_name, index);
    if (!e) return FALSE;
    if (out_name && name_max > 0) StrNCpy(out_name, e->name + StrLen(share_name) + 1, name_max - 1);
    if (out_name && name_max > 0) out_name[name_max - 1] = '\0';
    if (out_size) *out_size = e->byte_size;
    return TRUE;
}

// Copies up to max_len bytes of the file; returns the number copied.
I32 webui_read_file(const char* filename, char* buf, size_t max_len) {
    if (!filename || !buf || max_len == 0) return 0;
    char share[16] = "share";
    char key[REDSEA_MAX_FILENAME];
    if (!dav_key(filename, key, sizeof(key), share, sizeof(share), NULL)) return 0;
    RedSeaFileEntry* e = dav_find(key);
    if (!e) return 0;
    size_t sz = 0;
    U8* data = redsea_eml_read_file(e->name, &sz);
    if (!data) return 0;
    size_t cpy = sz < max_len ? sz : max_len;
    MemCpy(buf, data, cpy);
    Free(data);
    return (I32)cpy;
}

// Children of the read-only /backup tree. `rel` is the path below
// /dav/backup/ without leading or trailing '/' ("" for /backup itself).
// Writes one line per child: "d\t<name>\n" or "f\t<size>\t<name>\n".
// Returns the number of children, -1 if `rel` is not a directory, -2 if
// `max` is too small. Encrypted (vault) entries are hidden.
I32 webui_backup_children(const char* rel, char* out, size_t max) {
    RedSeaVolume* v = redsea_eml_get_volume();
    if (!v || !v->is_mounted || !rel || !out || max < 2) return -1;
    if (str_contains(rel, "..")) return -1;
    char prefix[REDSEA_MAX_FILENAME + 8];
    ksnprintf(prefix, sizeof(prefix), rel[0] ? "backup/%s/" : "backup/", rel);
    size_t pl = StrLen(prefix);
    static char seen[256][64];
    U32 nseen = 0;
    size_t pos = 0;
    I32 count = 0;
    Bool any = (rel[0] == '\0');
    out[0] = '\0';
    for (U32 i = 0; i < v->entry_count; i++) {
        const RedSeaFileEntry* e = &v->entries[i];
        if (!(e->flags & REDSEA_FLAG_USED) || (e->flags & (REDSEA_FLAG_DIR | REDSEA_FLAG_ENCRYPTED))) continue;
        if (StrNICmp(e->name, prefix, pl) != 0 || e->name[pl] == '\0') continue;
        const char* rest = e->name + pl;
        Bool bad = FALSE;
        for (const char* c = rest; *c; c++) bad |= (*c == '\t' || *c == '\n');
        if (bad) continue;
        any = TRUE;
        const char* slash = NULL;
        for (const char* c = rest; *c; c++) if (*c == '/') { slash = c; break; }
        char line[REDSEA_MAX_FILENAME + 32];
        if (slash) {
            size_t n = (size_t)(slash - rest);
            if (n == 0 || n >= sizeof(seen[0])) continue;
            Bool dup = FALSE;
            for (U32 k = 0; k < nseen && !dup; k++) dup = (StrLen(seen[k]) == n && StrNCmp(seen[k], rest, n) == 0);
            if (dup) continue;
            if (nseen >= 256) continue;
            MemCpy(seen[nseen], rest, n);
            seen[nseen][n] = '\0';
            nseen++;
            ksnprintf(line, sizeof(line), "d\t%s\n", seen[nseen - 1]);
        } else {
            ksnprintf(line, sizeof(line), "f\t%u\t%s\n", (U32)e->byte_size, rest);
        }
        size_t ll = StrLen(line);
        if (pos + ll + 1 > max) return -2;
        MemCpy(out + pos, line, ll + 1);
        pos += ll;
        count++;
    }
    return any ? count : -1;
}
