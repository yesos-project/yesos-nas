#!/usr/bin/env python3
"""
Snapshot test: /backup snapshots of share/, media/ and vault/ that share
RedSea extents (no data copied), read-only WebDAV browsing, restore of files
and whole snapshots (vault ciphertext included), space accounting, automatic
snapshots with retention, and persistence across reboot. Boots YesOS twice on
a scratch copy of yesos_disk.img. Non-zero exit status on failure.
"""
import hashlib
import os
import re
import subprocess
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402
import test_webadmin as tw  # noqa: E402
from test_webdav import basic  # noqa: E402

failures = []
ADMIN = ("snapadmin", "snap-admin-pass")
READER = ("snapreader", "snap-reader-pass")


def on_disk(disk, name):
    out = subprocess.run([sys.executable, os.path.join(harness.ROOT, "core", "tools", "redsea_injector.py"), disk, "list"],
                         capture_output=True, text=True).stdout
    return any(l.split() and l.split()[0] == name for l in out.splitlines())


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def main():
    tmp = tempfile.mkdtemp(prefix="yesos_snap_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    web, tls, udp = tw.free_ports(3)
    tw.TLS_PORT = tls
    A = basic(*ADMIN)
    R = basic(*READER)
    sha = lambda b: hashlib.sha256(b).hexdigest()

    def dav(method, path, body=None, h=A, extra=None):
        return tw.req(tls, method, path, body, dict(h, **(extra or {})))

    b_data = os.urandom(300 * 1024)
    c_data = os.urandom(200 * 1024)

    vm = tw.WebYesOS(disk, udp, web, tls)
    try:
        check(vm.wait_for("YesOS [", 120) and tw.wait_up(web), "system boots")
        check("[SNAPSHOT]" in vm.output(), "snapshot module initialised at boot")
        for (u, p), role in ((ADMIN, "admin"), (READER, "ro")):
            m = vm.send(f"user add {u} {p} {role}", 2)
            vm.wait_for("created successfully", 60, m)
        vm.send("nas admit 10.0.2.2", 1)
        auth, csrf = tw.session_of(tls, *ADMIN)
        check(auth is not None, "admin logged in to the panel")
        act = lambda action_name, **f: tw.action(tls, auth, csrf, action_name, **f)
        view = lambda section: tw.view(tls, auth, section)
        used = lambda: view("storage")["pool"]["used_bytes"]

        st1 = dav("PUT", "/dav/share/a.txt", b"version-1")[0]
        st2 = dav("PUT", "/dav/media/b.bin", b_data)[0]
        st3 = dav("PUT", "/dav/share/c.bin", c_data)[0]
        check((st1, st2, st3) == (201, 201, 201), f"test files uploaded ({st1}, {st2}, {st3})")
        vm.send("vault init", 1)
        vm.send(harness.PASS, 0.5)
        m = vm.send(harness.PASS, 0.5)
        check(vm.wait_for("Vault created and unlocked", 180, m), "vault created")
        m = vm.send("write /vault/S.TXT original-vault-secret", 3)
        check("write:" in vm.since(m), "secret written to the vault")

        # --- create: no data copied -----------------------------------------
        before = used()
        st, r = act("snapshot_create", comment="before changes", value="04/10/2026 18:00")
        snaps = view("snapshots")["snapshots"]
        s1 = snaps[0] if snaps else {}
        paths = {f["path"]: f for f in s1.get("files", [])}
        check(st == 200 and s1.get("note") == "before changes" and s1.get("created_by") == ADMIN[0],
              f"snapshot created from the panel ({r.get('message')})")
        check("share/a.txt" in paths and "media/b.bin" in paths and paths.get("vault/S.TXT", {}).get("encrypted"),
              "snapshot holds share, media and the (encrypted) vault file")
        check(not any(p.startswith("SYS/") for p in paths), "SYS (accounts, keys) never included")
        grew = used() - before
        check(grew <= 4096, f"no data copied: used space grew by {grew} bytes (manifest only)")
        sid = s1.get("id", 0)
        snapdir = f"/dav/backup/snap-{sid:04d}"

        # --- WebDAV: read-only tree, vault hidden ------------------------------
        st, _, body = dav("PROPFIND", "/dav/backup/", extra={"Depth": "1"})
        check(st == 207 and f"snap-{sid:04d}/".encode() in body, "PROPFIND /dav/backup lists the snapshot folder")
        st, _, body = dav("PROPFIND", snapdir + "/", extra={"Depth": "1"})
        check(st == 207 and b"<D:displayname>share</D:displayname>" in body and b"vault" not in body,
              "snapshot folder lists share and media, never vault")
        st, _, body = dav("PROPFIND", snapdir + "/share/", extra={"Depth": "1"})
        check(st == 207 and b"a.txt" in body and b"<D:collection/>" in body, "nested PROPFIND into the snapshot")
        st, _, body = dav("GET", snapdir + "/share/a.txt")
        check(st == 200 and body == b"version-1", "file read from the snapshot over WebDAV")
        st, _, _ = dav("GET", snapdir + "/vault/S.TXT")
        check(st == 404, "vault ciphertext not served from the snapshot")
        st, h, body = dav("GET", snapdir + "/")
        check(st == 200 and b"share/" in body and "text/html" in h.get("content-type", ""), "browser gets an HTML index")
        codes = [dav("PUT", snapdir + "/share/a.txt", b"evil")[0], dav("DELETE", snapdir + "/share/a.txt")[0],
                 dav("MKCOL", "/dav/backup/new/")[0], dav("PUT", "/dav/backup/x.txt", b"x")[0]]
        check(codes == [403] * 4, f"PUT, DELETE and MKCOL refused under /backup ({codes})")
        m = vm.send(f"disk rm backup/snap-{sid:04d}/share/a.txt", 2)
        m2 = vm.send("disk save backup/x.txt hi", 2)
        check("read-only backup area" in vm.since(m) and "read-only backup area" in vm.since(m2),
              "console cannot change /backup either")
        st, _, _ = dav("GET", snapdir + "/media/b.bin", h=R)
        check(st == 403, "read-only account has no access to /backup (share mask)")

        # --- the snapshot keeps the old data --------------------------------
        dav("PUT", "/dav/share/a.txt", b"version-2-longer")
        dav("DELETE", "/dav/media/b.bin")
        st, _, body = dav("GET", snapdir + "/share/a.txt")
        st2, _, body2 = dav("GET", snapdir + "/media/b.bin")
        check(body == b"version-1" and st2 == 200 and sha(body2) == sha(b_data),
              "after changing and deleting the originals the snapshot still has the old data")
        s1 = view("snapshots")["snapshots"][0]
        check(s1["unique_bytes"] >= len(b_data), f"exclusive space now includes the deleted file ({s1['unique_bytes']} B)")

        # --- restore ----------------------------------------------------------
        st, r = act("snapshot_restore", name=str(sid), path="share/a.txt")
        st2, _, body = dav("GET", "/dav/share/a.txt")
        check(st == 200 and body == b"version-1", "single file restored")
        m = vm.send("write /vault/S.TXT tampered-content", 3)
        st, r = act("snapshot_restore", name=str(sid), path="vault/S.TXT")
        m = vm.send("cat /vault/S.TXT", 2)
        check(st == 200 and "original-vault-secret" in vm.since(m), "vault file restored and still decrypts")
        st, r = act("snapshot_restore", name=str(sid), path="")
        st2, _, body = dav("GET", "/dav/media/b.bin")
        check(st == 200 and st2 == 200 and sha(body) == sha(b_data), f"whole snapshot restored ({r.get('message')})")
        st, r = act("snapshot_restore", name=str(sid), path="SYS/USERS.CFG")
        check(st != 200, "restore refuses paths outside share/media/vault")

        # --- delete frees only exclusive space, never live data ---------------
        dav("PUT", "/dav/share/d.bin", c_data)
        st, r = act("snapshot_create", comment="segunda")
        s2 = view("snapshots")["snapshots"][0]["id"]
        dav("DELETE", "/dav/share/d.bin")
        uniq = [s for s in view("snapshots")["snapshots"] if s["id"] == s2][0]["unique_bytes"]
        before = used()
        st, r = act("snapshot_delete", name=str(s2))
        freed = before - used()
        check(st == 200 and freed >= len(c_data) and abs(freed - uniq) <= 4096,
              f"deleting a snapshot frees its exclusive space ({freed} B freed, {uniq} B expected)")
        st, r = act("snapshot_delete", name=str(sid))
        st2, _, body = dav("GET", "/dav/media/b.bin")
        st3, _, body3 = dav("GET", "/dav/share/a.txt")
        check(st == 200 and sha(body) == sha(b_data) and body3 == b"version-1",
              "deleting the snapshot keeps the restored live files intact")
        st, _, _ = dav("GET", snapdir + "/share/a.txt")
        check(st == 404, "deleted snapshot no longer served")
        st, r = act("snapshot_delete", name=str(sid))
        check(st == 404, "deleting a missing snapshot reports 404")

        # --- automatic snapshots with retention --------------------------------
        st, r = act("snapshot_create", comment="manual-keep")
        manual_id = view("snapshots")["snapshots"][0]["id"]
        m = vm.send("snapshot auto 60 2", 2)
        for _ in range(3):
            vm.send("snapshot auto now", 3)
        sn = view("snapshots")
        autos = [s for s in sn["snapshots"] if s["automatic"]]
        check(sn["auto"]["interval_minutes"] == 60 and sn["auto"]["keep"] == 2, "automatic schedule configured")
        check(len(autos) == 2 and any(s["id"] == manual_id for s in sn["snapshots"]),
              f"retention keeps the last 2 automatic snapshots and never prunes manual ones ({[s['id'] for s in autos]})")
        st, r = act("snapshot_auto", value="1440:5")
        check(st == 200 and view("snapshots")["auto"]["keep"] == 5, "schedule changed from the panel")
        st, r = act("snapshot_auto", value="10:0")
        check(st == 400, "invalid retention rejected")

        # Files in /backup that belong to no snapshot (the source disk may carry
        # one from the old simulated backup manager): listed, then removed alone.
        ids_before = sorted(s["id"] for s in view("snapshots")["snapshots"])
        m = vm.send("snapshot legacy", 2)
        listing = vm.since(m)
        legacy = re.findall(r"^\s+(backup/\S+) \(\d+ bytes\)", listing, re.M)
        check(all("/snap-" not in n for n in legacy), f"legacy listing excludes snapshot files ({legacy})")
        m = vm.send("snapshot legacy delete", 3)
        after = vm.send("snapshot legacy", 2)
        ids_after = sorted(s["id"] for s in view("snapshots")["snapshots"])
        newest = max(ids_after) if ids_after else 0
        st, _, body = dav("GET", f"/dav/backup/snap-{newest:04d}/media/b.bin")
        check("No files in /backup outside the snapshots" in vm.since(after) and ids_after == ids_before
              and st == 200 and sha(body) == sha(b_data),
              f"legacy files removed ({len(legacy)}), snapshots untouched")

        persist_ids = sorted(s["id"] for s in view("snapshots")["snapshots"])
        dav("PUT", "/dav/share/after.txt", b"written-after-snapshots")
        log = [e["text"] for e in view("audit")["entries"]]
        check(any("snapshot" in t for t in log), "snapshot actions recorded in the audit log")
        out = vm.output()
        check("FATAL" not in out and "EXCEPTION" not in out and "Security Alert" not in out,
              "no kernel faults or RedSea security alerts")
        check(on_disk(disk, "SYS/VAULT.HDR") and on_disk(disk, "SYS/USERS.CFG"), "system files still on disk")
    finally:
        vm.stop()

    # Move the last entry a few slots further, leaving free slots between
    # entries: normal since v4 (deletes clear one slot). Nothing may be lost.
    import struct
    with open(disk, "r+b") as f:
        f.seek(512)
        sb = f.read(64)
        root_lba, root_sec = struct.unpack("<QQ", sb[24:40])
        f.seek(root_lba * 512)
        raw = bytearray(f.read(root_sec * 512))
        used = [i for i in range(len(raw) // 256) if struct.unpack("<I", raw[i * 256 + 248:i * 256 + 252])[0] & 1]
        last = used[-1]
        moved_name = bytes(raw[last * 256:last * 256 + 224]).split(b"\0")[0].decode()
        raw[(last + 5) * 256:(last + 6) * 256] = raw[last * 256:(last + 1) * 256]
        raw[last * 256:(last + 1) * 256] = bytes(256)
        f.seek(root_lba * 512)
        f.write(raw)

    vm = tw.WebYesOS(disk, udp, web, tls)
    try:
        check(vm.wait_for("YesOS [", 120) and tw.wait_up(web), "second boot")
        check("structure OK" in vm.output() and "Recovery" not in vm.output(),
              f"a free slot between entries is normal in v4 (moved '{moved_name}')")
        check("initialized, LOCKED" in vm.output(), "vault header found after reboot")
        vm.send("nas admit 10.0.2.2", 1)
        auth, csrf = tw.session_of(tls, *ADMIN)
        sn = tw.view(tls, auth, "snapshots") if auth else {}
        ids = sorted(s["id"] for s in sn.get("snapshots", []))
        check(ids == persist_ids, f"snapshots persist across reboot ({ids})")
        check(sn.get("auto", {}).get("interval_minutes") == 1440 and sn["auto"]["keep"] == 5, "schedule persists (SYS/SNAPSHOT.CFG)")
        # The free-extent map rebuilt at mount must keep shared extents busy:
        # writing a lot of new data must not overwrite snapshot or live files.
        for i in range(4):
            dav("PUT", f"/dav/share/fill{i}.bin", os.urandom(512 * 1024))
        st, _, body = dav("GET", "/dav/media/b.bin")
        newest = max(ids) if ids else 0
        st2, _, body2 = dav("GET", f"/dav/backup/snap-{newest:04d}/media/b.bin")
        check(st == 200 and sha(body) == sha(b_data) and st2 == 200 and sha(body2) == sha(b_data),
              "after reboot and new writes, live and snapshot data are intact")
        out = vm.output()
        check("Security Alert" not in out and "duplicate directory entry" not in out, "mount found a consistent volume")
        m = vm.send("disk", 3)
        check(moved_name.split("/")[-1] in vm.since(m), "the moved entry is still listed (and readable through the directory)")
    finally:
        vm.stop()
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
