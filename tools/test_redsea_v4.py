#!/usr/bin/env python3
"""
RedSea v4 test: migration and capacity.

1. Migration: a copy of yesos_disk.img (v3) is migrated to v4 on first boot;
   every entry keeps its name, extent and size, every CRC still matches, the
   second boot mounts v4 directly, and host + kernel fsck are clean.
2. Capacity: 5000 small files are written straight into a v4 image from the
   host (fast), then the NAS boots and handles them: boot and fsck times,
   two snapshots of 5000 files (10000+ entries, far beyond v3's 1024), a
   third refused with a clear message for lack of directory entries, delete
   frees the entries, and everything survives a reboot.

Usage: python3 tools/test_redsea_v4.py [files]      (non-zero exit on failure)
"""
import os
import re
import shutil
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402
import test_webadmin as tw  # noqa: E402
from test_webdav import basic  # noqa: E402
import redsea_fsck  # noqa: E402

failures = []
ADMIN = ("v4admin", "v4-admin-pass1")


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label, flush=True)
    if not cond:
        failures.append(label)
    return cond


def boot(disk, first=False, login=True):
    web, tls, udp = tw.free_ports(3)
    tw.TLS_PORT = tls
    t0 = time.time()
    vm = tw.WebYesOS(disk, udp, web, tls)
    ok = vm.wait_for("YesOS [", 240) and tw.wait_up(web, 120)
    boot_s = time.time() - t0
    auth = csrf = None
    if ok and first:
        m = vm.send(f"user add {ADMIN[0]} {ADMIN[1]} admin", 2)
        vm.wait_for("created successfully", 60, m)
    if ok and login:
        vm.send("nas admit 10.0.2.2", 1)
        auth, csrf = tw.session_of(tls, *ADMIN)
    return vm, tls, auth, csrf, ok, boot_s


def kernel_fsck(vm):
    t0 = time.time()
    m = vm.send("fsck", 1)
    vm.wait_for("data: ", 600, m)
    return vm.since(m), time.time() - t0


def geometry(img):
    with open(img, "rb") as f:
        f.seek(512)
        sb = f.read(64)
    ver = struct.unpack("<I", sb[8:12])[0]
    total, root_lba, root_sec, data_lba = struct.unpack("<QQQQ", sb[16:48])
    return ver, total, root_lba, root_sec, data_lba


def entries(img):
    with open(img, "rb") as f:
        _, ents = redsea_fsck.read_entries(f)
    return ents


def add_files(img, count):
    """Appends `count` small files to a v4 image: data after the highest used
    sector, entries in the first free directory slots (kernel CRC)."""
    ver, total, root_lba, root_sec, data_lba = geometry(img)
    assert ver == 4, ver
    ents = entries(img)
    used_slots = {e["slot"] for e in ents}
    next_lba = max([e["lba"] + e["sec"] for e in ents] + [root_lba + root_sec, data_lba])
    with open(img, "r+b") as f:
        f.seek(root_lba * 512)
        raw = bytearray(f.read(root_sec * 512))
        slot = 0
        for i in range(count):
            while slot in used_slots:
                slot += 1
            data = (f"bulk file {i:05d} ".encode() * 8)[:100 + i % 200]
            f.seek(next_lba * 512)
            f.write(data.ljust(512, b"\0"))
            name = f"share/bulk/f{i:05d}.txt".encode()
            entry = name.ljust(224, b"\0") + struct.pack("<QQQII", next_lba, 1, len(data), 0x1,
                                                         redsea_fsck.kernel_crc64(data) & 0xFFFFFFFF)
            raw[slot * 256:(slot + 1) * 256] = entry
            used_slots.add(slot)
            next_lba += 1
        f.seek(root_lba * 512)
        f.write(raw)
        f.seek(512 + 56)
        f.write(struct.pack("<Q", len(used_slots)))   # superblock total_files


def main():
    nfiles = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    tmp = tempfile.mkdtemp(prefix="yesos_v4_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    try:
        # ---- 1. migration ------------------------------------------------
        src_ver = geometry(disk)[0]
        before = {e["name"]: (e["lba"], e["sec"], e["size"], e["crc"]) for e in entries(disk)}
        vm, tls, auth, csrf, ok, boot_s = boot(disk, first=True)
        try:
            out = vm.output()
            check(ok, f"migration: boots ({boot_s:.1f} s)")
            if src_ver < 4:
                check(f"Volume migrated v{src_ver} -> v4: {len(before)} files" in out,
                      f"migration: v{src_ver} -> v4 reported with {len(before)} files")
            fo, _ = kernel_fsck(vm)
            check("fsck: CLEAN" in fo and " 0 BAD" in fo, "migration: kernel fsck clean (structure + every CRC)")
        finally:
            vm.stop()
        ver, total, root_lba, root_sec, _ = geometry(disk)
        after = {e["name"]: (e["lba"], e["sec"], e["size"], e["crc"]) for e in entries(disk)}
        check(ver == 4 and root_sec == 8192, f"migration: superblock is v4 with an 8192-sector directory (v{ver}, {root_sec})")
        # the RNG seed is replaced on every boot; the test added a user account
        rewritten = {"SYS/RNG.SEED", "SYS/USERS.CFG"}
        missing = {n for n in before if n not in rewritten and before[n] != after.get(n)}
        missing |= {n for n in rewritten if n in before and n not in after}
        check(not missing, f"migration: every entry keeps name, extent, size and CRC ({len(before)} entries)" +
              (f" -> {sorted(missing)[:3]}" if missing else ""))
        r = redsea_fsck.fsck(disk)
        check(not r["errors"], f"migration: host fsck clean ({r['crc_ok']} + {r['crc_legacy']} legacy CRCs)")
        vm, tls, auth, csrf, ok, _ = boot(disk, login=False)
        try:
            check(ok and "Volume migrated" not in vm.output(), "migration: second boot mounts v4 directly")
        finally:
            vm.stop()

        # ---- 2. capacity -------------------------------------------------
        t0 = time.time()
        add_files(disk, nfiles)
        r = redsea_fsck.fsck(disk, check_data=False)
        check(not r["errors"], f"capacity: {nfiles} files written into the image from the host ({time.time() - t0:.1f} s)")
        vm, tls, auth, csrf, ok, boot_s = boot(disk)
        try:
            out = vm.output()
            m = re.search(r"\((\d+) Files on Drive 0\)", out)
            check(ok and m and int(m.group(1)) >= nfiles and "structure OK" in out,
                  f"capacity: boots with {m.group(1) if m else '?'} entries, structure OK ({boot_s:.1f} s to the shell)")
            fo, fsck_s = kernel_fsck(vm)
            check("fsck: CLEAN" in fo and " 0 BAD" in fo, f"capacity: full kernel fsck clean ({fsck_s:.1f} s)")
            times = []
            for k in range(2):
                t0 = time.time()
                st, res = tw.action(tls, auth, csrf, "snapshot_create", comment=f"bulk {k}")
                times.append(time.time() - t0)
                check(st == 200, f"capacity: snapshot {k + 1} of {nfiles}+ files ({times[-1]:.1f} s) - {res.get('message')}")
            t0 = time.time()
            view = tw.view(tls, auth, "snapshots")
            list_s = time.time() - t0
            snaps = view.get("snapshots", [])
            check(len(snaps) == 2 and all(s["files_count"] >= nfiles for s in snaps),
                  f"capacity: snapshot list with file lists ({list_s:.1f} s, {view.get('dir_entries_free')} entries free)")
            st, res = tw.action(tls, auth, csrf, "snapshot_create", comment="one too many")
            check(st == 409 and "entries" in res.get("message", ""),
                  f"capacity: a snapshot that does not fit is refused clearly ({res.get('message')})")
            sid = snaps[0]["id"]
            t0 = time.time()
            st, res = tw.action(tls, auth, csrf, "snapshot_delete", name=str(sid))
            del_s = time.time() - t0
            free_after = tw.view(tls, auth, "snapshots").get("dir_entries_free", 0)
            check(st == 200 and free_after >= view.get("dir_entries_free", 0) + nfiles,
                  f"capacity: deleting a snapshot frees its entries ({del_s:.1f} s, {free_after} free)")
            st, res = tw.action(tls, auth, csrf, "snapshot_create", comment="fits again")
            check(st == 200, "capacity: a new snapshot fits again after the delete")
            st, _, body = tw.req(tls, "GET", "/dav/share/" + quote_name(f"f{nfiles - 1:05d}.txt"), None, basic(*ADMIN))
            fo, fsck_s = kernel_fsck(vm)
            check("fsck: CLEAN" in fo and " 0 BAD" in fo, f"capacity: kernel fsck clean after the snapshots ({fsck_s:.1f} s)")
        finally:
            vm.stop()
        r = redsea_fsck.fsck(disk)
        check(not r["errors"], f"capacity: host fsck clean after shutdown ({r['files']} files, {r['shared']} shared extents)")
        vm, tls, auth, csrf, ok, boot_s = boot(disk)
        try:
            snaps = tw.view(tls, auth, "snapshots").get("snapshots", []) if ok else []
            check(ok and len(snaps) == 2, f"capacity: after reboot both snapshots are there ({boot_s:.1f} s)")
        finally:
            vm.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


def quote_name(n):
    from urllib.parse import quote
    return quote(n)


if __name__ == "__main__":
    main()
