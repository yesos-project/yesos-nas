#!/usr/bin/env python3
"""
File system + snapshot model test.

Part A - fsck must catch damage: corrupt copies of the disk image (data byte
flipped, overlapping extents, extent beyond the disk, duplicate name) and
check that both tools/redsea_fsck.py and the kernel's `fsck` report them.

Part B - random operations against a model: writes, deletes, snapshot
create/delete, single-file and whole-snapshot restores, and two reboots,
driven through WebDAV and the admin API while Python keeps the exact
expected content. Every few operations every live file and every snapshot
file is compared byte for byte, and both fsck implementations must be clean.

Usage: python3 tools/test_fs_model.py [seed] [operations]   (non-zero exit on failure)
"""
import hashlib
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402
import test_webadmin as tw  # noqa: E402
from test_webdav import basic  # noqa: E402
import redsea_fsck  # noqa: E402

failures = []
ADMIN = ("fsadmin", "fs-admin-pass1")


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label, flush=True)
    if not cond:
        failures.append(label)
    return cond


def boot(disk):
    web, tls, udp = tw.free_ports(3)
    tw.TLS_PORT = tls
    vm = tw.WebYesOS(disk, udp, web, tls)
    ok = vm.wait_for("YesOS [", 120) and tw.wait_up(web)
    return vm, tls, ok


def kernel_fsck(vm):
    m = vm.send("fsck", 1)
    vm.wait_for("fsck: ", 120, m)
    vm.wait_for("data: ", 30, m)
    return vm.since(m)


# ---------------------------------------------------------------------------
# Part A
# ---------------------------------------------------------------------------

def entries_raw(img):
    with open(img, "rb") as f:
        f.seek(512)
        sb = f.read(64)
        root_lba, root_sec = struct.unpack("<QQ", sb[24:40])
        f.seek(root_lba * 512)
        return root_lba, bytearray(f.read(root_sec * 512))


def write_dir(img, root_lba, raw):
    with open(img, "r+b") as f:
        f.seek(root_lba * 512)
        f.write(raw)


def used_slots(raw):
    return [i for i in range(len(raw) // 256) if struct.unpack("<I", raw[i * 256 + 248:i * 256 + 252])[0] & 1]


def entry(raw, i):
    e = raw[i * 256:(i + 1) * 256]
    lba, sec, size = struct.unpack("<QQQ", e[224:248])
    return {"name": bytes(e[:224]).split(b"\0")[0].decode(), "lba": lba, "sec": sec, "size": size,
            "flags": struct.unpack("<I", e[248:252])[0]}


def part_a(tmp):
    base = os.path.join(tmp, "base.img")
    shutil.copyfile(harness.SRC_DISK, base)
    r = redsea_fsck.fsck(base)
    check(not r["errors"], f"host fsck: the source disk is clean ({r['files']} files)")
    root_lba, raw = entries_raw(base)
    files = [i for i in used_slots(raw) if not entry(raw, i)["flags"] & 8 and entry(raw, i)["size"] > 16]
    victim, other = files[0], files[1]

    cases = {}
    # 1. one data byte flipped
    img = os.path.join(tmp, "flip.img")
    shutil.copyfile(base, img)
    e = entry(raw, victim)
    with open(img, "r+b") as f:
        f.seek(e["lba"] * 512 + e["size"] // 2)
        b = f.read(1)
        f.seek(e["lba"] * 512 + e["size"] // 2)
        f.write(bytes([b[0] ^ 0x10]))
    cases["flip"] = (img, "does not match its CRC", e["name"])
    # 2. partial overlap: start one file one sector inside another
    img = os.path.join(tmp, "overlap.img")
    shutil.copyfile(base, img)
    raw2 = bytearray(raw)
    eo = entry(raw2, victim)
    struct.pack_into("<Q", raw2, other * 256 + 224, eo["lba"] + max(0, eo["sec"] - 1))
    write_dir(img, root_lba, raw2)
    cases["overlap"] = (img, "overlap", entry(raw2, other)["name"])
    # 3. extent beyond the end of the disk
    img = os.path.join(tmp, "bounds.img")
    shutil.copyfile(base, img)
    raw3 = bytearray(raw)
    struct.pack_into("<Q", raw3, other * 256 + 224, 10 ** 9)
    write_dir(img, root_lba, raw3)
    cases["bounds"] = (img, "outside the data area", entry(raw3, other)["name"])
    # 4. duplicate name
    img = os.path.join(tmp, "dup.img")
    shutil.copyfile(base, img)
    raw4 = bytearray(raw)
    raw4[other * 256:other * 256 + 224] = raw4[victim * 256:victim * 256 + 224]
    write_dir(img, root_lba, raw4)
    cases["dup"] = (img, "duplicate", entry(raw4, victim)["name"])

    for label, (img, needle, name) in cases.items():
        r = redsea_fsck.fsck(img)
        check(any(needle in x for x in r["errors"]), f"host fsck catches '{label}' ({name})")
        vm, _, ok = boot(img)
        try:
            out = kernel_fsck(vm) if ok else ""
            check(ok and "PROBLEMS FOUND" in out and needle in out, f"kernel fsck catches '{label}'")
        finally:
            vm.stop()


# ---------------------------------------------------------------------------
# Part B
# ---------------------------------------------------------------------------

NAMES = [f"share/f{i}.bin" for i in range(6)] + [f"media/m{i}.dat" for i in range(4)] + \
        ["share/con espacios & simbolos (v2).txt", "media/" + "n" * 150 + ".raw"]


class Model:
    def __init__(self):
        self.live = {}
        self.snaps = {}


def part_b(tmp, seed, n_ops):
    rnd = random.Random(seed)
    disk = os.path.join(tmp, "model.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    A = basic(*ADMIN)
    model = Model()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    stats = {"put": 0, "delete": 0, "snap": 0, "snapdel": 0, "restore1": 0, "restoreall": 0, "verify": 0}

    def size():
        return rnd.choice([0, 1, 511, 512, 513, 4096, rnd.randint(1, 3000), rnd.randint(3000, 120000),
                           rnd.randint(120000, 400000)])

    vm, tls, ok = boot(disk)
    if not check(ok, f"model run (seed {seed}): system boots"):
        vm.stop()
        return
    m = vm.send(f"user add {ADMIN[0]} {ADMIN[1]} admin", 2)
    vm.wait_for("created successfully", 60, m)

    def login():
        vm.send("nas admit 10.0.2.2", 1)
        return tw.session_of(tls, *ADMIN)

    auth, csrf = login()
    reboots_at = {n_ops // 3, 2 * n_ops // 3}

    def dav(method, name, body=None, snap=None):
        path = f"/dav/backup/snap-{snap:04d}/{name}" if snap else "/dav/" + name
        return tw.req(tls, method, quote(path), body, A)

    def verify_all(label):
        nonlocal auth, csrf
        bad = []
        for name in NAMES:
            st, _, body = dav("GET", name)
            if name in model.live:
                if st != 200 or sha(body) != sha(model.live[name]):
                    bad.append(f"live {name}: {st}, {len(body)} B vs {len(model.live[name])} B")
            elif st != 404:
                bad.append(f"live {name}: expected 404, got {st}")
        for sid, content in model.snaps.items():
            for name, data in content.items():
                st, _, body = dav("GET", name, snap=sid)
                if st != 200 or sha(body) != sha(data):
                    bad.append(f"snapshot {sid} {name}: {st}, {len(body)} B vs {len(data)} B")
        listed = tw.view(tls, auth, "snapshots").get("snapshots", [])
        if sorted(s["id"] for s in listed) != sorted(model.snaps):
            bad.append(f"snapshot list {sorted(s['id'] for s in listed)} vs model {sorted(model.snaps)}")
        out = kernel_fsck(vm)
        clean = "fsck: CLEAN" in out and " 0 BAD, 0 unreadable" in out
        if not clean:
            bad.append("kernel fsck: " + " | ".join(l for l in out.splitlines() if "ERROR" in l or "fsck:" in l)[:400])
        stats["verify"] += 1
        check(not bad, f"{label}: every live and snapshot file matches the model, kernel fsck clean" +
              (f" -> {bad[:4]}" if bad else ""))
        return not bad

    for op in range(1, n_ops + 1):
        if op in reboots_at:
            vm.stop()
            r = redsea_fsck.fsck(disk)
            check(not r["errors"], f"op {op}: host fsck clean after shutdown ({r['shared']} shared extents)" +
                  (f" -> {r['errors'][:3]}" if r["errors"] else ""))
            vm, tls, ok = boot(disk)
            check(ok and "fsck: structure OK" in vm.output(), f"op {op}: reboot, structure OK at mount")
            auth, csrf = login()
            verify_all(f"op {op} after reboot")
            continue
        kind = rnd.choices(["put", "delete", "snap", "snapdel", "restore1", "restoreall"],
                           weights=[45, 15, 10, 8, 14, 8])[0]
        if kind == "put":
            name = rnd.choice(NAMES)
            data = os.urandom(size())
            st = dav("PUT", name, data)[0]
            if st in (201, 204):
                model.live[name] = data
            else:
                check(False, f"op {op}: PUT {name} ({len(data)} B) -> {st}")
        elif kind == "delete" and model.live:
            name = rnd.choice(sorted(model.live))
            st = dav("DELETE", name)[0]
            if st in (200, 204):
                del model.live[name]
            else:
                check(False, f"op {op}: DELETE {name} -> {st}")
        elif kind == "snap":
            if len(model.snaps) >= 12:
                kind = "snapdel"
            else:
                st, r = tw.action(tls, auth, csrf, "snapshot_create", comment=f"op{op}")
                mm = re.search(r"Instantánea (\d+) creada", r.get("message", ""))
                if st == 200 and mm:
                    model.snaps[int(mm.group(1))] = dict(model.live)
                else:
                    check(False, f"op {op}: snapshot_create -> {st} {r.get('message')}")
        if kind == "snapdel" and model.snaps:
            sid = rnd.choice(sorted(model.snaps))
            st, r = tw.action(tls, auth, csrf, "snapshot_delete", name=str(sid))
            if st == 200:
                del model.snaps[sid]
            else:
                check(False, f"op {op}: snapshot_delete {sid} -> {st} {r.get('message')}")
        elif kind == "restore1" and model.snaps:
            sid = rnd.choice(sorted(model.snaps))
            if model.snaps[sid]:
                name = rnd.choice(sorted(model.snaps[sid]))
                st, r = tw.action(tls, auth, csrf, "snapshot_restore", name=str(sid), path=name)
                if st == 200:
                    model.live[name] = model.snaps[sid][name]
                else:
                    check(False, f"op {op}: restore {sid}:{name} -> {st} {r.get('message')}")
        elif kind == "restoreall" and model.snaps:
            sid = rnd.choice(sorted(model.snaps))
            st, r = tw.action(tls, auth, csrf, "snapshot_restore", name=str(sid), path="")
            if st == 200:
                model.live.update(model.snaps[sid])
            else:
                check(False, f"op {op}: restore all {sid} -> {st} {r.get('message')}")
        stats[kind] = stats.get(kind, 0) + 1
        if op % 40 == 0:
            if not verify_all(f"op {op}"):
                break
    verify_all("end of run")
    out = vm.output()
    check("VIRTIO-BLK]" not in out and "Security Alert" not in out and "FATAL" not in out,
          "no driver errors, RedSea alerts or kernel faults")
    vm.stop()
    r = redsea_fsck.fsck(disk)
    check(not r["errors"], f"host fsck clean at the end ({r['shared']} shared extents, {r['files']} files)")
    print(f"  operations: {stats}; live files {len(model.live)}, snapshots {len(model.snaps)}", flush=True)


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    n_ops = int(sys.argv[2]) if len(sys.argv) > 2 else 240
    tmp = tempfile.mkdtemp(prefix="yesos_fsmodel_")
    try:
        if "--no-damage" not in sys.argv:
            part_a(tmp)
        part_b(tmp, seed, n_ops)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
