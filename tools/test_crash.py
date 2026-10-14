#!/usr/bin/env python3
"""
Crash-consistency test: power cuts at random moments.

Each cycle runs a few acknowledged operations (writes, deletes, snapshot
create/delete, restores), then starts one more and kills QEMU after a random
delay - before, during or after it. After the reboot:
  - the kernel fsck must be clean (mount recovery included),
  - every file must hold either its previous content or the new one (never a
    mix, never anything else), untouched files must be unchanged,
  - every listed snapshot must be complete and byte-identical to the moment
    it was taken; an interrupted create leaves no snapshot or a complete one,
    an interrupted delete leaves it intact or gone.
The model then adopts what was observed and the next cycle starts.

Usage: python3 tools/test_crash.py [seed] [cycles]      (non-zero exit on failure)
"""
import hashlib
import struct
import os
import random
import shutil
import sys
import tempfile
import threading
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402
import test_webadmin as tw  # noqa: E402
from test_webdav import basic  # noqa: E402
import redsea_fsck  # noqa: E402

failures = []
ADMIN = ("crashadmin", "crash-admin-pass")
NAMES = [f"share/c{i}.bin" for i in range(5)] + [f"media/d{i}.dat" for i in range(3)]
H = lambda b: hashlib.sha256(b).hexdigest() if b is not None else None


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label, flush=True)
    if not cond:
        failures.append(label)
    return cond


class Node:
    def __init__(self, disk):
        self.disk = disk
        self.vm = None

    def boot(self, first=False):
        web, tls, udp = tw.free_ports(3)
        self.tls = tls
        tw.TLS_PORT = tls
        self.vm = tw.WebYesOS(self.disk, udp, web, tls)
        ok = self.vm.wait_for("YesOS [", 120) and tw.wait_up(web)
        if ok and first:
            m = self.vm.send(f"user add {ADMIN[0]} {ADMIN[1]} admin", 2)
            self.vm.wait_for("created successfully", 60, m)
        if ok:
            self.vm.send("nas admit 10.0.2.2", 1)
            self.auth, self.csrf = tw.session_of(tls, *ADMIN)
        return ok

    def stop(self):
        if self.vm:
            self.vm.stop()
            self.vm = None

    def dav(self, method, name, body=None, snap=None):
        path = f"/dav/backup/snap-{snap:04d}/{name}" if snap else "/dav/" + name
        return tw.req(self.tls, method, quote(path), body, basic(*ADMIN))

    def act(self, action_name, **f):
        return tw.action(self.tls, self.auth, self.csrf, action_name, **f)

    def fsck(self):
        m = self.vm.send("fsck", 1)
        self.vm.wait_for("data: ", 120, m)
        return self.vm.since(m)


def run(seed, cycles):
    rnd = random.Random(seed)
    tmp = tempfile.mkdtemp(prefix="yesos_crash_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    node = Node(disk)
    live = {}       # name -> bytes
    snaps = {}      # id -> {name: bytes}
    crashes = {"put": 0, "delete": 0, "snap": 0, "snapdel": 0, "restore1": 0, "restoreall": 0}
    recov = {"deletes": 0, "snapshots": 0}

    def size():
        return rnd.choice([0, 1, 511, 512, 4097, rnd.randint(1000, 60000), rnd.randint(60000, 300000)])

    def plan():
        kinds = ["put"] * 5 + ["delete"] * 2 + ["snap"] * 2 + ["snapdel", "restore1", "restoreall"]
        k = rnd.choice(kinds)
        if k == "put":
            return ("put", rnd.choice(NAMES), os.urandom(size()))
        if k == "delete" and live:
            return ("delete", rnd.choice(sorted(live)), None)
        if k == "snap" and len(snaps) < 8:
            return ("snap", None, None)
        if k == "snapdel" and snaps:
            return ("snapdel", rnd.choice(sorted(snaps)), None)
        if k == "restore1" and snaps:
            sid = rnd.choice(sorted(snaps))
            if snaps[sid]:
                return ("restore1", sid, rnd.choice(sorted(snaps[sid])))
        if k == "restoreall" and snaps:
            return ("restoreall", rnd.choice(sorted(snaps)), None)
        return ("put", rnd.choice(NAMES), os.urandom(size()))

    last_msg = [""]

    def execute(op):
        """Runs an operation; returns True when the NAS acknowledged it."""
        kind, a, b = op
        last_msg[0] = ""
        try:
            if kind == "put":
                return node.dav("PUT", a, b)[0] in (201, 204)
            if kind == "delete":
                return node.dav("DELETE", a)[0] in (200, 204)
            if kind == "snap":
                st, r = node.act("snapshot_create", comment="crash")
                return st == 200
            if kind == "snapdel":
                return node.act("snapshot_delete", name=str(a))[0] == 200
            if kind == "restore1":
                st, r = node.act("snapshot_restore", name=str(a), path=b)
                last_msg[0] = r.get("message", "")
                return st == 200
            if kind == "restoreall":
                st, r = node.act("snapshot_restore", name=str(a), path="")
                last_msg[0] = r.get("message", "")
                return st == 200
        except Exception as e:
            last_msg[0] = f"{type(e).__name__}: {e}"
            return False
        return False

    def apply(op):
        kind, a, b = op
        if kind == "put":
            live[a] = b
        elif kind == "delete":
            live.pop(a, None)
        elif kind == "snap":
            ids = [s["id"] for s in tw.view(node.tls, node.auth, "snapshots").get("snapshots", [])]
            new = [i for i in ids if i not in snaps]
            if new:
                snaps[max(new)] = dict(live)
        elif kind == "snapdel":
            snaps.pop(a, None)
        elif kind == "restore1":
            live[b] = snaps[a][b]
        elif kind == "restoreall":
            live.update(snaps[a])

    if not check(node.boot(first=True), f"seed {seed}: system boots"):
        node.stop()
        return
    for cycle in range(1, cycles + 1):
        # acknowledged operations
        for _ in range(rnd.randint(0, 4)):
            op = plan()
            if execute(op):
                apply(op)
            else:
                check(False, f"seed {seed} cycle {cycle}: acknowledged {op[0]} {op[1]} failed: {last_msg[0]}")
        # the operation interrupted by the power cut
        op = plan()
        kind, a, b = op
        before_live = dict(live)
        before_snaps = {k: dict(v) for k, v in snaps.items()}
        t = threading.Thread(target=execute, args=(op,), daemon=True)
        t.start()
        time.sleep(0 if rnd.random() < 0.2 else rnd.uniform(0, 0.3))
        node.vm.p.kill()
        node.vm.p.wait()
        node.vm = None
        t.join(5)
        crashes[kind] += 1

        if not check(node.boot(), f"seed {seed} cycle {cycle}: boots after a power cut during {kind}"):
            break
        out = node.vm.output()
        recov["deletes"] += out.count("interrupted delete")
        recov["snapshots"] += out.count("removed incomplete snapshot")
        fo = node.fsck()
        problems = []
        if "fsck: CLEAN" not in fo or " 0 BAD, 0 unreadable" not in fo:
            problems.append("kernel fsck: " + " | ".join(l.strip() for l in fo.splitlines() if "ERROR" in l or "fsck:" in l)[:300])

        # live files: allowed outcomes
        observed = {}
        for name in NAMES:
            st, _, body = node.dav("GET", name)
            observed[name] = body if st == 200 else None
            if st not in (200, 404):
                problems.append(f"{name}: HTTP {st}")
        for name in NAMES:
            old = before_live.get(name)
            allowed = {H(old)}
            if kind == "put" and name == a:
                allowed.add(H(b))
            if kind == "delete" and name == a:
                allowed.add(None)
            if kind == "restore1" and name == b:
                allowed.add(H(before_snaps[a][b]))
            if kind == "restoreall" and name in before_snaps.get(a, {}):
                allowed.add(H(before_snaps[a][name]))
            if H(observed[name]) not in allowed:
                problems.append(f"{name}: unexpected content after cut during {kind} "
                                f"({len(observed[name]) if observed[name] is not None else 'absent'} B)")
        # snapshots: complete or absent
        listed = {s["id"]: s for s in tw.view(node.tls, node.auth, "snapshots").get("snapshots", [])}
        expected_ids = set(before_snaps)
        if kind == "snapdel":
            expected_ids_opt = {a}
            if a not in listed:
                expected_ids.discard(a)
        else:
            expected_ids_opt = set()
        new_ids = set(listed) - set(before_snaps)
        if new_ids and not (kind == "snap" and len(new_ids) == 1):
            problems.append(f"unexpected snapshots {sorted(new_ids)}")
        missing = expected_ids - set(listed) - expected_ids_opt
        if missing:
            problems.append(f"snapshots lost: {sorted(missing)}")
        check_content = {sid: before_snaps[sid] for sid in set(listed) & set(before_snaps)}
        for sid in new_ids:
            check_content[sid] = before_live
        for sid, content in check_content.items():
            # only the files this test manages (the source disk may hold others)
            files = {f["path"] for f in listed[sid].get("files", []) if f["path"] in NAMES}
            if files != set(content):
                problems.append(f"snapshot {sid}: files {sorted(files)} != {sorted(content)}")
                continue
            for name, data in content.items():
                st, _, body = node.dav("GET", name, snap=sid)
                if st != 200 or H(body) != H(data):
                    problems.append(f"snapshot {sid} {name}: {st}")
        if not check(not problems, f"seed {seed} cycle {cycle}: consistent after a power cut during {kind}" +
                     (f" -> {problems[:3]}" if problems else "")):
            break
        # adopt the observed state
        live = {k: v for k, v in observed.items() if v is not None}
        snaps = {sid: (before_snaps[sid] if sid in before_snaps else dict(before_live)) for sid in listed}
    node.stop()
    r = redsea_fsck.fsck(disk)
    check(not r["errors"], f"seed {seed}: host fsck clean after the last clean shutdown" +
          (f" -> {r['errors'][:2]}" if r["errors"] else ""))
    print(f"  seed {seed}: power cuts during {crashes}; recovery: {recov}", flush=True)
    shutil.rmtree(tmp, ignore_errors=True)


def _dir(img):
    with open(img, "rb") as f:
        f.seek(512)
        sb = bytearray(f.read(512))
        root_lba, root_sec = struct.unpack("<QQ", sb[24:40])
        f.seek(root_lba * 512)
        return sb, root_lba, bytearray(f.read(root_sec * 512))


def _write_dir(img, sb, root_lba, raw):
    with open(img, "r+b") as f:
        f.seek(512)
        f.write(sb)
        f.seek(root_lba * 512)
        f.write(raw)


def _used(raw):
    return [i for i in range(len(raw) // 256) if struct.unpack("<I", raw[i * 256 + 248:i * 256 + 252])[0] & 1]


def _name(raw, i):
    return bytes(raw[i * 256:i * 256 + 224]).split(b"\0")[0].decode()


def deterministic():
    """Builds on disk the exact states a power cut can leave, then checks the repair."""
    tmp = tempfile.mkdtemp(prefix="yesos_crashdet_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    node = Node(disk)
    data = {f"share/k{i}.bin": os.urandom(5000 + 3000 * i) for i in range(4)}
    try:
        check(node.boot(first=True), "recovery: system boots")
        for n, d in data.items():
            node.dav("PUT", n, d)
        st, r = node.act("snapshot_create", comment="victim")
        sid = max(s["id"] for s in tw.view(node.tls, node.auth, "snapshots")["snapshots"])
        data["share/zz-last.bin"] = os.urandom(7777)   # a normal file is the last directory entry
        node.dav("PUT", "share/zz-last.bin", data["share/zz-last.bin"])
    finally:
        node.stop()

    # (a) interrupted delete: the last entry already copied into the deleted
    # file's slot, the last slot not yet cleared -> two identical entries.
    sb, root, raw = _dir(disk)
    used = _used(raw)
    last = used[-1]
    assert _name(raw, last) == "share/zz-last.bin", _name(raw, last)
    victim = next(i for i in used if _name(raw, i) == "share/k1.bin")
    moved = _name(raw, last)
    raw[victim * 256:(victim + 1) * 256] = raw[last * 256:(last + 1) * 256]
    # (b) interrupted snapshot: its manifest gone, its files still there
    manifest = next(i for i in _used(raw) if _name(raw, i) == f"backup/snap-{sid:04d}/.snapshot")
    raw[manifest * 256:(manifest + 1) * 256] = bytes(256)
    # (c) superblock file count left behind
    struct.pack_into("<Q", sb, 56, 7)
    _write_dir(disk, sb, root, raw)
    before = redsea_fsck.fsck(disk)
    check(any("duplicate" in e for e in before["errors"]), "recovery: damaged image really has the duplicate entry")

    try:
        check(node.boot(), "recovery: boots on the interrupted image")
        out = node.vm.output()
        check("completed 1 interrupted delete" in out, "recovery: interrupted delete completed at mount")
        check(f"removed incomplete snapshot {sid}" in out, "recovery: incomplete snapshot removed at boot")
        fo = node.fsck()
        check("fsck: CLEAN" in fo and "0 warning(s)" in fo and " 0 BAD" in fo,
              "recovery: kernel fsck clean, no warnings (superblock count repaired)")
        st, _, _ = node.dav("GET", "share/k1.bin")
        check(st == 404, "recovery: the deleted file stays deleted")
        ok = True
        for n, d in data.items():
            if n == "share/k1.bin":
                continue
            st, _, body = node.dav("GET", n)
            ok &= st == 200 and H(body) == H(d)
        check(ok, f"recovery: every other file intact, including the moved entry '{moved}'")
        snaps = [s["id"] for s in tw.view(node.tls, node.auth, "snapshots")["snapshots"]]
        check(sid not in snaps, "recovery: the incomplete snapshot is no longer listed")
    finally:
        node.stop()
    after = redsea_fsck.fsck(disk)
    check(not after["errors"] and not after["warnings"] and after["free_sectors"] > before["free_sectors"],
          f"recovery: host fsck clean; snapshot space reclaimed ({after['free_sectors'] - before['free_sectors']} sectors)")
    shutil.rmtree(tmp, ignore_errors=True)


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    cycles = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    if "--no-deterministic" not in sys.argv:
        deterministic()
    run(seed, cycles)
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
