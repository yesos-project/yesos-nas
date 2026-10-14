#!/usr/bin/env python3
"""
Disk stress test: many WebDAV writes, deletes, snapshots and vault writes in
one boot, then a reboot that must find every file byte-identical, the vault
header and the RNG seed. Run several copies in parallel to load the host:
it caught a torn-read bug in the virtio rings (packed structs).
Usage: python3 tools/test_disk_stress.py      (non-zero exit on failure)
"""
import hashlib
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness
import test_webadmin as tw
from test_webdav import basic
tmp = tempfile.mkdtemp(prefix="yesos_stress_"); disk = os.path.join(tmp, "d.img"); shutil.copyfile(harness.SRC_DISK, disk)
web, tls, udp = tw.free_ports(3); tw.TLS_PORT = tls
A = basic("st", "stress-pass-1")
expected = {}
problems = []
vm = tw.WebYesOS(disk, udp, web, tls)
try:
    assert vm.wait_for("YesOS [", 120) and tw.wait_up(web)
    m = vm.send("user add st stress-pass-1 admin", 2); vm.wait_for("created successfully", 60, m)
    vm.send("vault init", 1); vm.send(harness.PASS, 0.5); m = vm.send(harness.PASS, 0.5); vm.wait_for("Vault created", 180, m)
    for rnd in range(6):
        for k in range(6):
            data = os.urandom(1000 + 7000 * ((rnd * 6 + k) % 9))
            name = f"share/st{k}.bin"
            st = tw.req(tls, "PUT", "/dav/" + name, data, A)[0]
            if st == 201: expected[name] = hashlib.sha256(data).hexdigest()
        vm.send(f"snapshot create r{rnd}", 2)
        if rnd % 2: vm.send(f"snapshot delete {rnd}", 2)
        tw.req(tls, "DELETE", "/dav/share/st0.bin", None, A); expected.pop("share/st0.bin", None)
        vm.send(f"write /vault/V{rnd}.TXT vault-secret-{rnd}", 2)
    vm.send("snapshot legacy delete", 2)
finally:
    vm.stop()
vm = tw.WebYesOS(disk, udp, web, tls)
try:
    assert vm.wait_for("YesOS [", 120) and tw.wait_up(web)
    out = vm.output()
    if "initialized, LOCKED" not in out: problems.append("vault header missing")
    if "persisted seed" not in out: problems.append("RNG seed missing")
    if "VIRTIO-BLK]" in out: problems.append("virtio-blk errors reported")
    for name, h in expected.items():
        st, _, body = tw.req(tls, "GET", "/dav/" + name, None, A)
        if st != 200 or hashlib.sha256(body).hexdigest() != h: problems.append(f"{name}: {st}")
finally:
    vm.stop()
shutil.rmtree(tmp, ignore_errors=True)
if problems:
    print("FAILED:", problems)
    sys.exit(1)
print(f"All {len(expected)} files, the vault header and the RNG seed survived the reboot")
