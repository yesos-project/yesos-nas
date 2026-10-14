#!/usr/bin/env python3
"""
Replication test: disaster recovery from an encrypted copy on another machine.

NAS A (copy of yesos_disk.img): files in share/media, a vault with a secret,
two snapshots -> `yesos_replicate.py pull` into an encrypted repository ->
incremental pulls download only what changed -> the repository holds no
plaintext, a wrong certificate fingerprint and a wrong passphrase are refused,
`verify` detects tampering. Then NAS B, a freshly formatted empty disk:
`restore` brings back every file byte-for-byte, the vault opens with the
original passphrase and its secret is readable; a different vault header is
refused (409) once B has a vault; kernel and host fsck are clean.

Usage: python3 tools/test_replication.py      (non-zero exit on failure)
"""
import contextlib
import io
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402
import test_webadmin as tw  # noqa: E402
from test_webdav import basic  # noqa: E402
import redsea_fsck  # noqa: E402
import redsea_injector  # noqa: E402
import yesos_replicate as rep  # noqa: E402

failures = []
ADMIN = ("repadmin", "rep-admin-pass1")
BACKUP_PASS = "copia-de-seguridad-2026"


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label, flush=True)
    if not cond:
        failures.append(label)
    return cond


def boot(disk):
    web, tls, udp = tw.free_ports(3)
    tw.TLS_PORT = tls
    vm = tw.WebYesOS(disk, udp, web, tls)
    ok = vm.wait_for("YesOS [", 240) and tw.wait_up(web, 120)
    if ok:
        m = vm.send(f"user add {ADMIN[0]} {ADMIN[1]} admin", 2)
        vm.wait_for("created successfully", 60, m)
        vm.send("nas admit 10.0.2.2", 1)
    m = vm.send("tls", 2)
    vm.wait_for("SHA-256", 30, m)
    return vm, tls, ok, tw.console_fingerprint(vm.output())


def run(*argv, passphrase=BACKUP_PASS):
    """Runs the replication tool in-process; returns (exit code, output)."""
    os.environ["YESOS_PASSWORD"] = ADMIN[1]
    os.environ["YESOS_BACKUP_PASSPHRASE"] = passphrase
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = rep.main([str(a) for a in argv])
    text = out.getvalue()
    print("        > " + text.strip().replace("\n", "\n        > "))
    return code, text


def remote(tls, fp):
    return ["--host", "127.0.0.1", "--port", tls, "--user", ADMIN[0], "--fingerprint", fp]


def kernel_fsck(vm):
    m = vm.send("fsck", 1)
    vm.wait_for("data: ", 600, m)
    return vm.since(m)


def main():
    tmp = tempfile.mkdtemp(prefix="yesos_rep_")
    disk_a = os.path.join(tmp, "nas_a.img")
    disk_b = os.path.join(tmp, "nas_b.img")
    repo = os.path.join(tmp, "repo")
    shutil.copyfile(harness.SRC_DISK, disk_a)
    b_data = os.urandom(300 * 1024)
    big = os.urandom(64 * 1024)
    files = {"share/rep/a.txt": b"replica version 1 PLAINTEXT-MARKER-A", "media/rep/b.bin": b_data,
             "share/rep/big.bin": big}
    try:
        # ---- NAS A: data, vault, snapshots, pulls ------------------------
        vm, tls, ok, fp = boot(disk_a)
        try:
            check(ok and fp, f"NAS A boots, fingerprint from the console ({fp[:16] if fp else '?'}...)")
            auth, csrf = tw.session_of(tls, *ADMIN)
            act = lambda name_, **f: tw.action(tls, auth, csrf, name_, **f)
            dav = lambda m_, p_, b_=None: tw.req(tls, m_, p_, b_, basic(*ADMIN))
            sts = [dav("PUT", "/dav/" + p, d)[0] for p, d in files.items()]
            check(all(s == 201 for s in sts), f"files uploaded to NAS A ({sts})")
            vm.send("vault init", 1)
            vm.send(harness.PASS, 0.5)
            m = vm.send(harness.PASS, 0.5)
            check(vm.wait_for("Vault created and unlocked", 180, m), "vault created on NAS A")
            m = vm.send(f"write /vault/S.TXT {harness.SECRET}", 3)
            check("write:" in vm.since(m), "secret written to the vault")
            st, r = act("snapshot_create", comment="primera")
            check(st == 200, f"snapshot 1 ({r.get('message')})")

            code, _ = run("init", repo)
            check(code == 0 and os.path.exists(os.path.join(repo, "repo.json")), "encrypted repository created")
            code, _ = run("pull", repo, *remote(tls, "00" * 32))
            check(code == 1 and not rep.Repo(repo).snapshots(), "wrong certificate fingerprint: refused, nothing copied")
            code, _ = run("pull", repo, *remote(tls, fp), passphrase="otra-contrasena-mala")
            check(code == 1, "wrong backup passphrase: refused")
            code, out = run("pull", repo, *remote(tls, fp))
            check(code == 0 and "Pulled 1 new snapshot" in out, "first pull copies snapshot 1")

            files["share/rep/a.txt"] = b"replica version 2 PLAINTEXT-MARKER-B"
            files["share/rep/new.txt"] = b"added after snapshot 1"
            for p in ("share/rep/a.txt", "share/rep/new.txt"):
                dav("PUT", "/dav/" + p, files[p])
            st, r = act("snapshot_create", comment="segunda")
            check(st == 200, f"snapshot 2 ({r.get('message')})")
            code, out = run("pull", repo, *remote(tls, fp))
            check(code == 0 and "Pulled 1 new snapshot" in out and " 2 downloaded" in out,
                  "incremental pull: only the 2 changed/new files are downloaded")
            code, out = run("pull", repo, *remote(tls, fp))
            check(code == 0 and "Pulled 0 new snapshot" in out, "pull with nothing new copies nothing")
            st, r = act("snapshot_create", comment="sin cambios")
            code, out = run("pull", repo, *remote(tls, fp))
            check(code == 0 and "Pulled 1 new snapshot" in out and " 0 downloaded" in out,
                  "snapshot with no changes: listed, zero bytes downloaded")
            check("réplica: exportar" in str(tw.view(tls, auth, "audit")), "exports appear in the activity log")
        finally:
            vm.stop()

        # ---- repository checks -------------------------------------------
        blob = b""
        for root, _, names in os.walk(repo):
            for n in names:
                with open(os.path.join(root, n), "rb") as f:
                    blob += f.read()
        leaks = [lbl for lbl, needle in (("share text", b"PLAINTEXT-MARKER"), ("media data", b_data[1000:1064]),
                                         ("file names", b"share/rep"), ("vault secret", harness.SECRET.encode()))
                 if needle in blob]
        check(not leaks, f"repository holds no plaintext: contents and names encrypted {leaks or ''}")
        code, out = run("verify", repo)
        check(code == 0 and "OK:" in out, "verify: every object authenticates and matches its CRC")
        code, out = run("list", repo)
        check(code == 0 and out.count("snapshot") == 3 and "+vault header" in out, "list shows 3 snapshots with the vault header")
        bad = os.path.join(tmp, "repo_bad")
        shutil.copytree(repo, bad)
        objs = sorted(os.path.join(r, n) for r, _, ns in os.walk(os.path.join(bad, "objects")) for n in ns)
        victim = max(objs, key=os.path.getsize)
        with open(victim, "r+b") as f:
            f.seek(100)
            c = f.read(1)
            f.seek(100)
            f.write(bytes([c[0] ^ 1]))
        code, out = run("verify", bad)
        check(code == 1 and "authentication failed" in out, "verify detects a single flipped bit")
        os.remove(objs[0])
        code, out = run("verify", bad)
        check(code == 1 and "No such file" in out,
              "verify detects a missing object")

        # ---- NAS B: empty disk, restore ----------------------------------
        with contextlib.redirect_stdout(io.StringIO()):
            redsea_injector.format_disk(disk_b)
        vm, tls, ok, fp_b = boot(disk_b)
        try:
            check(ok and fp_b and fp_b != fp, "NAS B (new empty disk) boots with its own certificate")
            code, out = run("restore", repo, "--snap", "2", *remote(tls, fp))
            check(code == 1 and "fingerprint mismatch" in out, "restore to the wrong NAS fingerprint: refused")
            code, out = run("restore", repo, "--snap", "2", *remote(tls, fp_b))
            check(code == 0 and "Restored" in out, "snapshot 2 restored into NAS B")
            dav = lambda m_, p_, b_=None: tw.req(tls, m_, p_, b_, basic(*ADMIN))
            same = {p: dav("GET", "/dav/" + p)[2] == d for p, d in files.items()}
            check(all(same.values()), f"every file identical on NAS B ({sum(same.values())}/{len(same)})")
            m = vm.send("cat /vault/S.TXT", 2)
            check(harness.SECRET not in vm.since(m), "restored vault starts locked")
            vm.send("vault unlock", 1)
            m = vm.send(harness.PASS, 0.5)
            check(vm.wait_for("Vault unlocked", 60, m), "vault unlocks on NAS B with the original passphrase")
            m = vm.send("cat /vault/S.TXT", 2)
            check(harness.SECRET in vm.since(m), "vault secret readable on NAS B")
            auth, csrf = tw.session_of(tls, *ADMIN)
            hdrs = dict(auth, **{"X-CSRF-Token": csrf})
            st, _, cur = tw.req(tls, "GET", "/api/export/vault-header", None, auth)
            other = bytearray(cur)
            other[-1] ^= 0xFF
            st2, _, _ = tw.req(tls, "POST", "/api/import/vault-header", bytes(other), hdrs)
            check(st == 200 and st2 == 409, f"a vault header cannot replace an existing vault (HTTP {st2})")
            st, _, _ = tw.req(tls, "POST", "/api/import/file?path=share/x.txt", b"x", auth)
            check(st == 403, f"import without the CSRF token refused (HTTP {st})")
            for p in ("SYS/USERS.CFG", "backup/snap-0001/share/x", "share/../SYS/A", "kernel.bin"):
                st, _, _ = tw.req(tls, "POST", "/api/import/file?path=" + p, b"x", hdrs)
                check(st in (400, 403), f"import refused for '{p}' (HTTP {st})")
            code, out = run("restore", repo, "--snap", "2", *remote(tls, fp_b))
            check(code == 0 and "skipped" not in out, "restoring again over the same vault works (idempotent)")
            fo = kernel_fsck(vm)
            check("fsck: CLEAN" in fo and " 0 BAD" in fo, "NAS B kernel fsck clean")
        finally:
            vm.stop()
        r = redsea_fsck.fsck(disk_b)
        check(not r["errors"], f"NAS B host fsck clean ({r['files']} files)")
        r = redsea_fsck.fsck(disk_a)
        check(not r["errors"], "NAS A host fsck clean")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
