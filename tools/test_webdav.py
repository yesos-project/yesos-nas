#!/usr/bin/env python3
"""
WebDAV end-to-end test: login (HTTP Basic over HTTPS), permissions, and
byte-identical, persistent uploads and downloads. Boots YesOS twice on a
scratch copy of yesos_disk.img with TCP 8080 and 8443 forwarded.
Usage: python3 tools/test_webdav.py [image.jpg]     (non-zero exit on failure)
"""
import base64
import hashlib
import http.client
import os
import shutil
import sys
import tempfile
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402
import test_webadmin as tw  # noqa: E402

failures = []
ADMIN = ("davadmin", "dav-admin-pass1")
WRITER = ("davwriter", "dav-writer-pass")
READER = ("davreader", "dav-reader-pass")


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def basic(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def dav(port, method, path, body=None, creds=ADMIN, headers=None, tls=True):
    h = dict(headers or {})
    if creds:
        h.update(basic(*creds))
    if tls:
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=120, context=tw.client_ctx())
    else:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, hdrs, data


def main():
    image_path = sys.argv[1] if len(sys.argv) > 1 else None
    tmp = tempfile.mkdtemp(prefix="yesos_dav_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    with open(disk, "rb") as f:
        f.seek(512 + 8)
        src_version = int.from_bytes(f.read(4), "little")   # RedSea superblock version
    web, tls, udp = tw.free_ports(3)
    tw.TLS_PORT = tls

    image = open(image_path, "rb").read() if image_path else os.urandom(224226)
    big = os.urandom(3 * 1024 * 1024)               # maximum entropy, like encrypted/compressed data
    chunked = b"chunked upload " * 4000
    sha = lambda b: hashlib.sha256(b).hexdigest()
    long_name = "Captura de pantalla 2026-10-04 a las 14.11.32 - informe trimestral del NAS (version final).png"

    vm = tw.WebYesOS(disk, udp, web, tls)
    try:
        check(vm.wait_for("YesOS [", 120) and tw.wait_up(web), "system boots")
        boot1 = vm.output()
        if src_version < 4:
            check(f"Volume migrated v{src_version} -> v4" in boot1, f"existing v{src_version} disk migrated to RedSea v4 on first boot")
        else:
            check("Volume migrated" not in boot1, f"v{src_version} disk mounted without migration")
        for (u, p), role in ((ADMIN, "admin"), (WRITER, "rw"), (READER, "ro")):
            m = vm.send(f"user add {u} {p} {role}", 2)
            vm.wait_for("created successfully", 60, m)
        mark = len(vm.output())

        # --- login policy ---------------------------------------------------
        st, h, _ = dav(tls, "PROPFIND", "/dav/", creds=None, headers={"Depth": "1"})
        check(st == 401 and h.get("www-authenticate", "").startswith('Basic realm="YesOS NAS"'),
              f"no credentials -> 401 with a Basic challenge ({st})")
        st, _, _ = dav(tls, "GET", "/dav/share/x", creds=(ADMIN[0], "wrong-password"))
        check(st == 401, "wrong password -> 401")
        st, _, _ = dav(tls, "GET", "/dav/share/x", creds=("nobody", "whatever-pass"))
        check(st == 401, "unknown user -> 401")
        st, _, _ = dav(tls, "PROPFIND", "/dav/", creds=None, headers={"Authorization": "Basic !!!notbase64"})
        check(st == 401, "malformed Authorization header -> 401")
        st, _, _ = dav(web, "PROPFIND", "/dav/", creds=ADMIN, headers={"Depth": "1"}, tls=False)
        check(st == 403, "WebDAV over plain HTTP refused, even with credentials")
        st, h, _ = dav(web, "GET", "/dav/media/a%20b.jpg", creds=None, tls=False, headers={"Host": "127.0.0.1:8080"})
        check(st == 302 and h.get("location") == "https://127.0.0.1:8443/dav/media/a%20b.jpg",
              f"plain-HTTP GET redirected to HTTPS ({h.get('location')})")
        st, _, _ = dav(web, "OPTIONS", "/dav/", creds=None, tls=False)
        check(st == 200, "OPTIONS (capability probe) still answered without login")

        # --- data, as an admin ------------------------------------------------
        st, _, _ = dav(tls, "PUT", "/dav/media/photo.jpg", image)
        check(st == 201, f"PUT image ({len(image)} bytes) -> {st}")
        t0 = time.time()
        for _ in range(5):
            st, _, data = dav(tls, "GET", "/dav/media/photo.jpg")
        el = time.time() - t0
        check(st == 200 and sha(data) == sha(image), f"GET image is byte-identical ({len(data)} bytes)")
        check(el < 5, f"cached credentials: 5 authenticated GETs in {el:.2f}s (no Argon2 per request)")

        t0 = time.time()
        st, _, _ = dav(tls, "PUT", "/dav/share/random.bin", big)
        st2, _, data = dav(tls, "GET", "/dav/share/random.bin")
        check(st == 201 and st2 == 200 and sha(data) == sha(big),
              f"3 MiB random (high-entropy) file round trip over TLS ({time.time() - t0:.1f}s)")

        c = http.client.HTTPSConnection("127.0.0.1", tls, timeout=60, context=tw.client_ctx())
        c.putrequest("PUT", "/dav/share/chunked.txt")
        c.putheader("Transfer-Encoding", "chunked")
        c.putheader("Authorization", basic(*ADMIN)["Authorization"])
        c.endheaders()
        for i in range(0, len(chunked), 7000):
            part = chunked[i:i + 7000]
            c.send(b"%x\r\n" % len(part) + part + b"\r\n")
        c.send(b"0\r\n\r\n")
        st = c.getresponse().status
        c.close()
        st2, _, data = dav(tls, "GET", "/dav/share/chunked.txt")
        check(st == 201 and data == chunked, "chunked transfer-encoding upload")

        st, _, data = dav(tls, "PROPFIND", "/dav/media/", headers={"Depth": "1"})
        check(st == 207 and b"photo.jpg" in data, "PROPFIND lists the uploaded file")
        st, _, _ = dav(tls, "PUT", "/dav/media/" + quote(long_name), image)
        st2, _, data = dav(tls, "GET", "/dav/media/" + quote(long_name))
        check(st == 201 and st2 == 200 and sha(data) == sha(image), f"{len(long_name)}-character file name round trip")
        st, _, _ = dav(tls, "PUT", "/dav/media/" + "n" * 230 + ".jpg", b"x" * 10)
        check(st == 400, f"name beyond the 223-character limit -> clear 400 ({st})")
        st, _, _ = dav(tls, "PUT", "/dav/backup/x.txt", b"x")
        check(st == 403, "/backup is read-only (WORM)")
        st, _, _ = dav(tls, "PUT", "/dav/vault/x.txt", b"x")
        check(st == 403, "/vault not reachable over WebDAV, even for an admin")

        # --- roles and share masks -------------------------------------------
        st, _, _ = dav(tls, "PUT", "/dav/share/w.txt", b"writer", creds=WRITER)
        st2, _, data = dav(tls, "GET", "/dav/share/w.txt", creds=WRITER)
        check(st == 201 and data == b"writer", "read-write account uploads and downloads")
        st, _, data = dav(tls, "GET", "/dav/media/photo.jpg", creds=READER)
        check(st == 200 and sha(data) == sha(image), "read-only account reads /media")
        st, _, _ = dav(tls, "PUT", "/dav/media/r.txt", b"x", creds=READER)
        st2, _, _ = dav(tls, "DELETE", "/dav/media/photo.jpg", creds=READER)
        st3, _, _ = dav(tls, "MKCOL", "/dav/media/newdir/", creds=READER)
        check(st == 403 and st2 == 403 and st3 == 403, f"read-only account cannot PUT, DELETE or MKCOL ({st} {st2} {st3})")
        st, _, _ = dav(tls, "GET", "/dav/share/w.txt", creds=READER)
        check(st == 403, "read-only account limited to its shares (no /share)")

        # --- credential cache follows account changes ---------------------------
        m = vm.send(f"user passwd {WRITER[0]} dav-writer-new1", 2)
        vm.wait_for("updated successfully", 60, m)
        st, _, _ = dav(tls, "GET", "/dav/share/w.txt", creds=WRITER)
        st2, _, _ = dav(tls, "GET", "/dav/share/w.txt", creds=(WRITER[0], "dav-writer-new1"))
        check(st == 401 and st2 == 200, "old password stops working at once after a change (cache emptied)")
        m = vm.send(f"user del {WRITER[0]}", 2)
        st, _, _ = dav(tls, "GET", "/dav/share/w.txt", creds=(WRITER[0], "dav-writer-new1"))
        check(st == 401, "deleted account rejected")

        kernel_out = vm.since(mark).replace(f"user passwd {WRITER[0]} dav-writer-new1", "")
        check(ADMIN[1] not in kernel_out and READER[1] not in kernel_out and "dav-writer-new1" not in kernel_out,
              "passwords never printed by the kernel")
        check(f"[WEBDAV] '{ADMIN[0]}' logged in from 10.0.2.2" in vm.output(), "WebDAV logins noted on the console")

        # Consecutive failures since the last successful check count, so the
        # limit may be reached before the fifth attempt of this loop.
        codes = []
        for i in range(6):
            codes.append(dav(tls, "GET", "/dav/share/w.txt", creds=(ADMIN[0], f"bad-pass-{i}"))[0])
            if codes[-1] == 429:
                break
        st, _, _ = dav(tls, "GET", "/dav/media/photo.jpg")
        check(codes[-1] == 429 and len(codes) <= 5 and set(codes[:-1]) == {401} and st == 429,
              f"at most 5 failures throttle the IP, even for good credentials ({codes}, then {st})")
        time.sleep(31)
        st, _, _ = dav(tls, "GET", "/dav/media/photo.jpg")
        check(st == 200, "access resumes after the 30 s throttle")
    finally:
        vm.stop()

    vm = tw.WebYesOS(disk, udp, web, tls)
    try:
        check(vm.wait_for("YesOS [", 120) and tw.wait_up(web), "second boot")
        boot2 = vm.output()
        check("Volume migrated" not in boot2 and "RedSea" in boot2, "second boot mounts v4 directly")
        st, _, data = dav(tls, "GET", "/dav/media/photo.jpg")
        check(st == 200 and sha(data) == sha(image), "image and account persist across reboot")
        st, _, data = dav(tls, "GET", "/dav/media/" + quote(long_name))
        check(st == 200 and sha(data) == sha(image), "long-named file persists across reboot")
        st, _, data = dav(tls, "PROPFIND", "/dav/media/", headers={"Depth": "1"})
        check(quote(long_name, safe="/-._~").encode() in data, "PROPFIND lists the long name (percent-encoded href)")
        check(b"<D:displayname>" + long_name.encode() + b"</D:displayname>" in data, "displayname is the readable name")
        st, _, _ = dav(tls, "DELETE", "/dav/media/photo.jpg")
        st2, _, _ = dav(tls, "GET", "/dav/media/photo.jpg")
        check(st2 == 404, f"DELETE removes the file ({st}, then GET {st2})")
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
