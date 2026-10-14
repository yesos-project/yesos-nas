#!/usr/bin/env python3
"""
Web administration test: HTTPS (TLS 1.3), login policy, sessions, CSRF and
the JSON views. Boots YesOS headless twice on a scratch copy of
yesos_disk.img, with TCP 8080 (HTTP/WebDAV) and 8443 (HTTPS) forwarded.
Non-zero exit status on failure.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402

failures = []
SECTIONS = ["overview", "storage", "shares", "users", "devices", "network", "security", "session"]
TLS_PORT = None   # req() uses HTTPS for this port


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


class WebYesOS(harness.YesOS):
    """Same VM as the harness, plus TCP 8080 -> web_port and 8443 -> tls_port."""

    def __init__(self, disk, udp_port, web_port, tls_port=None):
        orig = harness.subprocess.Popen
        extra = f",hostfwd=tcp:127.0.0.1:{web_port}-:8080"
        if tls_port:
            extra += f",hostfwd=tcp:127.0.0.1:{tls_port}-:8443"

        def popen(cmd, *a, **kw):
            cmd = [c + extra if c.startswith("user,id=net0") else c for c in cmd]
            return orig(cmd, *a, **kw)

        harness.subprocess.Popen = popen
        try:
            super().__init__(disk, udp_port)
        finally:
            harness.subprocess.Popen = orig


def free_ports(n):
    """n distinct TCP ports that are free right now (avoids clashes between parallel tests)."""
    socks = [socket.socket() for _ in range(n)]
    for k in socks:
        k.bind(("127.0.0.1", 0))
    ports = [k.getsockname()[1] for k in socks]
    for k in socks:
        k.close()
    return ports


def client_ctx(max_version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # self-signed: the test pins the fingerprint instead
    if max_version:
        ctx.maximum_version = max_version
    return ctx


def req(port, method, path, body=None, headers=None):
    if port == TLS_PORT:
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=120, context=client_ctx())
    else:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, hdrs, data


FORM = {"Content-Type": "application/x-www-form-urlencoded"}


def login(port, user, pw):
    return req(port, "POST", "/api/login", urlencode({"user": user, "pass": pw}), FORM)


def action(port, auth, csrf, act, **fields):
    st, _, body = req(port, "POST", "/api/action/" + act, urlencode(fields),
                      dict(auth, **FORM, **({"X-CSRF-Token": csrf} if csrf else {})))
    try:
        return st, json.loads(body)
    except ValueError:
        return st, {"raw": body}


def view(port, auth, section):
    st, _, body = req(port, "GET", "/api/" + section, headers=auth)
    return json.loads(body) if st == 200 else {"status": st}


def session_of(port, user, pw):
    st, h, _ = login(port, user, pw)
    m = re.match(r"yesos_sid=([0-9a-f]{64});", h.get("set-cookie", ""))
    if st != 200 or not m:
        return None, None
    auth = {"Cookie": "yesos_sid=" + m.group(1)}
    return auth, view(port, auth, "session").get("csrf")


def tls_handshake(port, max_version=None):
    with socket.create_connection(("127.0.0.1", port), timeout=60) as raw:
        with client_ctx(max_version).wrap_socket(raw, server_hostname="yesos.local") as s:
            return s.version(), s.cipher()[0], s.getpeercert(binary_form=True)


def console_fingerprint(text):
    m = re.findall(r"\[TLS\]   SHA-256 ([0-9A-F:]{95})", text)
    return m[-1].replace(":", "").lower() if m else None


def wait_up(web, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        try:
            st, _, _ = req(web, "OPTIONS", "/dav/")   # answered without login
            if st == 200:
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


def main():
    global TLS_PORT
    tmp = tempfile.mkdtemp(prefix="yesos_web_")
    disk = os.path.join(tmp, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    web, tls, udp = free_ports(3)
    TLS_PORT = tls

    vm = WebYesOS(disk, udp, web, tls)
    try:
        check(vm.wait_for("YesOS [", 120) and wait_up(web), "system boots, HTTP up")
        out = vm.output()
        fp_console = console_fingerprint(out)
        check(fp_console is not None and "HTTPS admin panel on TCP 8443" in out, "console prints the HTTPS fingerprint")

        # --- TLS itself -----------------------------------------------------
        version, cipher, cert_der = tls_handshake(tls)
        check(version == "TLSv1.3", f"TLS 1.3 negotiated ({version}, {cipher})")
        check(cipher in ("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"), f"modern AEAD suite ({cipher})")
        check(hashlib.sha256(cert_der).hexdigest() == fp_console, "certificate fingerprint matches the console")
        cert = x509.load_der_x509_certificate(cert_der)
        pub = cert.public_key()
        try:
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
            sig_ok = True
        except Exception:
            sig_ok = False
        check(isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name == "secp256r1" and sig_ok,
              "self-signed ECDSA P-256 certificate with a valid signature")
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ips = san.get_values_for_type(x509.IPAddress)
        check(ipaddress.ip_address("10.0.2.15") in ips and ipaddress.ip_address("127.0.0.1") in ips
              and "yesos.local" in san.get_values_for_type(x509.DNSName),
              "SAN covers the NAS IP, 127.0.0.1 and yesos.local")
        try:
            tls_handshake(tls, ssl.TLSVersion.TLSv1_2)
            check(False, "TLS 1.2 client refused")
        except (ssl.SSLError, OSError):
            check(True, "TLS 1.2 client refused")

        if shutil.which("openssl"):
            def s_client(*args):
                r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{tls}", "-tls1_3", "-quiet", *args],
                                   input=b"GET /login HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                                   capture_output=True, timeout=60)
                return r.stdout
            check(b"login-form" in s_client("-ciphersuites", "TLS_AES_128_GCM_SHA256"),
                  "TLS_AES_128_GCM_SHA256 works (openssl s_client)")
            check(b"login-form" in s_client("-groups", "P-256:X25519"),
                  "client offering P-256 first is steered to X25519 (HelloRetryRequest)")

        # --- plain HTTP never serves the panel -------------------------------
        st, h, _ = req(web, "GET", "/", headers={"Host": "127.0.0.1:8080"})
        check(st == 302 and h.get("location") == "https://127.0.0.1:8443/",
              f"HTTP / redirects to HTTPS ({st} {h.get('location')})")
        st, h, _ = req(web, "GET", "/login", headers={"Host": "nas.lan"})
        check(st == 302 and h.get("location") == "https://nas.lan:8443/login", "HTTP /login redirects to HTTPS")
        st, _, body = req(web, "POST", "/api/login", "user=a&pass=b", {"Content-Type": "application/x-www-form-urlencoded"})
        check(st == 403 and b"https_required" in body, "login over plain HTTP refused")
        st, _, body = req(web, "GET", "/api/overview")
        check(st == 403 and b"https_required" in body, "API over plain HTTP refused")
        st, h, _ = req(web, "GET", "/", headers={"Host": "evil.example\"><script>"})
        check(st == 403 and "location" not in h, "hostile Host header cannot shape the redirect")

        # --- panel over HTTPS ----------------------------------------------
        st, h, _ = req(tls, "GET", "/")
        check(st == 302 and h.get("location") == "/login", f"/ without session redirects to /login ({st})")
        st, h, body = req(tls, "GET", "/login")
        csp = h.get("content-security-policy", "")
        check(st == 200 and b"login-form" in body, "login page served over HTTPS")
        check("script-src 'self'" in csp and "frame-ancestors 'none'" in csp, "strict CSP on the login page")
        check(h.get("x-frame-options") == "DENY" and h.get("cache-control") == "no-store", "anti-framing and no-store headers")
        check("access-control-allow-origin" not in h, "no wildcard CORS header")
        st = 401
        for s in SECTIONS:
            st, _, _ = req(tls, "GET", "/api/" + s)
            if st != 401:
                break
        check(st == 401, "every API section requires a session")

        st, _, body = req(tls, "GET", "/api/access")
        a = json.loads(body)
        check(a.get("admitted") is False and a.get("ip") == "10.0.2.2", f"access endpoint reports a non-admitted device ({a})")

        m = vm.send("user add webadmin s3cure-web-pass admin", 2)
        check(vm.wait_for("created successfully", 60, m), "admin account created at the console")
        m = vm.send("user add viewer viewer-password ro", 2)
        check(vm.wait_for("created successfully", 60, m), "read-only account created")

        st, _, body = login(tls, "webadmin", "s3cure-web-pass")
        check(st == 403 and b"not_admitted" in body, "login refused from a non-admitted device")

        vm.send("nas admit 10.0.2.2", 1)
        st, _, body = login(tls, "webadmin", "wrong-password")
        check(st == 401 and b"bad_credentials" in body, "wrong password rejected")
        st, _, body = login(tls, "nobody", "whatever-pass")
        check(st == 401 and b"bad_credentials" in body, "unknown user rejected with the same answer")
        st, _, body = login(tls, "viewer", "viewer-password")
        check(st == 403 and b"not_admin" in body, "non-admin account cannot log in")

        mark = len(vm.output())
        st, h, body = login(tls, "webadmin", "s3cure-web-pass")
        cookie = h.get("set-cookie", "")
        m = re.match(r"yesos_sid=([0-9a-f]{64});", cookie)
        check(st == 200 and m is not None, "admin logs in over HTTPS, session cookie set")
        check("Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie,
              "cookie is Secure, HttpOnly and SameSite=Strict")
        sid = m.group(1) if m else "0" * 64
        auth = {"Cookie": "yesos_sid=" + sid}
        check(sid not in vm.output() and "s3cure-web-pass" not in vm.since(mark),
              "token and password never printed on the console")
        st, _, _ = req(web, "GET", "/api/overview", headers=auth)
        check(st == 403, "a valid session cookie is useless over plain HTTP")

        st, _, body = req(tls, "GET", "/", headers=auth)
        check(st == 200 and b"/admin/app.js" in body, "admin panel served with a valid session")
        views = {}
        for s in SECTIONS:
            st, _, body = req(tls, "GET", "/api/" + s, headers=auth)
            try:
                views[s] = json.loads(body)
            except ValueError:
                views[s] = None
            if st != 200 or views[s] is None:
                break
        check(all(isinstance(views.get(s), dict) for s in SECTIONS), "every section returns valid JSON")
        ov = views.get("overview") or {}
        check(ov.get("pool", {}).get("mounted") and ov.get("pool", {}).get("total_bytes", 0) > 0,
              "overview shows the real RedSea pool")
        users = [u["name"] for u in (views.get("users") or {}).get("users", [])]
        check("webadmin" in users and "viewer" in users, f"users view lists the accounts ({users})")
        dev = (views.get("devices") or {}).get("devices", [])
        check(any(d["ip"] == "10.0.2.2" and d["status"] == "admitted" for d in dev), "devices view shows the admitted host")
        sec = views.get("security") or {}
        check(sec.get("transport_encrypted") is True and "TLS 1.3" in sec.get("transport", "") and "Z3" in sec.get("pmp", ""),
              "security view reports TLS 1.3 and the Z3-proven PMP")
        sess = views.get("session") or {}
        csrf = sess.get("csrf", "")
        check(sess.get("user") == "webadmin" and re.fullmatch(r"[0-9a-f]{64}", csrf or ""),
              "session view gives user and CSRF token")

        # --- write actions ---------------------------------------------------
        st, _ = action(tls, auth, None, "user_add", name="x1", password="password-123", role="rw")
        check(st == 403, "action without CSRF token refused")
        st, _, body = req(web, "POST", "/api/action/vault_lock", "", dict(auth, **FORM, **{"X-CSRF-Token": csrf}))
        check(st == 403 and b"https_required" in body, "actions over plain HTTP refused")
        st, r = action(tls, auth, csrf, "format_disk")
        check(st == 404, "unknown action rejected")
        st, r = action(tls, auth, csrf, "user_add", name="x" * 200, password="password-123", role="rw")
        check(st == 400, "over-long field rejected")

        st, r = action(tls, auth, csrf, "user_add", name="bad name", password="password-123", role="rw")
        check(st == 400, f"user name with a space rejected ({r.get('message')})")
        st, r = action(tls, auth, csrf, "user_add", name="carla", password="short", role="rw")
        check(st == 400, "short password rejected")
        st, r = action(tls, auth, csrf, "user_add", name="carla", password="carla-pass-1", role="superuser")
        check(st == 400, "unknown role rejected")
        st, r = action(tls, auth, csrf, "user_add", name="carla", password="carla-pass-1", role="rw")
        check(st == 200 and r.get("ok"), f"user created from the panel ({r.get('message')})")
        st, r = action(tls, auth, csrf, "user_add", name="carla", password="carla-pass-1", role="rw")
        check(st == 409, "duplicate user rejected")
        u = {x["name"]: x["role"] for x in view(tls, auth, "users").get("users", [])}
        check(u.get("carla") == "rw", f"new user listed with its role ({u})")

        st, r = action(tls, auth, csrf, "user_role", name="carla", role="admin")
        check(st == 200, "role changed to admin")
        tricky = "p@ss w&rd+1=%x"
        st, r = action(tls, auth, csrf, "user_password", name="carla", password=tricky)
        check(st == 200, "admin sets another user's password (special characters)")
        c_auth, c_csrf = session_of(tls, "carla", tricky)
        check(c_auth is not None, "that user logs in with the new password")
        st, r = action(tls, auth, csrf, "user_password", name="carla", password="carla-pass-2")
        st2, _, _ = req(tls, "GET", "/api/overview", headers=c_auth or {})
        check(st == 200 and st2 == 401, "changing a user's password closes that user's sessions")

        st, r = action(tls, auth, csrf, "user_role", name="webadmin", role="rw")
        check(st == 403, "admin cannot demote itself")
        st, r = action(tls, auth, csrf, "user_delete", name="webadmin")
        check(st == 403, "admin cannot delete itself")
        st, r = action(tls, auth, csrf, "user_password", name="webadmin", password="new-web-pass-9", current="not-it")
        check(st == 403, "own password change needs the current password")
        st, r = action(tls, auth, csrf, "user_password", name="webadmin", password="new-web-pass-9", current="s3cure-web-pass")
        st2, _, _ = req(tls, "GET", "/api/overview", headers=auth)
        check(st == 200 and st2 == 200, "own password changed; the current session stays open")

        c_auth, c_csrf = session_of(tls, "carla", "carla-pass-2")
        st, r = action(tls, auth, csrf, "user_role", name="carla", role="ro")
        st2, _, _ = req(tls, "GET", "/api/overview", headers=c_auth or {})
        check(st == 200 and st2 == 401, "demoting an admin closes its panel sessions")
        roles = lambda: {x["name"]: x["role"] for x in view(tls, auth, "users").get("users", [])}
        m = vm.send("user role carla admin", 2)
        check("Role of 'carla' set to ADMIN" in vm.since(m) and roles().get("carla") == "admin", "console: user role promotes to admin")
        c_auth, c_csrf = session_of(tls, "carla", "carla-pass-2")
        check(c_auth is not None, "promoted at the console: logs in to the panel")
        m = vm.send("user role carla ro", 2)
        st2, _, _ = req(tls, "GET", "/api/overview", headers=c_auth or {})
        check(roles().get("carla") == "ro" and st2 == 401, "console: demoting closes that user's panel sessions")
        others = [n for n, r in roles().items() if r == "admin" and n != "webadmin"]
        for n in others:   # the source disk may have its own admins: make webadmin the last one
            vm.send(f"user role {n} rw", 2)
        m = vm.send("user role webadmin rw", 2)
        st2, _, _ = req(tls, "GET", "/api/overview", headers=auth)
        check("at least one ADMIN" in vm.since(m) and roles().get("webadmin") == "admin" and st2 == 200,
              "console: the last admin cannot be demoted")
        for n in others:
            vm.send(f"user role {n} admin", 2)
        m = vm.send("user role carla superuser", 1)
        check("Uso: user role" in vm.since(m) and roles().get("carla") == "ro", "console: unknown role rejected")
        m = vm.send("user role nadie admin", 1)
        check("not found" in vm.since(m), "console: unknown user reported")
        st, r = action(tls, auth, csrf, "user_delete", name="carla")
        check(st == 200 and "carla" not in [x["name"] for x in view(tls, auth, "users").get("users", [])], "user deleted")
        st, r = action(tls, auth, csrf, "user_delete", name="carla")
        check(st == 404, "deleting a missing user reports 404")

        st, r = action(tls, auth, csrf, "auth_required", value="on")
        on = view(tls, auth, "shares").get("auth_required")
        st2, r = action(tls, auth, csrf, "auth_required", value="off")
        off = view(tls, auth, "shares").get("auth_required")
        check(st == 200 and on is True and st2 == 200 and off is False, "NAS protocol authentication toggled")

        st, r = action(tls, auth, csrf, "device_admit", ip="192.168.1.50", name="Portatil")
        devs = {d["ip"]: d for d in view(tls, auth, "devices").get("devices", [])}
        check(st == 200 and devs.get("192.168.1.50", {}).get("status") == "admitted"
              and devs["192.168.1.50"]["name"] == "Portatil", "device admitted from the panel")
        st, r = action(tls, auth, csrf, "device_block", ip="192.168.1.50")
        devs = {d["ip"]: d for d in view(tls, auth, "devices").get("devices", [])}
        check(st == 200 and devs.get("192.168.1.50", {}).get("status") == "blocked", "device blocked from the panel")
        st, r = action(tls, auth, csrf, "device_block", ip="10.0.2.2")
        check(st == 403, "admin cannot block the device it is using")
        for bad in ("8.8.8.8", "192.168.1.255", "abc", "10.0.0.1.5", "999.1.1.1"):
            st, r = action(tls, auth, csrf, "device_admit", ip=bad)
            if st != 400:
                break
        check(st == 400, f"public, broadcast and malformed IPs rejected (last: {bad})")

        for name, path, comment in (("fotos", "/share/../SYS", ""), ("fotos", "/SYS/x", ""), ("fotos", "relative", ""),
                                    ("mis fotos", "/share/fotos", ""), ("fotos", "/share/fotos", "a\n[evil]\npath = /SYS"),
                                    ("fotos", "/vault/x", "")):
            st, r = action(tls, auth, csrf, "share_add", name=name, path=path, comment=comment)
            if st != 400:
                break
        check(st == 400, f"unsafe share names, paths and comments rejected (last: {name} {path})")
        st, r = action(tls, auth, csrf, "share_add", name="fotos", path="/share/fotos", comment="Fotos de casa", readonly="on")
        sh = {x["name"]: x for x in view(tls, auth, "shares").get("shares", [])}
        check(st == 200 and sh.get("fotos", {}).get("readonly") is True and sh["fotos"]["path"] == "/share/fotos",
              "share created (read-only)")
        st, r = action(tls, auth, csrf, "share_add", name="fotos", path="/share/fotos2", comment="Editada", readonly="off")
        sh = {x["name"]: x for x in view(tls, auth, "shares").get("shares", [])}
        check(st == 200 and sh.get("fotos", {}).get("path") == "/share/fotos2" and sh["fotos"]["readonly"] is False,
              "share edited")
        st, r = action(tls, auth, csrf, "share_add", name="docs", path="/share/docs", comment="Persistente")
        st2, r = action(tls, auth, csrf, "share_delete", name="fotos")
        st3, r = action(tls, auth, csrf, "share_delete", name="fotos")
        check(st == 200 and st2 == 200 and st3 == 404, "share deleted (and a second delete reports 404)")

        vm.send("vault init", 1)
        vm.send(harness.PASS, 0.5)
        m = vm.send(harness.PASS, 0.5)
        check(vm.wait_for("Vault created and unlocked", 180, m), "vault created at the console")
        st, r = action(tls, auth, csrf, "vault_lock")
        v = view(tls, auth, "security").get("vault", {})
        check(st == 200 and v.get("initialized") and not v.get("unlocked"), "vault locked from the panel")

        log = view(tls, auth, "audit").get("entries", [])
        texts = " | ".join(e["text"] for e in log)
        check(len(log) >= 20 and any(not e["ok"] for e in log) and any(e["ok"] and "bloquear la b" in e["text"] for e in log),
              f"audit log records accepted and refused actions ({len(log)} entries)")
        check(tricky not in texts and "carla-pass" not in texts and "new-web-pass" not in texts, "no password in the audit log")
        out = vm.output()
        check("[WEBADMIN] OK   webadmin@10.0.2.2: crear usuario 'carla'" in out, "audit also printed on the console")
        check(tricky not in out and "carla-pass-2" not in out and "new-web-pass-9" not in out, "no password on the console")

        # Names with markup (possible from the console; WebDAV refuses < > ") and
        # with & (allowed over WebDAV) must come back escaped in JSON.
        vm.send("disk save share/<b>x</b>.txt hi", 2)
        dav_auth = {"Authorization": "Basic " + base64.b64encode(b"webadmin:new-web-pass-9").decode()}
        st, _, _ = req(tls, "PUT", "/dav/share/a%26b.txt", b"x", dav_auth)
        st2, _, body = req(tls, "GET", "/api/storage", headers=auth)
        check(st == 201 and st2 == 200, "files with & and markup in their names stored")
        check(b"<b>" not in body and b"\\u003cb\\u003ex\\u003c/b\\u003e" in body and b"a\\u0026b.txt" in body,
              "markup and & in file names are escaped in JSON")

        # WebDAV through TLS, with records in both directions larger than 16 KiB
        blob = os.urandom(1024 * 1024 + 123)
        st, _, _ = req(tls, "PUT", "/dav/share/tls-blob.bin", blob, dav_auth)
        st2, _, back = req(tls, "GET", "/dav/share/tls-blob.bin", headers=dav_auth)
        check(st == 201 and st2 == 200 and hashlib.sha256(back).digest() == hashlib.sha256(blob).digest(),
              "1 MiB WebDAV round trip over HTTPS is byte-identical")

        st, _, _ = req(tls, "GET", "/api/gateway", headers=auth)
        check(st == 404, "the NAS has no gateway: /api/gateway does not exist")
        st, _, _ = req(tls, "POST", "/api/logout", headers=auth)
        check(st == 403, "logout without CSRF token refused")
        st, _, _ = req(tls, "POST", "/api/logout", headers=dict(auth, **{"X-CSRF-Token": "0" * 64}))
        check(st == 403, "logout with a wrong CSRF token refused")
        st, _, _ = req(tls, "GET", "/api/overview", headers={"Cookie": "yesos_sid=" + "a" * 64})
        check(st == 401, "forged session token rejected")
        st, h, _ = req(tls, "POST", "/api/logout", headers=dict(auth, **{"X-CSRF-Token": csrf}))
        check(st == 200 and "Max-Age=0" in h.get("set-cookie", ""), "logout with CSRF token clears the cookie")
        st, _, _ = req(tls, "GET", "/api/overview", headers=auth)
        check(st == 401, "session no longer valid after logout")

        codes = [login(tls, "webadmin", "bad-password-%d" % i)[0] for i in range(5)]
        st, _, body = login(tls, "webadmin", "new-web-pass-9")
        check(codes == [401] * 5 and st == 429 and b"retry_sec" in body,
              f"5 failures throttle this IP ({codes}, then {st})")

        st, _, _ = req(web, "PUT", "/dav/share/web-ok.txt", b"x", dav_auth)
        check(st == 403, "WebDAV over plain HTTP refused (credentials never sent in clear)")
        m = vm.send("tls", 1)
        check(console_fingerprint(vm.since(m)) == fp_console, "`tls` console command shows the same fingerprint")
        out = vm.output()
        check("FATAL" not in out and "EXCEPTION" not in out, "no kernel faults")
    finally:
        vm.stop()

    # Second boot: the persisted key gives the same certificate.
    vm = WebYesOS(disk, udp, web, tls)
    try:
        check(vm.wait_for("YesOS [", 120) and wait_up(web), "second boot")
        out = vm.output()
        check("persisted self-signed" in out and console_fingerprint(out) == fp_console,
              "certificate (and fingerprint) persist across reboot")
        vm.send("nas admit 10.0.2.2", 1)
        auth2, _ = session_of(tls, "webadmin", "new-web-pass-9")
        check(auth2 is not None, "password changed in the panel persists across reboot")
        if auth2:
            names = [x["name"] for x in view(tls, auth2, "users").get("users", [])]
            shares = [x["name"] for x in view(tls, auth2, "shares").get("shares", [])]
            check("carla" not in names and "viewer" in names, "user changes persist across reboot")
            check("docs" in shares and "fotos" not in shares, "share changes persist across reboot (SYS/SMB.CFG)")
        _, _, cert_der = tls_handshake(tls)
        check(hashlib.sha256(cert_der).hexdigest() == fp_console, "served certificate unchanged after reboot")
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
