#!/usr/bin/env python3
"""
Makes docs/panel.png, the picture at the top of the README: YesOS NAS booted
in QEMU with HTTPS forwarded, a few accounts, shared folders, files and a
snapshot made from the console, then a real Firefox (headless, driven
through its Marionette protocol) logs in to the web panel as an admin from
an admitted device and takes a screenshot of the Overview page. Nothing is
drawn by this script: the picture is the browser's.
Usage: python3 tools/screenshot.py [output.png] [page]     (page: overview, users, ...)
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "core", "tools"))
import yesos_harness as harness  # noqa: E402
import test_webadmin as tw  # noqa: E402

ADMIN, PASSWORD = "admin", "panel-screenshot-pass"


class Marionette:
    """The few Marionette (WebDriver over TCP) commands needed here."""

    def __init__(self, port):
        for _ in range(100):
            try:
                self.s = socket.create_connection(("127.0.0.1", port), timeout=30)
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise SystemExit("Firefox's Marionette port did not open")
        self.buf = b""
        self.n = 0
        self._read()                                        # the server's hello

    def _read(self):
        while b":" not in self.buf:
            self.buf += self.s.recv(65536)
        size, rest = self.buf.split(b":", 1)
        size = int(size)
        while len(rest) < size:
            rest += self.s.recv(65536)
        self.buf = rest[size:]
        return json.loads(rest[:size])

    def cmd(self, command, **params):
        self.n += 1
        data = json.dumps([0, self.n, command, params]).encode()
        self.s.sendall(str(len(data)).encode() + b":" + data)
        while True:
            msg = self._read()
            if msg[0] == 1 and msg[1] == self.n:
                if msg[2]:
                    raise RuntimeError(f"{command}: {msg[2]}")
                return msg[3]

    def element(self, css):
        r = self.cmd("WebDriver:FindElement", using="css selector", value=css)
        return list(r["value"].values())[0]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(HERE), "docs", "panel.png")
    page = sys.argv[2] if len(sys.argv) > 2 else "overview"
    tmp = tempfile.mkdtemp(prefix="yesos_panel_")
    # A disk made the way `make run` makes it (the local yesos_disk.img may
    # hold accounts from earlier sessions; a fresh one has none).
    disk = os.path.join(tmp, "disk.img")
    import redsea_injector
    with open(os.devnull, "w") as quiet:
        old, sys.stdout = sys.stdout, quiet
        try:
            ok = redsea_injector.sync_curated(disk)
        finally:
            sys.stdout = old
    if not ok:
        raise SystemExit("could not make a fresh disk")
    web, tls, mport = tw.free_ports(3)
    vm = tw.WebYesOS(disk, 40000 + os.getpid() % 20000, web, tls)
    fox = None
    try:
        if not vm.wait_for("YesOS [", 120):
            raise SystemExit("no boot")
        for c in [f"user add {ADMIN} {PASSWORD} admin", "user add carla carla-password rw",
                  "user add guest guest-password ro", "mkdir /media", "mkdir /docs",
                  "write /docs/notes.txt Shopping list and other notes",
                  "write /media/readme.txt Photos and music go here",
                  "share add media /media rw Photos and music", "share add docs /docs ro Documents",
                  "snapshot create before the holidays", "nas admit 10.0.2.2"]:
            vm.send(c, 2)
        prof = os.path.join(tmp, "profile")
        os.makedirs(prof)
        with open(os.path.join(prof, "user.js"), "w") as f:
            f.write(f'user_pref("marionette.port", {mport});\n'
                    'user_pref("browser.shell.checkDefaultBrowser", false);\n'
                    'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
        fox = subprocess.Popen(["firefox", "--headless", "--marionette", "--no-remote", "--profile", prof],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        m = Marionette(mport)
        # The NAS's certificate is self-signed (its fingerprint is printed on the console).
        r = m.cmd("WebDriver:NewSession", acceptInsecureCerts=True,
                  capabilities={"alwaysMatch": {"acceptInsecureCerts": True}})
        print("session: acceptInsecureCerts =", r.get("capabilities", {}).get("acceptInsecureCerts"))
        m.cmd("WebDriver:SetWindowRect", width=1280, height=860)
        m.cmd("WebDriver:Navigate", url=f"https://127.0.0.1:{tls}/login")
        m.cmd("WebDriver:ElementSendKeys", id=m.element("#user"), text=ADMIN)
        m.cmd("WebDriver:ElementSendKeys", id=m.element("#pass"), text=PASSWORD)
        m.cmd("WebDriver:ElementClick", id=m.element("#submit"))
        # Argon2id under QEMU takes a while: wait until the panel replaces the login page.
        for _ in range(120):
            time.sleep(0.5)
            if "/login" not in m.cmd("WebDriver:GetCurrentURL")["value"]:
                break
        else:
            print([l for l in vm.output().splitlines() if "NAS AUTH" in l][-3:])
            raise SystemExit("the login did not go through")
        m.cmd("WebDriver:Navigate", url=f"https://127.0.0.1:{tls}/#/{page}")
        time.sleep(4)
        png = base64.b64decode(m.cmd("WebDriver:TakeScreenshot", full=False)["value"])
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "wb") as f:
            f.write(png)
        print(f"{out}: {len(png)} bytes")
        m.cmd("WebDriver:DeleteSession")
    finally:
        if fox:
            fox.kill()
            fox.wait()
        vm.stop()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
