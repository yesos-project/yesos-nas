#!/usr/bin/env python3
"""
End-to-end test for the encrypted /vault, Argon2id accounts and remote
command hardening. Boots YesOS headless in QEMU over the serial console,
twice on the same scratch disk (to check persistence across reboots).

Usage: python3 tools/test_vault_crypto.py [--keep-disk]
Exit status is non-zero on any failed check.
"""
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
from yesos_secure import SecureNasClient, SecureChannelError  # noqa: E402

from yesos_harness import ROOT, KERNEL, SRC_DISK, PASS, SECRET, NAS_PORT, YesOS  # noqa: E402,F401

failures = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def server_key(output):
    m = re.search(r"Server public key.*?\n.*?([0-9a-f]{64})", output)
    return m.group(1) if m else None


def nas_cmd(host_port, cmd_type, payload=b""):
    pkt = struct.pack("<IHHI256s", 0x59455343, 1, cmd_type, len(payload), payload)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(pkt, ("127.0.0.1", host_port))
        data, _ = s.recvfrom(2048)
        _, _, status, rlen = struct.unpack("<IHHI", data[:12])
        return status, data[12:12 + rlen]
    except socket.timeout:
        return None, b""
    finally:
        s.close()


def main():
    keep = "--keep-disk" in sys.argv
    tmpdir = tempfile.mkdtemp(prefix="yesos_vault_")
    disk = os.path.join(tmpdir, "disk.img")
    shutil.copyfile(SRC_DISK, disk)
    host_port = 40000 + os.getpid() % 20000

    boot1_key = None
    print("== Boot 1: fresh disk ==")
    vm = YesOS(disk, host_port)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots to shell prompt")
        out = vm.output()
        check("Zkr hardware entropy source: OK" in out, "Zkr entropy source detected")
        check("DRBG seeded" in out, "DRBG seeded at boot")
        check("admin123" not in out and "123456" not in out, "no default credentials announced")
        boot1_key = server_key(out)
        m0 = re.search(r"Loaded (\d+) user account", out)
        users_before = int(m0.group(1)) if m0 else 0   # accounts already on the source disk
        check(boot1_key is not None, "server public key shown at boot")

        m = vm.send("write /vault/SECRET.TXT " + SECRET, 2)
        check("vault not initialized" in vm.since(m) or "failed" in vm.since(m),
              "write to /vault refused before init")

        m = vm.send("vault init", 1)
        check("New vault passphrase" in vm.since(m), "vault init prompts for passphrase")
        m = vm.send(PASS, 0.5)
        check(PASS not in vm.since(m), "passphrase not echoed")
        m = vm.send(PASS, 0.5)
        check(vm.wait_for("Vault created and unlocked", 60, m), "vault created")

        m = vm.send("write /vault/SECRET.TXT " + SECRET, 2)
        check("write:" in vm.since(m) and "bytes" in vm.since(m), "encrypted write accepted")
        m = vm.send("keyhart test", 4)
        res = vm.since(m)
        check("KEY NOT REACHABLE OUTSIDE THE KEY HART" in res and "round trip" in res and "[FAIL]" not in res,
              "key hart: DEK unreadable from hart 0, seal/open round trip works")
        m = vm.send("cat /vault/SECRET.TXT", 2)
        check(SECRET in vm.since(m), "cat returns plaintext while unlocked")

        m = vm.send("disk cat vault/SECRET.TXT", 2)
        check(SECRET not in vm.since(m), "raw on-disk bytes are not plaintext")

        m = vm.send("disk save vault/PLAIN.TXT not-encrypted", 2)
        check("Refused plaintext write" in vm.since(m), "plaintext write under vault/ refused by RedSea")

        st, resp = nas_cmd(host_port, 0x01, b"help")
        check(st == 1 and b"DISABLED" in resp, "remote shell exec rejected in default build")
        st, resp = nas_cmd(host_port, 0x02, b"U0 x;")
        check(st == 1 and b"DISABLED" in resp, "remote HolyQ eval rejected in default build")

        m = vm.send("vault lock", 1)
        m = vm.send("cat /vault/SECRET.TXT", 2)
        check(SECRET not in vm.since(m) and "locked" in vm.since(m), "cat refused after lock")

        m = vm.send("user add alice short admin", 2)
        check("at least 8" in vm.since(m), "short NAS password rejected")
        m = vm.send("user add alice s3cure-passw0rd admin", 2)
        check(vm.wait_for("created successfully", 30, m), "NAS admin created with Argon2id")

        m = vm.send("lock", 1)
        check("no Master PIN configured" in vm.since(m), "console lock requires a configured PIN")
        m = vm.send("pin set 482915", 1)
        check(vm.wait_for("Master PIN successfully updated", 30, m), "PIN set")
        check("482915" not in vm.since(m).replace("pin set 482915", ""), "new PIN not echoed in confirmation")
        time.sleep(1)
    finally:
        vm.stop()

    with open(disk, "rb") as f:
        raw = f.read()
    check(SECRET.encode() not in raw, "secret absent from the raw disk image")
    check(PASS.encode() not in raw, "passphrase absent from the raw disk image")

    print("== Boot 2: same disk ==")
    vm = YesOS(disk, host_port)
    try:
        check(vm.wait_for("YesOS [", 90), "second boot reaches shell")
        out = vm.output()
        check("persisted seed" in out, "persisted RNG seed mixed in")
        check("initialized, LOCKED" in out, "vault header found, starts locked")
        check(f"Loaded {users_before + 1} user account" in out, "NAS account persisted")

        m = vm.send("cat /vault/SECRET.TXT", 2)
        check(SECRET not in vm.since(m), "locked after reboot")

        vm.send("vault unlock", 1)
        m = vm.send("wrong passphrase!", 0.5)
        check(vm.wait_for("wrong passphrase", 60, m), "wrong passphrase rejected")
        vm.send("vault unlock", 1)
        m = vm.send(PASS, 0.5)
        check(vm.wait_for("Vault unlocked", 60, m), "correct passphrase unlocks")
        m = vm.send("cat /vault/SECRET.TXT", 2)
        check(SECRET in vm.since(m), "plaintext readable after unlock on second boot")

        key_hex = server_key(vm.output())
        check(key_hex is not None and key_hex == boot1_key, "server static key persisted across reboot")
        key = bytes.fromhex(key_hex or "00" * 32)

        st, resp = nas_cmd(host_port, 0x26, b"alice:s3cure-passw0rd")
        check(st == 1 and b"SECURE CHANNEL REQUIRED" in resp, "plaintext AUTH refused (no passwords in clear)")
        st, resp = nas_cmd(host_port, 0x20)
        check(st == 1 and b"NOT ADMITTED" in resp, "no pre-admitted hosts (10.0.2.2 must be approved)")

        c = SecureNasClient("127.0.0.1", host_port, key)
        try:
            c.handshake()
            check(False, "handshake from non-admitted host refused")
        except SecureChannelError as e:
            check("NOT ADMITTED" in str(e), "handshake from non-admitted host refused")

        m = vm.send("user add bob readonly-pass ro", 2)
        check(vm.wait_for("created successfully", 30, m), "read-only NAS user created")
        vm.send("nas admit 10.0.2.2", 1)
        st, resp = nas_cmd(host_port, 0x20)
        check(st == 0 and b"NAS_OK" in resp, "plaintext NAS_INFO answered after admission")

        bad = SecureNasClient("127.0.0.1", host_port, bytes(32 - 1) + b"\x09")
        try:
            bad.handshake()
            check(False, "handshake with wrong pinned key fails")
        except SecureChannelError:
            check(True, "handshake with wrong pinned key fails")

        c = SecureNasClient("127.0.0.1", host_port, key)
        c.handshake()
        check(c.session_id is not None, "Noise NK handshake with pinned key")
        st, resp = c.request(0x22, b"/README.DD")
        check(st == 1 and b"AUTH REQUIRED" in resp, "secure session without login is unauthenticated")
        st, resp = c.request(0x26, b"alice:wrong-password")
        check(st == 1, "remote AUTH with wrong password fails")
        st, resp = c.request(0x26, b"alice:s3cure-passw0rd")
        check(st == 0 and b"AUTH_OK" in resp, f"remote AUTH as admin over Noise (resp={resp[:60]!r})")
        st, resp = c.request(0x22, b"/SYS/USERS.CFG")
        check(st == 1 and b"SYSTEM AREA" in resp, "admin cannot read /SYS remotely")
        st, resp = c.request(0x22, b"USERS.CFG")
        check(st == 1, "no fallback lookup to SYS/USERS.CFG via bare name")
        st, resp = c.request(0x22, b"/vault/SECRET.TXT")
        check(st == 0 and SECRET.encode() in resp, "authenticated admin reads unlocked vault")

        # Replay: resend a captured, valid datagram
        sent = []
        orig = c._roundtrip
        c._roundtrip = lambda pkt: (sent.append(pkt), orig(pkt))[1]
        c.request(0x20)
        c._roundtrip = orig
        try:
            c._roundtrip(sent[0])
            check(False, "replayed datagram rejected")
        except SecureChannelError as e:
            check("REPLAYED" in str(e), "replayed datagram rejected")

        # Tampering: flip one ciphertext bit with a fresh nonce
        pkt = bytearray(sent[0])
        pkt[12:20] = (c.nonce + 100).to_bytes(8, "little")
        pkt[-1] ^= 1
        try:
            c._roundtrip(bytes(pkt))
            check(False, "tampered datagram rejected")
        except SecureChannelError as e:
            check("DECRYPTION FAILED" in str(e), "tampered datagram rejected")

        # A second session does not inherit the first one's login
        c2 = SecureNasClient("127.0.0.1", host_port, key)
        st, resp = c2.request(0x22, b"/vault/SECRET.TXT")
        check(st == 1 and b"AUTH REQUIRED" in resp, "login is bound to the session, not the IP")
        st, resp = c2.request(0x26, b"bob:readonly-pass")
        check(st == 0 and b"AUTH_OK" in resp, "remote AUTH as read-only user")
        st, resp = c2.request(0x22, b"/vault/SECRET.TXT")
        check(st == 1 and b"VAULT REQUIRES" in resp, "read-only user cannot read vault")
        c.close()
        c2.close()
    finally:
        vm.stop()

    if keep:
        print("disk kept at", disk)
    else:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
