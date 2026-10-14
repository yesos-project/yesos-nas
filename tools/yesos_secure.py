#!/usr/bin/env python3
"""
YesOS 2.0 - Secure NAS channel client (Noise_NK_25519_ChaChaPoly_BLAKE2s).

The appliance's static public key must be pinned before connecting: run
`nas key` on the YesOS console and store it with

    python3 tools/nas_client.py --host <ip> trust <64-hex-key>

Wire format: see kernel/nas_secure.c. Requires the `cryptography` package.
"""

import hashlib
import hmac
import os
import socket
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

PROTOCOL_NAME = b"Noise_NK_25519_ChaChaPoly_BLAKE2s"
PROLOGUE = b"YesOS-NAS-v1"
HS_MAGIC = 0x5945534E
DATA_MAGIC = 0x59455345
ERR_MAGIC = 0x59455358
VERSION = 1
HASHLEN = 32

KNOWN_HOSTS = os.path.join(os.path.expanduser("~"), ".config", "yesos", "known_hosts")


class SecureChannelError(Exception):
    pass


# -----------------------------------------------------------------------------
# Key pinning
# -----------------------------------------------------------------------------

def _host_id(host, port):
    return f"{host}:{port}"


def load_pinned_key(host, port, path=KNOWN_HOSTS):
    try:
        with open(path, encoding="ascii") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2 and parts[0] == _host_id(host, port):
                    return bytes.fromhex(parts[1])
    except FileNotFoundError:
        pass
    return None


def pin_key(host, port, hexkey, path=KNOWN_HOSTS):
    key = bytes.fromhex(hexkey.strip())
    if len(key) != 32:
        raise ValueError("server key must be 32 bytes (64 hex characters)")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    lines = []
    try:
        with open(path, encoding="ascii") as f:
            lines = [l for l in f if l.split()[:1] != [_host_id(host, port)]]
    except FileNotFoundError:
        pass
    lines.append(f"{_host_id(host, port)} {key.hex()}\n")
    with open(path, "w", encoding="ascii") as f:
        f.writelines(lines)
    os.chmod(path, 0o600)


# -----------------------------------------------------------------------------
# Noise primitives (spec revision 34, sections 4-5)
# -----------------------------------------------------------------------------

def _hash(data):
    return hashlib.blake2s(data).digest()


def _hmac(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def _hkdf2(ck, ikm):
    temp = _hmac(ck, ikm)
    out1 = _hmac(temp, b"\x01")
    out2 = _hmac(temp, out1 + b"\x02")
    return out1, out2


def _nonce(n):
    return b"\x00" * 4 + struct.pack("<Q", n)


def _pub_bytes(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class _SymmetricState:
    def __init__(self):
        self.h = PROTOCOL_NAME.ljust(HASHLEN, b"\x00") if len(PROTOCOL_NAME) <= HASHLEN else _hash(PROTOCOL_NAME)
        self.ck = self.h
        self.k = None
        self.n = 0

    def mix_hash(self, data):
        self.h = _hash(self.h + data)

    def mix_key(self, ikm):
        self.ck, self.k = _hkdf2(self.ck, ikm)
        self.n = 0

    def encrypt_and_hash(self, pt):
        ct = ChaCha20Poly1305(self.k).encrypt(_nonce(self.n), pt, self.h) if self.k else pt
        if self.k:
            self.n += 1
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct):
        pt = ChaCha20Poly1305(self.k).decrypt(_nonce(self.n), ct, self.h) if self.k else ct
        if self.k:
            self.n += 1
        self.mix_hash(ct)
        return pt

    def split(self):
        return _hkdf2(self.ck, b"")


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------

class SecureNasClient:
    def __init__(self, host, port, server_key, timeout=5.0):
        if len(server_key) != 32:
            raise SecureChannelError("server key must be 32 bytes")
        self.host, self.port = host, port
        self.server_key = server_key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.session_id = None
        self.tx = self.rx = None
        self.nonce = 0

    def close(self):
        self.sock.close()

    def _roundtrip(self, pkt):
        self.sock.sendto(pkt, (self.host, self.port))
        data, _ = self.sock.recvfrom(2048)
        if len(data) >= 8 and struct.unpack_from("<I", data)[0] == ERR_MAGIC:
            code = struct.unpack_from("<i", data, 4)[0]
            raise SecureChannelError(f"{data[8:].decode(errors='replace')} (code {code})")
        return data

    def handshake(self):
        ss = _SymmetricState()
        ss.mix_hash(PROLOGUE)
        ss.mix_hash(self.server_key)                    # pre-message: <- s

        e = X25519PrivateKey.generate()
        e_pub = _pub_bytes(e.public_key())
        ss.mix_hash(e_pub)                              # -> e
        ss.mix_key(e.exchange(X25519PublicKey.from_public_bytes(self.server_key)))  # es
        msg1 = e_pub + ss.encrypt_and_hash(b"")

        data = self._roundtrip(struct.pack("<IB3x", HS_MAGIC, VERSION) + msg1)
        if len(data) != 8 + 8 + 48 or struct.unpack_from("<I", data)[0] != HS_MAGIC:
            raise SecureChannelError("malformed handshake response")
        session_id = struct.unpack_from("<Q", data, 8)[0]
        msg2 = data[16:]

        re_pub = msg2[:32]
        ss.mix_hash(re_pub)                             # <- e
        ss.mix_key(e.exchange(X25519PublicKey.from_public_bytes(re_pub)))  # ee
        try:
            ss.decrypt_and_hash(msg2[32:])
        except Exception as exc:
            raise SecureChannelError("server failed authentication (wrong pinned key?)") from exc

        k1, k2 = ss.split()
        self.tx, self.rx = ChaCha20Poly1305(k1), ChaCha20Poly1305(k2)
        self.session_id = session_id
        self.nonce = 0

    def request(self, cmd_type, payload=b""):
        """Sends one NAS command; returns (status, response_bytes). status 0 = OK."""
        if self.session_id is None:
            self.handshake()
        if len(payload) > 512:
            raise ValueError("payload too large (max 512 bytes)")
        nonce = self.nonce
        self.nonce += 1
        inner = struct.pack("<HH", cmd_type, len(payload)) + payload
        ct = self.tx.encrypt(_nonce(nonce), inner, b"")
        data = self._roundtrip(struct.pack("<IQQ", DATA_MAGIC, self.session_id, nonce) + ct)
        magic, sid, rnonce = struct.unpack_from("<IQQ", data)
        if magic != DATA_MAGIC or sid != self.session_id or rnonce != nonce:
            raise SecureChannelError("unexpected response header")
        try:
            pt = self.rx.decrypt(_nonce(rnonce), data[20:], b"")
        except Exception as exc:
            raise SecureChannelError("response failed authentication") from exc
        status, dlen = struct.unpack_from("<HH", pt)
        return status, pt[4:4 + dlen]
