#!/usr/bin/env python3
"""
YesOS NAS replication: copies the NAS snapshots to another machine (pull over
HTTPS), keeps them encrypted at rest, verifies them, and restores them into a
NAS (for example a new one after losing the disk).

  yesos_replicate.py init    REPO [--plain]
  yesos_replicate.py pull    REPO --host H [--port 8443] --user U --fingerprint SHA256
  yesos_replicate.py list    REPO
  yesos_replicate.py verify  REPO
  yesos_replicate.py restore REPO --snap ID --host H --user U --fingerprint SHA256 [--from NAS_ID]

Passwords: YESOS_PASSWORD (NAS account, admin role) and YESOS_BACKUP_PASSPHRASE
(the repository), or asked for interactively. The machine running this must
be admitted on the NAS (console: nas admit <ip>).

Repository layout (everything below objects/ and snapshots/ is encrypted
unless the repository was created with --plain):
  repo.json                     format, KDF salt/params, key check value
  objects/ab/<id>               file contents; id = HMAC(key, SHA-256(data))
  snapshots/<nas>/<id>.json     manifest of one snapshot (written last)
  index/<nas>.json              (extent, size, CRC) -> object, for incremental pulls
The NAS is identified by the first 16 hex digits of its TLS certificate
fingerprint. Every downloaded file is checked against the CRC the NAS stores.
"""
import argparse
import getpass
import hashlib
import hmac
import http.client
import json
import os
import ssl
import sys
import time
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
from redsea_fsck import kernel_crc64  # noqa: E402

FORMAT = 1


class ReplicaError(Exception):
    pass


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class Repo:
    def __init__(self, path, passphrase=None):
        self.path = path
        cfg_path = os.path.join(path, "repo.json")
        if not os.path.exists(cfg_path):
            raise ReplicaError(f"{path} is not a repository (run init)")
        with open(cfg_path) as f:
            self.cfg = json.load(f)
        if self.cfg.get("format") != FORMAT:
            raise ReplicaError("unsupported repository format")
        self.encrypted = self.cfg["encrypted"]
        if self.encrypted:
            if passphrase is None:
                passphrase = os.environ.get("YESOS_BACKUP_PASSPHRASE") or getpass.getpass("Backup passphrase: ")
            k = self.cfg["kdf"]
            master = Scrypt(salt=bytes.fromhex(k["salt"]), length=32, n=k["n"], r=k["r"], p=k["p"]).derive(passphrase.encode())
            self.enc_key = hmac.new(master, b"yesos-replica-enc", hashlib.sha256).digest()
            self.id_key = hmac.new(master, b"yesos-replica-id", hashlib.sha256).digest()
            check = hmac.new(master, b"yesos-replica-check", hashlib.sha256).hexdigest()
            if not hmac.compare_digest(check, self.cfg["check"]):
                raise ReplicaError("wrong backup passphrase")
            self.aead = ChaCha20Poly1305(self.enc_key)

    @staticmethod
    def create(path, passphrase, plain=False):
        os.makedirs(os.path.join(path, "objects"), exist_ok=True)
        os.makedirs(os.path.join(path, "snapshots"), exist_ok=True)
        os.makedirs(os.path.join(path, "index"), exist_ok=True)
        cfg = {"format": FORMAT, "encrypted": not plain}
        if not plain:
            salt = os.urandom(16)
            kdf = {"name": "scrypt", "n": 2 ** 15, "r": 8, "p": 1, "salt": salt.hex()}
            master = Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(passphrase.encode())
            cfg["kdf"] = kdf
            cfg["check"] = hmac.new(master, b"yesos-replica-check", hashlib.sha256).hexdigest()
        _atomic_write(os.path.join(path, "repo.json"), json.dumps(cfg, indent=1).encode())

    # -- sealed blobs ------------------------------------------------------
    def _seal(self, data, label):
        if not self.encrypted:
            return data
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, data, label.encode())

    def _open(self, blob, label):
        if not self.encrypted:
            return blob
        try:
            return self.aead.decrypt(blob[:12], blob[12:], label.encode())
        except Exception:
            raise ReplicaError(f"{label}: authentication failed (corrupted or tampered)")

    # -- objects -----------------------------------------------------------
    def object_id(self, data):
        digest = hashlib.sha256(data).digest()
        if self.encrypted:
            return hmac.new(self.id_key, digest, hashlib.sha256).hexdigest()
        return digest.hex()

    def _object_path(self, oid):
        return os.path.join(self.path, "objects", oid[:2], oid)

    def has_object(self, oid):
        return os.path.exists(self._object_path(oid))

    def put_object(self, data):
        oid = self.object_id(data)
        p = self._object_path(oid)
        if not os.path.exists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            _atomic_write(p, self._seal(data, "object:" + oid))
        return oid

    def get_object(self, oid):
        with open(self._object_path(oid), "rb") as f:
            data = self._open(f.read(), "object:" + oid)
        if self.object_id(data) != oid:
            raise ReplicaError(f"object {oid[:12]}: content does not match its id")
        return data

    # -- json documents ----------------------------------------------------
    def put_json(self, rel, obj):
        p = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        _atomic_write(p, self._seal(json.dumps(obj, indent=1).encode(), rel))

    def get_json(self, rel, default=None):
        p = os.path.join(self.path, rel)
        if not os.path.exists(p):
            return default
        with open(p, "rb") as f:
            return json.loads(self._open(f.read(), rel))

    def snapshots(self):
        out = []
        base = os.path.join(self.path, "snapshots")
        for nas in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            for name in sorted(os.listdir(os.path.join(base, nas))):
                if name.endswith(".json"):
                    out.append((nas, int(name[:-5])))
        return out


def _atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# NAS connection (HTTPS with a pinned certificate fingerprint)
# ---------------------------------------------------------------------------

class Nas:
    def __init__(self, host, port, fingerprint, user, password):
        self.host, self.port = host, port
        self.pin = fingerprint.replace(":", "").lower()
        if len(self.pin) != 64:
            raise ReplicaError("the fingerprint must be the 64-hex SHA-256 shown by the console command `tls`")
        self.cookie = None
        self.csrf = None
        st, _, body = self.request("POST", "/api/login", urlencode({"user": user, "pass": password}).encode(),
                                   {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)
        if st != 200:
            reason = json.loads(body or b"{}").get("error", st)
            raise ReplicaError(f"login refused: {reason}" +
                               (" (admit this machine on the NAS console: nas admit <ip>)" if reason == "not_admitted" else ""))
        st, _, body = self.request("GET", "/api/session")
        self.csrf = json.loads(body)["csrf"]
        self.nas_id = self.pin[:16]

    def request(self, method, path, body=None, headers=None, auth=True, timeout=120):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # self-signed: verified by fingerprint below
        c = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=ctx)
        c.connect()
        fp = hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(fp, self.pin):
            c.close()
            raise ReplicaError(f"certificate fingerprint mismatch: the NAS presented {fp}")
        h = dict(headers or {})
        if auth and self.cookie:
            h["Cookie"] = self.cookie
        if method == "POST" and self.csrf:
            h["X-CSRF-Token"] = self.csrf
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader("Set-Cookie")
        if sc and sc.startswith("yesos_sid=") and "Max-Age=0" not in sc:
            self.cookie = sc.split(";")[0]
        c.close()
        return r.status, dict(r.getheaders()), data

    def action(self, act, **fields):
        st, _, body = self.request("POST", "/api/action/" + act, urlencode(fields).encode(),
                                   {"Content-Type": "application/x-www-form-urlencoded"})
        return st, json.loads(body or b"{}")

    def view(self, section):
        st, _, body = self.request("GET", "/api/" + section)
        if st != 200:
            raise ReplicaError(f"/api/{section}: HTTP {st}")
        return json.loads(body)


def _secret(env, prompt):
    return os.environ.get(env) or getpass.getpass(prompt)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(a):
    if os.path.exists(os.path.join(a.repo, "repo.json")):
        raise ReplicaError(f"{a.repo} already exists")
    pw = None
    if not a.plain:
        pw = _secret("YESOS_BACKUP_PASSPHRASE", "New backup passphrase: ")
        if not os.environ.get("YESOS_BACKUP_PASSPHRASE") and getpass.getpass("Repeat it: ") != pw:
            raise ReplicaError("passphrases differ")
        if len(pw) < 10:
            raise ReplicaError("use at least 10 characters")
    Repo.create(a.repo, pw, a.plain)
    print(f"Repository created at {a.repo} ({'plain' if a.plain else 'encrypted: ChaCha20-Poly1305, scrypt'})")


def cmd_pull(a):
    repo = Repo(a.repo)
    nas = Nas(a.host, a.port, a.fingerprint, a.user, _secret("YESOS_PASSWORD", f"NAS password for {a.user}: "))
    have = {sid for n, sid in repo.snapshots() if n == nas.nas_id}
    index = repo.get_json(f"index/{nas.nas_id}.json", {})
    snaps = nas.view("snapshots")["snapshots"]
    stats = {"snapshots": 0, "files": 0, "downloaded": 0, "bytes": 0, "reused": 0}
    for s in sorted(snaps, key=lambda x: x["id"]):
        if s["id"] in have:
            continue
        nas.action("export_begin", name=str(s["id"]))
        files = []
        for f in s["files"]:
            key = f"{f['lba']}:{f['bytes']}:{f['crc']}"
            oid = index.get(key)
            if oid and repo.has_object(oid):
                stats["reused"] += 1
            else:
                st, _, data = nas.request("GET", "/api/export/file?" + urlencode({"snap": s["id"], "path": f["path"]}))
                if st != 200:
                    raise ReplicaError(f"snapshot {s['id']} {f['path']}: HTTP {st}")
                if len(data) != f["bytes"] or (kernel_crc64(data) & 0xFFFFFFFF if data else 0) != f["crc"]:
                    raise ReplicaError(f"snapshot {s['id']} {f['path']}: size/CRC mismatch after download")
                oid = repo.put_object(data)
                index[key] = oid
                stats["downloaded"] += 1
                stats["bytes"] += len(data)
            files.append({"path": f["path"], "bytes": f["bytes"], "crc": f["crc"], "encrypted": f["encrypted"], "object": oid})
            stats["files"] += 1
        vault_header = None
        if any(f["encrypted"] for f in files):
            st, _, data = nas.request("GET", "/api/export/vault-header")
            if st == 200:
                vault_header = repo.put_object(data)
        manifest = {"nas": nas.nas_id, "fingerprint": nas.pin, "id": s["id"], "automatic": s["automatic"],
                    "created_by": s["created_by"], "client_time": s["client_time"], "note": s["note"],
                    "files": files, "vault_header": vault_header, "pulled_at": int(time.time())}
        repo.put_json(f"index/{nas.nas_id}.json", index)       # objects first, then the index ...
        repo.put_json(f"snapshots/{nas.nas_id}/{s['id']}.json", manifest)   # ... then the manifest
        stats["snapshots"] += 1
    print(f"Pulled {stats['snapshots']} new snapshot(s) from NAS {nas.nas_id}: {stats['files']} files, "
          f"{stats['downloaded']} downloaded ({stats['bytes']} bytes), {stats['reused']} unchanged (not downloaded again)")
    return stats


def cmd_list(a):
    repo = Repo(a.repo)
    for nas, sid in repo.snapshots():
        m = repo.get_json(f"snapshots/{nas}/{sid}.json")
        size = sum(f["bytes"] for f in m["files"])
        print(f"NAS {nas}  snapshot {sid:4d}  {len(m['files']):5d} files  {size:12d} bytes  "
              f"{'auto ' if m['automatic'] else ''}{m['created_by']} {m['client_time']} {m['note']}"
              f"{'  +vault header' if m['vault_header'] else ''}")


def cmd_verify(a):
    repo = Repo(a.repo)
    problems, checked, seen = [], 0, set()
    for nas, sid in repo.snapshots():
        m = repo.get_json(f"snapshots/{nas}/{sid}.json")
        refs = [(f["object"], f) for f in m["files"]] + ([(m["vault_header"], None)] if m["vault_header"] else [])
        for oid, f in refs:
            if oid in seen:
                continue
            seen.add(oid)
            try:
                data = repo.get_object(oid)
                if f and ((kernel_crc64(data) & 0xFFFFFFFF if data else 0) != f["crc"] or len(data) != f["bytes"]):
                    problems.append(f"snapshot {sid} {f['path']}: CRC/size mismatch")
                checked += 1
            except (ReplicaError, OSError) as e:
                problems.append(f"snapshot {sid} {f['path'] if f else 'vault header'}: {e}")
    for p in problems:
        print("  ERROR:", p)
    print(f"{'OK' if not problems else 'PROBLEMS FOUND'}: {checked} objects verified, {len(problems)} problem(s)")
    return not problems


def cmd_restore(a):
    repo = Repo(a.repo)
    cands = [(n, s) for n, s in repo.snapshots() if s == a.snap and (not a.source or n.startswith(a.source))]
    if len(cands) != 1:
        raise ReplicaError(f"snapshot {a.snap}: {'not found' if not cands else 'several NAS have it, use --from'}")
    m = repo.get_json(f"snapshots/{cands[0][0]}/{a.snap}.json")
    nas = Nas(a.host, a.port, a.fingerprint, a.user, _secret("YESOS_PASSWORD", f"NAS password for {a.user}: "))
    nas.action("import_begin", name=str(len(m["files"])))
    vault_ok = False
    if any(f["encrypted"] for f in m["files"]) and m["vault_header"]:
        header = repo.get_object(m["vault_header"])
        st, _, body = nas.request("POST", "/api/import/vault-header", header)
        if st == 200:
            vault_ok = True
        else:
            st2, _, current = nas.request("GET", "/api/export/vault-header")
            vault_ok = st2 == 200 and current == header   # same vault: its files can be restored
            if not vault_ok:
                print("  warning: the NAS already has a different vault; vault files are skipped")
    done = skipped = 0
    for f in m["files"]:
        if f["encrypted"] and not vault_ok:
            skipped += 1
            continue
        data = repo.get_object(f["object"])
        st, _, body = nas.request("POST", "/api/import/file?" + urlencode({"path": f["path"]}), data,
                                  {"Content-Type": "application/octet-stream"})
        if st != 200:
            raise ReplicaError(f"{f['path']}: {json.loads(body or b'{}').get('message', st)}")
        done += 1
    print(f"Restored {done} file(s) of snapshot {a.snap} into NAS {nas.nas_id}" +
          (f"; {skipped} vault file(s) skipped" if skipped else "") +
          ("; unlock the vault with its passphrase (console: vault unlock)" if vault_ok else ""))
    return done


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init"); s.add_argument("repo"); s.add_argument("--plain", action="store_true")
    for name in ("pull", "restore"):
        s = sub.add_parser(name)
        s.add_argument("repo")
        s.add_argument("--host", required=True)
        s.add_argument("--port", type=int, default=8443)
        s.add_argument("--user", required=True)
        s.add_argument("--fingerprint", required=True)
        if name == "restore":
            s.add_argument("--snap", type=int, required=True)
            s.add_argument("--from", dest="source")
    sub.add_parser("list").add_argument("repo")
    sub.add_parser("verify").add_argument("repo")
    a = p.parse_args(argv)
    try:
        result = {"init": cmd_init, "pull": cmd_pull, "list": cmd_list, "verify": cmd_verify, "restore": cmd_restore}[a.cmd](a)
    except ReplicaError as e:
        print("error:", e, file=sys.stderr)
        return 1
    return 0 if result is not False else 1


if __name__ == "__main__":
    sys.exit(main())
