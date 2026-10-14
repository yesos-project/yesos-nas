#!/usr/bin/env python3
"""
===============================================================================
YesOS 2.0 - Host Linux NAS Client & Edge AI Interaction Tool
Communicates directly with YesOS NAS daemon running inside QEMU / Bare-Metal RISC-V
Port: UDP 31415 (Sovereign Air-Gap Private Storage Protocol - Pi Math)
Supports: status, list, search, smart, write, download, cat, upload
===============================================================================
"""

import sys
import os
import socket
import struct
import argparse
import time
import getpass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
from yesos_secure import SecureNasClient, SecureChannelError, load_pinned_key, pin_key

REMOTE_CMD_MAGIC  = 0x59455343
REMOTE_RESP_MAGIC = 0x59455352

CMD_FORMAT  = "<IHHI256s"
RESP_FORMAT = "<IHHI256s"

# NAS Command Types
NAS_CMD_INFO      = 0x20
NAS_CMD_LIST      = 0x21
NAS_CMD_READ      = 0x22
NAS_CMD_WRITE     = 0x23
NAS_CMD_AI_SEARCH = 0x24
NAS_CMD_SMART     = 0x25
NAS_CMD_AUTH      = 0x26
NAS_CMD_USER_MGR  = 0x27

READ_REQ_FORMAT = "<IHH248s"

# -----------------------------------------------------------------------------
# Transport: every command travels over the Noise NK secure channel
# (tools/yesos_secure.py). One session per (host, port) per process.
# -----------------------------------------------------------------------------

_SESSIONS = {}
_CREDENTIALS = None


def set_credentials(user, password):
    """Credentials sent (inside the encrypted channel) after every handshake."""
    global _CREDENTIALS
    _CREDENTIALS = (user, password) if user else None


def _open_session(host, port):
    key = load_pinned_key(host, port)
    if key is None:
        raise SecureChannelError(
            f"no pinned server key for {host}:{port}. Run 'nas key' on the YesOS console, then:\n"
            f"  python3 tools/nas_client.py --host {host} --port {port} trust <64-hex-key>")
    client = SecureNasClient(host, port, key)
    client.handshake()
    if _CREDENTIALS:
        user, password = _CREDENTIALS
        status, resp = client.request(NAS_CMD_AUTH, f"{user}:{password}".encode("utf-8"))
        if status != 0:
            client.close()
            raise SecureChannelError(resp.decode("utf-8", errors="replace"))
    _SESSIONS[(host, port)] = client
    return client


def send_nas_raw_request(host, port, cmd_type, payload_bytes=b""):
    for attempt in range(2):
        try:
            client = _SESSIONS.get((host, port)) or _open_session(host, port)
            status, data = client.request(cmd_type, payload_bytes[:512])
            return True, status, data
        except SecureChannelError as e:
            stale = _SESSIONS.pop((host, port), None)
            if stale:
                stale.close()
            # The appliance may have evicted or forgotten the session: re-handshake once.
            if attempt == 0 and "UNKNOWN SESSION" in str(e):
                continue
            return False, -1, str(e).encode("utf-8")
        except socket.timeout:
            _SESSIONS.pop((host, port), None)
            return False, -1, f"Timeout connecting to YesOS NAS at {host}:{port}".encode("utf-8")
        except OSError as e:
            return False, -1, f"Network error: {e}".encode("utf-8")
    return False, -1, b"unreachable"


def send_nas_request(host, port, cmd_type, payload_bytes=b""):
    ok, status, data = send_nas_raw_request(host, port, cmd_type, payload_bytes)
    return ok, status, data.decode("utf-8", errors="ignore")


def fetch_file_bytes(host, port, remote_path):
    path_bytes = remote_path.encode('utf-8')
    # 1. Query size / stat (flags = 1)
    stat_payload = struct.pack(READ_REQ_FORMAT, 0, 0, 1, path_bytes[:248])
    ok, status, raw_resp = send_nas_raw_request(host, port, NAS_CMD_READ, stat_payload)
    if not ok or status != 0:
        return False, f"File query error: {raw_resp.decode('utf-8', errors='ignore')}"

    stat_str = raw_resp.decode('utf-8', errors='ignore')
    if not stat_str.startswith("SIZE:"):
        return False, f"Server returned: {stat_str}"

    total_size = int(stat_str[5:])

    # 2. Download chunks
    data = bytearray()
    offset = 0
    chunk_size = 256

    while offset < total_size:
        req_payload = struct.pack(READ_REQ_FORMAT, offset, chunk_size, 0, path_bytes[:248])
        ok, status, chunk = send_nas_raw_request(host, port, NAS_CMD_READ, req_payload)
        if not ok or status != 0:
            return False, f"Failed at offset {offset}"
        if len(chunk) == 0:
            break
        data.extend(chunk)
        offset += len(chunk)

    return True, bytes(data)

def cmd_status(args):
    print(f"\n📡 Querying YesOS NAS Status from {args.host}:{args.port}...")
    ok, status, msg = send_nas_request(args.host, args.port, NAS_CMD_INFO)
    if ok:
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  YESOS 2.0 AIR-GAP NAS STORAGE POOL TELEMETRY")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"  {msg}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    else:
        print(f"❌ {msg}")

def cmd_list(args):
    print(f"\n📂 Querying YesOS Network Shares and Storage Pool...")
    ok, status, msg = send_nas_request(args.host, args.port, NAS_CMD_LIST)
    if ok:
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  YESOS SHARES & FILES OVERVIEW")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        for part in msg.split(" | "):
            print(f"  • {part}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    else:
        print(f"❌ {msg}")

def cmd_search(args):
    query = " ".join(args.query)
    print(f"\n🧠 Querying Edge AI Semantic Vector Search for: '{query}'...")
    ok, status, msg = send_nas_request(args.host, args.port, NAS_CMD_AI_SEARCH, query.encode('utf-8'))
    if ok:
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  RVV 1.0 VECTOR ENGINE SEARCH RESULTS")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"  {msg}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    else:
        print(f"❌ {msg}")

def cmd_smart(args):
    print(f"\n🔬 Querying S.M.A.R.T. Drive Health & Thermal Telemetry...")
    ok, status, msg = send_nas_request(args.host, args.port, NAS_CMD_SMART)
    if ok:
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  SILICON STORAGE DIAGNOSTICS")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"  {msg}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    else:
        print(f"❌ {msg}")

def cmd_write(args):
    data = args.content.encode('utf-8')
    print(f"\n💾 Uploading {len(data)} bytes to YesOS NAS Storage (Subject to Edge AI Anti-Ransomware inspection)...")
    ok, status, msg = send_nas_request(args.host, args.port, NAS_CMD_WRITE, data)
    if ok:
        if status == 0:
            print(f"✅ Success: {msg}\n")
        else:
            print(f"🚨 Blocked: {msg}\n")
    else:
        print(f"❌ {msg}")

def cmd_download(args):
    remote_path = args.remote_file
    local_path = args.output if args.output else os.path.basename(remote_path)
    print(f"\n📥 Downloading '{remote_path}' from YesOS NAS to '{local_path}'...")
    t0 = time.time()
    ok, res = fetch_file_bytes(args.host, args.port, remote_path)
    if ok:
        with open(local_path, "wb") as f:
            f.write(res)
        elapsed = max(0.001, time.time() - t0)
        speed_kb = (len(res) / 1024) / elapsed
        print(f"✅ Download complete: {len(res)} bytes saved to '{local_path}' ({speed_kb:.1f} KB/s)\n")
    else:
        print(f"❌ Download failed: {res}\n")

def cmd_cat(args):
    remote_path = args.remote_file
    ok, res = fetch_file_bytes(args.host, args.port, remote_path)
    if ok:
        try:
            print(res.decode('utf-8'))
        except UnicodeDecodeError:
            print(f"⚠️ Binary file ({len(res)} bytes). Hexdump preview:")
            print(" ".join(f"{b:02X}" for b in res[:64]))
    else:
        print(f"❌ Error reading '{remote_path}': {res}")

def cmd_upload(args):
    local_file = args.local_file
    if not os.path.isfile(local_file):
        print(f"❌ Local file '{local_file}' does not exist.")
        return
    with open(local_file, "rb") as f:
        data = f.read()

    print(f"\n📤 Uploading '{local_file}' ({len(data)} bytes) to YesOS NAS...")
    ok, status, msg = send_nas_request(args.host, args.port, NAS_CMD_WRITE, data)
    if ok:
        if status == 0:
            print(f"✅ Success: {msg}\n")
        else:
            print(f"🚨 Blocked by Edge AI Shield: {msg}\n")
    else:
        print(f"❌ Upload error: {msg}")

def cmd_trust(args):
    pin_key(args.host, args.port, args.key)
    print(f"✅ Pinned server key for {args.host}:{args.port}")

def cmd_login(args):
    user = args.username
    password = args.password or getpass.getpass(f"Password for {user}: ")
    print(f"\n🔐 Authenticating as '{user}' on YesOS NAS (encrypted channel)...")
    ok, status, msg = send_nas_request(args.host, args.port, NAS_CMD_AUTH, f"{user}:{password}".encode('utf-8'))
    if ok:
        if status == 0:
            print(f"✅ {msg}\n")
        else:
            print(f"❌ Authentication failed: {msg}\n")
    else:
        print(f"❌ Network error: {msg}\n")

def main():
    parser = argparse.ArgumentParser(description="YesOS 2.0 Host Linux NAS Client")
    parser.add_argument("--host", default="127.0.0.1", help="YesOS IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=31415, help="YesOS UDP port (default: 31415)")
    parser.add_argument("-u", "--user", default=None, help="Username for authentication")
    parser.add_argument("-p", "--password", default=None,
                        help="Password (prefer omitting it: you will be prompted, or set YESOS_NAS_PASSWORD)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # login / auth
    p_auth = subparsers.add_parser("login", help="Authenticate client with user credentials")
    p_auth.add_argument("username", help="NAS username")
    p_auth.add_argument("password", nargs="?", help="NAS password (prompted if omitted)")
    p_auth.set_defaults(func=cmd_login)

    # trust: pin the appliance's static public key (from `nas key` on the console)
    p_trust = subparsers.add_parser("trust", help="Pin the YesOS server public key")
    p_trust.add_argument("key", help="64-hex-character key shown by 'nas key'")
    p_trust.set_defaults(func=cmd_trust)

    # status
    p_status = subparsers.add_parser("status", help="Get NAS status and active clients")
    p_status.set_defaults(func=cmd_status)

    # list
    p_list = subparsers.add_parser("list", help="List shares and storage pool files")
    p_list.set_defaults(func=cmd_list)

    # search
    p_search = subparsers.add_parser("search", help="Semantic AI search across files")
    p_search.add_argument("query", nargs="+", help="Natural language search query")
    p_search.set_defaults(func=cmd_search)

    # smart
    p_smart = subparsers.add_parser("smart", help="Check S.M.A.R.T. drive health")
    p_smart.set_defaults(func=cmd_smart)

    # write
    p_write = subparsers.add_parser("write", help="Write text content to NAS")
    p_write.add_argument("content", help="Text content to write")
    p_write.set_defaults(func=cmd_write)

    # download
    p_dl = subparsers.add_parser("download", help="Download a file from YesOS NAS to host")
    p_dl.add_argument("remote_file", help="Remote file path (e.g. README.DD, GAME.HQ)")
    p_dl.add_argument("-o", "--output", help="Local output destination path")
    p_dl.set_defaults(func=cmd_download)

    # cat
    p_cat = subparsers.add_parser("cat", help="Print remote file contents directly in terminal")
    p_cat.add_argument("remote_file", help="Remote file path to read (e.g. README.DD)")
    p_cat.set_defaults(func=cmd_cat)

    # upload
    p_up = subparsers.add_parser("upload", help="Upload a file from host to YesOS NAS")
    p_up.add_argument("local_file", help="Local file to upload")
    p_up.set_defaults(func=cmd_upload)

    args = parser.parse_args()

    # Credentials are sent inside the encrypted channel right after the handshake
    if args.user and args.command not in ("login", "trust"):
        password = args.password or os.environ.get("YESOS_NAS_PASSWORD") or getpass.getpass(f"Password for {args.user}: ")
        set_credentials(args.user, password)

    args.func(args)

if __name__ == "__main__":
    main()
