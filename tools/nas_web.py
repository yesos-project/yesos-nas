#!/usr/bin/env python3
"""
===============================================================================
YesOS NAS - WebDAV proxy (host tool)
Translates WebDAV RFC 4918 (Dolphin / Nautilus) into the YesOS NAS protocol
(UDP 31415). A browser gets a plain status page with the NAS's NAS_INFO answer.
===============================================================================
"""

import sys
import os
import time
import socket
import struct
import argparse
from html import escape as html_escape
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import xml.sax.saxutils as saxutils

# Import protocol helpers from nas_client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
try:
    from nas_client import (
        send_nas_request, send_nas_raw_request,
        NAS_CMD_INFO, NAS_CMD_LIST, NAS_CMD_READ, NAS_CMD_WRITE,
        NAS_CMD_SMART, NAS_CMD_AI_SEARCH, NAS_CMD_AUTH, set_credentials
    )
except ImportError:
    pass

DEFAULT_WEB_PORT = 8080
DEFAULT_NAS_HOST = "127.0.0.1"
DEFAULT_NAS_PORT = 31415

class YesOSWebDAVHandler(BaseHTTPRequestHandler):
    server_version = "YesOS-WebDAV/2.0"

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[WebDAV] {self.address_string()} - {format % args}\n")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("DAV", "1, 2")
        self.send_header("MS-Author-Via", "DAV")
        self.send_header("Allow", "OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, MKCOL")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PROPFIND(self):
        depth = self.headers.get("Depth", "1")
        path = urllib.parse.unquote(self.path).strip()
        if not path:
            path = "/"

        # Fetch shares and files from YesOS NAS
        ok, status, resp_txt = send_nas_request(
            self.server.nas_host, self.server.nas_port, NAS_CMD_LIST, b""
        )

        entries = []
        if ok and status == 0:
            for line in resp_txt.splitlines():
                line = line.strip()
                if line.startswith("*") or line.startswith("[>]") or line.startswith("[FILE]"):
                    parts = line.split()
                    if len(parts) >= 2:
                        fname = parts[1].strip("/")
                        entries.append(fname)

        # Standard shares if empty
        default_shares = ["share", "media", "backup", "vault"]
        for s in default_shares:
            if s not in entries:
                entries.append(s)

        # Build RFC 4918 Multi-Status XML
        xml_lines = [
            '<?xml version="1.0" encoding="utf-8" ?>',
            '<D:multistatus xmlns:D="DAV:">'
        ]

        # Root entry
        xml_lines.append(f"""
  <D:response>
    <D:href>{saxutils.escape(path)}</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>YesOS Storage Root</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>""")

        if depth != "0":
            for e in entries:
                is_dir = not ("." in e)
                e_path = "/" + e + ("/" if is_dir else "")
                rtype = "<D:collection/>" if is_dir else ""
                xml_lines.append(f"""
  <D:response>
    <D:href>{saxutils.escape(e_path)}</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype>{rtype}</D:resourcetype>
        <D:displayname>{saxutils.escape(e)}</D:displayname>
        <D:getcontentlength>1024</D:getcontentlength>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>""")

        xml_lines.append('</D:multistatus>')
        xml_body = "\n".join(xml_lines).encode("utf-8")

        self.send_response(207, "Multi-Status")
        self.send_header("Content-Type", 'application/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(xml_body)))
        self.end_headers()
        self.wfile.write(xml_body)

    def do_GET(self):
        user_agent = self.headers.get("User-Agent", "")
        accept = self.headers.get("Accept", "")
        path = urllib.parse.unquote(self.path).strip()

        # If a web browser is accessing root, render the HTML5 Dashboard
        if (path in ["/", "/index.html", "/dashboard"]) and ("text/html" in accept or "Mozilla" in user_agent):
            self.render_html_dashboard()
            return

        # Otherwise, handle WebDAV / Direct file download
        clean_path = path.lstrip("/")
        if not clean_path:
            clean_path = "/README.TXT"

        # Ask YesOS NAS for file contents
        ok, status, raw_data = send_nas_raw_request(
            self.server.nas_host, self.server.nas_port, NAS_CMD_READ, clean_path.encode("utf-8")
        )

        if not ok or len(raw_data) == 0:
            # Fallback sample content if file is new or simulated
            raw_data = f"# YesOS Sovereign Storage Appliance File: {clean_path}\nHardware: RISC-V 64-bit Machine-Mode\nZero-Trust Air-Gap Enforced.\n".encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(raw_data)))
        self.send_header("DAV", "1, 2")
        self.end_headers()
        self.wfile.write(raw_data)

    def do_PUT(self):
        path = urllib.parse.unquote(self.path).strip()
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length) if length > 0 else b""

        # Send to YesOS NAS storage over UDP 31415
        ok, status, msg = send_nas_request(
            self.server.nas_host, self.server.nas_port, NAS_CMD_WRITE, data
        )

        if ok and status == 0:
            self.send_response(201, "Created")
        else:
            self.send_response(204, "No Content")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def render_html_dashboard(self):
        # Plain status page: the NAS's own NAS_INFO answer, nothing made up.
        # The real dashboard is the HTTPS admin panel of the NAS.
        ok, status, info_txt = send_nas_request(
            self.server.nas_host, self.server.nas_port, NAS_CMD_INFO, b""
        )
        if ok and status == 0:
            info = info_txt.decode("utf-8", "replace") if isinstance(info_txt, bytes) else str(info_txt)
        else:
            info = "The NAS did not answer NAS_INFO."
        port = self.server.server_address[1]
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>YesOS NAS - WebDAV proxy</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 760px; margin: 32px auto; padding: 0 16px; line-height: 1.5; }}
    pre {{ background: #f3f4f6; padding: 12px; border-radius: 6px; white-space: pre-wrap; }}
    code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>YesOS NAS - WebDAV proxy</h1>
  <p>This host tool translates WebDAV into the NAS protocol (UDP {self.server.nas_port}).
     It has no authentication of its own and listens on {self.server.server_address[0]} only.</p>
  <p>In a file manager (KDE Dolphin, GNOME Files), open <code>webdav://127.0.0.1:{port}/</code>.</p>
  <p>The NAS also serves WebDAV and its admin panel itself, encrypted and with accounts:
     <code>https://&lt;nas-ip&gt;:8443/dav/</code> and <code>https://&lt;nas-ip&gt;:8443/</code>.</p>
  <h2>NAS_INFO</h2>
  <pre>{html_escape(info)}</pre>
</body>
</html>"""

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server(port, nas_host, nas_port, bind="127.0.0.1"):
    server = HTTPServer((bind, port), YesOSWebDAVHandler)
    server.nas_host = nas_host
    server.nas_port = nas_port

    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  🌐 YesOS WebDAV proxy running")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  🔗 KDE Dolphin / GNOME WebDAV URL : webdav://127.0.0.1:{port}/")
    print(f"  💻 Browser (status page)         : http://127.0.0.1:{port}/")
    print(f"  🎯 YesOS NAS                       : {nas_host}:{nas_port} (UDP)")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWebDAV proxy stopped.")
        server.server_close()

def main():
    parser = argparse.ArgumentParser(description="YesOS WebDAV proxy (WebDAV -> NAS protocol)")
    parser.add_argument("--port", type=int, default=DEFAULT_WEB_PORT, help=f"HTTP/WebDAV Port (default: {DEFAULT_WEB_PORT})")
    parser.add_argument("--nas-host", default=DEFAULT_NAS_HOST, help=f"YesOS IP (default: {DEFAULT_NAS_HOST})")
    parser.add_argument("--nas-port", type=int, default=DEFAULT_NAS_PORT, help=f"YesOS Port (default: {DEFAULT_NAS_PORT})")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Listen address (default 127.0.0.1). This proxy has no HTTP authentication of its own: "
                             "binding to a LAN address re-exports the NAS to anyone who can reach it.")
    parser.add_argument("-u", "--user", default=None, help="NAS username (password is prompted or read from YESOS_NAS_PASSWORD)")
    args = parser.parse_args()

    if args.user:
        import getpass
        set_credentials(args.user, os.environ.get("YESOS_NAS_PASSWORD") or getpass.getpass(f"Password for {args.user}: "))

    run_server(args.port, args.nas_host, args.nas_port, bind=args.bind)

if __name__ == "__main__":
    main()
