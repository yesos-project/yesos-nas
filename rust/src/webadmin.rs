//! YesOS NAS - web administration over HTTP (port 8080).
//!
//! Routes: `/login`, `/` (admin panel), `/admin/*` (static assets) and
//! `/api/*` (JSON). Sessions, the login policy and the JSON views live in
//! kernel/webadmin.c; this module parses requests, enforces the session and
//! CSRF checks per route and adds the security headers.
//!
//! Transport: the panel and its API are served only over HTTPS (TLS 1.3 on
//! port 8443, see crate::tls). Over plain HTTP the admin routes redirect to
//! HTTPS and the API refuses to work, so passwords and session cookies never
//! cross the network in clear.

use alloc::vec::Vec;

use crate::http::{header, respond, HttpMethod, HttpRequest};

extern "C" {
    fn webadmin_login(user: *const u8, pass: *const u8, ip: u32, out_sid: *mut u8, out_csrf: *mut u8) -> i32;
    fn webadmin_check(sid: *const u8, csrf: *const u8, ip: u32, out_user: *mut u8, user_max: usize) -> i32;
    fn webadmin_logout(sid: *const u8, ip: u32);
    fn webadmin_throttle_remaining(ip: u32) -> u32;
    fn webadmin_json(section: *const u8, sid: *const u8, buf: *mut u8, max: usize) -> i32;
    fn webui_is_client_admitted(ip: u32) -> bool;
    fn webadmin_action(sid: *const u8, ip: u32, action: *const u8, fields: *const *const u8,
                       msg: *mut u8, msg_max: usize) -> i32;
    fn webdav_authorize(user: *const u8, pass: *const u8, ip: u32, share: *const u8, write: bool) -> i32;
    fn webadmin_export_file(snap: u32, path: *const u8, out: *mut *mut u8, out_len: *mut usize) -> i32;
    fn webadmin_export_vault_header(sid: *const u8, ip: u32, out: *mut *mut u8, out_len: *mut usize) -> i32;
    fn webadmin_import_file(sid: *const u8, ip: u32, path: *const u8, data: *const u8, len: usize,
                            msg: *mut u8, msg_max: usize) -> i32;
    fn webadmin_import_vault_header(sid: *const u8, ip: u32, data: *const u8, len: usize,
                                    msg: *mut u8, msg_max: usize) -> i32;
    fn Free(p: *mut u8);
}

const WA_OK: i32 = 0;
const WA_ERR_BAD_CREDENTIALS: i32 = -1;
const WA_ERR_NOT_ADMIN: i32 = -2;
const WA_ERR_NOT_ADMITTED: i32 = -3;
const WA_ERR_THROTTLED: i32 = -4;
const WA_ERR_BAD_CSRF: i32 = -7;

const TOKEN_HEX: usize = 64;
const COOKIE: &[u8] = b"yesos_sid=";

const SEC_HEADERS: &str = "Cache-Control: no-store\r\n\
X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Referrer-Policy: no-referrer\r\n\
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

const LOGIN_HTML: &str = include_str!("webadmin/login.html");
const APP_HTML: &str = include_str!("webadmin/app.html");
const APP_CSS: &str = include_str!("webadmin/app.css");
const APP_JS: &str = include_str!("webadmin/app.js");
const LOGIN_JS: &str = include_str!("webadmin/login.js");

const SECTIONS: [&str; 10] = ["overview", "storage", "shares", "users", "devices", "network", "security", "session", "audit", "snapshots"];

/// Form fields passed to webadmin_action, in the order of the WA_F_* indices.
const ACTION_FIELDS: [&[u8]; 9] = [b"name", b"password", b"current", b"role", b"ip", b"path", b"comment", b"readonly", b"value"];
const ACTIONS: [&str; 17] = ["fs_check", "export_begin", "import_begin", "user_add", "user_delete", "user_role", "user_password", "auth_required",
                             "device_admit", "device_block", "share_add", "share_delete", "vault_lock",
                             "snapshot_create", "snapshot_delete", "snapshot_restore", "snapshot_auto"];
const FIELD_MAX: usize = 256;   // RedSea names are up to 223 bytes (snapshot restore paths)

fn wipe(b: &mut [u8]) {
    crate::http::wipe(b);
}

fn send(ip: [u8; 4], port: u16, status: &str, ctype: &str, extra: &str, body: &[u8]) {
    let mut h: Vec<u8> = Vec::with_capacity(SEC_HEADERS.len() + extra.len() + 4);
    h.extend_from_slice(SEC_HEADERS.as_bytes());
    if !extra.is_empty() {
        h.extend_from_slice(b"\r\n");
        h.extend_from_slice(extra.as_bytes());
    }
    respond(ip, port, status, ctype, core::str::from_utf8(&h).unwrap_or(SEC_HEADERS), body);
}

fn json(ip: [u8; 4], port: u16, status: &str, body: &[u8]) {
    send(ip, port, status, "application/json; charset=utf-8", "", body);
}

/// Session token from the Cookie header, NUL-terminated (64 lowercase hex).
fn cookie_sid(req: &HttpRequest) -> Option<[u8; TOKEN_HEX + 1]> {
    let v = header(req.headers, b"Cookie")?;
    let mut i = 0;
    while i + COOKIE.len() + TOKEN_HEX <= v.len() {
        let at_start = i == 0 || v[i - 1] == b' ' || v[i - 1] == b';';
        if at_start && &v[i..i + COOKIE.len()] == COOKIE {
            let tok = &v[i + COOKIE.len()..i + COOKIE.len() + TOKEN_HEX];
            if !tok.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
                return None;
            }
            let mut out = [0u8; TOKEN_HEX + 1];
            out[..TOKEN_HEX].copy_from_slice(tok);
            return Some(out);
        }
        i += 1;
    }
    None
}

fn csrf_header(req: &HttpRequest) -> Option<[u8; TOKEN_HEX + 1]> {
    let v = header(req.headers, b"X-CSRF-Token")?;
    if v.len() != TOKEN_HEX {
        return None;
    }
    let mut out = [0u8; TOKEN_HEX + 1];
    out[..TOKEN_HEX].copy_from_slice(v);
    Some(out)
}

/// Checks the session (and the CSRF token when `need_csrf`). Returns the
/// session token on success; on failure the error response is already sent.
fn require_session(req: &HttpRequest, ip: [u8; 4], port: u16, need_csrf: bool) -> Option<[u8; TOKEN_HEX + 1]> {
    let ip_u32 = u32::from_be_bytes(ip);
    let sid = match cookie_sid(req) {
        Some(s) => s,
        None => {
            json(ip, port, "HTTP/1.1 401 Unauthorized", b"{\"error\":\"login required\"}");
            return None;
        }
    };
    let csrf = if need_csrf { csrf_header(req) } else { None };
    if need_csrf && csrf.is_none() {
        json(ip, port, "HTTP/1.1 403 Forbidden", b"{\"error\":\"missing CSRF token\"}");
        return None;
    }
    let csrf_ptr = match &csrf {
        Some(c) => c.as_ptr(),
        None => core::ptr::null(),
    };
    let mut user = [0u8; 32];
    let r = unsafe { webadmin_check(sid.as_ptr(), csrf_ptr, ip_u32, user.as_mut_ptr(), user.len()) };
    match r {
        WA_OK => Some(sid),
        WA_ERR_BAD_CSRF => {
            json(ip, port, "HTTP/1.1 403 Forbidden", b"{\"error\":\"bad CSRF token\"}");
            None
        }
        _ => {
            json(ip, port, "HTTP/1.1 401 Unauthorized", b"{\"error\":\"session expired\"}");
            None
        }
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes one application/x-www-form-urlencoded field into `out` (NUL-terminated).
/// Fails if the field is missing, malformed, contains NUL or does not fit.
fn form_field(body: &[u8], name: &[u8], out: &mut [u8]) -> bool {
    matches!(form_field_opt(body, name, out), Ok(true))
}

/// Ok(true): decoded; Ok(false): absent (out = ""); Err: malformed or too long.
fn form_field_opt(body: &[u8], name: &[u8], out: &mut [u8]) -> Result<bool, ()> {
    out[0] = 0;
    for pair in body.split(|&b| b == b'&') {
        let eq = match pair.iter().position(|&b| b == b'=') {
            Some(e) => e,
            None => continue,
        };
        if &pair[..eq] != name {
            continue;
        }
        let v = &pair[eq + 1..];
        let mut n = 0;
        let mut i = 0;
        while i < v.len() {
            let c = match v[i] {
                b'+' => b' ',
                b'%' => {
                    if i + 2 >= v.len() {
                        return Err(());
                    }
                    match (hex_val(v[i + 1]), hex_val(v[i + 2])) {
                        (Some(h), Some(l)) => {
                            i += 2;
                            (h << 4) | l
                        }
                        _ => return Err(()),
                    }
                }
                c => c,
            };
            if c == 0 || n + 1 >= out.len() {
                return Err(());
            }
            out[n] = c;
            n += 1;
            i += 1;
        }
        out[n] = 0;
        return Ok(true);
    }
    Ok(false)
}

fn login(req: &HttpRequest, ip: [u8; 4], port: u16) {
    let ip_u32 = u32::from_be_bytes(ip);
    let mut user = [0u8; 32];
    let mut pass = [0u8; 32];
    let ok_fields = form_field(req.body, b"user", &mut user) && form_field(req.body, b"pass", &mut pass);
    if !ok_fields {
        wipe(&mut pass);
        json(ip, port, "HTTP/1.1 400 Bad Request", b"{\"error\":\"user and pass are required (max 31 characters)\"}");
        return;
    }
    let mut sid = [0u8; TOKEN_HEX + 1];
    let mut csrf = [0u8; TOKEN_HEX + 1];
    let r = unsafe { webadmin_login(user.as_ptr(), pass.as_ptr(), ip_u32, sid.as_mut_ptr(), csrf.as_mut_ptr()) };
    wipe(&mut pass);
    wipe(&mut csrf);
    match r {
        WA_OK => {
            let mut cookie: Vec<u8> = Vec::with_capacity(160);
            cookie.extend_from_slice(b"Set-Cookie: yesos_sid=");
            cookie.extend_from_slice(&sid[..TOKEN_HEX]);
            cookie.extend_from_slice(b"; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800");
            wipe(&mut sid);
            send(ip, port, "HTTP/1.1 200 OK", "application/json; charset=utf-8",
                 core::str::from_utf8(&cookie).unwrap_or(""), b"{\"ok\":true}");
            wipe(&mut cookie);
        }
        WA_ERR_NOT_ADMITTED => json(ip, port, "HTTP/1.1 403 Forbidden",
            b"{\"error\":\"not_admitted\"}"),
        WA_ERR_NOT_ADMIN => json(ip, port, "HTTP/1.1 403 Forbidden",
            b"{\"error\":\"not_admin\"}"),
        WA_ERR_THROTTLED => {
            let mut b = Vec::with_capacity(48);
            b.extend_from_slice(b"{\"error\":\"throttled\",\"retry_sec\":");
            push_u32(&mut b, unsafe { webadmin_throttle_remaining(ip_u32) });
            b.extend_from_slice(b"}");
            json(ip, port, "HTTP/1.1 429 Too Many Requests", &b);
        }
        WA_ERR_BAD_CREDENTIALS => json(ip, port, "HTTP/1.1 401 Unauthorized",
            b"{\"error\":\"bad_credentials\"}"),
        _ => json(ip, port, "HTTP/1.1 503 Service Unavailable", b"{\"error\":\"no_entropy\"}"),
    }
}

fn push_u32(b: &mut Vec<u8>, mut n: u32) {
    let mut t = [0u8; 10];
    let mut i = 10;
    loop {
        i -= 1;
        t[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    b.extend_from_slice(&t[i..]);
}

/// Unauthenticated: tells the login page whether this device may log in.
fn access(ip: [u8; 4], port: u16) {
    let ip_u32 = u32::from_be_bytes(ip);
    let mut b = Vec::with_capacity(96);
    b.extend_from_slice(b"{\"ip\":\"");
    for (i, octet) in ip.iter().enumerate() {
        if i > 0 {
            b.push(b'.');
        }
        push_u32(&mut b, *octet as u32);
    }
    b.extend_from_slice(b"\",\"admitted\":");
    b.extend_from_slice(if unsafe { webui_is_client_admitted(ip_u32) } { b"true" } else { b"false" });
    b.extend_from_slice(b",\"retry_sec\":");
    push_u32(&mut b, unsafe { webadmin_throttle_remaining(ip_u32) });
    b.extend_from_slice(b"}");
    json(ip, port, "HTTP/1.1 200 OK", &b);
}

fn section(name: &str, sid: &[u8; TOKEN_HEX + 1], ip: [u8; 4], port: u16) {
    let mut sec = [0u8; 16];
    sec[..name.len()].copy_from_slice(name.as_bytes());
    let mut cap = 16 * 1024;
    while cap <= 16 * 1024 * 1024 {   // up to 16384 directory entries
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(cap, 0);
        let n = unsafe { webadmin_json(sec.as_ptr(), sid.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        if n >= 0 {
            buf.truncate(n as usize);
            json(ip, port, "HTTP/1.1 200 OK", &buf);
            if name == "session" {
                wipe(&mut buf);
            }
            return;
        }
        if n == -1 {
            break;
        }
        cap *= 4;
    }
    json(ip, port, "HTTP/1.1 500 Internal Server Error", b"{\"error\":\"view too large\"}");
}

fn json_escape_into(out: &mut Vec<u8>, s: &[u8]) {
    for &c in s {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'<' => out.extend_from_slice(b"\\u003c"),
            b'>' => out.extend_from_slice(b"\\u003e"),
            b'&' => out.extend_from_slice(b"\\u0026"),
            0..=0x1f => {}
            _ => out.push(c),
        }
    }
}

fn action(req: &HttpRequest, name: &str, sid: &[u8; TOKEN_HEX + 1], ip: [u8; 4], port: u16) {
    if !ACTIONS.contains(&name) {
        json(ip, port, "HTTP/1.1 404 Not Found", "{\"ok\":false,\"message\":\"Unknown action.\"}".as_bytes());
        return;
    }
    if req.body.len() > 4096 {
        json(ip, port, "HTTP/1.1 413 Payload Too Large", "{\"ok\":false,\"message\":\"Request too large.\"}".as_bytes());
        return;
    }
    let mut bufs = [[0u8; FIELD_MAX]; 9];
    let mut bad = false;
    for (i, f) in ACTION_FIELDS.iter().enumerate() {
        if form_field_opt(req.body, f, &mut bufs[i]).is_err() {
            bad = true;
        }
    }
    let mut status = 400;
    let mut msg = [0u8; 256];
    if bad {
        let t = "A field is too long or not valid.";
        msg[..t.len()].copy_from_slice(t.as_bytes());
    } else {
        let mut act = [0u8; 24];
        act[..name.len()].copy_from_slice(name.as_bytes());
        let ptrs: [*const u8; 9] = core::array::from_fn(|i| bufs[i].as_ptr());
        status = unsafe {
            webadmin_action(sid.as_ptr(), u32::from_be_bytes(ip), act.as_ptr(), ptrs.as_ptr(), msg.as_mut_ptr(), msg.len())
        };
    }
    for b in bufs.iter_mut() {
        wipe(b);
    }
    let n = msg.iter().position(|&b| b == 0).unwrap_or(msg.len());
    let mut out: Vec<u8> = Vec::with_capacity(n + 32);
    out.extend_from_slice(if status == 200 { b"{\"ok\":true,\"message\":\"" } else { b"{\"ok\":false,\"message\":\"" });
    json_escape_into(&mut out, &msg[..n]);
    out.extend_from_slice(b"\"}");
    let line = match status {
        200 => "HTTP/1.1 200 OK",
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        409 => "HTTP/1.1 409 Conflict",
        500 => "HTTP/1.1 500 Internal Server Error",
        _ => "HTTP/1.1 400 Bad Request",
    };
    json(ip, port, line, &out);
}

// ---------------------------------------------------------------------------
// Replication (tools/yesos_replicate.py): admin session, HTTPS only
// ---------------------------------------------------------------------------

fn query<'a>(raw_path: &'a str) -> &'a [u8] {
    match raw_path.find('?') {
        Some(q) => raw_path[q + 1..].as_bytes(),
        None => b"",
    }
}

fn status_line(code: i32) -> &'static str {
    match code {
        200 => "HTTP/1.1 200 OK",
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        409 => "HTTP/1.1 409 Conflict",
        413 => "HTTP/1.1 413 Payload Too Large",
        507 => "HTTP/1.1 507 Insufficient Storage",
        _ => "HTTP/1.1 400 Bad Request",
    }
}

fn json_message(ip: [u8; 4], port: u16, code: i32, msg: &[u8]) {
    let n = msg.iter().position(|&b| b == 0).unwrap_or(msg.len());
    let mut out: Vec<u8> = Vec::with_capacity(n + 32);
    out.extend_from_slice(if code == 200 { b"{\"ok\":true,\"message\":\"" } else { b"{\"ok\":false,\"message\":\"" });
    json_escape_into(&mut out, &msg[..n]);
    out.extend_from_slice(b"\"}");
    json(ip, port, status_line(code), &out);
}

fn send_c_buffer(ip: [u8; 4], port: u16, code: i32, data: *mut u8, len: usize) {
    if code == 0 && !data.is_null() {
        let bytes = unsafe { core::slice::from_raw_parts(data, len) };
        send(ip, port, "HTTP/1.1 200 OK", "application/octet-stream", "", bytes);
        unsafe { Free(data) };
    } else {
        json(ip, port, status_line(if code == 0 { 404 } else { code }), b"{\"ok\":false,\"message\":\"not found\"}");
    }
}

fn replication(req: &HttpRequest, path: &str, raw_path: &str, ip: [u8; 4], port: u16) -> bool {
    let get = req.method == HttpMethod::Get;
    let post = req.method == HttpMethod::Post || req.method == HttpMethod::Put;
    let ip_u32 = u32::from_be_bytes(ip);
    if get && path == "/api/export/file" {
        if require_session(req, ip, port, false).is_some() {
            let q = query(raw_path);
            let mut snap = [0u8; 16];
            let mut fpath = [0u8; 256];
            let ok = form_field(q, b"snap", &mut snap) && form_field(q, b"path", &mut fpath);
            let id = core::str::from_utf8(&snap[..snap.iter().position(|&b| b == 0).unwrap_or(0)])
                .ok().and_then(|t| t.parse::<u32>().ok()).unwrap_or(0);
            if !ok || id == 0 {
                json(ip, port, "HTTP/1.1 400 Bad Request", b"{\"ok\":false,\"message\":\"snap and path required\"}");
            } else {
                let mut out: *mut u8 = core::ptr::null_mut();
                let mut len: usize = 0;
                let code = unsafe { webadmin_export_file(id, fpath.as_ptr(), &mut out, &mut len) };
                send_c_buffer(ip, port, code, out, len);
            }
        }
        return true;
    }
    if get && path == "/api/export/vault-header" {
        if let Some(sid) = require_session(req, ip, port, false) {
            let mut out: *mut u8 = core::ptr::null_mut();
            let mut len: usize = 0;
            let code = unsafe { webadmin_export_vault_header(sid.as_ptr(), ip_u32, &mut out, &mut len) };
            send_c_buffer(ip, port, code, out, len);
        }
        return true;
    }
    if post && path == "/api/import/file" {
        if let Some(sid) = require_session(req, ip, port, true) {
            let mut fpath = [0u8; 256];
            let mut msg = [0u8; 256];
            let code = if form_field(query(raw_path), b"path", &mut fpath) {
                unsafe { webadmin_import_file(sid.as_ptr(), ip_u32, fpath.as_ptr(), req.body.as_ptr(), req.body.len(),
                                              msg.as_mut_ptr(), msg.len()) }
            } else {
                let t = b"path required";
                msg[..t.len()].copy_from_slice(t);
                400
            };
            json_message(ip, port, code, &msg);
        }
        return true;
    }
    if post && path == "/api/import/vault-header" {
        if let Some(sid) = require_session(req, ip, port, true) {
            let mut msg = [0u8; 256];
            let code = unsafe { webadmin_import_vault_header(sid.as_ptr(), ip_u32, req.body.as_ptr(), req.body.len(),
                                                             msg.as_mut_ptr(), msg.len()) };
            json_message(ip, port, code, &msg);
        }
        return true;
    }
    false
}

fn redirect(ip: [u8; 4], port: u16, to: &str) {
    let mut h: Vec<u8> = Vec::with_capacity(32);
    h.extend_from_slice(b"Location: ");
    h.extend_from_slice(to.as_bytes());
    send(ip, port, "HTTP/1.1 302 Found", "text/plain; charset=utf-8", core::str::from_utf8(&h).unwrap_or(""), b"");
}

fn has_session(req: &HttpRequest, ip: [u8; 4]) -> bool {
    match cookie_sid(req) {
        Some(sid) => unsafe {
            webadmin_check(sid.as_ptr(), core::ptr::null(), u32::from_be_bytes(ip), core::ptr::null_mut(), 0) == WA_OK
        },
        None => false,
    }
}

fn is_admin_path(path: &str) -> bool {
    path == "/" || path == "/index.html" || path == "/login" || path.starts_with("/api/") || path.starts_with("/admin/")
}

/// Over plain HTTP: send browsers to the HTTPS port of the same host name.
fn to_https(req: &HttpRequest, path: &str, ip: [u8; 4], port: u16) {
    let host = header(req.headers, b"Host").unwrap_or(b"");
    // Host without port; only characters valid in a host name or IPv4/IPv6 literal.
    let mut name: &[u8] = host;
    if let Some(c) = host.iter().rposition(|&b| b == b':') {
        if !host.starts_with(b"[") || host[..c].ends_with(b"]") {
            name = &host[..c];
        }
    }
    let ok = !name.is_empty() && name.len() <= 253
        && name.iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'));
    if !ok || path.starts_with("/api/") || path.starts_with("/admin/") {
        json(ip, port, "HTTP/1.1 403 Forbidden", b"{\"error\":\"https_required\"}");
        return;
    }
    let mut loc: Vec<u8> = Vec::with_capacity(320);
    loc.extend_from_slice(b"https://");
    loc.extend_from_slice(name);
    loc.extend_from_slice(b":8443");
    loc.extend_from_slice(if path == "/login" { b"/login" } else { b"/" });
    redirect(ip, port, core::str::from_utf8(&loc).unwrap_or("/"));
}

/// Handles the web admin routes; None for everything else (WebDAV etc).
pub fn handle(req: &HttpRequest, path: &str, raw_path: &str, ip: [u8; 4], port: u16, secure: bool) -> Option<i32> {
    let get = req.method == HttpMethod::Get || req.method == HttpMethod::Head;
    let post = req.method == HttpMethod::Post;
    let _ = raw_path;

    if !secure {
        if is_admin_path(path) && (get || post) {
            to_https(req, path, ip, port);
            return Some(1);
        }
        return None;
    }

    if path.starts_with("/api/export/") || path.starts_with("/api/import/") {
        if replication(req, path, raw_path, ip, port) {
            return Some(1);
        }
    }

    if get {
        let (ctype, body): (&str, &str) = match path {
            "/admin/app.css" => ("text/css; charset=utf-8", APP_CSS),
            "/admin/app.js" => ("application/javascript; charset=utf-8", APP_JS),
            "/admin/login.js" => ("application/javascript; charset=utf-8", LOGIN_JS),
            "/login" => ("text/html; charset=utf-8", LOGIN_HTML),
            _ => ("", ""),
        };
        if !ctype.is_empty() {
            send(ip, port, "HTTP/1.1 200 OK", ctype, "",
                 if req.method == HttpMethod::Head { b"" } else { body.as_bytes() });
            return Some(1);
        }
        if path == "/" || path == "/index.html" {
            if has_session(req, ip) {
                send(ip, port, "HTTP/1.1 200 OK", "text/html; charset=utf-8", "",
                     if req.method == HttpMethod::Head { b"" } else { APP_HTML.as_bytes() });
            } else {
                redirect(ip, port, "/login");
            }
            return Some(1);
        }
        if path == "/api/access" {
            access(ip, port);
            return Some(1);
        }
        if let Some(name) = path.strip_prefix("/api/") {
            if SECTIONS.contains(&name) {
                if let Some(sid) = require_session(req, ip, port, false) {
                    section(name, &sid, ip, port);
                }
            } else {
                json(ip, port, "HTTP/1.1 404 Not Found", b"{\"error\":\"unknown endpoint\"}");
            }
            return Some(1);
        }
    }

    if post && path == "/api/login" {
        login(req, ip, port);
        return Some(1);
    }
    if post {
        if let Some(name) = path.strip_prefix("/api/action/") {
            if let Some(sid) = require_session(req, ip, port, true) {
                action(req, name, &sid, ip, port);
            }
            return Some(1);
        }
    }
    if post && path == "/api/logout" {
        if let Some(sid) = require_session(req, ip, port, true) {
            unsafe { webadmin_logout(sid.as_ptr(), u32::from_be_bytes(ip)) };
            send(ip, port, "HTTP/1.1 200 OK", "application/json; charset=utf-8",
                 "Set-Cookie: yesos_sid=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0", b"{\"ok\":true}");
        }
        return Some(1);
    }
    if path.starts_with("/api/") || path.starts_with("/admin/") {
        json(ip, port, "HTTP/1.1 404 Not Found", b"{\"error\":\"unknown endpoint\"}");
        return Some(1);
    }
    None
}

// -----------------------------------------------------------------------------
// WebDAV login: HTTP Basic, accepted only over HTTPS
// -----------------------------------------------------------------------------

const DAV_REALM: &str = "DAV: 1, 2\r\nWWW-Authenticate: Basic realm=\"YesOS NAS\", charset=\"UTF-8\"";

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard base64 (padding optional) into `out`; returns the decoded length.
fn b64_decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let input = match input.iter().position(|&c| c == b'=') {
        Some(p) => {
            if !input[p..].iter().all(|&c| c == b'=') || input.len() - p > 2 {
                return None;
            }
            &input[..p]
        }
        None => input,
    };
    if input.len() % 4 == 1 {
        return None;
    }
    let mut n = 0;
    for chunk in input.chunks(4) {
        let mut v = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            v[i] = b64_val(c)?;
        }
        let bytes = [(v[0] << 2) | (v[1] >> 4), (v[1] << 4) | (v[2] >> 2), (v[2] << 6) | v[3]];
        let take = chunk.len() - 1;
        if n + take > out.len() {
            return None;
        }
        out[n..n + take].copy_from_slice(&bytes[..take]);
        n += take;
    }
    Some(n)
}

fn is_dav_write(m: HttpMethod) -> bool {
    !matches!(m, HttpMethod::Get | HttpMethod::Head | HttpMethod::Options | HttpMethod::Propfind)
}

fn dav_text(ip: [u8; 4], port: u16, status: &str, extra: &str, body: &str) {
    respond(ip, port, status, "text/plain; charset=utf-8", extra, body.as_bytes());
}

/// Guards every /dav request except OPTIONS. Returns true when a response was
/// already sent (the request must not be served).
pub fn dav_guard(req: &HttpRequest, path: &str, raw_path: &str, ip: [u8; 4], port: u16, secure: bool) -> bool {
    if !secure {
        // Basic credentials must never cross the LAN in clear.
        let host = header(req.headers, b"Host").unwrap_or(b"");
        let name: &[u8] = match host.iter().rposition(|&b| b == b':') {
            Some(c) if !host.starts_with(b"[") => &host[..c],
            _ => host,
        };
        let host_ok = !name.is_empty() && name.len() <= 253
            && name.iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
        let path_ok = raw_path.bytes().all(|b| b > 0x20 && b < 0x7f);
        if (req.method == HttpMethod::Get || req.method == HttpMethod::Head) && host_ok && path_ok {
            let mut loc: Vec<u8> = Vec::with_capacity(300);
            loc.extend_from_slice(b"Location: https://");
            loc.extend_from_slice(name);
            loc.extend_from_slice(b":8443");
            loc.extend_from_slice(raw_path.as_bytes());
            respond(ip, port, "HTTP/1.1 302 Found", "text/plain; charset=utf-8",
                    core::str::from_utf8(&loc).unwrap_or(""), b"");
        } else {
            dav_text(ip, port, "HTTP/1.1 403 Forbidden", "DAV: 1, 2",
                     "403: WebDAV needs HTTPS and an account. Use https://<nas-ip>:8443/dav/\n");
        }
        return true;
    }

    // Share = first segment after /dav/ ("" for /dav itself).
    let rest = path.strip_prefix("/dav").unwrap_or("").trim_start_matches('/');
    let seg = rest.split('/').next().unwrap_or("");
    let mut share = [0u8; 32];
    if seg.len() < share.len() {
        share[..seg.len()].copy_from_slice(seg.as_bytes());
    } else {
        share[..5].copy_from_slice(b"share");
    }

    let mut cred = [0u8; 96];
    let mut user = [0u8; 32];
    let mut pass = [0u8; 32];
    let mut have = false;
    if let Some(v) = header(req.headers, b"Authorization") {
        if v.len() > 6 && v[..6].eq_ignore_ascii_case(b"Basic ") {
            let b64 = &v[6..];
            let b64 = &b64[..b64.iter().position(|&c| c == b' ' || c == b'\t').unwrap_or(b64.len())];
            if let Some(n) = b64_decode(b64, &mut cred) {
                if let Some(colon) = cred[..n].iter().position(|&c| c == b':') {
                    let (u, p) = (&cred[..colon], &cred[colon + 1..n]);
                    if !u.is_empty() && u.len() < user.len() && p.len() < pass.len()
                        && !u.contains(&0) && !p.contains(&0) {
                        user[..u.len()].copy_from_slice(u);
                        pass[..p.len()].copy_from_slice(p);
                        have = true;
                    }
                }
            }
        }
    }
    wipe(&mut cred);
    let status = if have {
        unsafe { webdav_authorize(user.as_ptr(), pass.as_ptr(), u32::from_be_bytes(ip), share.as_ptr(), is_dav_write(req.method)) }
    } else {
        401
    };
    wipe(&mut pass);
    match status {
        0 => false,
        403 => {
            dav_text(ip, port, "HTTP/1.1 403 Forbidden", "DAV: 1, 2",
                     "403: this account has no access to that folder, or it is read-only.\n");
            true
        }
        429 => {
            dav_text(ip, port, "HTTP/1.1 429 Too Many Requests", "DAV: 1, 2\r\nRetry-After: 30",
                     "429: too many failed attempts; wait 30 s.\n");
            true
        }
        _ => {
            dav_text(ip, port, "HTTP/1.1 401 Unauthorized", DAV_REALM, "401: user name and password required.\n");
            true
        }
    }
}
