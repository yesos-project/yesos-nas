//! ==============================================================================
//! YesOS 2.0 - Native Bare-Metal Micro-TCP & WebUI Server
//! Target: riscv64gc-unknown-none-elf (#![no_std])
//! Implements RFC 793 Micro-TCP engine & Cyber-Vault Web Management Dashboard
//! ==============================================================================

use core::slice;

// -----------------------------------------------------------------------------
// TCP Protocol Constants
// -----------------------------------------------------------------------------
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

// -----------------------------------------------------------------------------
// C FFI Bindings
// -----------------------------------------------------------------------------

extern "C" {
    fn virtio_net_send_raw(frame: *const u8, len: usize) -> bool;
    fn webui_read_file(filename: *const u8, buf: *mut u8, max_len: usize) -> i32;
    fn webui_write_file(filename: *const u8, data: *const u8, size: usize) -> i32;
    fn webui_delete_file(filename: *const u8) -> i32;
    fn webui_file_exists(filename: *const u8) -> i32;
    fn webui_file_size(filename: *const u8) -> u64;
    fn webui_get_dav_file_count(share_name: *const u8) -> u32;
    fn webui_get_dav_file_info(share_name: *const u8, index: u32, out_name: *mut u8, name_max: usize, out_size: *mut u64) -> bool;
    fn webui_is_client_admitted(ip: u32) -> bool;
    fn webui_backup_children(rel: *const u8, out: *mut u8, max: usize) -> i32;
}

/// Children of a /dav/backup directory, or None if `rel` is not one.
fn backup_children(rel: &str) -> Option<Vec<u8>> {
    let mut rel_c: Vec<u8> = Vec::with_capacity(rel.len() + 1);
    rel_c.extend_from_slice(rel.as_bytes());
    rel_c.push(0);
    let mut cap = 32 * 1024;
    while cap <= 1024 * 1024 {
        let mut buf = alloc::vec![0u8; cap];
        let n = unsafe { webui_backup_children(rel_c.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        if n == -2 {
            cap *= 4;
            continue;
        }
        if n < 0 {
            return None;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
        buf.truncate(len);
        return Some(buf);
    }
    None
}

/// Multistatus for a /dav/backup directory (itself, plus children at Depth 1).
fn backup_multistatus(rel: &str, listing: &[u8], depth: u8) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 4096 + listing.len() * 4 + listing.iter().filter(|&&b| b == b'\n').count() * 512];
    let mut w = BufferWriter::new(&mut buf);
    let base = if rel.is_empty() { alloc::string::String::from("/dav/backup/") } else { alloc::format!("/dav/backup/{}/", rel) };
    let self_name = rel.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("backup");
    w.write_str("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:multistatus xmlns:D=\"DAV:\">\n");
    w.write_str("  <D:response><D:href>");
    w.write_href(&base);
    w.write_str("</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>");
    w.write_xml_text(self_name);
    w.write_str("</D:displayname></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n");
    if depth != 0 {
        for line in listing.split(|&b| b == b'\n') {
            let line = match core::str::from_utf8(line) { Ok(l) if !l.is_empty() => l, _ => continue };
            let mut parts = line.split('\t');
            let kind = parts.next().unwrap_or("");
            if kind == "d" {
                let name = parts.next().unwrap_or("");
                w.write_str("  <D:response><D:href>");
                w.write_href(&base);
                w.write_href(name);
                w.write_str("/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>");
                w.write_xml_text(name);
                w.write_str("</D:displayname></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n");
            } else if kind == "f" {
                let size = parts.next().unwrap_or("0");
                let name = parts.next().unwrap_or("");
                w.write_str("  <D:response><D:href>");
                w.write_href(&base);
                w.write_href(name);
                w.write_str("</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>");
                w.write_str(size);
                w.write_str("</D:getcontentlength><D:getcontenttype>");
                w.write_str(get_mime_type(name));
                w.write_str("</D:getcontenttype><D:displayname>");
                w.write_xml_text(name);
                w.write_str("</D:displayname></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n");
            }
        }
    }
    w.write_str("</D:multistatus>\n");
    let n = w.pos;
    buf.truncate(n);
    buf
}

/// Plain HTML index of a /dav/backup directory for browsers.
fn backup_html(rel: &str, listing: &[u8]) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 2048 + listing.len() * 8];
    let mut w = BufferWriter::new(&mut buf);
    let base = if rel.is_empty() { alloc::string::String::from("/dav/backup/") } else { alloc::format!("/dav/backup/{}/", rel) };
    w.write_str("<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\"><title>");
    w.write_xml_text(&base);
    w.write_str("</title></head><body style=\"font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px\"><h1 style=\"font-size:20px\">");
    w.write_xml_text(&base);
    w.write_str("</h1><p>Instantáneas de solo lectura.</p><ul>");
    if !rel.is_empty() {
        w.write_str("<li><a href=\"../\">..</a></li>");
    }
    for line in listing.split(|&b| b == b'\n') {
        let line = match core::str::from_utf8(line) { Ok(l) if !l.is_empty() => l, _ => continue };
        let mut parts = line.split('\t');
        let kind = parts.next().unwrap_or("");
        let (name, size) = if kind == "f" { let sz = parts.next().unwrap_or("0"); (parts.next().unwrap_or(""), Some(sz)) } else { (parts.next().unwrap_or(""), None) };
        w.write_str("<li><a href=\"");
        w.write_href(&base);
        w.write_href(name);
        if size.is_none() { w.write_str("/"); }
        w.write_str("\">");
        w.write_xml_text(name);
        if size.is_none() { w.write_str("/"); }
        w.write_str("</a>");
        if let Some(sz) = size { w.write_str(" ("); w.write_str(sz); w.write_str(" B)"); }
        w.write_str("</li>");
    }
    w.write_str("</ul></body></html>");
    let n = w.pos;
    buf.truncate(n);
    buf
}

// -----------------------------------------------------------------------------
// Stack-Based Buffer Formatter (#![no_std])
// -----------------------------------------------------------------------------
struct BufferWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufferWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        BufferWriter { buf, pos: 0 }
    }

    /// Percent-encodes everything except RFC 3986 unreserved characters and '/'.
    fn write_href(&mut self, s: &str) -> bool {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for &b in s.as_bytes() {
            let ok = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/');
            if ok {
                if self.pos >= self.buf.len() { return false; }
                self.buf[self.pos] = b;
                self.pos += 1;
            } else {
                if self.pos + 3 > self.buf.len() { return false; }
                self.buf[self.pos] = b'%';
                self.buf[self.pos + 1] = HEX[(b >> 4) as usize];
                self.buf[self.pos + 2] = HEX[(b & 15) as usize];
                self.pos += 3;
            }
        }
        true
    }

    /// Escapes text for XML character data.
    fn write_xml_text(&mut self, s: &str) -> bool {
        for ch in s.chars() {
            let ok = match ch {
                '&' => self.write_str("&amp;"),
                '<' => self.write_str("&lt;"),
                '>' => self.write_str("&gt;"),
                '"' => self.write_str("&quot;"),
                '\'' => self.write_str("&apos;"),
                _ => {
                    let mut tmp = [0u8; 4];
                    self.write_str(ch.encode_utf8(&mut tmp))
                }
            };
            if !ok { return false; }
        }
        true
    }

    fn write_str(&mut self, s: &str) -> bool {
        let bytes = s.as_bytes();
        if self.pos + bytes.len() > self.buf.len() {
            return false;
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        true
    }

    fn write_u64(&mut self, mut n: u64) -> bool {
        if n == 0 {
            return self.write_str("0");
        }
        let mut tmp = [0u8; 20];
        let mut idx = 20;
        while n > 0 {
            idx -= 1;
            tmp[idx] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        let slice = core::str::from_utf8(&tmp[idx..]).unwrap_or("");
        self.write_str(slice)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

// -----------------------------------------------------------------------------
// Internet Protocol Checksums (RFC 791 / RFC 793)
// -----------------------------------------------------------------------------
fn calc_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        let w = u16::from_be_bytes([header[i], header[i + 1]]);
        sum = sum.wrapping_add(w as u32);
        i += 2;
    }
    if i < header.len() {
        let w = (header[i] as u32) << 8;
        sum = sum.wrapping_add(w);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn calc_tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    // Pseudo-header:
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32);
    sum = sum.wrapping_add(6u32); // Protocol TCP
    sum = sum.wrapping_add(tcp_segment.len() as u32); // TCP Length

    // TCP segment (header + payload)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        let w = u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]);
        sum = sum.wrapping_add(w as u32);
        i += 2;
    }
    if i < tcp_segment.len() {
        let w = (tcp_segment[i] as u32) << 8;
        sum = sum.wrapping_add(w);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// -----------------------------------------------------------------------------
// TCP Frame Transmission
// -----------------------------------------------------------------------------
fn send_tcp_packet(
    dst_mac: &[u8],
    src_mac: &[u8],
    dst_ip: [u8; 4],
    src_ip: [u8; 4],
    dst_port: u16,
    src_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) {
    let mut frame = [0u8; 1514];
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType

    let tcp_hdr_len = 20 + options.len();
    let tcp_seg_len = tcp_hdr_len + payload.len();
    let ip_total_len = 20 + tcp_seg_len;
    if 14 + ip_total_len > frame.len() {
        return;
    }

    // IPv4 Header
    frame[14] = 0x45; // Version 4, IHL 5
    frame[15] = 0x00; // DSCP/ECN
    frame[16..18].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&0x7E57u16.to_be_bytes()); // ID
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't fragment
    frame[22] = 64;   // TTL
    frame[23] = 6;    // TCP
    frame[24..26].copy_from_slice(&[0, 0]);
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);

    let ip_chk = calc_ipv4_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_chk.to_be_bytes());

    // TCP Header
    let tcp_offset = 34;
    frame[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&ack.to_be_bytes());
    let data_offset_val = ((tcp_hdr_len / 4) as u8) << 4;
    frame[tcp_offset + 12] = data_offset_val;
    frame[tcp_offset + 13] = flags;
    frame[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&14600u16.to_be_bytes()); // Window
    frame[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&[0, 0]); // Checksum placeholder
    frame[tcp_offset + 18..tcp_offset + 20].copy_from_slice(&[0, 0]); // Urgent ptr

    if !options.is_empty() {
        frame[tcp_offset + 20..tcp_offset + 20 + options.len()].copy_from_slice(options);
    }

    if !payload.is_empty() {
        frame[tcp_offset + tcp_hdr_len..tcp_offset + tcp_seg_len].copy_from_slice(payload);
    }

    let tcp_chk = calc_tcp_checksum(src_ip, dst_ip, &frame[tcp_offset..tcp_offset + tcp_seg_len]);
    frame[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_chk.to_be_bytes());

    unsafe {
        virtio_net_send_raw(frame.as_ptr(), 14 + ip_total_len);
    }
}

/// Builds an HTTP response and queues it on the client's connection (the TCP
/// layer sequences, windows and retransmits it, then closes with FIN).
fn send_http_response_stream_ext(
    _dst_mac: &[u8],
    _src_mac: &[u8],
    dst_ip: [u8; 4],
    _src_ip: [u8; 4],
    dst_port: u16,
    _src_port: u16,
    _seq: u32,
    _ack: u32,
    status_header: &str,
    content_type: &str,
    extra_headers: &str,
    body: &[u8],
) {
    let mut hdr_buf = [0u8; 1536];
    let mut hw = BufferWriter::new(&mut hdr_buf);
    hw.write_str(status_header);
    hw.write_str("\r\nServer: YesOS-2.0-Sovereign-WebDAV\r\nContent-Type: ");
    hw.write_str(content_type);
    hw.write_str("\r\nContent-Length: ");
    hw.write_u64(body.len() as u64);
    if !extra_headers.is_empty() {
        hw.write_str("\r\n");
        hw.write_str(extra_headers);
    }
    hw.write_str("\r\nConnection: close\r\n\r\n");
    let mut out = Vec::with_capacity(hw.as_bytes().len() + body.len());
    out.extend_from_slice(hw.as_bytes());
    out.extend_from_slice(body);
    tcp_queue(dst_ip, dst_port, &out, true);
}

/// Response on the connection to (ip, port), used by the web admin module.
pub(crate) fn respond(ip: [u8; 4], port: u16, status: &str, content_type: &str, extra_headers: &str, body: &[u8]) {
    send_http_response_stream_ext(&[], &[], ip, [0; 4], port, 0, 0, 0, status, content_type, extra_headers, body);
}

pub(crate) fn header<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    header_value(headers, name)
}

fn send_http_response_stream(
    dst_mac: &[u8],
    src_mac: &[u8],
    dst_ip: [u8; 4],
    src_ip: [u8; 4],
    dst_port: u16,
    src_port: u16,
    seq: u32,
    ack: u32,
    status_header: &str,
    content_type: &str,
    body: &[u8],
) {
    send_http_response_stream_ext(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        seq, ack, status_header, content_type, "", body,
    );
}

// -----------------------------------------------------------------------------
// HTTP Request & Method Parser (WebDAV RFC 4918 Compliant)
// -----------------------------------------------------------------------------
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Head,
    Options,
    Propfind,
    Proppatch,
    Put,
    Delete,
    Mkcol,
    Lock,
    Unlock,
    Post,
    Other,
}

pub struct HttpRequest<'a> {
    pub method: HttpMethod,
    pub path: &'a str,
    pub depth: u8,
    pub headers: &'a [u8],
    pub body: &'a [u8],
}

fn parse_http_request<'a>(payload: &'a [u8]) -> Option<HttpRequest<'a>> {
    let mut i = 0;
    while i < payload.len() && payload[i] != b' ' {
        i += 1;
    }
    if i == 0 || i >= payload.len() {
        return None;
    }
    let method_slice = &payload[..i];
    let method = match method_slice {
        b"GET" => HttpMethod::Get,
        b"HEAD" => HttpMethod::Head,
        b"OPTIONS" => HttpMethod::Options,
        b"PROPFIND" => HttpMethod::Propfind,
        b"PROPPATCH" => HttpMethod::Proppatch,
        b"PUT" => HttpMethod::Put,
        b"DELETE" => HttpMethod::Delete,
        b"MKCOL" => HttpMethod::Mkcol,
        b"LOCK" => HttpMethod::Lock,
        b"UNLOCK" => HttpMethod::Unlock,
        b"POST" => HttpMethod::Post,
        _ => HttpMethod::Other,
    };

    while i < payload.len() && payload[i] == b' ' {
        i += 1;
    }
    let path_start = i;
    while i < payload.len() && payload[i] != b' ' && payload[i] != b'\r' && payload[i] != b'\n' {
        i += 1;
    }
    if path_start >= i {
        return None;
    }
    let path = core::str::from_utf8(&payload[path_start..i]).ok()?;

    // Locate header end and body start
    let mut header_end = payload.len();
    let mut body_start = payload.len();
    for j in 0..payload.len().saturating_sub(3) {
        if payload[j] == b'\r' && payload[j+1] == b'\n' && payload[j+2] == b'\r' && payload[j+3] == b'\n' {
            header_end = j;
            body_start = j + 4;
            break;
        }
    }
    if body_start == payload.len() {
        for j in 0..payload.len().saturating_sub(1) {
            if payload[j] == b'\n' && payload[j+1] == b'\n' {
                header_end = j;
                body_start = j + 2;
                break;
            }
        }
    }

    // Parse Depth header (default: 1)
    let mut depth: u8 = 1;
    let headers = &payload[..header_end];
    if headers.len() >= 6 {
        for k in 0..headers.len() - 5 {
            if (headers[k] == b'D' || headers[k] == b'd') &&
               (headers[k+1] == b'E' || headers[k+1] == b'e') &&
               (headers[k+2] == b'P' || headers[k+2] == b'p') &&
               (headers[k+3] == b'T' || headers[k+3] == b't') &&
               (headers[k+4] == b'H' || headers[k+4] == b'h') &&
               headers[k+5] == b':' {
                let mut d_idx = k + 6;
                while d_idx < headers.len() && (headers[d_idx] == b' ' || headers[d_idx] == b'\t') {
                    d_idx += 1;
                }
                if d_idx < headers.len() && headers[d_idx] == b'0' {
                    depth = 0;
                }
                break;
            }
        }
    }

    let body = if body_start < payload.len() {
        &payload[body_start..]
    } else {
        &[]
    };

    Some(HttpRequest { method, path, depth, headers, body })
}

// -----------------------------------------------------------------------------
// WebDAV RFC 4918 Helpers & XML Multistatus Definitions
// -----------------------------------------------------------------------------
fn get_mime_type(filename: &str) -> &'static str {
    if filename.ends_with(".png") || filename.ends_with(".PNG") {
        "image/png"
    } else if filename.ends_with(".jpg") || filename.ends_with(".jpeg") || filename.ends_with(".JPG") || filename.ends_with(".JPEG") {
        "image/jpeg"
    } else if filename.ends_with(".gif") || filename.ends_with(".GIF") {
        "image/gif"
    } else if filename.ends_with(".bmp") || filename.ends_with(".BMP") {
        "image/bmp"
    } else if filename.ends_with(".txt") || filename.ends_with(".TXT") {
        "text/plain; charset=utf-8"
    } else if filename.ends_with(".cfg") || filename.ends_with(".CFG") {
        "text/plain; charset=utf-8"
    } else if filename.ends_with(".doc") || filename.ends_with(".DOC") {
        "text/plain; charset=utf-8"
    } else if filename.ends_with(".doldoc") || filename.ends_with(".DOLDOC") {
        "text/plain; charset=utf-8"
    } else if filename.ends_with(".html") || filename.ends_with(".htm") {
        "text/html; charset=utf-8"
    } else if filename.ends_with(".json") {
        "application/json"
    } else if filename.ends_with(".xml") {
        "application/xml; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn is_collection_path(p: &str) -> bool {
    let p_trim = p.trim_end_matches('/');
    p_trim == "/dav" || p_trim == "/dav/share" || p_trim == "/dav/vault" || p_trim == "/dav/media" || p_trim == "/dav/backup"
}

fn decode_url_path<'a>(src: &'a str, out_buf: &'a mut [u8]) -> &'a str {
    let bytes = src.as_bytes();
    let mut i = 0;
    let mut o = 0;
    while i < bytes.len() && o < out_buf.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = match bytes[i + 1] {
                b'0'..=b'9' => bytes[i + 1] - b'0',
                b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
                b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
                _ => 255,
            };
            let h2 = match bytes[i + 2] {
                b'0'..=b'9' => bytes[i + 2] - b'0',
                b'a'..=b'f' => bytes[i + 2] - b'a' + 10,
                b'A'..=b'F' => bytes[i + 2] - b'A' + 10,
                _ => 255,
            };
            if h1 != 255 && h2 != 255 {
                out_buf[o] = (h1 << 4) | h2;
                o += 1;
                i += 3;
                continue;
            }
        }
        out_buf[o] = bytes[i];
        o += 1;
        i += 1;
    }
    core::str::from_utf8(&out_buf[..o]).unwrap_or(src)
}

const WEBDAV_ROOT_DEPTH0: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>YesOS NAS Root</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
"#;

const WEBDAV_SHARE_DEPTH0: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/share/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>share</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
"#;

const WEBDAV_VAULT_DEPTH0: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/vault/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>vault</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
"#;

const WEBDAV_MEDIA_DEPTH0: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/media/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>media</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
"#;

const WEBDAV_BACKUP_DEPTH0: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/backup/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>backup</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
"#;

const WEBDAV_ROOT_MULTISTATUS: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>YesOS NAS Root</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/share/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>share</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/media/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>media</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/backup/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>backup</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>
"#;

// Listings come from the RedSea directory (webui_get_dav_file_*); no
// fabricated example entries. The vault share is never listed.
fn write_share_multistatus_depth1<'a>(buf: &'a mut [u8]) -> &'a [u8] {
    write_generic_multistatus_depth1(buf, "share", b"share\0")
}

fn write_vault_multistatus_depth1<'a>(buf: &'a mut [u8]) -> &'a [u8] {
    write_generic_multistatus_depth1(buf, "vault", b"vault\0")
}

fn write_generic_multistatus_depth1<'a>(buf: &'a mut [u8], share_name: &str, share_c: &[u8]) -> &'a [u8] {
    let mut w = BufferWriter::new(buf);
    w.write_str(r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/"#);
    w.write_str(share_name);
    w.write_str(r#"/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>"#);
    w.write_str(share_name);
    w.write_str(r#"</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
"#);

    let count = unsafe { webui_get_dav_file_count(share_c.as_ptr()) };
    for idx in 0..count {
        let mut name_buf = [0u8; 256];
        let mut fsize = 0u64;
        let ok = unsafe {
            webui_get_dav_file_info(
                share_c.as_ptr(),
                idx,
                name_buf.as_mut_ptr(),
                name_buf.len(),
                &mut fsize,
            )
        };
        if ok {
            let mut end = 0;
            while end < name_buf.len() && name_buf[end] != 0 {
                end += 1;
            }
            if let Ok(fname) = core::str::from_utf8(&name_buf[..end]) {
                let mime = get_mime_type(fname);
                w.write_str("  <D:response>\n    <D:href>/dav/");
                w.write_str(share_name);
                w.write_str("/");
                w.write_href(fname);
                w.write_str("</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:resourcetype/>\n        <D:getcontentlength>");
                w.write_u64(fsize);
                w.write_str("</D:getcontentlength>\n        <D:getcontenttype>");
                w.write_str(mime);
                w.write_str("</D:getcontenttype>\n        <D:displayname>");
                w.write_xml_text(fname);
                w.write_str("</D:displayname>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n");
            }
        }
    }
    w.write_str("</D:multistatus>\n");
    let len = w.as_bytes().len();
    &buf[..len]
}

const WEBDAV_EXPLORER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>YesOS 2.0 // WebDAV Network Storage</title>
<style>
:root { --bg:#0a0c10; --card:#151821; --border:#1e2330; --text:#e2e8f0; --cyan:#00f0ff; --muted:#64748b; --emerald:#10b981; }
body { background:var(--bg); color:var(--text); font-family:monospace; padding:32px; max-width:900px; margin:0 auto; }
h1 { color:var(--cyan); font-size:22px; margin-bottom:8px; }
.sub { color:var(--muted); margin-bottom:24px; font-size:13px; }
.card { background:var(--card); border:1px solid var(--border); border-radius:6px; padding:20px; margin-bottom:20px; }
table { width:100%; border-collapse:collapse; margin-top:12px; }
th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-size:13px; }
th { color:var(--muted); font-weight:normal; }
a { color:var(--cyan); text-decoration:none; }
a:hover { text-decoration:underline; }
.badge { display:inline-block; padding:2px 6px; border-radius:3px; font-size:11px; font-weight:bold; }
.badge-rw { background:#064e3b; color:#34d399; }
.badge-lock { background:#7f1d1d; color:#f87171; }
.guide { background:#0f172a; border-left:3px solid var(--cyan); padding:12px 16px; margin-top:16px; font-size:12px; color:#cbd5e1; }
code { color:var(--cyan); background:#06080c; padding:2px 6px; border-radius:3px; }
.nav-bar { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; }
.nav-btn { display:inline-block; background:#161a22; border:1px solid #2a3142; color:var(--cyan); padding:6px 14px; border-radius:4px; text-decoration:none; font-size:12px; font-weight:bold; transition:all 0.15s ease; }
.nav-btn:hover { background:#222838; border-color:var(--cyan); }
</style>
</head>
<body>
<div class="nav-bar">
  <a href="/" class="nav-btn">&larr; Return to Cyber-Vault Dashboard</a>
  <span style="font-size:11px; color:var(--muted);">RFC 4918 Compliant • Ring 0 Machine-Mode</span>
</div>

<h1>YesOS 2.0 Sovereign WebDAV Network Mount</h1>
<div class="sub">RFC 4918 WebDAV Server running bare-metal on RISC-V M-Mode. Zero WAN Exposure.</div>

<div class="card">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <span style="font-weight:bold; font-size:15px;">Network Shared Folders</span>
    <span style="color:var(--cyan); font-size:12px;">DAV Level 1, 2 Compliant</span>
  </div>
  <table>
    <thead><tr><th>Folder Name</th><th>Access</th><th>Filesystem</th><th>Mount URL</th></tr></thead>
    <tbody>
      <tr>
        <td><b><a href="/dav/vault/">vault/</a></b></td>
        <td><span class="badge badge-lock">Encrypted Pool</span></td>
        <td>RedSea 64-bit CoW</td>
        <td><code class="dav-mount-link" data-path="/dav/vault/">http://10.0.2.15/dav/vault/</code></td>
      </tr>
      <tr>
        <td><b><a href="/dav/share/">share/</a></b></td>
        <td><span class="badge badge-rw">Read / Write</span></td>
        <td>RedSea Extent-Alloc</td>
        <td><code class="dav-mount-link" data-path="/dav/share/">http://10.0.2.15/dav/share/</code></td>
      </tr>
      <tr>
        <td><b><a href="/dav/media/">media/</a></b></td>
        <td><span class="badge badge-rw">Streaming</span></td>
        <td>RedSea Linear</td>
        <td><code class="dav-mount-link" data-path="/dav/media/">http://10.0.2.15/dav/media/</code></td>
      </tr>
      <tr>
        <td><b><a href="/dav/backup/">backup/</a></b></td>
        <td><span class="badge badge-lock">WORM Immutable</span></td>
        <td>RedSea Snapshots</td>
        <td><code class="dav-mount-link" data-path="/dav/backup/">http://10.0.2.15/dav/backup/</code></td>
      </tr>
    </tbody>
  </table>

  <div class="guide">
    <b>How to mount this NAS folder on your computer:</b><br><br>
    - <b>Windows:</b> File Explorer -&gt; <i>This PC</i> -&gt; <i>Map network drive</i> -&gt; Folder: <code class="dav-mount-url">http://10.0.2.15/dav/</code><br>
    - <b>macOS:</b> Finder -&gt; <i>Go</i> -&gt; <i>Connect to Server (Cmd+K)</i> -&gt; <code class="dav-mount-url">http://10.0.2.15/dav/</code><br>
    - <b>Linux:</b> Files (Nautilus) -&gt; <i>Other Locations</i> -&gt; <i>Connect to Server</i>: <code class="dav-mount-scheme">dav://10.0.2.15/dav/</code><br>
    - <b>Mobile:</b> Cx File Explorer / Documents -&gt; <i>Add WebDAV Storage</i>: <code class="dav-mount-url">http://10.0.2.15/dav/</code>
  </div>
</div>
<script>
const origin = window.location.origin || 'http://10.0.2.15';
const host = window.location.hostname || '10.0.2.15';
const port = window.location.port ? (':' + window.location.port) : '';
document.querySelectorAll('.dav-mount-link').forEach(el => {
  const p = el.getAttribute('data-path') || '';
  el.innerText = origin + p;
});
document.querySelectorAll('.dav-mount-url').forEach(el => el.innerText = origin + '/dav/');
document.querySelectorAll('.dav-mount-scheme').forEach(el => el.innerText = 'dav://' + host + port + '/dav/');
</script>
</body>
</html>
"#;

// -----------------------------------------------------------------------------
// Native Cyber-Vault WebUI HTML Dashboard
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// TCP Packet Dispatcher & HTTP Routing
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// Minimal stateful TCP for the HTTP/WebDAV server
//
// One request per connection (responses carry "Connection: close"):
//   SYN -> SYN-ACK (random ISN) -> in-order reassembly of the request
//   (Content-Length / chunked, Expect: 100-continue) -> response queued and
//   sent within the client's receive window -> FIN. Lost segments are
//   recovered by go-back-N retransmission from rust_tcp_tick().
// -----------------------------------------------------------------------------

use alloc::vec::Vec;

const TCP_MAX_CONNS: usize = 8;
const TCP_SEG: usize = 1400;
const TCP_MAX_REQUEST: usize = 16 * 1024 * 1024 + 16 * 1024;
const TCP_RTO_MS: u64 = 300;
const TCP_MAX_RETRIES: u32 = 40;
const TCP_IDLE_MS: u64 = 60_000;

extern "C" {
    fn timer_get_uptime_ms() -> u64;
}

struct TcpConn {
    cmac: [u8; 6],
    omac: [u8; 6],
    cip: [u8; 4],
    oip: [u8; 4],
    cport: u16,
    oport: u16,
    rcv_nxt: u32,
    iss: u32,
    rx: Vec<u8>,
    request_taken: bool,
    continue_sent: bool,
    tx: Vec<u8>,
    tx_final: bool,
    una: usize,
    nxt: usize,
    fin_sent: bool,
    rwnd: u32,
    last_ms: u64,
    retries: u32,
    /// TLS state for HTTPS connections (port 8443); `rx` then holds plaintext.
    tls: Option<alloc::boxed::Box<crate::tls::TlsConn>>,
}

pub(crate) const HTTPS_PORT: u16 = 8443;

fn wipe_vec(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    v.clear();
    v.shrink_to_fit();
}

/// Queues application bytes: encrypted for HTTPS, as-is for HTTP.
fn conn_write_app(c: &mut TcpConn, data: &[u8], final_: bool) {
    match c.tls.as_mut() {
        Some(t) => {
            let mut out = Vec::new();
            if !t.write(data, final_, &mut out) {
                t.failed = true;
            }
            c.tx.extend_from_slice(&out);
        }
        None => c.tx.extend_from_slice(data),
    }
    if final_ {
        c.tx_final = true;
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        for b in self.rx.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

static TCP_CONNS: yesos_core::crypto::Locked<[Option<TcpConn>; TCP_MAX_CONNS]> =
    yesos_core::crypto::Locked::new([const { None }; TCP_MAX_CONNS]);

fn now_ms() -> u64 {
    unsafe { timer_get_uptime_ms() }
}

fn find_conn(conns: &mut [Option<TcpConn>; TCP_MAX_CONNS], ip: [u8; 4], port: u16) -> Option<usize> {
    conns.iter().position(|c| matches!(c, Some(x) if x.cip == ip && x.cport == port))
}

fn conn_send(c: &TcpConn, seq: u32, flags: u8, payload: &[u8]) {
    send_tcp_packet(&c.cmac, &c.omac, c.cip, c.oip, c.cport, c.oport, seq, c.rcv_nxt, flags, &[], payload);
}

/// Sends queued data within the client's window; FIN after the final byte.
fn conn_pump(c: &mut TcpConn) {
    let wnd = if c.rwnd == 0 { TCP_SEG } else { c.rwnd as usize };
    while c.nxt < c.tx.len() && c.nxt - c.una < wnd {
        let take = core::cmp::min(TCP_SEG, c.tx.len() - c.nxt);
        let last = c.nxt + take == c.tx.len();
        let mut flags = TCP_ACK;
        if last {
            flags |= TCP_PSH;
            if c.tx_final {
                flags |= TCP_FIN;
                c.fin_sent = true;
            }
        }
        let seq = c.iss.wrapping_add(1).wrapping_add(c.nxt as u32);
        let data = &c.tx[c.nxt..c.nxt + take];
        conn_send(c, seq, flags, data);
        c.nxt += take;
    }
    if c.tx_final && !c.fin_sent && c.nxt == c.tx.len() {
        let seq = c.iss.wrapping_add(1).wrapping_add(c.tx.len() as u32);
        conn_send(c, seq, TCP_ACK | TCP_FIN, &[]);
        c.fin_sent = true;
    }
}

/// Queues response bytes on the connection to (ip, port) and starts sending.
fn tcp_queue(ip: [u8; 4], port: u16, data: &[u8], final_: bool) -> bool {
    TCP_CONNS.with(|conns| match find_conn(conns, ip, port) {
        Some(i) => {
            let c = conns[i].as_mut().unwrap();
            conn_write_app(c, data, final_);
            c.last_ms = now_ms();
            conn_pump(c);
            true
        }
        None => false,
    })
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| &h[i..i + n.len()] == n)
}

fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() > name.len() && line[name.len()] == b':' && line[..name.len()].eq_ignore_ascii_case(name) {
            let mut v = &line[name.len() + 1..];
            while let [b' ' | b'\t', rest @ ..] = v {
                v = rest;
            }
            return Some(v);
        }
    }
    None
}

fn parse_usize(v: &[u8]) -> Option<usize> {
    let mut n: usize = 0;
    if v.is_empty() {
        return None;
    }
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(n)
}

/// Decodes a complete chunked body; None while incomplete or malformed.
fn decode_chunked(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut p = 0;
    loop {
        let eol = find_subslice(&body[p..], b"\r\n")? + p;
        let size_str = body[p..eol].split(|&b| b == b';').next()?;
        let mut size: usize = 0;
        for &b in size_str {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                b' ' => continue,
                _ => return None,
            } as usize;
            size = size.checked_mul(16)?.checked_add(d)?;
        }
        p = eol + 2;
        if size == 0 {
            return if find_subslice(&body[p..], b"\r\n").is_some() { Some(out) } else { None };
        }
        if p + size + 2 > body.len() || out.len() + size > TCP_MAX_REQUEST {
            return None;
        }
        out.extend_from_slice(&body[p..p + size]);
        p += size + 2;
    }
}

enum RxState {
    Incomplete { send_continue: bool },
    Complete(Vec<u8>),
    TooLarge,
}

/// Decides whether `rx` holds a complete HTTP request.
fn request_state(rx: &[u8], continue_sent: bool) -> RxState {
    if rx.len() > TCP_MAX_REQUEST {
        return RxState::TooLarge;
    }
    let hdr_end = match find_subslice(rx, b"\r\n\r\n") {
        Some(i) => i + 4,
        None => return RxState::Incomplete { send_continue: false },
    };
    let headers = &rx[..hdr_end];
    let body = &rx[hdr_end..];
    let expect = header_value(headers, b"Expect").map_or(false, |v| v.eq_ignore_ascii_case(b"100-continue"));
    if header_value(headers, b"Transfer-Encoding").map_or(false, |v| v.eq_ignore_ascii_case(b"chunked")) {
        return match decode_chunked(body) {
            Some(decoded) => {
                let mut full = Vec::with_capacity(hdr_end + decoded.len());
                full.extend_from_slice(headers);
                full.extend_from_slice(&decoded);
                RxState::Complete(full)
            }
            None => RxState::Incomplete { send_continue: expect && !continue_sent },
        };
    }
    let want = header_value(headers, b"Content-Length").and_then(parse_usize).unwrap_or(0);
    if want > TCP_MAX_REQUEST {
        return RxState::TooLarge;
    }
    if body.len() >= want {
        return RxState::Complete(rx[..hdr_end + want].to_vec());
    }
    RxState::Incomplete { send_continue: expect && !continue_sent && body.is_empty() }
}

fn random_iss(port: u16) -> u32 {
    let mut b = [0u8; 4];
    if yesos_core::crypto::rng_fill(&mut b) == 0 {
        u32::from_le_bytes(b)
    } else {
        // DRBG not seeded yet (very early boot): still avoid a fixed ISN.
        let mut t: u64;
        unsafe { core::arch::asm!("rdtime {0}", out(reg) t) };
        (t as u32) ^ ((port as u32) << 16) ^ 0x5945_5330
    }
}

#[no_mangle]
pub extern "C" fn rust_handle_tcp(buf: *const u8, len: usize, ip_hdr_len: usize) -> i32 {
    if buf.is_null() || len < 14 + ip_hdr_len + 20 {
        return 0;
    }
    let frame = unsafe { slice::from_raw_parts(buf, len) };
    let client_mac = &frame[6..12];
    let our_mac = &frame[0..6];
    let ip = &frame[14..14 + ip_hdr_len];
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len > len - 14 || total_len < ip_hdr_len + 20 {
        return 0;
    }
    let client_ip = [ip[12], ip[13], ip[14], ip[15]];
    let our_ip = [ip[16], ip[17], ip[18], ip[19]];
    let tcp_offset = 14 + ip_hdr_len;
    let tcp = &frame[tcp_offset..14 + total_len];
    let client_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let client_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let client_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]) as u32;
    if data_offset < 20 || data_offset > tcp.len() {
        return 0;
    }
    if dst_port != 80 && dst_port != 8080 && dst_port != HTTPS_PORT {
        return 0;
    }
    let payload = &tcp[data_offset..];
    let mut cmac = [0u8; 6];
    cmac.copy_from_slice(client_mac);
    let mut omac = [0u8; 6];
    omac.copy_from_slice(our_mac);

    // RST: forget the connection
    if (flags & TCP_RST) != 0 {
        TCP_CONNS.with(|conns| {
            if let Some(i) = find_conn(conns, client_ip, client_port) {
                conns[i] = None;
            }
        });
        return 1;
    }

    // SYN: new connection (a retransmitted SYN restarts it)
    if (flags & TCP_SYN) != 0 {
        let tls = if dst_port == HTTPS_PORT {
            match crate::tls::TlsConn::new() {
                Some(t) => Some(t),
                None => return 1, // TLS not configured: ignore (no listener)
            }
        } else {
            None
        };
        let iss = random_iss(client_port);
        let now = now_ms();
        TCP_CONNS.with(|conns| {
            let slot = find_conn(conns, client_ip, client_port)
                .or_else(|| conns.iter().position(|c| c.is_none()))
                .unwrap_or_else(|| {
                    // evict the least recently active connection
                    let mut oldest = 0;
                    for (i, c) in conns.iter().enumerate() {
                        if let (Some(a), Some(b)) = (c, &conns[oldest]) {
                            if a.last_ms < b.last_ms {
                                oldest = i;
                            }
                        }
                    }
                    oldest
                });
            conns[slot] = Some(TcpConn {
                cmac, omac, cip: client_ip, oip: our_ip, cport: client_port, oport: dst_port,
                rcv_nxt: client_seq.wrapping_add(1), iss, rx: Vec::new(), request_taken: false,
                continue_sent: false, tx: Vec::new(), tx_final: false, una: 0, nxt: 0, fin_sent: false,
                rwnd: window, last_ms: now, retries: 0, tls,
            });
        });
        let mss_opt = [0x02, 0x04, 0x05, 0xb4]; // MSS = 1460
        send_tcp_packet(client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        iss, client_seq.wrapping_add(1), TCP_SYN | TCP_ACK, &mss_opt, &[]);
        return 1;
    }

    // Everything else belongs to a known connection; otherwise reset it.
    let mut request: Option<Vec<u8>> = None;
    let mut too_large = false;
    let known = TCP_CONNS.with(|conns| {
        let i = match find_conn(conns, client_ip, client_port) {
            Some(i) => i,
            None => return false,
        };
        let mut drop_conn = false;
        {
            let c = conns[i].as_mut().unwrap();
            c.last_ms = now_ms();

            // ACK processing: advance the send window
            if (flags & TCP_ACK) != 0 {
                c.rwnd = window;
                let acked = client_ack.wrapping_sub(c.iss.wrapping_add(1)) as usize;
                if acked <= c.tx.len() + 1 {
                    let data_acked = core::cmp::min(acked, c.tx.len());
                    if data_acked > c.una {
                        c.una = data_acked;
                        c.retries = 0;
                    }
                    if c.nxt < c.una {
                        c.nxt = c.una;
                    }
                    if c.fin_sent && acked == c.tx.len() + 1 {
                        drop_conn = true; // our FIN acknowledged: done
                    }
                }
            }

            // Incoming data, in order only
            if !drop_conn && !payload.is_empty() {
                if client_seq == c.rcv_nxt && !c.request_taken {
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(payload.len() as u32);
                    let mut have_data = true;
                    if let Some(t) = c.tls.as_mut() {
                        let mut out = Vec::new();
                        let mut plain = Vec::new();
                        t.feed(payload, &mut out, &mut plain);
                        let failed = t.failed;
                        c.tx.extend_from_slice(&out);
                        c.rx.extend_from_slice(&plain);
                        for b in plain.iter_mut() {
                            unsafe { core::ptr::write_volatile(b, 0) };
                        }
                        if failed {
                            // Alert (if any) goes out, then the connection closes.
                            c.request_taken = true;
                            c.tx_final = true;
                        }
                        have_data = !failed && !c.rx.is_empty();
                        if !have_data {
                            conn_pump(c);
                            if !failed {
                                let seq = c.iss.wrapping_add(1).wrapping_add(c.nxt as u32);
                                conn_send(c, seq, TCP_ACK, &[]);
                            }
                        }
                    } else {
                        c.rx.extend_from_slice(payload);
                    }
                    if have_data { match request_state(&c.rx, c.continue_sent) {
                        RxState::Complete(req) => {
                            c.request_taken = true;
                            wipe_vec(&mut c.rx);
                            request = Some(req);
                        }
                        RxState::TooLarge => {
                            c.request_taken = true;
                            wipe_vec(&mut c.rx);
                            too_large = true;
                        }
                        RxState::Incomplete { send_continue } => {
                            if send_continue {
                                c.continue_sent = true;
                                conn_write_app(c, b"HTTP/1.1 100 Continue\r\n\r\n", false);
                                conn_pump(c);
                            } else {
                                let seq = c.iss.wrapping_add(1).wrapping_add(c.nxt as u32);
                                conn_send(c, seq, TCP_ACK, &[]);
                            }
                        }
                    } }
                } else {
                    // duplicate or out of order: re-ACK what we have
                    let seq = c.iss.wrapping_add(1).wrapping_add(c.nxt as u32);
                    conn_send(c, seq, TCP_ACK, &[]);
                }
            }

            // Client FIN
            if !drop_conn && (flags & TCP_FIN) != 0 {
                let fin_seq = client_seq.wrapping_add(payload.len() as u32);
                if fin_seq == c.rcv_nxt {
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
                }
                let seq = c.iss.wrapping_add(1).wrapping_add(c.nxt as u32);
                conn_send(c, seq, TCP_ACK, &[]);
                if c.fin_sent && c.una == c.tx.len() {
                    drop_conn = true;
                }
            }

            if !drop_conn {
                conn_pump(c);
            }
        }
        if drop_conn {
            conns[i] = None;
        }
        true
    });

    if !known {
        if (flags & TCP_FIN) != 0 || !payload.is_empty() {
            send_tcp_packet(client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                            client_ack, client_seq.wrapping_add(payload.len() as u32), TCP_RST | TCP_ACK, &[], &[]);
        }
        return 1;
    }
    if too_large {
        send_http_response_stream_ext(client_mac, our_mac, client_ip, our_ip, client_port, dst_port, 0, 0,
            "HTTP/1.1 413 Payload Too Large", "text/plain; charset=utf-8", "",
            b"413: maximum upload size is 16 MiB\n");
        return 1;
    }
    if let Some(mut req) = request {
        // Outside the connection lock: responses re-enter it to queue data.
        let r = process_http(client_mac, our_mac, client_ip, our_ip, client_port, dst_port, &req);
        wipe_vec(&mut req); // may hold a login password
        return r;
    }
    1
}

/// Retransmissions and idle cleanup; called from the kernel main loop.
#[no_mangle]
pub extern "C" fn rust_tcp_tick() {
    let now = now_ms();
    TCP_CONNS.with(|conns| {
        for slot in conns.iter_mut() {
            let mut drop_conn = false;
            if let Some(c) = slot.as_mut() {
                let pending = c.una < c.nxt || (c.fin_sent && c.una == c.tx.len());
                if pending && now.wrapping_sub(c.last_ms) > TCP_RTO_MS {
                    c.retries += 1;
                    if c.retries > TCP_MAX_RETRIES {
                        drop_conn = true;
                    } else {
                        // go-back-N from the first unacknowledged byte
                        c.nxt = c.una;
                        c.fin_sent = false;
                        c.last_ms = now;
                        conn_pump(c);
                    }
                } else if now.wrapping_sub(c.last_ms) > TCP_IDLE_MS {
                    drop_conn = true;
                }
            }
            if drop_conn {
                *slot = None;
            }
        }
    });
}


/// Handles one complete HTTP request (assembled by the TCP layer). Responses
/// are queued on the connection; seq/ack are filled in by the TCP layer.
fn process_http(
    client_mac: &[u8],
    our_mac: &[u8],
    client_ip: [u8; 4],
    our_ip: [u8; 4],
    client_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> i32 {
    let resp_seq = 0u32;
    let resp_ack = 0u32;

        if let Some(req) = parse_http_request(payload) {
            let raw_path = req.path;
            let raw_no_query = match raw_path.find('?') {
                Some(q) => &raw_path[..q],
                None => raw_path,
            };
            let mut url_dec_buf = [0u8; 256];
            let clean_path = decode_url_path(raw_no_query, &mut url_dec_buf);
            let path = clean_path;

            // Security: Reject Directory Traversal attempts (CWE-22)
            if clean_path.contains("..") || clean_path.contains('\\') {
                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 400 Bad Request", "text/plain; charset=utf-8",
                    "DAV: 1, 2",
                    b"400 Bad Request: Path traversal rejected by Cyber-Vault\n",
                );
                return 1;
            }

            // Web administration (login, sessions, admin panel and its API)
            if let Some(r) = crate::webadmin::handle(&req, clean_path, raw_path, client_ip, client_port, dst_port == HTTPS_PORT) {
                return r;
            }

            // WebDAV requires a NAS account (HTTP Basic over HTTPS)
            if (clean_path == "/dav" || clean_path.starts_with("/dav/")) && req.method != HttpMethod::Options
                && crate::webadmin::dav_guard(&req, clean_path, raw_path, client_ip, client_port, dst_port == HTTPS_PORT)
            {
                return 1;
            }

            // /dav/backup is a read-only tree of snapshots
            let in_backup = clean_path == "/dav/backup" || clean_path.starts_with("/dav/backup/");
            if in_backup {
                let rel = clean_path.trim_start_matches("/dav/backup").trim_matches('/');
                let read_only_method = matches!(req.method, HttpMethod::Get | HttpMethod::Head | HttpMethod::Propfind | HttpMethod::Options);
                if !read_only_method {
                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port, resp_seq, resp_ack,
                        "HTTP/1.1 403 Forbidden", "text/plain; charset=utf-8", "DAV: 1, 2",
                        b"403 Forbidden: /backup is read-only (snapshots are managed from the panel or console)\n",
                    );
                    return 1;
                }
                if req.method != HttpMethod::Options {
                    if let Some(listing) = backup_children(rel) {
                        if req.method == HttpMethod::Propfind {
                            let xml = backup_multistatus(rel, &listing, req.depth);
                            send_http_response_stream_ext(
                                client_mac, our_mac, client_ip, our_ip, client_port, dst_port, resp_seq, resp_ack,
                                "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                                "DAV: 1, 2\r\nMS-Author-Via: DAV", &xml,
                            );
                        } else {
                            let html = backup_html(rel, &listing);
                            send_http_response_stream_ext(
                                client_mac, our_mac, client_ip, our_ip, client_port, dst_port, resp_seq, resp_ack,
                                "HTTP/1.1 200 OK", "text/html; charset=utf-8", "DAV: 1, 2",
                                if req.method == HttpMethod::Head { b"" } else { &html },
                            );
                        }
                        return 1;
                    }
                    // not a directory: the regular file handlers below serve it
                }
            }

            // Security: Zero-Trust Admission on /dav/vault/ (CWE-284)
            let ip_u32 = u32::from_be_bytes(client_ip);
            if (clean_path.starts_with("/dav/vault/") || clean_path == "/dav/vault") && !unsafe { webui_is_client_admitted(ip_u32) } {
                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 403 Forbidden", "text/plain; charset=utf-8",
                    "DAV: 1, 2",
                    b"403 Forbidden: Zero-Trust Vault requires physical IP admission in YesOS GUI\n",
                );
                return 1;
            }

            // Handle WebDAV OPTIONS request (e.g. OPTIONS * or OPTIONS /dav)
            if req.method == HttpMethod::Options {
                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 200 OK", "text/plain",
                    "DAV: 1, 2\r\nMS-Author-Via: DAV\r\nAllow: OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, LOCK, UNLOCK",
                    b"",
                );
                return 1;
            }

            // Handle WebDAV LOCK request
            if req.method == HttpMethod::Lock {
                let mut lock_buf = [0u8; 512];
                let mut lw = BufferWriter::new(&mut lock_buf);
                lw.write_str("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:prop xmlns:D=\"DAV:\">\n  <D:lockdiscovery>\n    <D:activelock>\n      <D:locktype><D:write/></D:locktype>\n      <D:lockscope><D:exclusive/></D:lockscope>\n      <D:depth>0</D:depth>\n      <D:timeout>Second-3600</D:timeout>\n      <D:locktoken><D:href>opaquelocktoken:yesos-lock-4918</D:href></D:locktoken>\n      <D:lockroot><D:href>");
                lw.write_str(clean_path);
                lw.write_str("</D:href></D:lockroot>\n    </D:activelock>\n  </D:lockdiscovery>\n</D:prop>\n");

                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 200 OK", "application/xml; charset=utf-8",
                    "DAV: 1, 2\r\nLock-Token: <opaquelocktoken:yesos-lock-4918>",
                    lw.as_bytes(),
                );
                return 1;
            }

            // Handle WebDAV UNLOCK request
            if req.method == HttpMethod::Unlock {
                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 204 No Content", "text/plain",
                    "DAV: 1, 2",
                    b"",
                );
                return 1;
            }

            // Handle WebDAV PROPPATCH request
            if req.method == HttpMethod::Proppatch {
                let mut pp_buf = [0u8; 512];
                let mut pw = BufferWriter::new(&mut pp_buf);
                pw.write_str("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:multistatus xmlns:D=\"DAV:\">\n  <D:response>\n    <D:href>");
                pw.write_str(clean_path);
                pw.write_str("</D:href>\n    <D:propstat>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n</D:multistatus>\n");

                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                    "DAV: 1, 2",
                    pw.as_bytes(),
                );
                return 1;
            }

            // Handle WebDAV MKCOL request
            if req.method == HttpMethod::Mkcol {
                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 201 Created", "text/plain",
                    "DAV: 1, 2",
                    b"Created",
                );
                return 1;
            }

            // Handle WebDAV PUT request (uploading binary files / images)
            if req.method == HttpMethod::Put {
                if clean_path.starts_with("/dav/backup/") || clean_path == "/dav/backup" {
                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 403 Forbidden", "text/plain; charset=utf-8",
                        "DAV: 1, 2",
                        b"403 Forbidden: /backup is WORM Immutable (Write-Once-Read-Many)\n",
                    );
                    return 1;
                }

                let mut path_c = [0u8; 256];
                let plen = core::cmp::min(clean_path.len(), 255);
                path_c[..plen].copy_from_slice(&clean_path.as_bytes()[..plen]);
                path_c[plen] = 0;

                let written = unsafe {
                    webui_write_file(path_c.as_ptr(), req.body.as_ptr(), req.body.len())
                };

                if written == -2 {
                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 400 Bad Request", "text/plain; charset=utf-8",
                        "DAV: 1, 2",
                        b"400 Bad Request: file name too long for RedSea (share/name must fit 223 characters)\n",
                    );
                    return 1;
                }
                if written <= 0 {
                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 403 Forbidden", "text/plain; charset=utf-8",
                        "DAV: 1, 2",
                        b"403 Forbidden: write refused (read-only share, quota or disk full)\n",
                    );
                    return 1;
                }

                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 201 Created", "text/plain; charset=utf-8",
                    "DAV: 1, 2",
                    b"Created",
                );
                return 1;
            }

            // Handle WebDAV DELETE request
            if req.method == HttpMethod::Delete {
                if clean_path.starts_with("/dav/backup/") || clean_path == "/dav/backup" {
                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 403 Forbidden", "text/plain; charset=utf-8",
                        "DAV: 1, 2",
                        b"403 Forbidden: /backup is WORM Immutable (Write-Once-Read-Many)\n",
                    );
                    return 1;
                }

                let mut path_c = [0u8; 256];
                let plen = core::cmp::min(clean_path.len(), 255);
                path_c[..plen].copy_from_slice(&clean_path.as_bytes()[..plen]);
                path_c[plen] = 0;

                let deleted = unsafe {
                    webui_delete_file(path_c.as_ptr())
                };

                if deleted == 0 {
                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 404 Not Found", "text/plain; charset=utf-8",
                        "DAV: 1, 2",
                        b"404 Not Found\n",
                    );
                    return 1;
                }

                send_http_response_stream_ext(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 204 No Content", "text/plain",
                    "DAV: 1, 2",
                    b"",
                );
                return 1;
            }

            // Handle WebDAV PROPFIND request
            if req.method == HttpMethod::Propfind {
                let p_trim = clean_path.trim_end_matches('/');
                let is_collection = is_collection_path(clean_path);

                if is_collection {
                    if req.depth == 0 {
                        let xml_body = if p_trim == "/dav/vault" {
                            WEBDAV_VAULT_DEPTH0.as_bytes()
                        } else if p_trim == "/dav/share" {
                            WEBDAV_SHARE_DEPTH0.as_bytes()
                        } else if p_trim == "/dav/media" {
                            WEBDAV_MEDIA_DEPTH0.as_bytes()
                        } else if p_trim == "/dav/backup" {
                            WEBDAV_BACKUP_DEPTH0.as_bytes()
                        } else {
                            WEBDAV_ROOT_DEPTH0.as_bytes()
                        };

                        send_http_response_stream_ext(
                            client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                            resp_seq, resp_ack,
                            "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                            "DAV: 1, 2\r\nMS-Author-Via: DAV",
                            xml_body,
                        );
                        return 1;
                    } else {
                        // Depth 1 or greater
                        if p_trim == "/dav/vault" {
                            let mut d1_buf = alloc::vec![0u8; 512 * 1024];
                            let xml_slice = write_vault_multistatus_depth1(&mut d1_buf);
                            send_http_response_stream_ext(
                                client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                                resp_seq, resp_ack,
                                "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                                "DAV: 1, 2\r\nMS-Author-Via: DAV",
                                xml_slice,
                            );
                            return 1;
                        } else if p_trim == "/dav/share" {
                            let mut d1_buf = alloc::vec![0u8; 512 * 1024];
                            let xml_slice = write_share_multistatus_depth1(&mut d1_buf);
                            send_http_response_stream_ext(
                                client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                                resp_seq, resp_ack,
                                "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                                "DAV: 1, 2\r\nMS-Author-Via: DAV",
                                xml_slice,
                            );
                            return 1;
                        } else if p_trim == "/dav/media" {
                            let mut d1_buf = alloc::vec![0u8; 512 * 1024];
                            let xml_slice = write_generic_multistatus_depth1(&mut d1_buf, "media", b"media\0");
                            send_http_response_stream_ext(
                                client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                                resp_seq, resp_ack,
                                "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                                "DAV: 1, 2\r\nMS-Author-Via: DAV",
                                xml_slice,
                            );
                            return 1;
                        } else if p_trim == "/dav/backup" {
                            let mut d1_buf = alloc::vec![0u8; 512 * 1024];
                            let xml_slice = write_generic_multistatus_depth1(&mut d1_buf, "backup", b"backup\0");
                            send_http_response_stream_ext(
                                client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                                resp_seq, resp_ack,
                                "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                                "DAV: 1, 2\r\nMS-Author-Via: DAV",
                                xml_slice,
                            );
                            return 1;
                        } else {
                            send_http_response_stream_ext(
                                client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                                resp_seq, resp_ack,
                                "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                                "DAV: 1, 2\r\nMS-Author-Via: DAV",
                                WEBDAV_ROOT_MULTISTATUS.as_bytes(),
                            );
                            return 1;
                        }
                    }
                } else {
                    // Not a collection: an individual file resource was requested (e.g. /dav/share/image.png)
                    let mut path_c = [0u8; 256];
                    let plen = core::cmp::min(clean_path.len(), 255);
                    path_c[..plen].copy_from_slice(&clean_path.as_bytes()[..plen]);
                    path_c[plen] = 0;

                    let exists = unsafe { webui_file_exists(path_c.as_ptr()) };
                    if exists == 0 {
                        // CRITICAL: Return 404 so WebDAV clients know target does NOT exist (prevents infinite recursion)
                        send_http_response_stream_ext(
                            client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                            resp_seq, resp_ack,
                            "HTTP/1.1 404 Not Found", "text/plain; charset=utf-8",
                            "DAV: 1, 2",
                            b"404 Not Found - Resource does not exist\n",
                        );
                        return 1;
                    }

                    let fsize = unsafe { webui_file_size(path_c.as_ptr()) };
                    let mime = get_mime_type(clean_path);
                    let display_name = match clean_path.rfind('/') {
                        Some(pos) => &clean_path[pos + 1..],
                        None => clean_path,
                    };

                    let mut xml_buf = [0u8; 2048];
                    let mut xw = BufferWriter::new(&mut xml_buf);
                    xw.write_str("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:multistatus xmlns:D=\"DAV:\">\n  <D:response>\n    <D:href>");
                    xw.write_href(clean_path);
                    xw.write_str("</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:resourcetype/>\n        <D:getcontentlength>");
                    xw.write_u64(fsize);
                    xw.write_str("</D:getcontentlength>\n        <D:getcontenttype>");
                    xw.write_str(mime);
                    xw.write_str("</D:getcontenttype>\n        <D:displayname>");
                    xw.write_xml_text(display_name);
                    xw.write_str("</D:displayname>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n</D:multistatus>\n");

                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 207 Multi-Status", "application/xml; charset=utf-8",
                        "DAV: 1, 2\r\nMS-Author-Via: DAV",
                        xw.as_bytes(),
                    );
                    return 1;
                }
            }

            // Handle GET / HEAD requests
            if req.method == HttpMethod::Get || req.method == HttpMethod::Head {
                if is_collection_path(clean_path) || clean_path == "/dav" || clean_path == "/dav/" {
                    // Serve WebDAV HTML Explorer
                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 200 OK", "text/html; charset=utf-8",
                        "DAV: 1, 2\r\nMS-Author-Via: DAV",
                        if req.method == HttpMethod::Head { b"" } else { WEBDAV_EXPLORER_HTML.as_bytes() },
                    );
                    return 1;
                } else if clean_path.starts_with("/dav/") {
                    // Serve individual files within WebDAV
                    let mut path_c = [0u8; 256];
                    let plen = core::cmp::min(clean_path.len(), 255);
                    path_c[..plen].copy_from_slice(&clean_path.as_bytes()[..plen]);
                    path_c[plen] = 0;

                    let exists = unsafe { webui_file_exists(path_c.as_ptr()) };
                    if exists == 0 {
                        send_http_response_stream_ext(
                            client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                            resp_seq, resp_ack,
                            "HTTP/1.1 404 Not Found", "text/plain; charset=utf-8",
                            "DAV: 1, 2",
                            b"404 Not Found\n",
                        );
                        return 1;
                    }

                    let fsize = unsafe { webui_file_size(path_c.as_ptr()) } as usize;
                    let mut file_buf: Vec<u8> = Vec::new();
                    if req.method != HttpMethod::Head && fsize > 0 && fsize <= 16 * 1024 * 1024 {
                        file_buf.resize(fsize, 0);
                        let rlen = unsafe { webui_read_file(path_c.as_ptr(), file_buf.as_mut_ptr(), file_buf.len()) };
                        file_buf.truncate(if rlen > 0 { rlen as usize } else { 0 });
                    }
                    let rslice: &[u8] = &file_buf;
                    let mime = get_mime_type(clean_path);

                    send_http_response_stream_ext(
                        client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                        resp_seq, resp_ack,
                        "HTTP/1.1 200 OK", mime,
                        "DAV: 1, 2\r\nAccept-Ranges: bytes",
                        if req.method == HttpMethod::Head { b"" } else { rslice },
                    );
                    return 1;
                }
            }

            if path == "/favicon.ico" {
                send_http_response_stream(
                    client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
                    resp_seq, resp_ack,
                    "HTTP/1.1 204 No Content", "text/plain",
                    b"",
                );
                return 1;
            }
        }

        // Default 404
        send_http_response_stream(
            client_mac, our_mac, client_ip, our_ip, client_port, dst_port,
            resp_seq, resp_ack,
            "HTTP/1.1 404 Not Found", "text/plain",
            b"404 Not Found - YesOS 2.0 Cyber-Vault",
        );
        1
}

