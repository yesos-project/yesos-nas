//! YesOS NAS - Rust part: TCP, TLS 1.3, HTTP/WebDAV, admin panel, Noise NK channel
#![no_std]

extern crate alloc;

// The core crate (allocator, panic handler, crypto, DRBG, C entry points).
pub use yesos_core;

pub mod noise;
pub mod http;
pub mod webadmin;
pub mod tls;
pub use http::rust_handle_tcp;
