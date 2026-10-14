//! ==============================================================================
//! YesOS 2.0 - Secure NAS channel: Noise_NK_25519_ChaChaPoly_BLAKE2s responder
//!
//! The protocol machinery is the `snow` crate (reference Rust implementation
//! of the Noise Protocol Framework). This module only keeps a small table of
//! transport sessions and exposes a C ABI for the UDP NAS server.
//!
//! NK: the client knows (pins) the appliance's static public key, so it
//! authenticates the server before sending anything; the client stays
//! anonymous at the Noise layer and logs in with a password inside the
//! encrypted channel. UDP may drop/reorder datagrams, so transport messages
//! carry an explicit nonce (stateless transport) and the server only accepts
//! strictly increasing nonces per session (replay protection).
//! ==============================================================================

use alloc::boxed::Box;
use core::slice;

use curve25519_dalek::montgomery::MontgomeryPoint;
use snow::params::{CipherChoice, DHChoice, HashChoice, NoiseParams};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use snow::{Builder, StatelessTransportState};
use zeroize::Zeroize;

use yesos_core::crypto::{rng_fill, Locked, YC_ERR_AUTH, YC_ERR_BUSY, YC_ERR_NO_ENTROPY, YC_ERR_PARAM, YC_OK};

pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_PROLOGUE: &[u8] = b"YesOS-NAS-v1";
pub const NOISE_MAX_SESSIONS: usize = 8;
pub const YC_ERR_REPLAY: i32 = -6;
pub const YC_ERR_NO_SESSION: i32 = -7;
pub const YC_ERR_NO_KEY: i32 = -8;

// -----------------------------------------------------------------------------
// snow resolver: default primitives, kernel DRBG for randomness
// -----------------------------------------------------------------------------

struct KernelRng;

impl Random for KernelRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        if rng_fill(dest) == YC_OK { Ok(()) } else { Err(snow::Error::Rng) }
    }
}

struct KernelResolver;

impl CryptoResolver for KernelResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(KernelRng))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

// -----------------------------------------------------------------------------
// State
// -----------------------------------------------------------------------------

struct Session {
    id: u64,
    transport: StatelessTransportState,
    last_rx_nonce: Option<u64>,
    last_used_ms: u64,
}

struct NoiseState {
    static_private: Option<[u8; 32]>,
    sessions: [Option<Session>; NOISE_MAX_SESSIONS],
}

static NOISE: Locked<NoiseState> = Locked::new(NoiseState {
    static_private: None,
    sessions: [const { None }; NOISE_MAX_SESSIONS],
});

fn params() -> Option<NoiseParams> {
    NOISE_PATTERN.parse().ok()
}

// -----------------------------------------------------------------------------
// C ABI
// -----------------------------------------------------------------------------

/// Installs the appliance's static X25519 private key (32 bytes).
#[no_mangle]
pub extern "C" fn yc_noise_set_static_key(private_key: *const u8) -> i32 {
    if private_key.is_null() {
        return YC_ERR_PARAM;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(unsafe { slice::from_raw_parts(private_key, 32) });
    NOISE.with(|n| {
        if let Some(old) = n.static_private.as_mut() {
            old.zeroize();
        }
        n.static_private = Some(k);
        for s in n.sessions.iter_mut() {
            *s = None;
        }
    });
    k.zeroize();
    YC_OK
}

/// Writes the 32-byte static public key matching the installed private key.
#[no_mangle]
pub extern "C" fn yc_noise_public_key(out: *mut u8) -> i32 {
    if out.is_null() {
        return YC_ERR_PARAM;
    }
    NOISE.with(|n| match n.static_private {
        Some(k) => {
            let p = MontgomeryPoint::mul_base_clamped(k);
            unsafe { slice::from_raw_parts_mut(out, 32) }.copy_from_slice(p.as_bytes());
            YC_OK
        }
        None => YC_ERR_NO_KEY,
    })
}

/// Processes a client's first handshake message (-> e, es) and writes the
/// response (<- e, ee) into `out`. On success the new session's slot and id
/// are returned; any session previously in that slot is discarded (the C side
/// must reset its per-slot login state).
#[no_mangle]
pub extern "C" fn yc_noise_accept(
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    slot_out: *mut u32,
    id_out: *mut u64,
    now_ms: u64,
) -> i32 {
    if msg.is_null() || out.is_null() || out_len.is_null() || slot_out.is_null() || id_out.is_null() || msg_len > 1024 {
        return YC_ERR_PARAM;
    }
    let msg = unsafe { slice::from_raw_parts(msg, msg_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_cap) };

    NOISE.with(|n| {
        let key = match n.static_private {
            Some(k) => k,
            None => return YC_ERR_NO_KEY,
        };
        let params = match params() {
            Some(p) => p,
            None => return YC_ERR_PARAM,
        };
        let builder = Builder::with_resolver(params, Box::new(KernelResolver));
        let builder = match builder.local_private_key(&key).and_then(|b| b.prologue(NOISE_PROLOGUE)) {
            Ok(b) => b,
            Err(_) => return YC_ERR_PARAM,
        };
        let mut hs = match builder.build_responder() {
            Ok(h) => h,
            Err(_) => return YC_ERR_PARAM,
        };

        let mut scratch = [0u8; 1024];
        if hs.read_message(msg, &mut scratch).is_err() {
            return YC_ERR_AUTH;
        }
        let written = match hs.write_message(&[], out) {
            Ok(w) => w,
            Err(snow::Error::Rng) => return YC_ERR_NO_ENTROPY,
            Err(_) => return YC_ERR_PARAM,
        };
        let transport = match hs.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(_) => return YC_ERR_PARAM,
        };

        let mut id_bytes = [0u8; 8];
        if rng_fill(&mut id_bytes) != YC_OK {
            return YC_ERR_NO_ENTROPY;
        }
        let id = u64::from_le_bytes(id_bytes);

        // Free slot first, otherwise evict the least recently used session.
        let slot = n
            .sessions
            .iter()
            .position(|s| s.is_none())
            .unwrap_or_else(|| {
                let mut oldest = 0;
                for (i, s) in n.sessions.iter().enumerate() {
                    if let (Some(a), Some(b)) = (s, &n.sessions[oldest]) {
                        if a.last_used_ms < b.last_used_ms {
                            oldest = i;
                        }
                    }
                }
                oldest
            });

        n.sessions[slot] = Some(Session { id, transport, last_rx_nonce: None, last_used_ms: now_ms });
        unsafe {
            *out_len = written;
            *slot_out = slot as u32;
            *id_out = id;
        }
        YC_OK
    })
}

fn with_session<R>(id: u64, f: impl FnOnce(usize, &mut Session) -> R) -> Result<R, i32> {
    NOISE
        .try_with(|n| {
            for (slot, entry) in n.sessions.iter_mut().enumerate() {
                if let Some(s) = entry {
                    if s.id == id {
                        return Ok(f(slot, s));
                    }
                }
            }
            Err(YC_ERR_NO_SESSION)
        })
        .unwrap_or(Err(YC_ERR_BUSY))
}

/// Decrypts a client transport message. Rejects nonces that are not strictly
/// greater than the last accepted one for the session.
#[no_mangle]
pub extern "C" fn yc_noise_decrypt(
    id: u64,
    nonce: u64,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    slot_out: *mut u32,
    now_ms: u64,
) -> i32 {
    if ct.is_null() || out.is_null() || out_len.is_null() || slot_out.is_null() || ct_len < 16 || out_cap < ct_len - 16 {
        return YC_ERR_PARAM;
    }
    let ct = unsafe { slice::from_raw_parts(ct, ct_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_cap) };
    match with_session(id, |slot, s| {
        if let Some(last) = s.last_rx_nonce {
            if nonce <= last {
                return YC_ERR_REPLAY;
            }
        }
        match s.transport.read_message(nonce, ct, out) {
            Ok(n) => {
                s.last_rx_nonce = Some(nonce);
                s.last_used_ms = now_ms;
                unsafe {
                    *out_len = n;
                    *slot_out = slot as u32;
                }
                YC_OK
            }
            Err(_) => YC_ERR_AUTH,
        }
    }) {
        Ok(r) => r,
        Err(e) => e,
    }
}

/// Encrypts a server transport message with the given nonce (the server
/// replies with the request's nonce on its own, independent direction key).
#[no_mangle]
pub extern "C" fn yc_noise_encrypt(
    id: u64,
    nonce: u64,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if (pt.is_null() && pt_len != 0) || out.is_null() || out_len.is_null() || out_cap < pt_len + 16 {
        return YC_ERR_PARAM;
    }
    let pt = if pt_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(pt, pt_len) } };
    let out = unsafe { slice::from_raw_parts_mut(out, out_cap) };
    match with_session(id, |_, s| match s.transport.write_message(nonce, pt, out) {
        Ok(n) => {
            unsafe { *out_len = n };
            YC_OK
        }
        Err(_) => YC_ERR_PARAM,
    }) {
        Ok(r) => r,
        Err(e) => e,
    }
}

/// Drops a session (logout, or evicted by the C side).
#[no_mangle]
pub extern "C" fn yc_noise_close(slot: u32) {
    NOISE.with(|n| {
        if let Some(s) = n.sessions.get_mut(slot as usize) {
            *s = None;
        }
    });
}
