//! YesOS NAS - TLS 1.3 server (HTTPS on TCP 8443).
//!
//! rustls (no_std, unbuffered API) with a small crypto provider built on the
//! audited RustCrypto crates:
//!   key exchange   X25519 (curve25519-dalek)
//!   cipher suites  TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256
//!   hash / HKDF    SHA-256, HMAC-SHA-256 (rustls' HKDF-over-HMAC)
//!   certificate    self-signed ECDSA P-256 (RFC 6979 deterministic signatures)
//!   randomness     the kernel DRBG (yesos_core::crypto)
//! TLS 1.2, session tickets, resumption and early data are disabled.
//!
//! The certificate is derived deterministically from the persisted private
//! key (SYS/TLS.KEY) and the NAS IP, so its SHA-256 fingerprint stays the same
//! across reboots. The console prints it; compare it with what the browser shows.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::Mac;
use p256::ecdsa::signature::Signer as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use rustls::crypto::hmac::{Hmac, Key, Tag};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::{NoServerSessionStorage, ServerConfig, UnbufferedServerConnection};
use rustls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use rustls::time_provider::TimeProvider;
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
    SignatureAlgorithm, SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
};

use yesos_core::crypto::Locked;

// -----------------------------------------------------------------------------
// Randomness, time
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct KernelRng;

impl SecureRandom for KernelRng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        if yesos_core::crypto::rng_fill(buf) == 0 { Ok(()) } else { Err(GetRandomFailed) }
    }
}

extern "C" {
    fn timer_get_uptime_ms() -> u64;
    /// The core's ChaCha20 keystream (module "chacha", kernel/chacha20.c):
    /// data ^= keystream from block `counter`; RVV when the hart has V.
    fn cc20_xor(key: *const u8, nonce: *const u8, counter: u32, data: *mut u8, len: usize);
    /// The core's ChaCha20-Poly1305 tag (kernel/poly1305.c, RFC 8439 2.8).
    fn cc20_poly1305_aead(otk: *const u8, aad: *const u8, aad_len: usize, ct: *const u8, ct_len: usize, tag: *mut u8);
}

/// The NAS has no trusted wall clock. Time is only used by rustls for ticket
/// lifetimes (tickets are disabled), so a fixed epoch plus uptime is enough.
#[derive(Debug)]
struct UptimeClock;

impl TimeProvider for UptimeClock {
    fn current_time(&self) -> Option<UnixTime> {
        let secs = 1_767_225_600 + unsafe { timer_get_uptime_ms() } / 1000; // 2026-01-01
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(secs)))
    }
}

// -----------------------------------------------------------------------------
// Key exchange: X25519
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct X25519;

struct X25519Kx {
    secret: [u8; 32],
    public: [u8; 32],
}

impl Drop for X25519Kx {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut secret = [0u8; 32];
        KernelRng.fill(&mut secret).map_err(|_| Error::FailedToGetRandomBytes)?;
        let public = MontgomeryPoint::mul_base_clamped(secret).to_bytes();
        Ok(Box::new(X25519Kx { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for X25519Kx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let mut shared = MontgomeryPoint(peer).mul_clamped(self.secret).to_bytes();
        // Low-order peer points give an all-zero secret (RFC 7748 section 6.1).
        if shared.iter().all(|&b| b == 0) {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let s = SharedSecret::from(&shared[..]);
        shared.zeroize();
        Ok(s)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// -----------------------------------------------------------------------------
// SHA-256, HMAC-SHA-256, HKDF
// -----------------------------------------------------------------------------

struct Sha256Hash;

struct Sha256Ctx(Sha256);

impl Hash for Sha256Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha256Ctx(Sha256::new()))
    }
    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&Sha256::digest(data)[..])
    }
    fn output_len(&self) -> usize {
        32
    }
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

impl Context for Sha256Ctx {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }
    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha256Ctx(self.0.clone()))
    }
    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

type HmacSha256 = hmac::Hmac<Sha256>;

struct HmacSha256Alg;

struct HmacSha256Key(HmacSha256);

impl Hmac for HmacSha256Alg {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // HMAC accepts keys of any length.
        Box::new(HmacSha256Key(<HmacSha256 as Mac>::new_from_slice(key).expect("hmac key")))
    }
    fn hash_output_len(&self) -> usize {
        32
    }
}

impl Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut m = self.0.clone();
        m.update(first);
        for part in middle {
            m.update(part);
        }
        m.update(last);
        Tag::new(&m.finalize().into_bytes()[..])
    }
    fn tag_len(&self) -> usize {
        32
    }
}

static SHA256: Sha256Hash = Sha256Hash;
static HMAC_SHA256: HmacSha256Alg = HmacSha256Alg;
static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA256);

// -----------------------------------------------------------------------------
// AEAD record protection (TLS 1.3)
// -----------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum AeadKind {
    ChaCha20Poly1305,
    Aes128Gcm,
}

struct Aead(AeadKind);

enum Cipher {
    ChaCha(ChaChaPoly),
    Aes(aes_gcm::Aes128Gcm),
}

/// ChaCha20-Poly1305 (RFC 8439 2.8), both from the core's module "chacha":
/// the keystream (cc20_xor, vector code) and Poly1305 (cc20_poly1305_aead,
/// 64-bit limbs). The one-time Poly1305 key is block 0 of the keystream, the
/// data uses blocks 1 onwards; the tag covers aad, ciphertext and both
/// lengths, and is checked in constant time before anything is decrypted.
struct ChaChaPoly {
    key: [u8; 32],
}

impl Drop for ChaChaPoly {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ChaChaPoly {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        ChaChaPoly { key: k }
    }

    fn xor(&self, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        // SAFETY: key and nonce are 32 and 12 bytes; data is valid for its length.
        unsafe { cc20_xor(self.key.as_ptr(), nonce.as_ptr(), counter, data.as_mut_ptr(), data.len()) }
    }

    fn tag(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let mut otk = [0u8; 32];
        self.xor(nonce, 0, &mut otk);
        let mut t = [0u8; 16];
        // SAFETY: every pointer is valid for the length passed with it.
        unsafe { cc20_poly1305_aead(otk.as_ptr(), aad.as_ptr(), aad.len(), ct.as_ptr(), ct.len(), t.as_mut_ptr()) };
        otk.zeroize();
        t
    }

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        self.xor(nonce, 1, buf);
        self.tag(nonce, aad, buf)
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        let mut t = self.tag(nonce, aad, buf);
        let ok = yesos_core::crypto::yc_ct_eq(t.as_ptr(), tag.as_ptr(), 16) == 1;
        t.zeroize();
        if !ok {
            return false;
        }
        self.xor(nonce, 1, buf);
        true
    }
}

/// RFC 8439 2.8.2 known-answer test of ChaChaPoly: sealing, opening, and a
/// flipped tag bit refused. The NAS offers the suite only if it passes.
fn chacha_poly_kat() -> bool {
    const PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const CT: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51,
        0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0,
        0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    const TAG: [u8; 16] = [0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91];
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = 0x80 + i as u8;
    }
    let nonce = [0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
    let c = ChaChaPoly::new(&key);
    let mut buf = [0u8; 114];
    buf.copy_from_slice(PT);
    let tag = c.seal(&nonce, &aad, &mut buf);
    let sealed = buf == CT && tag == TAG;
    let opened = c.open(&nonce, &aad, &mut buf, &TAG) && buf == *PT;
    let mut bad = TAG;
    bad[0] ^= 1;
    let mut buf2 = CT;
    let refused = !c.open(&nonce, &aad, &mut buf2, &bad) && buf2 == CT;
    sealed && opened && refused
}

static CHACHA_KAT: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-1);

/// 1 if the ChaCha20-Poly1305 known-answer test passed (and the suite is
/// offered), 0 if it failed, -1 before yc_tls_init.
#[no_mangle]
pub extern "C" fn yc_tls_chacha_kat() -> i32 {
    CHACHA_KAT.load(core::sync::atomic::Ordering::Relaxed)
}

impl Cipher {
    fn new(kind: AeadKind, key: &[u8]) -> Self {
        match kind {
            AeadKind::ChaCha20Poly1305 => Cipher::ChaCha(ChaChaPoly::new(key)),
            AeadKind::Aes128Gcm => Cipher::Aes(aes_gcm::Aes128Gcm::new_from_slice(key).expect("key")),
        }
    }

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Option<[u8; 16]> {
        let tag = match self {
            Cipher::ChaCha(c) => return Some(c.seal(nonce, aad, buf)),
            Cipher::Aes(c) => c.encrypt_in_place_detached(nonce.into(), aad, buf).ok()?,
        };
        let mut t = [0u8; 16];
        t.copy_from_slice(&tag);
        Some(t)
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        match self {
            Cipher::ChaCha(c) => c.open(nonce, aad, buf, tag),
            Cipher::Aes(c) => c.decrypt_in_place_detached(nonce.into(), aad, buf, tag.into()).is_ok(),
        }
    }
}

struct RecordCipher {
    cipher: Cipher,
    iv: Iv,
}

impl Tls13AeadAlgorithm for Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(RecordCipher { cipher: Cipher::new(self.0, key.as_ref()), iv })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(RecordCipher { cipher: Cipher::new(self.0, key.as_ref()), iv })
    }
    fn key_len(&self) -> usize {
        match self.0 {
            AeadKind::ChaCha20Poly1305 => 32,
            AeadKind::Aes128Gcm => 16,
        }
    }
    fn extract_keys(&self, _key: AeadKey, _iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

impl MessageEncrypter for RecordCipher {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        // Encrypted in place in the outgoing payload: no second buffer, and
        // so no plaintext copy left to wipe.
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let nonce = Nonce::new(&self.iv, seq).0;
        let tag = self.cipher.seal(&nonce, &make_tls13_aad(total), payload.as_mut()).ok_or(Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + 16
    }
}

impl MessageDecrypter for RecordCipher {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        if len < 16 {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(len);
        let (ct, tag) = payload.split_at_mut(len - 16);
        let mut t = [0u8; 16];
        t.copy_from_slice(tag);
        if !self.cipher.open(&nonce, &aad, ct, &t) {
            return Err(Error::DecryptError);
        }
        payload.truncate(len - 16);
        msg.into_tls13_unpadded_message()
    }
}

static CHACHA20_POLY1305: Aead = Aead(AeadKind::ChaCha20Poly1305);
static AES_128_GCM: Aead = Aead(AeadKind::Aes128Gcm);

static TLS13_CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &CHACHA20_POLY1305,
    quic: None,
};

static TLS13_AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &AES_128_GCM,
    quic: None,
};

// -----------------------------------------------------------------------------
// Certificate key: ECDSA P-256
// -----------------------------------------------------------------------------

struct EcdsaKey(Arc<p256::ecdsa::SigningKey>);

impl fmt::Debug for EcdsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaKey(P-256)")
    }
}

struct EcdsaSigner(Arc<p256::ecdsa::SigningKey>);

impl fmt::Debug for EcdsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaSigner(P-256)")
    }
}

impl SigningKey for EcdsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Box::new(EcdsaSigner(self.0.clone())))
        } else {
            None
        }
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl rustls::sign::Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: p256::ecdsa::Signature = self.0.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// Keys are installed directly as a CertifiedKey; loading from DER is unused.
#[derive(Debug)]
struct NoKeyLoading;

impl KeyProvider for NoKeyLoading {
    fn load_private_key(&self, _key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General("key loading not supported".into()))
    }
}

static KERNEL_RNG: KernelRng = KernelRng;
static NO_KEY_LOADING: NoKeyLoading = NoKeyLoading;
static X25519_GROUP: X25519 = X25519;

// -----------------------------------------------------------------------------
// Self-signed certificate (DER, written by hand)
// -----------------------------------------------------------------------------

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x0A];
const OID_SKI: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0E];
const OID_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F];
const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x11];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13];
const OID_EXT_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let octets = der(0x04, value);
    if critical {
        seq(&[oid, &[0x01, 0x01, 0xFF], &octets])
    } else {
        seq(&[oid, &octets])
    }
}

fn build_certificate(key: &p256::ecdsa::SigningKey, nas_ip: [u8; 4]) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let pubkey = point.as_bytes(); // 0x04 || X || Y
    let key_id = Sha256::digest(pubkey);

    let mut serial = [0u8; 16];
    serial.copy_from_slice(&key_id[..16]);
    serial[0] = (serial[0] & 0x7F) | 0x01; // positive, non-zero

    let name = seq(&[
        &der(0x31, &seq(&[OID_O, &der(0x0C, b"YesOS")])),
        &der(0x31, &seq(&[OID_CN, &der(0x0C, b"YesOS NAS")])),
    ]);
    let alg = seq(&[OID_ECDSA_SHA256]);
    let validity = seq(&[&der(0x17, b"250101000000Z"), &der(0x17, b"491231235959Z")]);
    let mut bits = vec![0u8];
    bits.extend_from_slice(pubkey);
    let spki = seq(&[&seq(&[OID_EC_PUBLIC_KEY, OID_P256]), &der(0x03, &bits)]);

    let mut san = Vec::new();
    san.extend(der(0x82, b"yesos.local"));
    san.extend(der(0x82, b"localhost"));
    san.extend(der(0x87, &nas_ip));
    if nas_ip != [127, 0, 0, 1] {
        san.extend(der(0x87, &[127, 0, 0, 1]));
    }
    let exts = seq(&[
        &extension(OID_BASIC_CONSTRAINTS, true, &seq(&[])),
        &extension(OID_KEY_USAGE, true, &[0x03, 0x02, 0x07, 0x80]), // digitalSignature
        &extension(OID_EXT_KEY_USAGE, false, &seq(&[OID_SERVER_AUTH])),
        &extension(OID_SAN, false, &der(0x30, &san)),
        &extension(OID_SKI, false, &der(0x04, &key_id[..20])),
    ]);

    let tbs = seq(&[
        &[0xA0, 0x03, 0x02, 0x01, 0x02], // version v3
        &der(0x02, &serial),
        &alg,
        &name,
        &validity,
        &name,
        &spki,
        &der(0xA3, &exts),
    ]);
    let sig: p256::ecdsa::Signature = key.sign(&tbs);
    let mut sig_bits = vec![0u8];
    sig_bits.extend_from_slice(sig.to_der().as_bytes());
    seq(&[&tbs, &alg, &der(0x03, &sig_bits)])
}

// -----------------------------------------------------------------------------
// Server configuration
// -----------------------------------------------------------------------------

struct TlsState {
    config: Option<Arc<ServerConfig>>,
    fingerprint: [u8; 32],
}

static TLS: Locked<TlsState> = Locked::new(TlsState { config: None, fingerprint: [0; 32] });

/// Builds the server configuration from a 32-byte P-256 private scalar and
/// the NAS IPv4 address (4 bytes, network order). Writes the certificate's
/// SHA-256 fingerprint to `fp_out`. Returns 0, or -1 for an invalid key
/// (the caller generates a new one), -2 if rustls rejects the configuration.
#[no_mangle]
pub extern "C" fn yc_tls_init(key: *const u8, nas_ip: *const u8, fp_out: *mut u8) -> i32 {
    if key.is_null() || nas_ip.is_null() || fp_out.is_null() {
        return -1;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(unsafe { core::slice::from_raw_parts(key, 32) });
    let mut ip = [0u8; 4];
    ip.copy_from_slice(unsafe { core::slice::from_raw_parts(nas_ip, 4) });
    let sk = match p256::ecdsa::SigningKey::from_bytes(&k.into()) {
        Ok(s) => s,
        Err(_) => {
            k.zeroize();
            return -1;
        }
    };
    k.zeroize();

    let cert = build_certificate(&sk, ip);
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&Sha256::digest(&cert));

    let kat = chacha_poly_kat();
    CHACHA_KAT.store(kat as i32, core::sync::atomic::Ordering::Relaxed);
    let mut suites = Vec::new();
    if kat {
        suites.push(SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256));
    }
    suites.push(SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256));
    let provider = Arc::new(CryptoProvider {
        cipher_suites: suites,
        kx_groups: vec![&X25519_GROUP],
        signature_verification_algorithms: WebPkiSupportedAlgorithms { all: &[], mapping: &[] },
        secure_random: &KERNEL_RNG,
        key_provider: &NO_KEY_LOADING,
    });
    let certified = CertifiedKey::new(vec![CertificateDer::from(cert)], Arc::new(EcdsaKey(Arc::new(sk))));
    let builder = match ServerConfig::builder_with_details(provider, Arc::new(UptimeClock))
        .with_protocol_versions(&[&rustls::version::TLS13])
    {
        Ok(b) => b,
        Err(_) => return -2,
    };
    let mut config = builder
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    TLS.with(|t| {
        t.config = Some(Arc::new(config));
        t.fingerprint = fp;
    });
    unsafe { core::ptr::copy_nonoverlapping(fp.as_ptr(), fp_out, 32) };
    0
}

/// Copies the current certificate fingerprint; returns 0 if TLS is ready.
#[no_mangle]
pub extern "C" fn yc_tls_fingerprint(fp_out: *mut u8) -> i32 {
    if fp_out.is_null() {
        return -1;
    }
    TLS.with(|t| {
        if t.config.is_none() {
            return -1;
        }
        unsafe { core::ptr::copy_nonoverlapping(t.fingerprint.as_ptr(), fp_out, 32) };
        0
    })
}

// -----------------------------------------------------------------------------
// Per-connection state, driven by the TCP layer (crate::http)
// -----------------------------------------------------------------------------

pub struct TlsConn {
    conn: UnbufferedServerConnection,
    incoming: Vec<u8>,
    pub failed: bool,
    pub peer_closed: bool,
}

impl Drop for TlsConn {
    fn drop(&mut self) {
        self.incoming.zeroize();
    }
}

impl TlsConn {
    /// None until yc_tls_init has succeeded.
    pub fn new() -> Option<Box<TlsConn>> {
        let config = TLS.with(|t| t.config.clone())?;
        let conn = UnbufferedServerConnection::new(config).ok()?;
        Some(Box::new(TlsConn { conn, incoming: Vec::new(), failed: false, peer_closed: false }))
    }

    /// Feeds TCP payload bytes. Handshake records to send are appended to
    /// `out_tls`; decrypted application data to `plain`.
    pub fn feed(&mut self, data: &[u8], out_tls: &mut Vec<u8>, plain: &mut Vec<u8>) {
        self.incoming.extend_from_slice(data);
        loop {
            let UnbufferedStatus { mut discard, state } = self.conn.process_tls_records(&mut self.incoming);
            let mut stop = false;
            match state {
                Err(_) => {
                    self.failed = true;
                    stop = true;
                }
                Ok(ConnectionState::ReadTraffic(mut r)) => {
                    while let Some(rec) = r.next_record() {
                        match rec {
                            Ok(rec) => {
                                plain.extend_from_slice(rec.payload);
                                discard += rec.discard;
                            }
                            Err(_) => {
                                self.failed = true;
                                break;
                            }
                        }
                    }
                }
                Ok(ConnectionState::EncodeTlsData(mut e)) => {
                    let mut buf = vec![0u8; 2048];
                    loop {
                        match e.encode(&mut buf) {
                            Ok(n) => {
                                out_tls.extend_from_slice(&buf[..n]);
                                break;
                            }
                            Err(EncodeError::InsufficientSize(s)) => buf.resize(s.required_size, 0),
                            Err(_) => {
                                self.failed = true;
                                break;
                            }
                        }
                    }
                }
                // The bytes are already in `out_tls`; the TCP layer sends them.
                Ok(ConnectionState::TransmitTlsData(t)) => t.done(),
                Ok(ConnectionState::BlockedHandshake) | Ok(ConnectionState::WriteTraffic(_)) => stop = true,
                Ok(ConnectionState::PeerClosed) => self.peer_closed = true,
                Ok(ConnectionState::Closed) => {
                    self.peer_closed = true;
                    stop = true;
                }
                Ok(_) => stop = true, // early data is not enabled
            }
            let d = core::cmp::min(discard, self.incoming.len());
            self.incoming.drain(..d);
            if stop || self.failed {
                break;
            }
        }
    }

    /// Encrypts application data (and a close_notify when `close`) into
    /// `out_tls`. Returns false if the handshake is not complete.
    pub fn write(&mut self, data: &[u8], close: bool, out_tls: &mut Vec<u8>) -> bool {
        let UnbufferedStatus { state, .. } = self.conn.process_tls_records(&mut []);
        let mut w = match state {
            Ok(ConnectionState::WriteTraffic(w)) => w,
            _ => return false,
        };
        // Records are written straight into out_tls, reserved once for all of
        // them (our own data: its size is known), not via a bounce buffer.
        const REC: usize = 16 * 1024;
        out_tls.reserve(data.len() + (data.len() / REC + 2) * 64);
        for chunk in data.chunks(REC) {
            let start = out_tls.len();
            let mut need = chunk.len() + 64;                    // header 5, content type 1, tag 16
            loop {
                out_tls.resize(start + need, 0);
                match w.encrypt(chunk, &mut out_tls[start..]) {
                    Ok(n) => {
                        out_tls.truncate(start + n);
                        break;
                    }
                    Err(EncryptError::InsufficientSize(s)) => need = s.required_size,
                    Err(_) => {
                        out_tls.truncate(start);
                        return false;
                    }
                }
            }
        }
        if close {
            let mut buf = vec![0u8; 256];
            loop {
                match w.queue_close_notify(&mut buf) {
                    Ok(n) => {
                        out_tls.extend_from_slice(&buf[..n]);
                        break;
                    }
                    Err(EncryptError::InsufficientSize(s)) => buf.resize(s.required_size, 0),
                    Err(_) => break,
                }
            }
        }
        true
    }
}
