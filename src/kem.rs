//! Hybrid post-quantum KEM — **X25519 + ML-KEM-768** (`x25519-mlkem768`).
//!
//! Clean-room of `skcomms/pqkem.py`. The classical X25519 leg (ephemeral-static
//! DHKEM, as in HPKE/TLS) is composed with the ML-KEM-768 leg (**FIPS 203**) by
//! **concatenate-then-KDF**:
//!
//! ```text
//! shared = HKDF-SHA256(IKM = X25519_ss ‖ MLKEM_ss, salt = b"",
//!                      info = b"sk_pqc/x25519-mlkem768/v1", L = 32)
//! ```
//!
//! Never XOR, never pure-PQ. The derived secret is secure if **either** the
//! X25519 or the ML-KEM-768 leg holds — this is a **hybrid**, not a "quantum-proof"
//! scheme. We never implement the lattice or curve math: ML-KEM is RustCrypto
//! `ml-kem`, X25519 is `x25519-dalek`, the combiner is `hkdf` + `sha2`.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

// --- Interop constants (DO NOT CHANGE — pinned by skcomms/pqkem.py) ---------

/// Suite identifier.
pub const SUITE_ID: &str = "x25519-mlkem768";

/// HKDF combiner `info` (RFC 5869) — the suite label.
pub const HKDF_INFO: &[u8] = b"sk_pqc/x25519-mlkem768/v1";

/// X25519 public-key length.
pub const X25519_PUB_LEN: usize = 32;
/// X25519 private-seed length.
pub const X25519_SEED_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key (public) length.
pub const MLKEM_PUB_LEN: usize = 1184;
/// ML-KEM-768 decapsulation-key (secret) length.
pub const MLKEM_SECRET_LEN: usize = 2400;
/// ML-KEM-768 ciphertext length.
pub const MLKEM_CT_LEN: usize = 1088;

/// Composite hybrid public-key length (`X25519_pub ‖ MLKEM_ek`).
pub const PUBLIC_KEY_LEN: usize = X25519_PUB_LEN + MLKEM_PUB_LEN; // 1216
/// Composite hybrid private-key length (`X25519_seed ‖ MLKEM_dk`).
pub const PRIVATE_KEY_LEN: usize = X25519_SEED_LEN + MLKEM_SECRET_LEN; // 2432
/// Composite hybrid ciphertext length (`X25519_eph_pub ‖ MLKEM_ct`).
pub const CIPHERTEXT_LEN: usize = X25519_PUB_LEN + MLKEM_CT_LEN; // 1120
/// Hybrid shared-secret length.
pub const SHARED_SECRET_LEN: usize = 32;

/// Errors from the hybrid KEM (never a panic on malformed input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    /// A field had the wrong length: `(what, expected, got)`.
    BadLength(&'static str, usize, usize),
    /// ML-KEM encapsulation/decapsulation rejected the material.
    MlKem(&'static str),
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemError::BadLength(what, exp, got) => {
                write!(f, "{what} must be {exp} bytes, got {got}")
            }
            KemError::MlKem(msg) => write!(f, "ML-KEM error: {msg}"),
        }
    }
}

impl Error for KemError {}

fn expect_len(what: &'static str, value: &[u8], expected: usize) -> Result<(), KemError> {
    if value.len() != expected {
        return Err(KemError::BadLength(what, expected, value.len()));
    }
    Ok(())
}

/// A hybrid keypair on the wire.
#[derive(Clone)]
pub struct HybridKeyPair {
    /// 1216-byte `X25519_pub ‖ MLKEM768_ek`.
    pub public_key: Vec<u8>,
    /// 2432-byte `X25519_seed ‖ MLKEM768_dk`.
    pub private_key: Vec<u8>,
}

/// Concat-then-KDF combiner. X25519 secret FIRST, then ML-KEM secret.
/// `HKDF-SHA256(x25519_ss ‖ mlkem_ss, salt = b"", info, L = 32)`.
fn combine(x25519_ss: &[u8], mlkem_ss: &[u8]) -> [u8; SHARED_SECRET_LEN] {
    let mut ikm = Vec::with_capacity(x25519_ss.len() + mlkem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);
    // salt = b"" (RFC 5869: HMAC zero-pads a sub-block key, so an empty salt and
    // a HashLen-zero salt yield the same PRK — matches pyca HKDF(salt=b"")).
    let hk = Hkdf::<Sha256>::new(Some(b""), &ikm);
    let mut okm = [0u8; SHARED_SECRET_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Generate a fresh hybrid keypair laid out as `X25519_part ‖ MLKEM768_part`.
pub fn hybrid_keypair() -> HybridKeyPair {
    let mut rng = OsRng;

    let x_static = StaticSecret::random_from_rng(&mut rng);
    let x_pub = PublicKey::from(&x_static);
    let x_seed = x_static.to_bytes();

    let (dk, ek) = MlKem768::generate(&mut rng);
    let ek_bytes = ek.as_bytes();
    let dk_bytes = dk.as_bytes();

    let mut public_key = Vec::with_capacity(PUBLIC_KEY_LEN);
    public_key.extend_from_slice(x_pub.as_bytes());
    public_key.extend_from_slice(&ek_bytes);

    let mut private_key = Vec::with_capacity(PRIVATE_KEY_LEN);
    private_key.extend_from_slice(&x_seed);
    private_key.extend_from_slice(&dk_bytes);

    HybridKeyPair {
        public_key,
        private_key,
    }
}

/// Encapsulate to a peer's 1216-byte hybrid public key.
///
/// Returns `(ciphertext, shared_secret)` — ciphertext is 1120 bytes
/// (`X25519_eph_pub ‖ MLKEM768_ct`), shared secret is 32 bytes.
pub fn hybrid_encap(peer_public_key: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), KemError> {
    expect_len("hybrid public key", peer_public_key, PUBLIC_KEY_LEN)?;

    let mut x_peer_arr = [0u8; X25519_PUB_LEN];
    x_peer_arr.copy_from_slice(&peer_public_key[..X25519_PUB_LEN]);
    let x_peer = PublicKey::from(x_peer_arr);

    let mlkem_pub = &peer_public_key[X25519_PUB_LEN..];
    let ek_enc = Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(mlkem_pub)
        .map_err(|_| KemError::BadLength("ML-KEM public key", MLKEM_PUB_LEN, mlkem_pub.len()))?;
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);

    let mut rng = OsRng;
    let x_eph = StaticSecret::random_from_rng(&mut rng);
    let x_eph_pub = PublicKey::from(&x_eph);
    let x_ss = x_eph.diffie_hellman(&x_peer);

    let (ct, mlkem_ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| KemError::MlKem("encapsulation failed"))?;

    let mut ciphertext = Vec::with_capacity(CIPHERTEXT_LEN);
    ciphertext.extend_from_slice(x_eph_pub.as_bytes());
    ciphertext.extend_from_slice(&ct);

    let shared = combine(x_ss.as_bytes(), &mlkem_ss);
    Ok((ciphertext, shared))
}

/// Decapsulate a 1120-byte hybrid ciphertext with the 2432-byte private key.
///
/// ML-KEM uses implicit rejection: a tampered ML-KEM ciphertext does NOT error —
/// it yields a pseudo-random secret that simply won't match the sender's. Wrong
/// *length* still returns [`KemError::BadLength`].
pub fn hybrid_decap(
    ciphertext: &[u8],
    private_key: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], KemError> {
    expect_len("hybrid ciphertext", ciphertext, CIPHERTEXT_LEN)?;
    expect_len("hybrid private key", private_key, PRIVATE_KEY_LEN)?;

    let mut x_eph_arr = [0u8; X25519_PUB_LEN];
    x_eph_arr.copy_from_slice(&ciphertext[..X25519_PUB_LEN]);
    let x_eph_pub = PublicKey::from(x_eph_arr);
    let mlkem_ct = &ciphertext[X25519_PUB_LEN..];

    let mut x_seed = [0u8; X25519_SEED_LEN];
    x_seed.copy_from_slice(&private_key[..X25519_SEED_LEN]);
    let x_static = StaticSecret::from(x_seed);
    let mlkem_dk = &private_key[X25519_SEED_LEN..];

    let x_ss = x_static.diffie_hellman(&x_eph_pub);

    let dk_enc = Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::try_from(mlkem_dk)
        .map_err(|_| KemError::BadLength("ML-KEM secret key", MLKEM_SECRET_LEN, mlkem_dk.len()))?;
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_enc);

    let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(mlkem_ct)
        .map_err(|_| KemError::BadLength("ML-KEM ciphertext", MLKEM_CT_LEN, mlkem_ct.len()))?;
    let mlkem_ss = dk
        .decapsulate(&ct_arr)
        .map_err(|_| KemError::MlKem("decapsulation failed"))?;

    Ok(combine(x_ss.as_bytes(), &mlkem_ss))
}

// Keep the params type referenced so an upstream rename surfaces at compile time.
#[allow(dead_code)]
type _AssertParams = MlKem768Params;
