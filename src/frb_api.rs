//! Optional **flutter_rust_bridge (frb)** API surface — gated behind the `dart`
//! feature (off by default).
//!
//! This is the Dart twin of `crate::python`: it lets the Dart `sk_pqc`
//! package be backed by the **same pure-Rust core** (the ML-KEM-768 leg is
//! RustCrypto `ml-kem` — **FIPS 203**; the X25519 leg is `x25519-dalek`), the
//! way the PyO3 bindings back the Python services. flutter_rust_bridge turns
//! the functions below into generated Dart glue (`flutter_rust_bridge_codegen
//! generate`), so the Flutter/Dart client reaches this core over FFI.
//!
//! These are **thin** wrappers: every byte of crypto wiring lives in
//! [`crate::kem`] and [`crate::ratchet`]; here we only marshal `Vec<u8>` and map
//! the crate error enums onto `String` (which frb surfaces as a Dart exception).
//!
//! **Hybrid**, not "quantum-proof": the derived secret holds as long as
//! **either** the classical X25519 leg **or** the ML-KEM-768 leg holds.
//! Standards: FIPS 203 (ML-KEM). ML-DSA / FIPS 204 is signatures — not used here.
//!
//! ## Why feature-gated
//! `flutter_rust_bridge` (and the codegen-emitted `frb_generated.rs`) are only
//! compiled with `--features dart`. The default `cargo build` / `cargo test`
//! path never pulls in frb and stays pure-Rust (the 99 in-tree tests are
//! unchanged). See `flutter_rust_bridge.yaml` and the README "Dart bindings".

use crate::kem;
use crate::ratchet;

/// A hybrid keypair, mirrored into Dart as a plain class by frb.
///
/// `public_key` is 1216 B (`X25519_pub ‖ MLKEM768_ek`); `private_key` is 2432 B
/// (`X25519_seed ‖ MLKEM768_dk`). Byte-compatible with the Dart `HybridKeyPair`
/// and `sk_pqc.hybrid_keypair()`.
pub struct FrbHybridKeyPair {
    /// 1216-byte composite public key.
    pub public_key: Vec<u8>,
    /// 2432-byte composite private key.
    pub private_key: Vec<u8>,
}

/// The result of [`hybrid_encap`], mirrored into Dart by frb.
///
/// `ciphertext` is 1120 B (`X25519_eph_pub ‖ MLKEM768_ct`); `shared_secret` is
/// the 32-byte hybrid secret. Byte-compatible with the Dart `EncapResult`.
pub struct FrbEncapResult {
    /// 1120-byte composite ciphertext.
    pub ciphertext: Vec<u8>,
    /// 32-byte hybrid shared secret.
    pub shared_secret: Vec<u8>,
}

/// Fresh hybrid keypair: 1216-byte public + 2432-byte private, laid out
/// `X25519_part ‖ MLKEM768_part`. Byte-compatible with the Dart
/// `HybridKemImpl.generateKeyPair()` wire format.
#[flutter_rust_bridge::frb(sync)]
pub fn hybrid_keypair() -> FrbHybridKeyPair {
    let kp = kem::hybrid_keypair();
    FrbHybridKeyPair {
        public_key: kp.public_key,
        private_key: kp.private_key,
    }
}

/// Encapsulate to a 1216-byte peer hybrid public key. Returns the 1120-byte
/// ciphertext and the 32-byte shared secret. Errors (as a Dart exception) on a
/// wrong-length key. Wire-compatible with the Dart `HybridKem.encapsulate()` — a
/// ciphertext from either side decapsulates on the other.
#[flutter_rust_bridge::frb(sync)]
pub fn hybrid_encap(peer_public_key: Vec<u8>) -> Result<FrbEncapResult, String> {
    let (ciphertext, shared) = kem::hybrid_encap(&peer_public_key).map_err(|e| e.to_string())?;
    Ok(FrbEncapResult {
        ciphertext,
        shared_secret: shared.to_vec(),
    })
}

/// Decapsulate a 1120-byte ciphertext with a 2432-byte hybrid private key →
/// 32-byte shared secret. Errors only on a wrong *length*; ML-KEM implicit
/// rejection (FIPS 203) means a tampered ciphertext yields a pseudo-random
/// secret (no error, no padding oracle). Byte-compatible with the Dart
/// `HybridKem.decapsulate()`.
#[flutter_rust_bridge::frb(sync)]
pub fn hybrid_decap(ciphertext: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, String> {
    let shared = kem::hybrid_decap(&ciphertext, &private_key).map_err(|e| e.to_string())?;
    Ok(shared.to_vec())
}

/// Deterministic, index-addressable 32-byte DM message key. Errors if
/// `epoch_secret` is not 32 bytes. Byte-for-byte identical to the Dart
/// `deriveDmMessageKey()` and `sk_pqc.derive_dm_message_key()` (shared HKDF
/// labels / KAT).
#[flutter_rust_bridge::frb(sync)]
pub fn derive_dm_message_key(
    epoch_secret: Vec<u8>,
    epoch: u64,
    index: u64,
) -> Result<Vec<u8>, String> {
    let key =
        ratchet::derive_dm_message_key(&epoch_secret, epoch, index).map_err(|e| e.to_string())?;
    Ok(key.to_vec())
}

/// The hybrid suite identifier (`x25519-mlkem768`). Lets the Dart side assert it
/// is talking to the expected core. Matches the Dart `kSuiteId`.
#[flutter_rust_bridge::frb(sync)]
pub fn suite_id() -> String {
    kem::SUITE_ID.to_string()
}

/// The interop wire lengths, mirrored into Dart so the binding can self-check
/// against `SkPqcSizes`. Order: public, private, ciphertext, shared-secret.
#[flutter_rust_bridge::frb(sync)]
pub fn wire_sizes() -> Vec<u64> {
    vec![
        kem::PUBLIC_KEY_LEN as u64,
        kem::PRIVATE_KEY_LEN as u64,
        kem::CIPHERTEXT_LEN as u64,
        kem::SHARED_SECRET_LEN as u64,
    ]
}
