//! # sk_core — sovereign shared Rust PQC core
//!
//! Foundation primitives for the SK ecosystem's confidentiality surfaces, in a
//! small clean-room Rust library that is **byte-for-byte interoperable** with the
//! Python `skcomms`/`skchat` daemons.
//!
//! - [`kem`] — hybrid **X25519 + ML-KEM-768** (`x25519-mlkem768`) KEM combiner:
//!   `HKDF-SHA256(X25519_ss ‖ MLKEM_ss)` concat-then-KDF, 32-byte output. ML-KEM
//!   is **FIPS 203** (RustCrypto `ml-kem`); X25519 is `x25519-dalek`.
//! - [`ratchet`] — SKChat 1:1 DM epoch-ratchet key schedule
//!   ([`ratchet::derive_dm_message_key`]) and the [`ratchet::should_rekey`] bound.
//!
//! ## Honest claims
//!
//! This is a **hybrid** scheme: secure as long as **either** the classical X25519
//! leg **or** the ML-KEM-768 leg holds. It is **not** "quantum-proof",
//! "quantum-safe", or "unbreakable". We never hand-roll lattice or curve math —
//! every primitive is a vetted RustCrypto / dalek crate; only the HKDF combiner
//! wiring is original. Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA, not used).

pub mod kem;
pub mod ratchet;
