//! # sk_pqc — sovereign shared Rust PQC core
//!
//! Foundation primitives for the SK ecosystem's confidentiality surfaces, in a
//! small clean-room Rust library that is **byte-for-byte interoperable** with the
//! Python `skcomms`/`skchat` daemons.
//!
//! The full SK confidentiality toolkit, in a clean-room Rust library that is
//! **byte-for-byte interoperable** with the Python `skcomms`/`skchat`/`sksecurity`
//! daemons (and the Dart `sk_pqc`):
//!
//! - [`kem`] — hybrid **X25519 + ML-KEM-768** (`x25519-mlkem768`) KEM combiner:
//!   `HKDF-SHA256(X25519_ss ‖ MLKEM_ss)` concat-then-KDF, 32-byte output. ML-KEM
//!   is **FIPS 203** (RustCrypto `ml-kem`); X25519 is `x25519-dalek`.
//! - [`ratchet`] — the 1:1 **DM epoch-ratchet**: per-message key schedule, hybrid
//!   epoch-secret wrap/unwrap, and the rekey bound (forward secrecy + PCS).
//! - [`dm_session`] — the stateful DM session driver (epoch lifecycle + KAM frames).
//! - [`group_ratchet`] — the **group epoch-ratchet** (per-epoch hybrid-wrapped key).
//! - [`pqdm`] — hybrid **DM sealing** with the downgrade-lock AAD.
//! - [`pqroute`] — the **metadata-routing envelope** (outer header + hybrid-sealed
//!   inner metadata+content).
//! - [`anon_queue`] — **anonymous, no-identity addressing** (opaque queue ids,
//!   `aqid:` codec, deniable HMAC auth).
//! - [`suites`] — the **crypto-suite registry** (the crypto-agility seam).
//! - [`report`] — the **honest self-report** (claim-evidence, never overclaims).
//!
//! ## Honest claims
//!
//! This is a **hybrid** scheme: secure as long as **either** the classical X25519
//! leg **or** the ML-KEM-768 leg holds. It is **not** "quantum-proof",
//! "quantum-safe", or "unbreakable". We never hand-roll lattice or curve math —
//! every primitive is a vetted RustCrypto / dalek crate; only the HKDF combiner
//! wiring is original. Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA, not used).

pub mod anon_queue;
pub mod dm_session;
pub mod group_ratchet;
pub mod kem;
pub mod pqdm;
pub mod pqroute;
pub mod ratchet;
pub mod report;
pub mod suites;
