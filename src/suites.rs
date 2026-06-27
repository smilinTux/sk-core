//! Cryptographic-suite registry — the crypto-agility seam (clean-room of
//! `skcomms/src/skcomms/crypto_suites.py`).
//!
//! This module performs **no cryptography**. It is the single source of truth for
//! what every crypto suite-id *means* and whether it is quantum-resistant. Giving
//! every encrypted / signed object a machine-readable *suite identifier* is what
//! makes future algorithm swaps non-breaking (policy / mechanism separation,
//! NIST CSWP 39) and what lets the runtime self-report (see [`crate::report`])
//! make honest, evidence-backed claims.
//!
//! A suite is one of three [`SuiteKind`]s — `kem` (key encapsulation /
//! key-exchange), `sig` (digital signature), or `aead` (symmetric authenticated
//! encryption) — and carries a [`SuiteStatus`] describing its quantum-resistance
//! posture. The deliberate, **honest** statuses are `classical`, `hybrid-pq`,
//! `pq`, and `symmetric`; there is no `quantum-proof` / `quantum-safe` state,
//! because no such guarantee exists.
//!
//! ## Honest claims
//!
//! [`CryptoSuite::is_quantum_resistant`] is the *single* predicate the
//! self-report uses, so no caller hand-rolls the (over-claimable) logic. It is
//! true only for `hybrid-pq`, `pq`, and `symmetric` suites — classical
//! asymmetric suites (Shor-breakable) are never quantum-resistant. A `hybrid-pq`
//! suite is secure if **either** its classical or its post-quantum leg holds; it
//! is *not* "unbreakable". The post-quantum KEM cites **FIPS 203** (ML-KEM); the
//! hybrid signature cites **FIPS 204** (ML-DSA, not registered here).
//!
//! This is byte-string-for-byte-string interoperable with the Python registry:
//! the `suite_id` / `status` / `kind` strings that travel on the wire
//! (`sig_suite` / `kem_suite` fields) are identical.

use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::sync::OnceLock;

/// What a suite *does*.
///
/// Serialises to the exact wire strings `"kem"`, `"sig"`, `"aead"` (matching the
/// Python `SuiteKind(str, Enum)` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuiteKind {
    /// Key encapsulation / key-exchange (confidentiality; HNDL-relevant).
    Kem,
    /// Digital signature (authentication; future-forgery-relevant).
    Sig,
    /// Symmetric authenticated encryption (already quantum-acceptable).
    Aead,
}

impl SuiteKind {
    /// The canonical wire string (`"kem"` / `"sig"` / `"aead"`).
    pub fn as_str(self) -> &'static str {
        match self {
            SuiteKind::Kem => "kem",
            SuiteKind::Sig => "sig",
            SuiteKind::Aead => "aead",
        }
    }
}

impl Serialize for SuiteKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// Quantum-resistance posture of a suite.
///
/// Deliberately four honest states — never "quantum-proof" / "quantum-safe".
/// Serialises to the exact wire strings `"classical"`, `"hybrid-pq"`, `"pq"`,
/// `"symmetric"` (matching the Python `SuiteStatus(str, Enum)` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuiteStatus {
    /// Shor- or Grover-relevant classical primitive(s) — *not* quantum-resistant.
    Classical,
    /// Classical ‖ PQ combiner — secure if **either** leg holds.
    HybridPq,
    /// Pure post-quantum (no classical component).
    Pq,
    /// Symmetric / hash — Grover-only, quantum-acceptable.
    Symmetric,
}

impl SuiteStatus {
    /// The canonical wire string (`"classical"` / `"hybrid-pq"` / `"pq"` /
    /// `"symmetric"`).
    pub fn as_str(self) -> &'static str {
        match self {
            SuiteStatus::Classical => "classical",
            SuiteStatus::HybridPq => "hybrid-pq",
            SuiteStatus::Pq => "pq",
            SuiteStatus::Symmetric => "symmetric",
        }
    }

    /// Parse a wire string back to a status. Unknown strings map to
    /// [`SuiteStatus::Classical`] — the honest default (an unrecognised suite
    /// must never be reported as quantum-resistant).
    pub fn from_wire(s: &str) -> SuiteStatus {
        match s {
            "hybrid-pq" => SuiteStatus::HybridPq,
            "pq" => SuiteStatus::Pq,
            "symmetric" => SuiteStatus::Symmetric,
            _ => SuiteStatus::Classical,
        }
    }

    /// Whether this *status* counts as quantum-resistant. The single predicate
    /// behind [`CryptoSuite::is_quantum_resistant`] and the self-report.
    pub fn is_quantum_resistant(self) -> bool {
        matches!(
            self,
            SuiteStatus::HybridPq | SuiteStatus::Pq | SuiteStatus::Symmetric
        )
    }
}

impl Serialize for SuiteStatus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A single registered cipher suite — an immutable lookup-table row.
///
/// The `suite_id` is the stable, machine-readable value that travels on the wire
/// in `sig_suite` / `kem_suite` fields. Everything else is descriptive metadata
/// the self-report cites; nothing here performs cryptography.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoSuite {
    /// Stable machine-readable identifier (e.g. `"x25519-mlkem768"`).
    pub suite_id: String,
    /// Whether this is a KEM, signature, or AEAD suite.
    pub kind: SuiteKind,
    /// Quantum-resistance posture.
    pub status: SuiteStatus,
    /// Ordered human-readable list of the underlying primitives.
    pub primitives: Vec<String>,
    /// FIPS / RFC references backing the claim (e.g. `["FIPS 203"]`).
    pub fips_refs: Vec<String>,
    /// One-line human summary.
    pub description: String,
    /// Whether this suite is *actually wired into running code*. The honesty
    /// gate: planned-but-unimplemented suites are seeded `false` so the
    /// self-report cannot overclaim.
    pub active: bool,
    /// Optional `suite_id` this is the migration target for (agility breadcrumb,
    /// no behavioural effect).
    pub replaces: Option<String>,
}

impl CryptoSuite {
    /// Construct a suite from `&str` slices (ergonomic registry seeding).
    ///
    /// `primitives` and `fips_refs` are copied into owned `String`s. `replaces`
    /// is `None` unless set via [`CryptoSuite::replacing`].
    pub fn new(
        suite_id: &str,
        kind: SuiteKind,
        status: SuiteStatus,
        primitives: &[&str],
        fips_refs: &[&str],
        description: &str,
        active: bool,
    ) -> CryptoSuite {
        CryptoSuite {
            suite_id: suite_id.to_string(),
            kind,
            status,
            primitives: primitives.iter().map(|s| s.to_string()).collect(),
            fips_refs: fips_refs.iter().map(|s| s.to_string()).collect(),
            description: description.to_string(),
            active,
            replaces: None,
        }
    }

    /// Builder: mark this suite as the migration target for `suite_id`.
    pub fn replacing(mut self, suite_id: &str) -> CryptoSuite {
        self.replaces = Some(suite_id.to_string());
        self
    }

    /// True only for hybrid-PQ, pure-PQ, or symmetric suites.
    ///
    /// Classical asymmetric suites are *not* quantum-resistant. This is the
    /// single predicate the self-report uses so no caller re-implements the
    /// (over-claimable) logic.
    pub fn is_quantum_resistant(&self) -> bool {
        self.status.is_quantum_resistant()
    }

    /// JSON-safe view (for the self-report). Byte-for-byte the same key set and
    /// value strings as the Python `CryptoSuite.to_dict`: `suite_id`, `kind`,
    /// `status`, `primitives`, `fips_refs`, `description`, `active`,
    /// `quantum_resistant`, `replaces`.
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "suite_id": self.suite_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "primitives": self.primitives,
            "fips_refs": self.fips_refs,
            "description": self.description,
            "active": self.active,
            "quantum_resistant": self.is_quantum_resistant(),
            "replaces": self.replaces,
        })
    }
}

impl Serialize for CryptoSuite {
    /// Serialises to the same shape as [`CryptoSuite::to_dict`].
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_dict().serialize(s)
    }
}

// ---------------------------------------------------------------------------
// Default suite ids (the classical Q0 defaults baked into the data models).
// ---------------------------------------------------------------------------

/// Default suite id for the at-rest symmetric layer today.
pub const DEFAULT_AT_REST_SUITE: &str = "aes256-gcm-v1";
/// Default classical KEM / key-wrap suite (skcomms envelope / DM wrap today).
pub const DEFAULT_KEM_SUITE: &str = "x25519-pgp-wrap-v1";

/// An in-memory suite registry — `suite_id → CryptoSuite`.
///
/// Construct a fresh one with [`Registry::seeded`] (the canonical set) or
/// [`Registry::empty`] (then [`Registry::register`]). The process-wide singleton
/// used by the free functions ([`get_suite`], [`all_suites`], …) is
/// [`Registry::global`].
#[derive(Debug, Clone, Default)]
pub struct Registry {
    by_id: HashMap<String, CryptoSuite>,
}

impl Registry {
    /// A registry with no suites.
    pub fn empty() -> Registry {
        Registry {
            by_id: HashMap::new(),
        }
    }

    /// A registry seeded with the canonical suites (clean-room of the Python
    /// `_seed()` — the subset wired into this Rust core):
    ///
    /// * `x25519-mlkem768` — **hybrid-pq** KEM (X25519 ‖ ML-KEM-768, FIPS 203),
    ///   the live primitive this crate implements (see [`crate::kem`]).
    /// * `x25519-pgp-wrap-v1` — **classical** X25519 PGP key-wrap.
    /// * `aes256-gcm-v1` — **symmetric** AES-256-GCM bulk cipher.
    pub fn seeded() -> Registry {
        let mut r = Registry::empty();
        // ---- Classical KEM / key-wrap (LIVE today) ----------------------
        r.register(CryptoSuite::new(
            "x25519-pgp-wrap-v1",
            SuiteKind::Kem,
            SuiteStatus::Classical,
            &["X25519 (Curve25519) PGP key-wrap", "AES-256 session key"],
            &["RFC 7748", "RFC 9580"],
            "Classical X25519 PGP key-wrap of an AES-256 session key \
             (skcomms envelope payload / DM wrap today).",
            true,
        ));
        // ---- Symmetric / at-rest (already quantum-acceptable) -----------
        r.register(CryptoSuite::new(
            "aes256-gcm-v1",
            SuiteKind::Aead,
            SuiteStatus::Symmetric,
            &["AES-256-GCM", "HKDF-SHA256"],
            &["FIPS 197", "SP 800-38D", "SP 800-108"],
            "AES-256-GCM bulk cipher — Grover-only (~128-bit), \
             quantum-acceptable. Do not migrate.",
            true,
        ));
        // ---- ACTIVE hybrid-PQ KEM (the live primitive in crate::kem) ----
        r.register(
            CryptoSuite::new(
                "x25519-mlkem768",
                SuiteKind::Kem,
                SuiteStatus::HybridPq,
                &[
                    "X25519 (ephemeral-static DHKEM)",
                    "ML-KEM-768 (FIPS 203, liboqs)",
                    "HKDF-SHA256 concat-KDF combiner",
                ],
                &["FIPS 203", "RFC 7748", "RFC 5869"],
                "LIVE hybrid X25519 || ML-KEM-768 key-encapsulation primitive \
                 (sk_pqc::kem). Secret unless BOTH primitives break. \
                 Cross-impl interoperable with sk_pqc (Dart) and skcomms.pqkem.",
                true,
            )
            .replacing("x25519-pgp-wrap-v1"),
        );
        r
    }

    /// Register a suite (idempotent by `suite_id`, last-write-wins). Returns a
    /// clone of the stored suite for convenience.
    pub fn register(&mut self, suite: CryptoSuite) -> CryptoSuite {
        let stored = suite.clone();
        self.by_id.insert(suite.suite_id.clone(), suite);
        stored
    }

    /// Return the registered suite for `suite_id` (or `None` if unknown).
    pub fn get_suite(&self, suite_id: &str) -> Option<&CryptoSuite> {
        self.by_id.get(suite_id)
    }

    /// Return all registered suites in a **stable** order (matching the Python
    /// `all_suites`): sort key is `(not active, status, suite_id)`, so active
    /// suites come first, then by status string, then by id.
    pub fn all_suites(&self) -> Vec<&CryptoSuite> {
        let mut v: Vec<&CryptoSuite> = self.by_id.values().collect();
        v.sort_by(|a, b| {
            (!a.active, a.status.as_str(), a.suite_id.as_str()).cmp(&(
                !b.active,
                b.status.as_str(),
                b.suite_id.as_str(),
            ))
        });
        v
    }

    /// Return only the suites wired into running code (`active == true`), in the
    /// same stable order as [`Registry::all_suites`].
    pub fn active_suites(&self) -> Vec<&CryptoSuite> {
        self.all_suites().into_iter().filter(|s| s.active).collect()
    }

    /// The status of a suite id, defaulting to [`SuiteStatus::Classical`] if
    /// unknown — an unrecognised suite must never be reported quantum-resistant.
    pub fn suite_status(&self, suite_id: &str) -> SuiteStatus {
        self.get_suite(suite_id)
            .map(|s| s.status)
            .unwrap_or(SuiteStatus::Classical)
    }

    /// Whether the given suite id is quantum-resistant (`false` if unknown).
    pub fn is_quantum_resistant(&self, suite_id: &str) -> bool {
        self.get_suite(suite_id)
            .map(|s| s.is_quantum_resistant())
            .unwrap_or(false)
    }

    /// The process-wide singleton, seeded once with the canonical suites.
    pub fn global() -> &'static Registry {
        static GLOBAL: OnceLock<Registry> = OnceLock::new();
        GLOBAL.get_or_init(Registry::seeded)
    }
}

// ---------------------------------------------------------------------------
// Free functions over the global registry (mirror the Python module API).
// ---------------------------------------------------------------------------

/// Return the globally-registered suite for `suite_id` (or `None` if unknown).
pub fn get_suite(suite_id: &str) -> Option<&'static CryptoSuite> {
    Registry::global().get_suite(suite_id)
}

/// Return all globally-registered suites (stable order; see
/// [`Registry::all_suites`]).
pub fn all_suites() -> Vec<&'static CryptoSuite> {
    Registry::global().all_suites()
}

/// Return only the globally-registered suites wired into running code.
pub fn active_suites() -> Vec<&'static CryptoSuite> {
    Registry::global().active_suites()
}

/// The status of a suite id over the global registry (CLASSICAL if unknown).
pub fn suite_status(suite_id: &str) -> SuiteStatus {
    Registry::global().suite_status(suite_id)
}

/// Whether the given suite id is quantum-resistant over the global registry
/// (`false` if unknown).
pub fn is_quantum_resistant(suite_id: &str) -> bool {
    Registry::global().is_quantum_resistant(suite_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_predicate_honesty() {
        // Classical asymmetric is NEVER quantum-resistant.
        assert!(!SuiteStatus::Classical.is_quantum_resistant());
        // The three honest QR statuses.
        assert!(SuiteStatus::HybridPq.is_quantum_resistant());
        assert!(SuiteStatus::Pq.is_quantum_resistant());
        assert!(SuiteStatus::Symmetric.is_quantum_resistant());
    }

    #[test]
    fn seeded_registry_has_the_three_named_suites() {
        let r = Registry::seeded();
        assert_eq!(
            r.suite_status("x25519-mlkem768"),
            SuiteStatus::HybridPq
        );
        assert_eq!(
            r.suite_status("x25519-pgp-wrap-v1"),
            SuiteStatus::Classical
        );
        assert_eq!(r.suite_status("aes256-gcm-v1"), SuiteStatus::Symmetric);
        // The hybrid KEM is the migration target for the classical wrap.
        assert_eq!(
            r.get_suite("x25519-mlkem768").unwrap().replaces.as_deref(),
            Some("x25519-pgp-wrap-v1")
        );
    }

    #[test]
    fn quantum_resistance_per_suite() {
        let r = Registry::seeded();
        assert!(r.is_quantum_resistant("x25519-mlkem768"));
        assert!(r.is_quantum_resistant("aes256-gcm-v1"));
        // Classical wrap is HNDL-exposed — not quantum-resistant.
        assert!(!r.is_quantum_resistant("x25519-pgp-wrap-v1"));
    }

    #[test]
    fn unknown_suite_is_classical_and_not_qr() {
        let r = Registry::seeded();
        // Honesty: an unrecognised id must never read as quantum-resistant.
        assert!(r.get_suite("totally-made-up").is_none());
        assert_eq!(r.suite_status("totally-made-up"), SuiteStatus::Classical);
        assert!(!r.is_quantum_resistant("totally-made-up"));
    }

    #[test]
    fn all_suites_stable_classical_first_then_status_then_id() {
        let r = Registry::seeded();
        let ids: Vec<&str> = r.all_suites().iter().map(|s| s.suite_id.as_str()).collect();
        // All active → sort by status string ("classical" < "hybrid-pq" <
        // "symmetric"), then suite_id.
        assert_eq!(
            ids,
            vec!["x25519-pgp-wrap-v1", "x25519-mlkem768", "aes256-gcm-v1"]
        );
    }

    #[test]
    fn register_is_idempotent_last_write_wins() {
        let mut r = Registry::empty();
        r.register(CryptoSuite::new(
            "x",
            SuiteKind::Kem,
            SuiteStatus::Classical,
            &["a"],
            &[],
            "first",
            true,
        ));
        r.register(CryptoSuite::new(
            "x",
            SuiteKind::Kem,
            SuiteStatus::HybridPq,
            &["b"],
            &[],
            "second",
            true,
        ));
        assert_eq!(r.all_suites().len(), 1);
        assert_eq!(r.get_suite("x").unwrap().description, "second");
        assert_eq!(r.get_suite("x").unwrap().status, SuiteStatus::HybridPq);
    }

    /// Byte-for-byte parity with the Python `CryptoSuite.to_dict` JSON shape for
    /// the hybrid KEM: exact key set + value strings (the wire contract).
    #[test]
    fn parity_to_dict_json_shape() {
        let r = Registry::seeded();
        let d = r.get_suite("x25519-mlkem768").unwrap().to_dict();
        assert_eq!(d["suite_id"], "x25519-mlkem768");
        assert_eq!(d["kind"], "kem");
        assert_eq!(d["status"], "hybrid-pq");
        assert_eq!(d["quantum_resistant"], true);
        assert_eq!(d["active"], true);
        assert_eq!(d["replaces"], "x25519-pgp-wrap-v1");
        assert_eq!(d["fips_refs"][0], "FIPS 203");
        assert_eq!(d["primitives"][1], "ML-KEM-768 (FIPS 203, liboqs)");
        // All nine canonical keys are present.
        let obj = d.as_object().unwrap();
        for k in [
            "suite_id",
            "kind",
            "status",
            "primitives",
            "fips_refs",
            "description",
            "active",
            "quantum_resistant",
            "replaces",
        ] {
            assert!(obj.contains_key(k), "missing key {k}");
        }
    }

    #[test]
    fn global_singleton_is_seeded() {
        assert!(get_suite("x25519-mlkem768").is_some());
        assert!(is_quantum_resistant("x25519-mlkem768"));
        assert!(!is_quantum_resistant("x25519-pgp-wrap-v1"));
        assert_eq!(active_suites().len(), 3);
    }
}
