//! Hybrid PQ message sealing — the PQXDH-style wrap for DMs + envelope payloads
//! (clean-room of `skcomms/src/skcomms/pqdm.py`).
//!
//! This is the Harvest-Now-Decrypt-Later (HNDL) fix for two confidentiality
//! surfaces — the skcomms envelope payload and the skchat 1:1 DM body. Both share
//! ONE construction, defined here, so the crypto is written once. It composes the
//! vetted hybrid KEM ([`crate::kem`], `x25519-mlkem768`, **FIPS 203** ML-KEM-768
//! leg) with AES-256-GCM + HKDF-SHA256.
//!
//! # The sealed blob (interop wire contract)
//!
//! ```text
//! sealed = ct(1120) ‖ nonce(12) ‖ aesgcm(body)        # body + 16-byte GCM tag
//! ```
//!
//! # Wrap-key derivation
//!
//! ```text
//! (ct, ss) = hybrid_encap(recipient_hybrid_pub)        # ss = HKDF(X25519 ‖ ML-KEM-768)
//! aad      = downgrade_lock_aad(negotiated_suite, sender, recipient)
//! wrap_key = HKDF-SHA256(IKM = ss, salt = b"", info = b"skcomms/pqdm/wrap/v1" ‖ b"|" ‖ aad, L = 32)
//! body     = AES-256-GCM(wrap_key).encrypt(nonce, plaintext, aad)
//! sealed   = ct ‖ nonce ‖ body
//! ```
//!
//! # Crypto-agility + downgrade-lock
//!
//! The negotiated suite id is **bound into the AEAD AAD** (the transcript). A peer
//! that strips the hybrid prekey to force a classical downgrade changes the
//! `negotiated_suite` the sender seals under, so a man-in-the-middle cannot
//! *silently* strip the PQ option: the recipient's AEAD open fails (the AAD won't
//! match) or the recorded suite no longer says hybrid. The lock is the AAD
//! binding; the AAD is canonical, sorted-key, compact JSON so both sides derive
//! identical bytes.
//!
//! # Honest claims
//!
//! This is a **hybrid**, not a "quantum-proof" / "unbreakable" scheme. The sealed
//! body stays confidential if **either** the X25519 leg **or** the ML-KEM-768 leg
//! (FIPS 203) holds. No crypto is hand-rolled here: ML-KEM/X25519 come from
//! [`crate::kem`] (RustCrypto `ml-kem` + `x25519-dalek`), and this module only
//! wires those to `aes-gcm` + `hkdf` + `sha2`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::kem::{self, KemError};

// --- Interop constants (DO NOT CHANGE — pinned by skcomms/pqdm.py) -----------

/// The hybrid KEM suite id (matches [`crate::kem::SUITE_ID`] and
/// `skcomms.pqdm.HYBRID_SUITE`). When this is the negotiated suite, the body is
/// hybrid-sealed.
pub const HYBRID_SUITE: &str = "x25519-mlkem768";

/// The classical suite id a peer falls back to when it advertises no hybrid
/// prekey (negotiated downgrade). Matches `skcomms.pqdm.CLASSICAL_SUITE`.
pub const CLASSICAL_SUITE: &str = "x25519-pgp-wrap-v1";

/// HKDF domain-separation label for the DM/envelope wrap key. Distinct from the
/// group/DM ratchet labels so a wrap key can never collide with an epoch key.
/// Equals `skcomms.pqdm._INFO_WRAP`.
pub const INFO_WRAP: &[u8] = b"skcomms/pqdm/wrap/v1";

/// AES-256-GCM nonce length (bytes).
pub const WRAP_NONCE_LEN: usize = 12;

/// AES-256-GCM authentication-tag length (bytes).
pub const AESGCM_TAG_LEN: usize = 16;

/// Minimum sealed-blob length: `ct(1120) + nonce(12) + tag(16)` for an empty
/// body. Equals `skcomms.pqdm.SEALED_MIN_LEN`.
pub const SEALED_MIN_LEN: usize = kem::CIPHERTEXT_LEN + WRAP_NONCE_LEN + AESGCM_TAG_LEN;

// --- Errors ------------------------------------------------------------------

/// Errors from hybrid DM/envelope sealing (never a panic on malformed input).
///
/// Mirrors the Python exception hierarchy: [`PqDmError::Format`] ↔
/// `PqDmFormatError`, [`PqDmError::DowngradeDetected`] ↔ `DowngradeDetected`,
/// [`PqDmError::Kem`] ↔ a propagated `PqKemError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqDmError {
    /// Malformed input (wrong public-key length, blob shorter than
    /// [`SEALED_MIN_LEN`], …). Never a crash. ↔ Python `PqDmFormatError`.
    Format(String),
    /// The AEAD open failed: wrong key, tampered ciphertext/tag, or a
    /// suite/party downgrade attempt (the bound AAD did not authenticate the
    /// body). Treat as a security event, not a retry-as-classical. ↔ Python
    /// `DowngradeDetected`.
    DowngradeDetected(String),
    /// Propagated from the hybrid KEM ([`crate::kem`]). The hybrid path never
    /// silently downgrades on a KEM failure.
    Kem(KemError),
}

impl fmt::Display for PqDmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqDmError::Format(m) => write!(f, "pqdm format error: {m}"),
            PqDmError::DowngradeDetected(m) => write!(f, "pqdm downgrade detected: {m}"),
            PqDmError::Kem(e) => write!(f, "pqdm KEM error: {e}"),
        }
    }
}

impl Error for PqDmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PqDmError::Kem(e) => Some(e),
            _ => None,
        }
    }
}

impl From<KemError> for PqDmError {
    fn from(e: KemError) -> Self {
        PqDmError::Kem(e)
    }
}

// --- Downgrade-lock AAD ------------------------------------------------------

/// Build the AEAD AAD that binds the negotiated suite into the transcript.
///
/// The negotiated suite and the conversation parties are authenticated by the
/// AEAD but NOT encrypted. A man-in-the-middle that strips the hybrid prekey to
/// force a downgrade changes what the sender seals under, so the binding cannot
/// be silently altered: tampering either fails the recipient's AEAD open
/// ([`PqDmError::DowngradeDetected`]) or is visible in the recorded suite.
///
/// The head is **canonical, sorted-key, compact JSON** — byte-for-byte equal to
/// Python's `json.dumps({...}, sort_keys=True, separators=(",", ":"))`:
///
/// ```text
/// {"negotiated_suite":<suite>,"recipient":<recipient>,"sender":<sender>,"v":1}
/// ```
///
/// (Sorted keys are guaranteed here by serializing a [`BTreeMap`], whose
/// iteration order is the key order, with `serde_json`'s default compact
/// `(",", ":")` separators.) The optional `extra` bytes are appended verbatim
/// after the JSON head, matching `head + (extra or b"")`.
///
/// # Arguments
/// * `negotiated_suite` — the suite both sides agreed on (hybrid or classical).
/// * `sender` / `recipient` — party identifiers bound into the AAD.
/// * `extra` — optional extra context bytes appended after the JSON head.
///
/// # Returns
/// The canonical AAD bytes (deterministic; both sides derive identical bytes).
pub fn downgrade_lock_aad(
    negotiated_suite: &str,
    sender: &str,
    recipient: &str,
    extra: Option<&[u8]>,
) -> Vec<u8> {
    // BTreeMap → sorted keys; serde_json default → compact `(",",":")` separators.
    let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    map.insert("v", serde_json::Value::from(1));
    map.insert(
        "negotiated_suite",
        serde_json::Value::from(negotiated_suite),
    );
    map.insert("sender", serde_json::Value::from(sender));
    map.insert("recipient", serde_json::Value::from(recipient));

    let mut head =
        serde_json::to_vec(&map).expect("BTreeMap<&str, Value> always serializes to JSON");
    if let Some(extra) = extra {
        head.extend_from_slice(extra);
    }
    head
}

// --- Wrap-key derivation -----------------------------------------------------

/// Derive the AES-256 wrap key from the hybrid shared secret + AAD.
///
/// The AAD is folded into the HKDF `info` so the wrap key itself is bound to the
/// negotiated suite/transcript (defence in depth alongside the AEAD AAD):
/// `HKDF-SHA256(IKM = shared, salt = b"", info = INFO_WRAP ‖ b"|" ‖ aad, L = 32)`.
/// Mirrors `skcomms.pqdm._wrap_key`.
fn wrap_key(shared: &[u8], aad: &[u8]) -> [u8; 32] {
    let mut info = Vec::with_capacity(INFO_WRAP.len() + 1 + aad.len());
    info.extend_from_slice(INFO_WRAP);
    info.push(b'|');
    info.extend_from_slice(aad);

    // salt = b"" — RFC 5869 zero-pads, so empty salt == HashLen-zero salt, which
    // matches pyca `HKDF(salt=b"")`.
    let hk = Hkdf::<Sha256>::new(Some(b""), shared);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

// --- Seal / open -------------------------------------------------------------

/// Hybrid-seal a plaintext body to a recipient's 1216-byte hybrid public key.
///
/// Encapsulates to `recipient_hybrid_pub` (`X25519 ‖ ML-KEM-768`), derives an
/// AES-256 wrap key, and AES-256-GCM-seals the body under the downgrade-lock AAD
/// (binding `negotiated_suite = `[`HYBRID_SUITE`]). The ~1.1 KB KEM ciphertext
/// rides in the sealed blob so the recipient can decapsulate. Mirrors
/// `skcomms.pqdm.seal` (which takes a `PrekeyBundle`; here the caller passes the
/// raw hybrid public key after its own `is_hybrid` gate).
///
/// # Arguments
/// * `plaintext` — the body to seal (DM / payload bytes).
/// * `recipient_hybrid_pub` — the recipient's [`crate::kem::PUBLIC_KEY_LEN`]-byte
///   hybrid public key.
/// * `sender` / `recipient` — party identifiers bound into the AAD (the recipient
///   MUST pass the same values to [`open_sealed`]).
///
/// # Returns
/// `ct(1120) ‖ nonce(12) ‖ aesgcm(body + 16-byte tag)`.
///
/// # Errors
/// * [`PqDmError::Format`] — `recipient_hybrid_pub` is the wrong length.
/// * [`PqDmError::Kem`] — propagated from [`crate::kem::hybrid_encap`].
///
/// Each call is non-deterministic (fresh X25519 ephemeral + fresh nonce), so the
/// same `(plaintext, pub)` yields a different blob every time.
pub fn seal(
    plaintext: &[u8],
    recipient_hybrid_pub: &[u8],
    sender: &str,
    recipient: &str,
) -> Result<Vec<u8>, PqDmError> {
    if recipient_hybrid_pub.len() != kem::PUBLIC_KEY_LEN {
        return Err(PqDmError::Format(format!(
            "hybrid public key must be {} bytes, got {}",
            kem::PUBLIC_KEY_LEN,
            recipient_hybrid_pub.len()
        )));
    }

    let aad = downgrade_lock_aad(HYBRID_SUITE, sender, recipient, None);

    let (ciphertext, shared) = kem::hybrid_encap(recipient_hybrid_pub)?;
    let key = wrap_key(&shared, &aad);

    let mut nonce_bytes = [0u8; WRAP_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let body = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| PqDmError::Format("AES-256-GCM encryption failed".into()))?;

    let mut sealed = Vec::with_capacity(ciphertext.len() + WRAP_NONCE_LEN + body.len());
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&body);
    Ok(sealed)
}

/// Open a hybrid-sealed blob with the recipient's 2432-byte hybrid private key.
///
/// Reconstructs the downgrade-lock AAD from the suite the recipient believes was
/// negotiated (`expected_suite`); if a downgrade was attempted (or the parties
/// were tampered, or the ciphertext/tag flipped) the AAD won't authenticate and
/// the AEAD open fails → [`PqDmError::DowngradeDetected`]. Mirrors
/// `skcomms.pqdm.open_sealed`.
///
/// # Arguments
/// * `sealed` — `ct ‖ nonce ‖ aesgcm(body)` from [`seal`].
/// * `hybrid_private` — the recipient's [`crate::kem::PRIVATE_KEY_LEN`]-byte
///   hybrid private key.
/// * `sender` / `recipient` — party identifiers (MUST match the [`seal`] call).
/// * `expected_suite` — the suite the recipient believes was negotiated (pass
///   [`HYBRID_SUITE`] for the normal hybrid path). Bound into the AAD — a
///   mismatch (silent downgrade) fails the open.
///
/// # Returns
/// The decrypted plaintext body.
///
/// # Errors
/// * [`PqDmError::Format`] — blob shorter than [`SEALED_MIN_LEN`].
/// * [`PqDmError::DowngradeDetected`] — AEAD open failed (tamper / suite or party
///   mismatch / wrong key).
/// * [`PqDmError::Kem`] — propagated from [`crate::kem::hybrid_decap`] (wrong
///   private-key length).
///
/// Note: ML-KEM uses implicit rejection, so a tampered KEM ciphertext does not
/// error at decap — it yields a pseudo-random secret, which then fails the AEAD
/// open here (still surfaced as [`PqDmError::DowngradeDetected`]).
pub fn open_sealed(
    sealed: &[u8],
    hybrid_private: &[u8],
    sender: &str,
    recipient: &str,
    expected_suite: &str,
) -> Result<Vec<u8>, PqDmError> {
    if sealed.len() < SEALED_MIN_LEN {
        return Err(PqDmError::Format(format!(
            "sealed blob must be >= {} bytes, got {}",
            SEALED_MIN_LEN,
            sealed.len()
        )));
    }

    let ciphertext = &sealed[..kem::CIPHERTEXT_LEN];
    let nonce_bytes = &sealed[kem::CIPHERTEXT_LEN..kem::CIPHERTEXT_LEN + WRAP_NONCE_LEN];
    let body = &sealed[kem::CIPHERTEXT_LEN + WRAP_NONCE_LEN..];

    let aad = downgrade_lock_aad(expected_suite, sender, recipient, None);
    let shared = kem::hybrid_decap(ciphertext, hybrid_private)?;
    let key = wrap_key(&shared, &aad);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .map_err(|_| {
            PqDmError::DowngradeDetected(format!(
                "hybrid-sealed open failed — wrong key, tampered ciphertext, or a \
                 suite-downgrade attempt (AAD bound suite={expected_suite:?})"
            ))
        })
}

// --- Negotiation helper ------------------------------------------------------

/// Return the suite both sides agree on (the recorded `negotiated_suite`).
///
/// Hybrid ([`HYBRID_SUITE`]) only when BOTH the local side supports it AND the
/// recipient advertises a hybrid prekey (`recipient_has_hybrid`); otherwise the
/// [`CLASSICAL_SUITE`] (negotiated downgrade). This is the single gate callers
/// use so the recorded suite is honest. Mirrors `skcomms.pqdm.negotiate_suite`.
pub fn negotiate_suite(local_supports_hybrid: bool, recipient_has_hybrid: bool) -> &'static str {
    if local_supports_hybrid && recipient_has_hybrid {
        HYBRID_SUITE
    } else {
        CLASSICAL_SUITE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical sorted-key AAD must be byte-for-byte equal to Python's
    /// `json.dumps(sort_keys=True, separators=(",",":"))` output (hardcoded
    /// vector computed from the Python).
    #[test]
    fn aad_matches_python_canonical_json() {
        let aad = downgrade_lock_aad(HYBRID_SUITE, "a", "b", None);
        let expected = r#"{"negotiated_suite":"x25519-mlkem768","recipient":"b","sender":"a","v":1}"#;
        assert_eq!(aad, expected.as_bytes());
        // And the exact hex, as emitted by the reference Python.
        assert_eq!(
            hex::encode(&aad),
            "7b226e65676f7469617465645f7375697465223a227832353531392d6d6c6b656d3736\
             38222c22726563697069656e74223a2262222c2273656e646572223a2261222c22762\
             23a317d"
                .replace([' ', '\n'], "")
        );
    }

    /// `downgrade_lock_aad` appends `extra` verbatim after the JSON head.
    #[test]
    fn aad_appends_extra_verbatim() {
        let aad = downgrade_lock_aad(HYBRID_SUITE, "a", "b", Some(b"\x00\xff"));
        assert!(aad.ends_with(b"\x00\xff"));
        assert_eq!(aad.len(), downgrade_lock_aad(HYBRID_SUITE, "a", "b", None).len() + 2);
    }

    /// The wrap-key HKDF must match the Python `_wrap_key` for a fixed shared
    /// secret + AAD (deterministic Python-parity vector).
    #[test]
    fn wrap_key_matches_python_vector() {
        let aad = downgrade_lock_aad(HYBRID_SUITE, "a", "b", None);
        let shared = [0x42u8; 32];
        let wk = wrap_key(&shared, &aad);
        assert_eq!(
            hex::encode(wk),
            "20e7c515adbdfac00668326bf121b46916f11cde9918c49b452d5d282a2178cd"
        );
    }

    /// Seal → open round-trips and recovers the exact plaintext.
    #[test]
    fn seal_open_roundtrip() {
        let kp = kem::hybrid_keypair();
        let msg = b"top secret HNDL payload";
        let sealed = seal(msg, &kp.public_key, "a", "b").unwrap();
        // Wire layout: ct || nonce || (body+tag).
        assert!(sealed.len() >= SEALED_MIN_LEN);
        assert_eq!(&sealed[..kem::CIPHERTEXT_LEN].len(), &kem::CIPHERTEXT_LEN);
        let out = open_sealed(&sealed, &kp.private_key, "a", "b", HYBRID_SUITE).unwrap();
        assert_eq!(out, msg);
    }

    /// Empty-body seal still produces a minimum-length valid blob that opens.
    #[test]
    fn seal_open_empty_body() {
        let kp = kem::hybrid_keypair();
        let sealed = seal(b"", &kp.public_key, "x", "y").unwrap();
        assert_eq!(sealed.len(), SEALED_MIN_LEN);
        let out = open_sealed(&sealed, &kp.private_key, "x", "y", HYBRID_SUITE).unwrap();
        assert!(out.is_empty());
    }

    /// Each seal is non-deterministic (fresh ephemeral + nonce), but both open.
    #[test]
    fn seal_is_nondeterministic_but_both_open() {
        let kp = kem::hybrid_keypair();
        let s1 = seal(b"x", &kp.public_key, "a", "b").unwrap();
        let s2 = seal(b"x", &kp.public_key, "a", "b").unwrap();
        assert_ne!(s1, s2);
        assert_eq!(open_sealed(&s1, &kp.private_key, "a", "b", HYBRID_SUITE).unwrap(), b"x");
        assert_eq!(open_sealed(&s2, &kp.private_key, "a", "b", HYBRID_SUITE).unwrap(), b"x");
    }

    /// A recipient tricked into a classical `expected_suite` fails the open: the
    /// AAD no longer authenticates the body (downgrade-lock).
    #[test]
    fn downgrade_lock_detects_suite_mismatch() {
        let kp = kem::hybrid_keypair();
        let sealed = seal(b"secret", &kp.public_key, "a", "b").unwrap();
        let err = open_sealed(&sealed, &kp.private_key, "a", "b", CLASSICAL_SUITE).unwrap_err();
        assert!(matches!(err, PqDmError::DowngradeDetected(_)));
    }

    /// Tampering a party identifier changes the AAD → open fails.
    #[test]
    fn downgrade_lock_detects_party_tamper() {
        let kp = kem::hybrid_keypair();
        let sealed = seal(b"secret", &kp.public_key, "a", "b").unwrap();
        let err = open_sealed(&sealed, &kp.private_key, "MALLORY", "b", HYBRID_SUITE).unwrap_err();
        assert!(matches!(err, PqDmError::DowngradeDetected(_)));
    }

    /// Flipping a tag bit fails the AEAD open.
    #[test]
    fn tampered_ciphertext_detected() {
        let kp = kem::hybrid_keypair();
        let mut sealed = seal(b"secret", &kp.public_key, "a", "b").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let err = open_sealed(&sealed, &kp.private_key, "a", "b", HYBRID_SUITE).unwrap_err();
        assert!(matches!(err, PqDmError::DowngradeDetected(_)));
    }

    /// A wrong-length public key is a format error, not a panic.
    #[test]
    fn seal_rejects_bad_pubkey_len() {
        let err = seal(b"x", &[0u8; 10], "a", "b").unwrap_err();
        assert!(matches!(err, PqDmError::Format(_)));
    }

    /// A too-short blob is a format error, not a panic.
    #[test]
    fn open_too_short_raises() {
        let kp = kem::hybrid_keypair();
        let err = open_sealed(b"too-short", &kp.private_key, "a", "b", HYBRID_SUITE).unwrap_err();
        assert!(matches!(err, PqDmError::Format(_)));
    }

    /// `negotiate_suite` is hybrid only when both sides advertise it.
    #[test]
    fn negotiate_suite_gating() {
        assert_eq!(negotiate_suite(true, true), HYBRID_SUITE);
        assert_eq!(negotiate_suite(true, false), CLASSICAL_SUITE);
        assert_eq!(negotiate_suite(false, true), CLASSICAL_SUITE);
        assert_eq!(negotiate_suite(false, false), CLASSICAL_SUITE);
    }
}
