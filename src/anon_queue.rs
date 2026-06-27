//! Anonymous, no-identity queue addressing — RFC-0001 P5 **foundation only**.
//!
//! Clean-room of `skcomms/src/skcomms/anon_queue.py`, byte-for-byte
//! interoperable with it. This is the *addressing + deniable-authentication*
//! primitive that a future SimpleX-style unidirectional message queue composes
//! on top of. It is the building block, **NOT a transport**: there is no relay,
//! no network, no store, no delivery here — only opaque id generation, an
//! `aqid:` address codec, and a repudiable shared-secret authenticator.
//!
//! # Clean-room notice
//!
//! SimpleX Chat / SMP is **AGPL-3.0**. Nothing here is derived from, copied
//! from, or a translation of their source. Only the *protocol idea* is borrowed
//! — that a queue can be addressed without any long-term identity by giving the
//! sender and the recipient two **independent, uncorrelated** opaque ids, so
//! that the relay holding the queue cannot link "who subscribes" to "who sends".
//! The wire format, the codec, and the MAC construction below are original.
//!
//! # What this module provides
//!
//! - [`new_queue_pair`] — one unidirectional queue's `(recipient_id,
//!   sender_id)`: two INDEPENDENT 16-byte random ids. The recipient SUBs on
//!   `recipient_id`; senders SEND to `sender_id`. They are deliberately
//!   uncorrelated — knowing one tells a relay nothing about the other.
//! - [`encode_aqid`] / [`decode_aqid`] — the `aqid:` address codec,
//!   `aqid:<relay>/<base64url-unpadded(sender_id)>`. Only the *sender* id is
//!   ever published (that is the part you hand out); the recipient id is the
//!   private subscription secret and never appears in an address.
//! - [`auth_tag`] / [`verify_tag`] — a **deniable** authenticator:
//!   `HMAC-SHA256(secret, nonce ‖ message)` over a shared secret. Because it is
//!   a symmetric MAC, a valid tag proves the message came from *someone who
//!   holds the shared secret* — but EITHER party could have produced it, so it
//!   is repudiable: it is authentic to the participants yet provides no
//!   transferable proof to a third party (the opposite of a digital signature).
//!
//! # Honesty (sk-standards)
//!
//! - This is **addressing + deniable auth ONLY**. No transport/relay exists
//!   yet, and nothing here encrypts message bodies — compose with the hybrid
//!   KEM ([`crate::kem`], X25519 ‖ ML-KEM-768, **FIPS 203**) and AES-256-GCM for
//!   confidentiality when the transport is built.
//! - The deniable MAC gives **authenticity + deniability**, never
//!   non-repudiation, and is not "unbreakable" — its security rests on
//!   HMAC-SHA256 and the secrecy of the shared secret.
//! - **Anonymity-set honesty:** unlinkable ids reduce metadata leakage *at the
//!   relay*, but on a small sovereign network the anonymity set is small. With
//!   few participants, timing/volume correlation and the sheer paucity of
//!   candidates can still deanonymize. This primitive raises the bar for a
//!   passive relay; it is not a magic anonymity cloak on a 3-node net.
//!
//! Primitives are reused, never hand-rolled: the OS CSPRNG (`rand::rngs::OsRng`)
//! for ids, RustCrypto `hmac`+`sha2` for the MAC, `subtle` for the constant-time
//! tag compare, and `base64` (URL-safe, unpadded) for the codec.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Interop constants (DO NOT CHANGE — pinned by skcomms/anon_queue.py)
// ---------------------------------------------------------------------------

/// Stable label for this addressing + deniable-auth construction.
///
/// Mirrors Python `ANON_SUITE` (`crypto_suites.py` style: lowercase, versioned).
pub const ANON_SUITE: &str = "aqid-v1";

/// Length (bytes) of each opaque queue id.
///
/// 16 B = 128 bits of CSPRNG entropy — collision-negligible and unlinkable,
/// matching the hybrid-prekey id sizing.
pub const QUEUE_ID_LEN: usize = 16;

/// `aqid:` scheme prefix for the address codec.
pub const AQID_SCHEME: &str = "aqid:";

/// Length (bytes) of an [`auth_tag`] / [`verify_tag`] tag (HMAC-SHA256 output).
pub const AUTH_TAG_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Malformed id, address, or argument (never a crash).
///
/// Mirrors Python `AnonQueueFormatError` — every fallible codec/encode path
/// returns this rather than panicking. (Python additionally has an
/// `AnonQueueError` base class; in Rust the single enum suffices.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnonQueueError {
    /// A relay locator was empty or contained the `/` id delimiter.
    BadRelay(&'static str),
    /// A queue id was not exactly [`QUEUE_ID_LEN`] bytes: `(what, got)`.
    BadIdLen(&'static str, usize),
    /// An `aqid:` address was structurally malformed (scheme / shape).
    BadAddress(&'static str),
    /// The id segment was not valid unpadded base64url.
    BadBase64,
}

impl fmt::Display for AnonQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnonQueueError::BadRelay(msg) => write!(f, "relay {msg}"),
            AnonQueueError::BadIdLen(what, got) => {
                write!(f, "{what} must be {QUEUE_ID_LEN} bytes, got {got}")
            }
            AnonQueueError::BadAddress(msg) => write!(f, "address {msg}"),
            AnonQueueError::BadBase64 => write!(f, "id is not valid base64url"),
        }
    }
}

impl Error for AnonQueueError {}

// ---------------------------------------------------------------------------
// Queue id generation
// ---------------------------------------------------------------------------

/// Generate one unidirectional queue's `(recipient_id, sender_id)`.
///
/// The two ids are **independent** 16-byte CSPRNG values, deliberately
/// uncorrelated: a relay that sees a SEND to `sender_id` cannot link it to the
/// SUB on `recipient_id` (and vice-versa). The recipient keeps `recipient_id`
/// private (its subscription secret) and publishes only `sender_id` (via
/// [`encode_aqid`]).
///
/// Returns `(recipient_id, sender_id)` — two distinct 16-byte values. Equality
/// is a `2^-128` event but, as in the Python, the invariant is enforced exactly
/// by re-drawing the sender id on the astronomically unlikely collision.
pub fn new_queue_pair() -> ([u8; QUEUE_ID_LEN], [u8; QUEUE_ID_LEN]) {
    let mut rng = OsRng;
    let mut recipient_id = [0u8; QUEUE_ID_LEN];
    let mut sender_id = [0u8; QUEUE_ID_LEN];
    rng.fill_bytes(&mut recipient_id);
    rng.fill_bytes(&mut sender_id);
    // Astronomically unlikely with 128-bit ids, but keep the invariant exact:
    // the pair MUST be distinct (their independence is the whole point).
    while sender_id == recipient_id {
        rng.fill_bytes(&mut sender_id);
    }
    (recipient_id, sender_id)
}

// ---------------------------------------------------------------------------
// aqid: address codec
// ---------------------------------------------------------------------------

/// Encode a publishable queue address `aqid:<relay>/<base64url(sender_id)>`.
///
/// Only the *sender* id is encoded — that is the half meant to be handed out.
/// The base64url is unpadded so the address stays clean in URLs / QR codes.
///
/// # Arguments
/// - `relay`: Non-empty relay locator (host / host:port / onion / etc.). Must
///   not contain `/` (that delimits the id) and must be non-empty.
/// - `sender_id`: The 16-byte sender id from [`new_queue_pair`].
///
/// # Errors
/// Returns [`AnonQueueError::BadRelay`] on an empty relay or one containing `/`,
/// and [`AnonQueueError::BadIdLen`] when `sender_id` is not [`QUEUE_ID_LEN`]
/// bytes — matching the Python, which raises `AnonQueueFormatError` in the same
/// cases. (The Rust signature returns a `Result` where the Python raises.)
pub fn encode_aqid(relay: &str, sender_id: &[u8]) -> Result<String, AnonQueueError> {
    if relay.is_empty() {
        return Err(AnonQueueError::BadRelay("must be a non-empty string"));
    }
    if relay.contains('/') {
        return Err(AnonQueueError::BadRelay("must not contain '/'"));
    }
    if sender_id.len() != QUEUE_ID_LEN {
        return Err(AnonQueueError::BadIdLen("sender_id", sender_id.len()));
    }
    let b64 = URL_SAFE_NO_PAD.encode(sender_id);
    Ok(format!("{AQID_SCHEME}{relay}/{b64}"))
}

/// Decode an `aqid:` address back to `(relay, sender_id)` exactly.
///
/// Round-trips [`encode_aqid`]. Rejects anything malformed rather than panicking.
///
/// # Errors
/// - [`AnonQueueError::BadAddress`] — missing/wrong scheme, no `/` separator, or
///   an empty relay/id segment.
/// - [`AnonQueueError::BadBase64`] — the id segment is not valid base64url.
/// - [`AnonQueueError::BadIdLen`] — the id decoded to something other than
///   [`QUEUE_ID_LEN`] bytes.
pub fn decode_aqid(s: &str) -> Result<(String, [u8; QUEUE_ID_LEN]), AnonQueueError> {
    let body = s
        .strip_prefix(AQID_SCHEME)
        .ok_or(AnonQueueError::BadAddress("must start with 'aqid:'"))?;
    // Partition on the FIRST '/': relay = before, b64 = after (matches Python
    // str.partition, where a relay containing no '/' is guaranteed by encode).
    let (relay, b64) = body
        .split_once('/')
        .ok_or(AnonQueueError::BadAddress("must be 'aqid:<relay>/<id>'"))?;
    if relay.is_empty() {
        return Err(AnonQueueError::BadAddress("relay must be non-empty"));
    }
    if b64.is_empty() {
        return Err(AnonQueueError::BadAddress("id must be non-empty"));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| AnonQueueError::BadBase64)?;
    if raw.len() != QUEUE_ID_LEN {
        return Err(AnonQueueError::BadIdLen("decoded id", raw.len()));
    }
    let mut sender_id = [0u8; QUEUE_ID_LEN];
    sender_id.copy_from_slice(&raw);
    Ok((relay.to_string(), sender_id))
}

// ---------------------------------------------------------------------------
// Deniable (repudiable) authenticator — HMAC-SHA256(secret, nonce ‖ message)
// ---------------------------------------------------------------------------

/// HMAC-SHA256 instance type for the deniable authenticator.
type HmacSha256 = Hmac<Sha256>;

/// Compute a **deniable** authenticator over `message`.
///
/// `tag = HMAC-SHA256(secret, nonce ‖ message)`. Being a shared-secret MAC, a
/// valid tag is authentic to the holders of `secret` but **repudiable** — either
/// party could have produced it, so it is NOT a signature and grants no
/// transferable proof to a third party. The `nonce` is bound into the MAC
/// (prepended to the message), so a fresh nonce yields a fresh tag.
///
/// # Arguments
/// - `secret`: Shared symmetric secret (e.g. a derived per-queue key). Any
///   length is accepted (HMAC keys are hashed/zero-padded to the block size).
/// - `message`: The bytes being authenticated.
/// - `nonce`: Per-message nonce, bound into the tag.
///
/// Returns the 32-byte HMAC-SHA256 tag ([`AUTH_TAG_LEN`]).
pub fn auth_tag(secret: &[u8], message: &[u8], nonce: &[u8]) -> Vec<u8> {
    // `new_from_slice` accepts any key length (HMAC takes variable-length keys),
    // so this never fails for HMAC — mirrors Python `hmac.HMAC(secret, SHA256())`.
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(nonce);
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time verify an [`auth_tag`] tag. Returns `true`/`false`, never panics.
///
/// Recomputes the expected MAC and compares it against `tag` in **constant time**
/// (`subtle::ConstantTimeEq`), so a mismatch leaks no timing about *where* it
/// differed. A wrong secret, tampered message, wrong nonce, wrong-length tag, or
/// tampered tag all return `false` rather than raising — matching the Python,
/// whose `hmac.HMAC.verify` is likewise constant-time and which catches every
/// failure into a `False`.
pub fn verify_tag(secret: &[u8], message: &[u8], nonce: &[u8], tag: &[u8]) -> bool {
    let expected = auth_tag(secret, message, nonce);
    // `subtle`'s slice `ct_eq` short-circuits only on differing length (which is
    // not a secret), and is otherwise constant-time over the byte content.
    expected.ct_eq(tag).into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_queue_pair_is_distinct_and_sized() {
        let (recipient_id, sender_id) = new_queue_pair();
        assert_eq!(recipient_id.len(), QUEUE_ID_LEN);
        assert_eq!(sender_id.len(), QUEUE_ID_LEN);
        // Independence invariant: the two ids must differ.
        assert_ne!(recipient_id, sender_id);
        // Two successive draws should (overwhelmingly) differ — sanity that we
        // are not returning a constant.
        let (r2, s2) = new_queue_pair();
        assert_ne!(sender_id, s2);
        assert_ne!(recipient_id, r2);
    }

    #[test]
    fn aqid_round_trip() {
        let (_recipient, sender_id) = new_queue_pair();
        let addr = encode_aqid("relay.example:5223", &sender_id).unwrap();
        assert!(addr.starts_with("aqid:relay.example:5223/"));
        let (relay, decoded) = decode_aqid(&addr).unwrap();
        assert_eq!(relay, "relay.example:5223");
        assert_eq!(decoded, sender_id);
    }

    #[test]
    fn encode_aqid_python_parity_vector() {
        // sender_id = bytes 0x00..=0x0f. Python:
        //   base64.urlsafe_b64encode(bytes(range(16))).rstrip(b"=")
        //   -> b"AAECAwQFBgcICQoLDA0ODw"
        let sender_id: Vec<u8> = (0u8..16).collect();
        let addr = encode_aqid("relay1", &sender_id).unwrap();
        assert_eq!(addr, "aqid:relay1/AAECAwQFBgcICQoLDA0ODw");
        // And it decodes back to the exact bytes.
        let (relay, decoded) = decode_aqid(&addr).unwrap();
        assert_eq!(relay, "relay1");
        assert_eq!(decoded.to_vec(), sender_id);
    }

    #[test]
    fn encode_aqid_rejects_bad_relay_and_len() {
        let sid = [0u8; QUEUE_ID_LEN];
        assert_eq!(
            encode_aqid("", &sid),
            Err(AnonQueueError::BadRelay("must be a non-empty string"))
        );
        assert_eq!(
            encode_aqid("a/b", &sid),
            Err(AnonQueueError::BadRelay("must not contain '/'"))
        );
        assert_eq!(
            encode_aqid("relay", &[0u8; 8]),
            Err(AnonQueueError::BadIdLen("sender_id", 8))
        );
    }

    #[test]
    fn decode_aqid_rejects_malformed() {
        // Wrong scheme.
        assert!(matches!(
            decode_aqid("http:relay/AAECAwQFBgcICQoLDA0ODw"),
            Err(AnonQueueError::BadAddress(_))
        ));
        // No separator.
        assert!(matches!(
            decode_aqid("aqid:relayonly"),
            Err(AnonQueueError::BadAddress(_))
        ));
        // Empty relay.
        assert!(matches!(
            decode_aqid("aqid:/AAECAwQFBgcICQoLDA0ODw"),
            Err(AnonQueueError::BadAddress(_))
        ));
        // Empty id.
        assert!(matches!(
            decode_aqid("aqid:relay/"),
            Err(AnonQueueError::BadAddress(_))
        ));
        // Not base64url ('*' is not in the alphabet).
        assert!(matches!(
            decode_aqid("aqid:relay/****"),
            Err(AnonQueueError::BadBase64)
        ));
        // Valid base64url but wrong decoded length (2 bytes, not 16).
        let short = URL_SAFE_NO_PAD.encode([0u8, 1u8]);
        assert!(matches!(
            decode_aqid(&format!("aqid:relay/{short}")),
            Err(AnonQueueError::BadIdLen("decoded id", 2))
        ));
    }

    #[test]
    fn auth_tag_python_parity_vector() {
        // Python:
        //   secret=b"shared-secret"; message=b"hello"; nonce=b"nonce123"
        //   hmac.new(secret, nonce+message, hashlib.sha256).hexdigest()
        //   -> f9639bfd00c4e17d76b026b64d97c71124fcec8ec947c0e4ebe2a508e101aa18
        let secret = b"shared-secret";
        let message = b"hello";
        let nonce = b"nonce123";
        let tag = auth_tag(secret, message, nonce);
        assert_eq!(tag.len(), AUTH_TAG_LEN);
        let expected =
            hex::decode("f9639bfd00c4e17d76b026b64d97c71124fcec8ec947c0e4ebe2a508e101aa18")
                .unwrap();
        assert_eq!(tag, expected);
    }

    #[test]
    fn auth_tag_is_deterministic_and_nonce_bound() {
        let secret = b"k";
        let msg = b"payload";
        let n1 = b"nonceAAAA";
        let n2 = b"nonceBBBB";
        // Deterministic for the same inputs.
        assert_eq!(auth_tag(secret, msg, n1), auth_tag(secret, msg, n1));
        // A different nonce yields a different tag (nonce is bound in).
        assert_ne!(auth_tag(secret, msg, n1), auth_tag(secret, msg, n2));
    }

    #[test]
    fn verify_tag_accepts_valid_and_rejects_tamper() {
        let secret = b"shared";
        let message = b"the message body";
        let nonce = b"unique-nonce";
        let tag = auth_tag(secret, message, nonce);

        // Genuine tag verifies.
        assert!(verify_tag(secret, message, nonce, &tag));

        // Tampered message -> reject.
        assert!(!verify_tag(secret, b"the messXge body", nonce, &tag));
        // Wrong nonce -> reject.
        assert!(!verify_tag(secret, message, b"other-nonce-", &tag));
        // Wrong secret -> reject.
        assert!(!verify_tag(b"wrong", message, nonce, &tag));
        // Tampered tag (flip last byte) -> reject.
        let mut bad = tag.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(!verify_tag(secret, message, nonce, &bad));
        // Wrong-length tag -> reject (constant-time compare short-circuits on len).
        assert!(!verify_tag(secret, message, nonce, &tag[..AUTH_TAG_LEN - 1]));
        assert!(!verify_tag(secret, message, nonce, &[]));
    }
}
