//! SKChat 1:1 DM ratchet session driver — clean-room of
//! `skchat/src/skchat/dm_session.py` (RFC-0001 P1, Level-3 periodic PQ rekey).
//!
//! [`DmSession`] is the stateful layer on top of the pure [`crate::ratchet`]
//! primitives ([`crate::ratchet::DmRatchet`]). It owns the **epoch lifecycle** for
//! one peer:
//!
//! * **Auto-(re)key.** The first [`DmSession::seal`] establishes epoch 0; once an
//!   epoch hits its bound (`rekey_msg_bound` messages **OR** `rekey_age_seconds`),
//!   the next [`DmSession::seal`] starts a fresh epoch with an independent secret —
//!   forward secrecy across the boundary, post-compromise security (the per-epoch
//!   hybrid-KEM rekey heals the channel if a single epoch secret leaks).
//! * **Key-agreement message (KAM) piggyback.** The wrapped epoch secret
//!   ([`crate::ratchet::wrap_dm_epoch_secret`]) rides the first [`KAM_REPEAT`]
//!   frames of each epoch ([`SealedDmFrame::kam`]), so the sender never waits a
//!   round-trip to start sending and a lost/reordered first frame doesn't strand
//!   the epoch.
//! * **Per-epoch secret store.** Both sides keep `{epoch -> secret}`, so frames are
//!   loss/reorder tolerant *across* epochs too: a frame for any epoch whose KAM has
//!   been seen opens by `(epoch, index)`.
//!
//! The per-frame body is AES-256-GCM with the `(epoch, index)` pair bound into the
//! AAD, so a frame can't be replayed into another slot. The KEM is the hybrid
//! **X25519 + ML-KEM-768** ([`crate::kem`], **FIPS 203**) — confidentiality holds
//! if **either** leg holds; this is a hybrid construction, not a "quantum-proof"
//! one. AES-256-GCM (symmetric) carries the bulk. Pure state machine — no I/O.
//!
//! Wire compatibility with the Python is exact: identical HKDF labels, identical
//! AAD bytes, and an identical length-prefixed [`PQDR_SCHEME`] token layout, so a
//! frame sealed by one implementation opens in the other.

use crate::ratchet::{
    derive_dm_message_key, new_epoch_secret, unwrap_dm_epoch_secret, wrap_dm_epoch_secret,
    DmRatchet, RatchetError, DEFAULT_REKEY_AGE_SECONDS, DEFAULT_REKEY_MSG_BOUND, EPOCH_SECRET_LEN,
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// AES-256-GCM nonce length for a frame body (random per frame).
pub const FRAME_NONCE_LEN: usize = 12;

/// AEAD AAD prefix — the `(epoch, index)` pair is appended after a `|`.
/// Equals Python's `_AAD_PREFIX`.
const AAD_PREFIX: &[u8] = b"skchat/dm-frame/v1";

/// The KAM (wrapped epoch secret) rides the first `KAM_REPEAT` frames of each
/// epoch — not just the first — so a lost/reordered first frame over a reliable
/// transport doesn't strand the epoch. Still per-epoch-amortised (3 of ~50 frames).
/// Equals Python's `_KAM_REPEAT`.
pub const KAM_REPEAT: u64 = 3;

/// Wire marker for a sealed DM *ratchet* frame stored in `ChatMessage.content`.
///
/// Mirrors the hybrid one-shot `pqdm1:` token shape: classical PGP starts with
/// `-----BEGIN PGP`, the hybrid one-shot with `pqdm1:`, and a ratchet frame with
/// this prefix — all three coexist in the same field. Equals Python's
/// `PQDR_SCHEME`.
pub const PQDR_SCHEME: &str = "pqdr1:";

/// Bind `(epoch, index)` into the AEAD AAD so a frame can't move slots.
///
/// `AAD_PREFIX ‖ b"|" ‖ u64_be(epoch) ‖ u64_be(index)`. Equals Python's
/// `_frame_aad`.
fn frame_aad(epoch: u64, index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 1 + 16);
    aad.extend_from_slice(AAD_PREFIX);
    aad.push(b'|');
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// Errors from the DM session driver and its `pqdr1:` codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmSessionError {
    /// A `pqdr1:` token was malformed (wrong scheme, bad base64, truncated, or
    /// trailing bytes). Carries a human-readable reason; never crashes on input.
    BadToken(String),
    /// AES-256-GCM frame open failed: tamper, wrong key, or a missing/invalid
    /// epoch secret. Never distinguishes the cause (no oracle).
    OpenFailed,
    /// No epoch secret is known for this frame's epoch (its key-agreement message
    /// was never seen).
    MissingEpochSecret(u64),
    /// Propagated from the ratchet/KEM layer (e.g. a malformed KAM, wrong key
    /// length, or KEM rejection during wrap/unwrap).
    Ratchet(RatchetError),
}

impl fmt::Display for DmSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmSessionError::BadToken(why) => write!(f, "invalid {PQDR_SCHEME} token: {why}"),
            DmSessionError::OpenFailed => write!(f, "dm frame open failed (tamper or wrong key)"),
            DmSessionError::MissingEpochSecret(e) => write!(
                f,
                "no epoch secret for epoch {e} (missing key-agreement message)"
            ),
            DmSessionError::Ratchet(e) => write!(f, "ratchet error: {e}"),
        }
    }
}

impl Error for DmSessionError {}

impl From<RatchetError> for DmSessionError {
    fn from(e: RatchetError) -> Self {
        DmSessionError::Ratchet(e)
    }
}

/// One sealed DM on the wire.
///
/// Mirrors `skchat.dm_session.SealedDmFrame`. The body is AES-256-GCM ciphertext
/// (plaintext + 16-byte tag) keyed by `(epoch_secret, epoch, index)` with the
/// `(epoch, index)` pair bound into the AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDmFrame {
    /// Epoch number whose secret keys this frame.
    pub epoch: u64,
    /// Zero-based message index within the epoch.
    pub index: u64,
    /// 12-byte AES-GCM nonce.
    pub nonce: Vec<u8>,
    /// AES-256-GCM ciphertext+tag of the plaintext.
    pub body: Vec<u8>,
    /// Wrapped epoch secret ([`crate::ratchet::wrap_dm_epoch_secret`]), present
    /// only on the first [`KAM_REPEAT`] frames of an epoch; `None` otherwise.
    pub kam: Option<Vec<u8>>,
}

impl SealedDmFrame {
    /// Serialize to the `pqdr1:` wire token (`PQDR_SCHEME` + base64 of the binary).
    ///
    /// Explicit length-prefixed big-endian binary, so the form is self-describing
    /// and the round-trip is exact — including the `kam = None` vs `kam = present`
    /// distinction (a one-byte presence flag separates "absent" from "empty"):
    ///
    /// ```text
    /// epoch(u64) ‖ index(u64)
    ///   ‖ nonce_len(u32) ‖ nonce
    ///   ‖ body_len(u32)  ‖ body
    ///   ‖ kam_flag(u8)   ‖ [kam_len(u32) ‖ kam]
    /// ```
    ///
    /// The base64 is the standard (padded) alphabet — identical to Python's
    /// `base64.b64encode`.
    pub fn to_token(&self) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&self.epoch.to_be_bytes());
        blob.extend_from_slice(&self.index.to_be_bytes());
        blob.extend_from_slice(&(self.nonce.len() as u32).to_be_bytes());
        blob.extend_from_slice(&self.nonce);
        blob.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        blob.extend_from_slice(&self.body);
        match &self.kam {
            None => blob.push(0u8),
            Some(kam) => {
                blob.push(1u8);
                blob.extend_from_slice(&(kam.len() as u32).to_be_bytes());
                blob.extend_from_slice(kam);
            }
        }
        let mut token = String::from(PQDR_SCHEME);
        token.push_str(&B64.encode(&blob));
        token
    }

    /// Parse a `pqdr1:` token back into a [`SealedDmFrame`].
    ///
    /// # Errors
    /// [`DmSessionError::BadToken`] if the token is not `pqdr1:`-schemed, not valid
    /// base64, or the binary is truncated / has trailing bytes / an invalid KAM
    /// flag (never a crash on bad input). Mirrors Python's `from_token`.
    pub fn from_token(token: &str) -> Result<SealedDmFrame, DmSessionError> {
        let body = token
            .strip_prefix(PQDR_SCHEME)
            .ok_or_else(|| DmSessionError::BadToken(format!("not a {PQDR_SCHEME} token")))?;
        let blob = B64
            .decode(body.as_bytes())
            .map_err(|e| DmSessionError::BadToken(format!("invalid base64: {e}")))?;

        let mut off = 0usize;
        // Closure-free cursor (so errors are explicit and no panics occur).
        macro_rules! take {
            ($n:expr) => {{
                let n = $n;
                if off + n > blob.len() {
                    return Err(DmSessionError::BadToken("truncated frame".into()));
                }
                let chunk = &blob[off..off + n];
                off += n;
                chunk
            }};
        }

        let epoch = u64::from_be_bytes(take!(8).try_into().unwrap());
        let index = u64::from_be_bytes(take!(8).try_into().unwrap());
        let nonce_len = u32::from_be_bytes(take!(4).try_into().unwrap()) as usize;
        let nonce = take!(nonce_len).to_vec();
        let body_len = u32::from_be_bytes(take!(4).try_into().unwrap()) as usize;
        let frame_body = take!(body_len).to_vec();
        let kam_flag = take!(1)[0];
        let kam = match kam_flag {
            0 => None,
            1 => {
                let kam_len = u32::from_be_bytes(take!(4).try_into().unwrap()) as usize;
                Some(take!(kam_len).to_vec())
            }
            other => {
                return Err(DmSessionError::BadToken(format!(
                    "invalid kam presence flag: {other}"
                )))
            }
        };
        if off != blob.len() {
            return Err(DmSessionError::BadToken("trailing bytes after frame".into()));
        }
        Ok(SealedDmFrame {
            epoch,
            index,
            nonce,
            body: frame_body,
            kam,
        })
    }
}

/// Stateful 1:1 ratchet session for one peer (drives a [`DmRatchet`]).
///
/// Mirrors `skchat.dm_session.DmSession`. Holds the outbound ratchet, the
/// per-epoch secret store (so any seen epoch opens), and the current epoch's KAM.
pub struct DmSession {
    /// Peer identifier this session is scoped to.
    pub peer: String,
    /// Re-key after this many messages in an epoch.
    pub rekey_msg_bound: u64,
    /// Re-key after the epoch is this old (seconds).
    pub rekey_age_seconds: u64,
    ratchet: Option<DmRatchet>,
    epoch_secrets: HashMap<u64, [u8; EPOCH_SECRET_LEN]>,
    current_kam: Option<Vec<u8>>,
}

impl DmSession {
    /// Create a session for `peer` with the default re-key bounds.
    pub fn new(peer: impl Into<String>) -> Self {
        Self::with_bounds(peer, DEFAULT_REKEY_MSG_BOUND, DEFAULT_REKEY_AGE_SECONDS)
    }

    /// Create a session with explicit re-key bounds.
    pub fn with_bounds(
        peer: impl Into<String>,
        rekey_msg_bound: u64,
        rekey_age_seconds: u64,
    ) -> Self {
        DmSession {
            peer: peer.into(),
            rekey_msg_bound,
            rekey_age_seconds,
            ratchet: None,
            epoch_secrets: HashMap::new(),
            current_kam: None,
        }
    }

    // -- sender ---------------------------------------------------------------

    /// Start a fresh epoch: new secret, set the outbound ratchet, store the KAM.
    fn begin_epoch(&mut self, epoch: u64, peer_hybrid_pub: &[u8]) -> Result<(), DmSessionError> {
        let secret = new_epoch_secret();
        // Wrap BEFORE mutating durable state, so a KEM error leaves us unchanged.
        let kam = wrap_dm_epoch_secret(&secret, peer_hybrid_pub)?;
        self.epoch_secrets.insert(epoch, secret);
        self.ratchet = Some(DmRatchet::with_bounds(
            epoch,
            secret,
            self.rekey_msg_bound,
            self.rekey_age_seconds,
        ));
        self.current_kam = Some(kam);
        Ok(())
    }

    /// Seal a plaintext to the peer, (re)keying as needed.
    ///
    /// Establishes epoch 0 on first use, or rolls to the next epoch once the
    /// current one hits its bound — the KAM rides the first [`KAM_REPEAT`] frames
    /// of each epoch (robust to a lost/reordered first frame).
    ///
    /// # Arguments
    /// * `plaintext` — the message bytes to seal.
    /// * `peer_hybrid_pub` — the peer's [`crate::kem::PUBLIC_KEY_LEN`]-byte hybrid
    ///   public key (used to wrap the epoch secret on a (re)key).
    ///
    /// # Errors
    /// [`DmSessionError::Ratchet`] if the hybrid wrap fails (bad key length / KEM).
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        peer_hybrid_pub: &[u8],
    ) -> Result<SealedDmFrame, DmSessionError> {
        let begin_at = match &self.ratchet {
            None => Some(0),
            Some(r) if r.should_rekey(None) => Some(r.epoch + 1),
            Some(_) => None,
        };
        if let Some(epoch) = begin_at {
            self.begin_epoch(epoch, peer_hybrid_pub)?;
        }

        let (idx, key, epoch) = {
            let r = self.ratchet.as_mut().expect("ratchet set by begin_epoch");
            let (idx, key) = r.next_outbound_key();
            (idx, key, r.epoch)
        };

        let kam = if idx < KAM_REPEAT {
            self.current_kam.clone()
        } else {
            None
        };

        let mut nonce = [0u8; FRAME_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let aad = frame_aad(epoch, idx);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let body = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| DmSessionError::OpenFailed)?;

        Ok(SealedDmFrame {
            epoch,
            index: idx,
            nonce: nonce.to_vec(),
            body,
            kam,
        })
    }

    // -- receiver -------------------------------------------------------------

    /// Open a sealed frame, accepting its KAM if it carries a new epoch.
    ///
    /// If the frame carries a KAM for an epoch not yet known, the wrapped epoch
    /// secret is unwrapped with `my_hybrid_priv` and stored; the frame then opens
    /// by `(epoch, index)`.
    ///
    /// # Errors
    /// * [`DmSessionError::Ratchet`] if a present KAM fails to unwrap.
    /// * [`DmSessionError::MissingEpochSecret`] if no secret is known for the
    ///   frame's epoch and it carries no KAM.
    /// * [`DmSessionError::OpenFailed`] on AEAD authentication failure (tamper /
    ///   wrong key).
    pub fn open(
        &mut self,
        frame: &SealedDmFrame,
        my_hybrid_priv: &[u8],
    ) -> Result<Vec<u8>, DmSessionError> {
        if let Some(kam) = &frame.kam {
            if !self.epoch_secrets.contains_key(&frame.epoch) {
                let secret = unwrap_dm_epoch_secret(kam, my_hybrid_priv)?;
                self.epoch_secrets.insert(frame.epoch, secret);
            }
        }
        let secret = self
            .epoch_secrets
            .get(&frame.epoch)
            .ok_or(DmSessionError::MissingEpochSecret(frame.epoch))?;

        let key = derive_dm_message_key(secret, frame.epoch, frame.index)?;
        let aad = frame_aad(frame.epoch, frame.index);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        cipher
            .decrypt(
                Nonce::from_slice(&frame.nonce),
                Payload {
                    msg: &frame.body,
                    aad: &aad,
                },
            )
            .map_err(|_| DmSessionError::OpenFailed)
    }

    // -- persistence ----------------------------------------------------------

    /// Capture the full ratchet state as a JSON-safe value (epoch secrets hex).
    ///
    /// The returned value carries **key material** (the epoch secrets); callers
    /// MUST seal it at rest, never persist it in the clear. Layout matches Python's
    /// `DmSession.snapshot`.
    pub fn snapshot(&self) -> serde_json::Value {
        let secrets: serde_json::Map<String, serde_json::Value> = self
            .epoch_secrets
            .iter()
            .map(|(e, s)| (e.to_string(), serde_json::Value::from(hex::encode(s))))
            .collect();
        let ratchet = match &self.ratchet {
            None => serde_json::Value::Null,
            Some(r) => serde_json::json!({
                "epoch": r.epoch,
                "message_index": r.message_index,
                "epoch_started_at": r.epoch_started_at,
            }),
        };
        serde_json::json!({
            "v": 1,
            "peer": self.peer,
            "rekey_msg_bound": self.rekey_msg_bound,
            "rekey_age_seconds": self.rekey_age_seconds,
            "epoch_secrets": serde_json::Value::Object(secrets),
            "current_kam": self.current_kam.as_ref().map(hex::encode),
            "ratchet": ratchet,
        })
    }

    /// Rebuild a session from [`snapshot`](Self::snapshot) — same secrets, same
    /// next index. Mirrors Python's `DmSession.restore`.
    ///
    /// # Errors
    /// [`DmSessionError::BadToken`] (reused as a generic codec error) if the
    /// snapshot is missing required fields or has malformed hex.
    pub fn restore(snap: &serde_json::Value) -> Result<DmSession, DmSessionError> {
        let bad = |m: &str| DmSessionError::BadToken(format!("bad snapshot: {m}"));

        let peer = snap
            .get("peer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| bad("missing peer"))?;
        let rekey_msg_bound = snap
            .get("rekey_msg_bound")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| bad("missing rekey_msg_bound"))?;
        let rekey_age_seconds = snap
            .get("rekey_age_seconds")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| bad("missing rekey_age_seconds"))?;

        let mut s = DmSession::with_bounds(peer, rekey_msg_bound, rekey_age_seconds);

        if let Some(obj) = snap.get("epoch_secrets").and_then(|v| v.as_object()) {
            for (e, hexval) in obj {
                let epoch: u64 = e.parse().map_err(|_| bad("bad epoch key"))?;
                let raw = hex::decode(hexval.as_str().ok_or_else(|| bad("secret not str"))?)
                    .map_err(|_| bad("bad secret hex"))?;
                if raw.len() != EPOCH_SECRET_LEN {
                    return Err(bad("secret wrong length"));
                }
                let mut arr = [0u8; EPOCH_SECRET_LEN];
                arr.copy_from_slice(&raw);
                s.epoch_secrets.insert(epoch, arr);
            }
        }

        s.current_kam = match snap.get("current_kam") {
            Some(serde_json::Value::String(h)) => {
                Some(hex::decode(h).map_err(|_| bad("bad current_kam hex"))?)
            }
            _ => None,
        };

        if let Some(rt) = snap.get("ratchet") {
            if !rt.is_null() {
                let epoch = rt
                    .get("epoch")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| bad("ratchet.epoch"))?;
                let message_index = rt
                    .get("message_index")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| bad("ratchet.message_index"))?;
                let epoch_started_at = rt
                    .get("epoch_started_at")
                    .and_then(|v| v.as_f64())
                    .ok_or_else(|| bad("ratchet.epoch_started_at"))?;
                let epoch_secret = *s
                    .epoch_secrets
                    .get(&epoch)
                    .ok_or_else(|| bad("ratchet epoch has no stored secret"))?;
                s.ratchet = Some(DmRatchet {
                    epoch,
                    epoch_secret,
                    message_index,
                    rekey_msg_bound: s.rekey_msg_bound,
                    rekey_age_seconds: s.rekey_age_seconds,
                    epoch_started_at,
                });
            }
        }
        Ok(s)
    }

    // -- test/introspection ---------------------------------------------------

    /// Return the stored secret for `epoch` (tests / introspection only).
    pub fn epoch_secret_for_test(&self, epoch: u64) -> Option<[u8; EPOCH_SECRET_LEN]> {
        self.epoch_secrets.get(&epoch).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem;

    /// Byte-for-byte parity with the Python `_frame_aad(7, 3)`.
    #[test]
    fn parity_frame_aad_vector() {
        assert_eq!(
            hex::encode(frame_aad(7, 3)),
            "736b636861742f646d2d6672616d652f76317c0000000000000007\
             0000000000000003"
        );
    }

    #[test]
    fn token_roundtrip_with_and_without_kam() {
        let with_kam = SealedDmFrame {
            epoch: 4,
            index: 9,
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            body: vec![0xAA; 40],
            kam: Some(vec![0xBB; 1180]),
        };
        let parsed = SealedDmFrame::from_token(&with_kam.to_token()).unwrap();
        assert_eq!(parsed, with_kam);

        let no_kam = SealedDmFrame {
            kam: None,
            ..with_kam.clone()
        };
        let parsed2 = SealedDmFrame::from_token(&no_kam.to_token()).unwrap();
        assert_eq!(parsed2, no_kam);
        // The presence flag distinguishes None from any present value on the wire.
        assert_ne!(with_kam.to_token(), no_kam.to_token());
    }

    #[test]
    fn from_token_rejects_bad_input() {
        assert!(matches!(
            SealedDmFrame::from_token("nope:abc"),
            Err(DmSessionError::BadToken(_))
        ));
        assert!(matches!(
            SealedDmFrame::from_token("pqdr1:!!!not-base64!!!"),
            Err(DmSessionError::BadToken(_))
        ));
        // Valid base64 but truncated binary.
        let truncated = format!("{PQDR_SCHEME}{}", B64.encode([0u8; 4]));
        assert!(matches!(
            SealedDmFrame::from_token(&truncated),
            Err(DmSessionError::BadToken(_))
        ));
    }

    #[test]
    fn two_party_roundtrip_single_message() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::new("bob");
        let mut bob_s = DmSession::new("alice");

        let frame = alice.seal(b"hi bob", &bob.public_key).unwrap();
        assert_eq!((frame.epoch, frame.index), (0, 0));
        assert!(frame.kam.is_some(), "first frame carries the KAM");

        assert_eq!(bob_s.open(&frame, &bob.private_key).unwrap(), b"hi bob");
    }

    #[test]
    fn multi_message_in_epoch_roundtrip_via_token() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::new("bob");
        let mut bob_s = DmSession::new("alice");

        let mut out = Vec::new();
        for m in [b"a".as_slice(), b"b", b"c"] {
            // Round-trip through the wire token to exercise the codec too.
            let token = alice.seal(m, &bob.public_key).unwrap().to_token();
            let frame = SealedDmFrame::from_token(&token).unwrap();
            out.push(bob_s.open(&frame, &bob.private_key).unwrap());
        }
        assert_eq!(out, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn loss_and_reorder_tolerant_within_epoch() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::new("bob");
        let mut bob_s = DmSession::new("alice");

        let f0 = alice.seal(b"first", &bob.public_key).unwrap();
        let _f1 = alice.seal(b"second", &bob.public_key).unwrap();
        let f2 = alice.seal(b"third", &bob.public_key).unwrap();

        assert_eq!(bob_s.open(&f0, &bob.private_key).unwrap(), b"first");
        // f1 dropped; f2 still opens (index-addressed).
        assert_eq!(bob_s.open(&f2, &bob.private_key).unwrap(), b"third");
    }

    #[test]
    fn kam_repeated_on_first_frames_then_stops() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::new("bob");

        let frames: Vec<_> = (0..5)
            .map(|i| alice.seal(format!("m{i}").as_bytes(), &bob.public_key).unwrap())
            .collect();

        for (i, frame) in frames.iter().enumerate().take(KAM_REPEAT as usize) {
            assert!(frame.kam.is_some(), "frame {i} should carry the KAM");
        }
        assert!(frames[KAM_REPEAT as usize].kam.is_none());
        assert_eq!(
            frames.iter().map(|f| f.index).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn reordered_kam_frame_establishes_epoch() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::new("bob");
        let mut bob_s = DmSession::new("alice");

        let _f0 = alice.seal(b"first", &bob.public_key).unwrap();
        let f1 = alice.seal(b"second", &bob.public_key).unwrap();

        // f0 lost; f1 (a repeated KAM) arrives first and still establishes.
        assert!(f1.kam.is_some());
        assert_eq!(bob_s.open(&f1, &bob.private_key).unwrap(), b"second");
    }

    #[test]
    fn auto_rekey_starts_new_epoch_with_pcs() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::with_bounds("bob", 2, DEFAULT_REKEY_AGE_SECONDS);
        let mut bob_s = DmSession::new("alice");

        let f0 = alice.seal(b"e0m0", &bob.public_key).unwrap();
        let f1 = alice.seal(b"e0m1", &bob.public_key).unwrap(); // epoch 0 at bound
        let f2 = alice.seal(b"e1m0", &bob.public_key).unwrap(); // triggers rekey

        assert_eq!((f0.epoch, f1.epoch), (0, 0));
        assert_eq!(f2.epoch, 1);
        assert!(f2.kam.is_some(), "rekey emits a fresh KAM (PQ heal)");

        assert_eq!(bob_s.open(&f0, &bob.private_key).unwrap(), b"e0m0");
        assert_eq!(bob_s.open(&f2, &bob.private_key).unwrap(), b"e1m0");

        // Post-compromise security: the two epochs use independent secrets.
        assert_ne!(
            alice.epoch_secret_for_test(0).unwrap(),
            alice.epoch_secret_for_test(1).unwrap()
        );
    }

    #[test]
    fn open_rejects_tampered_body() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::new("bob");
        let mut bob_s = DmSession::new("alice");

        let mut frame = alice.seal(b"authentic", &bob.public_key).unwrap();
        let last = frame.body.len() - 1;
        frame.body[last] ^= 0x01;
        assert_eq!(
            bob_s.open(&frame, &bob.private_key),
            Err(DmSessionError::OpenFailed)
        );
    }

    #[test]
    fn open_without_kam_for_unknown_epoch_errors() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::new("bob");
        let mut bob_s = DmSession::new("alice");

        // Send 4 frames so the 4th (index 3) carries NO KAM, then deliver only it.
        let mut last = alice.seal(b"x0", &bob.public_key).unwrap();
        for m in [b"x1".as_slice(), b"x2", b"x3"] {
            last = alice.seal(m, &bob.public_key).unwrap();
        }
        assert!(last.kam.is_none());
        assert_eq!(
            bob_s.open(&last, &bob.private_key),
            Err(DmSessionError::MissingEpochSecret(0))
        );
    }

    #[test]
    fn snapshot_restore_preserves_state() {
        let bob = kem::hybrid_keypair();
        let mut alice = DmSession::with_bounds("bob", 5, DEFAULT_REKEY_AGE_SECONDS);
        let _ = alice.seal(b"one", &bob.public_key).unwrap();
        let _ = alice.seal(b"two", &bob.public_key).unwrap();

        let snap = alice.snapshot();
        let mut restored = DmSession::restore(&snap).unwrap();

        assert_eq!(restored.peer, "bob");
        assert_eq!(restored.rekey_msg_bound, 5);
        assert_eq!(
            restored.epoch_secret_for_test(0),
            alice.epoch_secret_for_test(0)
        );
        // The restored session keeps sending from the same next index in epoch 0.
        let frame = restored.seal(b"three", &bob.public_key).unwrap();
        assert_eq!((frame.epoch, frame.index), (0, 2));

        let mut bob_s = DmSession::new("alice");
        assert_eq!(bob_s.open(&frame, &bob.private_key).unwrap(), b"three");
    }
}
