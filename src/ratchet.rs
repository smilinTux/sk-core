//! SKChat 1:1 DM epoch-ratchet key schedule (clean-room of
//! `skchat/dm_ratchet.py`).
//!
//! Per-conversation **epoch secrets** are distributed once per epoch via the
//! hybrid KEM (see [`crate::kem`]); per-message keys are derived symmetrically and
//! index-addressably from the epoch secret, so loss/reorder are tolerated. The
//! HKDF labels here are distinct from the group ratchet (`dm-ratchet` vs
//! `group-ratchet`) so a DM key can never collide with a group key.

use crate::kem;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Length of an epoch secret / a derived per-message key (bytes).
pub const EPOCH_SECRET_LEN: usize = 32;
/// Length of a derived per-message key (bytes).
pub const MESSAGE_KEY_LEN: usize = 32;

/// Default re-key bounds (RFC-0001 P1 / Apple-PQ3: 50 messages OR 7 days).
pub const DEFAULT_REKEY_MSG_BOUND: u64 = 50;
/// Default re-key age bound in seconds (7 days).
pub const DEFAULT_REKEY_AGE_SECONDS: u64 = 7 * 24 * 3600;

/// HKDF salt prefix — folds the epoch number into the salt (domain separation).
const EPOCH_SALT_PREFIX: &[u8] = b"skchat/dm-epoch/";
/// HKDF info prefix for per-message keys — folds the index in after a `/`.
/// Equals Python's `_INFO_DM_MESSAGE_KEY + b"/"`.
const MSG_INFO_PREFIX: &[u8] = b"skchat/dm-ratchet/msg/v1/";

/// HKDF `info` for the per-epoch wrap key (RFC 5869). Equals Python's
/// `_INFO_DM_WRAP`. Distinct from `MSG_INFO_PREFIX` and the `pqdm` wrap label,
/// so an epoch-wrap key can never collide with a message key or an envelope key.
pub const INFO_DM_WRAP: &[u8] = b"skchat/dm-ratchet/epoch-wrap/v1";

/// AES-256-GCM nonce length for the epoch-secret wrap (random per wrap).
pub const WRAP_NONCE_LEN: usize = 12;
/// Wrapped epoch secret on the wire = plaintext(32) + AES-GCM tag(16).
pub const WRAPPED_SECRET_LEN: usize = EPOCH_SECRET_LEN + 16;
/// Total per-conversation, per-epoch distribution payload size:
/// `hybrid_ct(1120) ‖ nonce(12) ‖ wrapped(48)`. Equals Python's
/// `WRAPPED_PAYLOAD_LEN`.
pub const WRAPPED_PAYLOAD_LEN: usize = kem::CIPHERTEXT_LEN + WRAP_NONCE_LEN + WRAPPED_SECRET_LEN;

/// Error type for the DM ratchet key schedule and epoch-secret distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    /// `epoch_secret` was not [`EPOCH_SECRET_LEN`] bytes.
    BadSecretLen(usize),
    /// The peer hybrid public key was not [`crate::kem::PUBLIC_KEY_LEN`] bytes.
    BadPublicKeyLen(usize),
    /// A wrapped payload was not [`WRAPPED_PAYLOAD_LEN`] bytes.
    BadPayloadLen(usize),
    /// The underlying hybrid KEM rejected the material (wrong length).
    Kem(kem::KemError),
    /// AES-256-GCM unwrap failed: tamper, wrong key, or an implicit-rejection
    /// pseudo-random KEM secret. Never distinguishes the cause (no oracle).
    UnwrapFailed,
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RatchetError::BadSecretLen(got) => {
                write!(
                    f,
                    "epoch_secret must be {EPOCH_SECRET_LEN} bytes, got {got}"
                )
            }
            RatchetError::BadPublicKeyLen(got) => write!(
                f,
                "peer hybrid public key must be {} bytes, got {got}",
                kem::PUBLIC_KEY_LEN
            ),
            RatchetError::BadPayloadLen(got) => write!(
                f,
                "wrapped epoch payload must be {WRAPPED_PAYLOAD_LEN} bytes, got {got}"
            ),
            RatchetError::Kem(e) => write!(f, "hybrid KEM error: {e}"),
            RatchetError::UnwrapFailed => write!(f, "dm epoch-secret unwrap failed"),
        }
    }
}

impl Error for RatchetError {}

impl From<kem::KemError> for RatchetError {
    fn from(e: kem::KemError) -> Self {
        RatchetError::Kem(e)
    }
}

/// Derive the AES-256 key for DM message `index` in `epoch`.
///
/// Deterministic and index-addressable: the same `(epoch_secret, epoch, index)`
/// always yields the same 32-byte key, and any index can be derived independently.
///
/// Construction (matches `skchat.dm_ratchet.derive_dm_message_key`):
/// ```text
/// salt = b"skchat/dm-epoch/"      ‖ u64_be(epoch)
/// info = b"skchat/dm-ratchet/msg/v1/" ‖ u64_be(index)
/// key  = HKDF-SHA256(IKM = epoch_secret, salt, info, L = 32)
/// ```
pub fn derive_dm_message_key(
    epoch_secret: &[u8],
    epoch: u64,
    index: u64,
) -> Result<[u8; MESSAGE_KEY_LEN], RatchetError> {
    if epoch_secret.len() != EPOCH_SECRET_LEN {
        return Err(RatchetError::BadSecretLen(epoch_secret.len()));
    }

    let mut salt = Vec::with_capacity(EPOCH_SALT_PREFIX.len() + 8);
    salt.extend_from_slice(EPOCH_SALT_PREFIX);
    salt.extend_from_slice(&epoch.to_be_bytes());

    let mut info = Vec::with_capacity(MSG_INFO_PREFIX.len() + 8);
    info.extend_from_slice(MSG_INFO_PREFIX);
    info.extend_from_slice(&index.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), epoch_secret);
    let mut okm = [0u8; MESSAGE_KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(okm)
}

/// Whether the bound (message count **OR** age) says this epoch should re-key.
///
/// Mirrors `DmRatchet.should_rekey`: re-key once `message_index >=
/// rekey_msg_bound`, or once the epoch is at least `rekey_age_seconds` old
/// (`now - epoch_started_at >= rekey_age_seconds`). Times are POSIX seconds.
pub fn should_rekey(
    message_index: u64,
    epoch_started_at: f64,
    now: f64,
    rekey_msg_bound: u64,
    rekey_age_seconds: u64,
) -> bool {
    if message_index >= rekey_msg_bound {
        return true;
    }
    (now - epoch_started_at) >= rekey_age_seconds as f64
}

/// Derive the 32-byte AES-256 wrap key from a hybrid shared secret.
///
/// `HKDF-SHA256(IKM = shared, salt = b"", info = INFO_DM_WRAP, L = 32)`.
/// (RFC 5869: an empty salt and a HashLen-zero salt yield the same PRK, matching
/// pyca `HKDF(salt=b"")`.)
fn dm_wrap_key(shared: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b""), shared);
    let mut okm = [0u8; 32];
    hk.expand(INFO_DM_WRAP, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Wall-clock POSIX seconds (UTC), as `f64` — matches Python `time.time()`.
fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Generate a fresh random 32-byte epoch secret (independent of any prior).
///
/// Mirrors `skchat.dm_ratchet.new_epoch_secret` (`os.urandom(32)`). Drawn from the
/// OS CSPRNG via [`rand::rngs::OsRng`].
pub fn new_epoch_secret() -> [u8; EPOCH_SECRET_LEN] {
    let mut secret = [0u8; EPOCH_SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

/// Wrap an epoch secret to a peer's hybrid-KEM public key (once per epoch).
///
/// Uses [`crate::kem::hybrid_encap`] (X25519 ‖ ML-KEM-768, **FIPS 203**) for a
/// one-time shared secret, HKDF-expands it to an AES-256 wrap key
/// (`dm_wrap_key`), and AES-256-GCM-encrypts the epoch secret with a random
/// 12-byte nonce and **no** associated data. The KEM ciphertext travels in the
/// blob so the peer can decapsulate — this post-quantum material is the per-epoch
/// cost, **not** a per-message cost.
///
/// The wrap is secure if **either** KEM leg (the X25519 or the ML-KEM-768 leg)
/// holds — this is a hybrid construction, not an "unbreakable" one.
///
/// Mirrors `skchat.dm_ratchet.wrap_dm_epoch_secret`.
///
/// # Arguments
/// * `epoch_secret` — the 32-byte epoch secret to distribute.
/// * `peer_hybrid_pub` — the peer's [`crate::kem::PUBLIC_KEY_LEN`]-byte hybrid
///   public key.
///
/// # Returns
/// `hybrid_ct(1120) ‖ nonce(12) ‖ wrapped(48)` = [`WRAPPED_PAYLOAD_LEN`] bytes.
///
/// # Errors
/// * [`RatchetError::BadSecretLen`] — `epoch_secret` was not 32 bytes.
/// * [`RatchetError::BadPublicKeyLen`] — wrong public-key length.
/// * [`RatchetError::Kem`] — propagated from the hybrid KEM.
pub fn wrap_dm_epoch_secret(
    epoch_secret: &[u8],
    peer_hybrid_pub: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    if epoch_secret.len() != EPOCH_SECRET_LEN {
        return Err(RatchetError::BadSecretLen(epoch_secret.len()));
    }
    if peer_hybrid_pub.len() != kem::PUBLIC_KEY_LEN {
        return Err(RatchetError::BadPublicKeyLen(peer_hybrid_pub.len()));
    }

    let (ciphertext, shared) = kem::hybrid_encap(peer_hybrid_pub)?;
    let wrap_key = dm_wrap_key(&shared);

    let mut nonce_bytes = [0u8; WRAP_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let wrapped = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), epoch_secret)
        .map_err(|_| RatchetError::UnwrapFailed)?;

    let mut payload = Vec::with_capacity(WRAPPED_PAYLOAD_LEN);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&wrapped);
    Ok(payload)
}

/// Recover an epoch secret from a wrapped payload with the recipient's hybrid key.
///
/// Inverse of [`wrap_dm_epoch_secret`]: decapsulates the KEM ciphertext, derives
/// the same wrap key, and AES-256-GCM-decrypts the wrapped secret.
///
/// ML-KEM uses implicit rejection — a tampered KEM ciphertext does NOT error at
/// decap, it yields a pseudo-random secret that then fails the AEAD open here,
/// surfaced uniformly as [`RatchetError::UnwrapFailed`] (no padding/auth oracle).
///
/// Mirrors `skchat.dm_ratchet.unwrap_dm_epoch_secret`.
///
/// # Arguments
/// * `payload` — `hybrid_ct(1120) ‖ nonce(12) ‖ wrapped(48)` from
///   [`wrap_dm_epoch_secret`].
/// * `peer_hybrid_priv` — the recipient's [`crate::kem::PRIVATE_KEY_LEN`]-byte
///   hybrid private key.
///
/// # Returns
/// The 32-byte epoch secret.
///
/// # Errors
/// * [`RatchetError::BadPayloadLen`] — wrong payload length.
/// * [`RatchetError::Kem`] — propagated (wrong private-key length).
/// * [`RatchetError::UnwrapFailed`] — AEAD auth failure (tamper / wrong key).
pub fn unwrap_dm_epoch_secret(
    payload: &[u8],
    peer_hybrid_priv: &[u8],
) -> Result<[u8; EPOCH_SECRET_LEN], RatchetError> {
    if payload.len() != WRAPPED_PAYLOAD_LEN {
        return Err(RatchetError::BadPayloadLen(payload.len()));
    }
    let ciphertext = &payload[..kem::CIPHERTEXT_LEN];
    let nonce_bytes = &payload[kem::CIPHERTEXT_LEN..kem::CIPHERTEXT_LEN + WRAP_NONCE_LEN];
    let wrapped = &payload[kem::CIPHERTEXT_LEN + WRAP_NONCE_LEN..];

    let shared = kem::hybrid_decap(ciphertext, peer_hybrid_priv)?;
    let wrap_key = dm_wrap_key(&shared);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), wrapped)
        .map_err(|_| RatchetError::UnwrapFailed)?;

    if plain.len() != EPOCH_SECRET_LEN {
        return Err(RatchetError::UnwrapFailed);
    }
    let mut out = [0u8; EPOCH_SECRET_LEN];
    out.copy_from_slice(&plain);
    Ok(out)
}

/// In-memory ratchet state for one 1:1 conversation epoch (sender or receiver).
///
/// A conversation's authoritative state is the current [`epoch`](Self::epoch)
/// number plus the current [`epoch_secret`](Self::epoch_secret); per-message keys
/// are derived on demand. The sender's [`message_index`](Self::message_index) is
/// its monotone counter for the *next* message it will send in this epoch; the
/// receiver ignores its own counter and uses each message's carried `(epoch,
/// index)` (index-addressable → loss/reorder tolerant).
///
/// Periodic rekey ([`should_rekey`](Self::should_rekey)) starts a fresh epoch with
/// an independent secret — forward secrecy across the boundary, post-compromise
/// security within. Mirrors `skchat.dm_ratchet.DmRatchet`.
#[derive(Debug, Clone)]
pub struct DmRatchet {
    /// Current epoch number.
    pub epoch: u64,
    /// 32-byte secret for the current epoch (key material — handle with care).
    pub epoch_secret: [u8; EPOCH_SECRET_LEN],
    /// Next outbound message index in this epoch.
    pub message_index: u64,
    /// Re-key after this many messages in an epoch.
    pub rekey_msg_bound: u64,
    /// Re-key after the epoch is this old (seconds).
    pub rekey_age_seconds: u64,
    /// Wall-clock creation time (POSIX seconds) of the epoch.
    pub epoch_started_at: f64,
}

impl DmRatchet {
    /// Create a ratchet for `epoch` with `epoch_secret`, default bounds, index 0,
    /// and `epoch_started_at` set to now.
    pub fn new(epoch: u64, epoch_secret: [u8; EPOCH_SECRET_LEN]) -> Self {
        Self::with_bounds(
            epoch,
            epoch_secret,
            DEFAULT_REKEY_MSG_BOUND,
            DEFAULT_REKEY_AGE_SECONDS,
        )
    }

    /// Create a ratchet with explicit re-key bounds (index 0, `epoch_started_at`
    /// = now).
    pub fn with_bounds(
        epoch: u64,
        epoch_secret: [u8; EPOCH_SECRET_LEN],
        rekey_msg_bound: u64,
        rekey_age_seconds: u64,
    ) -> Self {
        DmRatchet {
            epoch,
            epoch_secret,
            message_index: 0,
            rekey_msg_bound,
            rekey_age_seconds,
            epoch_started_at: now_seconds(),
        }
    }

    /// Derive the message key for `index` (default: the next outbound index).
    ///
    /// Infallible in practice — [`epoch_secret`](Self::epoch_secret) is always 32
    /// bytes — but returns the [`RatchetError`] from [`derive_dm_message_key`] for
    /// uniformity.
    pub fn message_key(&self, index: Option<u64>) -> Result<[u8; MESSAGE_KEY_LEN], RatchetError> {
        let idx = index.unwrap_or(self.message_index);
        derive_dm_message_key(&self.epoch_secret, self.epoch, idx)
    }

    /// Return `(index, key)` for the next message to send and advance the counter.
    ///
    /// The returned `index` MUST be placed on the wire so the peer derives the same
    /// key. Advancing the counter gives intra-epoch ordering; it does NOT gate
    /// decryption (the peer is index-addressed). Mirrors
    /// `DmRatchet.next_outbound_key`.
    pub fn next_outbound_key(&mut self) -> (u64, [u8; MESSAGE_KEY_LEN]) {
        let idx = self.message_index;
        let key = derive_dm_message_key(&self.epoch_secret, self.epoch, idx)
            .expect("epoch_secret is always EPOCH_SECRET_LEN bytes");
        self.message_index += 1;
        (idx, key)
    }

    /// Whether the bound (message count **OR** age) says this epoch should re-key.
    ///
    /// `now` defaults to the wall clock. Mirrors `DmRatchet.should_rekey`.
    pub fn should_rekey(&self, now: Option<f64>) -> bool {
        should_rekey(
            self.message_index,
            self.epoch_started_at,
            now.unwrap_or_else(now_seconds),
            self.rekey_msg_bound,
            self.rekey_age_seconds,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_and_distinctness() {
        let es = [9u8; 32];
        assert_eq!(
            derive_dm_message_key(&es, 2, 5).unwrap(),
            derive_dm_message_key(&es, 2, 5).unwrap()
        );
        assert_ne!(
            derive_dm_message_key(&es, 2, 5).unwrap(),
            derive_dm_message_key(&es, 2, 6).unwrap()
        );
    }

    #[test]
    fn rejects_bad_len() {
        assert_eq!(
            derive_dm_message_key(&[0u8; 16], 0, 0),
            Err(RatchetError::BadSecretLen(16))
        );
    }

    /// Byte-for-byte parity with the Python `derive_dm_message_key`
    /// (epoch_secret = [0x42; 32], epoch = 7, index = 3).
    #[test]
    fn parity_message_key_vector() {
        let es = [0x42u8; 32];
        let key = derive_dm_message_key(&es, 7, 3).unwrap();
        assert_eq!(
            hex::encode(key),
            "74095f508856520198d56192d8cfd3247f05f5c10f3b33b165e6f64ea1daaddf"
        );
    }

    /// Byte-for-byte parity with the Python HKDF wrap-key derivation
    /// (shared = 0..31, salt = "", info = INFO_DM_WRAP).
    #[test]
    fn parity_wrap_key_vector() {
        let shared: Vec<u8> = (0u8..32).collect();
        let wk = dm_wrap_key(&shared);
        assert_eq!(
            hex::encode(wk),
            "10e5ba98ec3dc39aa5fe92d05e4231ff99e5bd014a22f07f1387932e40b10036"
        );
    }

    #[test]
    fn new_epoch_secret_is_fresh_and_sized() {
        let a = new_epoch_secret();
        let b = new_epoch_secret();
        assert_eq!(a.len(), EPOCH_SECRET_LEN);
        assert_ne!(a, b, "two fresh epoch secrets must differ");
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kp = kem::hybrid_keypair();
        let secret = new_epoch_secret();
        let payload = wrap_dm_epoch_secret(&secret, &kp.public_key).unwrap();
        assert_eq!(payload.len(), WRAPPED_PAYLOAD_LEN);
        let recovered = unwrap_dm_epoch_secret(&payload, &kp.private_key).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn unwrap_rejects_tampered_payload() {
        let kp = kem::hybrid_keypair();
        let secret = new_epoch_secret();
        let mut payload = wrap_dm_epoch_secret(&secret, &kp.public_key).unwrap();
        // Flip a bit in the wrapped-secret region (last byte = part of the GCM tag).
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        assert_eq!(
            unwrap_dm_epoch_secret(&payload, &kp.private_key),
            Err(RatchetError::UnwrapFailed)
        );
    }

    #[test]
    fn wrap_rejects_bad_lengths() {
        let kp = kem::hybrid_keypair();
        assert_eq!(
            wrap_dm_epoch_secret(&[0u8; 16], &kp.public_key),
            Err(RatchetError::BadSecretLen(16))
        );
        assert_eq!(
            wrap_dm_epoch_secret(&[0u8; 32], &[0u8; 10]),
            Err(RatchetError::BadPublicKeyLen(10))
        );
        assert_eq!(
            unwrap_dm_epoch_secret(&[0u8; 5], &kp.private_key),
            Err(RatchetError::BadPayloadLen(5))
        );
    }

    #[test]
    fn dm_ratchet_next_outbound_advances_and_is_index_addressable() {
        let secret = [0x11u8; 32];
        let mut r = DmRatchet::new(0, secret);
        let (i0, k0) = r.next_outbound_key();
        let (i1, k1) = r.next_outbound_key();
        assert_eq!((i0, i1), (0, 1));
        assert_eq!(r.message_index, 2);
        // A receiver re-derives the same key index-addressably.
        assert_eq!(derive_dm_message_key(&secret, 0, 0).unwrap(), k0);
        assert_eq!(derive_dm_message_key(&secret, 0, 1).unwrap(), k1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn dm_ratchet_should_rekey_bounds() {
        let mut r = DmRatchet::with_bounds(0, [7u8; 32], 2, DEFAULT_REKEY_AGE_SECONDS);
        assert!(!r.should_rekey(Some(r.epoch_started_at)));
        r.message_index = 2;
        assert!(r.should_rekey(Some(r.epoch_started_at)), "msg bound hit");
        // Age bound: far-future `now` triggers rekey even below the msg bound.
        let mut r2 = DmRatchet::with_bounds(0, [7u8; 32], 50, 10);
        assert!(r2.should_rekey(Some(r2.epoch_started_at + 11.0)));
        r2.message_index = 1;
        assert!(!r2.should_rekey(Some(r2.epoch_started_at + 1.0)));
    }
}
