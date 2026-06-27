//! SKChat **group** epoch-ratchet — hybrid post-quantum group key distribution
//! (clean-room of `skchat/group_ratchet.py`, byte-for-byte interoperable).
//!
//! This is the marquee Harvest-Now-Decrypt-Later (HNDL) fix for group chat. It
//! replaces a *static* `os.urandom(32)` group key (PGP-wrapped per member) with a
//! **per-epoch ratchet** whose epoch secret is distributed via the vetted hybrid
//! KEM in [`crate::kem`] (`x25519-mlkem768` — `HKDF(X25519_ss ‖ MLKEM768_ss)`).
//!
//! ## Why this kills the highest-leverage quantum vulnerability
//!
//! A single long-lived AES key wrapped to each member's classical key means:
//! break **one** member's classical key (now, or post-CRQC against harvested
//! ciphertext) and you recover the AES key → decrypt **all** group history. The
//! epoch-ratchet breaks that:
//!
//! * The epoch secret is wrapped to each member with a **hybrid** KEM — it stays
//!   secret unless **both** the X25519 **and** the ML-KEM-768 leg are broken
//!   (HNDL-resistant; ML-KEM is **FIPS 203**).
//! * Each epoch has its own independent secret. A leaked epoch secret reveals only
//!   that epoch (post-compromise security, PCS).
//! * Re-keying on member add/remove gives forward secrecy (FS): a removed member
//!   cannot derive any future epoch's keys.
//!
//! ## Two layers
//!
//! 1. **Epoch distribution (asymmetric, hybrid-KEM, ONCE PER EPOCH).** For each
//!    member holding a [`kem::PUBLIC_KEY_LEN`]-byte hybrid public key, the 32-byte
//!    epoch secret is wrapped:
//!    ```text
//!    ct, ss   = hybrid_encap(member_pub)                  # PQ material — once/epoch
//!    wrap_key = HKDF-SHA256(ss, salt=b"", info=EPOCH_WRAP_INFO, L=32)
//!    wrapped  = AES-256-GCM(wrap_key).seal(nonce, epoch_secret)   # no AAD
//!    payload  = ct(1120) ‖ nonce(12) ‖ wrapped(48)        # 1180 B / member / epoch
//!    ```
//!    The ~1.1 KB of ML-KEM ciphertext is paid **once per epoch**, NOT per message.
//!
//! 2. **Per-message keys (symmetric KDF ratchet, NO PQ material).** Message keys
//!    are derived directly by index, so the scheme is loss- and reorder-tolerant:
//!    ```text
//!    salt = b"skchat/epoch/"               ‖ u64_be(epoch)
//!    info = b"skchat/group-ratchet/msg/v1/" ‖ u64_be(index)
//!    key  = HKDF-SHA256(IKM=epoch_secret, salt, info, L=32)
//!    ```
//!
//! ## Honest claims
//!
//! This is a **hybrid** scheme — secure as long as **either** the classical X25519
//! leg **or** the ML-KEM-768 leg (FIPS 203) holds. It is **not** "quantum-proof",
//! "quantum-safe", or "unbreakable". We never hand-roll lattice/curve/AEAD math:
//! ML-KEM + X25519 come from [`crate::kem`], AES-256-GCM from `aes-gcm`, the KDF
//! from `hkdf` + `sha2`; only the label/wire wiring is original. The HKDF labels
//! here (`group-ratchet`) are distinct from the DM ratchet (`dm-ratchet`,
//! [`crate::ratchet`]) so a group key can never collide with a DM key.

use crate::kem::{self, KemError, CIPHERTEXT_LEN as HYBRID_CIPHERTEXT_LEN};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::error::Error;
use std::fmt;

// --- Interop constants (DO NOT CHANGE — pinned by skchat/group_ratchet.py) ----

/// The crypto-suite id a group must carry to use this ratchet (matches
/// [`kem::SUITE_ID`] / `skcomms.crypto_suites`).
pub const HYBRID_KEM_SUITE: &str = "x25519-mlkem768";

/// Length of an epoch secret (bytes).
pub const EPOCH_SECRET_LEN: usize = 32;
/// Length of a derived per-message key (bytes).
pub const MESSAGE_KEY_LEN: usize = 32;

/// HKDF `info` for the epoch-secret wrap (RFC 5869). Equals Python's
/// `_INFO_EPOCH_WRAP`.
pub const EPOCH_WRAP_INFO: &[u8] = b"skchat/group-ratchet/epoch-wrap/v1";

/// HKDF salt prefix for per-message keys — the epoch number is appended as
/// `u64_be`. Equals Python's `_epoch_salt` prefix `b"skchat/epoch/"`.
const MSG_SALT_PREFIX: &[u8] = b"skchat/epoch/";
/// HKDF `info` prefix for per-message keys — the message index is appended as
/// `u64_be`. Equals Python's `_INFO_MESSAGE_KEY + b"/"`
/// (`b"skchat/group-ratchet/msg/v1" + b"/"`).
const MSG_INFO_PREFIX: &[u8] = b"skchat/group-ratchet/msg/v1/";

/// AES-256-GCM nonce length for the epoch-secret wrap (random per wrap).
pub const WRAP_NONCE_LEN: usize = 12;
/// Wrapped epoch secret = plaintext(32) + AES-256-GCM tag(16).
pub const WRAPPED_SECRET_LEN: usize = EPOCH_SECRET_LEN + 16;
/// Total per-member, per-epoch distribution payload size
/// (`ct(1120) ‖ nonce(12) ‖ wrapped(48)` = 1180).
pub const WRAPPED_PAYLOAD_LEN: usize =
    HYBRID_CIPHERTEXT_LEN + WRAP_NONCE_LEN + WRAPPED_SECRET_LEN;

/// Default re-key bound: re-key after this many messages in an epoch.
pub const DEFAULT_REKEY_MSG_BOUND: u64 = 50;
/// Default re-key bound: re-key once the epoch is this many seconds old (7 days).
pub const DEFAULT_REKEY_AGE_SECONDS: u64 = 7 * 24 * 3600;

// --- Errors -------------------------------------------------------------------

/// Errors from the group epoch-ratchet (never a panic on malformed input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupRatchetError {
    /// `epoch_secret` was not [`EPOCH_SECRET_LEN`] bytes: `(got)`.
    BadSecretLen(usize),
    /// The member hybrid public key was not [`kem::PUBLIC_KEY_LEN`] bytes: `(got)`.
    BadPublicKeyLen(usize),
    /// The member hybrid private key was not [`kem::PRIVATE_KEY_LEN`] bytes: `(got)`.
    BadPrivateKeyLen(usize),
    /// The wrapped payload was not [`WRAPPED_PAYLOAD_LEN`] bytes: `(got)`.
    BadPayloadLen(usize),
    /// The underlying hybrid KEM failed (propagated — never silently downgraded).
    Kem(KemError),
    /// AES-256-GCM authentication failed (wrong key or tampered payload).
    UnwrapFailed,
}

impl fmt::Display for GroupRatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupRatchetError::BadSecretLen(got) => {
                write!(f, "epoch_secret must be {EPOCH_SECRET_LEN} bytes, got {got}")
            }
            GroupRatchetError::BadPublicKeyLen(got) => write!(
                f,
                "member hybrid public key must be {} bytes, got {got}",
                kem::PUBLIC_KEY_LEN
            ),
            GroupRatchetError::BadPrivateKeyLen(got) => write!(
                f,
                "member hybrid private key must be {} bytes, got {got}",
                kem::PRIVATE_KEY_LEN
            ),
            GroupRatchetError::BadPayloadLen(got) => write!(
                f,
                "wrapped epoch payload must be {WRAPPED_PAYLOAD_LEN} bytes, got {got}"
            ),
            GroupRatchetError::Kem(e) => write!(f, "hybrid KEM error: {e}"),
            GroupRatchetError::UnwrapFailed => {
                write!(f, "epoch-secret unwrap failed (auth tag mismatch)")
            }
        }
    }
}

impl Error for GroupRatchetError {}

impl From<KemError> for GroupRatchetError {
    fn from(e: KemError) -> Self {
        GroupRatchetError::Kem(e)
    }
}

// --- Per-message key derivation (symmetric ratchet — no PQ material) ----------

/// Derive a message key from a known-length epoch secret (infallible internal).
fn derive_message_key_arr(
    epoch_secret: &[u8; EPOCH_SECRET_LEN],
    epoch: u64,
    index: u64,
) -> [u8; MESSAGE_KEY_LEN] {
    let mut salt = Vec::with_capacity(MSG_SALT_PREFIX.len() + 8);
    salt.extend_from_slice(MSG_SALT_PREFIX);
    salt.extend_from_slice(&epoch.to_be_bytes());

    let mut info = Vec::with_capacity(MSG_INFO_PREFIX.len() + 8);
    info.extend_from_slice(MSG_INFO_PREFIX);
    info.extend_from_slice(&index.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), epoch_secret);
    let mut okm = [0u8; MESSAGE_KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Derive the AES-256 key for message `index` in `epoch`.
///
/// Deterministic and index-addressable (loss/reorder tolerant): the same
/// `(epoch_secret, epoch, index)` always yields the same 32-byte key, and any
/// index can be derived independently of the others.
///
/// Construction (matches `skchat.group_ratchet.derive_message_key`):
/// ```text
/// salt = b"skchat/epoch/"               ‖ u64_be(epoch)
/// info = b"skchat/group-ratchet/msg/v1/" ‖ u64_be(index)
/// key  = HKDF-SHA256(IKM = epoch_secret, salt, info, L = 32)
/// ```
///
/// # Errors
/// [`GroupRatchetError::BadSecretLen`] if `epoch_secret` is not
/// [`EPOCH_SECRET_LEN`] bytes.
pub fn derive_message_key(
    epoch_secret: &[u8],
    epoch: u64,
    index: u64,
) -> Result<[u8; MESSAGE_KEY_LEN], GroupRatchetError> {
    let es: &[u8; EPOCH_SECRET_LEN] = epoch_secret
        .try_into()
        .map_err(|_| GroupRatchetError::BadSecretLen(epoch_secret.len()))?;
    Ok(derive_message_key_arr(es, epoch, index))
}

// --- Epoch-secret wrapping (hybrid KEM, once per epoch per member) -------------

/// Generate a fresh random 32-byte epoch secret (CSPRNG via `OsRng`).
pub fn new_epoch_secret() -> [u8; EPOCH_SECRET_LEN] {
    let mut secret = [0u8; EPOCH_SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// HKDF-expand the hybrid shared secret into the AES-256 epoch-wrap key.
/// `HKDF-SHA256(IKM = shared, salt = b"", info = EPOCH_WRAP_INFO, L = 32)`.
fn derive_wrap_key(shared: &[u8]) -> [u8; 32] {
    // salt = b"" (RFC 5869 zero-pads → same PRK as a HashLen-zero salt; matches
    // pyca `HKDF(salt=b"")`).
    let hk = Hkdf::<Sha256>::new(Some(b""), shared);
    let mut key = [0u8; 32];
    hk.expand(EPOCH_WRAP_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Wrap an epoch secret to a single member's hybrid-KEM public key.
///
/// Uses [`kem::hybrid_encap`] (X25519 ‖ ML-KEM-768) to derive a one-time shared
/// secret, HKDF-expands it to an AES-256 wrap key, and AES-256-GCM-encrypts the
/// epoch secret (no AAD, matching the Python `AESGCM().encrypt(nonce, pt, None)`).
/// The returned blob carries the KEM ciphertext so the recipient can decapsulate —
/// this PQ material is the per-epoch cost (NOT per message).
///
/// # Arguments
/// * `epoch_secret` — the [`EPOCH_SECRET_LEN`]-byte epoch secret.
/// * `member_hybrid_pub` — the member's [`kem::PUBLIC_KEY_LEN`]-byte hybrid public key.
///
/// # Returns
/// `ct(1120) ‖ nonce(12) ‖ wrapped(48)` = [`WRAPPED_PAYLOAD_LEN`] bytes.
///
/// # Errors
/// * [`GroupRatchetError::BadSecretLen`] / [`GroupRatchetError::BadPublicKeyLen`]
///   on malformed inputs.
/// * [`GroupRatchetError::Kem`] if the hybrid encapsulation fails (propagated —
///   never silently downgraded).
pub fn wrap_epoch_secret(
    epoch_secret: &[u8],
    member_hybrid_pub: &[u8],
) -> Result<Vec<u8>, GroupRatchetError> {
    if epoch_secret.len() != EPOCH_SECRET_LEN {
        return Err(GroupRatchetError::BadSecretLen(epoch_secret.len()));
    }
    if member_hybrid_pub.len() != kem::PUBLIC_KEY_LEN {
        return Err(GroupRatchetError::BadPublicKeyLen(member_hybrid_pub.len()));
    }

    let (ciphertext, shared) = kem::hybrid_encap(member_hybrid_pub)?;
    let wrap_key = derive_wrap_key(&shared);

    let mut nonce_bytes = [0u8; WRAP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    // `&[u8]` payload → empty AAD, matching pyca's `aad=None`.
    let wrapped = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), epoch_secret)
        .map_err(|_| GroupRatchetError::UnwrapFailed)?;

    let mut payload = Vec::with_capacity(WRAPPED_PAYLOAD_LEN);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&wrapped);
    Ok(payload)
}

/// Recover an epoch secret from a wrapped payload using the member's private key.
///
/// # Arguments
/// * `payload` — `ct(1120) ‖ nonce(12) ‖ wrapped(48)` from [`wrap_epoch_secret`].
/// * `member_hybrid_priv` — the member's [`kem::PRIVATE_KEY_LEN`]-byte hybrid
///   private key.
///
/// # Returns
/// The [`EPOCH_SECRET_LEN`]-byte epoch secret.
///
/// # Errors
/// * [`GroupRatchetError::BadPayloadLen`] / [`GroupRatchetError::BadPrivateKeyLen`]
///   on malformed inputs.
/// * [`GroupRatchetError::Kem`] if decapsulation fails on length grounds.
/// * [`GroupRatchetError::UnwrapFailed`] on AES-256-GCM auth failure (wrong key,
///   tampered payload, or — via ML-KEM implicit rejection — a tampered KEM
///   ciphertext yielding a mismatching shared secret).
pub fn unwrap_epoch_secret(
    payload: &[u8],
    member_hybrid_priv: &[u8],
) -> Result<[u8; EPOCH_SECRET_LEN], GroupRatchetError> {
    if payload.len() != WRAPPED_PAYLOAD_LEN {
        return Err(GroupRatchetError::BadPayloadLen(payload.len()));
    }
    if member_hybrid_priv.len() != kem::PRIVATE_KEY_LEN {
        return Err(GroupRatchetError::BadPrivateKeyLen(member_hybrid_priv.len()));
    }

    let ciphertext = &payload[..HYBRID_CIPHERTEXT_LEN];
    let nonce = &payload[HYBRID_CIPHERTEXT_LEN..HYBRID_CIPHERTEXT_LEN + WRAP_NONCE_LEN];
    let wrapped = &payload[HYBRID_CIPHERTEXT_LEN + WRAP_NONCE_LEN..];

    let shared = kem::hybrid_decap(ciphertext, member_hybrid_priv)?;
    let wrap_key = derive_wrap_key(&shared);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), wrapped)
        .map_err(|_| GroupRatchetError::UnwrapFailed)?;

    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| GroupRatchetError::BadSecretLen(plaintext.len()))
}

// --- Ratchet state ------------------------------------------------------------

/// In-memory ratchet state for one group epoch (sender or receiver side).
///
/// A group's authoritative state is the current `epoch` number + the current
/// `epoch_secret`; per-message keys are derived on demand. `message_index` is the
/// sender's monotone counter for the *next* message it will send in this epoch.
/// Receivers ignore their own counter and use each message's carried
/// `(epoch, index)`.
///
/// Mirrors `skchat.group_ratchet.EpochRatchet`.
#[derive(Clone, Debug)]
pub struct EpochRatchet {
    /// Current epoch number.
    pub epoch: u64,
    /// 32-byte secret for the current epoch.
    pub epoch_secret: [u8; EPOCH_SECRET_LEN],
    /// Next outbound message index in this epoch.
    pub message_index: u64,
    /// Re-key after this many messages in an epoch.
    pub rekey_msg_bound: u64,
    /// Re-key after the epoch is this many seconds old.
    pub rekey_age_seconds: u64,
    /// Wall-clock creation time (POSIX seconds) of the epoch.
    pub epoch_started_at: f64,
}

impl EpochRatchet {
    /// Create a ratchet for `epoch` with `epoch_secret`, default re-key bounds, and
    /// `epoch_started_at` set to the current POSIX time.
    pub fn new(epoch: u64, epoch_secret: [u8; EPOCH_SECRET_LEN]) -> Self {
        EpochRatchet {
            epoch,
            epoch_secret,
            message_index: 0,
            rekey_msg_bound: DEFAULT_REKEY_MSG_BOUND,
            rekey_age_seconds: DEFAULT_REKEY_AGE_SECONDS,
            epoch_started_at: now_unix(),
        }
    }

    /// Create a ratchet with an explicit `epoch_started_at` (for deterministic
    /// tests and replay).
    pub fn new_with_started_at(
        epoch: u64,
        epoch_secret: [u8; EPOCH_SECRET_LEN],
        epoch_started_at: f64,
    ) -> Self {
        EpochRatchet {
            epoch,
            epoch_secret,
            message_index: 0,
            rekey_msg_bound: DEFAULT_REKEY_MSG_BOUND,
            rekey_age_seconds: DEFAULT_REKEY_AGE_SECONDS,
            epoch_started_at,
        }
    }

    /// Derive the message key for `index` (the secret is fixed-length, so infallible).
    pub fn message_key(&self, index: u64) -> [u8; MESSAGE_KEY_LEN] {
        derive_message_key_arr(&self.epoch_secret, self.epoch, index)
    }

    /// Return `(index, key)` for the next message to send and advance the counter.
    ///
    /// The returned `index` MUST be placed on the wire so receivers derive the same
    /// key. Advancing the counter is what gives intra-epoch ordering; it does NOT
    /// gate decryption (receivers are index-addressed).
    pub fn next_outbound_key(&mut self) -> (u64, [u8; MESSAGE_KEY_LEN]) {
        let idx = self.message_index;
        let key = derive_message_key_arr(&self.epoch_secret, self.epoch, idx);
        self.message_index += 1;
        (idx, key)
    }

    /// Whether the bound (message count **OR** age) says this epoch should re-key.
    ///
    /// Mirrors `EpochRatchet.should_rekey`: re-key once `message_index >=
    /// rekey_msg_bound`, or once the epoch is at least `rekey_age_seconds` old
    /// (`now - epoch_started_at >= rekey_age_seconds`). `now` is POSIX seconds.
    pub fn should_rekey(&self, now: f64) -> bool {
        if self.message_index >= self.rekey_msg_bound {
            return true;
        }
        (now - self.epoch_started_at) >= self.rekey_age_seconds as f64
    }
}

/// Current POSIX time in seconds as `f64` (mirrors Python `time.time()`).
fn now_unix() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Python-PARITY: `derive_message_key(bytes(0..32), epoch, index)`.
    /// Values computed from `skchat.group_ratchet.derive_message_key` (pyca HKDF).
    #[test]
    fn parity_derive_message_key() {
        let mut es = [0u8; 32];
        for (i, b) in es.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = derive_message_key(&es, 7, 3).unwrap();
        assert_eq!(
            hex::encode(key),
            "7a5e2d075c683a156190450dbb2ba2e19fab6639da12e9dd7e283dbeba1e8054"
        );
        // Second hardcoded vector (epoch=0, index=0).
        let key0 = derive_message_key(&es, 0, 0).unwrap();
        assert_eq!(
            hex::encode(key0),
            "dfc01932cac7e640f0ddfee2694975f504a5cd4d15298837489f7bd1f18319e1"
        );
    }

    #[test]
    fn derive_determinism_and_distinctness() {
        let es = [9u8; 32];
        assert_eq!(
            derive_message_key(&es, 2, 5).unwrap(),
            derive_message_key(&es, 2, 5).unwrap()
        );
        // Distinct index, epoch, and secret all change the key.
        assert_ne!(
            derive_message_key(&es, 2, 5).unwrap(),
            derive_message_key(&es, 2, 6).unwrap()
        );
        assert_ne!(
            derive_message_key(&es, 2, 5).unwrap(),
            derive_message_key(&es, 3, 5).unwrap()
        );
        assert_ne!(
            derive_message_key(&es, 2, 5).unwrap(),
            derive_message_key(&[8u8; 32], 2, 5).unwrap()
        );
    }

    #[test]
    fn derive_rejects_bad_secret_len() {
        assert_eq!(
            derive_message_key(&[0u8; 16], 0, 0),
            Err(GroupRatchetError::BadSecretLen(16))
        );
    }

    #[test]
    fn wrap_layout_and_constants() {
        // Wire layout must equal the Python sizes exactly.
        assert_eq!(HYBRID_CIPHERTEXT_LEN, 1120);
        assert_eq!(WRAP_NONCE_LEN, 12);
        assert_eq!(WRAPPED_SECRET_LEN, 48);
        assert_eq!(WRAPPED_PAYLOAD_LEN, 1180);
        assert_eq!(HYBRID_KEM_SUITE, kem::SUITE_ID);
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let kp = kem::hybrid_keypair();
        let secret = new_epoch_secret();
        let payload = wrap_epoch_secret(&secret, &kp.public_key).unwrap();
        assert_eq!(payload.len(), WRAPPED_PAYLOAD_LEN);
        let recovered = unwrap_epoch_secret(&payload, &kp.private_key).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn wrap_is_randomized_but_both_unwrap() {
        // Fresh KEM ct + nonce each call → distinct payloads, same recovered secret.
        let kp = kem::hybrid_keypair();
        let secret = new_epoch_secret();
        let p1 = wrap_epoch_secret(&secret, &kp.public_key).unwrap();
        let p2 = wrap_epoch_secret(&secret, &kp.public_key).unwrap();
        assert_ne!(p1, p2);
        assert_eq!(unwrap_epoch_secret(&p1, &kp.private_key).unwrap(), secret);
        assert_eq!(unwrap_epoch_secret(&p2, &kp.private_key).unwrap(), secret);
    }

    #[test]
    fn unwrap_rejects_tampered_payload() {
        let kp = kem::hybrid_keypair();
        let secret = new_epoch_secret();
        let mut payload = wrap_epoch_secret(&secret, &kp.public_key).unwrap();
        // Flip a byte in the AES-GCM tag region (last byte).
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        assert_eq!(
            unwrap_epoch_secret(&payload, &kp.private_key),
            Err(GroupRatchetError::UnwrapFailed)
        );
    }

    #[test]
    fn unwrap_rejects_wrong_key() {
        let kp = kem::hybrid_keypair();
        let other = kem::hybrid_keypair();
        let secret = new_epoch_secret();
        let payload = wrap_epoch_secret(&secret, &kp.public_key).unwrap();
        // Wrong private key → ML-KEM implicit rejection → mismatching wrap key →
        // GCM auth failure.
        assert_eq!(
            unwrap_epoch_secret(&payload, &other.private_key),
            Err(GroupRatchetError::UnwrapFailed)
        );
    }

    #[test]
    fn wrap_rejects_bad_lengths() {
        let kp = kem::hybrid_keypair();
        assert_eq!(
            wrap_epoch_secret(&[0u8; 16], &kp.public_key),
            Err(GroupRatchetError::BadSecretLen(16))
        );
        assert_eq!(
            wrap_epoch_secret(&[0u8; 32], &[0u8; 10]),
            Err(GroupRatchetError::BadPublicKeyLen(10))
        );
    }

    #[test]
    fn unwrap_rejects_bad_lengths() {
        let kp = kem::hybrid_keypair();
        assert_eq!(
            unwrap_epoch_secret(&[0u8; 100], &kp.private_key),
            Err(GroupRatchetError::BadPayloadLen(100))
        );
        assert_eq!(
            unwrap_epoch_secret(&[0u8; WRAPPED_PAYLOAD_LEN], &[0u8; 10]),
            Err(GroupRatchetError::BadPrivateKeyLen(10))
        );
    }

    #[test]
    fn ratchet_outbound_advances_and_matches_receiver() {
        let secret = new_epoch_secret();
        let mut sender = EpochRatchet::new(4, secret);
        let receiver = EpochRatchet::new(4, secret);

        let (i0, k0) = sender.next_outbound_key();
        let (i1, k1) = sender.next_outbound_key();
        assert_eq!(i0, 0);
        assert_eq!(i1, 1);
        assert_eq!(sender.message_index, 2);
        assert_ne!(k0, k1);
        // Receiver derives the same keys by carried index (loss/reorder tolerant).
        assert_eq!(receiver.message_key(i0), k0);
        assert_eq!(receiver.message_key(i1), k1);
    }

    #[test]
    fn should_rekey_on_msg_bound() {
        let secret = new_epoch_secret();
        let mut r = EpochRatchet::new_with_started_at(1, secret, 1000.0);
        assert!(!r.should_rekey(1000.0));
        r.message_index = DEFAULT_REKEY_MSG_BOUND;
        assert!(r.should_rekey(1000.0));
    }

    #[test]
    fn should_rekey_on_age() {
        let secret = new_epoch_secret();
        let r = EpochRatchet::new_with_started_at(1, secret, 1000.0);
        // Just under 7 days → no rekey; at/over → rekey.
        assert!(!r.should_rekey(1000.0 + DEFAULT_REKEY_AGE_SECONDS as f64 - 1.0));
        assert!(r.should_rekey(1000.0 + DEFAULT_REKEY_AGE_SECONDS as f64));
    }
}
