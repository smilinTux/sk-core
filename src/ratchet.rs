//! SKChat 1:1 DM epoch-ratchet key schedule (clean-room of
//! `skchat/dm_ratchet.py`).
//!
//! Per-conversation **epoch secrets** are distributed once per epoch via the
//! hybrid KEM (see [`crate::kem`]); per-message keys are derived symmetrically and
//! index-addressably from the epoch secret, so loss/reorder are tolerated. The
//! HKDF labels here are distinct from the group ratchet (`dm-ratchet` vs
//! `group-ratchet`) so a DM key can never collide with a group key.

use hkdf::Hkdf;
use sha2::Sha256;
use std::error::Error;
use std::fmt;

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

/// Error type for the DM ratchet key schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    /// `epoch_secret` was not [`EPOCH_SECRET_LEN`] bytes.
    BadSecretLen(usize),
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RatchetError::BadSecretLen(got) => {
                write!(f, "epoch_secret must be {EPOCH_SECRET_LEN} bytes, got {got}")
            }
        }
    }
}

impl Error for RatchetError {}

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
}
