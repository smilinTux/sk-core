//! WASM bindings for the `sk-pqc` hybrid post-quantum core.
//!
//! Exposes the four primitives the in-browser demo needs:
//! `hybrid_keypair`, `hybrid_encap`, `hybrid_decap` (the **X25519 + ML-KEM-768**
//! hybrid KEM, FIPS 203 for the ML-KEM leg) and `derive_dm_message_key` (the DM
//! epoch-ratchet message-key HKDF).
//!
//! Honest claim: this is a **hybrid** scheme — secure as long as **either** the
//! classical X25519 leg or the ML-KEM-768 leg holds. It is **not** "quantum-proof".

use sk_pqc::{kem, ratchet};
use wasm_bindgen::prelude::*;

/// A freshly generated hybrid keypair (composite wire layout).
#[wasm_bindgen]
pub struct HybridKeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl HybridKeyPair {
    /// 1216-byte `X25519_pub ‖ MLKEM768_ek`.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    /// 2432-byte `X25519_seed ‖ MLKEM768_dk`.
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

/// The result of an encapsulation: ciphertext + the derived 32-byte shared secret.
#[wasm_bindgen]
pub struct EncapResult {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl EncapResult {
    /// 1120-byte `X25519_eph_pub ‖ MLKEM768_ct`.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// 32-byte hybrid shared secret.
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

/// Generate a fresh hybrid keypair. Randomness comes from the browser's
/// `crypto.getRandomValues` (via `getrandom`'s `js` feature backing `OsRng`).
#[wasm_bindgen]
pub fn hybrid_keypair() -> HybridKeyPair {
    let kp = kem::hybrid_keypair();
    HybridKeyPair {
        public_key: kp.public_key,
        private_key: kp.private_key,
    }
}

/// Encapsulate to a peer's 1216-byte hybrid public key. Returns ciphertext +
/// shared secret, or throws on a bad-length key.
#[wasm_bindgen]
pub fn hybrid_encap(peer_public_key: &[u8]) -> Result<EncapResult, JsValue> {
    let (ciphertext, shared) =
        kem::hybrid_encap(peer_public_key).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(EncapResult {
        ciphertext,
        shared_secret: shared.to_vec(),
    })
}

/// Decapsulate a 1120-byte hybrid ciphertext with the 2432-byte private key,
/// recovering the 32-byte shared secret. Throws only on a bad length (ML-KEM uses
/// implicit rejection: a tampered ciphertext yields a non-matching secret, not an error).
#[wasm_bindgen]
pub fn hybrid_decap(ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let ss =
        kem::hybrid_decap(ciphertext, private_key).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ss.to_vec())
}

/// Derive the 32-byte AES-256 key for DM message `index` in `epoch` from a
/// 32-byte epoch secret (the DM epoch-ratchet message-key HKDF). `epoch`/`index`
/// arrive from JS as `BigInt`.
#[wasm_bindgen]
pub fn derive_dm_message_key(
    epoch_secret: &[u8],
    epoch: u64,
    index: u64,
) -> Result<Vec<u8>, JsValue> {
    let key = ratchet::derive_dm_message_key(epoch_secret, epoch, index)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(key.to_vec())
}

/// The hybrid suite identifier (`x25519-mlkem768`).
#[wasm_bindgen]
pub fn suite_id() -> String {
    kem::SUITE_ID.to_string()
}
