//! `pqroute1` — the metadata-sealing **routing envelope** (clean-room of
//! `skcomms/pqroute.py`).
//!
//! A routing envelope separates *what a relay must see to forward* from *what only
//! the final destination may read*. The outer **route header** is plaintext (a
//! relay reads the next hop); the **inner** metadata + content are sealed to the
//! destination's hybrid prekey via the vetted [`crate::kem`] KEM
//! (`x25519-mlkem768`) + AES-256-GCM.
//!
//! # Why this beats a classical mix/relay layer
//!
//! A classical onion/mix relay protects routing metadata with classical public-key
//! crypto only, so a *harvest-now-decrypt-later* adversary that records every hop
//! can decrypt the sealed metadata once a cryptographically-relevant quantum
//! computer exists. `pqroute1` seals the inner layer with the **hybrid** X25519 +
//! ML-KEM-768 KEM (ML-KEM is **FIPS 203**): the inner layer stays confidential if
//! **either** the X25519 leg **or** the ML-KEM-768 leg holds. This is a *hybrid*
//! guarantee — **not** "quantum-proof", "quantum-safe", or "unbreakable". We never
//! implement lattice or curve math; the only original code here is the wiring of
//! [`crate::kem`] + `aes-gcm` + `hkdf`.
//!
//! # Wire format (the interop contract)
//!
//! ```text
//! blob  = hdr_len(4, big-endian) || route_hdr_json(plaintext)
//!       || ct(1120) || nonce(12) || aesgcm(inner)              # the sealed inner
//!
//! inner = meta_len(4, big-endian) || inner_metadata_json || content   # pre-seal
//! ```
//!
//! The sealed inner mirrors the DM-wrap idiom exactly:
//!
//! ```text
//! (ct, ss)  = hybrid_encap(dest_hybrid_pub)        # ct = X25519_eph || ML-KEM ct
//! aad       = b"pqroute1" || b"|" || canonical(route_hdr)
//! wrap_key  = HKDF-SHA256(IKM = ss, salt = b"", info = b"skcomms/pqroute/wrap/v1|" || aad, L = 32)
//! sealed    = ct || nonce || AES-256-GCM(wrap_key).encrypt(nonce, inner, aad)
//! ```
//!
//! # Header authenticity (defence beyond confidentiality)
//!
//! The outer route header is plaintext (a relay must read it) but it is folded into
//! the AEAD **AAD**, so it is *authenticated* end-to-end. A relay that rewrites the
//! next-hop field cannot do so silently: the destination reconstructs the AAD from
//! the header it actually receives, the AEAD fails to authenticate, and
//! [`open_routed`] returns [`PqRouteError::Open`]. The header is therefore
//! tamper-evident even though it is never encrypted.
//!
//! # Canonical JSON & byte-for-byte interop
//!
//! Headers and metadata are encoded with a canonical JSON encoder that matches
//! CPython's `json.dumps(obj, sort_keys=True, separators=(",", ":"))` **including
//! `ensure_ascii=True`** (non-ASCII escaped as `\uXXXX`, lowercase hex, surrogate
//! pairs above U+FFFF). The AAD therefore reproduces the exact bytes the Python
//! daemon computes, so an envelope sealed by one side opens on the other. Integer
//! and the common bool/null/string/array shapes are byte-identical; exotic float
//! formatting is the one edge where CPython's `repr` and `serde_json` *could*
//! diverge (routing headers are integer/string/bool in practice).
//!
//! # Honesty / no silent downgrade
//!
//! Hybrid sealing only. A KEM failure (e.g. a malformed key) is a hard error — this
//! module never falls back to a classical-only routing layer.
//!
//! CLEAN-ROOM: the routing-split *idea* is inspired by mix/relay designs (incl.
//! SimpleX) but no third-party code was used — only the SK primitives above.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::Value;
use sha2::Sha256;
use std::error::Error;
use std::fmt;

use crate::kem::{self, CIPHERTEXT_LEN as HYBRID_CIPHERTEXT_LEN, PUBLIC_KEY_LEN as HYBRID_PUBLIC_KEY_LEN};

// --- Interop constants (DO NOT CHANGE — pinned by skcomms/pqroute.py) --------

/// The routing-envelope suite id (bound into the AEAD AAD).
pub const ROUTE_SUITE: &str = "pqroute1";

/// HKDF domain-separation label for the routing-inner wrap key (distinct from the
/// DM/envelope-wrap label and the group-epoch-wrap label). Equals Python
/// `_INFO_WRAP`.
pub const INFO_WRAP: &[u8] = b"skcomms/pqroute/wrap/v1";

/// Bytes for both `hdr_len` and `meta_len` (big-endian `u32`).
pub const LEN_PREFIX: usize = 4;
/// AES-256-GCM nonce length (bytes).
pub const WRAP_NONCE_LEN: usize = 12;
/// AES-256-GCM authentication-tag length (bytes).
pub const AESGCM_TAG_LEN: usize = 16;
/// Derived AES-256 wrap-key length (bytes).
pub const WRAP_KEY_LEN: usize = 32;

/// Minimum sealed-inner size = `ct(1120) || nonce(12) || tag(16)`. The true floor
/// is a touch larger (the inner plaintext is at least 4 bytes of `meta_len`); this
/// is the AEAD floor used for length validation, matching Python `_SEALED_MIN_LEN`.
pub const SEALED_MIN_LEN: usize = HYBRID_CIPHERTEXT_LEN + WRAP_NONCE_LEN + AESGCM_TAG_LEN;

// --- Errors ------------------------------------------------------------------

/// Errors from the `pqroute1` routing envelope (never a panic on bad input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqRouteError {
    /// Malformed envelope or a wrong-length key — a blob-format problem.
    /// Mirrors Python `PqRouteFormatError`.
    Format(String),
    /// Opening failed: wrong key, tampered inner, or a rewritten (AAD-bound)
    /// route header. A security event, not a retry signal. Mirrors Python
    /// `PqRouteOpenError`.
    Open(String),
    /// Propagated from the hybrid KEM ([`crate::kem::KemError`]).
    Kem(kem::KemError),
}

impl fmt::Display for PqRouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqRouteError::Format(m) => write!(f, "pqroute format error: {m}"),
            PqRouteError::Open(m) => write!(f, "pqroute open error: {m}"),
            PqRouteError::Kem(e) => write!(f, "pqroute KEM error: {e}"),
        }
    }
}

impl Error for PqRouteError {}

impl From<kem::KemError> for PqRouteError {
    fn from(e: kem::KemError) -> Self {
        PqRouteError::Kem(e)
    }
}

// --- Canonical JSON (CPython json.dumps parity) ------------------------------

/// Canonicalise a [`Value`] to CPython-`json.dumps`-compatible bytes.
///
/// Matches `json.dumps(obj, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)`:
///
/// * object keys sorted by Unicode code point (UTF-8 byte order == code-point
///   order for valid UTF-8);
/// * tight separators (`,` and `:`, no spaces);
/// * non-ASCII (and any char outside `0x20..=0x7e`) escaped as `\uXXXX` with
///   lowercase hex, using surrogate pairs above U+FFFF.
///
/// This determinism is what makes the AAD — and therefore the whole envelope —
/// byte-for-byte interoperable with the Python daemon.
pub fn canonical(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    canonical_into(value, &mut out);
    out
}

fn canonical_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        // serde_json's `Number` Display matches CPython for ints and the usual
        // float shapes; see the module-level interop note for the float caveat.
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => encode_string_ascii(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_into(v, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sort explicitly so the output is correct regardless of whether
            // serde_json's `preserve_order` feature is enabled.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_string_ascii(k, out);
                out.push(b':');
                canonical_into(map.get(*k).expect("key from this map"), out);
            }
            out.push(b'}');
        }
    }
}

/// Encode a string exactly like CPython `py_encode_basestring_ascii`.
fn encode_string_ascii(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            _ => {
                let c = ch as u32;
                if (0x20..=0x7e).contains(&c) {
                    out.push(c as u8);
                } else if c <= 0xFFFF {
                    push_u_escape(c, out);
                } else {
                    // Encode as a UTF-16 surrogate pair, like CPython.
                    let v = c - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    push_u_escape(hi, out);
                    push_u_escape(lo, out);
                }
            }
        }
    }
    out.push(b'"');
}

/// Append a single `\uXXXX` escape (lowercase hex) for a 16-bit code unit.
fn push_u_escape(code_unit: u32, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(b"\\u");
    out.push(HEX[((code_unit >> 12) & 0xF) as usize]);
    out.push(HEX[((code_unit >> 8) & 0xF) as usize]);
    out.push(HEX[((code_unit >> 4) & 0xF) as usize]);
    out.push(HEX[(code_unit & 0xF) as usize]);
}

// --- AAD + wrap key ----------------------------------------------------------

/// AEAD AAD = `b"pqroute1" || b"|" || canonical(route_hdr)`.
///
/// Binds the (plaintext) route header to the sealed inner so any rewrite of the
/// header is tamper-evident at open time.
fn build_aad(route_canonical: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ROUTE_SUITE.len() + 1 + route_canonical.len());
    aad.extend_from_slice(ROUTE_SUITE.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(route_canonical);
    aad
}

/// Derive the AES-256 wrap key from the hybrid shared secret + AAD.
///
/// `HKDF-SHA256(IKM = shared, salt = b"", info = INFO_WRAP || b"|" || aad, L = 32)`.
/// `salt = b""` reproduces pyca's `HKDF(salt=b"")` (an empty HMAC key, zero-padded
/// to the block size — identical PRK to a HashLen-zero salt per RFC 5869).
fn derive_wrap_key(shared: &[u8], aad: &[u8]) -> [u8; WRAP_KEY_LEN] {
    let mut info = Vec::with_capacity(INFO_WRAP.len() + 1 + aad.len());
    info.extend_from_slice(INFO_WRAP);
    info.push(b'|');
    info.extend_from_slice(aad);

    let hk = Hkdf::<Sha256>::new(Some(b""), shared);
    let mut okm = [0u8; WRAP_KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

// --- Seal / open -------------------------------------------------------------

/// Build a `pqroute1` envelope: a plaintext route header + a hybrid-sealed inner.
///
/// The inner metadata + content are sealed to `dest_hybrid_pub` so an intermediate
/// relay can forward (reading only the plaintext `route_hdr`) without learning the
/// final destination, flags, timestamps, or body.
///
/// # Arguments
/// * `inner_metadata` — sensitive metadata (final destination, flags, timestamps…)
///   sealed to the destination. Any JSON value.
/// * `content` — the message body bytes (also sealed).
/// * `dest_hybrid_pub` — the destination's [`kem::PUBLIC_KEY_LEN`]-byte hybrid
///   public key (prekey).
/// * `route_hdr` — the OUTER routing header: next-hop routing fields only, e.g.
///   `{"to_relay": "...", "v": 1}`. Stays plaintext (a relay reads it) but is
///   AEAD-bound, hence tamper-evident.
///
/// # Returns
/// `hdr_len(4) || route_hdr_json || ct(1120) || nonce(12) || aesgcm(inner)`.
///
/// # Errors
/// * [`PqRouteError::Format`] — `dest_hybrid_pub` is the wrong length.
/// * [`PqRouteError::Kem`] — the hybrid encapsulation failed.
///
/// > NOTE: the Python signature returns the blob directly; encapsulation can fail
/// > in Rust, so this returns a [`Result`]. The success bytes are identical.
pub fn seal_routed(
    inner_metadata: &Value,
    content: &[u8],
    dest_hybrid_pub: &[u8],
    route_hdr: &Value,
) -> Result<Vec<u8>, PqRouteError> {
    if dest_hybrid_pub.len() != HYBRID_PUBLIC_KEY_LEN {
        return Err(PqRouteError::Format(format!(
            "dest_hybrid_pub must be {HYBRID_PUBLIC_KEY_LEN} bytes, got {}",
            dest_hybrid_pub.len()
        )));
    }

    let route_bytes = canonical(route_hdr);
    let meta_bytes = canonical(inner_metadata);

    // inner = meta_len(4 BE) || meta_json || content
    let mut inner = Vec::with_capacity(LEN_PREFIX + meta_bytes.len() + content.len());
    inner.extend_from_slice(&(meta_bytes.len() as u32).to_be_bytes());
    inner.extend_from_slice(&meta_bytes);
    inner.extend_from_slice(content);

    let aad = build_aad(&route_bytes);

    let (ciphertext, shared) = kem::hybrid_encap(dest_hybrid_pub)?;
    let wrap_key = derive_wrap_key(&shared, &aad);

    let mut nonce_bytes = [0u8; WRAP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let sealed_inner = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| PqRouteError::Format("AES-256-GCM seal failed".into()))?;

    // blob = hdr_len(4 BE) || route_hdr || ct || nonce || sealed_inner
    let mut blob = Vec::with_capacity(
        LEN_PREFIX + route_bytes.len() + ciphertext.len() + WRAP_NONCE_LEN + sealed_inner.len(),
    );
    blob.extend_from_slice(&(route_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(&route_bytes);
    blob.extend_from_slice(&ciphertext);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&sealed_inner);
    Ok(blob)
}

/// Parse and return ONLY the outer routing header — **no decryption**.
///
/// An intermediate relay calls this to learn the next hop; the sealed inner
/// (metadata + content) stays opaque to it.
///
/// # Errors
/// [`PqRouteError::Format`] if the blob is too short or the header isn't valid JSON.
pub fn read_route_header(blob: &[u8]) -> Result<Value, PqRouteError> {
    let (route_bytes, _sealed) = split_outer(blob)?;
    parse_json(route_bytes).map_err(|e| PqRouteError::Format(format!("route header not valid JSON: {e}")))
}

/// Return a blob with the outer header replaced, the sealed inner untouched.
///
/// Models a relay rewriting the next-hop field. The new header is **not** re-bound
/// to the sealed inner, so [`open_routed`] at the destination rejects it (AEAD AAD
/// mismatch) — exactly the tamper-evidence property. Provided as a test/inspection
/// helper, not a production path.
///
/// # Errors
/// [`PqRouteError::Format`] if `blob` is malformed.
pub fn replace_route_header(blob: &[u8], new_route_hdr: &Value) -> Result<Vec<u8>, PqRouteError> {
    let (_route_bytes, sealed) = split_outer(blob)?;
    let route_bytes = canonical(new_route_hdr);
    let mut out = Vec::with_capacity(LEN_PREFIX + route_bytes.len() + sealed.len());
    out.extend_from_slice(&(route_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&route_bytes);
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Open a `pqroute1` envelope with the destination's hybrid private key.
///
/// The AAD is reconstructed from the route header actually present in `blob`, so a
/// rewritten header (or any tamper of the sealed inner) fails the AEAD open.
///
/// # Arguments
/// * `blob` — the envelope from [`seal_routed`].
/// * `dest_hybrid_priv` — the destination's [`kem::PRIVATE_KEY_LEN`]-byte hybrid
///   private key.
///
/// # Returns
/// `(route_hdr, inner_metadata, content)`.
///
/// # Errors
/// * [`PqRouteError::Format`] — malformed blob.
/// * [`PqRouteError::Open`] — the AEAD open failed (wrong key, tampered inner, or a
///   rewritten route header), or the decapsulation failed, or the decrypted inner
///   is malformed.
pub fn open_routed(
    blob: &[u8],
    dest_hybrid_priv: &[u8],
) -> Result<(Value, Value, Vec<u8>), PqRouteError> {
    let (route_bytes, sealed) = split_outer(blob)?;
    if sealed.len() < SEALED_MIN_LEN {
        return Err(PqRouteError::Format(format!(
            "sealed inner must be >= {SEALED_MIN_LEN} bytes, got {}",
            sealed.len()
        )));
    }
    let route_hdr = parse_json(route_bytes)
        .map_err(|e| PqRouteError::Format(format!("route header not valid JSON: {e}")))?;

    let ciphertext = &sealed[..HYBRID_CIPHERTEXT_LEN];
    let nonce = &sealed[HYBRID_CIPHERTEXT_LEN..HYBRID_CIPHERTEXT_LEN + WRAP_NONCE_LEN];
    let body = &sealed[HYBRID_CIPHERTEXT_LEN + WRAP_NONCE_LEN..];

    let aad = build_aad(route_bytes);

    // A failed decap at open time = the envelope can't be opened with this key
    // (wrong/invalid private key). Treat as an open failure, not a blob-format
    // error — matching the Python contract.
    let shared = kem::hybrid_decap(ciphertext, dest_hybrid_priv)
        .map_err(|e| PqRouteError::Open(format!("hybrid decapsulation failed: {e}")))?;
    let wrap_key = derive_wrap_key(&shared, &aad);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let inner = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .map_err(|_| {
            PqRouteError::Open(
                "pqroute1 open failed — wrong key, tampered inner, or a rewritten route \
                 header (the header is AEAD-bound)"
                    .into(),
            )
        })?;

    // inner = meta_len(4 BE) || meta_json || content
    if inner.len() < LEN_PREFIX {
        return Err(PqRouteError::Open("decrypted inner is truncated".into()));
    }
    let meta_len = u32::from_be_bytes([inner[0], inner[1], inner[2], inner[3]]) as usize;
    if LEN_PREFIX + meta_len > inner.len() {
        return Err(PqRouteError::Open(
            "decrypted inner metadata length is out of range".into(),
        ));
    }
    let meta_bytes = &inner[LEN_PREFIX..LEN_PREFIX + meta_len];
    let content = inner[LEN_PREFIX + meta_len..].to_vec();
    let inner_metadata = parse_json(meta_bytes)
        .map_err(|e| PqRouteError::Open(format!("inner metadata not valid JSON: {e}")))?;

    Ok((route_hdr, inner_metadata, content))
}

// --- Helpers -----------------------------------------------------------------

/// Split `hdr_len(4) || route_hdr || sealed_inner` -> `(route_bytes, sealed)`.
fn split_outer(blob: &[u8]) -> Result<(&[u8], &[u8]), PqRouteError> {
    if blob.len() < LEN_PREFIX {
        return Err(PqRouteError::Format(
            "blob too short for a route-header length prefix".into(),
        ));
    }
    let hdr_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let start = LEN_PREFIX;
    let end = start
        .checked_add(hdr_len)
        .ok_or_else(|| PqRouteError::Format("route header length overflow".into()))?;
    if end > blob.len() {
        return Err(PqRouteError::Format("route header length exceeds blob size".into()));
    }
    Ok((&blob[start..end], &blob[end..]))
}

/// Parse UTF-8 JSON bytes into a [`Value`].
fn parse_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(bytes)
}

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Canonical JSON is deterministic and key-order-independent.
    #[test]
    fn canonical_is_deterministic_and_sorted() {
        let a = json!({"v": 1, "to_relay": "relay-7"});
        let b = json!({"to_relay": "relay-7", "v": 1});
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(canonical(&a), canonical(&a));
    }

    /// PARITY: canonical encoding equals CPython
    /// `json.dumps(sort_keys=True, separators=(",", ":"))` for a routing header.
    #[test]
    fn parity_canonical_route_header() {
        let rh = json!({"to_relay": "relay-7", "v": 1});
        assert_eq!(canonical(&rh), b"{\"to_relay\":\"relay-7\",\"v\":1}");
        // Hex computed from the Python: json.dumps(...).encode().hex()
        assert_eq!(
            hex::encode(canonical(&rh)),
            "7b22746f5f72656c6179223a2272656c61792d37222c2276223a317d"
        );
    }

    /// PARITY: `ensure_ascii=True` escaping (non-ASCII -> `\uXXXX`), bool/null,
    /// sorted keys — byte-identical to CPython `json.dumps`.
    #[test]
    fn parity_canonical_ensure_ascii() {
        // Input holds a real `é` (U+00E9); ensure_ascii escapes it to the six
        // ASCII bytes `é`. Keys sorted, bool/null lowercase. The expected
        // bytes are given as hex (computed from CPython) so the `\uXXXX` escapes
        // are unambiguous in source. The decoded form is
        // `{"a":true,"n":null,"note":"café","z":2}`.
        let v = json!({"note": "café", "z": 2, "a": true, "n": null});
        assert_eq!(
            hex::encode(canonical(&v)),
            "7b2261223a747275652c226e223a6e756c6c2c226e6f7465223a226361665c7530306539222c227a223a327d"
        );
    }

    /// PARITY: surrogate-pair escaping for code points above U+FFFF.
    /// Input holds a real `😀` (U+1F600); ensure_ascii escapes it to the UTF-16
    /// surrogate pair `😀` (lowercase hex), i.e. `{"e":"😀"}`.
    #[test]
    fn parity_canonical_surrogate_pair() {
        let v = json!({"e": "😀"});
        assert_eq!(hex::encode(canonical(&v)), "7b2265223a225c75643833645c7564653030227d");
    }

    /// PARITY: the derived AES-256 wrap key matches pyca's HKDF for a fixed shared
    /// secret + route header. Verified against both a manual RFC-5869 HKDF and the
    /// `cryptography` library's `HKDF(salt=b"")`.
    #[test]
    fn parity_wrap_key_vector() {
        let shared: Vec<u8> = (0u8..32).collect();
        let route_canonical = canonical(&json!({"to_relay": "relay-7", "v": 1}));
        let aad = build_aad(&route_canonical);
        // aad parity check (b"pqroute1|" + canonical).
        assert_eq!(
            hex::encode(&aad),
            "7071726f757465317c7b22746f5f72656c6179223a2272656c61792d37222c2276223a317d"
        );
        let wk = derive_wrap_key(&shared, &aad);
        assert_eq!(
            hex::encode(wk),
            "e68bc1c04dff6a00ad3ee7cdd86da50da37427f6d58f762c650219ca2fed8192"
        );
    }

    /// Full seal -> open round-trip recovers the header, metadata, and content.
    #[test]
    fn seal_open_round_trip() {
        let kp = kem::hybrid_keypair();
        let route_hdr = json!({"to_relay": "relay-7", "v": 1});
        let inner_meta = json!({"dest": "bob@sk", "ts": 1750000000, "flags": ["a", "b"]});
        let content = b"the secret body bytes".as_slice();

        let blob = seal_routed(&inner_meta, content, &kp.public_key, &route_hdr).unwrap();

        // A relay can read the header without the private key.
        assert_eq!(read_route_header(&blob).unwrap(), route_hdr);

        let (got_hdr, got_meta, got_content) = open_routed(&blob, &kp.private_key).unwrap();
        assert_eq!(got_hdr, route_hdr);
        assert_eq!(got_meta, inner_meta);
        assert_eq!(got_content, content);
    }

    /// Empty content and empty metadata still round-trip.
    #[test]
    fn seal_open_empty_content() {
        let kp = kem::hybrid_keypair();
        let route_hdr = json!({"v": 1});
        let inner_meta = json!({});
        let blob = seal_routed(&inner_meta, &[], &kp.public_key, &route_hdr).unwrap();
        let (_, meta, content) = open_routed(&blob, &kp.private_key).unwrap();
        assert_eq!(meta, inner_meta);
        assert!(content.is_empty());
    }

    /// A rewritten (AAD-bound) route header makes the AEAD open fail.
    #[test]
    fn rewritten_header_is_rejected() {
        let kp = kem::hybrid_keypair();
        let route_hdr = json!({"to_relay": "relay-7", "v": 1});
        let inner_meta = json!({"dest": "bob@sk"});
        let blob = seal_routed(&inner_meta, b"body", &kp.public_key, &route_hdr).unwrap();

        let tampered = replace_route_header(&blob, &json!({"to_relay": "evil", "v": 1})).unwrap();
        // The relay still reads the (rewritten) header fine...
        assert_eq!(read_route_header(&tampered).unwrap(), json!({"to_relay": "evil", "v": 1}));
        // ...but the destination's open fails: the header is authenticated.
        match open_routed(&tampered, &kp.private_key) {
            Err(PqRouteError::Open(_)) => {}
            other => panic!("expected Open error, got {other:?}"),
        }
    }

    /// Flipping a byte of the sealed inner is rejected by the AEAD tag.
    #[test]
    fn tampered_inner_is_rejected() {
        let kp = kem::hybrid_keypair();
        let blob = seal_routed(&json!({"d": 1}), b"body", &kp.public_key, &json!({"v": 1})).unwrap();
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01; // flip a tag/body byte
        match open_routed(&bad, &kp.private_key) {
            Err(PqRouteError::Open(_)) => {}
            other => panic!("expected Open error, got {other:?}"),
        }
    }

    /// Opening with the wrong private key fails (does not return garbage).
    #[test]
    fn wrong_key_is_rejected() {
        let kp = kem::hybrid_keypair();
        let other = kem::hybrid_keypair();
        let blob = seal_routed(&json!({"d": 1}), b"body", &kp.public_key, &json!({"v": 1})).unwrap();
        match open_routed(&blob, &other.private_key) {
            Err(PqRouteError::Open(_)) => {}
            other => panic!("expected Open error, got {other:?}"),
        }
    }

    /// A wrong-length destination public key is a format error, not a panic.
    #[test]
    fn bad_pub_len_is_format_error() {
        let err = seal_routed(&json!({}), b"", &[0u8; 10], &json!({"v": 1})).unwrap_err();
        match err {
            PqRouteError::Format(_) => {}
            other => panic!("expected Format error, got {other:?}"),
        }
    }

    /// A truncated blob is a format error.
    #[test]
    fn truncated_blob_is_format_error() {
        assert!(matches!(
            read_route_header(&[0u8; 2]),
            Err(PqRouteError::Format(_))
        ));
        // hdr_len claims more than the blob holds.
        let mut b = Vec::new();
        b.extend_from_slice(&100u32.to_be_bytes());
        b.extend_from_slice(b"short");
        assert!(matches!(split_outer(&b), Err(PqRouteError::Format(_))));
    }

    /// A too-short sealed inner is rejected by `open_routed` length validation.
    #[test]
    fn short_sealed_inner_is_format_error() {
        let route = canonical(&json!({"v": 1}));
        let mut blob = Vec::new();
        blob.extend_from_slice(&(route.len() as u32).to_be_bytes());
        blob.extend_from_slice(&route);
        blob.extend_from_slice(&[0u8; 16]); // far below SEALED_MIN_LEN
        match open_routed(&blob, &[0u8; kem::PRIVATE_KEY_LEN]) {
            Err(PqRouteError::Format(_)) => {}
            other => panic!("expected Format error, got {other:?}"),
        }
    }
}
