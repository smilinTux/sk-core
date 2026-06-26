# sk_core

**What it is:** the foundation crate of the sovereign **shared Rust PQC core** — a small,
clean-room Rust library that implements the two cryptographic primitives the SK ecosystem's
confidentiality surfaces are built on.

**What it's for:** giving native (and, later via FFI, mobile/desktop) clients the *same*
post-quantum key agreement and direct-message key schedule that the Python
`skcomms`/`skchat` daemons already speak — byte-for-byte interoperable, so a Rust client
and a Python client derive identical keys.

It provides:

1. **Hybrid KEM combiner — `x25519-mlkem768`** (`kem` module). Classical **X25519**
   (`x25519-dalek`) composed with **ML-KEM-768** (RustCrypto `ml-kem`, **FIPS 203**) via
   **concatenate-then-KDF**: `HKDF-SHA256(X25519_ss ‖ MLKEM_ss)` → 32-byte shared secret.
   Same construction as TLS `X25519MLKEM768` and Signal PQXDH. The derived secret is secure
   **if *either* leg holds** — it is *not* "quantum-proof" and makes no such claim.

2. **DM epoch-ratchet key schedule** (`ratchet` module). `derive_dm_message_key(epoch_secret,
   epoch, index)` — the deterministic, index-addressable per-message key derivation used by
   SKChat's 1:1 DM ratchet, plus the `should_rekey` bound logic (50 messages **OR** 7 days).

## Wire layout (interop contract — fixed, MUST NOT change)

```
hybrid public key = X25519_pub(32)          ‖ MLKEM768_ek(1184)   = 1216 B
hybrid secret key = X25519_seed(32)         ‖ MLKEM768_dk(2400)   = 2432 B
hybrid ciphertext = X25519_eph_pub(32)      ‖ MLKEM768_ct(1088)   = 1120 B
shared secret     = 32 B
```

HKDF combiner parameters (RFC 5869):

```
salt = b""                              (HashLen zero bytes)
info = b"sk_pqc/x25519-mlkem768/v1"
L    = 32
IKM  = X25519_ss ‖ MLKEM768_ss          (X25519 FIRST, then ML-KEM)
```

DM message-key parameters:

```
salt = b"skchat/dm-epoch/"      ‖ u64_be(epoch)
info = b"skchat/dm-ratchet/msg/v1/" ‖ u64_be(index)
L    = 32, IKM = epoch_secret
```

## Honest claims

This crate is a **hybrid** scheme: it remains secure as long as **either** the classical
X25519 leg **or** the ML-KEM-768 leg is unbroken. It is **not** "quantum-proof",
"quantum-safe", or "unbreakable". ML-KEM-768 is standardized as **FIPS 203**; the companion
signature standard is **FIPS 204** (ML-DSA, not used here). AES-256-GCM (used by callers, not
this crate) is symmetric and Grover-only — already quantum-resistant; the hard problem this
crate addresses is **key distribution**.

We never hand-roll lattice or curve math: the ML-KEM leg is RustCrypto `ml-kem`, the X25519
leg is `x25519-dalek`, and the combiner is `hkdf` + `sha2`.

## Status

Foundation primitives only. PyO3/FFI bindings are intentionally **not** included here (a
later coordination task). Clean-room implementation matching `skcomms/pqkem.py` and
`skchat/dm_ratchet.py`; a parity test pins the DM key derivation against a Python-computed
vector.

License: Apache-2.0.
