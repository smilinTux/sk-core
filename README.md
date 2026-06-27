# sk_pqc

> ⚠️ **Experimental · pre-1.0 · NOT independently security-audited.** Clean-room reference implementation: tested + Python-parity-verified, but no third-party audit, fuzzing, or formal review. Binds vetted crates (RustCrypto `ml-kem`, `x25519-dalek`); the wiring is original. **Review before production use.**


**What it is:** `sk_pqc` is the **sovereign shared Rust post-quantum cryptography
(PQC) core** for the SK ecosystem — a small, audited-dependency, clean-room Rust crate
that implements the hybrid key agreement, message-sealing, ratchet, routing-envelope,
anonymous-addressing, crypto-suite-registry, and honest-self-report primitives that the
SK confidentiality surfaces are built on.

**What it's for:** giving native Rust (and, later via FFI, mobile/desktop) clients the
*same* post-quantum cryptography that the Python `skcomms` / `skchat` / `sksecurity`
daemons and the Dart `sk_pqc` library already speak — **byte-for-byte interoperable**, so
a Rust client and a Python client derive identical keys, seal blobs the other can open,
and negotiate the same suites. Same HKDF labels, same AAD bytes, same wire layouts.

If you are searching for: a Rust **hybrid X25519 + ML-KEM-768 KEM**, a **post-quantum DM
ratchet**, a **PQXDH-style message seal**, a **metadata-routing envelope**, a **group
key-distribution ratchet**, an **anonymous queue address codec**, a **crypto-suite
registry**, or an **honest PQC self-report** — interoperable with a Python reference
implementation — this is that crate.

It is a **hybrid** scheme: it stays confidential as long as **either** the classical
X25519 leg **or** the ML-KEM-768 leg holds. It is **not** "quantum-proof", "quantum-safe",
or "unbreakable" and makes no such claim. ML-KEM-768 is standardized as **FIPS 203**.

---

## The 9 modules

| Module | What it does | Python source (clean-room of) |
| --- | --- | --- |
| [`kem`](src/kem.rs) | Hybrid KEM combiner **`x25519-mlkem768`**: X25519 (`x25519-dalek`) composed with ML-KEM-768 (RustCrypto `ml-kem`, FIPS 203) via concat-then-KDF `HKDF-SHA256(X25519_ss ‖ MLKEM_ss)` → 32-byte shared secret. `hybrid_keypair` / `hybrid_encap` / `hybrid_decap`. | `skcomms/pqkem.py` |
| [`ratchet`](src/ratchet.rs) | 1:1 **DM epoch-ratchet key schedule**: deterministic, index-addressable per-message key derivation (`derive_dm_message_key`), epoch-secret hybrid wrap/unwrap, rekey bound (50 msgs **OR** 7 days), `DmRatchet` driver. | `skchat/dm_ratchet.py` |
| [`dm_session`](src/dm_session.rs) | Stateful **DM session driver** on top of `ratchet`: epoch lifecycle (auto-rekey), key-agreement-message (KAM) piggyback, per-epoch secret store, `pqdr1:` sealed-frame token codec, snapshot/restore. | `skchat/src/skchat/dm_session.py` |
| [`group_ratchet`](src/group_ratchet.rs) | **Group epoch-ratchet**: replaces a static group key with a per-epoch ratchet whose secret is hybrid-KEM-wrapped per member (`wrap_epoch_secret` / `unwrap_epoch_secret`), plus symmetric per-message key derivation (`EpochRatchet`). The HNDL fix for group chat. | `skchat/group_ratchet.py` |
| [`pqdm`](src/pqdm.rs) | Hybrid **PQ message sealing** (PQXDH-style wrap) for DM bodies + envelope payloads: `seal` / `open_sealed`, with the negotiated-suite **downgrade-lock AAD** (`downgrade_lock_aad`) and `negotiate_suite`. | `skcomms/src/skcomms/pqdm.py` |
| [`pqroute`](src/pqroute.rs) | The **`pqroute1` metadata-routing envelope**: plaintext outer route header (relay-readable, AAD-authenticated) + hybrid-sealed inner metadata+content (`seal_routed` / `open_routed` / `read_route_header` / `replace_route_header`). | `skcomms/pqroute.py` |
| [`anon_queue`](src/anon_queue.rs) | **Anonymous, no-identity addressing** foundation: independent recipient/sender opaque queue ids (`new_queue_pair`), the `aqid:` address codec (`encode_aqid` / `decode_aqid`), and a deniable HMAC authenticator (`auth_tag` / `verify_tag`). Addressing + deniable auth only — not a transport. | `skcomms/src/skcomms/anon_queue.py` |
| [`suites`](src/suites.rs) | The **crypto-suite registry** (crypto-agility seam): the single source of truth mapping each `suite_id` to its kind/status/primitives/FIPS refs and the one `is_quantum_resistant` predicate. Performs no cryptography. | `skcomms/src/skcomms/crypto_suites.py` |
| [`report`](src/report.rs) | The **honest PQC self-report** (honesty engine): builds per-surface `(surface, component, suite, status, note)` posture from the registry, screens every note against the forbidden marketing words, and never marks a classical suite quantum-resistant. | `sksecurity/sksecurity/pqc_report.py` |

---

## Wire layout (interop contract — fixed, MUST NOT change)

```text
hybrid public key = X25519_pub(32)      ‖ MLKEM768_ek(1184)  = 1216 B
hybrid secret key = X25519_seed(32)     ‖ MLKEM768_dk(2400)  = 2432 B
hybrid ciphertext = X25519_eph_pub(32)  ‖ MLKEM768_ct(1088)  = 1120 B
shared secret     = 32 B
```

HKDF combiner parameters (RFC 5869), `kem`:

```text
salt = b""                              (HashLen zero bytes ≡ empty, per RFC 5869)
info = b"sk_pqc/x25519-mlkem768/v1"
L    = 32
IKM  = X25519_ss ‖ MLKEM768_ss          (X25519 FIRST, then ML-KEM)
```

DM message-key parameters, `ratchet`:

```text
salt = b"skchat/dm-epoch/"             ‖ u64_be(epoch)
info = b"skchat/dm-ratchet/msg/v1/"    ‖ u64_be(index)
L    = 32, IKM = epoch_secret
```

Higher-layer HKDF/AEAD labels (all pinned to the Python):

```text
dm epoch-wrap   info = b"skchat/dm-ratchet/epoch-wrap/v1"   (ratchet)
group msg       salt = b"skchat/epoch/" ‖ u64_be(epoch);    info = b"skchat/group-ratchet/msg/v1/" ‖ u64_be(index)
group wrap      info = b"skchat/group-ratchet/epoch-wrap/v1" (group_ratchet)
pqdm wrap       info = b"skcomms/pqdm/wrap/v1" ‖ b"|" ‖ aad  (pqdm)
pqroute wrap    info = b"skcomms/pqroute/wrap/v1|" ‖ aad      (pqroute)
dm frame aad    b"skchat/dm-frame/v1" ‖ b"|" ‖ u64_be(epoch) ‖ u64_be(index)
sealed tokens   "pqdm1:" (one-shot seal) · "pqdr1:" (ratchet frame) · "aqid:" (queue addr)
```

---

## Cross-language interoperability

`sk_pqc` does not invent a protocol; it is a **third implementation** of an existing one.
Three independent codebases speak the same wire:

- **Python** — `skcomms` (`pqkem.py`, `pqdm.py`, `pqroute.py`, `anon_queue.py`,
  `crypto_suites.py`), `skchat` (`dm_ratchet.py`, `dm_session.py`, `group_ratchet.py`),
  and `sksecurity` (`pqc_report.py`) — the reference daemons.
- **Dart** — `sk_pqc`, the mobile/desktop client library.
- **Rust** — this crate, for native clients (and later FFI).

They interoperate because they share, **byte-for-byte**:

1. **The same KDF labels.** Every HKDF `salt`/`info` string above is a copied constant,
   not a re-derivation. A label change in one language is a wire break in all three.
2. **The same AAD bytes.** The downgrade-lock AAD (`pqdm`) and route-header AAD
   (`pqroute`) are **canonical JSON** matching CPython's
   `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` —
   sorted keys, compact separators, non-ASCII escaped as `\uXXXX`. Both sides reconstruct
   identical AAD bytes, so an AEAD sealed by one opens on the other.
3. **The same wire layouts.** The fixed field lengths and concatenation orders above
   (X25519 part **first**, then ML-KEM) are identical across implementations.
4. **The same suite ids and status strings.** `x25519-mlkem768`, `x25519-pgp-wrap-v1`,
   `hybrid-pq`, `classical`, `kem`/`sig`/`aead` travel on the wire unchanged.

This is **parity-tested**: deterministic constructions are pinned against
Python-computed vectors in each module's inline `#[cfg(test)]` tests (e.g.
`report::parity_dm_l3_hybrid_note_vector` hardcodes the exact byte string the Python
`dm_ratchet_surface_for` produces). Round-trip and tamper-reject tests guard the
non-deterministic paths.

---

## Usage sketch

```rust
use sk_pqc::{kem, pqdm, ratchet};

// 1. Hybrid KEM key agreement (X25519 + ML-KEM-768, FIPS 203 leg).
let bob = kem::hybrid_keypair();                       // 1216-byte pub, 2432-byte priv
let (ct, ss_sender)   = kem::hybrid_encap(&bob.public_key)?;   // 1120-byte ciphertext
let ss_recipient      = kem::hybrid_decap(&ct, &bob.private_key)?;
assert_eq!(ss_sender, ss_recipient);                   // 32-byte shared secret

// 2. Seal a DM body to Bob (PQXDH-style hybrid wrap + downgrade-lock AAD).
let suite  = pqdm::negotiate_suite(/*local_hybrid=*/true, /*peer_hybrid=*/true);
let sealed = pqdm::seal(&bob.public_key, b"hello", suite, "alice", "bob")?;
let opened = pqdm::open_sealed(&sealed, &bob.private_key, suite, "alice", "bob")?;
assert_eq!(opened, b"hello");

// 3. Derive an index-addressable per-message DM key from an epoch secret.
let epoch_secret = ratchet::new_epoch_secret();
let k = ratchet::derive_dm_message_key(&epoch_secret, /*epoch=*/0, /*index=*/0)?;
```

For the full stateful flows see [`dm_session::DmSession`](src/dm_session.rs)
(auto-rekeying 1:1 sessions with `pqdr1:` tokens), [`group_ratchet::EpochRatchet`](src/group_ratchet.rs)
(group key distribution), and [`pqroute::seal_routed`](src/pqroute.rs) (routing envelopes).

---

## Honest claims

This crate is a **hybrid** scheme: it remains confidential as long as **either** the
classical X25519 leg **or** the ML-KEM-768 leg is unbroken. It is **not** "quantum-proof",
"quantum-safe", or "unbreakable", and the [`report`](src/report.rs) module mechanically
**rejects** those three words from any externally-visible note.

- ML-KEM-768 is standardized as **FIPS 203**. The companion signature standard is
  **FIPS 204** (ML-DSA) — referenced but **not** implemented here.
- AES-256-GCM (used by the sealing layers) is symmetric, Grover-only, and already
  quantum-acceptable. The hard problem this crate addresses is **key distribution**.
- A ratchet structure over a *classical* KEM is still harvest-now-decrypt-later (HNDL)
  exposed; the self-report says so regardless of ratchet level.

We never hand-roll lattice, curve, AEAD, or MAC math: the ML-KEM leg is RustCrypto
`ml-kem`, X25519 is `x25519-dalek`, the AEAD is `aes-gcm`, MACs are `hmac`, hashing/KDF
are `sha2` + `hkdf`, and constant-time compares are `subtle`. Only the combiner *wiring*
and the wire/label layout are original. See [SECURITY.md](SECURITY.md).

---

## Status

`0.1.0` — foundation primitives. PyO3/FFI bindings are intentionally **not** included
here (a later coordination task). Clean-room implementation matching the Python reference;
parity tests pin the deterministic constructions against Python-computed vectors.

**License:** Apache-2.0.

---

## Related projects / See also

- **`sk-pqc-py`** — the Python reference (`skcomms` / `skchat` / `sksecurity` PQC
  modules) this crate is a clean-room port of; the source-of-truth wire definitions.
- **`sk_pqc`** — the Dart client library; the third interoperable implementation
  (mobile/desktop).
- **`skcomms`** — the multi-channel communication daemon (federated envelopes, routing,
  anonymous queues) that consumes these primitives in Python.
- **`skchat`** — the chat client/daemon (1:1 DM ratchet, group ratchet, sessions).
- **`sk-standards`** — the canonical cross-repo standards (CRYPTOGRAPHY_STANDARD,
  DATA_FLOW_STANDARD, DOC_SOP, VERSION_STANDARD) this crate's docs and honesty gates
  conform to.
- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Standard operating
  procedure: [SOP.md](SOP.md) · Threat model: [SECURITY.md](SECURITY.md).