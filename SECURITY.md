# Security policy — sk_pqc

`sk_pqc` is the sovereign shared Rust PQC core for the SK ecosystem. This document states
its threat model, its cryptographic provenance (what is reused vs. what is original), the
supported versions, and how to report a vulnerability.

---

## Honest claims (read first)

`sk_pqc` is a **hybrid** scheme. Its key-distribution surfaces stay confidential as long
as **either** the classical X25519 leg **or** the ML-KEM-768 leg is unbroken. It is
**not** "quantum-proof", "quantum-safe", or "unbreakable" and makes no such claim — those
three words are mechanically forbidden in any externally-visible note (`report::FORBIDDEN_WORDS`).

- ML-KEM-768 is standardized as **NIST FIPS 203**. The companion signature standard
  **FIPS 204** (ML-DSA) is referenced but **not** implemented in this crate.
- AES-256-GCM is symmetric, only Grover-relevant, and already quantum-acceptable; the hard
  problem this crate solves is **key distribution**, not bulk encryption.
- A ratchet over a *classical* KEM is still harvest-now-decrypt-later (HNDL) exposed. The
  self-report says so regardless of ratchet level.

---

## Cryptographic provenance — no hand-rolled crypto

The security of this crate **binds** vetted implementations. We never implement lattice,
elliptic-curve, AEAD, MAC, or hash math ourselves. Only the *combiner wiring*, the wire
layout, and the KDF labels are original SK code.

| Primitive | Crate (provenance) | Role |
| --- | --- | --- |
| ML-KEM-768 (FIPS 203) | RustCrypto `ml-kem` 0.2.1 | post-quantum KEM leg |
| X25519 | `x25519-dalek` 2 (dalek-cryptography) | classical KEM/DH leg |
| HKDF-SHA256 (RFC 5869) | `hkdf` 0.12 + `sha2` 0.10 (RustCrypto) | combiner + key schedule |
| AES-256-GCM | `aes-gcm` 0.10 (RustCrypto) | authenticated body sealing |
| HMAC-SHA256 | `hmac` 0.12 + `sha2` (RustCrypto) | deniable queue authenticator |
| Constant-time compare | `subtle` 2 (dalek-cryptography) | MAC/tag verification |
| CSPRNG | `rand` 0.8 `OsRng` | all key/nonce/id generation |

The crate contains no `unsafe` of its own and performs no I/O. Malformed input returns a
typed error (`KemError`, `RatchetError`, `PqDmError`, `PqRouteError`, `AnonQueueError`,
`GroupRatchetError`, `DmSessionError`) — never a panic, never an error oracle that
distinguishes "wrong key" from "tampered ciphertext".

---

## Threat model

**Assets.** Message/DM/group-chat plaintext; routing metadata; the unlinkability of queue
addresses; the integrity of the negotiated crypto suite.

**Primary adversary — Harvest-Now-Decrypt-Later (HNDL).** A network adversary that records
all ciphertext today and decrypts later with a cryptographically-relevant quantum computer
(CRQC). **Mitigation:** every confidentiality surface seals to the **hybrid** KEM; a
recorded transcript stays confidential unless **both** the X25519 **and** the ML-KEM-768
leg are broken. ML-KEM-768 (FIPS 203) defeats the quantum leg; X25519 defeats a flaw in
ML-KEM. This is the explicit design driver for `kem`, `pqdm`, `pqroute`, `group_ratchet`,
and the `ratchet`/`dm_session` epoch rekey.

**Active in-transit tamper.** Bit-flips, ciphertext substitution, AAD/header rewriting.
**Mitigation:** AES-256-GCM authenticates every sealed body; the `(epoch, index)` pair
(`ratchet`/`dm_session`) and the negotiated suite id (`pqdm`) and the plaintext route
header (`pqroute`) are bound into the AEAD AAD, so a moved frame, a stripped PQ option, or
a rewritten next-hop fails to open (`PqDmError::Open` / `PqRouteError::Open`). ML-KEM uses
implicit rejection: a tampered KEM ciphertext yields a pseudo-random secret that simply
fails the AEAD — not an error oracle.

**Silent downgrade (MITM strips the hybrid prekey).** **Mitigation:** the negotiated suite
id is bound into the `pqdm` downgrade-lock AAD (canonical JSON, identical bytes across
implementations). A peer that forces a classical downgrade changes the suite the sender
seals under, so the downgrade cannot be *silent*: the recipient's open fails or the
recorded suite no longer reads hybrid, and the `report` self-report surfaces a `classical`
line rather than an invented hybrid one.

**Honesty / over-claim risk (a first-class threat here).** A report that over-states the
crypto posture is itself a security failure. **Mitigation:** `report` resolves status
*only* from the `suites` registry (unknown ⇒ `classical` ⇒ never quantum-resistant),
screens every note against `FORBIDDEN_WORDS`, and `assert_honest` is a runtime backstop.

**Compromise of an epoch / member key.** **Mitigation:** independent per-epoch secrets give
post-compromise security (PCS) — a leaked epoch secret reveals only that epoch — and
rekey-on-membership-change gives forward secrecy (FS); a removed member cannot derive
future epoch keys (`group_ratchet`, `dm_session`).

### Out of scope / known limitations

- **Endpoint compromise.** If an endpoint is owned, plaintext and keys are exposed; no
  transport crypto helps.
- **Metadata at small anonymity sets.** `anon_queue` unlinkable ids reduce *relay-side*
  metadata leakage, but on a small sovereign network (e.g. 3 nodes) timing/volume
  correlation and candidate paucity can still deanonymize. It raises the bar for a passive
  relay; it is not an anonymity cloak.
- **Identity / authentication / PKI, key management, key rotation policy, and transport**
  are the consumers' responsibility, not this crate's.
- **Side channels** beyond the constant-time guarantees of the underlying RustCrypto/dalek
  crates and `subtle` are out of scope.
- **`anon_queue` deniable MAC** provides authenticity + deniability, **never**
  non-repudiation.

---

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ active (pre-1.0; the wire contract is stabilizing toward 1.0) |
| < 0.1 | ❌ |

Until 1.0, security fixes land on the latest 0.1.x. Wire-affecting changes are major bumps
per the SOP §7 / sk-standards VERSION_STANDARD and are parity-verified against the Python
and Dart implementations before release.

---

## Reporting a vulnerability

Report privately — **do not** open a public issue for a security report.

- Use GitHub **private vulnerability reporting** on `github.com/smilinTux/sk-pqc-rs`
  (Security ▸ Report a vulnerability), or
- Contact the smilinTux maintainers through the org's listed private security channel.

Please include: affected version/commit, the module and construction involved, a minimal
reproduction (ideally a failing test vector), and — if it is an interop/wire issue —
whether the Python (`sk-pqc-py`) or Dart (`sk_pqc`) implementation is also affected, since
a wire-level fix must be coordinated across all three. We aim to acknowledge within a few
business days and will coordinate disclosure timing with you.
