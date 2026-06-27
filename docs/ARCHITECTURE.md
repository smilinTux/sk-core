# Architecture — sk_pqc

This document gives the **data-flow** view of `sk_pqc`, per the sk-standards
DATA_FLOW_STANDARD: it traces a concrete DM-sealing path **hop by hop**, naming the module,
the operation, and the **crypto posture** (what protects the bytes) at each step. For the
static module dependency graph see [../SOP.md](../SOP.md) §2; for module summaries see
[../README.md](../README.md).

---

## Layering

```mermaid
graph TD
    A["Application: skchat / skcomms client"]
    A --> DMS["dm_session — stateful DM driver (epochs, KAM, pqdr1: tokens)"]
    A --> GRP["group_ratchet — group key distribution"]
    A --> PQR["pqroute — routing envelope"]
    DMS --> RAT["ratchet — DM epoch key schedule"]
    RAT --> KEM["kem — hybrid X25519 + ML-KEM-768 (FIPS 203)"]
    GRP --> KEM
    PQR --> KEM
    PQDM["pqdm — one-shot hybrid seal"] --> KEM
    A --> PQDM
    SUI["suites — registry"] --> REP["report — honest self-report"]
    A --> REP
    A --> AQ["anon_queue — addressing + deniable auth"]
```

---

## Data-flow: sealing a DM frame (the `dm_session` → `ratchet` → `kem` path)

The marquee path. Alice seals a 1:1 DM body to Bob. The diagram shows where the bytes
flow, which module owns each hop, and the **crypto posture** (the box style) at that hop.

```mermaid
flowchart TD
    PT["plaintext DM body<br/>(in the clear, in Alice's process)"]:::plain

    subgraph dm_session["dm_session :: DmSession::seal"]
        EPOCH{"current epoch within<br/>bound? (≤50 msgs AND ≤7 days)"}:::logic
        REKEY["start NEW epoch<br/>ratchet::new_epoch_secret()<br/>32 random bytes (OsRng)"]:::secret
        IDX["allocate (epoch, index)"]:::logic
        MK["ratchet::derive_dm_message_key(secret, epoch, index)<br/>HKDF-SHA256(IKM=epoch_secret,<br/>salt=skchat/dm-epoch/‖epoch,<br/>info=skchat/dm-ratchet/msg/v1/‖index)"]:::kdf
        AAD["frame_aad = skchat/dm-frame/v1 | u64(epoch) u64(index)<br/>(binds the slot — anti-replay)"]:::aad
        BODY["AES-256-GCM(message_key).encrypt(nonce, body, AAD)<br/>→ nonce(12) ‖ ct ‖ tag(16)"]:::aead
    end

    subgraph kam["KAM piggyback (first 3 frames of the epoch only)"]
        WRAP["ratchet::wrap_dm_epoch_secret(bob_hybrid_pub, epoch_secret)"]:::secret
        ENCAP["kem::hybrid_encap(bob_pub)<br/>X25519 eph-static DH  ⊕  ML-KEM-768 encap (FIPS 203)<br/>ss = HKDF-SHA256(X25519_ss ‖ MLKEM_ss)"]:::hybrid
        WRAPK["wrap_key = HKDF-SHA256(ss, info=skchat/dm-ratchet/epoch-wrap/v1)"]:::kdf
        SEAL["AES-256-GCM(wrap_key).seal(epoch_secret)<br/>payload = ct(1120) ‖ nonce(12) ‖ wrapped(48)"]:::aead
    end

    FRAME["SealedDmFrame { epoch, index, nonce, body, kam? }"]:::frame
    TOKEN["to_token() → 'pqdr1:' ‖ length-prefixed fields (base64)<br/>(stored in ChatMessage.content)"]:::wire

    PT --> EPOCH
    EPOCH -- bound hit --> REKEY --> IDX
    EPOCH -- still valid --> IDX
    IDX --> MK --> BODY
    AAD --> BODY
    REKEY -. once/epoch .-> WRAP
    WRAP --> ENCAP --> WRAPK --> SEAL
    BODY --> FRAME
    SEAL -. rides 3 frames .-> FRAME
    FRAME --> TOKEN

    classDef plain fill:#fff3cd,stroke:#b8860b,color:#000
    classDef logic fill:#e2e3e5,stroke:#6c757d,color:#000
    classDef secret fill:#f8d7da,stroke:#c0392b,color:#000
    classDef kdf fill:#cfe2ff,stroke:#1f6feb,color:#000
    classDef aad fill:#d1c4e9,stroke:#6f42c1,color:#000
    classDef aead fill:#d4edda,stroke:#2ea043,color:#000
    classDef hybrid fill:#1f6feb,stroke:#0b3d91,color:#fff
    classDef frame fill:#ffe0b2,stroke:#e67e22,color:#000
    classDef wire fill:#212529,stroke:#000,color:#fff
```

### Crypto posture per hop

| Hop | Module | Operation | Posture / what protects it |
| --- | --- | --- | --- |
| plaintext | (app) | DM body in process memory | **none** — cleartext, endpoint-trusted only |
| epoch check | `dm_session` | bound = 50 msgs **OR** 7 days | control logic; drives FS/PCS by forcing rekey |
| new epoch secret | `ratchet` | `new_epoch_secret()` 32 B `OsRng` | **secret** — independent per epoch (PCS root) |
| message key | `ratchet` | HKDF-SHA256 keyed by epoch secret, domain-separated by `dm-epoch`/`dm-ratchet` labels + `(epoch,index)` | **KDF** — index-addressable, loss/reorder tolerant |
| frame AAD | `dm_session` | `skchat/dm-frame/v1 \| epoch index` | **AAD bind** — anti-replay, frame can't move slots |
| body seal | `dm_session` | AES-256-GCM(message_key) | **AEAD** — confidentiality + integrity (symmetric, quantum-acceptable) |
| KAM: hybrid encap | `kem` | X25519 ⊕ ML-KEM-768, `HKDF(X25519_ss ‖ MLKEM_ss)` | **hybrid PQ** — secure if **either** leg holds (FIPS 203 ML-KEM) |
| KAM: wrap key | `ratchet` | HKDF-SHA256 over KEM secret, `epoch-wrap` label | **KDF** — domain-separated from message keys |
| KAM: seal secret | `ratchet` | AES-256-GCM(wrap_key).seal(epoch_secret) | **AEAD** — the epoch secret is the only PQ-protected material; paid 3×/epoch, not per message |
| frame token | `dm_session` | `pqdr1:` length-prefixed base64 | **wire** — coexists with PGP `-----BEGIN` and one-shot `pqdm1:` in the same field |

**Posture summary.** The bulk body is sealed under a *symmetric* AES-256-GCM key (already
quantum-acceptable). The **only** asymmetric/PQ material on the wire is the per-epoch
secret, wrapped via the **hybrid** KEM and amortised across the epoch — so the recorded
transcript is HNDL-resistant (secure unless **both** X25519 and ML-KEM-768 break), while
the per-message cost stays symmetric.

---

## Data-flow: the one-shot seal (`pqdm`) and the downgrade-lock

The `pqdm::seal` path used for stateless DM/envelope bodies (`pqdm1:` token). Same hybrid
root, with the **negotiated suite bound into the AEAD AAD** as a downgrade-lock.

```mermaid
flowchart LR
    NS["negotiate_suite(local_hybrid, peer_hybrid)<br/>→ x25519-mlkem768 | x25519-pgp-wrap-v1"]:::logic
    EN["kem::hybrid_encap(recipient_pub)<br/>ss = HKDF(X25519_ss ‖ MLKEM_ss)"]:::hybrid
    AAD["downgrade_lock_aad(suite, sender, recipient)<br/>= canonical JSON (sorted, compact, ascii-escaped)"]:::aad
    WK["wrap_key = HKDF-SHA256(ss,<br/>info = skcomms/pqdm/wrap/v1 | AAD)"]:::kdf
    SEAL["AES-256-GCM(wrap_key).encrypt(nonce, body, AAD)<br/>sealed = ct(1120) ‖ nonce(12) ‖ body"]:::aead
    NS --> WK
    EN --> WK --> SEAL
    AAD --> WK
    AAD --> SEAL

    classDef logic fill:#e2e3e5,stroke:#6c757d,color:#000
    classDef hybrid fill:#1f6feb,stroke:#0b3d91,color:#fff
    classDef aad fill:#d1c4e9,stroke:#6f42c1,color:#000
    classDef kdf fill:#cfe2ff,stroke:#1f6feb,color:#000
    classDef aead fill:#d4edda,stroke:#2ea043,color:#000
```

Because the suite id is folded into both the wrap-key `info` **and** the AEAD AAD, a MITM
that strips the hybrid prekey to force `x25519-pgp-wrap-v1` changes the bytes the sender
seals under — the recipient's open fails or the recorded suite no longer reads hybrid. The
downgrade cannot be *silent*, and `report::conversation_surface_for` surfaces a `classical`
line rather than an invented hybrid one.

---

## The honesty surface (`suites` → `report`)

```mermaid
flowchart LR
    SID["suite_id on the wire<br/>(e.g. x25519-mlkem768)"]:::wire
    REG["suites::get_suite(id)<br/>(unknown ⇒ classical ⇒ never QR)"]:::logic
    RES["status · primitives · fips_refs · quantum_resistant"]:::logic
    NOTE["report builds honest note<br/>(hybrid = secure if EITHER leg holds; cites FIPS 203)"]:::aad
    GATE["is_honest_note() screen<br/>+ assert_honest() backstop<br/>(rejects quantum-proof / -safe / unbreakable)"]:::gate
    OUT["SurfaceReport / Report → JSON"]:::wire
    SID --> REG --> RES --> NOTE --> GATE --> OUT

    classDef wire fill:#212529,stroke:#000,color:#fff
    classDef logic fill:#e2e3e5,stroke:#6c757d,color:#000
    classDef aad fill:#d1c4e9,stroke:#6f42c1,color:#000
    classDef gate fill:#2ea043,stroke:#15682b,color:#fff
```

Status is resolved **only** from the registry; the report only *narrates* what the registry
says, and the honesty gate is mechanical — a classical or unknown suite can never be marked
quantum-resistant, and the forbidden marketing words can never reach a caller.

---

## Cross-language note

Every label, length, AAD byte, and canonical-JSON rule shown above is shared verbatim with
the Python (`sk-pqc-py`) and Dart (`sk_pqc`) implementations. A blob sealed by any one of
the three opens in the other two; deterministic constructions are pinned by parity test
vectors (see [../SOP.md](../SOP.md) §5).
