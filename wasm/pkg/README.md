# sk-pqc-wasm — hybrid KEM in the browser

WASM bindings for the pure-Rust [`sk-pqc`](..) core, plus a standalone in-browser
demo that proves a **hybrid X25519 + ML-KEM-768** KEM round-trip entirely in
WebAssembly.

## What it exposes

| WASM export | Core function | What it does |
|---|---|---|
| `hybrid_keypair()` | `kem::hybrid_keypair` | fresh 1216-byte pub / 2432-byte priv |
| `hybrid_encap(pub)` | `kem::hybrid_encap` | 1120-byte ciphertext + 32-byte secret |
| `hybrid_decap(ct, priv)` | `kem::hybrid_decap` | recover the 32-byte secret |
| `derive_dm_message_key(es, epoch, index)` | `ratchet::derive_dm_message_key` | DM ratchet message key (HKDF) |
| `suite_id()` | `kem::SUITE_ID` | `"x25519-mlkem768"` |

Randomness on `wasm32-unknown-unknown` is backed by the browser's
`crypto.getRandomValues` (the `getrandom`/`js` feature behind `OsRng`).

## Build

```sh
# from this wasm/ dir, with the wasm32-unknown-unknown target installed:
wasm-pack build --release --target web --out-dir pkg
```

This emits `pkg/sk_pqc_wasm_bg.wasm` + `pkg/sk_pqc_wasm.js` (the JS glue) that
`index.html` imports.

## Run the demo

Serve over HTTP (ES-module imports need a real origin, not `file://`):

```sh
python3 -m http.server 8000
# open http://localhost:8000/
```

The page generates a keypair (Alice), encapsulates to it (Bob), decapsulates
(Alice), and asserts both sides derived the **same** 32-byte secret — plus a
wrong-key negative control and a DM-ratchet message-key derivation.

## Honest claim

This is a **hybrid** scheme: secure as long as **either** the classical X25519
leg **or** the ML-KEM-768 (FIPS 203) leg holds. It is **not** "quantum-proof",
"quantum-safe", or "unbreakable".
