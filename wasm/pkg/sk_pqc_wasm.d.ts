/* tslint:disable */
/* eslint-disable */

/**
 * The result of an encapsulation: ciphertext + the derived 32-byte shared secret.
 */
export class EncapResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * 1120-byte `X25519_eph_pub ‖ MLKEM768_ct`.
     */
    readonly ciphertext: Uint8Array;
    /**
     * 32-byte hybrid shared secret.
     */
    readonly shared_secret: Uint8Array;
}

/**
 * A freshly generated hybrid keypair (composite wire layout).
 */
export class HybridKeyPair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * 2432-byte `X25519_seed ‖ MLKEM768_dk`.
     */
    readonly private_key: Uint8Array;
    /**
     * 1216-byte `X25519_pub ‖ MLKEM768_ek`.
     */
    readonly public_key: Uint8Array;
}

/**
 * Derive the 32-byte AES-256 key for DM message `index` in `epoch` from a
 * 32-byte epoch secret (the DM epoch-ratchet message-key HKDF). `epoch`/`index`
 * arrive from JS as `BigInt`.
 */
export function derive_dm_message_key(epoch_secret: Uint8Array, epoch: bigint, index: bigint): Uint8Array;

/**
 * Decapsulate a 1120-byte hybrid ciphertext with the 2432-byte private key,
 * recovering the 32-byte shared secret. Throws only on a bad length (ML-KEM uses
 * implicit rejection: a tampered ciphertext yields a non-matching secret, not an error).
 */
export function hybrid_decap(ciphertext: Uint8Array, private_key: Uint8Array): Uint8Array;

/**
 * Encapsulate to a peer's 1216-byte hybrid public key. Returns ciphertext +
 * shared secret, or throws on a bad-length key.
 */
export function hybrid_encap(peer_public_key: Uint8Array): EncapResult;

/**
 * Generate a fresh hybrid keypair. Randomness comes from the browser's
 * `crypto.getRandomValues` (via `getrandom`'s `js` feature backing `OsRng`).
 */
export function hybrid_keypair(): HybridKeyPair;

/**
 * The hybrid suite identifier (`x25519-mlkem768`).
 */
export function suite_id(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_encapresult_free: (a: number, b: number) => void;
    readonly derive_dm_message_key: (a: number, b: number, c: bigint, d: bigint) => [number, number, number, number];
    readonly encapresult_ciphertext: (a: number) => [number, number];
    readonly encapresult_shared_secret: (a: number) => [number, number];
    readonly hybrid_decap: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly hybrid_encap: (a: number, b: number) => [number, number, number];
    readonly hybrid_keypair: () => number;
    readonly hybridkeypair_private_key: (a: number) => [number, number];
    readonly hybridkeypair_public_key: (a: number) => [number, number];
    readonly suite_id: () => [number, number];
    readonly __wbg_hybridkeypair_free: (a: number, b: number) => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
