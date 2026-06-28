//! Behavioural tests for `sk_pqc`. Run with `cargo test`.

use sk_pqc::kem::{
    hybrid_decap, hybrid_encap, hybrid_keypair, CIPHERTEXT_LEN, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN,
    SHARED_SECRET_LEN,
};
use sk_pqc::ratchet::{
    derive_dm_message_key, should_rekey, DEFAULT_REKEY_AGE_SECONDS, DEFAULT_REKEY_MSG_BOUND,
};

// ---------------------------------------------------------------------------
// Hybrid KEM
// ---------------------------------------------------------------------------

#[test]
fn kem_wire_lengths_match_python() {
    // Interop contract pinned by skcomms/pqkem.py.
    let kp = hybrid_keypair();
    assert_eq!(kp.public_key.len(), PUBLIC_KEY_LEN, "public key len");
    assert_eq!(kp.private_key.len(), PRIVATE_KEY_LEN, "private key len");
    assert_eq!(PUBLIC_KEY_LEN, 1216);
    assert_eq!(PRIVATE_KEY_LEN, 2432);
    assert_eq!(CIPHERTEXT_LEN, 1120);
}

#[test]
fn kem_encap_decap_roundtrip_equal_secrets() {
    let kp = hybrid_keypair();
    let (ct, ss_enc) = hybrid_encap(&kp.public_key).expect("encap");
    assert_eq!(ct.len(), CIPHERTEXT_LEN, "ciphertext len");
    assert_eq!(ss_enc.len(), SHARED_SECRET_LEN, "shared secret len");
    let ss_dec = hybrid_decap(&ct, &kp.private_key).expect("decap");
    assert_eq!(
        ss_enc, ss_dec,
        "encap and decap shared secrets must be equal"
    );
}

#[test]
fn kem_distinct_keypairs_distinct_secrets() {
    let a = hybrid_keypair();
    let b = hybrid_keypair();
    let (_ct_a, ss_a) = hybrid_encap(&a.public_key).expect("encap a");
    let (_ct_b, ss_b) = hybrid_encap(&b.public_key).expect("encap b");
    assert_ne!(
        ss_a, ss_b,
        "different recipients should yield different secrets"
    );
}

#[test]
fn kem_rejects_wrong_length_public_key() {
    let bad = vec![0u8; PUBLIC_KEY_LEN - 1];
    assert!(hybrid_encap(&bad).is_err(), "short public key must error");
}

#[test]
fn kem_rejects_wrong_length_ciphertext() {
    let kp = hybrid_keypair();
    let bad = vec![0u8; CIPHERTEXT_LEN - 1];
    assert!(
        hybrid_decap(&bad, &kp.private_key).is_err(),
        "short ciphertext must error"
    );
}

// ---------------------------------------------------------------------------
// DM ratchet key schedule
// ---------------------------------------------------------------------------

const ES: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

#[test]
fn ratchet_derive_is_deterministic() {
    let k1 = derive_dm_message_key(&ES, 7, 3).expect("derive");
    let k2 = derive_dm_message_key(&ES, 7, 3).expect("derive");
    assert_eq!(k1, k2, "same (epoch_secret, epoch, index) -> same key");
    assert_eq!(k1.len(), 32);
}

#[test]
fn ratchet_derive_index_distinct() {
    let k3 = derive_dm_message_key(&ES, 7, 3).expect("derive");
    let k4 = derive_dm_message_key(&ES, 7, 4).expect("derive");
    assert_ne!(k3, k4, "different index -> different key");
}

#[test]
fn ratchet_derive_epoch_distinct() {
    let a = derive_dm_message_key(&ES, 0, 0).expect("derive");
    let b = derive_dm_message_key(&ES, 1, 0).expect("derive");
    assert_ne!(a, b, "different epoch -> different key");
}

#[test]
fn ratchet_rejects_wrong_length_secret() {
    let bad = [0u8; 31];
    assert!(
        derive_dm_message_key(&bad, 0, 0).is_err(),
        "short epoch_secret must error"
    );
}

/// PARITY: hardcoded vectors computed by running the *real*
/// `skchat.dm_ratchet.derive_dm_message_key` (verified `match: True` against a
/// standalone HKDF reimplementation). epoch_secret = bytes(range(32)).
#[test]
fn ratchet_parity_with_python() {
    let cases: &[(u64, u64, &str)] = &[
        (
            7,
            3,
            "abca41b038c1565004c201741f896ae0c122fd8f6716ba4b85c850e5d163e6bc",
        ),
        (
            7,
            4,
            "ee18766d0fb4c31b03bb544a300232008fee43197d177d584bbed77ebd497834",
        ),
        (
            0,
            0,
            "976feb338842bce61bde060cc8559d66472e1c1c9edcfba3ae70cabb39e3f39a",
        ),
        (
            1,
            0,
            "5cf5ac603c0e9dd2165bf583930e5a2b5549e3b98fd1057de3fead1184610422",
        ),
    ];
    for (epoch, index, expected_hex) in cases {
        let got = derive_dm_message_key(&ES, *epoch, *index).expect("derive");
        assert_eq!(
            hex::encode(got),
            *expected_hex,
            "Rust derive must match Python for epoch={epoch} index={index}"
        );
    }
}

// ---------------------------------------------------------------------------
// should_rekey
// ---------------------------------------------------------------------------

#[test]
fn rekey_triggers_on_message_bound() {
    assert!(!should_rekey(
        DEFAULT_REKEY_MSG_BOUND - 1,
        0.0,
        0.0,
        DEFAULT_REKEY_MSG_BOUND,
        DEFAULT_REKEY_AGE_SECONDS
    ));
    assert!(should_rekey(
        DEFAULT_REKEY_MSG_BOUND,
        0.0,
        0.0,
        DEFAULT_REKEY_MSG_BOUND,
        DEFAULT_REKEY_AGE_SECONDS
    ));
    assert!(should_rekey(
        DEFAULT_REKEY_MSG_BOUND + 5,
        0.0,
        0.0,
        DEFAULT_REKEY_MSG_BOUND,
        DEFAULT_REKEY_AGE_SECONDS
    ));
}

#[test]
fn rekey_triggers_on_age_bound() {
    let age = DEFAULT_REKEY_AGE_SECONDS as f64;
    // Not enough messages, but epoch is old enough.
    assert!(!should_rekey(
        0,
        0.0,
        age - 1.0,
        DEFAULT_REKEY_MSG_BOUND,
        DEFAULT_REKEY_AGE_SECONDS
    ));
    assert!(should_rekey(
        0,
        0.0,
        age,
        DEFAULT_REKEY_MSG_BOUND,
        DEFAULT_REKEY_AGE_SECONDS
    ));
}
