//! Runtime PQC self-report — the **honesty engine** (clean-room of the core of
//! `sksecurity/sksecurity/pqc_report.py`).
//!
//! Given a *negotiated* crypto suite and a DM *ratchet level*, this module builds
//! an honest per-surface report — `(surface, component, suite_id, note)` plus the
//! resolved status / quantum-resistance / FIPS references — that the runtime can
//! emit as JSON. The cardinal rules (sk-standards CRYPTOGRAPHY_STANDARD), enforced
//! mechanically here:
//!
//! 1. **Never** mark a classical suite quantum-resistant. The status comes
//!    *only* from the [`crate::suites`] registry; an unknown suite resolves to
//!    `classical` (and is therefore never quantum-resistant).
//! 2. **Never** emit a forbidden marketing word — `quantum-proof`,
//!    `quantum-safe`, or `unbreakable`. Every note is screened by
//!    [`is_honest_note`]; the builders are unit-tested to produce only honest
//!    notes, and [`SurfaceReport::assert_honest`] is a runtime backstop.
//! 3. A `hybrid-pq` leg is secure **iff EITHER** the X25519 **or** the
//!    ML-KEM-768 (**FIPS 203**) leg holds — a hybrid, not an absolute guarantee.
//! 4. A ratchet structure over a *classical* KEM is still HNDL-exposed: the note
//!    says so regardless of ratchet level — forward secrecy over a Shor-breakable
//!    KEM does not stop a harvest-now-decrypt-later adversary.
//!
//! The single source of truth for suite semantics is [`crate::suites`]; this
//! module only *narrates* what that registry says, honestly.

use crate::suites::{self, SuiteStatus};
use serde::Serialize;

/// Marketing words this report must NEVER emit. Screened case-insensitively.
///
/// These are absolute-guarantee claims no hybrid (or any) scheme can honestly
/// make. [`is_honest_note`] rejects any string containing one.
pub const FORBIDDEN_WORDS: &[&str] = &["quantum-proof", "quantum-safe", "unbreakable"];

/// Classical fallback suite for a DM / envelope conversation with no hybrid
/// prekey (matches Python `DEFAULT_CONVERSATION_SUITE`).
pub const DEFAULT_CONVERSATION_SUITE: &str = "x25519-pgp-wrap-v1";

/// The hybrid KEM suite id (FIPS 203 ML-KEM-768 ‖ X25519).
pub const HYBRID_KEM_SUITE: &str = "x25519-mlkem768";

/// Whether a note is honest: contains **none** of the [`FORBIDDEN_WORDS`].
///
/// Case-insensitive substring screen. Use this to gate any externally-visible
/// crypto claim — per the architecture doc, no quantum-resistance claim may be
/// made unless it maps to a (registry-backed, forbidden-word-free) line in this
/// report.
pub fn is_honest_note(note: &str) -> bool {
    let lower = note.to_ascii_lowercase();
    !FORBIDDEN_WORDS.iter().any(|w| lower.contains(w))
}

/// The DM forward-secrecy ratchet level the self-report can learn (RFC-0001 P4).
///
/// Determines *how much* forward secrecy a 1:1 session actually provides — which
/// is independent of (and never upgrades) the negotiated KEM's quantum status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetLevel {
    /// Today's stateless single-prekey hybrid seal. PQ protection lives at the
    /// *published prekey only*; no running ratchet → no forward secrecy beyond
    /// prekey rotation.
    L2Oneshot,
    /// The running per-epoch ratchet ([`crate::ratchet::DmRatchet`]): a per-epoch
    /// hybrid-KEM rekey giving forward secrecy (FS) **and** post-compromise
    /// security (PCS).
    L3Epoch,
}

impl RatchetLevel {
    /// The canonical wire string (`"L2-oneshot"` / `"L3-epoch"`).
    pub fn as_str(self) -> &'static str {
        match self {
            RatchetLevel::L2Oneshot => "L2-oneshot",
            RatchetLevel::L3Epoch => "L3-epoch",
        }
    }

    /// Parse a wire string; unknown values fall back to [`RatchetLevel::L2Oneshot`]
    /// (the honest, *lower*-assurance default — matches the Python guard).
    pub fn from_wire(s: &str) -> RatchetLevel {
        match s {
            "L3-epoch" => RatchetLevel::L3Epoch,
            _ => RatchetLevel::L2Oneshot,
        }
    }
}

/// One security surface's resolved, honest crypto posture.
///
/// Serialises (via serde) to the same key set as the Python `SurfaceReport`:
/// `surface`, `component`, `active_suite`, `status`, `quantum_resistant`,
/// `primitives`, `fips_refs`, `note`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceReport {
    /// e.g. `"dm"`, `"envelope-payload"`, `"group-key"`, `"at-rest"`.
    pub surface: String,
    /// Owning repo / module.
    pub component: String,
    /// The suite id actually in use for this surface.
    pub active_suite: String,
    /// Resolved status: `classical` / `symmetric` / `hybrid-pq` / `pq`.
    pub status: String,
    /// Whether the resolved suite is quantum-resistant. Derived from `status` via
    /// the registry — never asserted independently.
    pub quantum_resistant: bool,
    /// Ordered underlying primitives (from the registry, or `["unknown"]`).
    pub primitives: Vec<String>,
    /// FIPS / RFC references (from the registry, or empty).
    pub fips_refs: Vec<String>,
    /// Honest human-readable note (guaranteed forbidden-word-free by
    /// [`SurfaceReport::assert_honest`]).
    pub note: String,
}

impl SurfaceReport {
    /// Debug-time backstop: panics if `note` contains a [`FORBIDDEN_WORDS`] entry
    /// or if a classical suite is marked quantum-resistant. The builders already
    /// guarantee both invariants; this makes a regression loud in tests.
    pub fn assert_honest(&self) {
        assert!(
            is_honest_note(&self.note),
            "self-report note emitted a forbidden word: {:?}",
            self.note
        );
        if self.status == "classical" {
            assert!(
                !self.quantum_resistant,
                "classical surface marked quantum-resistant: {:?}",
                self.surface
            );
        }
    }
}

/// Resolve a suite id to `(status, primitives, fips_refs, quantum_resistant)`.
///
/// Reads the [`crate::suites`] registry. Unknown ids resolve as `classical` with
/// `primitives = ["unknown"]` and no FIPS refs (and therefore never
/// quantum-resistant) — the Python `_resolve_suite` honesty fallback.
struct Resolved {
    status: SuiteStatus,
    primitives: Vec<String>,
    fips_refs: Vec<String>,
    quantum_resistant: bool,
}

fn resolve_suite(suite_id: &str) -> Resolved {
    match suites::get_suite(suite_id) {
        Some(s) => Resolved {
            status: s.status,
            primitives: s.primitives.clone(),
            fips_refs: s.fips_refs.clone(),
            quantum_resistant: s.is_quantum_resistant(),
        },
        None => Resolved {
            status: SuiteStatus::Classical,
            primitives: vec!["unknown".to_string()],
            fips_refs: vec![],
            quantum_resistant: false,
        },
    }
}

/// Assemble a [`SurfaceReport`] from a surface tuple + resolved suite metadata.
fn surface_from(surface: &str, component: &str, suite_id: &str, note: String) -> SurfaceReport {
    let r = resolve_suite(suite_id);
    let report = SurfaceReport {
        surface: surface.to_string(),
        component: component.to_string(),
        active_suite: suite_id.to_string(),
        status: r.status.as_str().to_string(),
        quantum_resistant: r.quantum_resistant,
        primitives: r.primitives,
        fips_refs: r.fips_refs,
        note,
    };
    // Honesty backstop — the note builders never violate these, but make any
    // future regression fail loudly rather than ship an over-claim.
    report.assert_honest();
    report
}

/// `" with <peer>"` (leading space) or `""` for an empty peer — matches the
/// Python `who` interpolation exactly.
fn who(peer: &str) -> String {
    if peer.is_empty() {
        String::new()
    } else {
        format!(" with {peer}")
    }
}

/// Build the **per-DM** surface report, learning the RATCHET LEVEL (RFC-0001 P4).
///
/// Clean-room of `pqc_report.dm_ratchet_surface_for`. The honest report states
/// not just *which suite* the 1:1 conversation negotiated, but *how much forward
/// secrecy* the running session actually provides — and it never lets a ratchet
/// structure over a classical KEM read as post-quantum.
///
/// # Arguments
/// * `negotiated_suite` — the suite the conversation actually used
///   (`x25519-mlkem768` for hybrid, else the classical wrap). Empty → the
///   [`DEFAULT_CONVERSATION_SUITE`] classical fallback (so a silent downgrade
///   surfaces as a classical line, never an invented hybrid one).
/// * `ratchet_level` — [`RatchetLevel::L2Oneshot`] or [`RatchetLevel::L3Epoch`].
/// * `epoch` — current ratchet epoch (surfaced in the L3 note).
/// * `peer` — optional peer identifier for the note (`""` to omit).
///
/// # Honesty
/// * If the negotiated suite is **classical**, the note says HNDL-exposed
///   regardless of ratchet level (rule 4 above).
/// * If hybrid, the note states security holds while **EITHER** the X25519 or the
///   ML-KEM-768 (FIPS 203) leg holds — never "quantum-proof"/"-safe".
/// * The returned [`SurfaceReport::quantum_resistant`] comes from the registry,
///   so a classical suite can never be marked quantum-resistant.
pub fn dm_ratchet_surface_for(
    negotiated_suite: &str,
    ratchet_level: RatchetLevel,
    epoch: u64,
    peer: &str,
) -> SurfaceReport {
    let suite_id = if negotiated_suite.is_empty() {
        DEFAULT_CONVERSATION_SUITE
    } else {
        negotiated_suite
    };
    let resolved = resolve_suite(suite_id);
    let is_hybrid = resolved.quantum_resistant;
    let w = who(peer);
    let level = ratchet_level.as_str();

    let note = if !is_hybrid {
        // Classical KEM: a ratchet over it is still HNDL-exposed at BOTH levels.
        format!(
            "DM{w} on the CLASSICAL PGP key-wrap ({suite_id}) — HNDL-exposed: \
recorded ciphertext is retroactively decryptable. The {level} \
ratchet structure provides NO post-quantum confidentiality while the \
KEM is classical; negotiate the hybrid X25519+ML-KEM-768 (FIPS 203) \
suite to close the harvest-now-decrypt-later gap."
        )
    } else if ratchet_level == RatchetLevel::L3Epoch {
        format!(
            "DM{w} on the running epoch-ratchet, FS + PCS, hybrid \
X25519+ML-KEM-768 rekey per epoch (epoch {epoch}). Each epoch \
re-derives the chain from a fresh hybrid-KEM secret, so a compromised \
key neither decrypts past epochs (forward secrecy) nor future ones \
once healed (post-compromise security). Secure while EITHER the \
X25519 or the ML-KEM-768 (FIPS 203) leg holds."
        )
    } else {
        // L2-oneshot, hybrid.
        format!(
            "DM{w} sealed with a stateless one-shot hybrid seal — PQ at the \
published prekey only, no running ratchet. Forward secrecy is limited \
to prekey rotation (no per-message/per-epoch rekey, no \
post-compromise security). Secure while EITHER the X25519 or the \
ML-KEM-768 (FIPS 203) leg holds; upgrade to the L3 epoch-ratchet for \
FS + PCS."
        )
    };

    surface_from("dm", "skchat (DmRatchet)", suite_id, note)
}

/// The kind of confidentiality conversation a surface describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationKind {
    /// skchat 1:1 direct message (`"dm"` surface, `skchat (ChatCrypto)`).
    Dm,
    /// skcomms federated envelope payload (`"envelope-payload"` surface).
    Envelope,
}

/// Build a per-conversation DM / envelope surface report (clean-room of
/// `pqc_report.conversation_surface_for`).
///
/// Reflects a SPECIFIC conversation's actually-negotiated suite so a hybrid
/// conversation reports `x25519-mlkem768` [hybrid-pq] while a classical
/// (downgraded / classical-only-peer) conversation still reports classical — a
/// silent-downgrade attempt shows up here as a classical line, never a hybrid one.
///
/// # Arguments
/// * `negotiated_suite` — the suite the conversation actually used (empty →
///   [`DEFAULT_CONVERSATION_SUITE`]).
/// * `kind` — [`ConversationKind::Dm`] or [`ConversationKind::Envelope`].
/// * `peer` — optional peer identifier for the note (`""` to omit).
pub fn conversation_surface_for(
    negotiated_suite: &str,
    kind: ConversationKind,
    peer: &str,
) -> SurfaceReport {
    let suite_id = if negotiated_suite.is_empty() {
        DEFAULT_CONVERSATION_SUITE
    } else {
        negotiated_suite
    };
    let (surface, component) = match kind {
        ConversationKind::Envelope => ("envelope-payload", "skcomms (EnvelopeCrypto)"),
        ConversationKind::Dm => ("dm", "skchat (ChatCrypto)"),
    };
    let resolved = resolve_suite(suite_id);
    let w = who(peer);
    let upper = surface.to_ascii_uppercase();

    let note = if resolved.quantum_resistant {
        format!(
            "{upper} conversation{w} negotiated the hybrid KEM: the \
body symmetric key is wrapped via X25519+ML-KEM-768 (PQXDH-style \
signed prekey) and AES-256-GCM seals the body. Negotiated suite is \
bound into the AEAD AAD (downgrade-lock). HNDL-resistant."
        )
    } else {
        format!(
            "{upper} conversation{w} on the CLASSICAL PGP key-wrap \
(HNDL-exposed). Either the peer advertised no hybrid prekey or a \
downgrade occurred — recorded honestly. Hybrid engages only when \
both sides advertise a hybrid prekey."
        )
    };

    surface_from(surface, component, suite_id, note)
}

/// The honest top-level claim for a set of surfaces (clean-room of the
/// `build_report` honest-claim branch, scoped to the surfaces we build here).
///
/// * all quantum-resistant → an all-QR claim;
/// * any classical present → the explicit NOT-quantum-resistant-end-to-end claim;
/// * else (only symmetric) → the symmetric-only claim.
///
/// Never asserts global / end-to-end / unconditional post-quantum protection, and
/// never emits a [`FORBIDDEN_WORDS`] entry.
pub fn honest_claim(surfaces: &[SurfaceReport]) -> String {
    let total = surfaces.len();
    let qr = surfaces.iter().filter(|s| s.quantum_resistant).count();
    let any_classical = surfaces.iter().any(|s| s.status == "classical");
    if total > 0 && qr == total {
        "All owned surfaces are quantum-resistant.".to_string()
    } else if any_classical {
        "NOT quantum-resistant end-to-end. Asymmetric surfaces reported here are \
CLASSICAL (Shor-breakable) unless a hybrid X25519+ML-KEM-768 (FIPS 203) suite \
was negotiated. Symmetric/at-rest layers are quantum-acceptable. Do not claim \
hybrid/post-quantum protection where a surface reads classical."
            .to_string()
    } else {
        "Only symmetric surfaces present; no asymmetric PQ migration done.".to_string()
    }
}

/// A whole self-report: the resolved surfaces, summary counts, and the honest
/// top-level claim. Serialises to JSON via serde.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Constant report tag (`"pqc-self-report"`).
    pub report: &'static str,
    /// Per-surface resolved posture.
    pub surfaces: Vec<SurfaceReport>,
    /// Summary counts.
    pub summary: Summary,
    /// The honest top-level claim (forbidden-word-free).
    pub honest_claim: String,
}

/// Summary counts over a [`Report`]'s surfaces.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Total surfaces.
    pub total_surfaces: usize,
    /// How many are quantum-resistant.
    pub quantum_resistant: usize,
    /// How many resolved to `classical`.
    pub classical: usize,
    /// How many resolved to `symmetric`.
    pub symmetric: usize,
}

impl Report {
    /// Build a report from already-resolved surfaces (computes the summary +
    /// honest claim). Each surface is re-checked by
    /// [`SurfaceReport::assert_honest`].
    pub fn from_surfaces(surfaces: Vec<SurfaceReport>) -> Report {
        for s in &surfaces {
            s.assert_honest();
        }
        let total_surfaces = surfaces.len();
        let quantum_resistant = surfaces.iter().filter(|s| s.quantum_resistant).count();
        let classical = surfaces.iter().filter(|s| s.status == "classical").count();
        let symmetric = surfaces.iter().filter(|s| s.status == "symmetric").count();
        let claim = honest_claim(&surfaces);
        Report {
            report: "pqc-self-report",
            surfaces,
            summary: Summary {
                total_surfaces,
                quantum_resistant,
                classical,
                symmetric,
            },
            honest_claim: claim,
        }
    }

    /// Serialise to a pretty JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Report serialises to JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classical_suite_is_never_quantum_resistant() {
        // Both ratchet levels over the classical wrap MUST resolve classical.
        for level in [RatchetLevel::L2Oneshot, RatchetLevel::L3Epoch] {
            let s = dm_ratchet_surface_for("x25519-pgp-wrap-v1", level, 9, "bob");
            assert_eq!(s.status, "classical");
            assert!(!s.quantum_resistant, "classical must never be QR");
            assert!(s.note.contains("HNDL-exposed"));
            assert!(is_honest_note(&s.note));
        }
    }

    #[test]
    fn unknown_suite_resolves_classical_not_qr() {
        // An unrecognised / spoofed suite id must read classical (honesty).
        let s = dm_ratchet_surface_for("acme-unobtainium-9000", RatchetLevel::L3Epoch, 1, "");
        assert_eq!(s.status, "classical");
        assert!(!s.quantum_resistant);
        assert_eq!(s.primitives, vec!["unknown".to_string()]);
        assert!(s.fips_refs.is_empty());
    }

    #[test]
    fn empty_suite_falls_back_to_classical_default() {
        let s = dm_ratchet_surface_for("", RatchetLevel::L2Oneshot, 0, "");
        assert_eq!(s.active_suite, DEFAULT_CONVERSATION_SUITE);
        assert_eq!(s.status, "classical");
        assert!(!s.quantum_resistant);
    }

    #[test]
    fn hybrid_l3_is_quantum_resistant_and_cites_fips203() {
        let s = dm_ratchet_surface_for(HYBRID_KEM_SUITE, RatchetLevel::L3Epoch, 5, "bob");
        assert_eq!(s.status, "hybrid-pq");
        assert!(s.quantum_resistant);
        assert!(s.note.contains("FIPS 203"));
        assert!(s.note.contains("EITHER"));
        assert!(s.note.contains("epoch 5"));
        assert!(is_honest_note(&s.note));
    }

    #[test]
    fn hybrid_l2_oneshot_states_limited_fs() {
        let s = dm_ratchet_surface_for(HYBRID_KEM_SUITE, RatchetLevel::L2Oneshot, 0, "");
        assert_eq!(s.status, "hybrid-pq");
        assert!(s.quantum_resistant);
        assert!(s.note.contains("one-shot hybrid seal"));
        assert!(s.note.contains("EITHER"));
    }

    #[test]
    fn no_builder_ever_emits_a_forbidden_word() {
        // Exhaustively sweep the construction space the builders cover.
        let suites = [
            "x25519-mlkem768",
            "x25519-pgp-wrap-v1",
            "aes256-gcm-v1",
            "",
            "junk",
        ];
        for suite in suites {
            for level in [RatchetLevel::L2Oneshot, RatchetLevel::L3Epoch] {
                for peer in ["", "alice"] {
                    let dm = dm_ratchet_surface_for(suite, level, 3, peer);
                    assert!(is_honest_note(&dm.note), "dm note: {:?}", dm.note);
                }
            }
            for kind in [ConversationKind::Dm, ConversationKind::Envelope] {
                let c = conversation_surface_for(suite, kind, "carol");
                assert!(is_honest_note(&c.note), "conv note: {:?}", c.note);
            }
        }
    }

    #[test]
    fn is_honest_note_catches_each_forbidden_word() {
        assert!(!is_honest_note("this is quantum-proof"));
        assert!(!is_honest_note("Totally QUANTUM-SAFE!"));
        assert!(!is_honest_note("an unbreakable cipher"));
        assert!(is_honest_note(
            "hybrid: secure if EITHER leg holds (FIPS 203)"
        ));
    }

    #[test]
    fn conversation_envelope_vs_dm_components() {
        let dm = conversation_surface_for(HYBRID_KEM_SUITE, ConversationKind::Dm, "");
        assert_eq!(dm.surface, "dm");
        assert_eq!(dm.component, "skchat (ChatCrypto)");
        assert!(dm.note.starts_with("DM conversation"));
        let env = conversation_surface_for(HYBRID_KEM_SUITE, ConversationKind::Envelope, "");
        assert_eq!(env.surface, "envelope-payload");
        assert_eq!(env.component, "skcomms (EnvelopeCrypto)");
        assert!(env.note.starts_with("ENVELOPE-PAYLOAD conversation"));
    }

    #[test]
    fn report_summary_counts_and_serialises() {
        let surfaces = vec![
            dm_ratchet_surface_for(HYBRID_KEM_SUITE, RatchetLevel::L3Epoch, 1, ""),
            dm_ratchet_surface_for("x25519-pgp-wrap-v1", RatchetLevel::L2Oneshot, 0, ""),
        ];
        let rpt = Report::from_surfaces(surfaces);
        assert_eq!(rpt.summary.total_surfaces, 2);
        assert_eq!(rpt.summary.quantum_resistant, 1);
        assert_eq!(rpt.summary.classical, 1);
        assert!(rpt
            .honest_claim
            .contains("NOT quantum-resistant end-to-end"));
        assert!(is_honest_note(&rpt.honest_claim));
        // JSON round-trips with the expected keys.
        let v: serde_json::Value = serde_json::from_str(&rpt.to_json()).unwrap();
        assert_eq!(v["report"], "pqc-self-report");
        assert_eq!(v["summary"]["quantum_resistant"], 1);
        assert_eq!(v["surfaces"][0]["status"], "hybrid-pq");
        assert_eq!(v["surfaces"][0]["quantum_resistant"], true);
        assert_eq!(v["surfaces"][1]["quantum_resistant"], false);
    }

    /// Byte-for-byte parity with the Python `dm_ratchet_surface_for` note for a
    /// deterministic input: `("x25519-mlkem768", "L3-epoch", epoch=5, peer="bob")`.
    /// The literal below is exactly what the Python builds.
    #[test]
    fn parity_dm_l3_hybrid_note_vector() {
        let s = dm_ratchet_surface_for(HYBRID_KEM_SUITE, RatchetLevel::L3Epoch, 5, "bob");
        let expected = "DM with bob on the running epoch-ratchet, FS + PCS, hybrid \
X25519+ML-KEM-768 rekey per epoch (epoch 5). Each epoch \
re-derives the chain from a fresh hybrid-KEM secret, so a compromised \
key neither decrypts past epochs (forward secrecy) nor future ones \
once healed (post-compromise security). Secure while EITHER the \
X25519 or the ML-KEM-768 (FIPS 203) leg holds.";
        assert_eq!(s.note, expected);
        assert_eq!(s.surface, "dm");
        assert_eq!(s.component, "skchat (DmRatchet)");
        assert_eq!(s.active_suite, "x25519-mlkem768");
    }

    /// Byte-for-byte parity with the Python classical-KEM note for
    /// `("x25519-pgp-wrap-v1", "L2-oneshot", epoch=0, peer="")`.
    #[test]
    fn parity_dm_classical_note_vector() {
        let s = dm_ratchet_surface_for("x25519-pgp-wrap-v1", RatchetLevel::L2Oneshot, 0, "");
        let expected = "DM on the CLASSICAL PGP key-wrap (x25519-pgp-wrap-v1) — HNDL-exposed: \
recorded ciphertext is retroactively decryptable. The L2-oneshot \
ratchet structure provides NO post-quantum confidentiality while the \
KEM is classical; negotiate the hybrid X25519+ML-KEM-768 (FIPS 203) \
suite to close the harvest-now-decrypt-later gap.";
        assert_eq!(s.note, expected);
    }
}
