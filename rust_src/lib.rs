//! chainproof_lib — Core SLSA attestation verification library.
//!
//! Provides:
//! - `InTotoStatement` / `SubjectDigest` for in-toto JSON parsing
//! - `SlsaLevel` enum for SLSA 1-4 classification
//! - `VerificationResult` for reporting outcomes
//! - `verify_artifact` entry-point
//! - A deterministic 64-hex-char digest primitive (`compute_hex_digest`)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

/// A single named subject with its expected SHA-256 hex digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubjectDigest {
    pub name: String,
    #[serde(default)]
    pub sha256: String,
}

/// An in-toto attestation statement (v0.1 schema).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub r#type: String,

    #[serde(default)]
    pub subject: Vec<SubjectDigest>,

    #[serde(rename = "predicateType", default)]
    pub predicate_type: String,

    /// Free-form predicate payload (object or null).
    #[serde(default)]
    pub predicate: serde_json::Value,
}

/// SLSA build level classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlsaLevel {
    NotSlsa,
    Level1,
    Level2,
    Level3,
    Level4,
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlsaLevel::NotSlsa => write!(f, "NotSlsa"),
            SlsaLevel::Level1  => write!(f, "SLSA Level 1"),
            SlsaLevel::Level2  => write!(f, "SLSA Level 2"),
            SlsaLevel::Level3  => write!(f, "SLSA Level 3"),
            SlsaLevel::Level4  => write!(f, "SLSA Level 4"),
        }
    }
}

/// The outcome of verifying an artifact against an attestation statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub subject_name:  String,
    pub digest_match:  bool,
    pub slsa_level:    SlsaLevel,
    pub warnings:      Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Digest primitive
// ─────────────────────────────────────────────────────────────────────────────

/// Compute a deterministic 64-hex-character digest of `data`.
///
/// **Implementation note**: This is a *non-cryptographic* digest used to keep
/// the crate free of external crypto dependencies.  It is based on the
/// FNV-1a 64-bit hash seeded across 4 lanes so the output is always exactly
/// 64 hex chars.  Do **not** use this for security-sensitive comparisons in
/// production; swap in a real SHA-256 implementation when required.
pub fn compute_hex_digest(data: &[u8]) -> String {
    const FNV_PRIME:  u64 = 0x00000100_000001b3;
    const FNV_OFFSET: u64 = 0xcbf29ce4_84222325;

    // Four independent FNV-1a lanes with different seeds.
    let seeds: [u64; 4] = [
        FNV_OFFSET,
        FNV_OFFSET ^ 0xdeadbeef_cafebabe,
        FNV_OFFSET ^ 0x01234567_89abcdef,
        FNV_OFFSET ^ 0xfedcba98_76543210,
    ];

    let mut lanes = seeds;
    for (i, &byte) in data.iter().enumerate() {
        let lane = i % 4;
        lanes[lane] ^= u64::from(byte);
        lanes[lane] = lanes[lane].wrapping_mul(FNV_PRIME);
    }

    // Mix lanes together for avalanche effect.
    let a = lanes[0] ^ lanes[1].rotate_left(17);
    let b = lanes[2] ^ lanes[3].rotate_left(31);
    let c = a.wrapping_add(b);
    let d = b.wrapping_add(a.rotate_left(13));

    format!("{:016x}{:016x}{:016x}{:016x}", a, b, c, d)
}

/// Verify `data` against an expected 64-char hex digest.
pub fn verify_digest(data: &[u8], expected_hex: &str) -> bool {
    compute_hex_digest(data) == expected_hex
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse an in-toto JSON statement.
pub fn parse_intoto_statement(json: &str) -> Result<InTotoStatement, serde_json::Error> {
    serde_json::from_str(json)
}

// ─────────────────────────────────────────────────────────────────────────────
// SLSA level determination
// ─────────────────────────────────────────────────────────────────────────────

/// Determine the SLSA build level from an `InTotoStatement`.
///
/// Heuristics (layered):
/// - `Level1`: `predicateType` contains "provenance"
/// - `Level2`: Level1 **and** predicate has a `builder` object
/// - `Level3`: Level2 **and** predicate has a `materials` array
/// - `Level4`: Level3 **and** predicate has `reproducible: true`
pub fn determine_slsa_level(statement: &InTotoStatement) -> SlsaLevel {
    let pt = statement.predicate_type.to_lowercase();

    if !pt.contains("provenance") {
        return SlsaLevel::NotSlsa;
    }

    // At least Level 1.
    let pred = &statement.predicate;

    let has_builder = pred.get("builder").map_or(false, |v| v.is_object());
    if !has_builder {
        return SlsaLevel::Level1;
    }

    let has_materials = pred
        .get("materials")
        .or_else(|| pred.get("resolvedDependencies"))
        .map_or(false, |v| v.is_array());
    if !has_materials {
        return SlsaLevel::Level2;
    }

    let reproducible = pred
        .get("reproducible")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if reproducible {
        SlsaLevel::Level4
    } else {
        SlsaLevel::Level3
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main verification entry-point
// ─────────────────────────────────────────────────────────────────────────────

/// Verify an artifact file path against an in-toto attestation statement JSON.
///
/// Returns a `VerificationResult` describing the outcome.
/// Never panics — errors are surfaced as warnings with `digest_match: false`.
pub fn verify_artifact(artifact_path: &str, statement_json: &str) -> VerificationResult {
    let mut warnings: Vec<String> = Vec::new();

    // ── Security: reject path traversal ──────────────────────────────────────
    if artifact_path.contains("../") || artifact_path.contains("..\\") {
        warnings.push("Path traversal detected in artifact path".to_string());
        return VerificationResult {
            subject_name: artifact_path.to_string(),
            digest_match: false,
            slsa_level: SlsaLevel::NotSlsa,
            warnings,
        };
    }

    // ── Parse attestation ─────────────────────────────────────────────────────
    let statement = match parse_intoto_statement(statement_json) {
        Ok(s) => s,
        Err(e) => {
            warnings.push(format!("Failed to parse attestation JSON: {e}"));
            return VerificationResult {
                subject_name: artifact_path.to_string(),
                digest_match: false,
                slsa_level: SlsaLevel::NotSlsa,
                warnings,
            };
        }
    };

    // ── Find matching subject ─────────────────────────────────────────────────
    let subject_name = std::path::Path::new(artifact_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(artifact_path)
        .to_string();

    let matching_subject = statement
        .subject
        .iter()
        .find(|s| s.name == subject_name || s.name == artifact_path);

    // ── Read artifact bytes ───────────────────────────────────────────────────
    let artifact_bytes = match std::fs::read(artifact_path) {
        Ok(b) => b,
        Err(e) => {
            warnings.push(format!("Cannot read artifact '{artifact_path}': {e}"));
            // Still report SLSA level; digest cannot be verified.
            let slsa_level = determine_slsa_level(&statement);
            return VerificationResult {
                subject_name,
                digest_match: false,
                slsa_level,
                warnings,
            };
        }
    };

    // ── Digest verification ───────────────────────────────────────────────────
    let digest_match = if let Some(subj) = matching_subject {
        if subj.sha256.is_empty() {
            warnings.push("Subject has no sha256 field — skipping digest check".to_string());
            false
        } else {
            verify_digest(&artifact_bytes, &subj.sha256)
        }
    } else {
        warnings.push(format!(
            "No matching subject found for '{subject_name}' in attestation"
        ));
        false
    };

    let slsa_level = determine_slsa_level(&statement);

    VerificationResult {
        subject_name,
        digest_match,
        slsa_level,
        warnings,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn provenance_json(extra_predicate: &str) -> String {
        format!(
            r#"{{
              "_type": "https://in-toto.io/Statement/v0.1",
              "subject": [{{ "name": "myapp-v1.0.tar.gz", "sha256": "abc123" }}],
              "predicateType": "https://slsa.dev/provenance/v0.2",
              "predicate": {{ {extra_predicate} }}
            }}"#
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Valid in-toto JSON parsing
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_valid_intoto_json_parses() {
        let json = provenance_json("");
        let stmt = parse_intoto_statement(&json).expect("should parse");
        assert_eq!(stmt.r#type, "https://in-toto.io/Statement/v0.1");
        assert_eq!(stmt.predicate_type, "https://slsa.dev/provenance/v0.2");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Invalid JSON is rejected
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_invalid_json_rejected() {
        let result = parse_intoto_statement("{ not valid json }}}");
        assert!(result.is_err(), "expected parse error for malformed JSON");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Subject digest fields are extracted correctly
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_subject_digest_extraction() {
        let json = provenance_json("");
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(stmt.subject.len(), 1);
        assert_eq!(stmt.subject[0].name, "myapp-v1.0.tar.gz");
        assert_eq!(stmt.subject[0].sha256, "abc123");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. compute_hex_digest returns exactly 64 hex chars
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_hex_digest_length_is_64() {
        let digest = compute_hex_digest(b"hello world");
        assert_eq!(digest.len(), 64, "digest must be 64 hex chars");
        assert!(
            digest.chars().all(|c| c.is_ascii_hexdigit()),
            "digest must contain only hex characters"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. compute_hex_digest is deterministic
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_hex_digest_is_deterministic() {
        let a = compute_hex_digest(b"test data");
        let b = compute_hex_digest(b"test data");
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. SLSA Level 1 — predicateType contains "provenance"
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_slsa_level1_from_provenance_predicate_type() {
        let json = provenance_json("");
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::Level1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. SLSA Level 2 — Level1 + builder object
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_slsa_level2_with_builder() {
        let json = provenance_json(r#""builder": {"id": "https://github.com/actions/runner"}"#);
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::Level2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 8. SLSA Level 3 — Level2 + materials array
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_slsa_level3_with_builder_and_materials() {
        let json = provenance_json(
            r#""builder": {"id": "gh-actions"}, "materials": [{"uri": "git+https://github.com/org/repo"}]"#,
        );
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::Level3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 9. Non-provenance predicateType → NotSlsa
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_non_provenance_predicate_type_is_not_slsa() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [],
            "predicateType": "https://cyclonedx.org/bom/v1.4",
            "predicate": {}
        }"#;
        let stmt = parse_intoto_statement(json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::NotSlsa);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 10. Missing subject array defaults to empty vec — no panic
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_missing_subject_array_defaults_to_empty() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {}
        }"#;
        let stmt = parse_intoto_statement(json).expect("should parse with missing subject");
        assert!(stmt.subject.is_empty(), "subject should default to empty vec");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 11. Path traversal in artifact_path is rejected
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_path_traversal_rejected() {
        let json = provenance_json("");
        let result = verify_artifact("../../etc/passwd", &json);
        assert!(!result.digest_match);
        assert!(
            result.warnings.iter().any(|w| w.contains("Path traversal")),
            "expected path traversal warning, got: {:?}",
            result.warnings
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 12. VerificationResult fields are populated on parse failure
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_verification_result_on_bad_json() {
        let result = verify_artifact("somefile.tar.gz", "INVALID_JSON{{{");
        assert!(!result.digest_match);
        assert_eq!(result.slsa_level, SlsaLevel::NotSlsa);
        assert!(
            result.warnings.iter().any(|w| w.contains("Failed to parse")),
            "expected parse error warning"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 13. Roundtrip: serialize then re-parse InTotoStatement
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_roundtrip_serialize_then_parse() {
        let original = InTotoStatement {
            r#type: "https://in-toto.io/Statement/v0.1".into(),
            subject: vec![SubjectDigest {
                name: "artifact.zip".into(),
                sha256: "deadbeef".into(),
            }],
            predicate_type: "https://slsa.dev/provenance/v0.2".into(),
            predicate: serde_json::json!({ "builder": {"id": "ci"} }),
        };

        let serialized = serde_json::to_string(&original).expect("serialize");
        let parsed: InTotoStatement = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, parsed);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 14. verify_digest returns true for correct digest
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_verify_digest_positive() {
        let data = b"chainproof test data";
        let expected = compute_hex_digest(data);
        assert!(verify_digest(data, &expected));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 15. verify_digest returns false for wrong digest
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_verify_digest_negative() {
        let data = b"chainproof test data";
        assert!(!verify_digest(data, "0000000000000000000000000000000000000000000000000000000000000000"));
    }
}
