
//! chainproof_lib — SLSA supply-chain attestation verification engine

use serde::{Deserialize, Serialize};

// ─── SHA-256 inline (no external crypto crates required) ─────────────────────
// Full FIPS-compliant SHA-256 implementation.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let orig_bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&orig_bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh) =
            (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let tmp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e;
            e = d.wrapping_add(tmp1);
            d = c; c = b; b = a;
            a = tmp1.wrapping_add(tmp2);
        }
        h[0]=h[0].wrapping_add(a); h[1]=h[1].wrapping_add(b);
        h[2]=h[2].wrapping_add(c); h[3]=h[3].wrapping_add(d);
        h[4]=h[4].wrapping_add(e); h[5]=h[5].wrapping_add(f);
        h[6]=h[6].wrapping_add(g); h[7]=h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── Domain Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubjectDigest {
    pub name: String,
    #[serde(rename = "sha256")]
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<SubjectDigest>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum SlsaLevel {
    NotSlsa,
    Level1,
    Level2,
    Level3,
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlsaLevel::NotSlsa  => write!(f, "Not SLSA"),
            SlsaLevel::Level1   => write!(f, "SLSA Level 1"),
            SlsaLevel::Level2   => write!(f, "SLSA Level 2"),
            SlsaLevel::Level3   => write!(f, "SLSA Level 3"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationResult {
    pub subject_name: String,
    pub digest_match: bool,
    pub slsa_level: String,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum VerifyError {
    ParseError(serde_json::Error),
    PathTraversal,
    NoSubjects,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::ParseError(e) => write!(f, "JSON parse error: {}", e),
            VerifyError::PathTraversal => write!(f, "Path traversal detected in artifact path"),
            VerifyError::NoSubjects    => write!(f, "Statement contains no subjects"),
        }
    }
}

// ─── Core Logic ──────────────────────────────────────────────────────────────

pub fn parse_intoto_statement(json: &str) -> Result<InTotoStatement, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn determine_slsa_level(statement: &InTotoStatement) -> SlsaLevel {
    if !statement.predicate_type.contains("provenance") {
        return SlsaLevel::NotSlsa;
    }
    let pred = statement.predicate.to_string();
    let has_builder = pred.contains("builder");
    let has_materials = pred.contains("material") || pred.contains("materials");
    match (has_builder, has_materials) {
        (true, true)  => SlsaLevel::Level3,
        (true, false) => SlsaLevel::Level2,
        _             => SlsaLevel::Level1,
    }
}

pub fn verify_artifact(artifact_path: &str, statement_json: &str) -> Result<VerificationResult, VerifyError> {
    if artifact_path.contains("..") {
        return Err(VerifyError::PathTraversal);
    }
    let statement = parse_intoto_statement(statement_json)
        .map_err(VerifyError::ParseError)?;
    if statement.subject.is_empty() {
        return Err(VerifyError::NoSubjects);
    }
    let subject = &statement.subject[0];
    let mut warnings = Vec::new();

    // Try to read artifact from disk; if not found, note in warnings
    let digest_match = match std::fs::read(artifact_path) {
        Ok(data) => {
            let actual = sha256_hex(&data);
            actual == subject.sha256
        }
        Err(_) => {
            warnings.push(format!("Artifact '{}' not found on disk; digest unverified", artifact_path));
            false
        }
    };

    let level = determine_slsa_level(&statement);
    Ok(VerificationResult {
        subject_name: subject.name.clone(),
        digest_match,
        slsa_level: level.to_string(),
        warnings,
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_statement(predicate_type: &str, extra_pred: &str) -> String {
        format!(r#"{{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{{"name": "artifact.tar.gz", "sha256": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"}}],
            "predicateType": "{}",
            "predicate": {{{}}}
        }}"#, predicate_type, extra_pred)
    }

    #[test]
    fn test_sha256_hello() {
        // SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let hex = sha256_hex(b"hello");
        assert_eq!(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_sha256_output_length() {
        let hex = sha256_hex(b"any data here");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_parse_valid_statement() {
        let json = sample_statement("https://slsa.dev/provenance/v0.2", "");
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(stmt.subject.len(), 1);
        assert_eq!(stmt.subject[0].name, "artifact.tar.gz");
    }

    #[test]
    fn test_parse_invalid_json_fails() {
        let result = parse_intoto_statement("not valid json {{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_subject_digest_extracted() {
        let json = sample_statement("https://slsa.dev/provenance/v0.2", "");
        let stmt = parse_intoto_statement(&json).unwrap();
        assert!(!stmt.subject[0].sha256.is_empty());
    }

    #[test]
    fn test_slsa_level1_provenance_no_builder() {
        let json = sample_statement("https://slsa.dev/provenance/v0.2", r#""version": 1"#);
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::Level1);
    }

    #[test]
    fn test_slsa_level2_with_builder() {
        let json = sample_statement("https://slsa.dev/provenance/v0.2", r#""builder": {"id": "ci"}"#);
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::Level2);
    }

    #[test]
    fn test_slsa_level3_with_builder_and_materials() {
        let json = sample_statement("https://slsa.dev/provenance/v0.2",
            r#""builder": {"id": "ci"}, "materials": [{"uri": "git+https://github.com/x/y"}]"#);
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::Level3);
    }

    #[test]
    fn test_slsa_not_slsa_for_non_provenance() {
        let json = sample_statement("https://example.com/other-predicate", "");
        let stmt = parse_intoto_statement(&json).unwrap();
        assert_eq!(determine_slsa_level(&stmt), SlsaLevel::NotSlsa);
    }

    #[test]
    fn test_path_traversal_rejected() {
        let json = sample_statement("https://slsa.dev/provenance/v0.2", "");
        let result = verify_artifact("../etc/passwd", &json);
        assert!(matches!(result, Err(VerifyError::PathTraversal)));
    }

    #[test]
    fn test_missing_artifact_warns_not_panics() {
        let json = sample_statement("https://slsa.dev/provenance/v0.2", "");
        let result = verify_artifact("/nonexistent/artifact.tar.gz", &json).unwrap();
        assert!(!result.warnings.is_empty());
        assert!(!result.digest_match);
    }

    #[test]
    fn test_empty_subject_array_returns_error() {
        let json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {}
        }"#;
        let result = verify_artifact("/some/path", json);
        assert!(matches!(result, Err(VerifyError::NoSubjects)));
    }

    #[test]
    fn test_sha256_real_file_digest() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"supply chain test content").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        let expected = sha256_hex(b"supply chain test content");
        // Build statement with correct digest
        let json = format!(r#"{{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{{"name": "test", "sha256": "{}"}}],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {{}}
        }}"#, expected);
        let result = verify_artifact(&path, &json).unwrap();
        assert!(result.digest_match);
    }
}
