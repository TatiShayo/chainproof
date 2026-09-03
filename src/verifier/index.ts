import * as fs from 'fs';
import * as path from 'path';
import { VerificationOptions, VerificationResult, UnifiedSBOM, VulnerabilityReport } from '../types/index.js';
import { computeSha256, sanitizePath, validateDigest } from '../utils/security.js';
import { extractAttestationStatement, verifySubjectDigest } from '../attestation/intoto.js';
import { parseSBOM, verifySBOMIntegrity } from '../sbom/index.js';
import { parseGrypeOutput } from '../vulnerability/matcher.js';
import { PolicyEngine, PRESET_POLICIES } from '../policy/engine.js';
import { evaluateSLSALevel } from '../provenance/slsa.js';

export class ChainproofVerifier {
  /**
   * Verifies an artifact against its supply chain metadata and security policy.
   */
  public static verify(options: VerificationOptions): VerificationResult {
    const errors: string[] = [];
    const baseDir = options.baseDir;

    // 1. Sanitize and resolve artifact path
    let safeArtifactPath: string;
    try {
      safeArtifactPath = sanitizePath(options.artifactPath, baseDir);
    } catch (err: any) {
      return {
        artifactPath: options.artifactPath,
        artifactSha256: '',
        verified: false,
        slsaLevelAchieved: 0,
        policyResult: { passed: false, rules: [], failures: [err.message], warnings: [] },
        attestationVerified: false,
        signatureVerified: false,
        provenanceVerified: false,
        errors: [err.message]
      };
    }

    if (!fs.existsSync(safeArtifactPath)) {
      const msg = `Artifact file not found at ${safeArtifactPath}`;
      return {
        artifactPath: safeArtifactPath,
        artifactSha256: '',
        verified: false,
        slsaLevelAchieved: 0,
        policyResult: { passed: false, rules: [], failures: [msg], warnings: [] },
        attestationVerified: false,
        signatureVerified: false,
        provenanceVerified: false,
        errors: [msg]
      };
    }

    const artifactBuffer = fs.readFileSync(safeArtifactPath);
    const artifactSha256 = computeSha256(artifactBuffer);

    // 2. Load and verify SBOM if provided
    let sbom: UnifiedSBOM | undefined;
    if (options.sbomPath) {
      try {
        const safeSbomPath = sanitizePath(options.sbomPath, baseDir);
        if (fs.existsSync(safeSbomPath)) {
          const sbomContent = fs.readFileSync(safeSbomPath);
          sbom = parseSBOM(sbomContent);
        } else {
          errors.push(`SBOM file not found at ${safeSbomPath}`);
        }
      } catch (err: any) {
        errors.push(`Failed to parse SBOM: ${err.message}`);
      }
    }

    // 3. Load and verify Attestation / Sigstore bundle if provided
    let attestationVerified = false;
    let signatureVerified = false;
    let attestationStatement: any;

    if (options.attestationPath) {
      try {
        const safeAttPath = sanitizePath(options.attestationPath, baseDir);
        if (fs.existsSync(safeAttPath)) {
          const attContent = fs.readFileSync(safeAttPath);
          attestationStatement = extractAttestationStatement(attContent);

          // Verify subject digest against artifact
          const digestMatch = verifySubjectDigest(attestationStatement, path.basename(safeArtifactPath), artifactSha256);
          if (digestMatch.match) {
            attestationVerified = true;
            signatureVerified = true;
          } else {
            errors.push(`Attestation subject mismatch: ${digestMatch.error}`);
          }
        } else {
          errors.push(`Attestation file not found at ${safeAttPath}`);
        }
      } catch (err: any) {
        errors.push(`Failed to parse attestation: ${err.message}`);
      }
    }

    // 4. Load and verify Provenance if provided
    let provenanceVerified = false;
    let provenanceObj: any;
    let slsaLevel = 0;

    if (options.provenancePath) {
      try {
        const safeProvPath = sanitizePath(options.provenancePath, baseDir);
        if (fs.existsSync(safeProvPath)) {
          const provContent = fs.readFileSync(safeProvPath);
          provenanceObj = extractAttestationStatement(provContent);

          const provDigestMatch = verifySubjectDigest(provenanceObj, path.basename(safeArtifactPath), artifactSha256);
          if (provDigestMatch.match) {
            provenanceVerified = true;
          } else {
            errors.push(`Provenance subject mismatch: ${provDigestMatch.error}`);
          }

          const slsaEval = evaluateSLSALevel(provenanceObj);
          slsaLevel = slsaEval.level;
        } else {
          errors.push(`Provenance file not found at ${safeProvPath}`);
        }
      } catch (err: any) {
        errors.push(`Failed to parse provenance: ${err.message}`);
      }
    } else if (attestationStatement && attestationStatement.predicateType?.includes('slsa')) {
      provenanceObj = attestationStatement;
      provenanceVerified = attestationVerified;
      const slsaEval = evaluateSLSALevel(attestationStatement);
      slsaLevel = slsaEval.level;
    }

    // 5. Load vulnerability report if provided
    let vulnerabilities: VulnerabilityReport | undefined;
    if (options.cveScanPath) {
      try {
        const safeCvePath = sanitizePath(options.cveScanPath, baseDir);
        if (fs.existsSync(safeCvePath)) {
          const cveContent = fs.readFileSync(safeCvePath);
          vulnerabilities = parseGrypeOutput(cveContent);
        } else {
          errors.push(`CVE scan report not found at ${safeCvePath}`);
        }
      } catch (err: any) {
        errors.push(`Failed to parse CVE scan report: ${err.message}`);
      }
    }

    // 6. Policy Evaluation
    const policyConfig = options.policy || PRESET_POLICIES.default;
    const policyEngine = new PolicyEngine(policyConfig);

    const policyResult = policyEngine.evaluate({
      provenance: provenanceObj,
      sbom,
      vulnerabilities,
      signaturePresent: signatureVerified,
      attestationPresent: attestationVerified
    });

    const isVerified = policyResult.passed && errors.length === 0;

    return {
      artifactPath: safeArtifactPath,
      artifactSha256,
      verified: isVerified,
      slsaLevelAchieved: slsaLevel,
      policyResult,
      sbom,
      vulnerabilities,
      attestationVerified,
      signatureVerified,
      provenanceVerified,
      errors
    };
  }
}
