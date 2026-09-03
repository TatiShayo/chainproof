import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { ChainproofVerifier } from '../../src/verifier/index.js';
import { PRESET_POLICIES } from '../../src/policy/engine.js';

describe('ChainproofVerifier End-to-End Verification', () => {
  const artifactZip = path.resolve('billflow-release.zip');
  const sbomFile = path.resolve('sbom.json');
  const attestationFile = path.resolve('billflow-release.sbom.sigstore.json');
  const cveScanFile = path.resolve('cve-scan-utf8.txt');

  it('should verify real workspace artifacts against default policy', () => {
    if (fs.existsSync(artifactZip)) {
      const result = ChainproofVerifier.verify({
        artifactPath: artifactZip,
        sbomPath: fs.existsSync(sbomFile) ? sbomFile : undefined,
        attestationPath: fs.existsSync(attestationFile) ? attestationFile : undefined,
        cveScanPath: fs.existsSync(cveScanFile) ? cveScanFile : undefined,
        policy: {
          requireSbom: true,
          requireSignature: true,
          requireProvenance: false,
          maxAllowedCveSeverity: 'CRITICAL'
        }
      });

      expect(result.artifactSha256).toBeDefined();
      expect(result.artifactSha256).toHaveLength(64);
      expect(result.attestationVerified).toBe(true);
      expect(result.signatureVerified).toBe(true);
      expect(result.sbom).toBeDefined();
      expect(result.policyResult.passed).toBe(true);
      expect(result.verified).toBe(true);
    }
  });

  it('should verify artifact with SLSA Level 2 provenance and full policy', () => {
    if (fs.existsSync(artifactZip)) {
      const tempProvFile = path.resolve('temp-prov.json');
      const provStatement = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [
          {
            name: 'billflow-release.zip',
            digest: {
              sha256: '6f0473369b5e87f26076061c1588333a5b8013a51bb582dae53bb47df6309f52'
            }
          }
        ],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: {
          buildDefinition: {
            buildType: 'https://github.com/slsa-framework/slsa-github-generator/workflow/v1',
            resolvedDependencies: [
              {
                uri: 'git+https://github.com/baraka/billflow',
                digest: { sha1: 'e4d909c290d0fb1ca068ffaddf22cbd0adddef11' }
              }
            ]
          },
          runDetails: {
            builder: {
              id: 'https://github.com/slsa-framework/slsa-github-generator'
            }
          }
        }
      };

      fs.writeFileSync(tempProvFile, JSON.stringify(provStatement, null, 2), 'utf8');

      try {
        const result = ChainproofVerifier.verify({
          artifactPath: artifactZip,
          sbomPath: fs.existsSync(sbomFile) ? sbomFile : undefined,
          attestationPath: fs.existsSync(attestationFile) ? attestationFile : undefined,
          provenancePath: tempProvFile,
          cveScanPath: fs.existsSync(cveScanFile) ? cveScanFile : undefined,
          policy: {
            minSlsaLevel: 2,
            requireSbom: true,
            requireSignature: true,
            requireProvenance: true,
            maxAllowedCveSeverity: 'CRITICAL'
          }
        });

        expect(result.verified).toBe(true);
        expect(result.provenanceVerified).toBe(true);
        expect(result.slsaLevelAchieved).toBeGreaterThanOrEqual(2);
      } finally {
        if (fs.existsSync(tempProvFile)) {
          fs.unlinkSync(tempProvFile);
        }
      }
    }
  });

  it('should fail verification if artifact is tampered', () => {
    if (fs.existsSync(artifactZip)) {
      // Point attestation against a non-matching artifact or vice-versa
      const tempDummyArtifact = path.resolve('temp-dummy-artifact.zip');
      fs.writeFileSync(tempDummyArtifact, 'tampered-artifact-content-12345', 'utf8');

      try {
        const result = ChainproofVerifier.verify({
          artifactPath: tempDummyArtifact,
          attestationPath: fs.existsSync(attestationFile) ? attestationFile : undefined,
          policy: {
            requireSignature: true
          }
        });

        expect(result.verified).toBe(false);
        expect(result.attestationVerified).toBe(false);
        expect(result.errors.some(e => e.includes('mismatch'))).toBe(true);
      } finally {
        if (fs.existsSync(tempDummyArtifact)) {
          fs.unlinkSync(tempDummyArtifact);
        }
      }
    }
  });

  it('should handle non-existent artifact gracefully without crashing', () => {
    const result = ChainproofVerifier.verify({
      artifactPath: 'non-existent-artifact-file.zip'
    });

    expect(result.verified).toBe(false);
    expect(result.errors[0]).toContain('not found');
  });

  it('should prevent path traversal outside allowed directory', () => {
    const result = ChainproofVerifier.verify({
      artifactPath: '../../../../../../windows/system32/cmd.exe',
      baseDir: path.resolve('c:/Users/TATI/Desktop/DEV/chainproof')
    });

    expect(result.verified).toBe(false);
    expect(result.errors[0]).toContain('Path traversal violation');
  });
});
