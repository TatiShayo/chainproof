import { describe, it, expect } from 'vitest';
import { PolicyEngine, PRESET_POLICIES } from '../../src/policy/engine.js';
import { UnifiedSBOM, VulnerabilityReport } from '../../src/types/index.js';

describe('Policy Engine Rules & Compliance Profiles', () => {
  const sampleProvenance = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'release.zip', digest: { sha256: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890' } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://github.com/slsa-framework/slsa-github-generator/workflow/v1',
        externalParameters: { workflow: { path: '.github/workflows/supply-chain.yml', ref: 'refs/heads/main' } },
        resolvedDependencies: [
          {
            uri: 'git+https://github.com/org/billflow',
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

  const sampleSBOM: UnifiedSBOM = {
    format: 'cyclonedx',
    specVersion: '1.5',
    components: [
      {
        name: 'hono',
        version: '4.12.23',
        hashes: { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
        licenses: ['MIT']
      }
    ],
    rawSha256: 'dummy'
  };

  const sampleVulns: VulnerabilityReport = {
    sourceFormat: 'grype-table',
    items: [
      {
        name: 'hono',
        installedVersion: '4.12.23',
        vulnerabilityId: 'GHSA-wwfh-h76j-fc44',
        severity: 'MEDIUM'
      }
    ],
    summary: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 1,
      LOW: 0,
      NEGLIGIBLE: 0,
      UNKNOWN: 0
    }
  };

  describe('Default Preset Policy', () => {
    it('should pass on valid provenance, SBOM, and acceptable CVEs', () => {
      const engine = new PolicyEngine(PRESET_POLICIES.default);
      const res = engine.evaluate({
        provenance: sampleProvenance,
        sbom: sampleSBOM,
        vulnerabilities: sampleVulns,
        signaturePresent: true
      });

      expect(res.passed).toBe(true);
      expect(res.failures).toHaveLength(0);
    });

    it('should fail when provenance is missing if required', () => {
      const engine = new PolicyEngine(PRESET_POLICIES.default);
      const res = engine.evaluate({
        sbom: sampleSBOM
      });

      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('SLSA provenance is required'))).toBe(true);
    });

    it('should fail when SBOM is missing if required', () => {
      const engine = new PolicyEngine(PRESET_POLICIES.default);
      const res = engine.evaluate({
        provenance: sampleProvenance
      });

      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('SBOM'))).toBe(true);
    });
  });

  describe('Strict & SLSA-L3 Policies', () => {
    it('should enforce SLSA Level 3 requirements', () => {
      const engine = new PolicyEngine(PRESET_POLICIES['slsa-l3']);
      const res = engine.evaluate({
        provenance: sampleProvenance,
        sbom: sampleSBOM,
        signaturePresent: true
      });

      expect(res.passed).toBe(true);
    });

    it('should fail SLSA Level 3 when builder is unhardened', () => {
      const unhardened = JSON.parse(JSON.stringify(sampleProvenance));
      unhardened.predicate.runDetails.builder.id = 'https://cloudbuild.googleapis.com';
      const engine = new PolicyEngine(PRESET_POLICIES['slsa-l3']);
      const res = engine.evaluate({
        provenance: unhardened,
        sbom: sampleSBOM,
        signaturePresent: true
      });

      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('SLSA Level'))).toBe(true);
    });

    it('should fail when prohibited license is detected in SBOM', () => {
      const engine = new PolicyEngine({
        requireSbom: true,
        prohibitedLicenses: ['GPL-3.0', 'AGPL-3.0']
      });

      const gplSbom: UnifiedSBOM = {
        format: 'cyclonedx',
        specVersion: '1.5',
        components: [
          {
            name: 'gpl-dep',
            version: '1.0.0',
            hashes: {},
            licenses: ['GPL-3.0']
          }
        ],
        rawSha256: 'dummy'
      };

      const res = engine.evaluate({ sbom: gplSbom });
      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('prohibited licenses'))).toBe(true);
    });
  });

  describe('Builder & Source Repo Restrictions', () => {
    it('should pass when builder matches allowedBuilders list', () => {
      const engine = new PolicyEngine({
        minSlsaLevel: 1,
        allowedBuilders: ['https://github.com/slsa-framework']
      });

      const res = engine.evaluate({ provenance: sampleProvenance });
      expect(res.passed).toBe(true);
    });

    it('should fail when builder is outside allowedBuilders list', () => {
      const engine = new PolicyEngine({
        minSlsaLevel: 1,
        allowedBuilders: ['https://trusted-ci.example.com']
      });

      const res = engine.evaluate({ provenance: sampleProvenance });
      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('not in the allowed builders list'))).toBe(true);
    });

    it('should pass when source repository matches allowedSourceRepos', () => {
      const engine = new PolicyEngine({
        minSlsaLevel: 1,
        allowedSourceRepos: ['https://github.com/org/billflow']
      });

      const res = engine.evaluate({ provenance: sampleProvenance });
      expect(res.passed).toBe(true);
    });

    it('should fail when source repository is not in allowedSourceRepos', () => {
      const engine = new PolicyEngine({
        minSlsaLevel: 1,
        allowedSourceRepos: ['https://github.com/another-org/untrusted']
      });

      const res = engine.evaluate({ provenance: sampleProvenance });
      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('not in the allowed repositories list'))).toBe(true);
    });
  });

  describe('Allowed Licenses Policy Rule', () => {
    it('should pass when all component licenses are in allowedLicenses', () => {
      const engine = new PolicyEngine({
        requireSbom: true,
        allowedLicenses: ['MIT', 'APACHE-2.0', 'BSD-3-CLAUSE']
      });

      const res = engine.evaluate({ sbom: sampleSBOM });
      expect(res.passed).toBe(true);
      expect(res.rules.some(r => r.rule === 'allowed-licenses' && r.status === 'PASS')).toBe(true);
    });

    it('should fail when a component has an unapproved license', () => {
      const engine = new PolicyEngine({
        requireSbom: true,
        allowedLicenses: ['Apache-2.0']
      });

      const res = engine.evaluate({ sbom: sampleSBOM }); // sampleSBOM has MIT
      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('unapproved licenses'))).toBe(true);
    });
  });

  describe('Pinned Dependencies and Signature Policy Rules', () => {
    it('should pass requirePinnedDependencies when commit SHA is 40-char hex', () => {
      const engine = new PolicyEngine({
        requireProvenance: true,
        requirePinnedDependencies: true
      });

      const res = engine.evaluate({ provenance: sampleProvenance });
      expect(res.passed).toBe(true);
    });

    it('should fail requirePinnedDependencies when commit SHA is branch name', () => {
      const unpinned = JSON.parse(JSON.stringify(sampleProvenance));
      unpinned.predicate.buildDefinition.resolvedDependencies[0].digest = { sha1: 'main-branch' };

      const engine = new PolicyEngine({
        requireProvenance: true,
        requirePinnedDependencies: true
      });

      const res = engine.evaluate({ provenance: unpinned });
      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('not cryptographically pinned'))).toBe(true);
    });

    it('should fail requireSignature when signature is not present', () => {
      const engine = new PolicyEngine({
        requireSignature: true
      });

      const res = engine.evaluate({ signaturePresent: false, attestationPresent: false });
      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('Cryptographic signature is required'))).toBe(true);
    });

    it('should pass requireSignature only when a verified signature is present', () => {
      const engine = new PolicyEngine({
        requireSignature: true
      });

      // A parsed attestation is NOT a verified signature: a digest match
      // proves the statement describes the artifact, not that the signing
      // key approved it. Self-authored attestation JSON must not pass here.
      const attestationOnly = engine.evaluate({ attestationPresent: true });
      expect(attestationOnly.passed).toBe(false);
      expect(attestationOnly.failures.some(f => f.includes('Cryptographic signature is required'))).toBe(true);

      const verifiedSignature = engine.evaluate({ signaturePresent: true, attestationPresent: true });
      expect(verifiedSignature.passed).toBe(true);
    });
  });

  describe('CVE Severity Policy Thresholds', () => {
    it('should fail when CVE exceeds maxAllowedCveSeverity MEDIUM', () => {
      const highVulns: VulnerabilityReport = {
        sourceFormat: 'grype-table',
        items: [
          { name: 'lodash', installedVersion: '4.17.20', vulnerabilityId: 'CVE-2023-1', severity: 'HIGH' }
        ],
        summary: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, NEGLIGIBLE: 0, UNKNOWN: 0 }
      };

      const engine = new PolicyEngine({ maxAllowedCveSeverity: 'HIGH' });
      const res = engine.evaluate({ vulnerabilities: highVulns });
      expect(res.passed).toBe(false);
      expect(res.failures.some(f => f.includes('violating maximum allowed severity'))).toBe(true);
    });

    it('should pass when all CVEs are below maxAllowedCveSeverity', () => {
      const lowVulns: VulnerabilityReport = {
        sourceFormat: 'grype-table',
        items: [
          { name: 'lodash', installedVersion: '4.17.20', vulnerabilityId: 'CVE-2023-2', severity: 'LOW' }
        ],
        summary: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1, NEGLIGIBLE: 0, UNKNOWN: 0 }
      };

      const engine = new PolicyEngine({ maxAllowedCveSeverity: 'HIGH' });
      const res = engine.evaluate({ vulnerabilities: lowVulns });
      expect(res.passed).toBe(true);
    });
  });
});

