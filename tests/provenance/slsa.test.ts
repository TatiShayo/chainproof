import { describe, it, expect } from 'vitest';
import {
  parseSLSAProvenance,
  evaluateSLSALevel,
  isHostedBuilder,
  isPinnedCommitSha,
  verifyBuilder,
  verifySourceRepo,
  SLSA_PREDICATE_V1,
  SLSA_PREDICATE_V02
} from '../../src/provenance/slsa.js';

describe('SLSA Provenance & Compliance Verification', () => {
  const validV1Provenance = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'app.tar.gz', digest: { sha256: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890' } }],
    predicateType: SLSA_PREDICATE_V1,
    predicate: {
      buildDefinition: {
        buildType: 'https://github.com/slsa-framework/slsa-github-generator/workflow/v1',
        externalParameters: {
          workflow: { path: '.github/workflows/build.yml', ref: 'refs/heads/main' }
        },
        resolvedDependencies: [
          {
            uri: 'git+https://github.com/myorg/myapp',
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

  const validV02Provenance = {
    _type: 'https://in-toto.io/Statement/v0.1',
    subject: [{ name: 'app.tar.gz', digest: { sha256: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890' } }],
    predicateType: SLSA_PREDICATE_V02,
    predicate: {
      builder: {
        id: 'https://cloudbuild.googleapis.com/GoogleHostedWorker'
      },
      buildType: 'https://cloudbuild.googleapis.com/v1',
      materials: [
        {
          uri: 'git+https://github.com/myorg/myapp',
          digest: { sha1: 'e4d909c290d0fb1ca068ffaddf22cbd0adddef11' }
        }
      ]
    }
  };

  describe('parseSLSAProvenance', () => {
    it('should parse SLSA v1.0 statement correctly', () => {
      const parsed = parseSLSAProvenance(validV1Provenance);
      expect(parsed.version).toBe('v1');
      expect(parsed.predicate.buildDefinition).toBeDefined();
    });

    it('should parse SLSA v0.2 statement correctly', () => {
      const parsed = parseSLSAProvenance(validV02Provenance);
      expect(parsed.version).toBe('v0.2');
      expect(parsed.predicate.builder.id).toBe('https://cloudbuild.googleapis.com/GoogleHostedWorker');
    });

    it('should reject invalid provenance payloads', () => {
      expect(() => parseSLSAProvenance({ random: 123 })).toThrow(/Unrecognized SLSA Provenance format/i);
    });
  });

  describe('isPinnedCommitSha', () => {
    it('should return true for valid 40-character SHA-1', () => {
      expect(isPinnedCommitSha('e4d909c290d0fb1ca068ffaddf22cbd0adddef11')).toBe(true);
    });

    it('should return true for valid 64-character SHA-256', () => {
      expect(isPinnedCommitSha('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe(true);
    });

    it('should return false for short hashes, branches, tags, or invalid strings', () => {
      expect(isPinnedCommitSha('main')).toBe(false);
      expect(isPinnedCommitSha('v1.0.0')).toBe(false);
      expect(isPinnedCommitSha('e4d909c')).toBe(false);
      expect(isPinnedCommitSha('')).toBe(false);
      expect(isPinnedCommitSha(undefined)).toBe(false);
    });
  });

  describe('isHostedBuilder', () => {
    it('should identify known hosted builders', () => {
      expect(isHostedBuilder('https://github.com/slsa-framework/slsa-github-generator')).toBe(true);
      expect(isHostedBuilder('https://cloudbuild.googleapis.com')).toBe(true);
      expect(isHostedBuilder('https://tekton.dev/chains')).toBe(true);
      expect(isHostedBuilder('https://gitlab.com/ci')).toBe(true);
    });

    it('should return false for unknown / local / developer builders', () => {
      expect(isHostedBuilder('file:///home/developer/build.sh')).toBe(false);
      expect(isHostedBuilder('http://localhost:8080')).toBe(false);
      expect(isHostedBuilder(undefined)).toBe(false);
    });
  });

  describe('evaluateSLSALevel', () => {
    it('should evaluate hardened SLSA v1 provenance to Level 3', () => {
      const evaluation = evaluateSLSALevel(validV1Provenance);
      expect(evaluation.level).toBe(3);
      expect(evaluation.meetsLevel1).toBe(true);
      expect(evaluation.meetsLevel2).toBe(true);
      expect(evaluation.meetsLevel3).toBe(true);
      expect(evaluation.builderId).toBe('https://github.com/slsa-framework/slsa-github-generator');
      expect(evaluation.sourceUri).toBe('git+https://github.com/myorg/myapp');
      expect(evaluation.commitSha).toBe('e4d909c290d0fb1ca068ffaddf22cbd0adddef11');
    });

    it('should evaluate SLSA v0.2 provenance with hosted builder to Level 2', () => {
      const evaluation = evaluateSLSALevel(validV02Provenance);
      expect(evaluation.level).toBe(2);
      expect(evaluation.meetsLevel1).toBe(true);
      expect(evaluation.meetsLevel2).toBe(true);
      expect(evaluation.meetsLevel3).toBe(false);
    });

    it('should drop to Level 1 if builder is not hosted', () => {
      const unhosted = JSON.parse(JSON.stringify(validV1Provenance));
      unhosted.predicate.runDetails.builder.id = 'https://my-local-machine.local/builder';
      const evaluation = evaluateSLSALevel(unhosted);
      expect(evaluation.level).toBe(1);
      expect(evaluation.meetsLevel1).toBe(true);
      expect(evaluation.meetsLevel2).toBe(false);
    });

    it('should drop to Level 1 if source dependency commit SHA is unpinned', () => {
      const unpinned = JSON.parse(JSON.stringify(validV1Provenance));
      unpinned.predicate.buildDefinition.resolvedDependencies[0].digest = { sha1: 'main' };
      const evaluation = evaluateSLSALevel(unpinned);
      expect(evaluation.level).toBe(1);
      expect(evaluation.meetsLevel2).toBe(false);
    });

    it('should return Level 0 on invalid or broken provenance', () => {
      const evaluation = evaluateSLSALevel({ broken: true });
      expect(evaluation.level).toBe(0);
      expect(evaluation.meetsLevel1).toBe(false);
    });
  });

  describe('verifyBuilder', () => {
    it('should allow wildcard builder list', () => {
      const res = verifyBuilder(validV1Provenance, ['*']);
      expect(res.allowed).toBe(true);
    });

    it('should allow exact and prefix builder matches', () => {
      const res = verifyBuilder(validV1Provenance, ['https://github.com/slsa-framework']);
      expect(res.allowed).toBe(true);
    });

    it('should allow regex pattern builder matches', () => {
      const res = verifyBuilder(validV1Provenance, ['/slsa-github-generator/']);
      expect(res.allowed).toBe(true);
    });

    it('should reject untrusted builders', () => {
      const res = verifyBuilder(validV1Provenance, ['https://trusted-enterprise.com/builder']);
      expect(res.allowed).toBe(false);
    });
  });

  describe('verifySourceRepo', () => {
    it('should match allowed source repository', () => {
      const res = verifySourceRepo(validV1Provenance, ['https://github.com/myorg/myapp']);
      expect(res.allowed).toBe(true);
      expect(res.commitSha).toBe('e4d909c290d0fb1ca068ffaddf22cbd0adddef11');
    });

    it('should reject unauthorized source repository', () => {
      const res = verifySourceRepo(validV1Provenance, ['https://github.com/another-org/otherapp']);
      expect(res.allowed).toBe(false);
    });
  });
});
