import { describe, it, expect } from 'vitest';
import { verifySBOMIntegrity, detectTamperedSBOM } from '../../src/sbom/index.js';
import { computeSha256 } from '../../src/utils/security.js';
import { UnifiedSBOM } from '../../src/types/index.js';

describe('SBOM Integrity & Tampering Detection', () => {
  const sampleCleanSBOM: UnifiedSBOM = {
    format: 'cyclonedx',
    specVersion: '1.5',
    documentName: 'clean-app',
    components: [
      {
        name: 'lodash',
        version: '4.17.21',
        purl: 'pkg:npm/lodash@4.17.21',
        type: 'library',
        hashes: {
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        },
        licenses: ['MIT']
      },
      {
        name: 'commander',
        version: '11.1.0',
        purl: 'pkg:npm/commander@11.1.0',
        type: 'library',
        hashes: {
          sha1: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
        },
        licenses: ['MIT']
      }
    ],
    rawSha256: 'dummy'
  };

  describe('verifySBOMIntegrity', () => {
    it('should return intact: true when calculated SHA-256 matches expected digest', () => {
      const raw = '{"bomFormat":"CycloneDX"}';
      const actualHash = computeSha256(raw);
      const res = verifySBOMIntegrity(raw, actualHash);
      expect(res.intact).toBe(true);
      expect(res.calculatedDigest).toBe(actualHash);
    });

    it('should support SHA-1 SBOM integrity verification', () => {
      const raw = '{"bomFormat":"CycloneDX","version":1}';
      const sha1 = '78c187d7b567d1db0cf5a73010b991bdf0d9f046';
      const res = verifySBOMIntegrity(raw, sha1, 'sha1');
      expect(res.calculatedDigest).toHaveLength(40);
    });

    it('should support SHA-512 SBOM integrity verification', () => {
      const raw = '{"bomFormat":"CycloneDX","version":1}';
      const res = verifySBOMIntegrity(raw, 'dummy', 'sha512');
      expect(res.calculatedDigest).toHaveLength(128);
    });

    it('should throw on unsupported hash algorithm', () => {
      expect(() => verifySBOMIntegrity('{}', 'abc', 'md5')).toThrow(/Unsupported hash algorithm/i);
    });

    it('should return intact: false on tampered raw content', () => {
      const original = '{"bomFormat":"CycloneDX"}';
      const originalHash = computeSha256(original);
      const tampered = '{"bomFormat":"CycloneDX","injected":true}';

      const res = verifySBOMIntegrity(tampered, originalHash);
      expect(res.intact).toBe(false);
      expect(res.calculatedDigest).not.toBe(originalHash);
    });
  });

  describe('detectTamperedSBOM', () => {
    it('should detect no issues on clean SBOM', () => {
      const res = detectTamperedSBOM(sampleCleanSBOM);
      expect(res.tampered).toBe(false);
      expect(res.issues).toHaveLength(0);
    });

    it('should flag empty components list', () => {
      const emptySbom: UnifiedSBOM = { ...sampleCleanSBOM, components: [] };
      const res = detectTamperedSBOM(emptySbom);
      expect(res.tampered).toBe(true);
      expect(res.issues[0]).toContain('zero components');
    });

    it('should flag missing or blank component names', () => {
      const tampered: UnifiedSBOM = {
        ...sampleCleanSBOM,
        components: [
          {
            name: '   ',
            version: '1.0.0',
            hashes: {},
            licenses: []
          }
        ]
      };
      const res = detectTamperedSBOM(tampered);
      expect(res.tampered).toBe(true);
      expect(res.issues.some(i => i.includes('empty or missing name'))).toBe(true);
    });

    it('should flag whitespace-only component version', () => {
      const tampered: UnifiedSBOM = {
        ...sampleCleanSBOM,
        components: [
          {
            name: 'pkg-a',
            version: '   ',
            hashes: {},
            licenses: []
          }
        ]
      };
      const res = detectTamperedSBOM(tampered);
      expect(res.tampered).toBe(true);
      expect(res.issues.some(i => i.includes('empty whitespace version'))).toBe(true);
    });

    it('should flag invalid PURL prefix', () => {
      const tampered: UnifiedSBOM = {
        ...sampleCleanSBOM,
        components: [
          {
            name: 'malicious-pkg',
            version: '1.0.0',
            purl: 'invalid:purl/malicious-pkg',
            hashes: {},
            licenses: []
          }
        ]
      };
      const res = detectTamperedSBOM(tampered);
      expect(res.tampered).toBe(true);
      expect(res.issues.some(i => i.includes('Invalid PURL format'))).toBe(true);
    });

    it('should flag corrupted SHA-256, SHA-1, and SHA-512 hash strings', () => {
      const tampered: UnifiedSBOM = {
        ...sampleCleanSBOM,
        components: [
          {
            name: 'corrupted-hash-pkg',
            version: '1.0.0',
            hashes: {
              sha256: 'tooshort',
              sha1: 'not-40-hex-characters',
              sha512: 'not-128-hex-characters'
            },
            licenses: []
          }
        ]
      };
      const res = detectTamperedSBOM(tampered);
      expect(res.tampered).toBe(true);
      expect(res.issues.some(i => i.includes('invalid SHA-256 hash length'))).toBe(true);
      expect(res.issues.some(i => i.includes('invalid SHA-1 hash length'))).toBe(true);
      expect(res.issues.some(i => i.includes('invalid SHA-512 hash length'))).toBe(true);
    });
  });
});

