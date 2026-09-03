import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { sanitizePath, timingSafeEqual, validateDigest, computeSha256 } from '../../src/utils/security.js';
import { parseDSSEEnvelope, verifySubjectDigest } from '../../src/attestation/intoto.js';
import { detectTamperedSBOM } from '../../src/sbom/index.js';
import { UnifiedSBOM } from '../../src/types/index.js';

describe('Security Hardening & Attack Vectors', () => {
  describe('Path Traversal & Injection Defense', () => {
    const sandboxDir = path.resolve('c:/chainproof/sandbox');

    it('should reject standard dot-dot-slash directory traversal', () => {
      expect(() => sanitizePath('../../../etc/shadow', sandboxDir)).toThrow(/Path traversal violation/i);
    });

    it('should reject Windows backslash directory traversal', () => {
      expect(() => sanitizePath('..\\..\\..\\windows\\system32\\drivers', sandboxDir)).toThrow(/Path traversal violation/i);
    });

    it('should reject redundant slashes traversal', () => {
      expect(() => sanitizePath('..//..//..//secrets.env', sandboxDir)).toThrow(/Path traversal violation/i);
    });

    it('should reject mid-path directory breakouts', () => {
      expect(() => sanitizePath('valid_sub/../../../../target.key', sandboxDir)).toThrow(/Path traversal violation/i);
    });

    it('should reject null byte injection in paths', () => {
      expect(() => sanitizePath('safe.json\0../../target.key', sandboxDir)).toThrow(/null byte detected/i);
    });
  });

  describe('Timing Attack Resistance', () => {
    it('should compare byte-by-byte in constant time for equality', () => {
      const secret = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const exact = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const lastByteDiff = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856';
      const firstByteDiff = 'f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      expect(timingSafeEqual(secret, exact)).toBe(true);
      expect(timingSafeEqual(secret, lastByteDiff)).toBe(false);
      expect(timingSafeEqual(secret, firstByteDiff)).toBe(false);
    });

    it('should safely handle non-string or mismatched length parameters without timing leak', () => {
      expect(timingSafeEqual('short', 'longer-string')).toBe(false);
      expect(timingSafeEqual(null as any, 'string')).toBe(false);
      expect(timingSafeEqual('string', undefined as any)).toBe(false);
    });
  });

  describe('Attestation Forgery & Tamper Resistance', () => {
    it('should detect when payload subject hash is replaced with fraudulent digest', () => {
      const genuineDigest = computeSha256('genuine release zip artifact');
      const statement = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: 'release.zip', digest: { sha256: genuineDigest } }],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: { buildDefinition: { buildType: 'sample' } }
      };

      const attackerArtifactDigest = computeSha256('attacker modified malicious payload');
      const check = verifySubjectDigest(statement as any, 'release.zip', attackerArtifactDigest);

      expect(check.match).toBe(false);
      expect(check.error).toContain('Digest mismatch');
    });

    it('should detect corrupted or manipulated envelope payload base64', () => {
      const corruptedEnvelope = {
        payload: 'ThisIsNotValidBase64!!!===',
        payloadType: 'application/vnd.in-toto+json',
        signatures: []
      };

      expect(() => parseDSSEEnvelope(corruptedEnvelope)).toThrow();
    });
  });

  describe('Malicious Package Anomaly Detection', () => {
    it('should identify anomalous packages with corrupt cryptographic hashes', () => {
      const anomalousSBOM: UnifiedSBOM = {
        format: 'cyclonedx',
        specVersion: '1.5',
        components: [
          {
            name: 'injected-trojan',
            version: '1.0.0',
            hashes: {
              sha256: 'xyz123' // illegal short hash
            },
            licenses: ['MIT']
          }
        ],
        rawSha256: 'dummy'
      };

      const res = detectTamperedSBOM(anomalousSBOM);
      expect(res.tampered).toBe(true);
      expect(res.issues.some(i => i.includes('invalid SHA-256 hash length'))).toBe(true);
    });
  });
});
