import { describe, it, expect } from 'vitest';
import * as path from 'path';
import {
  sanitizePath,
  computeSha256,
  computeSha1,
  computeSha512,
  timingSafeEqual,
  validateDigest,
  decodeBase64,
  encodeBase64
} from '../../src/utils/security.js';

describe('Security Utilities', () => {
  describe('sanitizePath', () => {
    it('should resolve normal valid paths', () => {
      const p = sanitizePath('fleet.config.json');
      expect(p).toBe(path.resolve('fleet.config.json'));
    });

    it('should reject null byte injection attempts', () => {
      expect(() => sanitizePath('release.zip\0.txt')).toThrow(/null byte detected/i);
    });

    it('should reject empty path input', () => {
      expect(() => sanitizePath('')).toThrow(/non-empty string/i);
    });

    it('should enforce allowedBaseDir boundary on relative traversal', () => {
      const baseDir = path.resolve('c:/safe/directory');
      expect(() => sanitizePath('../../../etc/passwd', baseDir)).toThrow(/Path traversal violation/i);
      expect(() => sanitizePath('..\\..\\windows\\system32', baseDir)).toThrow(/Path traversal violation/i);
    });

    it('should allow paths strictly inside allowedBaseDir', () => {
      const baseDir = path.resolve('c:/safe/directory');
      const safeSub = sanitizePath('subdir/file.json', baseDir);
      expect(safeSub).toBe(path.resolve(baseDir, 'subdir/file.json'));
    });
  });

  describe('Cryptographic Hash Utilities', () => {
    it('should correctly compute SHA-256 for known strings', () => {
      // sha256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      expect(computeSha256('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      // sha256 of "hello" is 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
      expect(computeSha256('hello')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });

    it('should correctly compute SHA-1 for known strings', () => {
      // sha1 of "hello" is aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
      expect(computeSha1('hello')).toBe('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
    });

    it('should correctly compute SHA-512 for known strings', () => {
      const sha = computeSha512('test');
      expect(sha).toHaveLength(128);
    });

    it('should support Buffer inputs for hashes', () => {
      const buf = Buffer.from('buffer data', 'utf8');
      expect(computeSha256(buf)).toBe(computeSha256('buffer data'));
    });
  });

  describe('timingSafeEqual & validateDigest', () => {
    it('should return true for identical strings', () => {
      expect(timingSafeEqual('abc123def456', 'abc123def456')).toBe(true);
    });

    it('should return false for different strings of same length', () => {
      expect(timingSafeEqual('abc123def456', 'abc123def457')).toBe(false);
    });

    it('should return false for different lengths without error', () => {
      expect(timingSafeEqual('abc', 'abcdef')).toBe(false);
    });

    it('should validate digests regardless of sha256: prefix or case', () => {
      const raw = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
      expect(validateDigest(raw, `sha256:${raw}`)).toBe(true);
      expect(validateDigest(`SHA256:${raw.toUpperCase()}`, raw)).toBe(true);
      expect(validateDigest(raw, '0000000000000000000000000000000000000000000000000000000000000000')).toBe(false);
    });
  });

  describe('Base64 Helpers', () => {
    it('should encode and decode standard UTF-8 strings', () => {
      const text = 'Hello, Chainproof supply chain security! 🛡️';
      const encoded = encodeBase64(text);
      expect(decodeBase64(encoded)).toBe(text);
    });

    it('should decode URL-safe base64 strings with - and _ and missing padding', () => {
      // "subjects?yes=1" base64 is "c3ViamVjdHM/eWVzPTE=" -> urlsafe "c3ViamVjdHM_eWVzPTE"
      const urlSafe = 'c3ViamVjdHM_eWVzPTE';
      expect(decodeBase64(urlSafe)).toBe('subjects?yes=1');
    });
  });
});
