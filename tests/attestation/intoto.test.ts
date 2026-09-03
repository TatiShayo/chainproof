import { describe, it, expect } from 'vitest';
import {
  parseInTotoStatement,
  parseDSSEEnvelope,
  verifySubjectDigest,
  extractAttestationStatement,
  isValidInTotoStatement,
  IN_TOTO_STATEMENT_V1,
  IN_TOTO_STATEMENT_V01
} from '../../src/attestation/intoto.js';
import { encodeBase64 } from '../../src/utils/security.js';

describe('In-toto Attestation Parsing & Verification', () => {
  const sampleStatement = {
    _type: IN_TOTO_STATEMENT_V1,
    subject: [
      {
        name: 'release.zip',
        digest: {
          sha256: '6f0473369b5e87f26076061c1588333a5b8013a51bb582dae53bb47df6309f52'
        }
      }
    ],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://github.com/slsa-framework/slsa-github-generator/workflow/v1'
      },
      runDetails: {
        builder: {
          id: 'https://github.com/slsa-framework/slsa-github-generator'
        }
      }
    }
  };

  it('should validate and parse a valid in-toto Statement v1', () => {
    expect(isValidInTotoStatement(sampleStatement)).toBe(true);
    const parsed = parseInTotoStatement(JSON.stringify(sampleStatement));
    expect(parsed._type).toBe(IN_TOTO_STATEMENT_V1);
    expect(parsed.subject[0].name).toBe('release.zip');
    expect(parsed.predicateType).toBe('https://slsa.dev/provenance/v1');
  });

  it('should validate and parse Statement v0.1', () => {
    const v01Stmt = { ...sampleStatement, _type: IN_TOTO_STATEMENT_V01 };
    expect(isValidInTotoStatement(v01Stmt)).toBe(true);
    const parsed = parseInTotoStatement(v01Stmt);
    expect(parsed._type).toBe(IN_TOTO_STATEMENT_V01);
  });

  it('should reject invalid statement formats', () => {
    expect(isValidInTotoStatement({})).toBe(false);
    expect(isValidInTotoStatement({ _type: 'invalid' })).toBe(false);
    expect(isValidInTotoStatement({ _type: IN_TOTO_STATEMENT_V1, subject: [] })).toBe(false);
    expect(isValidInTotoStatement({ _type: IN_TOTO_STATEMENT_V1, subject: [{ name: 'test' }] })).toBe(false);
    expect(isValidInTotoStatement({ _type: IN_TOTO_STATEMENT_V1, subject: [{ name: 'test', digest: {} }] })).toBe(false);
    expect(isValidInTotoStatement({ _type: IN_TOTO_STATEMENT_V1, subject: [{ name: '   ', digest: { sha256: 'abc' } }] })).toBe(false);
    expect(() => parseInTotoStatement('{}')).toThrow(/Invalid in-toto statement format/i);
  });

  it('should parse DSSE envelope and decode base64 in-toto statement', () => {
    const payloadBase64 = encodeBase64(JSON.stringify(sampleStatement));
    const dsse = {
      payload: payloadBase64,
      payloadType: 'application/vnd.in-toto+json',
      signatures: [{ keyid: 'key1', sig: 'MEQCIA123' }]
    };

    const { envelope, statement } = parseDSSEEnvelope(dsse);
    expect(envelope.payloadType).toBe('application/vnd.in-toto+json');
    expect(envelope.signatures).toHaveLength(1);
    expect(statement.subject[0].name).toBe('release.zip');
  });

  it('should extract in-toto statement from nested Sigstore bundle structure', () => {
    const payloadBase64 = encodeBase64(JSON.stringify(sampleStatement));
    const bundle = {
      mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
      dsseEnvelope: {
        payload: payloadBase64,
        payloadType: 'application/vnd.in-toto+json',
        signatures: [{ sig: 'MEYCIQ...' }]
      }
    };

    const extracted = extractAttestationStatement(bundle);
    expect(extracted.subject[0].name).toBe('release.zip');
    expect(extracted.predicateType).toBe('https://slsa.dev/provenance/v1');
  });

  it('should extract in-toto statement from JSONL line format', () => {
    const jsonl = `\n${JSON.stringify(sampleStatement)}\n`;
    const extracted = extractAttestationStatement(jsonl);
    expect(extracted.subject[0].name).toBe('release.zip');
  });

  describe('verifySubjectDigest', () => {
    it('should verify matching artifact digest', () => {
      const match = verifySubjectDigest(
        sampleStatement,
        'release.zip',
        '6f0473369b5e87f26076061c1588333a5b8013a51bb582dae53bb47df6309f52'
      );
      expect(match.match).toBe(true);
      expect(match.subjectName).toBe('release.zip');
    });

    it('should verify matching artifact with sha256: prefix in digest', () => {
      const match = verifySubjectDigest(
        sampleStatement,
        'release.zip',
        'sha256:6f0473369b5e87f26076061c1588333a5b8013a51bb582dae53bb47df6309f52'
      );
      expect(match.match).toBe(true);
    });

    it('should verify subject with SHA-1 digest', () => {
      const sha1Stmt = {
        ...sampleStatement,
        subject: [{ name: 'bundle.tar', digest: { sha1: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' } }]
      };
      const match = verifySubjectDigest(sha1Stmt as any, 'bundle.tar', 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'sha1');
      expect(match.match).toBe(true);
    });

    it('should verify subject with SHA-512 digest', () => {
      const sha512Hex = 'a'.repeat(128);
      const sha512Stmt = {
        ...sampleStatement,
        subject: [{ name: 'bundle.tar', digest: { sha512: sha512Hex } }]
      };
      const match = verifySubjectDigest(sha512Stmt as any, 'bundle.tar', sha512Hex, 'sha512');
      expect(match.match).toBe(true);
    });

    it('should detect hash mismatch and report expected vs actual', () => {
      const match = verifySubjectDigest(
        sampleStatement,
        'release.zip',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
      expect(match.match).toBe(false);
      expect(match.error).toContain('Digest mismatch');
      expect(match.expectedDigest).toBe('6f0473369b5e87f26076061c1588333a5b8013a51bb582dae53bb47df6309f52');
    });

    it('should match basename even if full path is passed', () => {
      const match = verifySubjectDigest(
        sampleStatement,
        '/var/build/dist/release.zip',
        '6f0473369b5e87f26076061c1588333a5b8013a51bb582dae53bb47df6309f52'
      );
      expect(match.match).toBe(true);
    });
  });
});
