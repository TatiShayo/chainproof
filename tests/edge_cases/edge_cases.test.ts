import { describe, it, expect } from 'vitest';
import { safeJsonParse, safeJsonStringify } from '../../src/utils/json.js';
import { decodeBase64, encodeBase64, sanitizePath, timingSafeEqual } from '../../src/utils/security.js';
import { parseInTotoStatement, verifySubjectDigest, isValidInTotoStatement } from '../../src/attestation/intoto.js';
import { parseCycloneDX } from '../../src/sbom/cyclonedx.js';
import { parseSPDX } from '../../src/sbom/spdx.js';
import { parseGrypeTable, parseGrypeJson, normalizeSeverity } from '../../src/vulnerability/matcher.js';
import { evaluateSLSALevel } from '../../src/provenance/slsa.js';

describe('Edge Cases & Resiliency Test Suite', () => {
  describe('JSON & Encoding Edge Cases', () => {
    it('should handle deeply nested JSON objects without crashing', () => {
      let nested: any = { value: 1 };
      for (let i = 0; i < 50; i++) {
        nested = { child: nested };
      }
      const serialized = safeJsonStringify(nested);
      const parsed = safeJsonParse(serialized);
      expect(parsed.success).toBe(true);
    });

    it('should handle strings with mixed quotes and escaped characters', () => {
      const complexStr = JSON.stringify({ key: 'hello "world" with \n newline and \t tabs and \\ backslash' });
      const parsed = safeJsonParse(complexStr);
      expect(parsed.success).toBe(true);
      expect(parsed.data?.key).toContain('hello "world"');
    });

    it('should handle boolean and number root values in safeJsonParse', () => {
      expect(safeJsonParse('true').data).toBe(true);
      expect(safeJsonParse('12345').data).toBe(12345);
      expect(safeJsonParse('"string-value"').data).toBe('string-value');
    });

    it('should handle null and undefined inputs safely', () => {
      expect(safeJsonParse(null as any).success).toBe(false);
      expect(safeJsonParse(undefined as any).success).toBe(false);
    });
  });

  describe('Base64 Decoding Edge Cases', () => {
    it('should decode empty base64 string to empty string', () => {
      expect(decodeBase64('')).toBe('');
    });

    it('should handle unpadded base64 strings gracefully', () => {
      // "any carnal pleasure" -> "YW55IGNhcm5hbCBwbGVhc3VyZQ==" -> unpadded "YW55IGNhcm5hbCBwbGVhc3VyZQ"
      expect(decodeBase64('YW55IGNhcm5hbCBwbGVhc3VyZQ')).toBe('any carnal pleasure');
    });

    it('should handle base64 with URL-safe replacement characters', () => {
      const data = 'Hello???---///';
      const encoded = encodeBase64(data).replace(/\+/g, '-').replace(/\//g, '_');
      expect(decodeBase64(encoded)).toBe(data);
    });
  });

  describe('In-toto Statement Edge Cases', () => {
    it('should handle in-toto statement with multiple subjects', () => {
      const stmt = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [
          { name: 'artifact-a.tar.gz', digest: { sha256: 'aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111' } },
          { name: 'artifact-b.tar.gz', digest: { sha256: 'bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222' } }
        ],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: { buildDefinition: { buildType: 'test' } }
      };

      expect(isValidInTotoStatement(stmt)).toBe(true);

      const matchA = verifySubjectDigest(stmt as any, 'artifact-a.tar.gz', 'aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111');
      expect(matchA.match).toBe(true);
      expect(matchA.subjectName).toBe('artifact-a.tar.gz');

      const matchB = verifySubjectDigest(stmt as any, 'artifact-b.tar.gz', 'bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222');
      expect(matchB.match).toBe(true);
      expect(matchB.subjectName).toBe('artifact-b.tar.gz');
    });

    it('should handle statement with uppercase and lowercase digest comparisons', () => {
      const stmt = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [
          { name: 'app.zip', digest: { sha256: 'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890' } }
        ],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: { buildDefinition: { buildType: 'test' } }
      };

      const match = verifySubjectDigest(stmt as any, 'app.zip', 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890');
      expect(match.match).toBe(true);
    });
  });

  describe('CycloneDX & SPDX Parser Edge Cases', () => {
    it('should parse CycloneDX with missing version or hashes gracefully', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        components: [
          {
            name: 'pkg-without-version'
          }
        ]
      };

      const parsed = parseCycloneDX(sbom);
      expect(parsed.components[0].name).toBe('pkg-without-version');
      expect(parsed.components[0].version).toBe('0.0.0');
    });

    it('should parse SPDX packages with missing licenseConcluded gracefully', () => {
      const sbom = {
        spdxVersion: 'SPDX-2.3',
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: 'test-spdx',
        packages: [
          {
            SPDXID: 'SPDXRef-1',
            name: 'unlicensed-pkg'
          }
        ]
      };

      const parsed = parseSPDX(sbom);
      expect(parsed.components[0].name).toBe('unlicensed-pkg');
      expect(parsed.components[0].licenses).toHaveLength(0);
    });
  });

  describe('Vulnerability Scanning Edge Cases', () => {
    it('should parse Grype table with irregular spacing or missing optional columns', () => {
      const table = `
NAME     INSTALLED  FIXED IN  TYPE  VULNERABILITY        SEVERITY
pkg1     1.0.0      (won't    npm   CVE-2024-0001        High
pkg2     2.0.0      2.0.1     npm   CVE-2024-0002        Low
`;
      const items = parseGrypeTable(table);
      expect(items).toHaveLength(2);
      expect(items[0].fixedInVersion).toBeUndefined();
      expect(items[1].fixedInVersion).toBe('2.0.1');
    });

    it('should handle empty Grype table without crashing', () => {
      expect(parseGrypeTable('')).toHaveLength(0);
      expect(parseGrypeTable('   \n  \n')).toHaveLength(0);
    });

    it('should handle empty Grype JSON matches array', () => {
      const parsed = parseGrypeJson({ matches: [] });
      expect(parsed).toHaveLength(0);
    });
  });

  describe('SLSA Evaluation Edge Cases', () => {
    it('should handle provenance with empty resolvedDependencies array', () => {
      const prov = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: 'test.zip', digest: { sha256: 'abc' } }],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: {
          buildDefinition: {
            buildType: 'https://github.com/slsa-framework/slsa-github-generator/workflow/v1',
            resolvedDependencies: []
          },
          runDetails: {
            builder: { id: 'https://github.com/slsa-framework/slsa-github-generator' }
          }
        }
      };

      const evaluation = evaluateSLSALevel(prov);
      expect(evaluation.meetsLevel1).toBe(true);
      expect(evaluation.meetsLevel2).toBe(false); // missing pinned source dependency
      expect(evaluation.level).toBe(1);
    });
  });
});
