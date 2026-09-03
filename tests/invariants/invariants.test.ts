import { describe, it, expect } from 'vitest';
import { computeSha256, computeSha1, computeSha512 } from '../../src/utils/security.js';
import { safeJsonParse, safeJsonStringify } from '../../src/utils/json.js';
import { SEVERITY_RANKS, normalizeSeverity } from '../../src/vulnerability/matcher.js';
import { evaluateSLSALevel } from '../../src/provenance/slsa.js';
import { PolicyEngine } from '../../src/policy/engine.js';
import { SeverityLevel } from '../../src/types/index.js';

describe('System Invariants & Mathematical Properties', () => {
  describe('Cryptographic Invariants', () => {
    it('Invariant 1: Hash functions must be strictly deterministic (H(x) === H(x))', () => {
      const input = 'chainproof deterministic supply chain invariant test payload';
      expect(computeSha256(input)).toBe(computeSha256(input));
      expect(computeSha1(input)).toBe(computeSha1(input));
      expect(computeSha512(input)).toBe(computeSha512(input));
    });

    it('Invariant 2: Different inputs must yield collision-free distinct outputs', () => {
      const inputs = ['input_A', 'input_B', 'input_C', 'input_AA', 'input_a'];
      const hashes = new Set(inputs.map(i => computeSha256(i)));
      expect(hashes.size).toBe(inputs.length);
    });

    it('Invariant 3: Output length of hash functions must be strictly fixed', () => {
      for (const len of [0, 1, 10, 100, 1000]) {
        const text = 'a'.repeat(len);
        expect(computeSha256(text)).toHaveLength(64);
        expect(computeSha1(text)).toHaveLength(40);
        expect(computeSha512(text)).toHaveLength(128);
      }
    });
  });

  describe('JSON Serialization & Parsing Invariant', () => {
    it('Invariant 4: safeJsonParse(safeJsonStringify(x)) must be isomorphic to x for pure data objects', () => {
      const testData = {
        name: 'chainproof',
        version: '1.0.0',
        metadata: {
          timestamp: '2026-08-15T00:00:00Z',
          scores: [1, 2, 3.14, 100],
          verified: true,
          nested: {
            deep: {
              value: 'intact'
            }
          }
        }
      };

      const serialized = safeJsonStringify(testData);
      const parsed = safeJsonParse(serialized);
      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual(testData);
    });
  });

  describe('Severity Order Invariant', () => {
    it('Invariant 5: Severity ranking must form a strict total order: CRITICAL > HIGH > MEDIUM > LOW > NEGLIGIBLE > UNKNOWN', () => {
      const ordered: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN'];
      for (let i = 0; i < ordered.length - 1; i++) {
        const current = ordered[i];
        const next = ordered[i + 1];
        expect(SEVERITY_RANKS[current]).toBeGreaterThan(SEVERITY_RANKS[next]);
      }
    });
  });

  describe('SLSA Level Hierarchy Invariant', () => {
    it('Invariant 6: SLSA Level 3 achievement strictly implies Level 2 and Level 1', () => {
      const fullL3 = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: 'app.zip', digest: { sha256: 'abc' } }],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: {
          buildDefinition: {
            buildType: 'https://github.com/slsa-framework/slsa-github-generator/workflow/v1',
            externalParameters: { wf: 'build.yml' },
            resolvedDependencies: [
              { uri: 'git+https://github.com/org/repo', digest: { sha1: '1234567890123456789012345678901234567890' } }
            ]
          },
          runDetails: {
            builder: { id: 'https://github.com/slsa-framework/slsa-github-generator' }
          }
        }
      };

      const evalResult = evaluateSLSALevel(fullL3);
      expect(evalResult.level).toBe(3);
      expect(evalResult.meetsLevel3).toBe(true);
      expect(evalResult.meetsLevel2).toBe(true);
      expect(evalResult.meetsLevel1).toBe(true);
    });
  });

  describe('Policy Engine Monotonicity Invariant', () => {
    it('Invariant 7: Tightening policy constraints monotonically decreases or maintains pass status', () => {
      const lenientEngine = new PolicyEngine({ minSlsaLevel: 1 });
      const strictEngine = new PolicyEngine({ minSlsaLevel: 3, requireSbom: true, requireSignature: true });

      const context = {
        provenance: {
          _type: 'https://in-toto.io/Statement/v1',
          subject: [{ name: 'app.zip', digest: { sha256: 'abc' } }],
          predicateType: 'https://slsa.dev/provenance/v1',
          predicate: {
            buildDefinition: { buildType: 'generic' }
          }
        }
      };

      const lenientRes = lenientEngine.evaluate(context);
      const strictRes = strictEngine.evaluate(context);

      expect(lenientRes.passed).toBe(true);
      expect(strictRes.passed).toBe(false);
    });
  });
});
