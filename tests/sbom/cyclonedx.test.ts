import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import {
  parseCycloneDX,
  validateCycloneDXStructure,
  extractCycloneDXComponents
} from '../../src/sbom/cyclonedx.js';

describe('CycloneDX SBOM Parsing & Extraction', () => {
  const sampleCycloneDX = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
    version: 1,
    metadata: {
      timestamp: '2026-08-01T00:00:00Z',
      component: {
        name: 'sample-app',
        version: '1.0.0'
      }
    },
    components: [
      {
        type: 'library',
        name: 'express',
        version: '4.18.2',
        purl: 'pkg:npm/express@4.18.2',
        licenses: [{ license: { id: 'MIT' } }],
        hashes: [{ alg: 'SHA-256', content: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }]
      },
      {
        type: 'library',
        name: 'lodash',
        version: '4.17.21',
        purl: 'pkg:npm/lodash@4.17.21',
        licenses: [{ license: { name: 'MIT License' } }]
      },
      {
        type: 'library',
        name: 'custom-tool',
        version: '2.0.0',
        licenses: [{ expression: 'Apache-2.0 OR MIT' }]
      }
    ]
  };

  it('should validate valid CycloneDX structure', () => {
    const valid = validateCycloneDXStructure(sampleCycloneDX);
    expect(valid.valid).toBe(true);
    expect(valid.errors).toHaveLength(0);
  });

  it('should invalidate missing bomFormat or specVersion', () => {
    const invalid = validateCycloneDXStructure({ bomFormat: 'NotCyclone', specVersion: 123 });
    expect(invalid.valid).toBe(false);
    expect(invalid.errors.length).toBeGreaterThan(0);
  });

  it('should extract components with licenses and hashes accurately', () => {
    const components = extractCycloneDXComponents(sampleCycloneDX as any);
    expect(components).toHaveLength(3);

    const expressComp = components.find(c => c.name === 'express');
    expect(expressComp?.version).toBe('4.18.2');
    expect(expressComp?.licenses).toContain('MIT');
    expect(expressComp?.hashes['sha-256']).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

    const customComp = components.find(c => c.name === 'custom-tool');
    expect(customComp?.licenses).toContain('Apache-2.0 OR MIT');
  });

  it('should parse CycloneDX JSON string into UnifiedSBOM', () => {
    const jsonStr = JSON.stringify(sampleCycloneDX);
    const unified = parseCycloneDX(jsonStr);

    expect(unified.format).toBe('cyclonedx');
    expect(unified.specVersion).toBe('1.5');
    expect(unified.documentName).toBe('sample-app');
    expect(unified.components).toHaveLength(3);
    expect(unified.rawSha256).toHaveLength(64);
  });

  it('should parse real repository sbom.json from chainproof root', () => {
    const sbomPath = path.resolve('sbom.json');
    if (fs.existsSync(sbomPath)) {
      const raw = fs.readFileSync(sbomPath);
      const unified = parseCycloneDX(raw);
      expect(unified.format).toBe('cyclonedx');
      expect(unified.components.length).toBeGreaterThan(10);
      expect(unified.components.some(c => c.name.includes('babel'))).toBe(true);
    }
  });
});
