import { describe, it, expect } from 'vitest';
import { parseSPDX, validateSPDXStructure, extractSPDXPackages } from '../../src/sbom/spdx.js';
import { detectSBOMFormat, parseSBOM } from '../../src/sbom/index.js';

describe('SPDX SBOM Parsing & Extraction', () => {
  const sampleSPDX = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'sample-project-spdx',
    documentNamespace: 'http://spdx.org/spdxdocs/sample-1.0',
    packages: [
      {
        SPDXID: 'SPDXRef-Package-react',
        name: 'react',
        versionInfo: '18.2.0',
        downloadLocation: 'NOASSERTION',
        licenseConcluded: 'MIT',
        licenseDeclared: 'MIT',
        checksums: [
          {
            algorithm: 'SHA256',
            checksumValue: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
          }
        ],
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: 'pkg:npm/react@18.2.0'
          }
        ]
      },
      {
        SPDXID: 'SPDXRef-Package-zod',
        name: 'zod',
        versionInfo: '3.22.4',
        licenseConcluded: 'MIT'
      }
    ]
  };

  it('should validate valid SPDX structure', () => {
    const valid = validateSPDXStructure(sampleSPDX);
    expect(valid.valid).toBe(true);
    expect(valid.errors).toHaveLength(0);
  });

  it('should invalidate missing spdxVersion, SPDXID, or name', () => {
    const invalid = validateSPDXStructure({ spdxVersion: '1.0' });
    expect(invalid.valid).toBe(false);
    expect(invalid.errors.length).toBeGreaterThan(0);
  });

  it('should extract packages and external PURLs from SPDX', () => {
    const packages = extractSPDXPackages(sampleSPDX as any);
    expect(packages).toHaveLength(2);

    const reactPkg = packages.find(p => p.name === 'react');
    expect(reactPkg?.version).toBe('18.2.0');
    expect(reactPkg?.purl).toBe('pkg:npm/react@18.2.0');
    expect(reactPkg?.licenses).toContain('MIT');
    expect(reactPkg?.hashes['sha256']).toBe('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
  });

  it('should parse SPDX JSON into UnifiedSBOM', () => {
    const jsonStr = JSON.stringify(sampleSPDX);
    const unified = parseSPDX(jsonStr);

    expect(unified.format).toBe('spdx');
    expect(unified.specVersion).toBe('SPDX-2.3');
    expect(unified.documentName).toBe('sample-project-spdx');
    expect(unified.components).toHaveLength(2);
  });

  describe('detectSBOMFormat & parseSBOM', () => {
    it('should detect CycloneDX format', () => {
      expect(detectSBOMFormat({ bomFormat: 'CycloneDX', specVersion: '1.4' })).toBe('cyclonedx');
    });

    it('should detect SPDX format', () => {
      expect(detectSBOMFormat({ spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT', name: 'doc' })).toBe('spdx');
    });

    it('should return unknown for unrecognized JSON', () => {
      expect(detectSBOMFormat({ message: 'hello' })).toBe('unknown');
    });

    it('should parse dynamically via unified parseSBOM', () => {
      const unified = parseSBOM(JSON.stringify(sampleSPDX));
      expect(unified.format).toBe('spdx');
      expect(unified.components[0].name).toBe('react');
    });
  });
});
