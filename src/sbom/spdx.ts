import { SPDXSBOM, SPDXPackage, UnifiedComponent, UnifiedSBOM } from '../types/index.js';
import { safeJsonParse } from '../utils/json.js';
import { computeSha256 } from '../utils/security.js';

/**
 * Validates whether an object complies with the SPDX JSON schema specification.
 */
export function validateSPDXStructure(obj: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!obj || typeof obj !== 'object') {
    return { valid: false, errors: ['SPDX SBOM must be a non-null object'] };
  }

  if (!obj.spdxVersion || typeof obj.spdxVersion !== 'string' || !obj.spdxVersion.startsWith('SPDX-')) {
    errors.push(`Expected valid "spdxVersion" (e.g. "SPDX-2.3"), found "${obj.spdxVersion}"`);
  }

  if (!obj.SPDXID || typeof obj.SPDXID !== 'string') {
    errors.push('Missing or invalid "SPDXID" field');
  }

  if (!obj.name || typeof obj.name !== 'string') {
    errors.push('Missing or invalid document "name" field');
  }

  if (obj.packages && !Array.isArray(obj.packages)) {
    errors.push('"packages" must be an array if present');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Extracts unified components from an SPDX SBOM.
 */
export function extractSPDXPackages(sbom: SPDXSBOM): UnifiedComponent[] {
  const components: UnifiedComponent[] = [];
  if (!sbom.packages || !Array.isArray(sbom.packages)) {
    return components;
  }

  for (const pkg of sbom.packages) {
    if (!pkg.name) continue;

    const hashes: Record<string, string> = {};
    if (Array.isArray(pkg.checksums)) {
      for (const chk of pkg.checksums) {
        if (chk.algorithm && chk.checksumValue) {
          hashes[chk.algorithm.toLowerCase()] = chk.checksumValue;
        }
      }
    }

    if (pkg.packageVerificationCode?.packageVerificationCodeValue) {
      hashes['spdx:verificationcode'] = pkg.packageVerificationCode.packageVerificationCodeValue;
    }

    const licenses: string[] = [];
    if (pkg.licenseConcluded && pkg.licenseConcluded !== 'NOASSERTION' && pkg.licenseConcluded !== 'NONE') {
      licenses.push(pkg.licenseConcluded);
    }
    if (pkg.licenseDeclared && pkg.licenseDeclared !== 'NOASSERTION' && pkg.licenseDeclared !== 'NONE' && !licenses.includes(pkg.licenseDeclared)) {
      licenses.push(pkg.licenseDeclared);
    }

    // Extract purl from externalRefs if available
    let purl: string | undefined;
    if (Array.isArray(pkg.externalRefs)) {
      const purlRef = pkg.externalRefs.find(r => r.referenceType === 'purl' || r.referenceCategory === 'PACKAGE-MANAGER');
      if (purlRef?.referenceLocator) {
        purl = purlRef.referenceLocator;
      }
    }

    components.push({
      name: pkg.name,
      version: pkg.versionInfo || '0.0.0',
      purl,
      type: 'package',
      hashes,
      licenses
    });
  }

  return components;
}

/**
 * Parses raw JSON string, Buffer, or object into a UnifiedSBOM representing SPDX.
 */
export function parseSPDX(input: string | Buffer | object): UnifiedSBOM {
  let rawStr = '';
  let parsed: SPDXSBOM;

  if (Buffer.isBuffer(input)) {
    rawStr = input.toString('utf8');
    const res = safeJsonParse<SPDXSBOM>(input);
    if (!res.success || !res.data) {
      throw new Error(`Failed to parse SPDX JSON: ${res.error}`);
    }
    parsed = res.data;
  } else if (typeof input === 'string') {
    rawStr = input;
    const res = safeJsonParse<SPDXSBOM>(input);
    if (!res.success || !res.data) {
      throw new Error(`Failed to parse SPDX JSON: ${res.error}`);
    }
    parsed = res.data;
  } else if (typeof input === 'object' && input !== null) {
    parsed = input as SPDXSBOM;
    rawStr = JSON.stringify(input);
  } else {
    throw new Error('Invalid input to parseSPDX');
  }

  const validation = validateSPDXStructure(parsed);
  if (!validation.valid) {
    throw new Error(`SPDX schema validation failed: ${validation.errors.join('; ')}`);
  }

  const components = extractSPDXPackages(parsed);

  return {
    format: 'spdx',
    specVersion: parsed.spdxVersion,
    documentName: parsed.name,
    timestamp: undefined,
    components,
    rawSha256: computeSha256(rawStr)
  };
}
