import { CycloneDXSBOM, CycloneDXComponent, UnifiedComponent, UnifiedSBOM } from '../types/index.js';
import { safeJsonParse } from '../utils/json.js';
import { computeSha256 } from '../utils/security.js';

/**
 * Validates whether an object complies with the CycloneDX JSON schema specification.
 */
export function validateCycloneDXStructure(obj: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!obj || typeof obj !== 'object') {
    return { valid: false, errors: ['CycloneDX SBOM must be a non-null object'] };
  }

  if (obj.bomFormat !== 'CycloneDX') {
    errors.push(`Expected bomFormat to be "CycloneDX", found "${obj.bomFormat}"`);
  }

  if (!obj.specVersion || typeof obj.specVersion !== 'string') {
    errors.push('Missing or invalid "specVersion" field');
  }

  if (obj.components && !Array.isArray(obj.components)) {
    errors.push('"components" must be an array if present');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Extracts unified components from a CycloneDX SBOM.
 */
export function extractCycloneDXComponents(sbom: CycloneDXSBOM): UnifiedComponent[] {
  const components: UnifiedComponent[] = [];
  if (!sbom.components || !Array.isArray(sbom.components)) {
    return components;
  }

  for (const c of sbom.components) {
    if (!c.name) continue;

    const hashes: Record<string, string> = {};
    if (Array.isArray(c.hashes)) {
      for (const h of c.hashes) {
        if (h.alg && h.content) {
          hashes[h.alg.toLowerCase()] = h.content;
        }
      }
    }

    const licenses: string[] = [];
    if (Array.isArray(c.licenses)) {
      for (const lic of c.licenses) {
        if (lic.license?.id) {
          licenses.push(lic.license.id);
        } else if (lic.license?.name) {
          licenses.push(lic.license.name);
        } else if (lic.expression) {
          licenses.push(lic.expression);
        }
      }
    }

    components.push({
      name: c.name,
      version: c.version || '0.0.0',
      purl: c.purl,
      type: c.type || 'library',
      hashes,
      licenses
    });
  }

  return components;
}

/**
 * Parses raw JSON string, Buffer, or object into a UnifiedSBOM representing CycloneDX.
 */
export function parseCycloneDX(input: string | Buffer | object): UnifiedSBOM {
  let rawStr = '';
  let parsed: CycloneDXSBOM;

  if (Buffer.isBuffer(input)) {
    rawStr = input.toString('utf8');
    const res = safeJsonParse<CycloneDXSBOM>(input);
    if (!res.success || !res.data) {
      throw new Error(`Failed to parse CycloneDX JSON: ${res.error}`);
    }
    parsed = res.data;
  } else if (typeof input === 'string') {
    rawStr = input;
    const res = safeJsonParse<CycloneDXSBOM>(input);
    if (!res.success || !res.data) {
      throw new Error(`Failed to parse CycloneDX JSON: ${res.error}`);
    }
    parsed = res.data;
  } else if (typeof input === 'object' && input !== null) {
    parsed = input as CycloneDXSBOM;
    rawStr = JSON.stringify(input);
  } else {
    throw new Error('Invalid input to parseCycloneDX');
  }

  const validation = validateCycloneDXStructure(parsed);
  if (!validation.valid) {
    throw new Error(`CycloneDX schema validation failed: ${validation.errors.join('; ')}`);
  }

  const components = extractCycloneDXComponents(parsed);

  return {
    format: 'cyclonedx',
    specVersion: parsed.specVersion,
    documentName: parsed.metadata?.component?.name || parsed.serialNumber,
    timestamp: parsed.metadata?.timestamp,
    components,
    rawSha256: computeSha256(rawStr)
  };
}
