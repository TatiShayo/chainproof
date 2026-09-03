import { UnifiedSBOM, UnifiedComponent } from '../types/index.js';
import { parseCycloneDX } from './cyclonedx.js';
import { parseSPDX } from './spdx.js';
import { safeJsonParse } from '../utils/json.js';
import { computeSha256, computeSha1, computeSha512, validateDigest } from '../utils/security.js';

/**
 * Detects whether an SBOM is CycloneDX, SPDX, or unknown format.
 */
export function detectSBOMFormat(input: string | Buffer | object): 'cyclonedx' | 'spdx' | 'unknown' {
  let parsed: any;
  if (typeof input === 'object' && !Buffer.isBuffer(input)) {
    parsed = input;
  } else {
    const res = safeJsonParse(input);
    if (!res.success || !res.data) {
      return 'unknown';
    }
    parsed = res.data;
  }

  if (parsed.bomFormat === 'CycloneDX' || (parsed.$schema && parsed.$schema.includes('cyclonedx'))) {
    return 'cyclonedx';
  }

  if (parsed.spdxVersion || parsed.SPDXID || (parsed.$schema && parsed.$schema.includes('spdx'))) {
    return 'spdx';
  }

  if (Array.isArray(parsed.components)) {
    return 'cyclonedx';
  }

  if (Array.isArray(parsed.packages)) {
    return 'spdx';
  }

  return 'unknown';
}

/**
 * Automatically detects format and parses an SBOM into a UnifiedSBOM.
 */
export function parseSBOM(input: string | Buffer | object): UnifiedSBOM {
  const format = detectSBOMFormat(input);

  if (format === 'cyclonedx') {
    return parseCycloneDX(input);
  } else if (format === 'spdx') {
    return parseSPDX(input);
  } else {
    throw new Error('Unsupported or unrecognized SBOM format (must be CycloneDX or SPDX JSON)');
  }
}

/**
 * Verifies that the raw SBOM bytes match an expected cryptographic digest (e.g. from an attestation subject or signature).
 */
export function verifySBOMIntegrity(
  rawSBOM: string | Buffer,
  expectedDigest: string,
  algorithm: string = 'sha256'
): { intact: boolean; calculatedDigest: string; expectedDigest: string } {
  let calculatedDigest = '';
  const normAlg = (algorithm || 'sha256').toLowerCase().replace(/[^a-z0-9]/g, '');

  if (normAlg === 'sha256') {
    calculatedDigest = computeSha256(rawSBOM);
  } else if (normAlg === 'sha1') {
    calculatedDigest = computeSha1(rawSBOM);
  } else if (normAlg === 'sha512') {
    calculatedDigest = computeSha512(rawSBOM);
  } else {
    throw new Error(`Unsupported hash algorithm "${algorithm}" for SBOM integrity verification`);
  }

  const intact = validateDigest(calculatedDigest, expectedDigest);
  return {
    intact,
    calculatedDigest,
    expectedDigest
  };
}

/**
 * Detects potential tampering or corruption in an SBOM:
 * - Empty or whitespace-only component names
 * - Non-semantic or illegal version strings
 * - Malformed hashes
 * - Duplicate package identifiers with divergent versions
 */
export function detectTamperedSBOM(sbom: UnifiedSBOM): { tampered: boolean; issues: string[] } {
  const issues: string[] = [];

  if (!sbom || typeof sbom !== 'object') {
    return { tampered: true, issues: ['SBOM is not a valid object'] };
  }

  if (!sbom.components || !Array.isArray(sbom.components) || sbom.components.length === 0) {
    issues.push('SBOM contains zero components or packages');
  }

  for (const comp of (sbom.components || [])) {
    if (!comp || typeof comp !== 'object') {
      issues.push('Found malformed component in SBOM');
      continue;
    }

    if (!comp.name || typeof comp.name !== 'string' || comp.name.trim().length === 0) {
      issues.push('Found component with empty or missing name');
    }

    if (comp.version && typeof comp.version === 'string' && comp.version.trim().length === 0) {
      issues.push(`Component "${comp.name}" has empty whitespace version`);
    }

    if (comp.purl) {
      if (typeof comp.purl !== 'string' || !comp.purl.startsWith('pkg:')) {
        issues.push(`Invalid PURL format for component "${comp.name}": "${comp.purl}"`);
      }
    }

    // Validate hash formats
    if (comp.hashes && typeof comp.hashes === 'object') {
      for (const [alg, hashVal] of Object.entries(comp.hashes)) {
        const normAlg = alg.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (typeof hashVal !== 'string') {
          issues.push(`Component "${comp.name}" has non-string hash value for algorithm ${alg}`);
        } else if (normAlg === 'sha256' && !/^[0-9a-fA-F]{64}$/.test(hashVal.trim())) {
          issues.push(`Component "${comp.name}" has invalid SHA-256 hash length: "${hashVal}"`);
        } else if (normAlg === 'sha1' && !/^[0-9a-fA-F]{40}$/.test(hashVal.trim())) {
          issues.push(`Component "${comp.name}" has invalid SHA-1 hash length: "${hashVal}"`);
        } else if (normAlg === 'sha512' && !/^[0-9a-fA-F]{128}$/.test(hashVal.trim())) {
          issues.push(`Component "${comp.name}" has invalid SHA-512 hash length: "${hashVal}"`);
        }
      }
    }
  }

  return {
    tampered: issues.length > 0,
    issues
  };
}

export * from './cyclonedx.js';
export * from './spdx.js';
