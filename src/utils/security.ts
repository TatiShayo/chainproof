import * as crypto from 'crypto';
import * as path from 'path';

/**
 * Sanitizes and resolves a file path, guarding against path traversal,
 * null byte injection, and directory breakout attacks.
 *
 * `allowedBaseDir` is REQUIRED: without it the function has no containment
 * boundary to enforce and silently returns the resolved path — callers that
 * omitted it were effectively unguarded.
 */
export function sanitizePath(filePath: string, allowedBaseDir: string): string {
  if (!filePath || typeof filePath !== 'string' || filePath.trim().length === 0) {
    throw new Error('Path must be a non-empty string');
  }

  // Null byte injection check
  if (filePath.includes('\0')) {
    throw new Error('Invalid path: null byte detected');
  }

  // Normalize path
  const normalized = path.normalize(filePath.trim());

  // The base directory is required — enforce containment against it.
  if (typeof allowedBaseDir !== 'string' || allowedBaseDir.length === 0) {
    throw new Error('sanitizePath: allowedBaseDir is required');
  }
  if (allowedBaseDir.includes('\0')) {
    throw new Error('Invalid base directory: null byte detected');
  }

  const resolvedBase = path.resolve(allowedBaseDir);
  const resolvedTarget = path.resolve(resolvedBase, normalized);

  // Ensure the target path stays inside the base path
  const relative = path.relative(resolvedBase, resolvedTarget);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Path traversal violation: "${filePath}" escapes allowed directory "${allowedBaseDir}"`);
  }
  return resolvedTarget;
}

/**
 * Computes SHA-256 hex digest of a Buffer or string.
 */
export function computeSha256(data: Buffer | string): string {
  if (data === undefined || data === null) {
    data = '';
  }
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Computes SHA-1 hex digest of a Buffer or string.
 */
export function computeSha1(data: Buffer | string): string {
  if (data === undefined || data === null) {
    data = '';
  }
  return crypto.createHash('sha1').update(data).digest('hex');
}

/**
 * Computes SHA-512 hex digest of a Buffer or string.
 */
export function computeSha512(data: Buffer | string): string {
  if (data === undefined || data === null) {
    data = '';
  }
  return crypto.createHash('sha512').update(data).digest('hex');
}

/**
 * Performs a timing-safe equality check between two strings.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Validates calculated digest against expected digest in a timing-safe manner.
 */
export function validateDigest(calculated: string, expected: string): boolean {
  if (typeof calculated !== 'string' || typeof expected !== 'string') {
    return false;
  }
  const normCalculated = calculated.trim().toLowerCase().replace(/^sha256:/i, '').replace(/^sha1:/i, '').replace(/^sha512:/i, '');
  const normExpected = expected.trim().toLowerCase().replace(/^sha256:/i, '').replace(/^sha1:/i, '').replace(/^sha512:/i, '');
  return timingSafeEqual(normCalculated, normExpected);
}

/**
 * Decodes base64 or base64url string to UTF-8 text.
 */
export function decodeBase64(str: string): string {
  if (!str || typeof str !== 'string') {
    return '';
  }
  // Normalize base64url if needed
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Decodes base64 or base64url string to Buffer.
 */
export function decodeBase64ToBuffer(str: string): Buffer {
  if (!str || typeof str !== 'string') {
    return Buffer.alloc(0);
  }
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Encodes Buffer or string to base64.
 */
export function encodeBase64(data: Buffer | string): string {
  if (data === null || data === undefined) {
    return '';
  }
  return Buffer.from(data).toString('base64');
}
