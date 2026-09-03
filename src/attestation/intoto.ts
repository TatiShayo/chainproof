import * as fs from 'fs';
import { InTotoStatement, DSSEEnvelope, SigstoreBundle, InTotoSubject } from '../types/index.js';
import { safeJsonParse } from '../utils/json.js';
import { decodeBase64, validateDigest, computeSha256 } from '../utils/security.js';

export const IN_TOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1';
export const IN_TOTO_STATEMENT_V01 = 'https://in-toto.io/Statement/v0.1';

/**
 * Validates whether an object complies with the in-toto Statement specification.
 */
export function isValidInTotoStatement(obj: any): obj is InTotoStatement {
  if (!obj || typeof obj !== 'object') return false;

  const validTypes = [
    IN_TOTO_STATEMENT_V1,
    IN_TOTO_STATEMENT_V01,
    'http://in-toto.io/Statement/v1',
    'http://in-toto.io/Statement/v0.1'
  ];

  if (!obj._type || typeof obj._type !== 'string' || !validTypes.includes(obj._type)) {
    return false;
  }

  if (!Array.isArray(obj.subject) || obj.subject.length === 0) {
    return false;
  }

  for (const subj of obj.subject) {
    if (
      !subj ||
      typeof subj !== 'object' ||
      typeof subj.name !== 'string' ||
      subj.name.trim().length === 0 ||
      !subj.digest ||
      typeof subj.digest !== 'object' ||
      Object.keys(subj.digest).length === 0
    ) {
      return false;
    }
  }

  if (!obj.predicateType || typeof obj.predicateType !== 'string') {
    return false;
  }

  if (!obj.predicate || typeof obj.predicate !== 'object') {
    return false;
  }

  return true;
}

/**
 * Parses raw JSON string, Buffer, or object into an InTotoStatement.
 */
export function parseInTotoStatement(input: string | Buffer | object): InTotoStatement {
  let parsed: any;
  if (typeof input === 'object' && !Buffer.isBuffer(input)) {
    parsed = input;
  } else {
    const res = safeJsonParse(input);
    if (!res.success || !res.data) {
      throw new Error(`Failed to parse in-toto statement JSON: ${res.error}`);
    }
    parsed = res.data;
  }

  // If it's wrapped in a Sigstore bundle or DSSE envelope, extract payload first
  if (parsed.dsseEnvelope) {
    return parseDSSEEnvelope(parsed.dsseEnvelope).statement;
  }

  if (parsed.payload && (parsed.payloadType || parsed.signatures)) {
    return parseDSSEEnvelope(parsed).statement;
  }

  if (!isValidInTotoStatement(parsed)) {
    throw new Error('Invalid in-toto statement format: missing or invalid _type, subject, predicateType, or predicate');
  }

  return parsed;
}

/**
 * Parses a DSSE envelope, decoding the base64 payload and extracting the in-toto statement.
 */
export function parseDSSEEnvelope(input: string | Buffer | object): { envelope: DSSEEnvelope; statement: InTotoStatement } {
  let envelopeObj: any;
  if (typeof input === 'object' && !Buffer.isBuffer(input)) {
    envelopeObj = input;
  } else {
    const res = safeJsonParse(input);
    if (!res.success || !res.data) {
      throw new Error(`Failed to parse DSSE envelope JSON: ${res.error}`);
    }
    envelopeObj = res.data;
  }

  if (envelopeObj.dsseEnvelope) {
    envelopeObj = envelopeObj.dsseEnvelope;
  }

  if (!envelopeObj.payload || typeof envelopeObj.payload !== 'string') {
    throw new Error('DSSE envelope missing payload string');
  }

  const decodedPayload = decodeBase64(envelopeObj.payload);
  const stmtRes = safeJsonParse(decodedPayload);
  if (!stmtRes.success || !stmtRes.data) {
    throw new Error(`Failed to parse decoded DSSE payload as JSON: ${stmtRes.error}`);
  }

  if (!isValidInTotoStatement(stmtRes.data)) {
    throw new Error('Decoded DSSE payload is not a valid in-toto statement');
  }

  const envelope: DSSEEnvelope = {
    payload: envelopeObj.payload,
    payloadType: envelopeObj.payloadType || 'application/vnd.in-toto+json',
    signatures: Array.isArray(envelopeObj.signatures) ? envelopeObj.signatures : []
  };

  return { envelope, statement: stmtRes.data };
}

/**
 * Verifies that the in-toto statement contains a subject matching the given artifact name and digest.
 */
export function verifySubjectDigest(
  statement: InTotoStatement,
  artifactNameOrPath: string,
  actualDigest: string,
  algorithm: string = 'sha256'
): { match: boolean; expectedDigest?: string; subjectName?: string; error?: string } {
  if (!statement || !Array.isArray(statement.subject)) {
    return { match: false, error: 'Invalid statement subject array' };
  }

  const baseName = artifactNameOrPath.replace(/\\/g, '/').split('/').pop() || artifactNameOrPath;
  const normAlg = (algorithm || 'sha256').toLowerCase().replace(/[^a-z0-9]/g, '');

  for (const subject of statement.subject) {
    const subjName = subject.name.replace(/\\/g, '/').split('/').pop() || subject.name;
    const subjDigest = subject.digest
      ? subject.digest[normAlg] || subject.digest[algorithm.toLowerCase()] || subject.digest[algorithm.toUpperCase()]
      : undefined;

    // Check by name or matching digest directly if subject name is generic or matches baseName
    if (subjDigest) {
      if (validateDigest(actualDigest, subjDigest)) {
        return { match: true, expectedDigest: subjDigest, subjectName: subject.name };
      }
      if (subjName === baseName) {
        return {
          match: false,
          expectedDigest: subjDigest,
          subjectName: subject.name,
          error: `Digest mismatch for subject "${subject.name}": expected ${subjDigest}, got ${actualDigest}`
        };
      }
    }
  }

  // If we couldn't match, return first subject's digest if available
  const firstSubj = statement.subject[0];
  const expected = firstSubj?.digest
    ? firstSubj.digest[normAlg] || firstSubj.digest[algorithm.toLowerCase()]
    : undefined;
  return {
    match: false,
    expectedDigest: expected,
    subjectName: firstSubj?.name,
    error: `No subject in statement matched artifact "${baseName}" with digest ${actualDigest}`
  };
}

/**
 * Extracts in-toto statement from any Sigstore bundle, DSSE file, or in-toto JSONL file.
 */
export function extractAttestationStatement(input: string | Buffer | object): InTotoStatement {
  if (typeof input === 'string') {
    const trimmed = input.trim();
    // Handle JSONL format (take last non-empty line or first line)
    if (trimmed.includes('\n') && !trimmed.startsWith('{')) {
      const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);
      for (const line of lines) {
        try {
          return parseInTotoStatement(line);
        } catch {
          // try next
        }
      }
    }
  }

  return parseInTotoStatement(input);
}
