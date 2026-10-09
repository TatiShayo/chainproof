import * as crypto from 'crypto';
import { DSSEEnvelope, SigstoreBundle } from '../types/index.js';
import { decodeBase64ToBuffer } from '../utils/security.js';

/**
 * DSSE / Sigstore signature verification.
 *
 * SECURITY: before this module existed, a subject-DIGEST match was treated as
 * a verified signature (verifier/index.ts set signatureVerified = true when the
 * in-toto subject digest equalled the artifact hash). A digest match proves
 * only that the statement describes this artifact — anyone can author such a
 * JSON. Only a signature that verifies cryptographically against the DSSE
 * Pre-Authentication Encoding counts now.
 *
 * Trust material, in priority order:
 *   1. `trustedPublicKeys` — PEM public keys the deployment trusts (the
 *      operator's own signing key). The DSSE signature must verify against one.
 *   2. The Sigstore bundle's leaf certificate (`verificationMaterial
 *      .certificate.rawBytes`). The DSSE signature must verify against the
 *      certificate's public key.
 *   3. `trustedRoots` — when provided, the leaf must additionally chain to one
 *      of these PEM roots and be inside its validity window (`options.now`).
 *
 * With no key material at all the result is `verified: false` — fail closed.
 *
 * Not implemented (out of scope, offline CLI): Rekor transparency-log
 * inclusion-proof verification and RFC3161 timestamp validation. The bundle's
 * tlogEntries are surfaced as metadata for operators to audit separately.
 */

export interface CosignVerificationResult {
  verified: boolean;
  error?: string;
  details: {
    signaturesTotal: number;
    signaturesVerified: number;
    keyId?: string;
    signerIdentity?: string;
    certificateIssuer?: string;
    certificateValidity?: { notBefore: string; notAfter: string };
    trustAnchored: boolean;
  };
}

export interface CosignVerifyOptions {
  /** PEM-encoded trusted public keys (operator's own signing keys). */
  trustedPublicKeys?: string[];
  /** PEM-encoded trusted root certificates; enables chain + validity checks. */
  trustedRoots?: string[];
  /** Expected signer identity (certificate SAN email/URI). */
  expectedIdentity?: string;
  /** Reference time for certificate validity checks. Defaults to now. */
  now?: Date;
}

/**
 * DSSE Pre-Authentication Encoding (PAE). This exact byte sequence is what
 * DSSE signs — verifying anything else (e.g. the raw payload) is the classic
 * DSSE bypass.
 */
export function computeDSSEPAE(payloadType: string, payload: Buffer): Buffer {
  const type = payloadType || 'application/vnd.in-toto+json';
  const header = Buffer.from(
    `DSSEv1 ${Buffer.byteLength(type, 'utf8')} ${type} ${payload.length} `,
    'utf8'
  );
  return Buffer.concat([header, payload]);
}

function pemToKey(pem: string): crypto.KeyObject | null {
  try {
    return crypto.createPublicKey(pem);
  } catch {
    return null;
  }
}

function certFromBase64Der(rawBytes: string): crypto.X509Certificate | null {
  try {
    return new crypto.X509Certificate(Buffer.from(rawBytes, 'base64'));
  } catch {
    return null;
  }
}

function extractIdentity(cert: crypto.X509Certificate): string | undefined {
  // subjectAltName looks like "email:a@b.com, URI:https://..." in Node.
  const san = cert.subjectAltName || '';
  const emailMatch = san.match(/email:([^,\s]+)/i);
  if (emailMatch) return emailMatch[1];
  const uriMatch = san.match(/URI:([^,\s]+)/i);
  if (uriMatch) return uriMatch[1];
  return undefined;
}

function chainsToTrustedRoot(
  leaf: crypto.X509Certificate,
  trustedRoots: crypto.X509Certificate[]
): boolean {
  for (const root of trustedRoots) {
    try {
      if (leaf.verify(root.publicKey)) return true;
    } catch {
      // try next root
    }
  }
  return false;
}

function isCertValidAt(cert: crypto.X509Certificate, when: Date): boolean {
  const t = when.getTime();
  return t >= new Date(cert.validFrom).getTime() && t <= new Date(cert.validTo).getTime();
}

/**
 * Verifies a DSSE envelope's signatures.
 *
 * With `trustedPublicKeys` the envelope alone is enough. With a Sigstore
 * bundle, pass the whole bundle (see verifySigstoreBundle) — the leaf
 * certificate inside it is the verification key.
 */
export function verifyDSSESignature(
  envelope: DSSEEnvelope,
  options: CosignVerifyOptions = {}
): CosignVerificationResult {
  const result: CosignVerificationResult = {
    verified: false,
    details: { signaturesTotal: 0, signaturesVerified: 0, trustAnchored: false },
  };

  if (!envelope || typeof envelope.payload !== 'string' || !envelope.payload) {
    result.error = 'DSSE envelope missing payload';
    return result;
  }
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
    result.error = 'DSSE envelope has no signatures';
    return result;
  }

  const trustedKeys = (options.trustedPublicKeys || [])
    .map(pemToKey)
    .filter((k): k is crypto.KeyObject => k !== null);

  if (trustedKeys.length === 0) {
    // No operator keys — the caller must supply key material another way
    // (a Sigstore bundle leaf certificate, via verifySigstoreBundle).
    result.error =
      'No trusted key material available: pass trustedPublicKeys or verify a Sigstore bundle';
    return result;
  }

  const payload = decodeBase64ToBuffer(envelope.payload);
  const pae = computeDSSEPAE(envelope.payloadType, payload);
  result.details.signaturesTotal = envelope.signatures.length;

  for (const signature of envelope.signatures) {
    let sigBuffer: Buffer;
    try {
      sigBuffer = decodeBase64ToBuffer(signature.sig);
    } catch {
      continue;
    }
    for (const key of trustedKeys) {
      try {
        if (crypto.verify(null, pae, key, sigBuffer)) {
          result.details.signaturesVerified += 1;
          result.verified = true;
          result.details.trustAnchored = true; // operator-supplied key IS the anchor
          result.details.keyId = signature.keyid;
          break;
        }
      } catch {
        // wrong key type/algorithm for this signature — try the next key
      }
    }
    if (result.verified) break;
  }

  if (!result.verified && !result.error) {
    result.error = 'No signature verified against the trusted public key(s)';
  }
  return result;
}

/**
 * Verifies a Sigstore bundle: extracts the leaf certificate from
 * verificationMaterial, verifies the DSSE signature against it, and — when
 * trustedRoots are configured — chains the leaf and checks its validity
 * window. Without trustedRoots the signature is still cryptographically
 * verified against the bundle's own certificate; `trustAnchored` reports that
 * no root was checked.
 */
export function verifySigstoreBundle(
  bundle: SigstoreBundle,
  options: CosignVerifyOptions = {}
): CosignVerificationResult {
  const envelope = bundle?.dsseEnvelope;
  const result: CosignVerificationResult = {
    verified: false,
    details: { signaturesTotal: 0, signaturesVerified: 0, trustAnchored: false },
  };

  if (!envelope || typeof envelope.payload !== 'string' || !Array.isArray(envelope.signatures)) {
    result.error = 'Not a DSSE Sigstore bundle';
    return result;
  }

  const trustedRoots = (options.trustedRoots || [])
    .map((pem) => {
      try {
        return new crypto.X509Certificate(pem);
      } catch {
        return null;
      }
    })
    .filter((c): c is crypto.X509Certificate => c !== null);

  const payload = decodeBase64ToBuffer(envelope.payload);
  const pae = computeDSSEPAE(envelope.payloadType, payload);
  result.details.signaturesTotal = envelope.signatures.length;

  const certRaw = bundle.verificationMaterial?.certificate?.rawBytes;
  const leaf = certRaw ? certFromBase64Der(certRaw) : null;

  if (!leaf) {
    // No certificate in the bundle: fall back to operator-provided keys.
    return verifyDSSESignature(envelope, options);
  }

  result.details.signerIdentity = extractIdentity(leaf);
  result.details.certificateIssuer = leaf.issuer || undefined;
  result.details.certificateValidity = {
    notBefore: leaf.validFrom,
    notAfter: leaf.validTo,
  };

  // Root-based trust checks run before the crypto check so an expired or
  // mis-chained certificate can never report a verified signature.
  if (trustedRoots.length > 0) {
    if (!chainsToTrustedRoot(leaf, trustedRoots)) {
      result.error = 'Signing certificate does not chain to any trusted root';
      return result;
    }
    result.details.trustAnchored = true;
    if (!isCertValidAt(leaf, options.now ?? new Date())) {
      result.error = `Signing certificate is outside its validity window (${leaf.validFrom} – ${leaf.validTo})`;
      return result;
    }
  }

  for (const signature of envelope.signatures) {
    try {
      const sigBuffer = decodeBase64ToBuffer(signature.sig);
      if (crypto.verify(null, pae, leaf.publicKey, sigBuffer)) {
        result.details.signaturesVerified += 1;
        result.verified = true;
        break;
      }
    } catch {
      // try the next signature
    }
  }

  if (!result.verified && !result.error) {
    result.error = 'DSSE signature does not verify against the bundle certificate';
  }

  if (result.verified && options.expectedIdentity) {
    if (result.details.signerIdentity !== options.expectedIdentity) {
      result.verified = false;
      result.error = `Signer identity "${result.details.signerIdentity}" does not match expected "${options.expectedIdentity}"`;
    }
  }

  return result;
}

/**
 * Verifies signature material from any attestation file content: a DSSE
 * Sigstore bundle, a bare DSSE envelope, or {dsseEnvelope} wrapper.
 */
export function verifyAttestationSignature(
  content: string | Buffer,
  options: CosignVerifyOptions = {}
): CosignVerificationResult {
  let parsed: any;
  try {
    const text = typeof content === 'string' ? content : content.toString('utf8');
    // JSONL attestations: verify the last parseable line.
    const candidate =
      text.trim().includes('\n') && !text.trim().startsWith('{')
        ? text.trim().split('\n').filter(Boolean).pop()
        : text;
    parsed = JSON.parse(candidate!);
  } catch (err: any) {
    return {
      verified: false,
      error: `Attestation is not valid JSON: ${err.message}`,
      details: { signaturesTotal: 0, signaturesVerified: 0, trustAnchored: false },
    };
  }

  if (parsed?.dsseEnvelope) {
    // Sigstore bundle wrapper: { mediaType, verificationMaterial, dsseEnvelope }
    return verifySigstoreBundle(parsed as SigstoreBundle, options);
  }

  if (parsed?.payload && Array.isArray(parsed?.signatures)) {
    // Bare DSSE envelope: no certificate, so verification falls back to
    // operator-provided trusted keys.
    return verifySigstoreBundle({ mediaType: "", dsseEnvelope: parsed } as SigstoreBundle, options);
  }

  return {
    verified: false,
    error:
      'Attestation carries no DSSE envelope or signature — a subject digest match is not a signature',
    details: { signaturesTotal: 0, signaturesVerified: 0, trustAnchored: false },
  };
}
