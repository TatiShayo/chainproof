import { describe, it, expect } from "vitest";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  computeDSSEPAE,
  verifyDSSESignature,
  verifySigstoreBundle,
  verifyAttestationSignature,
} from "../../src/verifier/cosign.js";
import { ChainproofVerifier } from "../../src/verifier/index.js";

const REAL_BUNDLE = path.resolve("billflow-release.sbom.sigstore.json");

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=g$/, "");
}

function b64(buf: Buffer): string {
  return buf.toString("base64");
}

/** Builds a DSSE envelope signed with the given private key over `payloadObj`. */
function makeSignedEnvelope(payloadObj: unknown, privateKey: crypto.KeyObject): any {
  const payload = Buffer.from(JSON.stringify(payloadObj), "utf8");
  const pae = computeDSSEPAE("application/vnd.in-toto+json", payload);
  const signature = crypto.sign(null, pae, privateKey);
  return {
    payloadType: "application/vnd.in-toto+json",
    payload: b64(payload),
    signatures: [{ keyid: "test-key", sig: b64(signature) }],
  };
}

describe("DSSE PAE", () => {
  it("encodes the exact DSSE v1 pre-authentication format", () => {
    const pae = computeDSSEPAE("application/vnd.in-toto+json", Buffer.from("hello"));
    expect(pae.toString("utf8")).toBe("DSSEv1 28 application/vnd.in-toto+json 5 hello");
  });
});

describe("verifyDSSESignature", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pem = publicKey.export({ type: "spki", format: "pem" }) as string;

  it("verifies a correctly signed envelope against a trusted key", () => {
    const envelope = makeSignedEnvelope({ _type: "https://in-toto.io/Statement/v0.1" }, privateKey);
    const result = verifyDSSESignature(envelope, { trustedPublicKeys: [pem] });
    expect(result.verified).toBe(true);
    expect(result.details.signaturesVerified).toBe(1);
  });

  it("rejects a valid envelope signed by an untrusted key", () => {
    const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey;
    const envelope = makeSignedEnvelope({ _type: "https://in-toto.io/Statement/v0.1" }, other);
    const result = verifyDSSESignature(envelope, { trustedPublicKeys: [pem] });
    expect(result.verified).toBe(false);
    expect(result.error).toMatch(/No signature verified/);
  });

  it("rejects a tampered payload (signature no longer covers it)", () => {
    const envelope = makeSignedEnvelope({ _type: "https://in-toto.io/Statement/v0.1" }, privateKey);
    // Flip a byte in the decoded payload, re-encode.
    const payload = Buffer.from(envelope.payload, "base64");
    payload[payload.length - 2] = payload[payload.length - 2] === 0x41 ? 0x42 : 0x41;
    envelope.payload = b64(payload);

    const result = verifyDSSESignature(envelope, { trustedPublicKeys: [pem] });
    expect(result.verified).toBe(false);
  });

  it("fails closed with no key material at all", () => {
    const envelope = makeSignedEnvelope({ a: 1 }, privateKey);
    const result = verifyDSSESignature(envelope, {});
    expect(result.verified).toBe(false);
    expect(result.error).toMatch(/No trusted key material/);
  });

  it("rejects an envelope with no signatures", () => {
    const result = verifyDSSESignature({ payloadType: "application/vnd.in-toto+json", payload: b64(Buffer.from("{}")), signatures: [] }, {
      trustedPublicKeys: [pem],
    });
    expect(result.verified).toBe(false);
    expect(result.error).toMatch(/no signatures/i);
  });
});

describe("Sigstore bundle verification (real fixture)", () => {
  it("verifies the real bundle's DSSE signature against its leaf certificate", () => {
    if (!fs.existsSync(REAL_BUNDLE)) return; // fixture absent: skip
    const bundle = JSON.parse(fs.readFileSync(REAL_BUNDLE, "utf8"));
    const result = verifySigstoreBundle(bundle, {});
    expect(result.verified).toBe(true);
    expect(result.details.signerIdentity).toBeTruthy();
    expect(result.details.certificateIssuer).toContain("sigstore");
  });

  it("fails when the payload is tampered inside the real bundle", () => {
    if (!fs.existsSync(REAL_BUNDLE)) return;
    const bundle = JSON.parse(fs.readFileSync(REAL_BUNDLE, "utf8"));
    const payload = Buffer.from(bundle.dsseEnvelope.payload, "base64");
    payload[10] = payload[10] === 0x41 ? 0x42 : 0x41;
    bundle.dsseEnvelope.payload = b64(payload);

    const result = verifySigstoreBundle(bundle, {});
    expect(result.verified).toBe(false);
    expect(result.error).toMatch(/does not verify/);
  });

  it("enforces the expected signer identity when configured", () => {
    if (!fs.existsSync(REAL_BUNDLE)) return;
    const bundle = JSON.parse(fs.readFileSync(REAL_BUNDLE, "utf8"));
    const result = verifySigstoreBundle(bundle, { expectedIdentity: "someone-else@example.com" });
    expect(result.verified).toBe(false);
    expect(result.error).toMatch(/does not match expected/);
  });
});

describe("verifyAttestationSignature", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pem = publicKey.export({ type: "spki", format: "pem" }) as string;

  it("rejects a bare self-authored in-toto statement (no signature at all)", () => {
    // The pre-fix attack: author this JSON, match the subject digest, pass.
    const statement = JSON.stringify({
      _type: "https://in-toto.io/Statement/v0.1",
      predicateType: "https://slsa.dev/provenance/v0.2",
      subject: [{ name: "release.zip", digest: { sha256: "a".repeat(64) } }],
      predicate: {},
    });

    const result = verifyAttestationSignature(statement, { trustedPublicKeys: [pem] });
    expect(result.verified).toBe(false);
    expect(result.error).toMatch(/no DSSE envelope or signature/);
  });

  it("accepts a signed DSSE envelope with a trusted key", () => {
    const envelope = makeSignedEnvelope({ _type: "https://in-toto.io/Statement/v0.1" }, privateKey);
    const result = verifyAttestationSignature(JSON.stringify(envelope), { trustedPublicKeys: [pem] });
    expect(result.verified).toBe(true);
  });

  it("rejects non-JSON attestation content", () => {
    const result = verifyAttestationSignature("this is not json", { trustedPublicKeys: [pem] });
    expect(result.verified).toBe(false);
    expect(result.error).toMatch(/not valid JSON/);
  });
});

describe("end-to-end: a digest match alone never verifies the signature", () => {
  it("self-authored attestation JSON fails a requireSignature policy", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-e2e-"));
    try {
      const artifactPath = path.join(tmp, "release.zip");
      fs.writeFileSync(artifactPath, "artifact-bytes");

      const statement = {
        _type: "https://in-toto.io/Statement/v0.1",
        predicateType: "https://slsa.dev/provenance/v0.2",
        subject: [
          {
            name: "release.zip",
            digest: {
              sha256: crypto.createHash("sha256").update("artifact-bytes").digest("hex"),
            },
          },
        ],
        predicate: {},
      };
      const attPath = path.join(tmp, "attestation.json");
      fs.writeFileSync(attPath, JSON.stringify(statement));

      const result = ChainproofVerifier.verify({
        artifactPath,
        attestationPath: attPath,
        baseDir: tmp,
        policy: {
          requireSbom: false,
          requireSignature: true,
          requireProvenance: false,
        },
      });

      // The digest DOES match — the statement genuinely describes the artifact.
      expect(result.attestationVerified).toBe(true);
      // But nobody signed it, so the signature must NOT read as verified and
      // the signature-requiring policy must fail.
      expect(result.signatureVerified).toBe(false);
      expect(result.policyResult.passed).toBe(false);
      expect(result.verified).toBe(false);
      expect(result.policyResult.failures.some((f) => f.includes("Cryptographic signature is required"))).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
