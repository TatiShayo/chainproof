import { describe, it, expect } from "vitest";
import { verifySubjectDigest } from "../../src/attestation/intoto.js";
import { evaluateSLSALevel } from "../../src/provenance/slsa.js";
import { sanitizePath, computeSha256 } from "../../src/utils/security.js";

describe("Chainproof Cosign & SLSA In-Toto Verification", () => {
  it("verifies matching subject digest against artifact sha256", () => {
    const artifact = Buffer.from("production release binary v1.0.0");
    const sha = computeSha256(artifact);

    const statement = {
      _type: "https://in-toto.io/Statement/v0.1",
      predicateType: "https://slsa.dev/provenance/v0.2",
      subject: [
        {
          name: "release.tar.gz",
          digest: {
            sha256: sha,
          },
        },
      ],
      predicate: {},
    };

    const isMatch = verifySubjectDigest(statement as any, "release.tar.gz", sha);
    expect(isMatch.match).toBe(true);

    const isMismatched = verifySubjectDigest(statement as any, "release.tar.gz", "0000000000000000000000000000000000000000000000000000000000000000");
    expect(isMismatched.match).toBe(false);
  });

  it("evaluates SLSA level based on builder and source requirements", () => {
    const minimalProvenance = {
      builder: { id: "https://github.com/actions/runner" },
      buildType: "https://github.com/actions/workflow@v1",
      invocation: { configSource: { uri: "git+https://github.com/org/repo" } },
    };

    const evaluation = evaluateSLSALevel(minimalProvenance as any);
    expect(evaluation.level).toBeGreaterThanOrEqual(1);
  });

  it("prevents path traversal escapes when resolving artifacts", () => {
    expect(() => {
      sanitizePath("../../etc/shadow", process.cwd());
    }).toThrow(/traversal/i);
  });
});
