# SPEC 001: Cryptographic Supply Chain Provenance Verifier

## Problem Statement
Enterprises deploy containers without knowing if the binary in the registry matches the source code reviewed in git.

## Solution
A CLI and automated GitHub Action that inspects Cosign attestations and in-toto statements to verify SLSA Level 3 provenance.

## User Stories
1. As a security engineer, I want to block deployments of unsigned containers, so that supply chain injections are prevented.
2. As an auditor, I want an immutable record of every package's build provenance, so that compliance audits pass instantly.

## Implementation Decisions
- In-toto statement parser in `src/verifier/statement.ts`.
- Cosign signature checker in `src/verifier/cosign.ts`.

## Testing Decisions
- Seam: `tests/verifier/cosign-attestation-verification.test.ts`.
- Verify validation of valid, expired, and tampered in-toto attestation JSON payloads.
