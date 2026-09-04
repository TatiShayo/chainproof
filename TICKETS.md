# TICKETS — ChainProof Supply Chain Pipeline

## [TICKET-001] In-Toto Statement & Cosign Attestation Verifier
- **Blocked by**: None
- **Delivers**: Cryptographic validator checking artifact SHA-256 digests against signed in-toto predicates.
- **Verification**: `tests/verifier/cosign-attestation-verification.test.ts`

## [TICKET-002] Air-Gapped Rekor SET Offline Bundler
- **Blocked by**: TICKET-001
- **Delivers**: Standalone verifier operating without active network connection to public transparency logs.
- **Verification**: Offline cryptographic verification tests.
