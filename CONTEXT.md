# CONTEXT.md — Ubiquitous Domain Language (ChainProof)

## Core Entities
- **InTotoStatement**: Structured cryptographic predicate declaring the materials, builder, and output artifact hashes.
- **CosignAttestation**: Cryptographic signature generated via OIDC identity tokens and Rekor transparency logs.
- **SlsaProvenance**: Software Supply Chain Levels for Software Artifacts compliance specification.
- **RekorEntryTimestamp**: Cryptographic timestamp proving signature publication before certificate expiration.

## Domain Invariants
- Artifact SHA-256 digest must match the in-toto `subject.digest.sha256` value exactly.
- Attestation signatures must trace to trusted OIDC issuer roots.

## Forbidden Terminology
- Do not call attestations "checksums"; use "CryptographicAttestation".
- Do not refer to supply chain checks as "security scans"; use "ProvenanceVerification".
