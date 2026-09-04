# ADR 0001: In-Toto SLSA Provenance and Offline Rekor Verification

## Context
Modern software ecosystems suffer from software supply chain attacks where build artifacts are injected with malicious code.

## Decision
1. **In-Toto v0.1 Predicates**: Require canonical in-toto statements declaring all build dependencies and commit SHAs.
2. **Cosign & Rekor Verification**: Validate keyless signatures against transparency logs.
3. **Air-Gap Bundle Support**: Support offline verification via bundled Rekor SETs.

## Consequences
- **Positive**: Complete immunity against build artifact tampering and SolarWinds-style attacks.
- **Negative**: Requires strict OIDC identity federation in CI/CD pipelines.
