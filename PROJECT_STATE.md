# PROJECT STATE — chainproof

**Status**: `DONE — VERIFIED (HERMES v6 Standard)`  
**Last Verified Date**: 2026-08-15  

## Executive Summary
`chainproof` is a comprehensive supply chain security engine providing:
- CycloneDX & SPDX Software Bill of Materials (SBOM) parsing, component extraction, and tampering detection.
- In-toto attestation parsing and Cosign/Sigstore DSSE envelope verification.
- SLSA Level 1, 2, and 3 provenance verification, builder validation, and pinned commit digest verification.
- Grype vulnerability scanning report integration and severity threshold enforcement.
- Fleet aggregation and Markdown supply-chain governance reporting across multi-repository workspaces.
- CLI application with strict exit codes (0 = Pass, 1 = Fail, 2 = Error).

## Verification Evidence

### 1. TypeScript Typecheck
**Command**: `npm run typecheck`  
**Exit Code**: 0  
**Output**: Clean pass (0 errors).

### 2. Vitest Test Suite
**Command**: `npm test`  
**Exit Code**: 0  
**Output**: 15 test files, 164 passing tests covering all core modules, invariants, edge cases, and CLI operations.

### 3. Production Build
**Command**: `npm run build`  
**Exit Code**: 0  
**Output**: Compiled to `dist/` with executable CLI bin.

## Structure & Deliverables
- **`src/types/index.ts`**: Complete supply chain type definitions (SLSA v1/v0.2, in-toto, CycloneDX, SPDX, Grype, Policy, Fleet).
- **`src/utils/security.ts`**: Cryptographic hash functions (SHA-256, SHA-1, SHA-512), timing-safe comparisons, path traversal defenses, base64 decoding.
- **`src/utils/json.ts`**: Safe UTF-8/UTF-16 BOM-stripping JSON parsing and circular-safe stringification.
- **`src/attestation/intoto.ts`**: In-toto statement parser, DSSE envelope extractor, subject digest verifier.
- **`src/provenance/slsa.ts`**: SLSA Level 1-3 evaluation engine, builder verifier, source repository matcher.
- **`src/sbom/cyclonedx.ts` & `src/sbom/spdx.ts`**: CycloneDX and SPDX schema validation and component extraction.
- **`src/sbom/index.ts`**: Dynamic SBOM detector, multi-algorithm integrity verifier, and anomaly detector.
- **`src/vulnerability/matcher.ts`**: Grype text table & JSON parser, SBOM component matcher, severity threshold evaluator.
- **`src/policy/engine.ts`**: Supply chain policy engine supporting presets (default, strict, slsa-l1, slsa-l2, slsa-l3) and custom policies.
- **`src/verifier/index.ts`**: Unified artifact verifier.
- **`src/fleet/aggregator.ts`**: Multi-repository fleet governance aggregator and Markdown matrix generator.
- **`src/cli/index.ts`**: Production CLI tool (`chainproof verify`, `chainproof report`, `chainproof inspect-sbom`, `chainproof inspect-provenance`).
- **`tests/`**: 15 test suites with 164 tests.
