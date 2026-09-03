# AUDIT LOG — chainproof

## [2026-08-15] HERMES v6 Full Audit, Bug Fixing, Hardening & Massive Test Suite Expansion

### System Environment & Tooling
- OS: Windows
- TypeScript (`typescript@^6.0.3`)
- Compiler target: `ES2022`, module: `nodenext`
- Test Runner: Vitest (`vitest@^4.1.10`)
- Module system: ESM (`"type": "module"`)

### Executed Gates & Results
1. **TypeScript Typecheck (`npm run typecheck`)**:
   - Exit Code: 0
   - Output: Clean pass (0 type errors).

2. **Production Build (`npm run build`)**:
   - Exit Code: 0
   - Output: Full compilation to `dist/` with executable CLI binaries.

3. **Vitest Comprehensive Test Suite (`npm test`)**:
   - Exit Code: 0
   - Summary: 15 test files, 164 tests passed (0 failed, 0 skipped).

### Key Bugs Fixed & Hardening Applied
- **SBOM Multi-Algorithm Hash Validation**: Fixed hardcoded SHA-256 fallback in `verifySBOMIntegrity` to correctly support SHA-1, SHA-512, and validate illegal hash lengths and unsupported algorithms.
- **SLSA Provenance & Pinned Dependency Check**: Fixed policy engine checking string truthiness (`Boolean(commitSha)`) rather than cryptographic SHA validity (`isPinnedCommitSha(commitSha)`), preventing unpinned branch names from falsely passing.
- **In-toto Attestation Integrity**: Hardened `isValidInTotoStatement` to reject empty digest objects and whitespace subject names; normalized digest algorithm keys in `verifySubjectDigest`.
- **Policy Engine Rule Expansion**: Added `allowedLicenses` policy evaluation rule to check compliance against whitelist licenses, complementing `prohibitedLicenses`.
- **Path Traversal & Injection Prevention**: Enhanced `sanitizePath` to reject whitespace-only paths and sanitize base directories against null-byte injection.
- **CLI Exit Codes & Error Handling**: Verified exit codes (0 = Pass, 1 = Policy Failure, 2 = Error/Missing file), and added full end-to-end command execution tests.
- **Vitest Runner Standardization**: Created canonical `vitest.config.ts`, configured ESM in `package.json`, and removed stale/temporary artifacts.

### Gate Summary
- **Typecheck**: PASS
- **Tests**: 164/164 PASS (15 suites)
- **Build**: PASS
- **Status**: FULLY VERIFIED & HARDENED (HERMES v6 Standard)
