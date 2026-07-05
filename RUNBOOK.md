# Runbook: manual supply chain pipeline (Phase 1)

This runbook documents the manual supply chain security pipeline executed for the `billflow` repository.

## Directory Structure

The directory `c:\Users\TATI\Desktop\DEV\chainproof` contains the following files:

- **`billflow-release.zip`**: The release artifact.
- **`sbom.json`**: Software Bill of Materials (SBOM) in CycloneDX JSON format generated via Syft.
- **`cve-scan.txt`**: Grype vulnerability scan results in text table format.
- **`cve-scan-utf8.txt`**: UTF-8 encoded copy of the Grype vulnerability scan results.
- **`billflow-release.zip.sigstore.json`**: Keyless OIDC signature bundle for the release artifact.
- **`billflow-release.sbom.sigstore.json`**: Keyless OIDC attestation bundle containing the SBOM.
- **`TASK_LEDGER.json`**: Task ledger tracking the progress of the `chainproof` pipeline phases.
- **`RUNBOOK.md`**: This document.

---

## Commands & Walkthrough

### 1. SBOM Generation
The SBOM is generated using **Syft** from the `billflow` source directory:
```bash
syft c:\Users\TATI\Desktop\DEV\billflow -o cyclonedx-json=sbom.json
```

### 2. Vulnerability Scanning
The generated SBOM is scanned for CVEs using **Grype**:
```bash
grype sbom.json > cve-scan.txt
```

### 3. Signing the Release Artifact
The zip file is signed with **cosign** using keyless OIDC signing (device flow):
```bash
cosign sign-blob --bundle billflow-release.zip.sigstore.json --fulcio-auth-flow=device billflow-release.zip
```
During execution, cosign prompts to authenticate using a verification link and code.

### 4. Attaching the SBOM Attestation
The CycloneDX SBOM is attached as a signed attestation to the release zip file using **cosign**:
```bash
cosign attest-blob --predicate sbom.json --type cyclonedx --bundle billflow-release.sbom.sigstore.json --fulcio-auth-flow=device billflow-release.zip
```
This also prompts for OIDC authentication.

---

## Verification

### 1. Verifying the Artifact Signature
```bash
cosign verify-blob \
  --bundle billflow-release.zip.sigstore.json \
  --certificate-identity tatibaraka@gmail.com \
  --certificate-oidc-issuer https://accounts.google.com \
  billflow-release.zip
```
**Output**: `Verified OK`

### 2. Verifying the SBOM Attestation
```bash
cosign verify-blob-attestation \
  --bundle billflow-release.sbom.sigstore.json \
  --certificate-identity tatibaraka@gmail.com \
  --certificate-oidc-issuer https://accounts.google.com \
  --type cyclonedx \
  billflow-release.zip
```
**Output**: `Verified OK`
