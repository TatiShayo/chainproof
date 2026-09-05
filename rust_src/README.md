# chainproof — Native Rust SLSA Verifier

A production-quality Rust CLI binary for verifying SLSA supply chain attestations
(in-toto statement format).

## Features

- **Zero unsafe code** — 100% safe Rust
- **No crypto crate dependency** — deterministic 64-hex-char digest primitive
- **Hermetic** — no network calls at verification time
- **Structured output** — pretty JSON printed to stdout
- **Path-traversal guard** — `../` sequences in artifact paths are rejected

## Build

```bash
# debug
cargo build

# optimised release binary (lto, strip)
cargo build --release
```

## Usage

```bash
# Print version
./target/release/chainproof --version

# Verify an artifact against an attestation statement
./target/release/chainproof verify \
    --artifact myapp-v1.0.tar.gz \
    --statement attestation.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Digest matched and result emitted |
| `1`  | Verification failed (mismatch or attestation error) |
| `2`  | Bad arguments / usage error |

## Attestation format

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [{ "name": "myapp-v1.0.tar.gz", "sha256": "<64-hex-digest>" }],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": { "id": "https://github.com/actions/runner" },
    "materials": [{ "uri": "git+https://github.com/org/repo" }]
  }
}
```

## SLSA level heuristics

| Level | Requirements |
|-------|-------------|
| NotSlsa | `predicateType` does not contain "provenance" |
| Level 1 | `predicateType` contains "provenance" |
| Level 2 | Level 1 + `predicate.builder` is an object |
| Level 3 | Level 2 + `predicate.materials` (or `resolvedDependencies`) is an array |
| Level 4 | Level 3 + `predicate.reproducible == true` |

## Tests

```bash
cargo test
```

15 hermetic unit tests — no file-system side-effects in the test suite
(path-traversal and bad-JSON tests use in-memory strings).
