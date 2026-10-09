#!/usr/bin/env node
import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { ChainproofVerifier } from '../verifier/index.js';
import { FleetAggregator } from '../fleet/aggregator.js';
import { parseSBOM } from '../sbom/index.js';
import { parseSLSAProvenance, evaluateSLSALevel } from '../provenance/slsa.js';
import { PRESET_POLICIES, PolicyEngine } from '../policy/engine.js';
import { PolicyConfig, SeverityLevel } from '../types/index.js';
import { sanitizePath } from '../utils/security.js';
import { safeJsonParse } from '../utils/json.js';

export const program = new Command();

/** Commander collect helper for repeatable options. */
function collect(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}

/** Reads a PEM file, containment-checked against the given base. */
function readPem(pemPath: string, baseDir: string, label: string): string {
  const safePath = sanitizePath(pemPath, baseDir);
  if (!fs.existsSync(safePath)) {
    console.error(`[ERROR] ${label} file not found: ${safePath}`);
    process.exit(2);
  }
  return fs.readFileSync(safePath, 'utf8');
}

program
  .name('chainproof')
  .description('Chainproof HERMES v6 — Supply Chain Security, SLSA Verification & Fleet Governance')
  .version('1.0.0');

// 1. Verify Command
program
  .command('verify')
  .description('Verify an artifact against SLSA provenance, CycloneDX/SPDX SBOMs, and security policies')
  .argument('<artifact>', 'Path to the release artifact to verify')
  .option('-s, --sbom <path>', 'Path to CycloneDX or SPDX SBOM JSON file')
  .option('-a, --attestation <path>', 'Path to Cosign/Sigstore attestation bundle or in-toto statement')
  .option('-p, --provenance <path>', 'Path to SLSA provenance file')
  .option('-c, --cve-scan <path>', 'Path to Grype CVE scan report file')
  .option('--policy <path>', 'Path to custom policy JSON configuration')
  .option('--slsa-level <level>', 'Required SLSA level (1, 2, or 3)', '1')
  .option('--max-cve-severity <severity>', 'Max allowed CVE severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)', 'CRITICAL')
  .option('--trusted-key <pemFile>', 'Trusted public key (PEM) for DSSE signature verification; repeatable', collect, [])
  .option('--trusted-root <pemFile>', 'Trusted root certificate (PEM) for Sigstore bundle chains; repeatable', collect, [])
  .option('--expected-signer <identity>', 'Expected signer identity (certificate SAN email/URI)')
  .option('--json', 'Output results in JSON format', false)
  .action((artifact, options) => {
    try {
      const baseDir = process.cwd();
      let policy: PolicyConfig = { ...PRESET_POLICIES.default };

      if (options.policy) {
        const safePolicyPath = sanitizePath(options.policy, baseDir);
        if (!fs.existsSync(safePolicyPath)) {
          console.error(`[ERROR] Policy file not found: ${safePolicyPath}`);
          process.exit(2);
        }
        const parsed = safeJsonParse<PolicyConfig>(fs.readFileSync(safePolicyPath, 'utf8'));
        if (!parsed.success || !parsed.data) {
          console.error(`[ERROR] Invalid policy JSON: ${parsed.error}`);
          process.exit(2);
        }
        policy = parsed.data;
      }

      if (options.slsaLevel) {
        const lvl = parseInt(options.slsaLevel, 10);
        if (lvl >= 1 && lvl <= 3) {
          policy.minSlsaLevel = lvl as 1 | 2 | 3;
        }
      }

      if (options.maxCveSeverity) {
        policy.maxAllowedCveSeverity = options.maxCveSeverity.toUpperCase() as SeverityLevel | 'NONE';
      }

      const trustedPublicKeys = (options.trustedKey || []).map((p: string) =>
        readPem(p, baseDir, 'Trusted key')
      );
      const trustedRoots = (options.trustedRoot || []).map((p: string) =>
        readPem(p, baseDir, 'Trusted root')
      );

      const result = ChainproofVerifier.verify({
        artifactPath: artifact,
        sbomPath: options.sbom,
        attestationPath: options.attestation,
        provenancePath: options.provenance,
        cveScanPath: options.cveScan,
        policy,
        baseDir,
        trustedPublicKeys: trustedPublicKeys.length > 0 ? trustedPublicKeys : undefined,
        trustedRoots: trustedRoots.length > 0 ? trustedRoots : undefined,
        expectedSignerIdentity: options.expectedSigner
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`\n==================================================`);
        console.log(`CHAINPROOF VERIFICATION RESULT`);
        console.log(`==================================================`);
        console.log(`Artifact:    ${result.artifactPath}`);
        console.log(`SHA-256:     ${result.artifactSha256 || 'N/A'}`);
        console.log(`Status:      ${result.verified ? '✅ PASS' : '❌ FAIL'}`);
        console.log(`SLSA Level:  Level ${result.slsaLevelAchieved}`);
        console.log(`Signature:   ${result.signatureVerified ? 'Verified' : 'Not verified'}`);
        console.log(`Attestation: ${result.attestationVerified ? 'Verified' : 'Not verified'}`);

        if (result.sbom) {
          console.log(`SBOM:        ${result.sbom.format.toUpperCase()} (${result.sbom.components.length} components)`);
        }

        if (result.vulnerabilities) {
          const v = result.vulnerabilities.summary;
          console.log(`CVEs:        ${v.CRITICAL} Critical, ${v.HIGH} High, ${v.MEDIUM} Medium, ${v.LOW} Low`);
        }

        console.log(`\nPolicy Evaluation:`);
        for (const rule of result.policyResult.rules) {
          const icon = rule.status === 'PASS' ? '✅' : '❌';
          console.log(`  ${icon} [${rule.rule}]: ${rule.message}`);
        }

        if (result.errors.length > 0) {
          console.log(`\nErrors / Warnings:`);
          for (const err of result.errors) {
            console.log(`  ⚠️  ${err}`);
          }
        }
      }

      if (result.errors.length > 0 && !result.artifactSha256) {
        process.exit(2);
      }

      process.exit(result.verified ? 0 : 1);
    } catch (err: any) {
      console.error(`[ERROR] Verification encountered a system error: ${err.message}`);
      process.exit(2);
    }
  });

// 2. Report Command
program
  .command('report')
  .description('Aggregate and evaluate supply chain security for all repositories in a fleet')
  .option('-c, --config <path>', 'Path to fleet.config.json', 'fleet.config.json')
  .option('-p, --policy <path>', 'Path to policy JSON')
  .option('-o, --output <path>', 'Output path for Markdown report')
  .option('--json', 'Output results in JSON format', false)
  .action((options) => {
    try {
      const baseDir = process.cwd();
      const configPath = sanitizePath(options.config, baseDir);
      if (!fs.existsSync(configPath)) {
        console.error(`[ERROR] Fleet config not found at: ${configPath}`);
        process.exit(2);
      }

      let policy: PolicyConfig | undefined;
      if (options.policy) {
        const safePolicyPath = sanitizePath(options.policy, baseDir);
        const parsed = safeJsonParse<PolicyConfig>(fs.readFileSync(safePolicyPath, 'utf8'));
        if (!parsed.success || !parsed.data) {
          console.error(`[ERROR] Invalid policy JSON: ${parsed.error}`);
          process.exit(2);
        }
        policy = parsed.data;
      }

      const summary = FleetAggregator.evaluateFleet(configPath, policy);

      if (options.output) {
        const safeOutPath = sanitizePath(options.output, baseDir);
        const md = FleetAggregator.generateMarkdownReport(summary);
        fs.writeFileSync(safeOutPath, md, 'utf8');
        console.log(`[OK] Fleet report saved to ${safeOutPath}`);
      }

      if (options.json) {
        console.log(JSON.stringify(summary, null, 2));
      } else if (!options.output) {
        console.log(FleetAggregator.generateMarkdownReport(summary));
      }

      process.exit(summary.overallStatus === 'PASS' ? 0 : 1);
    } catch (err: any) {
      console.error(`[ERROR] Fleet report generation failed: ${err.message}`);
      process.exit(2);
    }
  });

// 3. Inspect SBOM Command
program
  .command('inspect-sbom')
  .description('Inspect and extract components from a CycloneDX or SPDX SBOM file')
  .argument('<sbom-file>', 'Path to SBOM file')
  .option('--json', 'Output raw parsed components as JSON', false)
  .action((sbomFile, options) => {
    try {
      const safePath = sanitizePath(sbomFile, process.cwd());
      if (!fs.existsSync(safePath)) {
        console.error(`[ERROR] File not found: ${safePath}`);
        process.exit(2);
      }

      const content = fs.readFileSync(safePath);
      const parsed = parseSBOM(content);

      if (options.json) {
        console.log(JSON.stringify(parsed, null, 2));
      } else {
        console.log(`Format:        ${parsed.format.toUpperCase()}`);
        console.log(`Spec Version:  ${parsed.specVersion}`);
        console.log(`Total Components: ${parsed.components.length}`);
        console.log(`SHA-256:       ${parsed.rawSha256}`);
        console.log(`\nSample Components (first 10):`);
        for (const comp of parsed.components.slice(0, 10)) {
          console.log(`  - ${comp.name} @ ${comp.version} (${comp.licenses.join(', ') || 'No license declared'})`);
        }
      }
      process.exit(0);
    } catch (err: any) {
      console.error(`[ERROR] Failed to inspect SBOM: ${err.message}`);
      process.exit(2);
    }
  });

// 4. Inspect Provenance Command
program
  .command('inspect-provenance')
  .description('Inspect SLSA provenance statement and evaluate SLSA compliance level')
  .argument('<prov-file>', 'Path to provenance JSON or in-toto JSONL file')
  .option('--json', 'Output evaluation as JSON', false)
  .action((provFile, options) => {
    try {
      const safePath = sanitizePath(provFile, process.cwd());
      if (!fs.existsSync(safePath)) {
        console.error(`[ERROR] File not found: ${safePath}`);
        process.exit(2);
      }

      const content = fs.readFileSync(safePath, 'utf8');
      const evaluation = evaluateSLSALevel(content);

      if (options.json) {
        console.log(JSON.stringify(evaluation, null, 2));
      } else {
        console.log(`Achieved SLSA Level: Level ${evaluation.level}`);
        console.log(`Builder ID:          ${evaluation.builderId || 'N/A'}`);
        console.log(`Source URI:          ${evaluation.sourceUri || 'N/A'}`);
        console.log(`Commit SHA:          ${evaluation.commitSha || 'N/A'}`);
        console.log(`\nEvaluation Reasons:`);
        for (const r of evaluation.reasons) {
          console.log(`  • ${r}`);
        }
      }
      process.exit(0);
    } catch (err: any) {
      console.error(`[ERROR] Failed to inspect provenance: ${err.message}`);
      process.exit(2);
    }
  });

if (process.argv[1] && (
  process.argv[1].includes('cli') ||
  process.argv[1].endsWith('chainproof') ||
  process.argv[1].endsWith('index.js') ||
  process.argv[1].endsWith('index.ts')
)) {
  program.parse(process.argv);
}
