import { describe, it, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { program } from '../../src/cli/index.js';

describe('Chainproof CLI Application', () => {
  const cliScript = path.resolve('dist/cli/index.js');

  describe('Commander Configuration & Flag Parsing', () => {
    it('should be configured with correct name and version', () => {
      expect(program.name()).toBe('chainproof');
      expect(program.description()).toContain('Supply Chain Security');
    });

    it('should have verify command with all required options', () => {
      const verifyCmd = program.commands.find(c => c.name() === 'verify');
      expect(verifyCmd).toBeDefined();

      const optionNames = verifyCmd?.options.map(o => o.long || o.short);
      expect(optionNames).toContain('--sbom');
      expect(optionNames).toContain('--attestation');
      expect(optionNames).toContain('--provenance');
      expect(optionNames).toContain('--cve-scan');
      expect(optionNames).toContain('--policy');
      expect(optionNames).toContain('--slsa-level');
      expect(optionNames).toContain('--max-cve-severity');
      expect(optionNames).toContain('--json');
    });

    it('should have report command with config and output options', () => {
      const reportCmd = program.commands.find(c => c.name() === 'report');
      expect(reportCmd).toBeDefined();

      const optionNames = reportCmd?.options.map(o => o.long || o.short);
      expect(optionNames).toContain('--config');
      expect(optionNames).toContain('--policy');
      expect(optionNames).toContain('--output');
      expect(optionNames).toContain('--json');
    });

    it('should have inspect-sbom command', () => {
      const inspectSbomCmd = program.commands.find(c => c.name() === 'inspect-sbom');
      expect(inspectSbomCmd).toBeDefined();
      expect(inspectSbomCmd?.registeredArguments[0].name()).toBe('sbom-file');
    });

    it('should have inspect-provenance command', () => {
      const inspectProvCmd = program.commands.find(c => c.name() === 'inspect-provenance');
      expect(inspectProvCmd).toBeDefined();
      expect(inspectProvCmd?.registeredArguments[0].name()).toBe('prov-file');
    });
  });

  describe('CLI Command Execution & Exit Codes', () => {
    it('should exit with 0 on --help', () => {
      const output = execSync(`node "${cliScript}" --help`, { encoding: 'utf8' });
      expect(output).toContain('Usage: chainproof');
      expect(output).toContain('verify');
      expect(output).toContain('report');
      expect(output).toContain('inspect-sbom');
      expect(output).toContain('inspect-provenance');
    });

    it('should exit with 0 on --version', () => {
      const output = execSync(`node "${cliScript}" --version`, { encoding: 'utf8' });
      expect(output.trim()).toBe('1.0.0');
    });

    it('should exit with 0 and output valid JSON on inspect-sbom --json', () => {
      const output = execSync(`node "${cliScript}" inspect-sbom sbom.json --json`, { encoding: 'utf8' });
      const parsed = JSON.parse(output);
      expect(parsed.format).toBe('cyclonedx');
      expect(parsed.components.length).toBeGreaterThan(0);
      expect(parsed.rawSha256).toHaveLength(64);
    });

    it('should exit with 0 on inspect-sbom with human readable text format', () => {
      const output = execSync(`node "${cliScript}" inspect-sbom sbom.json`, { encoding: 'utf8' });
      expect(output).toContain('Format:');
      expect(output).toContain('CYCLONEDX');
      expect(output).toContain('Total Components:');
      expect(output).toContain('Sample Components');
    });

    it('should exit with code 2 when inspecting non-existent SBOM file', () => {
      let exitCode = 0;
      try {
        execSync(`node "${cliScript}" inspect-sbom non-existent-file.json`, { stdio: 'pipe' });
      } catch (err: any) {
        exitCode = err.status;
      }
      expect(exitCode).toBe(2);
    });

    it('should exit with code 0 on inspect-provenance ATTESTATION.jsonl', () => {
      const output = execSync(`node "${cliScript}" inspect-provenance ATTESTATION.jsonl --json`, { encoding: 'utf8' });
      const parsed = JSON.parse(output);
      expect(parsed.level).toBeDefined();
      expect(parsed.reasons).toBeInstanceOf(Array);
    });

    it('should exit with code 2 when inspecting non-existent provenance file', () => {
      let exitCode = 0;
      try {
        execSync(`node "${cliScript}" inspect-provenance missing-prov.json`, { stdio: 'pipe' });
      } catch (err: any) {
        exitCode = err.status;
      }
      expect(exitCode).toBe(2);
    });

    it('should exit with code 2 when verifying non-existent artifact', () => {
      let exitCode = 0;
      try {
        execSync(`node "${cliScript}" verify non-existent-release.zip`, { stdio: 'pipe' });
      } catch (err: any) {
        exitCode = err.status;
      }
      expect(exitCode).toBe(2);
    });

    it('should exit with code 2 when fleet config does not exist', () => {
      let exitCode = 0;
      try {
        execSync(`node "${cliScript}" report --config non-existent-fleet.json`, { stdio: 'pipe' });
      } catch (err: any) {
        exitCode = err.status;
      }
      expect(exitCode).toBe(2);
    });

    it('should execute verify command with --json flag and return structured result on policy evaluation', () => {
      let output = '';
      let exitCode = 0;
      try {
        output = execSync(
          `node "${cliScript}" verify billflow-release.zip --sbom sbom.json --attestation billflow-release.sbom.sigstore.json --slsa-level 1 --max-cve-severity CRITICAL --json`,
          { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
        );
      } catch (err: any) {
        exitCode = err.status;
        output = err.stdout ? err.stdout.toString('utf8') : '';
      }
      expect(exitCode).toBe(1); // Fails default policy because provenance is required
      const parsed = JSON.parse(output);
      expect(parsed.artifactSha256).toHaveLength(64);
      expect(parsed.attestationVerified).toBe(true);
      expect(parsed.signatureVerified).toBe(true);
      expect(parsed.policyResult).toBeDefined();
    });

    it('should exit with code 0 when verifying artifact against satisfied custom policy', () => {
      const tempPolicyPath = path.resolve('temp-test-policy.json');
      fs.writeFileSync(
        tempPolicyPath,
        JSON.stringify({
          requireSbom: true,
          requireSignature: true,
          requireProvenance: false,
          maxAllowedCveSeverity: 'CRITICAL'
        }),
        'utf8'
      );

      try {
        const output = execSync(
          `node "${cliScript}" verify billflow-release.zip --sbom sbom.json --attestation billflow-release.sbom.sigstore.json --policy "${tempPolicyPath}" --json`,
          { encoding: 'utf8' }
        );
        const parsed = JSON.parse(output);
        expect(parsed.verified).toBe(true);
        expect(parsed.artifactSha256).toHaveLength(64);
      } finally {
        if (fs.existsSync(tempPolicyPath)) {
          fs.unlinkSync(tempPolicyPath);
        }
      }
    });

    it('should execute fleet report command with --json output', () => {
      let output = '';
      try {
        output = execSync(`node "${cliScript}" report --config fleet.config.json --json`, {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (err: any) {
        output = err.stdout ? err.stdout.toString('utf8') : '';
      }
      const parsed = JSON.parse(output);
      expect(parsed.totalRepositories).toBeGreaterThan(0);
      expect(parsed.repositories).toBeInstanceOf(Array);
      expect(parsed.timestamp).toBeDefined();
    });
  });
});

