import * as fs from 'fs';
import * as path from 'path';
import { FleetConfig, FleetSummary, RepoEvaluationSummary, PolicyConfig } from '../types/index.js';
import { safeJsonParse } from '../utils/json.js';
import { ChainproofVerifier } from '../verifier/index.js';
import { PRESET_POLICIES } from '../policy/engine.js';
import { sanitizePath } from '../utils/security.js';

export class FleetAggregator {
  /**
   * Evaluates all repositories in a fleet config and generates a comprehensive summary.
   */
  public static evaluateFleet(configPathOrObj: string | FleetConfig, defaultPolicy?: PolicyConfig): FleetSummary {
    let config: FleetConfig;

    if (typeof configPathOrObj === 'string') {
      const safeConfigPath = sanitizePath(configPathOrObj);
      if (!fs.existsSync(safeConfigPath)) {
        throw new Error(`Fleet config not found at: ${safeConfigPath}`);
      }
      const raw = fs.readFileSync(safeConfigPath, 'utf8');
      const parsed = safeJsonParse<FleetConfig>(raw);
      if (!parsed.success || !parsed.data) {
        throw new Error(`Failed to parse fleet config: ${parsed.error}`);
      }
      config = parsed.data;
    } else {
      config = configPathOrObj;
    }

    if (!Array.isArray(config.repositories)) {
      throw new Error('Fleet configuration must contain a "repositories" array');
    }

    const policy = config.policy || defaultPolicy || PRESET_POLICIES.default;
    const summaries: RepoEvaluationSummary[] = [];

    for (const repoPath of config.repositories) {
      const repoName = path.basename(repoPath);
      const errors: string[] = [];

      if (!fs.existsSync(repoPath)) {
        summaries.push({
          repoPath,
          repoName,
          status: 'ERROR',
          artifactPresent: false,
          sbomPresent: false,
          signaturePresent: false,
          attestationPresent: false,
          provenancePresent: false,
          slsaLevel: 0,
          criticalCves: 0,
          highCves: 0,
          mediumCves: 0,
          lowCves: 0,
          policyViolations: [`Repository path does not exist: ${repoPath}`],
          errors: [`Path not found: ${repoPath}`]
        });
        continue;
      }

      // Check standard files
      const zipPath = path.join(repoPath, 'release.zip');
      const altZipPath = path.join(repoPath, `${repoName}-release.zip`);
      const artifactPath = fs.existsSync(zipPath) ? zipPath : fs.existsSync(altZipPath) ? altZipPath : zipPath;

      const sbomPath = path.join(repoPath, 'sbom.json');
      const cvePath = path.join(repoPath, 'cve-scan.txt');
      const altCvePath = path.join(repoPath, 'cve-scan-utf8.txt');
      const chosenCvePath = fs.existsSync(cvePath) ? cvePath : fs.existsSync(altCvePath) ? altCvePath : cvePath;

      const sigPath = path.join(repoPath, 'release.zip.sigstore.json');
      const altSigPath = path.join(repoPath, `${repoName}-release.zip.sigstore.json`);
      const chosenSigPath = fs.existsSync(sigPath) ? sigPath : fs.existsSync(altSigPath) ? altSigPath : undefined;

      const attPath = path.join(repoPath, 'release.sbom.sigstore.json');
      const altAttPath = path.join(repoPath, `${repoName}-release.sbom.sigstore.json`);
      const chosenAttPath = fs.existsSync(attPath) ? attPath : fs.existsSync(altAttPath) ? altAttPath : chosenSigPath;

      const provPath = path.join(repoPath, 'provenance.intoto.jsonl');
      const chosenProvPath = fs.existsSync(provPath) ? provPath : undefined;

      const artifactPresent = fs.existsSync(artifactPath);
      const sbomPresent = fs.existsSync(sbomPath);
      const signaturePresent = Boolean(chosenSigPath && fs.existsSync(chosenSigPath));
      const attestationPresent = Boolean(chosenAttPath && fs.existsSync(chosenAttPath));
      const provenancePresent = Boolean(chosenProvPath && fs.existsSync(chosenProvPath));

      if (!artifactPresent) {
        summaries.push({
          repoPath,
          repoName,
          status: 'FAIL',
          artifactPresent: false,
          sbomPresent,
          signaturePresent,
          attestationPresent,
          provenancePresent,
          slsaLevel: 0,
          criticalCves: 0,
          highCves: 0,
          mediumCves: 0,
          lowCves: 0,
          policyViolations: ['Release artifact not found in repository'],
          errors: ['Artifact missing']
        });
        continue;
      }

      const verifyRes = ChainproofVerifier.verify({
        artifactPath,
        sbomPath: sbomPresent ? sbomPath : undefined,
        attestationPath: chosenAttPath,
        provenancePath: chosenProvPath,
        cveScanPath: fs.existsSync(chosenCvePath) ? chosenCvePath : undefined,
        policy
      });

      const criticalCves = verifyRes.vulnerabilities?.summary.CRITICAL || 0;
      const highCves = verifyRes.vulnerabilities?.summary.HIGH || 0;
      const mediumCves = verifyRes.vulnerabilities?.summary.MEDIUM || 0;
      const lowCves = verifyRes.vulnerabilities?.summary.LOW || 0;

      summaries.push({
        repoPath,
        repoName,
        status: verifyRes.verified ? 'PASS' : 'FAIL',
        artifactPresent: true,
        sbomPresent,
        signaturePresent,
        attestationPresent,
        provenancePresent,
        slsaLevel: verifyRes.slsaLevelAchieved,
        criticalCves,
        highCves,
        mediumCves,
        lowCves,
        policyViolations: verifyRes.policyResult.failures,
        errors: verifyRes.errors
      });
    }

    const passedCount = summaries.filter(s => s.status === 'PASS').length;
    const failedCount = summaries.filter(s => s.status === 'FAIL').length;
    const errorCount = summaries.filter(s => s.status === 'ERROR').length;

    return {
      timestamp: new Date().toISOString(),
      totalRepositories: summaries.length,
      passedCount,
      failedCount,
      errorCount,
      overallStatus: failedCount === 0 && errorCount === 0 ? 'PASS' : 'FAIL',
      repositories: summaries
    };
  }

  /**
   * Formats a fleet evaluation summary as a rich Markdown report.
   */
  public static generateMarkdownReport(summary: FleetSummary): string {
    let md = `# CHAINPROOF — Fleet Supply Chain Security Report\n\n`;
    md += `**Evaluation Timestamp**: ${summary.timestamp}  \n`;
    md += `**Overall Status**: ${summary.overallStatus === 'PASS' ? '✅ **PASS**' : '❌ **FAIL**'}  \n`;
    md += `**Repositories**: ${summary.totalRepositories} total (${summary.passedCount} passed, ${summary.failedCount} failed, ${summary.errorCount} errors)\n\n`;

    md += `## Fleet Matrix\n\n`;
    md += `| Repository | Status | SLSA Level | SBOM | Signature | Provenance | CVEs (C/H/M/L) | Violations |\n`;
    md += `|------------|--------|------------|------|-----------|------------|----------------|------------|\n`;

    for (const r of summary.repositories) {
      const statusEmoji = r.status === 'PASS' ? '✅ PASS' : r.status === 'FAIL' ? '❌ FAIL' : '⚠️ ERROR';
      const sbomIcon = r.sbomPresent ? '✅' : '❌';
      const sigIcon = r.signaturePresent ? '✅' : '❌';
      const provIcon = r.provenancePresent ? '✅' : '❌';
      const cves = `${r.criticalCves}/${r.highCves}/${r.mediumCves}/${r.lowCves}`;
      const violations = r.policyViolations.length > 0 ? r.policyViolations.join('; ') : 'None';

      md += `| **${r.repoName}** | ${statusEmoji} | Level ${r.slsaLevel} | ${sbomIcon} | ${sigIcon} | ${provIcon} | ${cves} | ${violations} |\n`;
    }

    md += `\n---\n*Generated by Chainproof HERMES v6 Engine*\n`;
    return md;
  }
}
