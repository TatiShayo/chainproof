import { PolicyConfig, PolicyEvaluationResult, PolicyRuleResult, UnifiedSBOM, VulnerabilityReport } from '../types/index.js';
import { evaluateSLSALevel, verifyBuilder, verifySourceRepo, isPinnedCommitSha } from '../provenance/slsa.js';
import { evaluateVulnerabilityThreshold } from '../vulnerability/matcher.js';
import { detectTamperedSBOM } from '../sbom/index.js';

export const PRESET_POLICIES: Record<string, PolicyConfig> = {
  default: {
    minSlsaLevel: 1,
    requireSbom: true,
    requireSignature: false,
    requireProvenance: true,
    maxAllowedCveSeverity: 'CRITICAL',
    requirePinnedDependencies: false
  },
  'slsa-l1': {
    minSlsaLevel: 1,
    requireProvenance: true
  },
  'slsa-l2': {
    minSlsaLevel: 2,
    requireProvenance: true,
    requireSignature: true,
    requirePinnedDependencies: true
  },
  'slsa-l3': {
    minSlsaLevel: 3,
    requireProvenance: true,
    requireSignature: true,
    requirePinnedDependencies: true,
    requireSbom: true
  },
  strict: {
    minSlsaLevel: 2,
    requireSbom: true,
    requireSignature: true,
    requireProvenance: true,
    maxAllowedCveSeverity: 'HIGH',
    requirePinnedDependencies: true
  }
};

export class PolicyEngine {
  private config: PolicyConfig;

  constructor(config: PolicyConfig = PRESET_POLICIES.default) {
    this.config = config;
  }

  public getConfig(): PolicyConfig {
    return this.config;
  }

  /**
   * Evaluates supply chain artifacts against configured policies.
   */
  public evaluate(context: {
    provenance?: any;
    sbom?: UnifiedSBOM;
    vulnerabilities?: VulnerabilityReport;
    signaturePresent?: boolean;
    attestationPresent?: boolean;
  }): PolicyEvaluationResult {
    const rules: PolicyRuleResult[] = [];
    const failures: string[] = [];
    const warnings: string[] = [];

    // 1. Check SLSA Provenance Requirement & Level
    const provenanceRequired = this.config.requireProvenance === true || (this.config.requireProvenance !== false && Boolean(this.config.minSlsaLevel));
    if (provenanceRequired) {
      if (!context.provenance) {
        const msg = 'SLSA provenance is required by policy but was not provided or found';
        rules.push({ rule: 'require-provenance', status: 'FAIL', message: msg });
        failures.push(msg);
      } else {
        rules.push({ rule: 'require-provenance', status: 'PASS', message: 'SLSA provenance is present' });

        const slsaEval = evaluateSLSALevel(context.provenance);
        const requiredLevel = this.config.minSlsaLevel || 1;

        if (slsaEval.level >= requiredLevel) {
          rules.push({
            rule: `min-slsa-level-${requiredLevel}`,
            status: 'PASS',
            message: `Artifact satisfies SLSA Level ${slsaEval.level} (required: Level ${requiredLevel})`,
            details: slsaEval
          });
        } else {
          const msg = `Artifact achieved SLSA Level ${slsaEval.level}, which is below required Level ${requiredLevel}. Reasons: ${slsaEval.reasons.join('; ')}`;
          rules.push({
            rule: `min-slsa-level-${requiredLevel}`,
            status: 'FAIL',
            message: msg,
            details: slsaEval
          });
          failures.push(msg);
        }

        // Check Allowed Builders
        if (this.config.allowedBuilders && this.config.allowedBuilders.length > 0) {
          const builderCheck = verifyBuilder(context.provenance, this.config.allowedBuilders);
          if (builderCheck.allowed) {
            rules.push({
              rule: 'allowed-builders',
              status: 'PASS',
              message: `Builder "${builderCheck.builderId}" is trusted by policy`,
              details: builderCheck
            });
          } else {
            const msg = `Builder "${builderCheck.builderId}" is not in the allowed builders list (${this.config.allowedBuilders.join(', ')})`;
            rules.push({ rule: 'allowed-builders', status: 'FAIL', message: msg, details: builderCheck });
            failures.push(msg);
          }
        }

        // Check Allowed Source Repos
        if (this.config.allowedSourceRepos && this.config.allowedSourceRepos.length > 0) {
          const repoCheck = verifySourceRepo(context.provenance, this.config.allowedSourceRepos);
          if (repoCheck.allowed) {
            rules.push({
              rule: 'allowed-source-repos',
              status: 'PASS',
              message: `Source repo "${repoCheck.repoUri}" is in allowed list`,
              details: repoCheck
            });
          } else {
            const msg = `Source repo "${repoCheck.repoUri}" is not in the allowed repositories list (${this.config.allowedSourceRepos.join(', ')})`;
            rules.push({ rule: 'allowed-source-repos', status: 'FAIL', message: msg, details: repoCheck });
            failures.push(msg);
          }
        }

        // Check Pinned Dependencies
        if (this.config.requirePinnedDependencies) {
          const isPinned = isPinnedCommitSha(slsaEval.commitSha);
          if (isPinned) {
            rules.push({
              rule: 'require-pinned-dependencies',
              status: 'PASS',
              message: `Source dependency is pinned to commit SHA: ${slsaEval.commitSha}`
            });
          } else {
            const msg = 'Source dependency is not cryptographically pinned to a full commit SHA';
            rules.push({ rule: 'require-pinned-dependencies', status: 'FAIL', message: msg });
            failures.push(msg);
          }
        }
      }
    }

    // 2. Check Signature Requirement
    if (this.config.requireSignature) {
      if (context.signaturePresent || context.attestationPresent) {
        rules.push({ rule: 'require-signature', status: 'PASS', message: 'Cryptographic signature / attestation verified' });
      } else {
        const msg = 'Cryptographic signature is required by policy but was not verified or missing';
        rules.push({ rule: 'require-signature', status: 'FAIL', message: msg });
        failures.push(msg);
      }
    }

    // 3. Check SBOM Requirement & Tampering
    if (this.config.requireSbom) {
      if (!context.sbom) {
        const msg = 'Software Bill of Materials (SBOM) is required by policy but was not provided or found';
        rules.push({ rule: 'require-sbom', status: 'FAIL', message: msg });
        failures.push(msg);
      } else {
        rules.push({
          rule: 'require-sbom',
          status: 'PASS',
          message: `SBOM is present in ${context.sbom.format.toUpperCase()} format with ${context.sbom.components.length} components`
        });

        // Check for tampered/corrupted SBOM
        const tamperCheck = detectTamperedSBOM(context.sbom);
        if (tamperCheck.tampered) {
          const msg = `SBOM tampering / malformation detected: ${tamperCheck.issues.join('; ')}`;
          rules.push({ rule: 'sbom-integrity', status: 'FAIL', message: msg, details: tamperCheck });
          failures.push(msg);
        } else {
          rules.push({ rule: 'sbom-integrity', status: 'PASS', message: 'SBOM structure and component integrity verified' });
        }

        // Check allowed licenses
        if (this.config.allowedLicenses && this.config.allowedLicenses.length > 0) {
          const allowed = this.config.allowedLicenses.map(l => l.toUpperCase());
          const unapproved: Array<{ component: string; license: string }> = [];

          for (const comp of context.sbom.components) {
            if (comp.licenses.length === 0) {
              unapproved.push({ component: comp.name, license: 'UNSPECIFIED' });
            } else {
              for (const lic of comp.licenses) {
                if (!allowed.includes(lic.toUpperCase())) {
                  unapproved.push({ component: comp.name, license: lic });
                }
              }
            }
          }

          if (unapproved.length > 0) {
            const msg = `Found ${unapproved.length} components with unapproved licenses: ${unapproved.map(f => `${f.component} (${f.license})`).join(', ')}`;
            rules.push({ rule: 'allowed-licenses', status: 'FAIL', message: msg, details: unapproved });
            failures.push(msg);
          } else {
            rules.push({ rule: 'allowed-licenses', status: 'PASS', message: 'All component licenses are approved by policy' });
          }
        }

        // Check prohibited licenses
        if (this.config.prohibitedLicenses && this.config.prohibitedLicenses.length > 0) {
          const prohibited = this.config.prohibitedLicenses.map(l => l.toUpperCase());
          const foundProhibited: Array<{ component: string; license: string }> = [];

          for (const comp of context.sbom.components) {
            for (const lic of comp.licenses) {
              if (prohibited.includes(lic.toUpperCase())) {
                foundProhibited.push({ component: comp.name, license: lic });
              }
            }
          }

          if (foundProhibited.length > 0) {
            const msg = `Found ${foundProhibited.length} components with prohibited licenses: ${foundProhibited.map(f => `${f.component} (${f.license})`).join(', ')}`;
            rules.push({ rule: 'prohibited-licenses', status: 'FAIL', message: msg, details: foundProhibited });
            failures.push(msg);
          } else {
            rules.push({ rule: 'prohibited-licenses', status: 'PASS', message: 'No prohibited licenses detected' });
          }
        }
      }
    }

    // 4. Check Vulnerability Thresholds
    if (this.config.maxAllowedCveSeverity && context.vulnerabilities) {
      const vulnEval = evaluateVulnerabilityThreshold(context.vulnerabilities, this.config.maxAllowedCveSeverity);
      if (vulnEval.pass) {
        rules.push({
          rule: `max-cve-severity-${this.config.maxAllowedCveSeverity}`,
          status: 'PASS',
          message: `Vulnerability threshold satisfied (no CVEs >= ${this.config.maxAllowedCveSeverity})`,
          details: vulnEval.countBySeverity
        });
      } else {
        const msg = `Found ${vulnEval.violations.length} vulnerabilities violating maximum allowed severity "${this.config.maxAllowedCveSeverity}": ${vulnEval.violations.map(v => `${v.name}@${v.installedVersion} [${v.vulnerabilityId}:${v.severity}]`).join(', ')}`;
        rules.push({
          rule: `max-cve-severity-${this.config.maxAllowedCveSeverity}`,
          status: 'FAIL',
          message: msg,
          details: vulnEval
        });
        failures.push(msg);
      }
    }

    return {
      passed: failures.length === 0,
      rules,
      failures,
      warnings
    };
  }
}
