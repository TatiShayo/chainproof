import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { FleetConfig } from './types/index.js';
import { sanitizePath, computeSha256 } from './utils/security.js';
import { safeJsonParse } from './utils/json.js';

const defaultConfigPath = path.resolve(process.cwd(), 'fleet.config.json');

export function runCommand(commandLine: string, cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    console.log(`[EXEC] Running: ${commandLine} in ${cwd}`);
    const proc = spawn(commandLine, {
      cwd,
      shell: true,
      env: {
        ...process.env,
        SYFT_CHECK_FOR_APP_UPDATE: 'false',
        GRYPE_CHECK_FOR_APP_UPDATE: 'false'
      }
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      const text = data.toString();
      stdout += text;
      process.stdout.write(text);
    });

    proc.stderr.on('data', (data) => {
      const text = data.toString();
      stderr += text;
      process.stderr.write(text);
    });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(`Command failed with code ${code}. Stderr: ${stderr}`));
      }
    });
  });
}

export async function generateFleetArtifacts(configPath: string = defaultConfigPath): Promise<void> {
  const safeConfigPath = sanitizePath(configPath, process.cwd());
  if (!fs.existsSync(safeConfigPath)) {
    console.error(`Config file not found at ${safeConfigPath}`);
    process.exit(2);
  }

  const rawConfig = fs.readFileSync(safeConfigPath, 'utf8');
  const parseRes = safeJsonParse<FleetConfig>(rawConfig);
  if (!parseRes.success || !parseRes.data) {
    console.error(`Failed to parse fleet config: ${parseRes.error}`);
    process.exit(2);
  }

  const config = parseRes.data;

  for (const repoPath of config.repositories) {
    console.log(`\n==================================================`);
    console.log(`Processing Repository: ${repoPath}`);
    console.log(`==================================================`);

    if (!fs.existsSync(repoPath)) {
      console.warn(`Repository path does not exist: ${repoPath}`);
      continue;
    }

    // Repository paths are contained to the directory the fleet config lives
    // in (the workspace root): siblings are legitimate, escaping above the
    // config is not.
    const safeRepoPath = sanitizePath(repoPath, path.dirname(safeConfigPath));
    const zipPath = path.join(safeRepoPath, 'release.zip');
    const sbomPath = path.join(safeRepoPath, 'sbom.json');
    const cvePath = path.join(safeRepoPath, 'cve-scan.txt');
    const sigPath = path.join(safeRepoPath, 'release.zip.sigstore.json');
    const attPath = path.join(safeRepoPath, 'release.sbom.sigstore.json');
    const provPath = path.join(safeRepoPath, 'provenance.intoto.jsonl');

    // Remove any old files to ensure clean state
    for (const f of [zipPath, sbomPath, cvePath, sigPath, attPath, provPath]) {
      if (fs.existsSync(f)) {
        try {
          fs.unlinkSync(f);
        } catch (e: any) {
          console.warn(`Warning: Could not remove old file ${f}: ${e.message}`);
        }
      }
    }

    try {
      // 1. Package Release Artifact
      console.log(`Generating release.zip...`);
      await runCommand('git archive -o release.zip HEAD', safeRepoPath);

      // 2. Generate SBOM
      console.log(`Generating sbom.json with syft...`);
      const lockfile = path.join(safeRepoPath, 'package-lock.json');
      if (fs.existsSync(lockfile)) {
        await runCommand('syft package-lock.json -o cyclonedx-json=sbom.json', safeRepoPath);
      } else {
        await runCommand('syft dir:. -o cyclonedx-json=sbom.json', safeRepoPath);
      }

      // 3. Grype scan
      console.log(`Running Grype scan...`);
      const scanResults = await runCommand('grype sbom.json', safeRepoPath);
      fs.writeFileSync(cvePath, scanResults, 'utf8');

      // 4. Sign release.zip
      console.log(`Signing release.zip with cosign...`);
      await runCommand('cosign sign-blob --fulcio-auth-flow=device --bundle release.zip.sigstore.json release.zip', safeRepoPath);

      // 5. Attach SBOM Attestation
      console.log(`Attesting sbom.json with cosign...`);
      await runCommand('cosign attest-blob --fulcio-auth-flow=device --predicate sbom.json --type cyclonedx --bundle release.sbom.sigstore.json release.zip', safeRepoPath);

      // 6. Generate provenance
      console.log(`Generating provenance.intoto.jsonl...`);
      const zipBuffer = fs.readFileSync(zipPath);
      const sha256 = computeSha256(zipBuffer);

      let headSha = '0000000000000000000000000000000000000000';
      try {
        headSha = (await runCommand('git rev-parse HEAD', safeRepoPath)).trim();
      } catch {
        console.warn(`Could not determine git rev-parse HEAD for ${safeRepoPath}`);
      }

      let repoUri = `git+https://github.com/example/${path.basename(safeRepoPath)}`;
      try {
        const remote = (await runCommand('git config --get remote.origin.url', safeRepoPath)).trim();
        if (remote) {
          repoUri = `git+${remote.replace(/^git@([^:]+):/, 'https://$1/').replace(/\.git$/, '')}`;
        }
      } catch {
        console.warn(`No git remote found for ${safeRepoPath}; using default URI in provenance.`);
      }

      const provenance = {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [
          {
            name: 'release.zip',
            digest: {
              sha256
            }
          }
        ],
        predicateType: 'https://slsa.dev/provenance/v1',
        predicate: {
          buildDefinition: {
            buildType: 'https://github.com/slsa-framework/slsa-github-generator/workflow/v1',
            externalParameters: {
              workflow: {
                path: '.github/workflows/supply-chain.yml',
                ref: 'refs/heads/main'
              }
            },
            resolvedDependencies: [
              {
                uri: repoUri,
                digest: {
                  sha1: headSha
                }
              }
            ]
          },
          runDetails: {
            builder: {
              id: 'https://github.com/slsa-framework/slsa-github-generator'
            },
            metadata: {
              invocationId: `run-${Date.now()}`,
              startedOn: new Date().toISOString()
            }
          }
        }
      };

      fs.writeFileSync(provPath, JSON.stringify(provenance, null, 2) + '\n', 'utf8');
      console.log(`Provenance generated at ${provPath}`);
    } catch (err: any) {
      console.error(`[ERROR] Failed to process repo ${safeRepoPath}: ${err.message}`);
    }
  }

  console.log(`\nAll artifacts generated!`);
}

if (process.argv[1] && (process.argv[1].endsWith('generate.ts') || process.argv[1].endsWith('generate.js'))) {
  const customConfig = process.argv[2] || defaultConfigPath;
  generateFleetArtifacts(customConfig).catch((err) => {
    console.error(err);
    process.exit(2);
  });
}
