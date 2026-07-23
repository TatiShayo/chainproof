"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const child_process_1 = require("child_process");
const configPath = path.resolve(__dirname, '../fleet.config.json');
function runCommand(commandLine, cwd) {
    return new Promise((resolve, reject) => {
        console.log(`[EXEC] Running: ${commandLine} in ${cwd}`);
        const proc = (0, child_process_1.spawn)(commandLine, {
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
            }
            else {
                reject(new Error(`Command failed with code ${code}. Stderr: ${stderr}`));
            }
        });
    });
}
async function main() {
    if (!fs.existsSync(configPath)) {
        console.error(`Config file not found at ${configPath}`);
        process.exit(1);
    }
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    for (const repoPath of config.repositories) {
        console.log(`\n==================================================`);
        console.log(`Processing Repository: ${repoPath}`);
        console.log(`==================================================`);
        if (!fs.existsSync(repoPath)) {
            console.warn(`Repository path does not exist: ${repoPath}`);
            continue;
        }
        const zipPath = path.join(repoPath, 'release.zip');
        const sbomPath = path.join(repoPath, 'sbom.json');
        const cvePath = path.join(repoPath, 'cve-scan.txt');
        const sigPath = path.join(repoPath, 'release.zip.sigstore.json');
        const attPath = path.join(repoPath, 'release.sbom.sigstore.json');
        const provPath = path.join(repoPath, 'provenance.intoto.jsonl');
        // Remove any old files to ensure clean state
        for (const f of [zipPath, sbomPath, cvePath, sigPath, attPath, provPath]) {
            if (fs.existsSync(f)) {
                fs.unlinkSync(f);
            }
        }
        // 1. Package Release Artifact
        console.log(`Generating release.zip...`);
        await runCommand('git archive -o release.zip HEAD', repoPath);
        // 2. Generate SBOM
        console.log(`Generating sbom.json with syft...`);
        const lockfile = path.join(repoPath, 'package-lock.json');
        if (fs.existsSync(lockfile)) {
            await runCommand('syft package-lock.json -o cyclonedx-json=sbom.json', repoPath);
        }
        else {
            await runCommand('syft dir:. -o cyclonedx-json=sbom.json', repoPath);
        }
        // 3. Grype scan
        console.log(`Running Grype scan...`);
        const scanResults = await runCommand('grype sbom.json', repoPath);
        fs.writeFileSync(cvePath, scanResults, 'utf8');
        // 4. Sign release.zip
        console.log(`Signing release.zip with cosign...`);
        await runCommand('cosign sign-blob --fulcio-auth-flow=device --bundle release.zip.sigstore.json release.zip', repoPath);
        // 5. Attach SBOM Attestation
        console.log(`Attesting sbom.json with cosign...`);
        await runCommand('cosign attest-blob --fulcio-auth-flow=device --predicate sbom.json --type cyclonedx --bundle release.sbom.sigstore.json release.zip', repoPath);
        // 6. Generate provenance
        console.log(`Generating provenance.intoto.jsonl...`);
        const zipBuffer = fs.readFileSync(zipPath);
        const sha256 = crypto.createHash('sha256').update(zipBuffer).digest('hex');
        // Real source coordinates — provenance with placeholder digests is worse
        // than none, because it attests to something that never existed.
        const headSha = (await runCommand('git rev-parse HEAD', repoPath)).trim();
        let repoUri = `git+https://github.com/example/${path.basename(repoPath)}`;
        try {
            const remote = (await runCommand('git config --get remote.origin.url', repoPath)).trim();
            if (remote) {
                repoUri = `git+${remote.replace(/^git@([^:]+):/, 'https://$1/').replace(/\.git$/, '')}`;
            }
        }
        catch {
            console.warn(`No git remote found for ${repoPath}; using placeholder URI in provenance.`);
        }
        const provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "release.zip",
                    "digest": {
                        "sha256": sha256
                    }
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/slsa-framework/slsa-github-generator/workflow/v1",
                    "externalParameters": {
                        "workflow": {
                            "path": ".github/workflows/supply-chain.yml",
                            "ref": "refs/heads/main"
                        }
                    },
                    "resolvedDependencies": [
                        {
                            "uri": repoUri,
                            "digest": {
                                "sha1": headSha
                            }
                        }
                    ]
                },
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/slsa-framework/slsa-github-generator"
                    }
                }
            }
        };
        fs.writeFileSync(provPath, JSON.stringify(provenance, null, 2) + '\n', 'utf8');
        console.log(`Provenance generated at ${provPath}`);
    }
    console.log(`\nAll artifacts generated!`);
}
main().catch((err) => {
    console.error(err);
    process.exit(1);
});
