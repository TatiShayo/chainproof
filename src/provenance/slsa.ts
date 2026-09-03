import { InTotoStatement, SLSAPredicateV1, SLSAPredicateV02 } from '../types/index.js';
import { parseInTotoStatement } from '../attestation/intoto.js';

export const SLSA_PREDICATE_V1 = 'https://slsa.dev/provenance/v1';
export const SLSA_PREDICATE_V02 = 'https://slsa.dev/provenance/v0.2';

export interface SLSALevelEvaluation {
  level: 0 | 1 | 2 | 3;
  meetsLevel1: boolean;
  meetsLevel2: boolean;
  meetsLevel3: boolean;
  builderId?: string;
  sourceUri?: string;
  commitSha?: string;
  reasons: string[];
}

/**
 * Checks if a commit hash is a valid full cryptographic SHA (40 hex chars for SHA-1, 64 hex chars for SHA-256).
 */
export function isPinnedCommitSha(sha: string | undefined): boolean {
  if (!sha || typeof sha !== 'string') return false;
  const trimmed = sha.trim();
  return /^[0-9a-fA-F]{40}$/.test(trimmed) || /^[0-9a-fA-F]{64}$/.test(trimmed);
}

/**
 * Known hosted builder platforms
 */
export const KNOWN_HOSTED_BUILDERS = [
  'https://github.com/slsa-framework/slsa-github-generator',
  'https://github.com/actions/runner',
  'https://cloudbuild.googleapis.com',
  'https://tekton.dev',
  'https://gitlab.com',
  'https://circleci.com',
  'https://travis-ci.com'
];

/**
 * Checks if a builder ID belongs to a known hosted/managed build service.
 */
export function isHostedBuilder(builderId: string | undefined): boolean {
  if (!builderId || typeof builderId !== 'string') return false;
  const trimmed = builderId.trim();
  return KNOWN_HOSTED_BUILDERS.some(hb => trimmed.startsWith(hb)) || trimmed.includes('github-generator') || trimmed.includes('slsa');
}

/**
 * Parses and extracts SLSA provenance from an in-toto statement or predicate object.
 */
export function parseSLSAProvenance(input: any): { version: 'v1' | 'v0.2'; predicate: any; statement?: InTotoStatement } {
  let statement: InTotoStatement | undefined;
  let predicate: any;
  let predicateType: string = '';

  if (input._type && input.predicateType && input.predicate) {
    statement = input as InTotoStatement;
    predicateType = statement.predicateType;
    predicate = statement.predicate;
  } else if (typeof input === 'string' || Buffer.isBuffer(input)) {
    statement = parseInTotoStatement(input);
    predicateType = statement.predicateType;
    predicate = statement.predicate;
  } else if (input.buildDefinition || input.runDetails) {
    predicate = input;
    predicateType = SLSA_PREDICATE_V1;
  } else if (input.builder && input.buildType) {
    predicate = input;
    predicateType = SLSA_PREDICATE_V02;
  } else {
    throw new Error('Unrecognized SLSA Provenance format');
  }

  if (predicateType.includes('v1') || predicate.buildDefinition) {
    return { version: 'v1', predicate, statement };
  } else if (predicateType.includes('v0.2') || predicate.builder) {
    return { version: 'v0.2', predicate, statement };
  }

  return { version: 'v1', predicate, statement };
}

/**
 * Evaluates the SLSA compliance level (0, 1, 2, or 3) of a provenance statement.
 */
export function evaluateSLSALevel(input: any): SLSALevelEvaluation {
  const reasons: string[] = [];
  let parsed: { version: 'v1' | 'v0.2'; predicate: any; statement?: InTotoStatement };

  try {
    parsed = parseSLSAProvenance(input);
  } catch (err: any) {
    return {
      level: 0,
      meetsLevel1: false,
      meetsLevel2: false,
      meetsLevel3: false,
      reasons: [`Failed to parse SLSA provenance: ${err.message}`]
    };
  }

  const { version, predicate, statement } = parsed;
  let builderId: string | undefined;
  let sourceUri: string | undefined;
  let commitSha: string | undefined;

  let meetsLevel1 = false;
  let meetsLevel2 = false;
  let meetsLevel3 = false;

  if (version === 'v1') {
    const v1 = predicate as SLSAPredicateV1;
    builderId = v1.runDetails?.builder?.id;

    const buildDef = v1.buildDefinition;
    if (!buildDef || !buildDef.buildType) {
      reasons.push('L1 check failed: Missing buildDefinition or buildType in SLSA v1 provenance');
    } else {
      meetsLevel1 = true;
      reasons.push('L1 satisfied: Build definition and parameters documented');
    }

    // Check source resolved dependencies
    const resolved = buildDef?.resolvedDependencies || [];
    const sourceDep = resolved.find(d => d.uri && (d.uri.startsWith('git+') || d.uri.startsWith('https://') || d.uri.includes('github.com')));
    if (sourceDep) {
      sourceUri = sourceDep.uri;
      commitSha = sourceDep.digest?.sha1 || sourceDep.digest?.sha256 || Object.values(sourceDep.digest || {})[0];
    }

    // Level 2 checks:
    // 1. Hosted build platform
    // 2. Source dependency resolved with cryptographic commit SHA
    if (meetsLevel1) {
      const isHosted = isHostedBuilder(builderId);
      const isPinned = isPinnedCommitSha(commitSha);

      if (!isHosted) {
        reasons.push(`L2 check failed: Builder "${builderId}" is not a recognized hosted build platform`);
      }
      if (!isPinned) {
        reasons.push(`L2 check failed: Source repository commit SHA is missing or not a valid cryptographic hash (found: "${commitSha}")`);
      }

      if (isHosted && isPinned) {
        meetsLevel2 = true;
        reasons.push('L2 satisfied: Hosted build service with cryptographically pinned source resolution');
      }
    }

    // Level 3 checks:
    // 1. Isolated / ephemeral build environment
    // 2. Non-falsifiable provenance generated by build service
    // 3. Hermetic / locked parameter definitions
    if (meetsLevel2) {
      const hasBuildParams = Boolean(buildDef.externalParameters || buildDef.internalParameters);
      const isHardenedBuilder = builderId?.includes('slsa-github-generator') || builderId?.includes('slsa-framework');
      
      if (isHardenedBuilder && hasBuildParams) {
        meetsLevel3 = true;
        reasons.push('L3 satisfied: Hardened, isolated generator with non-falsifiable build parameters');
      } else {
        reasons.push('L3 check failed: Build environment lacks verified hermeticity or isolation guarantees');
      }
    }
  } else {
    // SLSA v0.2
    const v02 = predicate as SLSAPredicateV02;
    builderId = v02.builder?.id;

    if (!v02.builder || !v02.buildType) {
      reasons.push('L1 check failed: Missing builder or buildType in SLSA v0.2 provenance');
    } else {
      meetsLevel1 = true;
      reasons.push('L1 satisfied: SLSA v0.2 builder and buildType present');
    }

    const materials = v02.materials || [];
    const sourceMat = materials.find(m => m.uri && (m.uri.startsWith('git+') || m.uri.includes('github')));
    if (sourceMat) {
      sourceUri = sourceMat.uri;
      commitSha = sourceMat.digest?.sha1 || sourceMat.digest?.sha256;
    }

    if (meetsLevel1) {
      const isHosted = isHostedBuilder(builderId);
      const isPinned = isPinnedCommitSha(commitSha);

      if (isHosted && isPinned) {
        meetsLevel2 = true;
        reasons.push('L2 satisfied: Hosted build platform with pinned materials');
      } else {
        if (!isHosted) reasons.push(`L2 check failed: Builder "${builderId}" is not hosted`);
        if (!isPinned) reasons.push(`L2 check failed: Materials commit SHA "${commitSha}" is not pinned`);
      }
    }

    if (meetsLevel2 && builderId?.includes('slsa-github-generator')) {
      meetsLevel3 = true;
      reasons.push('L3 satisfied: Pinned generator builder');
    }
  }

  let finalLevel: 0 | 1 | 2 | 3 = 0;
  if (meetsLevel3) finalLevel = 3;
  else if (meetsLevel2) finalLevel = 2;
  else if (meetsLevel1) finalLevel = 1;

  return {
    level: finalLevel,
    meetsLevel1,
    meetsLevel2,
    meetsLevel3,
    builderId,
    sourceUri,
    commitSha,
    reasons
  };
}

/**
 * Verifies that the provenance was generated by an allowed builder ID.
 */
export function verifyBuilder(provenance: any, allowedBuilders: string[]): { allowed: boolean; builderId?: string; matched?: string } {
  const { predicate } = parseSLSAProvenance(provenance);
  const builderId: string | undefined = predicate.runDetails?.builder?.id || predicate.builder?.id;

  if (!builderId) {
    return { allowed: false, builderId: undefined };
  }

  if (allowedBuilders.length === 0) {
    return { allowed: true, builderId };
  }

  for (const allowed of allowedBuilders) {
    if (allowed === '*' || builderId === allowed || builderId.startsWith(allowed)) {
      return { allowed: true, builderId, matched: allowed };
    }
    // Regex matching
    if (allowed.startsWith('/') && allowed.endsWith('/')) {
      const regexPattern: RegExp = new RegExp(allowed.slice(1, -1));
      if (regexPattern.test(builderId)) {
        return { allowed: true, builderId, matched: allowed };
      }
    }
  }

  return { allowed: false, builderId };
}

/**
 * Verifies that the provenance points to an allowed source repository.
 */
export function verifySourceRepo(provenance: any, allowedRepos: string[]): { allowed: boolean; repoUri?: string; commitSha?: string } {
  const evaluation = evaluateSLSALevel(provenance);
  const repoUri = evaluation.sourceUri;

  if (!repoUri) {
    return { allowed: false, repoUri: undefined, commitSha: evaluation.commitSha };
  }

  if (allowedRepos.length === 0) {
    return { allowed: true, repoUri, commitSha: evaluation.commitSha };
  }

  const normRepoUri = repoUri.replace(/^git\+/, '').replace(/\.git$/, '').toLowerCase();

  for (const allowed of allowedRepos) {
    const normAllowed = allowed.replace(/^git\+/, '').replace(/\.git$/, '').toLowerCase();
    if (normAllowed === '*' || normRepoUri === normAllowed || normRepoUri.endsWith(normAllowed)) {
      return { allowed: true, repoUri, commitSha: evaluation.commitSha };
    }
  }

  return { allowed: false, repoUri, commitSha: evaluation.commitSha };
}
