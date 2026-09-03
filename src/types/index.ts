export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN';

export interface DigestSet {
  sha256?: string;
  sha1?: string;
  sha512?: string;
  [algorithm: string]: string | undefined;
}

export interface InTotoSubject {
  name: string;
  digest: DigestSet;
}

export interface InTotoStatement {
  _type: string;
  subject: InTotoSubject[];
  predicateType: string;
  predicate: Record<string, any>;
}

export interface Signature {
  keyid?: string;
  sig: string;
}

export interface DSSEEnvelope {
  payload: string;
  payloadType: string;
  signatures: Signature[];
}

export interface SigstoreBundle {
  mediaType: string;
  verificationMaterial?: {
    certificate?: {
      rawBytes: string;
    };
    tlogEntries?: any[];
    timestampVerificationData?: any;
    [key: string]: any;
  };
  dsseEnvelope?: DSSEEnvelope;
  messageSignature?: {
    messageDigest: {
      algorithm: string;
      digest: string;
    };
    signature: string;
  };
  [key: string]: any;
}

export interface SLSABuildDefinitionV1 {
  buildType: string;
  externalParameters?: Record<string, any>;
  internalParameters?: Record<string, any>;
  resolvedDependencies?: Array<{
    uri?: string;
    digest?: DigestSet;
    name?: string;
    annotations?: Record<string, any>;
  }>;
}

export interface SLSARunDetailsV1 {
  builder: {
    id: string;
    version?: string;
    builderDependencies?: any[];
  };
  metadata?: {
    invocationId?: string;
    startedOn?: string;
    finishedOn?: string;
  };
  byproducts?: any[];
}

export interface SLSAPredicateV1 {
  buildDefinition: SLSABuildDefinitionV1;
  runDetails: SLSARunDetailsV1;
}

export interface SLSAPredicateV02 {
  builder: {
    id: string;
  };
  buildType: string;
  invocation?: {
    configSource?: {
      uri?: string;
      digest?: DigestSet;
      entryPoint?: string;
    };
    parameters?: Record<string, any>;
    environment?: Record<string, any>;
  };
  materials?: Array<{
    uri: string;
    digest: DigestSet;
  }>;
}

export interface CycloneDXComponent {
  'bom-ref'?: string;
  bomRef?: string;
  type?: string;
  name: string;
  version?: string;
  purl?: string;
  cpe?: string;
  hashes?: Array<{
    alg: string;
    content: string;
  }>;
  licenses?: Array<{
    license?: {
      id?: string;
      name?: string;
      url?: string;
    };
    expression?: string;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

export interface CycloneDXSBOM {
  $schema?: string;
  bomFormat: 'CycloneDX' | string;
  specVersion: string;
  serialNumber?: string;
  version?: number;
  metadata?: {
    timestamp?: string;
    tools?: any;
    component?: any;
    [key: string]: any;
  };
  components?: CycloneDXComponent[];
  dependencies?: Array<{
    ref: string;
    dependsOn?: string[];
  }>;
  [key: string]: any;
}

export interface SPDXPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  downloadLocation?: string;
  packageVerificationCode?: {
    packageVerificationCodeValue: string;
  };
  checksums?: Array<{
    algorithm: string;
    checksumValue: string;
  }>;
  licenseConcluded?: string;
  licenseDeclared?: string;
  externalRefs?: Array<{
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }>;
}

export interface SPDXSBOM {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  documentNamespace?: string;
  packages?: SPDXPackage[];
  relationships?: Array<{
    spdxElementId: string;
    relatedSpdxElement: string;
    relationshipType: string;
  }>;
  [key: string]: any;
}

export interface UnifiedComponent {
  name: string;
  version: string;
  purl?: string;
  type?: string;
  hashes: Record<string, string>;
  licenses: string[];
}

export interface UnifiedSBOM {
  format: 'cyclonedx' | 'spdx';
  specVersion: string;
  documentName?: string;
  timestamp?: string;
  components: UnifiedComponent[];
  rawSha256: string;
}

export interface VulnerabilityItem {
  name: string;
  installedVersion: string;
  fixedInVersion?: string;
  type?: string;
  vulnerabilityId: string;
  severity: SeverityLevel;
  epss?: string;
  risk?: string;
}

export interface VulnerabilityReport {
  sourceFormat: 'grype-table' | 'grype-json' | 'generic';
  items: VulnerabilityItem[];
  summary: Record<SeverityLevel, number>;
}

export interface PolicyConfig {
  minSlsaLevel?: 1 | 2 | 3;
  allowedBuilders?: string[];
  allowedSourceRepos?: string[];
  requireSbom?: boolean;
  requireSignature?: boolean;
  requireProvenance?: boolean;
  maxAllowedCveSeverity?: SeverityLevel | 'NONE';
  allowedLicenses?: string[];
  prohibitedLicenses?: string[];
  requirePinnedDependencies?: boolean;
}

export interface PolicyRuleResult {
  rule: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  message: string;
  details?: any;
}

export interface PolicyEvaluationResult {
  passed: boolean;
  rules: PolicyRuleResult[];
  failures: string[];
  warnings: string[];
}

export interface VerificationOptions {
  artifactPath: string;
  sbomPath?: string;
  attestationPath?: string;
  provenancePath?: string;
  cveScanPath?: string;
  policy?: PolicyConfig;
  baseDir?: string;
}

export interface VerificationResult {
  artifactPath: string;
  artifactSha256: string;
  verified: boolean;
  slsaLevelAchieved: number;
  policyResult: PolicyEvaluationResult;
  sbom?: UnifiedSBOM;
  vulnerabilities?: VulnerabilityReport;
  attestationVerified: boolean;
  signatureVerified: boolean;
  provenanceVerified: boolean;
  errors: string[];
}

export interface FleetConfig {
  repositories: string[];
  policy?: PolicyConfig;
}

export interface RepoEvaluationSummary {
  repoPath: string;
  repoName: string;
  status: 'PASS' | 'FAIL' | 'ERROR' | 'SKIPPED';
  artifactPresent: boolean;
  sbomPresent: boolean;
  signaturePresent: boolean;
  attestationPresent: boolean;
  provenancePresent: boolean;
  slsaLevel: number;
  criticalCves: number;
  highCves: number;
  mediumCves: number;
  lowCves: number;
  policyViolations: string[];
  errors: string[];
}

export interface FleetSummary {
  timestamp: string;
  totalRepositories: number;
  passedCount: number;
  failedCount: number;
  errorCount: number;
  overallStatus: 'PASS' | 'FAIL';
  repositories: RepoEvaluationSummary[];
}
