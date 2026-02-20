/**
 * MLVScan scan result and finding types.
 *
 * These match the JSON schema produced by MLVScan.WASM. Use with {@link scanAssembly}
 * from the main package.
 */

/** Root object returned by a scan. Contains metadata, input info, summary, and findings. */
export interface ScanResult {
  /** Schema version of this result (e.g. "1.0.0"). */
  schemaVersion: string
  /** Scanner and scan run metadata. */
  metadata: ScanMetadata
  /** The assembly that was scanned. */
  input: ScanInput
  /** Aggregated counts and triggered rules. */
  summary: ScanSummary
  /** Individual security/relevance findings. */
  findings: Finding[]
  /** Optional call chains for detailed mode. */
  callChains?: CallChain[]
  /** Optional data flow chains for developer mode. */
  dataFlows?: DataFlowChain[]
  /** Optional remediation guidance for developer mode. */
  developerGuidance?: DeveloperGuidance[]
}

/** Metadata about the scanner and this scan run. */
export interface ScanMetadata {
  scannerVersion: string
  /** ISO 8601 timestamp of the scan. */
  timestamp: string
  /** Level of detail: summary, detailed (with call chains), or developer (with data flows and guidance). */
  scanMode: 'summary' | 'detailed' | 'developer'
  /** Where the scan ran: wasm, cli, server, or desktop. */
  platform: 'wasm' | 'cli' | 'server' | 'desktop'
}

/** Describes the assembly that was scanned. */
export interface ScanInput {
  fileName: string
  sizeBytes: number
  /** SHA-256 hash of the file when available. */
  sha256Hash?: string
}

/** Aggregated scan summary: total findings and counts by severity. */
export interface ScanSummary {
  totalFindings: number
  /** Map of severity (e.g. "Low", "Critical") to count. */
  countBySeverity: Record<string, number>
  /** Rule IDs that produced at least one finding. */
  triggeredRules: string[]
}

/** Finding severity level. */
export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'

/** A single finding: one triggered rule or suspicious pattern in the assembly. */
export interface Finding {
  id?: string
  ruleId?: string
  description: string
  severity: Severity
  /** Human-readable location (e.g. type/method name or file:line). */
  location: string
  codeSnippet?: string
  /** Present in detailed/developer mode when a call chain was analyzed. */
  callChain?: CallChain
  /** Present in developer mode when a data flow was analyzed. */
  dataFlowChain?: DataFlowChain
}

/** A call chain from entry point to a suspicious declaration. */
export interface CallChain {
  id?: string
  ruleId?: string
  description: string
  severity: Severity
  nodes: CallChainNode[]
}

/** Role of a node in a call chain. */
export type CallChainNodeType = 'EntryPoint' | 'IntermediateCall' | 'SuspiciousDeclaration'

/** One node in a call chain (method or declaration). */
export interface CallChainNode {
  nodeType: CallChainNodeType
  location: string
  description: string
  codeSnippet?: string
}

/** A data flow from source to sink (e.g. download and execute). */
export interface DataFlowChain {
  id?: string
  description: string
  severity: Severity
  pattern: DataFlowPattern
  /** Confidence score (e.g. 0–1). */
  confidence: number
  sourceVariable?: string
  methodLocation?: string
  isCrossMethod: boolean
  involvedMethods?: string[]
  nodes: DataFlowNode[]
}

/** Class of data flow pattern the chain represents. */
export type DataFlowPattern =
  | 'Legitimate'
  | 'DownloadAndExecute'
  | 'DataExfiltration'
  | 'DynamicCodeLoading'
  | 'CredentialTheft'
  | 'RemoteConfigLoad'
  | 'ObfuscatedPersistence'
  | 'Unknown'

/** Role of a node in a data flow (source, transform, sink, or intermediate). */
export type DataFlowNodeType = 'Source' | 'Transform' | 'Sink' | 'Intermediate'

/** One node in a data flow chain. */
export interface DataFlowNode {
  nodeType: DataFlowNodeType
  location: string
  operation: string
  dataDescription: string
  instructionOffset: number
  methodKey?: string
  isMethodBoundary: boolean
  targetMethodKey?: string
  codeSnippet?: string
}

/** Remediation suggestion for a rule or finding (developer mode). */
export interface DeveloperGuidance {
  ruleId?: string
  remediation: string
  documentationUrl?: string
  alternativeApis?: string[]
  isRemediable: boolean
}

export interface DeepBehaviorAnalysisConfig {
  enableDeepAnalysis?: boolean
  emitDiagnosticFindings?: boolean
  requireCorrelatedBaseFinding?: boolean
  deepScanOnlyFlaggedMethods?: boolean
  enableStringDecodeFlow?: boolean
  enableExecutionChainAnalysis?: boolean
  enableResourcePayloadAnalysis?: boolean
  enableDynamicLoadCorrelation?: boolean
  enableNativeInteropCorrelation?: boolean
  enableScriptHostLaunchAnalysis?: boolean
  enableEnvironmentPivotCorrelation?: boolean
  enableNetworkToExecutionCorrelation?: boolean

  maxInstructionsPerMethod?: number
  maxAnalysisTimeMsPerMethod?: number
  maxDeepMethodsPerAssembly?: number
  maxTrackedDataFlowEdgesPerMethod?: number
}

export interface ScanConfigInput {
  developerMode?: boolean
  enableCrossMethodAnalysis?: boolean
  maxCallChainDepth?: number
  enableReturnValueTracking?: boolean
  detectAssemblyMetadata?: boolean
  enableMultiSignalDetection?: boolean
  analyzeExceptionHandlers?: boolean
  analyzeLocalVariables?: boolean
  analyzePropertyAccessors?: boolean
  enableRecursiveResourceScanning?: boolean
  maxRecursiveResourceSizeMB?: number
  deepAnalysis?: DeepBehaviorAnalysisConfig
}
