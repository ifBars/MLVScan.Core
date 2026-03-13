export {
  MLVSCAN_SCHEMA_VERSION,
} from './generated/mlvscan-schema.js'

export type {
  CallChain,
  CallChainNode,
  CallChainNodeType,
  DataFlowChain,
  DataFlowNode,
  DataFlowNodeType,
  DataFlowPattern,
  DeveloperGuidance,
  Finding,
  ScanInput,
  ScanMetadata,
  ScanMode,
  ScanPlatform,
  ScanResult,
  ScanSummary,
  SchemaVersion,
  Severity,
  ThreatFamily,
  ThreatFamilyEvidence,
  ThreatMatchKind,
} from './generated/mlvscan-schema.js'

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
