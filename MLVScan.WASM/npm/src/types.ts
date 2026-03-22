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
  FindingVisibility,
  ScanInput,
  ScanMetadata,
  ScanMode,
  ScanPlatform,
  ScanResult,
  ScanSummary,
  SchemaVersion,
  Severity,
  ThreatDisposition,
  ThreatDispositionClassification,
  ThreatFamily,
  ThreatFamilyEvidence,
  ThreatMatchKind,
} from './generated/mlvscan-schema.js'

/**
 * Browser-facing scan configuration passed to `scanAssemblyWithConfig`.
 *
 * This mirrors the public Core scan options while keeping the shape friendly for JSON serialization.
 * Omitted values use the WASM scanner defaults.
 */
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
}
