# @mlvscan/wasm-core

[![npm](https://img.shields.io/npm/v/@mlvscan/wasm-core.svg?color=red)](https://www.npmjs.com/package/@mlvscan/wasm-core)

WebAssembly scanning engine for [MLVScan](https://github.com/ifBars/MLVScan). It runs the MLVScan.Core malware detection engine in the browser with no server-side scan step.

## Installation

```bash
bun add @mlvscan/wasm-core
```

## Serving The Framework Files

The package ships with a `dist/_framework` directory containing the .NET WASM runtime. Your build tool must serve these files at runtime. With Vite, use `vite-plugin-static-copy`:

```ts
// vite.config.ts
import { viteStaticCopy } from 'vite-plugin-static-copy'

export default {
  plugins: [
    viteStaticCopy({
      targets: [{
        src: 'node_modules/@mlvscan/wasm-core/dist/_framework',
        dest: '.'
      }]
    })
  ]
}
```

Then initialize with `baseUrl: '/'`, or set `baseUrl` to the route where `_framework/dotnet.js` is served.

## Quick Start

```ts
import { initScanner, scanAssembly } from '@mlvscan/wasm-core'

await initScanner({ baseUrl: '/' })

const file = event.target.files[0]
const bytes = new Uint8Array(await file.arrayBuffer())
const result = await scanAssembly(bytes, file.name)

console.log(`${result.disposition?.classification}: ${result.disposition?.headline}`)
console.log(`Found ${result.summary.totalFindings} finding(s)`)

for (const family of result.threatFamilies ?? []) {
  console.log(`Matched family: ${family.displayName} (${family.matchKind})`)
}
```

## API Reference

### `initScanner(options?)`

Loads the .NET WASM runtime. Call once at app startup before scanning, or let `scanAssembly` initialize on first use. Repeated calls are no-ops after initialization.

```ts
await initScanner({
  baseUrl: '/',             // Where _framework is served. Defaults to '/'.
  useMock: false,           // Force mock mode for tests. Defaults to false.
  throwOnInitFailure: false // Throw instead of falling back to mock on load failure.
})
```

If `throwOnInitFailure` is not set and WASM fails to load, the scanner falls back to mock mode and returns zero findings. Use `getScannerStatus()` or `getInitError()` to detect that state.

### `scanAssembly(fileBytes, fileName)`

Scans a managed .NET assembly and returns a `ScanResult`. It auto-initializes the scanner if `initScanner` was not called first.

```ts
const result = await scanAssembly(bytes, 'MyMod.dll')
```

### `scanAssemblyWithConfig(fileBytes, fileName, config)`

Scans with explicit Core scan configuration. Omitted values use the WASM scanner defaults.

```ts
const result = await scanAssemblyWithConfig(bytes, 'MyMod.dll', {
  developerMode: true,
  enableCrossMethodAnalysis: true,
  enableReturnValueTracking: true
})
```

### Status And Utility

| Function | Returns | Description |
|---|---|---|
| `isScannerReady()` | `boolean` | True when init has completed with either real WASM or mock fallback. |
| `isMockScanner()` | `boolean` | True when running in mock mode. |
| `getScannerStatus()` | `ScannerStatus` | Full status snapshot: ready, mock, explicit mock, and init error. |
| `getScannerVersion()` | `Promise<string>` | Scanner engine version, such as `"1.4.1"`. Returns `"1.0.0-mock"` in mock mode. |
| `getSchemaVersion()` | `Promise<string>` | Result schema version, currently `"1.2.0"`. |
| `getInitError()` | `Error \| null` | The error that caused WASM fallback, or null if healthy. |

## Configuration And Result Detail

`scanAssemblyWithConfig` accepts `ScanConfigInput`, which mirrors the public Core scan options in a JSON-friendly shape:

```ts
await scanAssemblyWithConfig(bytes, 'MyMod.dll', {
  developerMode: true,
  enableCrossMethodAnalysis: true,
  maxCallChainDepth: 5,
  enableReturnValueTracking: true,
  detectAssemblyMetadata: true,
  enableRecursiveResourceScanning: true,
  maxRecursiveResourceSizeMB: 10
})
```

The default result mode is `detailed`. Setting `developerMode: true` uses developer mode and includes developer guidance when available.

## Handling WASM Load Failures

```ts
await initScanner({ baseUrl: '/' })

const status = getScannerStatus()
if (status.initError) {
  console.warn('Scanner unavailable, results will be empty:', status.initError.message)
}
```

To throw instead of falling back:

```ts
await initScanner({ baseUrl: '/', throwOnInitFailure: true })
```

## Type Reference

### `ScanResult`

```ts
interface ScanResult {
  schemaVersion: '1.2.0'
  metadata: ScanMetadata
  input: ScanInput
  assembly?: AssemblyMetadata | null
  summary: ScanSummary
  findings: Finding[]
  callChains?: CallChain[] | null
  dataFlows?: DataFlowChain[] | null
  developerGuidance?: DeveloperGuidance[] | null
  threatFamilies?: ThreatFamily[] | null
  disposition?: ThreatDisposition | null
}
```

### `Finding`

```ts
interface Finding {
  id?: string | null
  ruleId?: string | null
  description: string
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  location: string
  codeSnippet?: string | null
  riskScore?: number | null
  callChainId?: string | null
  dataFlowChainId?: string | null
  developerGuidance?: DeveloperGuidance | null
  callChain?: CallChain | null
  dataFlowChain?: DataFlowChain | null
  visibility?: 'Default' | 'Advanced' | null
}
```

### `ThreatDisposition`

```ts
interface ThreatDisposition {
  classification: 'Clean' | 'Suspicious' | 'KnownThreat'
  headline: string
  summary: string
  blockingRecommended: boolean
  primaryThreatFamilyId?: string | null
  relatedFindingIds: string[]
}
```

For the full type definitions, see [`types.ts`](https://github.com/ifBars/MLVScan.Core/blob/main/MLVScan.WASM/npm/src/types.ts).

## Related

- [MLVScan.Core](https://github.com/ifBars/MLVScan.Core) - The detection engine and shared schema source.
- [MLVScan.Web](https://github.com/ifBars/MLVScan.Web) - React web app built on this package.
- [MLVScan](https://github.com/ifBars/MLVScan) - MelonLoader/BepInEx plugin.

## Architecture Notes

MLVScan.Core is environment-agnostic. It powers multiple integration points without containing mod loader-specific code.

---

Licensed under GPL-3.0.
