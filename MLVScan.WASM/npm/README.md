# @mlvscan/wasm-core

[![npm](https://img.shields.io/npm/v/@mlvscan/wasm-core.svg?color=red)](https://www.npmjs.com/package/@mlvscan/wasm-core)

WebAssembly scanning engine for [MLVScan](https://github.com/ifBars/MLVScan). Runs the full [MLVScan.Core](https://github.com/ifBars/MLVScan.Core) malware detection engine entirely in the browser — no server, no uploads, no tracking.

## Installation

```bash
npm install @mlvscan/wasm-core
```

## Serving the Framework Files

The package ships with a `dist/_framework` directory containing the .NET WASM runtime. **Your build tool must serve these files at runtime.** With Vite, use `vite-plugin-static-copy`:

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

Then initialize with `baseUrl: '/'` (the default).

## Quick Start

```ts
import { initScanner, scanAssembly } from '@mlvscan/wasm-core'

// Initialize once at app startup
await initScanner({ baseUrl: '/' })

// Scan a DLL from a file input
const file = event.target.files[0]
const bytes = new Uint8Array(await file.arrayBuffer())
const result = await scanAssembly(bytes, file.name)

console.log(`Found ${result.summary.totalFindings} issue(s)`)
for (const finding of result.findings) {
  console.log(`[${finding.severity}] ${finding.description} @ ${finding.location}`)
}
```

## API Reference

### `initScanner(options?)`

Loads the .NET WASM runtime. Call once at app startup before scanning. Safe to call multiple times — subsequent calls are no-ops if already initialized.

```ts
await initScanner({
  baseUrl: '/',             // Where _framework is served. Defaults to '/'.
  useMock: false,           // Force mock mode (useful for testing). Defaults to false.
  throwOnInitFailure: false // Throw instead of falling back to mock on load failure.
})
```

If `throwOnInitFailure` is not set and WASM fails to load, the scanner silently falls back to mock mode (returning zero findings). Use `getScannerStatus()` to detect this.

---

### `scanAssembly(fileBytes, fileName)`

Scans a .NET assembly and returns a [`ScanResult`](#scanresult). Auto-initializes if `initScanner` was not called first.

```ts
const result = await scanAssembly(bytes, 'MyMod.dll')
```

---

### `scanAssemblyWithConfig(fileBytes, fileName, config)`

Scans with explicit options for deeper analysis (call chains, data flows, developer guidance).

```ts
const result = await scanAssemblyWithConfig(bytes, 'MyMod.dll', {
  developerMode: true,
  enableCrossMethodAnalysis: true,
  deepAnalysis: {
    enableDeepAnalysis: true,
    enableNetworkToExecutionCorrelation: true,
  }
})
```

---

### Status & Utility

| Function | Returns | Description |
|---|---|---|
| `isScannerReady()` | `boolean` | True when init has completed (real or mock). Use to gate the scan button. |
| `isMockScanner()` | `boolean` | True when running in mock mode. |
| `getScannerStatus()` | `ScannerStatus` | Full status snapshot — ready, mock, explicit mock, and init error. |
| `getScannerVersion()` | `Promise<string>` | Scanner engine version (e.g. `"1.1.7"`). Returns `"1.0.0-mock"` in mock mode. |
| `getSchemaVersion()` | `Promise<string>` | Result schema version (e.g. `"1.0.0"`). |
| `getInitError()` | `Error \| null` | The error that caused WASM fallback, or null if healthy. |

## Scan Modes

The `scanMode` in [`ScanConfigInput`](#scanassemblywithconfig) controls the depth of analysis and what is included in the result:

| Mode | Description |
|---|---|
| `summary` (default) | Fast scan. Returns findings with severity and location. |
| `detailed` | Includes `callChains` — the execution path from entry point to suspicious code. |
| `developer` | Includes `dataFlows` and `developerGuidance` with remediation suggestions. |

## Handling WASM Load Failures

If the WASM runtime fails to load (e.g. COOP/COEP headers not set, browser incompatibility), the scanner falls back to mock mode automatically. Check the status after init to show an appropriate message:

```ts
await initScanner({ baseUrl: '/' })

const status = getScannerStatus()
if (status.initError) {
  console.warn('Scanner unavailable, results will be empty:', status.initError.message)
}
```

To throw instead of falling back silently:

```ts
await initScanner({ baseUrl: '/', throwOnInitFailure: true })
```

## Type Reference

### `ScanResult`

The root object returned by all scan functions.

```ts
interface ScanResult {
  schemaVersion: string
  metadata: ScanMetadata       // Scanner version, timestamp, scan mode, platform
  input: ScanInput             // File name, size, optional SHA-256
  summary: ScanSummary         // Total findings and counts by severity
  findings: Finding[]          // Individual security findings
  callChains?: CallChain[]     // Detailed mode: execution paths
  dataFlows?: DataFlowChain[]  // Developer mode: source-to-sink data flows
  developerGuidance?: DeveloperGuidance[] // Developer mode: remediation suggestions
}
```

### `Finding`

```ts
interface Finding {
  ruleId?: string
  description: string
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  location: string       // Type/method name or file:line
  codeSnippet?: string
}
```

### `ScannerStatus`

```ts
interface ScannerStatus {
  ready: boolean
  isMock: boolean
  mockRequestedExplicitly: boolean
  initError: Error | null
}
```

For the full type definitions, see [`types.ts`](https://github.com/ifBars/MLVScan.Core/blob/main/MLVScan.WASM/npm/src/types.ts).

## Related

*   [MLVScan.Core](https://github.com/ifBars/MLVScan.Core) — The detection engine (NuGet package, CLI, WASM source)
*   [MLVScan.Web](https://github.com/ifBars/MLVScan.Web) — React web app built on this package
*   [MLVScan](https://github.com/ifBars/MLVScan) — MelonLoader/BepInEx plugin

---
*Licensed under GPL-3.0*
