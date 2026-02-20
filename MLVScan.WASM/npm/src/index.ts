/**
 * @packageDocumentation
 *
 * WebAssembly core for MLVScan. Loads the .NET WASM runtime and MLVScan.WASM assembly
 * to scan Unity mod assemblies (e.g. MelonLoader/BepInEx DLLs) in the browser.
 *
 * Call {@link initScanner} before scanning (or let {@link scanAssembly} init automatically).
 * Use {@link getScannerStatus} or {@link getInitError} to detect mock fallback and show
 * appropriate UI. Use {@link isMockScanner} to distinguish "running in mock mode" from
 * "real WASM scanner ready".
 *
 * @example
 * ```ts
 * import { initScanner, scanAssembly, getScannerStatus } from '@mlvscan/wasm-core'
 * await initScanner({ baseUrl: '/' })
 * const status = getScannerStatus()
 * if (status.initError) console.warn('Scanner unavailable:', status.initError)
 * const result = await scanAssembly(dllBytes, 'MyMod.dll')
 * ```
 */

import type { ScanConfigInput, ScanResult } from './types'

let scannerExports: any = null
let scannerLoaded = false
let dotnetModule: any = null
let useMockScanner = false
/** Set when we fell back to mock due to load/init failure (not when useMock: true). */
let initError: Error | null = null
/** True when mock was explicitly requested via options; false when fallback due to error. */
let mockRequestedExplicitly = false

const mockScanResult: ScanResult = {
  schemaVersion: '1.0.0',
  metadata: {
    scannerVersion: '1.0.0-mock',
    timestamp: new Date().toISOString(),
    scanMode: 'summary',
    platform: 'wasm',
  },
  input: {
    fileName: 'sample.dll',
    sizeBytes: 1024,
  },
  summary: {
    totalFindings: 0,
    countBySeverity: {},
    triggeredRules: [],
  },
  findings: []
}

/**
 * Options for initializing the WASM scanner.
 *
 * Pass these to {@link initScanner}. The scanner loads `_framework/dotnet.js` from
 * `baseUrl`; ensure your dev server or build serves the npm package's `dist/_framework`
 * at that path.
 */
export interface ScannerInitOptions {
    /**
     * Base URL where the _framework directory is served.
     * Defaults to '/'.
     */
    baseUrl?: string;

    /**
     * Whether to use the mock scanner (useful for testing or if WASM fails).
     * Defaults to false.
     */
    useMock?: boolean;

    /**
     * If true, initScanner() throws when WASM fails to load or initialize
     * (instead of falling back to mock). Use when you want to show an error UI
     * rather than silent mock. Ignored when useMock is true.
     * Defaults to false.
     */
    throwOnInitFailure?: boolean;
}

/**
 * Snapshot of scanner state after init. Use with {@link getScannerStatus} to drive UI
 * (e.g. show "Scanner unavailable" when `initError` is set, or "Mock mode" when
 * `isMock && mockRequestedExplicitly`).
 */
export interface ScannerStatus {
    /** True when init has completed (success or fallback). */
    ready: boolean;
    /** True when running in mock mode (explicit or fallback). */
    isMock: boolean;
    /** True when mock was requested via init options; false when fallback due to error. */
    mockRequestedExplicitly: boolean;
    /** Set when we fell back to mock due to load/init failure. Null if real WASM is active or mock was explicit. */
    initError: Error | null;
}

/**
 * Loads the .NET WASM runtime from the given base URL. Caches the module and sets
 * initError / useMockScanner on failure.
 * @internal
 */
async function loadDotnet(baseUrl: string): Promise<any> {
  if (dotnetModule) {
    return dotnetModule
  }

  // Ensure trailing slash
  const safeBaseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const dotnetUrl = `${safeBaseUrl}_framework/dotnet.js`;

  try {
    // Dynamic import to bypass some bundlers
    const dynamicImport = new Function('url', 'return import(url)')
    const mod = await dynamicImport(dotnetUrl)
    dotnetModule = mod.dotnet || mod.default || mod
    return dotnetModule
  } catch (err) {
    initError = err instanceof Error ? err : new Error(String(err))
    console.warn('Blazor WASM not available, using mock scanner', initError)
    useMockScanner = true
    return null
  }
}

/**
 * Initializes the WASM scanner: loads the .NET runtime and MLVScan.WASM assembly.
 * Call once before scanning (or rely on {@link scanAssembly} / {@link getScannerVersion}
 * to init on first use). Safe to call multiple times; subsequent calls no-op if already
 * initialized.
 *
 * @param options - See {@link ScannerInitOptions}. Omitted options use defaults.
 * @throws When `throwOnInitFailure` is true and WASM fails to load or initialize.
 */
export async function initScanner(options: ScannerInitOptions = {}): Promise<void> {
  if (scannerLoaded && scannerExports) {
    return
  }

  const { baseUrl = '/', useMock = false, throwOnInitFailure = false } = options;

  if (useMock) {
    initError = null
    mockRequestedExplicitly = true
    useMockScanner = true
    scannerExports = null
    scannerLoaded = true
    return
  }

  initError = null
  mockRequestedExplicitly = false

  try {
    const dotnet = await loadDotnet(baseUrl)
    if (useMockScanner || !dotnet) {
      scannerExports = null
      scannerLoaded = true
      if (throwOnInitFailure && initError) {
        throw initError
      }
      return
    }

    const safeBaseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`
    const frameworkPath = `${safeBaseUrl}_framework/`

    const { getAssemblyExports, getConfig } = await dotnet
      .withDiagnosticTracing(false)
      .create({
        locateFile: (path: string) => frameworkPath + path,
      })

    scannerExports = await getAssemblyExports(getConfig().mainAssemblyName)
    scannerLoaded = true
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error))
    initError = err
    console.warn('Failed to initialize WASM scanner, falling back to mock:', err)
    useMockScanner = true
    scannerExports = null
    scannerLoaded = true
    if (throwOnInitFailure) {
      throw err
    }
  }
}

/**
 * Scans a .NET assembly (e.g. a Unity mod DLL) and returns structured findings.
 * Initializes the scanner if not yet initialized. In mock mode returns a result
 * with zero findings and scanner version `1.0.0-mock`.
 *
 * @param fileBytes - Raw bytes of the assembly (e.g. from FileReader or fetch).
 * @param fileName - Name of the file (used in the result and for logging).
 * @returns A {@link ScanResult} with metadata, summary, and findings.
 * @throws When the scanner is not in mock mode but the WASM scan call fails.
 */
export async function scanAssembly(
  fileBytes: Uint8Array,
  fileName: string
): Promise<ScanResult> {
  if (!scannerLoaded) {
    await initScanner()
  }

  if (useMockScanner || !scannerExports) {
    return {
      ...mockScanResult,
      input: {
        fileName,
        sizeBytes: fileBytes.length,
      },
    }
  }

  if (!scannerExports.MLVScan?.WASM?.ScannerExports) {
    throw new Error('Scanner not properly initialized: MLVScan.WASM.ScannerExports not found')
  }

  try {
    const resultJson = scannerExports.MLVScan.WASM.ScannerExports.ScanAssembly(fileBytes, fileName)
    return JSON.parse(resultJson) as ScanResult
  } catch (error) {
    throw new Error(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Scans an assembly with an explicit scan configuration (including deep analysis options).
 * Use this for opt-in deep scans while keeping quick scan defaults for normal usage.
 */
export async function scanAssemblyWithConfig(
  fileBytes: Uint8Array,
  fileName: string,
  config: ScanConfigInput
): Promise<ScanResult> {
  if (!scannerLoaded) {
    await initScanner()
  }

  if (useMockScanner || !scannerExports) {
    return {
      ...mockScanResult,
      input: {
        fileName,
        sizeBytes: fileBytes.length,
      },
    }
  }

  if (!scannerExports.MLVScan?.WASM?.ScannerExports) {
    throw new Error('Scanner not properly initialized: MLVScan.WASM.ScannerExports not found')
  }

  try {
    const configJson = JSON.stringify(config ?? {})
    const resultJson = scannerExports.MLVScan.WASM.ScannerExports.ScanAssemblyWithConfig(
      fileBytes,
      fileName,
      configJson
    )
    return JSON.parse(resultJson) as ScanResult
  } catch (error) {
    throw new Error(`Scan with config failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Returns whether the scanner is ready to use (initialization finished, either
 * with real WASM or mock). Use this to gate UI (e.g. enable "Scan" only when
 * ready). For more detail use {@link getScannerStatus}.
 */
export function isScannerReady(): boolean {
  return scannerLoaded && (useMockScanner || scannerExports !== null)
}

/**
 * Returns true when the scanner is running in mock mode (either requested via
 * init options or fallback due to WASM load/init failure). Use to show a
 * "Mock mode" badge or to avoid relying on real scan results.
 */
export function isMockScanner(): boolean {
  return useMockScanner
}

/**
 * Returns the error that caused fallback to mock, or null if WASM is active
 * or mock was explicitly requested. Use with {@link getScannerStatus} to show
 * "Scanner unavailable: {message}".
 */
export function getInitError(): Error | null {
  return initError
}

/**
 * Returns the current scanner status: ready flag, mock mode, whether mock was
 * explicit, and any init error. Use to drive UI (e.g. banner when
 * `status.initError`, or "Mock mode" when `status.isMock`).
 */
export function getScannerStatus(): ScannerStatus {
  return {
    ready: scannerLoaded && (useMockScanner || scannerExports !== null),
    isMock: useMockScanner,
    mockRequestedExplicitly,
    initError,
  }
}

/**
 * Returns the scanner engine version (e.g. `"1.1.7"`). In mock mode returns
 * `"1.0.0-mock"`. Initializes the scanner if not yet initialized.
 *
 * @throws When the real WASM is loaded but the version call fails.
 */
export async function getScannerVersion(): Promise<string> {
  if (!scannerLoaded) {
    await initScanner()
  }

  if (useMockScanner || !scannerExports?.MLVScan?.WASM?.ScannerExports) {
    return '1.0.0-mock'
  }

  try {
    return scannerExports.MLVScan.WASM.ScannerExports.GetVersion()
  } catch (error) {
    throw new Error(
      `Failed to get scanner version: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * Returns the scan result schema version (e.g. `"1.0.0"`). In mock mode returns
 * `"1.0.0"`. Initializes the scanner if not yet initialized.
 *
 * @throws When the real WASM is loaded but the schema version call fails.
 */
export async function getSchemaVersion(): Promise<string> {
  if (!scannerLoaded) {
    await initScanner()
  }

  if (useMockScanner || !scannerExports?.MLVScan?.WASM?.ScannerExports) {
    return '1.0.0'
  }

  try {
    return scannerExports.MLVScan.WASM.ScannerExports.GetSchemaVersion()
  } catch (error) {
    throw new Error(
      `Failed to get schema version: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/** Re-export scan result and finding types. */
export * from './types.js'
