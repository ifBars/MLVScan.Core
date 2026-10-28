# MLVScan.Core

![Tests](https://github.com/ifBars/MLVScan.Core/workflows/Tests/badge.svg)
[![codecov](https://codecov.io/gh/ifBars/MLVScan.Core/branch/main/graph/badge.svg)](https://codecov.io/gh/ifBars/MLVScan.Core)
[![NuGet](https://img.shields.io/nuget/v/MLVScan.Core.svg)](https://www.nuget.org/packages/MLVScan.Core/)
[![npm](https://img.shields.io/npm/v/@mlvscan/wasm-core.svg?color=red)](https://www.npmjs.com/package/@mlvscan/wasm-core)

**MLVScan.Core** is a cross-platform malware detection engine for .NET assemblies, powered by IL analysis with Mono.Cecil. It serves as the scanning backbone for [MLVScan](https://github.com/ifBars/MLVScan) (MelonLoader, BepInEx 5.x, and BepInEx 6.x Mono/Il2Cpp), [MLVScan.DevCLI](https://github.com/ifBars/MLVScan.DevCLI), and [MLVScan.Web](https://github.com/ifBars/MLVScan.Web) through the `@mlvscan/wasm-core` package.

## Why MLVScan?

Most modders download mods from trusted sites like **Thunderstore** or **NexusMods**, where files are typically already scanned by **VirusTotal**. This catches most plain viruses, but sophisticated threats often slip through.

**MLVScan acts as your second line of defense.** It specifically targets:

- **Virus loaders:** malicious DLLs designed to download additional payloads.
- **Obfuscation techniques:** code that hides its true purpose from standard AV.
- **Stealthy payloads:** threats that do not match known signatures.

Think of it as the checkpoint after VirusTotal: catching what traditional scanners miss.

## Installation

```bash
dotnet add package MLVScan.Core
```

## Quick Usage

```csharp
using MLVScan;
using MLVScan.Models.Dto;
using MLVScan.Services;

var rules = RuleFactory.CreateDefaultRules();
var scanner = new AssemblyScanner(rules);
var assemblyPath = "path/to/suspicious.dll";
var assemblyBytes = File.ReadAllBytes(assemblyPath);
var findings = scanner.Scan(assemblyPath).ToList();
var result = ScanResultMapper.ToDto(
    findings,
    Path.GetFileName(assemblyPath),
    assemblyBytes,
    new ScanResultOptions
    {
        Platform = "my-tool",
        PlatformVersion = "1.0.0"
    });

Console.WriteLine($"{result.Disposition?.Classification}: {result.Disposition?.Headline}");

if (result.ThreatFamilies?.Count > 0)
{
    foreach (var family in result.ThreatFamilies)
    {
        Console.WriteLine($"Matched family: {family.DisplayName} ({family.FamilyId})");
    }
}

foreach (var finding in result.Findings)
{
    Console.WriteLine($"[{finding.Severity}] {finding.RuleId}: {finding.Description}");
}
```

The scanner emits rule findings as the foundational evidence, but the primary verdict comes from the threat-intel layer: matched `threatFamilies` and the final `disposition` built on top of those findings.

A `Suspicious` disposition can carry `blockingRecommended: false`. Currently this is limited to a verified local restart script: a bounded IL analysis binds the written script to its encoded, detached PowerShell launcher. The accepted script waits for the current process and launches a literal `steam://run/<app-id>` URI, with optional logging, bounded delays/retry, and non-recursive `*.delete` cleanup. The original execution findings remain visible. This is advisory review, not a clean verdict or a guarantee about other code in the assembly.

Unknown script operations, unresolved launch bindings, additional high-risk findings, suspicious data flows, incomplete analysis, or known threat-family matches prevent this advisory classification. The recognizer does not use file hashes, mod names, method names, or game-specific IDs. Unsupported restart implementations retain the existing classification.

Process argument resolution follows bounded `Encoding.GetBytes`/`Convert.ToBase64String`, `Convert.FromBase64String`/`Encoding.GetString`, and string replacement chains. Recovered PowerShell encoded commands participate in detection and appear in finding descriptions, including CLI output. Runtime-dependent values remain explicitly partial; competing local assignments retain their possible values instead of selecting the nearest store. Recovery has size, work, and depth limits and never executes sample code. This improves evidence coverage; it is not a guarantee that every runtime command can be reconstructed.

For the supported detached PowerShell launcher, a proven binding to a local `WriteAllText` also exposes the written script body to detection and reporting. Script binding and restart approval are separate: a bound script containing additional operations stays visible and must still pass the closed restart grammar before it can receive an advisory disposition.

Conflicting helper returns and observed mutable-field writes retain bounded alternatives, including unresolved values. Supported encoding transforms preserve those alternatives separately. Field observations do not establish receiver identity or runtime write order; search limits are reported explicitly. Possible dangerous process targets remain detection evidence even when another alternative names a legitimate tool.

### Deep analysis modes

`ScanConfig.DeepScanMode` controls when larger, still finite analysis budgets are used:

```csharp
using MLVScan.Models;

var config = new ScanConfig { DeepScanMode = DeepScanMode.RetryOnIncomplete };
var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), config);
var findings = scanner.Scan(assemblyPath).ToList();
var modeUsed = scanner.LastScanUsedDeepAnalysis ? "deep" : "standard";
```

`Disabled` is the default single pass. `RetryOnIncomplete` runs a second pass when data-flow analysis or process value recovery reaches a configured limit. `Always` uses deep budgets from the start. Deep analysis increases call depth, data-flow budgets, and process value recovery budgets; it can take longer and can still report incomplete analysis if a higher limit is reached. Hosts should report `deep` as the result scan mode when `LastScanUsedDeepAnalysis` is true.

Process recovery defaults to 4,096 work units, depth 32, and 32 alternatives. Deep mode raises these to at least 65,536, 64, and 128 respectively. `MaxValueResolutionWork`, `MaxValueResolutionDepth`, and `MaxValueResolutionAlternatives` configure these finite budgets. Conflicting returns and mutable field writes remain uncertain in every mode; increasing a budget never makes an ambiguous value concrete.

`ValueResolutionBudget` is an advanced diagnostic for partial process-value recovery. It triggers retry mode and retains the candidates recovered so far. It does not, by itself, establish malicious behavior or mean that assembly instructions were skipped. Deep analysis can still reach a limit or encounter values that depend on runtime input.

## Documentation

Complete documentation is available in the [MLVScan.Core docs](https://mlvscan.com/docs/reference/core/).

## Features

- **Platform agnostic:** works on Windows, Linux, and WebAssembly.
- **Multi-signal detection:** context-aware analysis reduces false positives.
- **Stream support:** scan files from memory without writing to disk.
- **Deep behavior analysis:** correlates practical decode, load, and execute behavior chains in compiled code.

---

Licensed under GPL-3.0.
