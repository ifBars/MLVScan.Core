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

## Documentation

Complete documentation is available in the [MLVScan.Core docs](https://mlvscan.com/docs/libraries/core).

## Features

- **Platform agnostic:** works on Windows, Linux, and WebAssembly.
- **Multi-signal detection:** context-aware analysis reduces false positives.
- **Stream support:** scan files from memory without writing to disk.
- **Deep behavior analysis:** correlates practical decode, load, and execute behavior chains in compiled code.

---

Licensed under GPL-3.0.
