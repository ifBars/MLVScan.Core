# MLVScan.Core

![Tests](https://github.com/ifBars/MLVScan.Core/workflows/Tests/badge.svg)
[![codecov](https://codecov.io/gh/ifBars/MLVScan.Core/branch/main/graph/badge.svg)](https://codecov.io/gh/ifBars/MLVScan.Core)
[![NuGet](https://img.shields.io/nuget/v/MLVScan.Core.svg)](https://www.nuget.org/packages/MLVScan.Core/)
[![npm](https://img.shields.io/npm/v/@mlvscan/wasm-core.svg?color=red)](https://www.npmjs.com/package/@mlvscan/wasm-core)

**MLVScan.Core** is a cross-platform malware detection engine for .NET assemblies, powered by IL analysis (Mono.Cecil). It serves as the scanning backbone for [MLVScan](https://github.com/ifBars/MLVScan) (MelonLoader, BepInEx 5.x, and BepInEx 6.x Mono/Il2Cpp) and [MLVScan.Web](https://github.com/ifBars/MLVScan.Web) (Blazor).

## 📦 Installation

```bash
dotnet add package MLVScan.Core
```

## 🚀 Quick Usage

```csharp
var rules = RuleFactory.CreateDefaultRules();
var scanner = new AssemblyScanner(rules);
var findings = scanner.Scan("path/to/suspicious.dll");

if (findings.Any(f => f.Severity == Severity.Critical))
{
    Console.WriteLine("Malware detected!");
}
```

## 📚 Documentation

Complete documentation is available in the **[MLVScan.Core Wiki](https://github.com/ifBars/MLVScan.Core/wiki)**:

*   **[Getting Started](https://github.com/ifBars/MLVScan.Core/wiki/Getting-Started)** - Detailed integration guide.
*   **[Detection Rules](https://github.com/ifBars/MLVScan.Core/wiki/Detection-Rules)** - List of all 17+ security rules.
*   **[API Reference](https://github.com/ifBars/MLVScan.Core/wiki/API-Reference)** - Deep dive into the codebase.

## ✨ Features

*   **Platform Agnostic**: Works on Windows, Linux, Web (WASM).
*   **Multi-Signal Detection**: Context-aware analysis reduces false positives.
*   **Stream Support**: Scan files from memory without writing to disk.
*   **Deep Behavior Analysis**: Correlates practical decode/load/execute behavior chains in compiled code.

## 🧪 Testing

Run all tests:
```bash
dotnet test MLVScan.Core.sln
```

**Note**: Some tests are designed to fail locally to document features that need implementation, but pass in CI. To run tests with CI behavior locally:
```bash
CI=true dotnet test MLVScan.Core.sln
```

---
*Licensed under GPL-3.0*
