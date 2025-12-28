# MLVScan.Core

**MLVScan.Core** is a cross-platform malware detection engine for .NET assemblies, powered by IL analysis (Mono.Cecil). It serves as the scanning backbone for [MLVScan](../MLVScan) (MelonLoader) and [MLVScanWeb](../MLVScanWeb) (Blazor).

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
*   **Deep IL Analysis**: Detects patterns in compiled code, not just metadata.

---
*Licensed under GPL-3.0*
