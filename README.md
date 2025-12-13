# MLVScan.Core

Core scanning engine for MLVScan - a security-focused scanner that detects malicious patterns in Unity mod assemblies.

## Overview

MLVScan.Core is a platform-agnostic library that provides the core IL analysis and malware detection capabilities used by:
- **MLVScan** - MelonLoader plugin for scanning mods at runtime
- **MLVScanWeb** - Blazor WebAssembly web application for online scanning
- **Future BepInEx support** - Coming soon

## Installation

```bash
dotnet add package MLVScan.Core
```

## Quick Start

### Basic Usage

```csharp
using MLVScan;
using MLVScan.Models;
using MLVScan.Services;

// Create scanner with default rules
var rules = RuleFactory.CreateDefaultRules();
var scanner = new AssemblyScanner(rules);

// Scan a file
var findings = scanner.Scan("path/to/mod.dll");

foreach (var finding in findings)
{
    Console.WriteLine($"[{finding.Severity}] {finding.Description}");
    Console.WriteLine($"  Location: {finding.Location}");
    if (!string.IsNullOrEmpty(finding.CodeSnippet))
        Console.WriteLine($"  Code: {finding.CodeSnippet}");
}
```

### Stream-Based Scanning (Web/Memory)

```csharp
// Scan from a stream (e.g., uploaded file)
using var stream = File.OpenRead("mod.dll");
var findings = scanner.Scan(stream, "mod.dll");
```

### Custom Configuration

```csharp
var config = new ScanConfig
{
    EnableMultiSignalDetection = true,
    DetectAssemblyMetadata = true
};

var scanner = new AssemblyScanner(rules, config);
```

### Platform-Specific Assembly Resolution

For MelonLoader or BepInEx environments that need to resolve game assemblies:

```csharp
// Implement IAssemblyResolverProvider
public class MyGameResolverProvider : IAssemblyResolverProvider
{
    public IAssemblyResolver CreateResolver()
    {
        var resolver = new DefaultAssemblyResolver();
        resolver.AddSearchDirectory("path/to/game/Managed");
        return resolver;
    }
}

// Use with scanner
var scanner = new AssemblyScanner(rules, config, new MyGameResolverProvider());
```

## Architecture

```
MLVScan.Core/
├── Abstractions/
│   ├── IScanLogger.cs          # Logging abstraction
│   ├── NullScanLogger.cs       # No-op logger
│   ├── ConsoleScanLogger.cs    # Console output logger
│   └── IAssemblyResolverProvider.cs  # Assembly resolution abstraction
├── Models/
│   ├── ScanConfig.cs           # Configuration options
│   ├── ScanFinding.cs          # Detection result
│   ├── MethodSignals.cs        # Pattern tracking
│   └── Rules/                  # All IScanRule implementations
├── Services/
│   ├── AssemblyScanner.cs      # Main entry point
│   ├── TypeScanner.cs          # Type-level scanning
│   ├── MethodScanner.cs        # Method-level scanning
│   ├── InstructionAnalyzer.cs  # IL instruction analysis
│   ├── ReflectionDetector.cs   # Reflection-based attack detection
│   ├── SignalTracker.cs        # Multi-signal pattern tracking
│   └── Helpers/                # Utility classes
└── RuleFactory.cs              # Centralized rule creation
```

## Available Detection Rules

| Rule | Description | Severity |
|------|-------------|----------|
| ProcessStartRule | Detects Process.Start calls | High |
| Shell32Rule | Detects Windows shell execution | Critical |
| Base64Rule | Detects Base64 decoding operations | Medium |
| DllImportRule | Detects native DLL imports | Medium/High |
| ReflectionRule | Detects reflection-based invocation | High |
| RegistryRule | Detects registry manipulation | High |
| LoadFromStreamRule | Detects dynamic assembly loading | Critical |
| EncodedStringLiteralRule | Detects numeric-encoded strings | High |
| DataExfiltrationRule | Detects data sending to external endpoints | Critical |
| PersistenceRule | Detects persistence mechanisms | Critical |
| COMReflectionAttackRule | Detects COM-based shell execution | Critical |
| And more... | 17 rules total | - |

## Multi-Signal Detection

The scanner uses a multi-signal detection system to reduce false positives. Benign operations (like base64 decoding) are only flagged when combined with other suspicious patterns in the same method or type.

## License

GPL-3.0-or-later

## Contributing

Contributions are welcome! Please see the main [MLVScan repository](https://github.com/ifBars/MLVScan) for contribution guidelines.
