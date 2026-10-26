using MLVScan.Abstractions;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.IO.Compression;

namespace MLVScan.Models.Rules;

/// <summary>
/// Detects embedded ZIP resources staged to TEMP and embedded ZIP/JAR byte fields tied to concealed execution.
/// Text-only resource extraction remains diagnostic evidence without establishing an executable payload.
/// </summary>
public sealed class EmbeddedArchivePayloadRule : IScanRule
{
    private const int MinimumArchiveBytes = 512;
    private const int MaximumArchiveBytes = 32 * 1024 * 1024;

    /// <inheritdoc />
    public string Description =>
        "Detected embedded ZIP/JAR archive bytes used by a file or child-process execution path.";

    /// <inheritdoc />
    public Severity Severity => Severity.High;

    /// <inheritdoc />
    public string RuleId => "EmbeddedArchivePayloadRule";

    /// <inheritdoc />
    public bool RequiresCompanionFinding => false;

    /// <inheritdoc />
    public bool IsSuspicious(MethodReference method) => false;

    /// <inheritdoc />
    public IEnumerable<ScanFinding> PostAnalysisRefine(
        ModuleDefinition module,
        IEnumerable<ScanFinding> existingFindings)
    {
        if (module == null)
        {
            return [];
        }

        var extractionFindings = AnalyzeResourceExtraction(module).ToList();

        bool hasProcessExecution = existingFindings?.Any(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            (Contains(finding.Description, "Redirected I/O") ||
             Contains(finding.Description, "WindowStyle=Hidden") ||
             Contains(finding.Description, "CreateNoWindow=true"))) == true;
        if (!hasProcessExecution)
        {
            return extractionFindings;
        }

        var methods = EnumerateTypes(module)
            .SelectMany(static type => type.Methods)
            .Where(static method => method.HasBody)
            .ToList();
        bool hasMaterializationSink = methods.Any(method => method.Body.Instructions.Any(instruction =>
            instruction.Operand is MethodReference called &&
            ((called.DeclaringType?.FullName == "System.IO.File" &&
              called.Name.Contains("WriteAllBytes", StringComparison.Ordinal)) ||
             (called.DeclaringType?.FullName == "System.IO.Stream" &&
              called.Name.Contains("WriteAsync", StringComparison.Ordinal)) ||
             called.Name == "InitializeArray")));
        bool hasArchiveExecutionMarker = methods
            .SelectMany(static method => method.Body.Instructions)
            .Select(static instruction => instruction.Operand as string)
            .Any(static literal =>
                literal?.Contains(".jar", StringComparison.OrdinalIgnoreCase) == true ||
                literal?.Contains("-cp ", StringComparison.OrdinalIgnoreCase) == true ||
                literal?.Contains("MemJarBootstrap", StringComparison.OrdinalIgnoreCase) == true);

        if (!hasMaterializationSink || !hasArchiveExecutionMarker)
        {
            return extractionFindings;
        }

        var archiveFields = EnumerateTypes(module)
            .SelectMany(static type => type.Fields)
            .Where(static field =>
                field.HasFieldRVA &&
                field.InitialValue is { Length: >= MinimumArchiveBytes and <= MaximumArchiveBytes } bytes &&
                IsZip(bytes))
            .ToList();

        return extractionFindings.Concat(archiveFields.Select(field => new ScanFinding(
            field.FullName,
            $"Detected embedded ZIP/JAR archive payload ({field.InitialValue.Length} bytes) paired with archive materialization and concealed child-process execution.",
            Severity,
            $"archive magic: PK; field: {field.FullName}; size: {field.InitialValue.Length} bytes")
        {
            RuleId = RuleId,
            RiskScore = 88,
            BypassCompanionCheck = true
        }));
    }

    private IEnumerable<ScanFinding> AnalyzeResourceExtraction(ModuleDefinition module)
    {
        foreach (var method in EnumerateTypes(module).SelectMany(static type => type.Methods).Where(static method => method.HasBody))
        {
            var instructions = method.Body.Instructions;
            var resources = new Dictionary<int, string>();
            for (int index = 0; index < instructions.Count; index++)
            {
                if (instructions[index].OpCode != OpCodes.Newobj ||
                    instructions[index].Operand is not MethodReference constructor ||
                    constructor.DeclaringType.FullName != "System.IO.Compression.ZipArchive" ||
                    !ExecutionTargetMatcher.TryGetArgumentSource(method, index, 0, out int stream) ||
                    !ExecutionTargetMatcher.IsCall(instructions[stream], "System.Reflection.Assembly", "GetManifestResourceStream") ||
                    !InstructionValueResolver.TryResolveCallArgumentDisplay(method, (MethodReference)instructions[stream].Operand,
                        instructions, stream, 0, out string resourceName))
                {
                    continue;
                }
                resources[index] = resourceName;
            }

            if (resources.Count == 0)
            {
                continue;
            }

            for (int index = 0; index < instructions.Count; index++)
            {
                if (instructions[index].Operand is not MethodReference extract ||
                    extract.DeclaringType.FullName != "System.IO.Compression.ZipFileExtensions" || extract.Name != "ExtractToFile" ||
                    !TryGetExtractedArchive(method, index, out int archiveIndex) ||
                    !resources.TryGetValue(archiveIndex, out string? resourceName) ||
                    !InstructionValueResolver.TryResolveCallArgumentDisplay(method, extract, instructions, index, 1, out string destination) ||
                    !destination.Replace('\\', '/').StartsWith("%TEMP%/", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (var resource in module.Resources.OfType<EmbeddedResource>().Where(resource => resource.Name == resourceName))
                {
                    string? selectedEntry = null;
                    if (ExecutionTargetMatcher.TryGetArgumentSource(method, index, 0, out int entrySource) &&
                        ExecutionTargetMatcher.IsCall(instructions[entrySource], "System.IO.Compression.ZipArchive", "GetEntry") &&
                        InstructionValueResolver.TryResolveCallArgumentDisplay(method, (MethodReference)instructions[entrySource].Operand,
                            instructions, entrySource, 0, out string entryName) && !entryName.StartsWith('<'))
                    {
                        selectedEntry = entryName;
                    }
                    if (!TryInspectArchive(resource, selectedEntry, out bool hasExecutable))
                    {
                        continue;
                    }
                    yield return new ScanFinding($"{method.DeclaringType.FullName}.{method.Name}:{instructions[index].Offset}",
                        hasExecutable ? "Embedded ZIP executable/script content extracted to TEMP (potential payload staging)." :
                        "Embedded ZIP content extracted to TEMP; no executable/script entries established (diagnostic only).",
                        hasExecutable ? Severity.High : Severity.Medium,
                        $"resource: {resource.Name}; destination: {destination}")
                    {
                        RuleId = RuleId, RiskScore = hasExecutable ? 85 : 40, BypassCompanionCheck = hasExecutable
                    };
                }
            }
        }
    }

    private static bool TryGetExtractedArchive(MethodDefinition method, int extractIndex, out int archive)
    {
        archive = -1;
        var instructions = method.Body.Instructions;
        if (!ExecutionTargetMatcher.TryGetArgumentSource(method, extractIndex, 0, out int entry))
        {
            return false;
        }
        if (ExecutionTargetMatcher.IsCall(instructions[entry], "System.IO.Compression.ZipArchive", "GetEntry"))
        {
            return ExecutionTargetMatcher.TryGetReceiverSource(method, entry, out archive);
        }
        return instructions[entry].Operand is MethodReference { Name: "get_Current" } &&
               ExecutionTargetMatcher.TryGetReceiverSource(method, entry, out int enumerator) &&
               instructions[enumerator].Operand is MethodReference { Name: "GetEnumerator" } &&
               ExecutionTargetMatcher.TryGetReceiverSource(method, enumerator, out int entries) &&
               ExecutionTargetMatcher.IsCall(instructions[entries], "System.IO.Compression.ZipArchive", "get_Entries") &&
               ExecutionTargetMatcher.TryGetReceiverSource(method, entries, out archive);
    }

    private static bool TryInspectArchive(EmbeddedResource resource, string? selectedEntry, out bool hasExecutable)
    {
        hasExecutable = false;
        try
        {
            using var stream = resource.GetResourceStream();
            if (stream.Length > MaximumArchiveBytes)
            {
                return false;
            }
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
            foreach (var entry in archive.Entries)
            {
                if ((selectedEntry == null || entry.FullName == selectedEntry) &&
                    Path.GetExtension(entry.FullName).ToLowerInvariant() is ".exe" or ".dll" or ".cmd" or ".bat" or ".ps1" or ".vbs" or ".js" or ".jar" or ".lnk" or ".url" or ".hta" or ".scr" or ".com")
                {
                    hasExecutable = true;
                    break;
                }
            }
            return true;
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or ArgumentException)
        {
            return false;
        }
    }

    private static bool IsZip(byte[] bytes) =>
        bytes.Length >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4B &&
        ((bytes[2] == 0x03 && bytes[3] == 0x04) ||
         (bytes[2] == 0x05 && bytes[3] == 0x06) ||
         (bytes[2] == 0x07 && bytes[3] == 0x08));

    private static bool Contains(string? value, string needle) =>
        value?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;

    private static IEnumerable<TypeDefinition> EnumerateTypes(ModuleDefinition module)
    {
        foreach (var type in module.Types)
        {
            yield return type;
            foreach (var nested in EnumerateNestedTypes(type))
            {
                yield return nested;
            }
        }
    }

    private static IEnumerable<TypeDefinition> EnumerateNestedTypes(TypeDefinition type)
    {
        foreach (var nested in type.NestedTypes)
        {
            yield return nested;
            foreach (var descendant in EnumerateNestedTypes(nested))
            {
                yield return descendant;
            }
        }
    }
}
