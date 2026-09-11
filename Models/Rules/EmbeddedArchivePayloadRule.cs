using MLVScan.Abstractions;
using Mono.Cecil;

namespace MLVScan.Models.Rules;

/// <summary>
/// Detects embedded archive bytes that are materialized and handed to a process-execution path.
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

        bool hasProcessExecution = existingFindings?.Any(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            (Contains(finding.Description, "Redirected I/O") ||
             Contains(finding.Description, "WindowStyle=Hidden") ||
             Contains(finding.Description, "CreateNoWindow=true"))) == true;
        if (!hasProcessExecution)
        {
            return [];
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
            return [];
        }

        var archiveFields = EnumerateTypes(module)
            .SelectMany(static type => type.Fields)
            .Where(static field =>
                field.HasFieldRVA &&
                field.InitialValue is { Length: >= MinimumArchiveBytes and <= MaximumArchiveBytes } bytes &&
                IsZip(bytes))
            .ToList();

        return archiveFields.Select(field => new ScanFinding(
            field.FullName,
            $"Detected embedded ZIP/JAR archive payload ({field.InitialValue.Length} bytes) paired with archive materialization and concealed child-process execution.",
            Severity,
            $"archive magic: PK; field: {field.FullName}; size: {field.InitialValue.Length} bytes")
        {
            RuleId = RuleId,
            RiskScore = 88,
            BypassCompanionCheck = true
        });
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
