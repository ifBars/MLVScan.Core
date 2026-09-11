using System.Text;
using MLVScan.Abstractions;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules;

/// <summary>
/// Correlates high-risk payload delivery, persistence, and execution operations that are deliberately
/// split across sibling helper methods or compiler-generated async state machines.
/// </summary>
public sealed class CoordinatedPayloadDeliveryRule : IScanRule
{
    /// <inheritdoc />
    public string Description =>
        "Detected coordinated payload delivery, persistence, and concealed execution across multiple methods.";

    /// <inheritdoc />
    public Severity Severity => Severity.Critical;

    /// <inheritdoc />
    public string RuleId => "CoordinatedPayloadDeliveryRule";

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

        var priorFindings = existingFindings?.ToList() ?? [];
        var findings = new List<ScanFinding>();

        foreach (var namespaceGroup in module.Types
                     .Where(static type => !string.IsNullOrWhiteSpace(type.Namespace))
                     .GroupBy(static type => type.Namespace, StringComparer.Ordinal))
        {
            var namespaceTypes = namespaceGroup.SelectMany(EnumerateTypeAndNested).ToList();
            var methods = namespaceTypes
                .SelectMany(EnumerateMethods)
                .Where(static method => method.HasBody)
                .ToList();
            var calls = methods
                .SelectMany(static method => method.Body.Instructions
                    .Where(static instruction => instruction.Operand is MethodReference)
                    .Select(instruction => (Method: method, Called: (MethodReference)instruction.Operand)))
                .ToList();
            var literals = methods
                .SelectMany(static method => method.Body.Instructions)
                .Where(static instruction => instruction.OpCode == OpCodes.Ldstr)
                .Select(static instruction => instruction.Operand as string)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Cast<string>()
                .ToList();
            var scopedProcessFindings = priorFindings
                .Where(finding =>
                    string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
                    finding.Location.StartsWith(namespaceGroup.Key + ".", StringComparison.Ordinal))
                .ToList();

            if (IsArchiveAutorunHiddenLaunch(calls, literals, scopedProcessFindings))
            {
                findings.Add(CreateFinding(
                    namespaceGroup.Key,
                    "Detected coordinated archive payload delivery to a user-profile location, Windows autorun persistence, and hidden executable launch across sibling methods.",
                    [
                        DescribeCall(calls, IsNetworkRead, "network read"),
                        DescribeCall(calls, IsArchiveExtraction, "archive extraction"),
                        DescribeCall(calls, IsRegistryWrite, "registry autorun write"),
                        "staging: user-profile path with archive payload",
                        "execution: concealed Process.Start with hidden arguments"
                    ]));
            }

            if (IsBlockchainResolvedJavaStager(methods, calls, literals, scopedProcessFindings))
            {
                findings.Add(CreateFinding(
                    namespaceGroup.Key,
                    "Detected coordinated blockchain-resolved Java archive stager: EVM RPC service discovery, fixed-key string decoding, JAR staging, and hidden or elevated Java execution.",
                    [
                        DescribeCall(calls, IsNetworkSend, "EVM RPC/network send"),
                        DescribeCall(calls, IsFileWrite, "archive write"),
                        "transform: fixed-key XOR string reconstruction",
                        "staging: .jar classpath payload",
                        "execution: hidden or elevated Java child process"
                    ]));
            }
        }

        return findings;
    }

    private static bool IsArchiveAutorunHiddenLaunch(
        IReadOnlyList<(MethodDefinition Method, MethodReference Called)> calls,
        IReadOnlyList<string> literals,
        IReadOnlyList<ScanFinding> processFindings)
    {
        bool hasHiddenLaunch = processFindings.Any(finding =>
            Contains(finding.Description, "CreateNoWindow=true") &&
            Contains(finding.Description, "WindowStyle=Hidden") &&
            Contains(finding.Description, "--hidden"));

        return calls.Any(call => IsNetworkRead(call.Called)) &&
               calls.Any(call => IsFileWrite(call.Called)) &&
               calls.Any(call => IsArchiveExtraction(call.Called)) &&
               calls.Any(call => IsRegistryWrite(call.Called)) &&
               calls.Any(call => IsUserProfilePath(call.Called)) &&
               literals.Any(static literal => literal.Contains(".zip", StringComparison.OrdinalIgnoreCase)) &&
               literals.Any(static literal =>
                   literal.Contains(@"CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)) &&
               hasHiddenLaunch;
    }

    private static bool IsBlockchainResolvedJavaStager(
        IReadOnlyList<MethodDefinition> methods,
        IReadOnlyList<(MethodDefinition Method, MethodReference Called)> calls,
        IReadOnlyList<string> literals,
        IReadOnlyList<ScanFinding> processFindings)
    {
        bool hasFixedKeyXorDecoder = methods.Any(method =>
            method.Body.Instructions.Any(static instruction => instruction.OpCode == OpCodes.Xor) &&
            method.Body.Instructions.Any(instruction =>
                instruction.Operand is MethodReference called &&
                called.DeclaringType?.FullName == "System.Text.Encoding" &&
                called.Name == "GetString"));
        bool hasEvmLookup = literals.Any(static literal =>
                                literal.Equals("eth_call", StringComparison.OrdinalIgnoreCase)) &&
                            literals.Any(static literal =>
                                literal.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                                literal.Length >= 10);
        bool hasJavaArchiveMarkers = literals.Any(static literal =>
                                         literal.Contains(".jar", StringComparison.OrdinalIgnoreCase)) &&
                                     literals.Any(static literal =>
                                         literal.Contains("-cp ", StringComparison.OrdinalIgnoreCase) ||
                                         literal.Contains("MemJarBootstrap", StringComparison.OrdinalIgnoreCase) ||
                                         literal.Contains("com.renderassist.Main", StringComparison.OrdinalIgnoreCase));
        bool hasConcealedJavaLaunch = processFindings.Any(finding =>
            Contains(finding.Description, "WindowStyle=Hidden") ||
            Contains(finding.Description, "Redirected I/O") ||
            Contains(finding.Description, "CreateNoWindow=true"));

        return hasFixedKeyXorDecoder &&
               hasEvmLookup &&
               hasJavaArchiveMarkers &&
               hasConcealedJavaLaunch &&
               calls.Any(call => IsNetworkSend(call.Called)) &&
               calls.Any(call => IsFileWrite(call.Called)) &&
               calls.Any(call => IsProcessStart(call.Called));
    }

    private static bool IsNetworkRead(MethodReference method)
    {
        string type = method.DeclaringType?.FullName ?? string.Empty;
        string name = method.Name;
        return IsNetworkType(type) &&
               (name.Contains("GetResponse", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("GetAsync", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("GetByteArray", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("GetStream", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Download", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Get", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsNetworkSend(MethodReference method)
    {
        string type = method.DeclaringType?.FullName ?? string.Empty;
        string name = method.Name;
        return IsNetworkType(type) &&
               (name.Contains("Post", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Put", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Send", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("Upload", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("GetRequestStream", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsNetworkType(string type) =>
        type.StartsWith("System.Net", StringComparison.OrdinalIgnoreCase) ||
        type.Contains("UnityWebRequest", StringComparison.OrdinalIgnoreCase);

    private static bool IsArchiveExtraction(MethodReference method) =>
        method.DeclaringType?.FullName == "System.IO.Compression.ZipFile" &&
        method.Name.Contains("ExtractToDirectory", StringComparison.Ordinal);

    private static bool IsFileWrite(MethodReference method)
    {
        string type = method.DeclaringType?.FullName ?? string.Empty;
        return (type == "System.IO.File" &&
                (method.Name.StartsWith("Write", StringComparison.Ordinal) ||
                 method.Name == "Create")) ||
               (type == "System.IO.FileStream" && method.Name == ".ctor") ||
               (type == "System.IO.Stream" &&
                (method.Name.Contains("CopyTo", StringComparison.Ordinal) ||
                 method.Name.Contains("Write", StringComparison.Ordinal)));
    }

    private static bool IsRegistryWrite(MethodReference method)
    {
        string type = method.DeclaringType?.FullName ?? string.Empty;
        return type.Contains("Registry", StringComparison.OrdinalIgnoreCase) &&
               (method.Name.Contains("SetValue", StringComparison.OrdinalIgnoreCase) ||
                method.Name.Contains("CreateSubKey", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsUserProfilePath(MethodReference method) =>
        method.DeclaringType?.FullName == "System.Environment" && method.Name == "GetFolderPath";

    private static bool IsProcessStart(MethodReference method) =>
        method.DeclaringType?.FullName == "System.Diagnostics.Process" && method.Name == "Start";

    private static string DescribeCall(
        IEnumerable<(MethodDefinition Method, MethodReference Called)> calls,
        Func<MethodReference, bool> predicate,
        string fallback)
    {
        var match = calls.FirstOrDefault(call => predicate(call.Called));
        return match.Called == null
            ? fallback
            : $"{fallback}: {match.Called.DeclaringType?.FullName}.{match.Called.Name} in {match.Method.FullName}";
    }

    private ScanFinding CreateFinding(string location, string description, IEnumerable<string> evidence)
    {
        return new ScanFinding(location, description, Severity, string.Join(Environment.NewLine, evidence))
        {
            RuleId = RuleId,
            RiskScore = 98,
            BypassCompanionCheck = true
        };
    }

    private static bool Contains(string? value, string needle) =>
        value?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;

    private static IEnumerable<TypeDefinition> EnumerateTypes(ModuleDefinition module)
    {
        foreach (var type in module.Types)
        {
            foreach (var item in EnumerateTypeAndNested(type))
            {
                yield return item;
            }
        }
    }

    private static IEnumerable<TypeDefinition> EnumerateTypeAndNested(TypeDefinition type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
        {
            foreach (var item in EnumerateTypeAndNested(nested))
            {
                yield return item;
            }
        }
    }

    private static IEnumerable<MethodDefinition> EnumerateMethods(TypeDefinition type) => type.Methods;
}
