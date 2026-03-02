using System.Text;
using System.Text.RegularExpressions;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Comprehensive rule for detecting and scoring dynamic assembly loading.
    /// Replaces LoadFromStreamRule with overload-aware risk scoring, provenance tracing,
    /// recursive embedded resource scanning, AssemblyResolve handler analysis,
    /// reflective/obfuscated load detection, and post-load behavior correlation.
    /// </summary>
    public class AssemblyDynamicLoadRule : IScanRule
    {
        public string Description => "Detected dynamic assembly loading with risk indicators.";
        public Severity Severity => Severity.High;
        public string RuleId => "AssemblyDynamicLoadRule";
        public bool RequiresCompanionFinding => true;

        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "Avoid runtime assembly loading when possible. If necessary, detect the runtime " +
            "(IL2CPP vs Mono) using your framework's utilities. Ship dependencies as separate " +
            "assemblies in the appropriate framework directory (e.g., Mods/ folder for MelonLoader, " +
            "plugin folder for BepInEx). Reference assemblies at compile time instead of loading dynamically.",
            null,
            new[] {
                "MelonUtils.IsGameIl2Cpp() (MelonLoader)",
                "MelonMod.MelonAssembly (MelonLoader)",
                "IL2CPPUtils.IsGameIl2Cpp() (BepInEx 6.x)"
            },
            true
        );

        // Pending findings collected during AnalyzeContextualPattern, refined in PostAnalysisRefine
        private readonly List<PendingLoadFinding> _pendingFindings = new();

        #region Well-Known Safe Assembly Names

        private static readonly HashSet<string> SafeAssemblyPrefixes = new(StringComparer.OrdinalIgnoreCase)
        {
            "Il2Cpp", "Il2CppInterop", "0Harmony", "Harmony", "HarmonyLib",
            "Newtonsoft.Json", "UnityEngine", "Assembly-CSharp",
            "MelonLoader", "BepInEx", "MonoMod", "Mono.Cecil",
            "System", "Microsoft", "mscorlib", "netstandard",
            "NuGet", "Ionic.Zip", "DotNetZip", "LitJson", "YamlDotNet",
            "Steamworks", "Facepunch", "Sirenix", "UniTask"
        };

        private static readonly Regex SimpleAssemblyNamePattern =
            new(@"^[A-Za-z][A-Za-z0-9._\-]*$", RegexOptions.Compiled);

        #endregion

        #region IScanRule Implementation

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return IsAssemblyLoadMethod(typeName, methodName);
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(
            MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex,
            MethodSignals methodSignals)
        {
            if (method?.DeclaringType == null)
                yield break;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            if (!IsAssemblyLoadMethod(typeName, methodName))
                yield break;

            // Classify the overload
            var overload = ClassifyOverload(method);
            int baseScore = GetBaseScore(overload);

            // For Load(string) / Load(AssemblyName), check if the argument is a safe name
            if (overload == LoadOverload.LoadString || overload == LoadOverload.LoadAssemblyName)
            {
                var argName = ExtractStringArgument(instructions, instructionIndex);
                if (argName != null && IsSafeAssemblyName(argName))
                {
                    // Suppress entirely — this is a legitimate dependency probe
                    yield break;
                }
            }

            // Compute provenance score from backward slice
            var provenance = AnalyzeProvenance(instructions, instructionIndex);
            int provenanceScore = provenance.Score;

            // Compute post-load behavior score from forward slice
            int postLoadScore = AnalyzePostLoadBehavior(instructions, instructionIndex);

            // Compute evasion score (reflective invocation detected by context)
            int evasionScore = 0;

            // Compute AssemblyResolve bonus from method-level signals
            int resolveScore = 0;

            // Type-level correlation from MethodSignals
            int correlationScore = ComputeCorrelationScore(methodSignals);

            int totalScore = baseScore + provenanceScore + postLoadScore + evasionScore + resolveScore + correlationScore;

            // Map score to severity
            var severity = MapScoreToSeverity(totalScore);

            if (severity == null)
                yield break; // Score too low to report

            // Build description
            var desc = BuildDescription(overload, totalScore, provenance, severity.Value);

            // Build code snippet
            var snippetBuilder = new StringBuilder();
            int contextLines = 2;
            for (int j = Math.Max(0, instructionIndex - contextLines);
                 j < Math.Min(instructions.Count, instructionIndex + contextLines + 1);
                 j++)
            {
                snippetBuilder.Append(j == instructionIndex ? ">>> " : "    ");
                snippetBuilder.AppendLine(instructions[j].ToString());
            }

            var finding = new ScanFinding(
                $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                desc,
                severity.Value,
                snippetBuilder.ToString().TrimEnd())
            {
                RiskScore = totalScore,
                // Bypass companion check for Critical findings with strong evidence
                BypassCompanionCheck = totalScore >= 75
            };

            // Store pending finding for PostAnalysisRefine (resource scanning enrichment)
            if (provenance.HasResourceSource)
            {
                _pendingFindings.Add(new PendingLoadFinding
                {
                    Finding = finding,
                    ResourceName = provenance.ResourceName,
                    InstructionIndex = instructionIndex,
                    Overload = overload,
                    TotalScore = totalScore
                });
            }

            yield return finding;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(
            MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            // Detect AssemblyResolve / Resolving event subscription
            for (int i = 0; i < instructions.Count; i++)
            {
                var instr = instructions[i];
                if ((instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt) &&
                    instr.Operand is MethodReference calledMethod &&
                    calledMethod.DeclaringType != null)
                {
                    var declType = calledMethod.DeclaringType.FullName;
                    var mName = calledMethod.Name;

                    bool isResolveSubscription =
                        (declType == "System.AppDomain" && mName == "add_AssemblyResolve") ||
                        (declType.Contains("AssemblyLoadContext") && mName == "add_Resolving") ||
                        (declType.Contains("AssemblyLoadContext") && mName == "add_ResolvingUnmanagedDll");

                    if (!isResolveSubscription)
                        continue;

                    // Try to find the handler method via ldftn
                    var handlerMethod = FindDelegateTarget(instructions, i);
                    int handlerScore = 15; // base score for subscription

                    if (handlerMethod != null)
                    {
                        // Analyze the handler body
                        handlerScore += AnalyzeResolveHandler(handlerMethod);
                    }

                    // Determine severity based on handler analysis
                    var severity = handlerScore >= 50 ? Severity.High :
                                   handlerScore >= 25 ? Severity.Medium :
                                   Severity.Low;

                    var snippetBuilder = new StringBuilder();
                    for (int j = Math.Max(0, i - 2); j < Math.Min(instructions.Count, i + 3); j++)
                    {
                        snippetBuilder.Append(j == i ? ">>> " : "    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }

                    var handlerInfo = handlerMethod != null
                        ? $" Handler: {handlerMethod.DeclaringType?.Name}.{handlerMethod.Name}"
                        : "";

                    findings.Add(new ScanFinding(
                        $"{method.DeclaringType?.FullName}.{method.Name}:{instr.Offset}",
                        $"AssemblyResolve/Resolving event subscription detected (score {handlerScore}).{handlerInfo}",
                        severity,
                        snippetBuilder.ToString().TrimEnd())
                    {
                        RiskScore = handlerScore,
                        BypassCompanionCheck = handlerScore >= 50
                    });
                }
            }

            // Detect reflective invocation of assembly load methods
            findings.AddRange(DetectReflectiveLoadInvocation(method, instructions, methodSignals));

            return findings;
        }

        public IEnumerable<ScanFinding> PostAnalysisRefine(
            ModuleDefinition module,
            IEnumerable<ScanFinding> existingFindings)
        {
            var additionalFindings = new List<ScanFinding>();

            foreach (var pending in _pendingFindings)
            {
                if (string.IsNullOrEmpty(pending.ResourceName))
                    continue;

                // Try to find and scan the embedded resource
                var innerFindings = ScanEmbeddedResource(module, pending.ResourceName);
                if (innerFindings.Count > 0)
                {
                    // Compute boost from inner findings
                    int innerBoost = innerFindings.Any(f => f.Severity >= Severity.Critical) ? 50 :
                                     innerFindings.Any(f => f.Severity >= Severity.High) ? 30 :
                                     innerFindings.Any(f => f.Severity >= Severity.Medium) ? 15 : 5;

                    int newScore = pending.TotalScore + innerBoost;
                    var newSeverity = MapScoreToSeverity(newScore) ?? Severity.High;

                    // Build description of inner findings
                    var innerDesc = string.Join("; ",
                        innerFindings.Take(3).Select(f => $"[{f.Severity}] {f.Description}"));
                    if (innerFindings.Count > 3)
                        innerDesc += $" (+{innerFindings.Count - 3} more)";

                    additionalFindings.Add(new ScanFinding(
                        pending.Finding.Location,
                        $"Embedded assembly '{pending.ResourceName}' loaded from resources contains suspicious code: {innerDesc} (combined score {newScore})",
                        newSeverity,
                        pending.Finding.CodeSnippet)
                    {
                        RiskScore = newScore,
                        BypassCompanionCheck = newScore >= 50 // Lower threshold for recursive findings
                    });
                }
            }

            _pendingFindings.Clear();
            return additionalFindings;
        }

        #endregion

        #region Overload Classification

        private enum LoadOverload
        {
            LoadBytes,          // Assembly.Load(byte[])
            LoadBytesWithPdb,   // Assembly.Load(byte[], byte[])
            LoadString,         // Assembly.Load(string)
            LoadAssemblyName,   // Assembly.Load(AssemblyName)
            LoadFrom,           // Assembly.LoadFrom(string)
            LoadFile,           // Assembly.LoadFile(string)
            ALCLoadFromStream,  // AssemblyLoadContext.LoadFromStream(Stream)
            ALCLoadFromStreamPdb, // AssemblyLoadContext.LoadFromStream(Stream, Stream)
            ALCLoadFromPath,    // AssemblyLoadContext.LoadFromAssemblyPath(string)
            Unknown
        }

        private static LoadOverload ClassifyOverload(MethodReference method)
        {
            var declType = method.DeclaringType?.FullName ?? "";
            var name = method.Name;
            int paramCount = method.Parameters.Count;

            if (declType == "System.Reflection.Assembly")
            {
                if (name == "Load")
                {
                    if (paramCount == 0)
                        return LoadOverload.Unknown;

                    var firstParam = method.Parameters[0].ParameterType.FullName;
                    if (firstParam == "System.Byte[]")
                        return paramCount == 1 ? LoadOverload.LoadBytes : LoadOverload.LoadBytesWithPdb;
                    if (firstParam == "System.String")
                        return LoadOverload.LoadString;
                    if (firstParam == "System.Reflection.AssemblyName")
                        return LoadOverload.LoadAssemblyName;
                }
                if (name == "LoadFrom")
                    return LoadOverload.LoadFrom;
                if (name == "LoadFile")
                    return LoadOverload.LoadFile;
            }

            if (declType.Contains("AssemblyLoadContext"))
            {
                if (name == "LoadFromStream")
                    return paramCount <= 1 ? LoadOverload.ALCLoadFromStream : LoadOverload.ALCLoadFromStreamPdb;
                if (name == "LoadFromAssemblyPath")
                    return LoadOverload.ALCLoadFromPath;
            }

            return LoadOverload.Unknown;
        }

        private static int GetBaseScore(LoadOverload overload) => overload switch
        {
            LoadOverload.LoadBytesWithPdb => 50,
            LoadOverload.LoadBytes => 45,
            LoadOverload.ALCLoadFromStream => 45,
            LoadOverload.ALCLoadFromStreamPdb => 50,
            LoadOverload.LoadFile => 35,
            LoadOverload.LoadFrom => 30,
            LoadOverload.ALCLoadFromPath => 30,
            LoadOverload.LoadString => 10,
            LoadOverload.LoadAssemblyName => 10,
            _ => 20
        };

        #endregion

        #region Safe Assembly Name Check

        private static bool IsSafeAssemblyName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            // Check against known safe prefixes
            foreach (var prefix in SafeAssemblyPrefixes)
            {
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Check if it looks like a valid simple assembly name (not a path, URL, or encoded data)
            if (!SimpleAssemblyNamePattern.IsMatch(name))
                return false;

            // If it's a simple name without suspicious characteristics, treat as likely safe
            // (still emits Low finding in caller for audit)
            return name.Length < 200 && !name.Contains("://") && !name.Contains("\\") && !name.Contains("/");
        }

        #endregion

        #region Provenance Analysis (Backward Slice)

        private class ProvenanceResult
        {
            public int Score { get; set; }
            public bool HasNetworkSource { get; set; }
            public bool HasBase64 { get; set; }
            public bool HasCrypto { get; set; }
            public bool HasCompression { get; set; }
            public bool HasResourceSource { get; set; }
            public bool HasTempPath { get; set; }
            public bool HasSensitivePath { get; set; }
            public bool HasWriteThenLoad { get; set; }
            public string? ResourceName { get; set; }

            public string GetSummary()
            {
                var parts = new List<string>();
                if (HasNetworkSource)
                    parts.Add("network");
                if (HasBase64)
                    parts.Add("base64");
                if (HasCrypto)
                    parts.Add("crypto");
                if (HasCompression)
                    parts.Add("compression");
                if (HasResourceSource)
                    parts.Add("resource");
                if (HasTempPath)
                    parts.Add("temp-path");
                if (HasSensitivePath)
                    parts.Add("sensitive-path");
                if (HasWriteThenLoad)
                    parts.Add("write-then-load");
                return parts.Count > 0 ? string.Join(" -> ", parts) : "unknown";
            }
        }

        private static ProvenanceResult AnalyzeProvenance(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int loadCallIndex)
        {
            var result = new ProvenanceResult();
            int windowStart = Math.Max(0, loadCallIndex - 200);

            for (int i = windowStart; i < loadCallIndex; i++)
            {
                var instr = instructions[i];

                // Check method calls for provenance indicators
                if ((instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt) &&
                    instr.Operand is MethodReference calledMethod &&
                    calledMethod.DeclaringType != null)
                {
                    var declType = calledMethod.DeclaringType.FullName;
                    var mName = calledMethod.Name;

                    // Network sources
                    if ((declType.StartsWith("System.Net") || declType.Contains("HttpClient") ||
                         declType.Contains("WebClient") || declType.Contains("UnityWebRequest")) &&
                        (mName.Contains("Get") || mName.Contains("Download") || mName.Contains("Receive")))
                    {
                        result.HasNetworkSource = true;
                        result.Score += 25;
                    }

                    // Base64
                    if (declType == "System.Convert" && mName == "FromBase64String")
                    {
                        result.HasBase64 = true;
                        result.Score += 15;
                    }

                    // Crypto
                    if (declType.Contains("System.Security.Cryptography") &&
                        (mName == "Create" || mName == "CreateDecryptor" ||
                         mName == "TransformFinalBlock" || mName == "TransformBlock"))
                    {
                        result.HasCrypto = true;
                        result.Score += 25;
                    }
                    if ((declType.Contains("RijndaelManaged") || declType.Contains("DESCryptoServiceProvider") ||
                         declType.Contains("TripleDES") || declType.Contains("RC2")) && mName == ".ctor")
                    {
                        result.HasCrypto = true;
                        result.Score += 25;
                    }

                    // Compression
                    if ((declType.Contains("GZipStream") || declType.Contains("DeflateStream") ||
                         declType.Contains("BrotliStream")) && mName == ".ctor")
                    {
                        result.HasCompression = true;
                        result.Score += 15;
                    }

                    // Resource source
                    if (declType.Contains("Assembly") && mName == "GetManifestResourceStream")
                    {
                        result.HasResourceSource = true;
                        result.Score += 10;

                        // Try to extract resource name from preceding ldstr
                        if (i > 0 && instructions[i - 1].OpCode == OpCodes.Ldstr &&
                            instructions[i - 1].Operand is string resName)
                        {
                            result.ResourceName = resName;
                        }
                    }

                    // File operations from temp/sensitive paths
                    if (declType.StartsWith("System.IO.File") &&
                        (mName.Contains("Read") || mName == "ReadAllBytes"))
                    {
                        result.Score += 5;
                    }

                    if ((declType == "System.IO.Path" && mName == "GetTempPath") ||
                        (declType == "System.IO.Path" && mName == "GetTempFileName"))
                    {
                        result.HasTempPath = true;
                        result.Score += 10;
                    }

                    if (declType == "System.Environment" && mName == "GetFolderPath")
                    {
                        result.HasSensitivePath = true;
                        result.Score += 20;
                    }

                    // Write-then-load pattern
                    if (declType.StartsWith("System.IO.File") &&
                        (mName.Contains("Write") || mName.Contains("Create")))
                    {
                        result.HasWriteThenLoad = true;
                        result.Score += 15;
                    }
                }

                // Check string literals for suspicious content
                if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string literal)
                {
                    if (literal.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                        literal.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!result.HasNetworkSource)
                        {
                            result.HasNetworkSource = true;
                            result.Score += 25;
                        }
                    }

                    if (literal.Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
                        literal.Contains("AppData", StringComparison.OrdinalIgnoreCase) ||
                        literal.Contains("ProgramData", StringComparison.OrdinalIgnoreCase) ||
                        literal.Contains("Startup", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!result.HasSensitivePath)
                        {
                            result.HasSensitivePath = true;
                            result.Score += 15;
                        }
                    }
                }
            }

            // Cap provenance score to avoid over-inflation
            result.Score = Math.Min(result.Score, 80);
            return result;
        }

        #endregion

        #region Post-Load Behavior Analysis (Forward Slice)

        private static int AnalyzePostLoadBehavior(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int loadCallIndex)
        {
            int score = 0;
            int windowEnd = Math.Min(instructions.Count, loadCallIndex + 100);
            bool foundEntryPoint = false;
            bool foundInvoke = false;
            bool foundGetType = false;
            bool foundCreateInstance = false;

            for (int i = loadCallIndex + 1; i < windowEnd; i++)
            {
                var instr = instructions[i];
                if ((instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt) ||
                    instr.Operand is not MethodReference calledMethod ||
                    calledMethod.DeclaringType == null)
                    continue;

                var declType = calledMethod.DeclaringType.FullName;
                var mName = calledMethod.Name;

                // Assembly.EntryPoint access (get_EntryPoint)
                if (declType == "System.Reflection.Assembly" && mName == "get_EntryPoint" && !foundEntryPoint)
                {
                    foundEntryPoint = true;
                    score += 10;
                }

                // MethodInfo.Invoke / MethodBase.Invoke
                if ((declType == "System.Reflection.MethodInfo" || declType == "System.Reflection.MethodBase") &&
                    mName == "Invoke" && !foundInvoke)
                {
                    foundInvoke = true;
                    score += 15;
                }

                // Assembly.GetType / GetTypes
                if (declType == "System.Reflection.Assembly" &&
                    (mName == "GetType" || mName == "GetTypes") && !foundGetType)
                {
                    foundGetType = true;
                    score += 5;
                }

                // Activator.CreateInstance
                if (declType == "System.Activator" && mName == "CreateInstance" && !foundCreateInstance)
                {
                    foundCreateInstance = true;
                    score += 10;
                }
            }

            return Math.Min(score, 30);
        }

        #endregion

        #region Method Signal Correlation

        private static int ComputeCorrelationScore(MethodSignals? signals)
        {
            if (signals == null)
                return 0;

            int score = 0;

            if (signals.HasProcessLikeCall)
                score += 30;
            if (signals.HasNetworkCall)
                score += 20;
            if (signals.HasFileWrite && signals.UsesSensitiveFolder)
                score += 25;
            if (signals.HasEncodedStrings)
                score += 10;
            if (signals.HasBase64)
                score += 10;

            return Math.Min(score, 50);
        }

        #endregion

        #region AssemblyResolve Handler Analysis

        private static MethodDefinition? FindDelegateTarget(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int subscribeCallIndex)
        {
            // Walk backward to find ldftn which loads the handler method pointer
            for (int i = subscribeCallIndex - 1; i >= Math.Max(0, subscribeCallIndex - 10); i--)
            {
                var instr = instructions[i];
                if (instr.OpCode == OpCodes.Ldftn && instr.Operand is MethodReference handlerRef)
                {
                    // Try to resolve to a definition
                    try
                    {
                        return handlerRef.Resolve();
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
            return null;
        }

        private static int AnalyzeResolveHandler(MethodDefinition handler)
        {
            if (!handler.HasBody)
                return 0;

            int score = 0;
            var instructions = handler.Body.Instructions;
            bool hasLoadBytes = false;
            bool hasCrypto = false;
            bool hasNetwork = false;
            bool hasResource = false;
            bool hasCompression = false;
            bool isCosturaLike = false;

            foreach (var instr in instructions)
            {
                if ((instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt &&
                     instr.OpCode != OpCodes.Newobj) ||
                    instr.Operand is not MethodReference calledMethod ||
                    calledMethod.DeclaringType == null)
                    continue;

                var declType = calledMethod.DeclaringType.FullName;
                var mName = calledMethod.Name;

                // Check for Assembly.Load(byte[])
                if (declType == "System.Reflection.Assembly" && mName == "Load")
                {
                    if (calledMethod.Parameters.Count > 0 &&
                        calledMethod.Parameters[0].ParameterType.FullName == "System.Byte[]")
                    {
                        hasLoadBytes = true;
                    }
                }

                // Crypto
                if (declType.Contains("System.Security.Cryptography"))
                    hasCrypto = true;

                // Network
                if (declType.StartsWith("System.Net") || declType.Contains("HttpClient") ||
                    declType.Contains("WebClient"))
                    hasNetwork = true;

                // Resource access
                if (declType.Contains("Assembly") && mName == "GetManifestResourceStream")
                    hasResource = true;

                // Compression
                if (declType.Contains("GZipStream") || declType.Contains("DeflateStream"))
                    hasCompression = true;
            }

            // Detect Costura-like pattern: resource loading without crypto/network
            if (hasResource && hasLoadBytes && !hasCrypto && !hasNetwork)
            {
                // Check if the type name suggests Costura
                if (handler.DeclaringType?.FullName?.Contains("Costura") == true ||
                    handler.DeclaringType?.Namespace?.Contains("Costura") == true)
                {
                    isCosturaLike = true;
                }
                // Also check for resource names starting with "costura."
                foreach (var instr in instructions)
                {
                    if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string s &&
                        s.StartsWith("costura.", StringComparison.OrdinalIgnoreCase))
                    {
                        isCosturaLike = true;
                        break;
                    }
                }
            }

            if (isCosturaLike)
                return 0; // Costura is legitimate

            // Score based on what we found
            if (hasLoadBytes)
                score += 15;
            if (hasCrypto)
                score += 25;
            if (hasNetwork)
                score += 25;
            if (hasCompression)
                score += 10;

            // Resource + LoadBytes without crypto/network is common for dependency bundling
            if (hasResource && hasLoadBytes && !hasCrypto && !hasNetwork)
                score = Math.Min(score, 10);

            return score;
        }

        #endregion

        #region Reflective Load Detection

        private static IEnumerable<ScanFinding> DetectReflectiveLoadInvocation(
            MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            MethodSignals? methodSignals)
        {
            var findings = new List<ScanFinding>();

            for (int i = 0; i < instructions.Count; i++)
            {
                var instr = instructions[i];
                if ((instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt) ||
                    instr.Operand is not MethodReference calledMethod ||
                    calledMethod.DeclaringType == null)
                    continue;

                var declType = calledMethod.DeclaringType.FullName;
                var mName = calledMethod.Name;

                // Pattern: Type.GetMethod("Load"/"LoadFrom"/"LoadFile") + Invoke
                if (declType == "System.Type" && mName == "GetMethod")
                {
                    // Look for preceding ldstr with load-family method name
                    string? targetMethodName = null;
                    for (int j = i - 1; j >= Math.Max(0, i - 5); j--)
                    {
                        if (instructions[j].OpCode == OpCodes.Ldstr &&
                            instructions[j].Operand is string str)
                        {
                            if (str == "Load" || str == "LoadFrom" || str == "LoadFile" ||
                                str == "LoadFromStream" || str == "LoadFromAssemblyPath")
                            {
                                targetMethodName = str;
                            }
                            break;
                        }
                    }

                    if (targetMethodName == null)
                        continue;

                    // Check if we also have Assembly type context nearby
                    bool hasAssemblyContext = false;
                    for (int j = Math.Max(0, i - 15); j < Math.Min(instructions.Count, i + 15); j++)
                    {
                        if (instructions[j].OpCode == OpCodes.Ldstr &&
                            instructions[j].Operand is string s &&
                            (s.Contains("System.Reflection.Assembly") || s.Contains("AssemblyLoadContext")))
                        {
                            hasAssemblyContext = true;
                            break;
                        }
                        if (instructions[j].OpCode == OpCodes.Ldtoken &&
                            instructions[j].Operand is TypeReference typeRef &&
                            (typeRef.FullName == "System.Reflection.Assembly" ||
                             typeRef.FullName.Contains("AssemblyLoadContext")))
                        {
                            hasAssemblyContext = true;
                            break;
                        }
                    }

                    if (!hasAssemblyContext)
                        continue;

                    int evasionScore = 20 + GetBaseScore(LoadOverload.Unknown);

                    var snippetBuilder = new StringBuilder();
                    for (int j = Math.Max(0, i - 3); j < Math.Min(instructions.Count, i + 4); j++)
                    {
                        snippetBuilder.Append(j == i ? ">>> " : "    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }

                    findings.Add(new ScanFinding(
                        $"{method.DeclaringType?.FullName}.{method.Name}:{instr.Offset}",
                        $"Reflective invocation of Assembly.{targetMethodName} detected via GetMethod (evasion technique, score {evasionScore})",
                        evasionScore >= 50 ? Severity.High : Severity.Medium,
                        snippetBuilder.ToString().TrimEnd())
                    {
                        RiskScore = evasionScore,
                        BypassCompanionCheck = evasionScore >= 50
                    });
                }
            }

            return findings;
        }

        #endregion

        #region Recursive Embedded Resource Scanning

        private static List<ScanFinding> ScanEmbeddedResource(ModuleDefinition module, string resourceName)
        {
            var findings = new List<ScanFinding>();

            try
            {
                if (!module.HasResources)
                    return findings;

                // Find the resource
                EmbeddedResource? resource = null;
                foreach (var res in module.Resources)
                {
                    if (res is EmbeddedResource embedded && res.Name == resourceName)
                    {
                        resource = embedded;
                        break;
                    }
                }

                if (resource == null)
                    return findings;

                var resourceData = resource.GetResourceData();
                if (resourceData == null || resourceData.Length == 0)
                    return findings;

                // Size limit: skip resources larger than 10MB
                if (resourceData.Length > 10 * 1024 * 1024)
                    return findings;

                // Check if it looks like a PE/assembly (MZ header)
                if (resourceData.Length < 2 || resourceData[0] != 0x4D || resourceData[1] != 0x5A)
                {
                    // Try GZip decompression if it starts with GZip magic bytes
                    if (resourceData.Length > 2 && resourceData[0] == 0x1F && resourceData[1] == 0x8B)
                    {
                        try
                        {
                            using var compressedStream = new System.IO.MemoryStream(resourceData);
                            using var gzipStream = new System.IO.Compression.GZipStream(
                                compressedStream, System.IO.Compression.CompressionMode.Decompress);
                            using var decompressedStream = new System.IO.MemoryStream();
                            gzipStream.CopyTo(decompressedStream);
                            resourceData = decompressedStream.ToArray();

                            // Re-check for MZ header after decompression
                            if (resourceData.Length < 2 || resourceData[0] != 0x4D || resourceData[1] != 0x5A)
                                return findings;
                        }
                        catch
                        {
                            return findings; // Decompression failed, skip
                        }
                    }
                    else
                    {
                        return findings; // Not a PE
                    }
                }

                // Try to read as assembly
                try
                {
                    using var resourceStream = new System.IO.MemoryStream(resourceData);
                    var readerParams = new ReaderParameters
                    {
                        ReadWrite = false,
                        InMemory = true,
                        ReadSymbols = false
                    };
                    var innerAssembly = AssemblyDefinition.ReadAssembly(resourceStream, readerParams);

                    // Run a limited scan on the inner assembly using default rules
                    var innerRules = RuleFactory.CreateDefaultRules()
                        .Where(r => r is not AssemblyDynamicLoadRule) // Prevent infinite recursion
                        .ToList();
                    var innerScanner = new MLVScan.Services.AssemblyScanner(innerRules);

                    using var innerScanStream = new System.IO.MemoryStream(resourceData);
                    var innerFindings = innerScanner.Scan(innerScanStream, $"embedded:{resourceName}").ToList();

                    // Only return Medium+ findings from inner scan
                    findings.AddRange(innerFindings.Where(f => f.Severity >= Severity.Medium));
                }
                catch
                {
                    // Not a valid assembly, skip
                }
            }
            catch
            {
                // Resource analysis failed, skip
            }

            return findings;
        }

        #endregion

        #region Helpers

        private static bool IsAssemblyLoadMethod(string typeName, string methodName)
        {
            if (typeName == "System.Reflection.Assembly" &&
                (methodName == "Load" || methodName == "LoadFrom" || methodName == "LoadFile"))
                return true;

            if (typeName.Contains("AssemblyLoadContext") &&
                (methodName == "LoadFromStream" || methodName == "LoadFromAssemblyPath"))
                return true;

            return false;
        }

        private static string? ExtractStringArgument(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex)
        {
            // Walk backward to find the ldstr that pushes the first argument
            for (int i = callIndex - 1; i >= Math.Max(0, callIndex - 10); i--)
            {
                var instr = instructions[i];
                if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string str)
                    return str;

                // Stop if we hit another call (argument likely comes from a call return)
                if (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt)
                    return null;
            }
            return null;
        }

        private static Severity? MapScoreToSeverity(int score)
        {
            if (score < 15)
                return null; // Suppress
            if (score < 25)
                return Severity.Low;
            if (score < 50)
                return Severity.Medium;
            if (score < 75)
                return Severity.High;
            return Severity.Critical;
        }

        private static string BuildDescription(
            LoadOverload overload,
            int totalScore,
            ProvenanceResult provenance,
            Severity severity)
        {
            var overloadName = overload switch
            {
                LoadOverload.LoadBytes => "Assembly.Load(byte[])",
                LoadOverload.LoadBytesWithPdb => "Assembly.Load(byte[], byte[])",
                LoadOverload.LoadString => "Assembly.Load(string)",
                LoadOverload.LoadAssemblyName => "Assembly.Load(AssemblyName)",
                LoadOverload.LoadFrom => "Assembly.LoadFrom(string)",
                LoadOverload.LoadFile => "Assembly.LoadFile(string)",
                LoadOverload.ALCLoadFromStream => "AssemblyLoadContext.LoadFromStream",
                LoadOverload.ALCLoadFromStreamPdb => "AssemblyLoadContext.LoadFromStream (with PDB)",
                LoadOverload.ALCLoadFromPath => "AssemblyLoadContext.LoadFromAssemblyPath",
                _ => "Assembly.Load (unknown overload)"
            };

            var provenanceSummary = provenance.GetSummary();
            if (provenanceSummary == "unknown")
                return $"Dynamic assembly load detected ({overloadName}, score {totalScore})";

            return $"Dynamic assembly load detected ({overloadName}, score {totalScore}): provenance: {provenanceSummary}";
        }

        #endregion

        #region Internal Types

        private class PendingLoadFinding
        {
            public ScanFinding Finding { get; set; } = null!;
            public string? ResourceName { get; set; }
            public int InstructionIndex { get; set; }
            public LoadOverload Overload { get; set; }
            public int TotalScore { get; set; }
        }

        #endregion
    }
}
