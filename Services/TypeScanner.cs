using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Diagnostics;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.ComponentModel;

namespace MLVScan.Services
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class TypeScanner
    {
        private static readonly HashSet<string> ReflectionCompanionRuleIds = new(StringComparer.Ordinal)
        {
            "ProcessStartRule",
            "Shell32Rule",
            "COMReflectionAttackRule",
            "AssemblyDynamicLoadRule",
            "PersistenceRule",
            "RegistryRule",
            "DataExfiltrationRule",
            "DataInfiltrationRule",
            "Base64Rule",
            "HexStringRule",
            "EncodedStringLiteralRule",
            "EncodedStringPipelineRule",
            "EncodedBlobSplittingRule",
            "ByteArrayManipulationRule"
        };

        private readonly MethodScanner _methodScanner;
        private readonly SignalTracker _signalTracker;
        private readonly ReflectionDetector _reflectionDetector;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly PropertyEventScanner _propertyEventScanner;
        private readonly IEnumerable<IScanRule> _rules;
        private readonly ScanConfig _config;
        private readonly ScanTelemetryHub _telemetry;

        public TypeScanner(MethodScanner methodScanner, SignalTracker signalTracker,
            ReflectionDetector reflectionDetector,
            CodeSnippetBuilder snippetBuilder, PropertyEventScanner propertyEventScanner, IEnumerable<IScanRule> rules,
            ScanConfig config)
            : this(methodScanner, signalTracker, reflectionDetector, snippetBuilder, propertyEventScanner, rules,
                config, new ScanTelemetryHub())
        {
        }

        internal TypeScanner(MethodScanner methodScanner, SignalTracker signalTracker,
            ReflectionDetector reflectionDetector,
            CodeSnippetBuilder snippetBuilder, PropertyEventScanner propertyEventScanner, IEnumerable<IScanRule> rules,
            ScanConfig config, ScanTelemetryHub telemetry)
        {
            _methodScanner = methodScanner ?? throw new ArgumentNullException(nameof(methodScanner));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _reflectionDetector = reflectionDetector ?? throw new ArgumentNullException(nameof(reflectionDetector));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _propertyEventScanner =
                propertyEventScanner ?? throw new ArgumentNullException(nameof(propertyEventScanner));
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _config = config ?? new ScanConfig();
            _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
        }

        public IEnumerable<ScanFinding> ScanType(TypeDefinition type)
        {
            var findings = new List<ScanFinding>();
            var typeStart = _telemetry.StartTimestamp();
            var typeMethodCount = type.Methods.Count;
            var nestedTypeCount = type.NestedTypes.Count;
            var pendingReflectionCount = 0;
            _telemetry.IncrementCounter("TypeScanner.TypesScanned");
            _telemetry.IncrementCounter("TypeScanner.MethodsDiscovered", typeMethodCount);
            _telemetry.IncrementCounter("TypeScanner.NestedTypesDiscovered", nestedTypeCount);

            try
            {
                string typeFullName = type.FullName;
                var methodContexts = _propertyEventScanner.BuildAccessorContexts(type);

                // Initialize type-level signal tracking for this type
                if (_config.EnableMultiSignalDetection)
                {
                    _signalTracker.GetOrCreateTypeSignals(typeFullName);
                }

                // Queue of pending reflection findings that need type-level signals to be confirmed
                var pendingReflectionFindings =
                    new List<(MethodDefinition method, Instruction instruction, int index,
                        Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals? methodSignals)>();

                // Scan methods in this type
                foreach (var method in type.Methods)
                {
                    var methodResult = _methodScanner.ScanMethod(method, typeFullName);
                    AnnotateFindings(methodResult.Findings, method, methodContexts);
                    findings.AddRange(methodResult.Findings);
                    pendingReflectionFindings.AddRange(methodResult.PendingReflectionFindings);
                }

                pendingReflectionCount = pendingReflectionFindings.Count;
                _telemetry.IncrementCounter("TypeScanner.PendingReflectionQueued", pendingReflectionCount);

                // After scanning all methods, check pending reflection findings with type-level signals
                if (_config.EnableMultiSignalDetection)
                {
                    var pendingReflectionStart = _telemetry.StartTimestamp();
                    ProcessPendingReflectionFindings(pendingReflectionFindings, typeFullName, findings, methodContexts);
                    _telemetry.AddPhaseElapsed("TypeScanner.ProcessPendingReflectionFindings",
                        pendingReflectionStart);
                }

                // Clear type signals after processing
                _signalTracker.ClearTypeSignals(typeFullName);

                // Recursively scan nested types
                foreach (var nestedType in type.NestedTypes)
                {
                    findings.AddRange(ScanType(nestedType));
                }
            }
            catch (Exception)
            {
                // Skip type if it can't be properly analyzed
            }
            finally
            {
                _telemetry.AddPhaseElapsed("TypeScanner.ScanType", typeStart);
                _telemetry.RecordTypeSample(
                    type.FullName,
                    typeStart,
                    typeMethodCount,
                    nestedTypeCount,
                    findings.Count,
                    pendingReflectionCount);
            }

            return findings;
        }

        private void ProcessPendingReflectionFindings(
            List<(MethodDefinition method, Instruction instruction, int index,
                    Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals? methodSignals)>
                pendingReflectionFindings,
            string typeFullName,
            List<ScanFinding> findings,
            IReadOnlyDictionary<MethodDefinition, string> methodContexts)
        {
            if (pendingReflectionFindings.Count == 0)
                return;

            var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
            if (typeSignal == null)
                return;

            // Check if other rules have been triggered at type level (not just ReflectionRule)
            var reflectionRule = _rules.FirstOrDefault(r => r is ReflectionRule);
            if (reflectionRule == null)
                return;

            bool hasTypeLevelTriggeredRules = HasStrongReflectionCompanion(typeSignal, reflectionRule.RuleId);

            if (!hasTypeLevelTriggeredRules)
                return;

            var reflectionFindingsBefore = findings.Count;
            // Process each pending reflection finding
            foreach (var (method, instruction, index, instructions, methodSignals) in pendingReflectionFindings)
            {
                var snippet = _snippetBuilder.BuildSnippet(instructions, index, 2);

                var finding = new ScanFinding(
                    $"{method.DeclaringType?.FullName}.{method.Name}:{instruction.Offset}",
                    reflectionRule.Description + " (combined with other suspicious patterns detected in this type)",
                    reflectionRule.Severity,
                    snippet) { RuleId = reflectionRule.RuleId, DeveloperGuidance = reflectionRule.DeveloperGuidance };
                if (methodContexts.TryGetValue(method, out var context))
                {
                    finding.Description += $" ({context})";
                }

                findings.Add(finding);
                // Mark rule as triggered
                if (methodSignals != null)
                {
                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, reflectionRule.RuleId);
                }
            }

            _telemetry.IncrementCounter("TypeScanner.PendingReflectionFindingsConfirmed",
                findings.Count - reflectionFindingsBefore);
        }

        private static bool HasStrongReflectionCompanion(MethodSignals typeSignal, string reflectionRuleId)
        {
            foreach (var triggeredRuleId in typeSignal.GetTriggeredRuleIds())
            {
                if (triggeredRuleId.Equals(reflectionRuleId, StringComparison.Ordinal))
                    continue;

                if (ReflectionCompanionRuleIds.Contains(triggeredRuleId))
                    return true;
            }

            return false;
        }

        private static void AnnotateFindings(List<ScanFinding> findings, MethodDefinition method,
            IReadOnlyDictionary<MethodDefinition, string> methodContexts)
        {
            if (!methodContexts.TryGetValue(method, out var context))
                return;

            foreach (var finding in findings)
            {
                if (!finding.Description.Contains(context, StringComparison.Ordinal))
                {
                    finding.Description += $" ({context})";
                }
            }
        }
    }
}
