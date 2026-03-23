using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.ComponentModel;

namespace MLVScan.Services
{
    /// <summary>
    /// Tracks method-level and type-level analysis signals used to correlate multi-signal detections.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class SignalTracker
    {
        private readonly Dictionary<string, MethodSignals> _typeSignals;
        private readonly ScanConfig _config;

        /// <summary>
        /// Creates a tracker for scan signals using the supplied configuration.
        /// </summary>
        /// <param name="config">The scan configuration that controls signal aggregation behavior.</param>
        public SignalTracker(ScanConfig config)
        {
            _config = config ?? new ScanConfig();
            _typeSignals = new Dictionary<string, MethodSignals>();
        }

        /// <summary>
        /// Creates a new per-method signal bag when multi-signal detection is enabled.
        /// </summary>
        /// <returns>A new <see cref="MethodSignals"/> instance, or <see langword="null"/> when the feature is disabled.</returns>
        public MethodSignals? CreateMethodSignals()
        {
            return _config.EnableMultiSignalDetection ? new MethodSignals() : null;
        }

        /// <summary>
        /// Gets the type-level signal bag for the supplied type name, creating it when multi-signal detection is enabled.
        /// </summary>
        /// <param name="typeFullName">The fully qualified type name used as the signal key.</param>
        /// <returns>The existing or newly created type-level signal bag, or <see langword="null"/> when disabled.</returns>
        public MethodSignals? GetOrCreateTypeSignals(string typeFullName)
        {
            if (!_config.EnableMultiSignalDetection)
                return null;

            if (!_typeSignals.TryGetValue(typeFullName, out var typeSignal))
            {
                typeSignal = new MethodSignals();
                _typeSignals[typeFullName] = typeSignal;
            }

            return typeSignal;
        }

        /// <summary>
        /// Gets the tracked type-level signals for the supplied type name.
        /// </summary>
        /// <param name="typeFullName">The fully qualified type name used as the signal key.</param>
        /// <returns>The tracked signals, or <see langword="null"/> if the type has not been seen.</returns>
        public MethodSignals? GetTypeSignals(string typeFullName)
        {
            return _typeSignals.TryGetValue(typeFullName, out var typeSignal) ? typeSignal : null;
        }

        /// <summary>
        /// Removes any tracked type-level signals for the supplied type name.
        /// </summary>
        /// <param name="typeFullName">The fully qualified type name to remove from the tracker.</param>
        public void ClearTypeSignals(string typeFullName)
        {
            _typeSignals.Remove(typeFullName);
        }

        /// <summary>
        /// Updates the supplied signal bag based on a called method and propagates the signal to the declaring type when applicable.
        /// </summary>
        /// <param name="signals">The method-level signal bag to update.</param>
        /// <param name="method">The referenced method being evaluated.</param>
        /// <param name="declaringType">The declaring type used for type-level aggregation, if available.</param>
        public void UpdateMethodSignals(MethodSignals signals, MethodReference method, TypeDefinition? declaringType)
        {
            if (method?.DeclaringType == null || signals == null)
                return;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Check for Base64
            if (typeName.Contains("Convert") && methodName.Contains("FromBase64"))
            {
                signals.HasBase64 = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasBase64 = true;
                    }
                }
            }

            // Check for Process.Start
            if (typeName.Contains("System.Diagnostics.Process") && methodName == "Start")
            {
                signals.HasProcessLikeCall = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasProcessLikeCall = true;
                    }
                }
            }

            // Check for reflection invocation
            if ((typeName == "System.Reflection.MethodInfo" && methodName == "Invoke") ||
                (typeName == "System.Reflection.MethodBase" && methodName == "Invoke"))
            {
                signals.HasSuspiciousReflection = true;
            }

            // Check for network calls
            if (typeName.StartsWith("System.Net") || typeName.Contains("WebRequest") ||
                typeName.Contains("HttpClient") || typeName.Contains("WebClient"))
            {
                signals.HasNetworkCall = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasNetworkCall = true;
                    }
                }
            }

            // Check for file writes
            if ((typeName.StartsWith("System.IO.File") &&
                 (methodName.Contains("Write") || methodName.Contains("Create"))) ||
                (typeName.StartsWith("System.IO.Stream") && methodName.Contains("Write")))
            {
                signals.HasFileWrite = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasFileWrite = true;
                    }
                }
            }

            // Check for environment variable manipulation (e.g., PATH modification attacks)
            if (typeName == "System.Environment" && methodName == "SetEnvironmentVariable")
            {
                signals.HasEnvironmentVariableModification = true;
                // Mark type-level signal
                if (declaringType != null)
                {
                    var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                    if (typeSignal != null)
                    {
                        typeSignal.HasEnvironmentVariableModification = true;
                    }
                }
            }
        }

        /// <summary>
        /// Marks the current method and declaring type as having encoded-string activity.
        /// </summary>
        /// <param name="methodSignals">The method-level signal bag to update.</param>
        /// <param name="declaringType">The declaring type used for type-level aggregation, if available.</param>
        public void MarkEncodedStrings(MethodSignals? methodSignals, TypeDefinition? declaringType)
        {
            if (methodSignals == null)
                return;

            methodSignals.HasEncodedStrings = true;
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.HasEncodedStrings = true;
                }
            }
        }

        /// <summary>
        /// Marks the current method and declaring type as using a sensitive folder path.
        /// </summary>
        /// <param name="methodSignals">The method-level signal bag to update.</param>
        /// <param name="declaringType">The declaring type used for type-level aggregation, if available.</param>
        public void MarkSensitiveFolder(MethodSignals? methodSignals, TypeDefinition? declaringType)
        {
            if (methodSignals == null)
                return;

            methodSignals.UsesSensitiveFolder = true;
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.UsesSensitiveFolder = true;
                }
            }
        }

        /// <summary>
        /// Marks the current method and declaring type as using suspicious local variables.
        /// </summary>
        /// <param name="methodSignals">The method-level signal bag to update.</param>
        /// <param name="declaringType">The declaring type used for type-level aggregation, if available.</param>
        public void MarkSuspiciousLocalVariables(MethodSignals? methodSignals, TypeDefinition? declaringType)
        {
            if (methodSignals == null)
                return;

            methodSignals.HasSuspiciousLocalVariables = true;
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.HasSuspiciousLocalVariables = true;
                }
            }
        }

        /// <summary>
        /// Marks the current method and declaring type as using suspicious exception handling.
        /// </summary>
        /// <param name="methodSignals">The method-level signal bag to update.</param>
        /// <param name="declaringType">The declaring type used for type-level aggregation, if available.</param>
        public void MarkSuspiciousExceptionHandling(MethodSignals? methodSignals, TypeDefinition? declaringType)
        {
            if (methodSignals == null)
                return;

            methodSignals.HasSuspiciousExceptionHandling = true;
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.HasSuspiciousExceptionHandling = true;
                }
            }
        }

        /// <summary>
        /// Marks a rule as triggered in the current method and declaring type.
        /// </summary>
        /// <param name="methodSignals">The method-level signal bag to update.</param>
        /// <param name="declaringType">The declaring type used for type-level aggregation, if available.</param>
        /// <param name="ruleId">The identifier of the rule that was triggered.</param>
        public void MarkRuleTriggered(MethodSignals? methodSignals, TypeDefinition? declaringType, string ruleId)
        {
            if (methodSignals == null || string.IsNullOrEmpty(ruleId))
                return;

            methodSignals.MarkRuleTriggered(ruleId);
            if (declaringType != null)
            {
                var typeSignal = GetOrCreateTypeSignals(declaringType.FullName);
                if (typeSignal != null)
                {
                    typeSignal.MarkRuleTriggered(ruleId);
                }
            }
        }
    }
}
