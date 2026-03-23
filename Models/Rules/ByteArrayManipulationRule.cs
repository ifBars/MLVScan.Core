using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects byte-array centric transformations that can hide embedded payloads, especially Base64
    /// decoding and in-memory byte buffer reconstruction.
    /// </summary>
    public class ByteArrayManipulationRule : IScanRule
    {
        /// <summary>
        /// Gets developer guidance for legitimate byte-array processing scenarios.
        /// </summary>
        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "If processing images or audio, use Unity's asset loading APIs (AudioClip.LoadWAVData, Texture2D.LoadImage). For legitimate binary data, document the purpose clearly.",
            null,
            new[] { "UnityEngine.AudioClip.LoadWAVData", "UnityEngine.Texture2D.LoadImage" },
            true
        );

        /// <summary>
        /// Returns true when the method matches a byte-array transformation primitive used by this rule.
        /// </summary>
        /// <param name="method">The method reference to inspect.</param>
        /// <returns><see langword="true"/> for the byte-array decode and reconstruction APIs tracked by this rule.</returns>
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            switch (typeName)
            {
                // Common Base64 decoding pattern for hidden payloads
                case "System.Convert" when methodName is "FromBase64String" or "FromBase64CharArray":
                // Check for MemoryStream constructor with byte array parameter
                // The constructor pattern is caught here - when a MemoryStream is created with a byte array
                case "System.IO.MemoryStream" when methodName == ".ctor":
                    return true;
            }

            // Intentionally do not flag System.BitConverter usage here to avoid false positives for common audio processing (e.g., WAV/PCM handling)
            return false;
        }

        /// <summary>
        /// Gets the description emitted with findings produced by this rule.
        /// </summary>
        public string Description =>
            "Detected byte array manipulation. Often legitimate (e.g., WAV/PCM audio processing), but can also be used to hide or load malicious payloads.";

        /// <summary>
        /// Gets the severity assigned to byte-array manipulation patterns.
        /// </summary>
        public Severity Severity => Severity.Low;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "ByteArrayManipulationRule";

        /// <summary>
        /// Gets a value indicating whether this rule should be paired with another finding before reporting.
        /// </summary>
        public bool RequiresCompanionFinding => true;
    }
}
