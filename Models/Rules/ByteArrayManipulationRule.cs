using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    public class ByteArrayManipulationRule : IScanRule
    {
        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "If processing images or audio, use Unity's asset loading APIs (AudioClip.LoadWAVData, Texture2D.LoadImage). For legitimate binary data, document the purpose clearly.",
            null,
            new[] { "UnityEngine.AudioClip.LoadWAVData", "UnityEngine.Texture2D.LoadImage" },
            true
        );

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

        public string Description =>
            "Detected byte array manipulation. Often legitimate (e.g., WAV/PCM audio processing), but can also be used to hide or load malicious payloads.";

        public Severity Severity => Severity.Low;
        public string RuleId => "ByteArrayManipulationRule";
        public bool RequiresCompanionFinding => true;
    }
}
