namespace MLVScan.Models
{
    /// <summary>
    /// Developer-facing guidance for fixing false positives or understanding
    /// why certain patterns are flagged by MLVScan.
    /// </summary>
    public interface IDeveloperGuidance
    {
        /// <summary>
        /// Human-readable explanation of how to fix this finding.
        /// Example: "For mod settings, use MelonPreferences instead of File.WriteAllText"
        /// </summary>
        string Remediation { get; }

        /// <summary>
        /// Optional URL to documentation explaining the recommended approach.
        /// Example: "https://melonwiki.xyz/#/modders/preferences"
        /// </summary>
        string? DocumentationUrl { get; }

        /// <summary>
        /// Optional list of API names developers should use instead.
        /// Example: ["MelonPreferences.CreateEntry", "MelonPreferences.GetEntry"]
        /// </summary>
        string[]? AlternativeApis { get; }

        /// <summary>
        /// Whether there's a safe alternative to the flagged pattern.
        /// False indicates "just don't do this" (e.g., Process.Start, shell execution).
        /// </summary>
        bool IsRemediable { get; }
    }
}
