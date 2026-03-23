using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Describes a built-in threat family and the variant matchers associated with it.
/// </summary>
internal sealed class ThreatFamilyDefinition
{
    /// <summary>
    /// Gets or sets the stable identifier for the threat family.
    /// </summary>
    public string FamilyId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the display name shown to developers and downstream consumers.
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the short family summary used in classification output.
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets advisory slugs associated with the family.
    /// </summary>
    public IReadOnlyList<string> AdvisorySlugs { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets exact hashes that map directly to this family.
    /// </summary>
    public IReadOnlyList<string> ExactSampleHashes { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets the family variants that can be matched from behavioral context.
    /// </summary>
    public IReadOnlyList<ThreatFamilyVariantDefinition> Variants { get; set; } = Array.Empty<ThreatFamilyVariantDefinition>();
}

/// <summary>
/// Describes a specific variant of a threat family and the matcher used to recognize it.
/// </summary>
internal sealed class ThreatFamilyVariantDefinition
{
    /// <summary>
    /// Gets or sets the stable identifier for the variant.
    /// </summary>
    public string VariantId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the display name for the variant.
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the short summary describing the variant behavior.
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the classifier confidence when this variant matches.
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// Gets or sets the matcher that evaluates the analysis context for this variant.
    /// </summary>
    public Func<ThreatFamilyAnalysisContext, ThreatFamilyVariantMatch?> Matcher { get; set; } = _ => null;
}

/// <summary>
/// Represents the evidence produced by a matched threat-family variant.
/// </summary>
internal sealed class ThreatFamilyVariantMatch
{
    /// <summary>
    /// Gets or sets the rule identifiers that contributed to the match.
    /// </summary>
    public IReadOnlyList<string> MatchedRules { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Gets or sets the evidence items that support the match.
    /// </summary>
    public IReadOnlyList<ThreatFamilyEvidence> Evidence { get; set; } = Array.Empty<ThreatFamilyEvidence>();
}
