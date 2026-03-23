namespace MLVScan.Models.Dto;

/// <summary>
/// Controls whether a finding should appear in the default user-facing view.
/// </summary>
public enum FindingVisibility
{
    /// <summary>
    /// Finding should appear in default result views.
    /// </summary>
    Default,

    /// <summary>
    /// Finding should be shown only in advanced or developer-focused views.
    /// </summary>
    Advanced
}
