namespace MLVScan;

/// <summary>
/// Centralized version constants for MLVScan schema and core library.
/// CoreVersion is sourced from the core library's declared version constant so it remains stable
/// even when MLVScan.Core is merged into a loader assembly.
/// </summary>
public static class MLVScanVersions
{
    internal const string DeclaredCoreVersion = "1.3.6";

    /// <summary>
    /// The JSON schema version (semver).
    /// This defines the structure of scan result output.
    /// </summary>
    public const string SchemaVersion = "1.2.0";

    /// <summary>
    /// The MLVScan.Core library version (semver).
    /// Sourced from the core library's declared compatibility version.
    /// </summary>
    public static string CoreVersion => DeclaredCoreVersion;

    /// <summary>
    /// Gets the full version string for the core library.
    /// </summary>
    [Obsolete("Use the CoreVersion property instead. Removed in v2.0.")]
    public static string GetCoreVersion() => CoreVersion;

    /// <summary>
    /// Gets the full user-facing version string for the core library.
    /// </summary>
    public static string GetVersionString() => $"MLVScan.Core v{CoreVersion}";

    /// <summary>
    /// Gets the schema version string.
    /// </summary>
    [Obsolete("Use the SchemaVersion property instead. Removed in v2.0.")]
    public static string GetSchemaVersion() => SchemaVersion;
}
