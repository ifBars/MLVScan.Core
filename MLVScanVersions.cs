using System.Reflection;

namespace MLVScan;

/// <summary>
/// Centralized version constants for MLVScan schema and core library.
/// CoreVersion is read from assembly metadata at runtime to avoid duplication.
/// </summary>
public static class MLVScanVersions
{
    /// <summary>
    /// The JSON schema version (semver).
    /// This defines the structure of scan result output.
    /// </summary>
    public const string SchemaVersion = "1.0.0";

    /// <summary>
    /// The MLVScan.Core library version (semver).
    /// Read from assembly metadata at runtime to stay in sync with .csproj.
    /// </summary>
    public static string CoreVersion => GetAssemblyVersion();

    /// <summary>
    /// Gets the core library version from assembly metadata.
    /// Falls back to "0.0.0" if not available.
    /// </summary>
    private static string GetAssemblyVersion()
    {
        var assembly = typeof(MLVScanVersions).Assembly;
        var version = assembly.GetName().Version;
        if (version != null)
        {
            return version.ToString(3); // Major.Minor.Patch
        }

        var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
        if (informationalVersion != null)
        {
            return informationalVersion.InformationalVersion;
        }

        return "0.0.0";
    }

    /// <summary>
    /// Gets the full version string for the core library.
    /// </summary>
    public static string GetCoreVersion() => CoreVersion;

    /// <summary>
    /// Gets the schema version string.
    /// </summary>
    public static string GetSchemaVersion() => SchemaVersion;
}
