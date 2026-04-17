namespace MLVScan.Models.Dto;

/// <summary>
/// Generic metadata extracted from the scanned assembly without introducing platform-specific semantics.
/// </summary>
public class AssemblyMetadataDto
{
    /// <summary>
    /// Assembly simple name.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Assembly identity version from the assembly definition.
    /// </summary>
    public string? AssemblyVersion { get; set; }

    /// <summary>
    /// AssemblyFileVersionAttribute value when present.
    /// </summary>
    public string? FileVersion { get; set; }

    /// <summary>
    /// AssemblyInformationalVersionAttribute value when present.
    /// </summary>
    public string? InformationalVersion { get; set; }

    /// <summary>
    /// TargetFrameworkAttribute value when present.
    /// </summary>
    public string? TargetFramework { get; set; }

    /// <summary>
    /// CLR metadata runtime version from the module header.
    /// </summary>
    public string? ModuleRuntimeVersion { get; set; }

    /// <summary>
    /// Referenced assembly simple names.
    /// </summary>
    public List<string>? ReferencedAssemblies { get; set; }
}
