using MLVScan.Models;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction over the core static-analysis pipeline.
    /// Implementations inspect a managed assembly and return the findings emitted by the configured rule set.
    /// </summary>
    public interface IAssemblyScanner
    {
        /// <summary>
        /// Scans an assembly loaded from disk.
        /// </summary>
        /// <param name="assemblyPath">Path to the assembly file to inspect.</param>
        /// <returns>The findings generated for the supplied assembly.</returns>
        IEnumerable<ScanFinding> Scan(string assemblyPath);

        /// <summary>
        /// Scans an assembly from an in-memory stream.
        /// This overload is intended for hosts that receive uploaded or generated assemblies without writing them to disk first.
        /// </summary>
        /// <param name="assemblyStream">A readable stream containing the assembly bytes.</param>
        /// <param name="virtualPath">Optional display path used in error reporting and finding locations.</param>
        /// <returns>The findings generated for the supplied assembly.</returns>
        IEnumerable<ScanFinding> Scan(Stream assemblyStream, string? virtualPath = null);
    }
}
