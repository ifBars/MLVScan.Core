using MLVScan.Models;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction over assembly scanning. Implementations analyze a .NET assembly
    /// and return a collection of detected findings.
    /// </summary>
    public interface IAssemblyScanner
    {
        /// <summary>
        /// Scans an assembly from a file path.
        /// </summary>
        /// <param name="assemblyPath">The absolute path to the assembly file.</param>
        /// <returns>A collection of scan findings.</returns>
        IEnumerable<ScanFinding> Scan(string assemblyPath);

        /// <summary>
        /// Scans an assembly from a stream.
        /// Suitable for web and cloud scenarios where the assembly is not persisted to disk.
        /// </summary>
        /// <param name="assemblyStream">A readable stream containing the assembly bytes.</param>
        /// <param name="virtualPath">Optional virtual path used in error and finding messages.</param>
        /// <returns>A collection of scan findings.</returns>
        IEnumerable<ScanFinding> Scan(Stream assemblyStream, string? virtualPath = null);
    }
}
