namespace MLVScan
{
    /// <summary>
    /// Version and build constants for MLVScan.Core.
    /// Update this file when releasing new versions.
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// Core engine version - the scanning/analysis library version.
        /// </summary>
        public const string CoreVersion = "1.2.1";

        /// <summary>
        /// Gets the full version string with prefix.
        /// </summary>
        public static string GetVersionString() => $"MLVScan.Core v{CoreVersion}";
    }
}
