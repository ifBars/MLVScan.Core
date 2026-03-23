namespace MLVScan
{
    /// <summary>
    /// Legacy version constants retained for backward compatibility.
    /// Prefer <see cref="MLVScanVersions"/> for all new code.
    /// </summary>
    [Obsolete("Use MLVScanVersions instead. Removed in v2.0.")]
    public static class Constants
    {
        /// <summary>
        /// Legacy public constant retained for compatibility with older consumers.
        /// Prefer <see cref="MLVScanVersions.CoreVersion"/>.
        /// </summary>
        [Obsolete("Use MLVScanVersions.CoreVersion instead. Removed in v2.0.")]
        public const string CoreVersion = "1.3.5";

        /// <summary>
        /// Gets the full version string with prefix.
        /// Prefer <see cref="MLVScanVersions.GetVersionString"/>.
        /// </summary>
        [Obsolete("Use MLVScanVersions.GetVersionString() instead. Removed in v2.0.")]
        public static string GetVersionString() => MLVScanVersions.GetVersionString();
    }
}
