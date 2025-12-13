namespace MLVScan.Abstractions
{
    /// <summary>
    /// A no-op logger implementation that discards all log messages.
    /// Useful for scenarios where logging is not needed (e.g., web scanning, unit tests).
    /// </summary>
    public sealed class NullScanLogger : IScanLogger
    {
        /// <summary>
        /// Singleton instance for convenience.
        /// </summary>
        public static readonly NullScanLogger Instance = new();

        private NullScanLogger() { }

        public void Debug(string message) { }
        public void Info(string message) { }
        public void Warning(string message) { }
        public void Error(string message) { }
        public void Error(string message, Exception exception) { }
    }
}
