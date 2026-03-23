namespace MLVScan.Abstractions
{
    /// <summary>
    /// A no-op logger implementation that discards all log messages.
    /// </summary>
    public sealed class NullScanLogger : IScanLogger
    {
        /// <summary>
        /// Singleton instance for convenience.
        /// </summary>
        public static readonly NullScanLogger Instance = new();

        private NullScanLogger() { }

        /// <inheritdoc />
        public void Debug(string message) { }
        /// <inheritdoc />
        public void Info(string message) { }
        /// <inheritdoc />
        public void Warning(string message) { }
        /// <inheritdoc />
        public void Error(string message) { }
        /// <inheritdoc />
        public void Error(string message, Exception exception) { }
    }
}
