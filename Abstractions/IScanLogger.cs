namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction for logging within the MLVScan scanning engine.
    /// Implement this interface to integrate with platform-specific logging systems.
    /// </summary>
    public interface IScanLogger
    {
        /// <summary>
        /// Logs a debug message.
        /// </summary>
        void Debug(string message);

        /// <summary>
        /// Logs an informational message.
        /// </summary>
        void Info(string message);

        /// <summary>
        /// Logs a warning message.
        /// </summary>
        void Warning(string message);

        /// <summary>
        /// Logs an error message.
        /// </summary>
        void Error(string message);

        /// <summary>
        /// Logs an error message together with exception details.
        /// </summary>
        void Error(string message, Exception exception);
    }
}
