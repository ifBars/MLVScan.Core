namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction for logging within the MLVScan scanning engine.
    /// Implement this interface to integrate with platform-specific logging
    /// (e.g., MelonLoader's MelonLogger, BepInEx's ManualLogSource).
    /// </summary>
    public interface IScanLogger
    {
        /// <summary>
        /// Logs a debug message. Use for detailed diagnostic information.
        /// </summary>
        void Debug(string message);

        /// <summary>
        /// Logs an informational message. Use for general operational messages.
        /// </summary>
        void Info(string message);

        /// <summary>
        /// Logs a warning message. Use for potentially harmful situations.
        /// </summary>
        void Warning(string message);

        /// <summary>
        /// Logs an error message. Use for error events that might still allow the application to continue.
        /// </summary>
        void Error(string message);

        /// <summary>
        /// Logs an error message with exception details.
        /// </summary>
        void Error(string message, Exception exception);
    }
}
