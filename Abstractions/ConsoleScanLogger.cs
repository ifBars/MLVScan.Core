using System.ComponentModel;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// A console-based logger implementation for diagnostic scenarios.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class ConsoleScanLogger : IScanLogger
    {
        /// <summary>
        /// Singleton instance for convenience.
        /// </summary>
        public static readonly ConsoleScanLogger Instance = new();

        /// <inheritdoc />
        public void Debug(string message) => Console.WriteLine($"[MLVScan DEBUG] {message}");
        /// <inheritdoc />
        public void Info(string message) => Console.WriteLine($"[MLVScan INFO] {message}");
        /// <inheritdoc />
        public void Warning(string message) => Console.WriteLine($"[MLVScan WARN] {message}");
        /// <inheritdoc />
        public void Error(string message) => Console.WriteLine($"[MLVScan ERROR] {message}");
        /// <inheritdoc />
        public void Error(string message, Exception exception) => Console.WriteLine($"[MLVScan ERROR] {message}: {exception}");
    }
}
