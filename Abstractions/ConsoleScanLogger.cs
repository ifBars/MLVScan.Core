namespace MLVScan.Abstractions
{
    /// <summary>
    /// A simple console-based logger implementation.
    /// Useful for debugging, CLI tools, or web scenarios where console output is acceptable.
    /// </summary>
    public class ConsoleScanLogger : IScanLogger
    {
        /// <summary>
        /// Singleton instance for convenience.
        /// </summary>
        public static readonly ConsoleScanLogger Instance = new();

        public void Debug(string message) => Console.WriteLine($"[MLVScan DEBUG] {message}");
        public void Info(string message) => Console.WriteLine($"[MLVScan INFO] {message}");
        public void Warning(string message) => Console.WriteLine($"[MLVScan WARN] {message}");
        public void Error(string message) => Console.WriteLine($"[MLVScan ERROR] {message}");
        public void Error(string message, Exception exception) => Console.WriteLine($"[MLVScan ERROR] {message}: {exception}");
    }
}
