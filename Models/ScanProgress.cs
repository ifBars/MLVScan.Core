namespace MLVScan.Models
{
    /// <summary>
    /// Reports deterministic progress through the static-analysis pipeline.
    /// </summary>
    /// <remarks>
    /// Progress is measured in scanner work units, not wall-clock time or uploaded bytes. Hosts can use
    /// <see cref="Percentage"/> for a simple progress bar and <see cref="Phase"/> with <see cref="CurrentItem"/>
    /// for more detailed status text.
    /// </remarks>
    public sealed class ScanProgress
    {
        /// <summary>
        /// Creates a progress snapshot for the current scanner phase.
        /// </summary>
        /// <param name="phase">The scanner phase currently being executed.</param>
        /// <param name="completedUnits">The number of completed work units.</param>
        /// <param name="totalUnits">The total number of work units currently known.</param>
        /// <param name="currentItem">Optional assembly, module, type, method, or rule identifier being processed.</param>
        public ScanProgress(string phase, int completedUnits, int totalUnits, string? currentItem = null)
        {
            Phase = string.IsNullOrWhiteSpace(phase) ? "Scanning" : phase;
            TotalUnits = Math.Max(1, totalUnits);
            CompletedUnits = Math.Min(Math.Max(0, completedUnits), TotalUnits);
            CurrentItem = currentItem;
        }

        /// <summary>
        /// Gets the scanner phase currently being executed.
        /// </summary>
        public string Phase { get; }

        /// <summary>
        /// Gets the number of completed scanner work units.
        /// </summary>
        public int CompletedUnits { get; }

        /// <summary>
        /// Gets the total number of scanner work units currently known.
        /// </summary>
        public int TotalUnits { get; }

        /// <summary>
        /// Gets the integer completion percentage derived from completed and total work units.
        /// </summary>
        public int Percentage => (int)Math.Round((double)CompletedUnits / TotalUnits * 100);

        /// <summary>
        /// Gets the assembly, module, type, method, or rule identifier currently being processed when available.
        /// </summary>
        public string? CurrentItem { get; }
    }
}
