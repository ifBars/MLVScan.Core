namespace MLVScan.Models.Rules.Helpers
{
    /// <summary>
    /// Accumulates decode, sink, and danger scores for a single obfuscation analysis pass.
    /// </summary>
    internal sealed class ObfuscatedExecutionEvidence
    {
        private const int MaxDecodeScore = 55;
        private const int MaxSinkScore = 55;
        private const int MaxDangerScore = 35;

        /// <summary>
        /// Gets the score contributed by decode-oriented indicators.
        /// </summary>
        public int DecodeScore { get; private set; }

        /// <summary>
        /// Gets the score contributed by execution or staging sinks.
        /// </summary>
        public int SinkScore { get; private set; }

        /// <summary>
        /// Gets the score contributed by suspicious contextual danger indicators.
        /// </summary>
        public int DangerScore { get; private set; }

        /// <summary>
        /// Gets or sets the combined score used by higher-level heuristics.
        /// </summary>
        public int TotalScore { get; set; }

        /// <summary>
        /// Gets the first instruction index that contributed evidence to this analysis.
        /// </summary>
        public int AnchorInstructionIndex { get; private set; } = -1;

        /// <summary>
        /// Gets or sets whether the analysis observed an encoded literal.
        /// </summary>
        public bool HasEncodedLiteral { get; set; }

        /// <summary>
        /// Gets or sets whether the analysis observed a strong decode primitive.
        /// </summary>
        public bool HasStrongDecodePrimitive { get; set; }

        /// <summary>
        /// Gets or sets whether a reflection invoke sink was observed.
        /// </summary>
        public bool HasReflectionInvokeSink { get; set; }

        /// <summary>
        /// Gets or sets whether a dynamic assembly-load sink was observed.
        /// </summary>
        public bool HasAssemblyLoadSink { get; set; }

        /// <summary>
        /// Gets or sets whether a process-launch sink was observed.
        /// </summary>
        public bool HasProcessLikeSink { get; set; }

        /// <summary>
        /// Gets or sets whether a native execution bridge was observed.
        /// </summary>
        public bool HasNativeSink { get; set; }

        /// <summary>
        /// Gets or sets whether the analysis observed dynamic target resolution.
        /// </summary>
        public bool HasDynamicTargetResolution { get; set; }

        /// <summary>
        /// Gets or sets whether a network transfer primitive was observed.
        /// </summary>
        public bool HasNetworkCall { get; set; }

        /// <summary>
        /// Gets or sets whether a file-write primitive was observed.
        /// </summary>
        public bool HasFileWriteCall { get; set; }

        /// <summary>
        /// Gets or sets whether a dangerous literal marker was observed.
        /// </summary>
        public bool HasDangerousLiteral { get; set; }

        /// <summary>
        /// Gets or sets whether sensitive path access was observed.
        /// </summary>
        public bool HasSensitivePathAccess { get; set; }

        /// <summary>
        /// Gets the decode reasons collected during analysis.
        /// </summary>
        public List<string> DecodeReasons { get; } = new List<string>();

        /// <summary>
        /// Gets the sink reasons collected during analysis.
        /// </summary>
        public List<string> SinkReasons { get; } = new List<string>();

        /// <summary>
        /// Gets the contextual danger reasons collected during analysis.
        /// </summary>
        public List<string> DangerReasons { get; } = new List<string>();

        /// <summary>
        /// Adds decode evidence, capped to the configured maximum score.
        /// </summary>
        /// <param name="points">The points to add.</param>
        /// <param name="reason">The human-readable reason for the evidence.</param>
        /// <param name="instructionIndex">The instruction index that produced the evidence.</param>
        public void AddDecode(int points, string reason, int instructionIndex)
        {
            if (!AddReason(DecodeReasons, reason))
            {
                return;
            }

            DecodeScore = Math.Min(MaxDecodeScore, DecodeScore + points);
            UpdateAnchor(instructionIndex);
        }

        /// <summary>
        /// Adds sink evidence, capped to the configured maximum score.
        /// </summary>
        /// <param name="points">The points to add.</param>
        /// <param name="reason">The human-readable reason for the evidence.</param>
        /// <param name="instructionIndex">The instruction index that produced the evidence.</param>
        public void AddSink(int points, string reason, int instructionIndex)
        {
            if (!AddReason(SinkReasons, reason))
            {
                return;
            }

            SinkScore = Math.Min(MaxSinkScore, SinkScore + points);
            UpdateAnchor(instructionIndex);
        }

        /// <summary>
        /// Adds contextual danger evidence, capped to the configured maximum score.
        /// </summary>
        /// <param name="points">The points to add.</param>
        /// <param name="reason">The human-readable reason for the evidence.</param>
        /// <param name="instructionIndex">The instruction index that produced the evidence.</param>
        public void AddDanger(int points, string reason, int instructionIndex)
        {
            if (!AddReason(DangerReasons, reason))
            {
                return;
            }

            DangerScore = Math.Min(MaxDangerScore, DangerScore + points);
            UpdateAnchor(instructionIndex);
        }

        private void UpdateAnchor(int instructionIndex)
        {
            if (AnchorInstructionIndex < 0)
            {
                AnchorInstructionIndex = instructionIndex;
            }
        }

        private static bool AddReason(List<string> reasons, string reason)
        {
            if (reasons.Count >= 5 || reasons.Contains(reason))
            {
                return false;
            }

            reasons.Add(reason);
            return true;
        }
    }
}
