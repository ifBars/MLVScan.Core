namespace MLVScan.Models.Rules.Helpers
{
    internal sealed class ObfuscatedExecutionEvidence
    {
        private const int MaxDecodeScore = 55;
        private const int MaxSinkScore = 55;
        private const int MaxDangerScore = 35;

        public int DecodeScore { get; private set; }
        public int SinkScore { get; private set; }
        public int DangerScore { get; private set; }
        public int TotalScore { get; set; }
        public int AnchorInstructionIndex { get; private set; } = -1;

        public bool HasEncodedLiteral { get; set; }
        public bool HasStrongDecodePrimitive { get; set; }
        public bool HasReflectionInvokeSink { get; set; }
        public bool HasAssemblyLoadSink { get; set; }
        public bool HasProcessLikeSink { get; set; }
        public bool HasNativeSink { get; set; }
        public bool HasDynamicTargetResolution { get; set; }
        public bool HasNetworkCall { get; set; }
        public bool HasFileWriteCall { get; set; }
        public bool HasDangerousLiteral { get; set; }
        public bool HasSensitivePathAccess { get; set; }

        public List<string> DecodeReasons { get; } = new List<string>();
        public List<string> SinkReasons { get; } = new List<string>();
        public List<string> DangerReasons { get; } = new List<string>();

        public void AddDecode(int points, string reason, int instructionIndex)
        {
            if (!AddReason(DecodeReasons, reason))
            {
                return;
            }

            DecodeScore = Math.Min(MaxDecodeScore, DecodeScore + points);
            UpdateAnchor(instructionIndex);
        }

        public void AddSink(int points, string reason, int instructionIndex)
        {
            if (!AddReason(SinkReasons, reason))
            {
                return;
            }

            SinkScore = Math.Min(MaxSinkScore, SinkScore + points);
            UpdateAnchor(instructionIndex);
        }

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
