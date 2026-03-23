namespace MLVScan.Models
{
    /// <summary>
    /// Tracks suspicious signals collected while analyzing a method or aggregating behavior at the type level.
    /// The scanner uses these signals to correlate weak indicators into higher-confidence findings.
    /// </summary>
    public class MethodSignals
    {
        /// <summary>
        /// Gets or sets a value indicating whether encoded or obfuscated strings were observed.
        /// </summary>
        public bool HasEncodedStrings { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether reflection APIs were used in a suspicious way.
        /// </summary>
        public bool HasSuspiciousReflection { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether a sensitive folder identifier was referenced.
        /// </summary>
        public bool UsesSensitiveFolder { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the method appears to launch an external process or shell.
        /// </summary>
        public bool HasProcessLikeCall { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether Base64 decoding primitives were observed.
        /// </summary>
        public bool HasBase64 { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether network activity was observed.
        /// </summary>
        public bool HasNetworkCall { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the method writes data to disk.
        /// </summary>
        public bool HasFileWrite { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether suspicious local variables were observed.
        /// </summary>
        public bool HasSuspiciousLocalVariables { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether suspicious exception-handler behavior was observed.
        /// </summary>
        public bool HasSuspiciousExceptionHandling { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether suspicious path manipulation was observed.
        /// </summary>
        public bool HasPathManipulation { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether environment-variable modification was observed.
        /// </summary>
        public bool HasEnvironmentVariableModification { get; set; }

        private HashSet<string> _triggeredRuleIds = new HashSet<string>();

        /// <summary>
        /// Records that the specified rule has triggered for the current signal set.
        /// </summary>
        /// <param name="ruleId">The identifier of the triggered rule.</param>
        public void MarkRuleTriggered(string ruleId)
        {
            if (!string.IsNullOrEmpty(ruleId))
            {
                _triggeredRuleIds.Add(ruleId);
            }
        }

        /// <summary>
        /// Determines whether any recorded rule other than the supplied rule has triggered.
        /// </summary>
        /// <param name="ruleId">The rule identifier to exclude from the comparison.</param>
        /// <returns><see langword="true"/> when another rule has been recorded; otherwise, <see langword="false"/>.</returns>
        public bool HasTriggeredRuleOtherThan(string ruleId)
        {
            if (string.IsNullOrEmpty(ruleId))
            {
                return _triggeredRuleIds.Count > 0;
            }

            return _triggeredRuleIds.Count > 0 && !_triggeredRuleIds.All(id => id == ruleId);
        }

        /// <summary>
        /// Determines whether at least one rule has been recorded for the current signal set.
        /// </summary>
        /// <returns><see langword="true"/> when one or more rules have been recorded; otherwise, <see langword="false"/>.</returns>
        public bool HasAnyTriggeredRule()
        {
            return _triggeredRuleIds.Count > 0;
        }

        /// <summary>
        /// Returns the recorded rule identifiers.
        /// </summary>
        /// <returns>A snapshot of the triggered rule identifiers.</returns>
        public IEnumerable<string> GetTriggeredRuleIds()
        {
            return _triggeredRuleIds.ToList();
        }

        /// <summary>
        /// Gets the number of high-level signal flags currently set.
        /// </summary>
        public int SignalCount
        {
            get
            {
                int count = 0;
                if (HasEncodedStrings)
                    count++;
                if (HasSuspiciousReflection)
                    count++;
                if (UsesSensitiveFolder)
                    count++;
                if (HasProcessLikeCall)
                    count++;
                if (HasBase64)
                    count++;
                if (HasNetworkCall)
                    count++;
                if (HasFileWrite)
                    count++;
                if (HasSuspiciousLocalVariables)
                    count++;
                if (HasSuspiciousExceptionHandling)
                    count++;
                return count;
            }
        }

        /// <summary>
        /// Determines whether the current signal mix matches a critical-risk combination.
        /// </summary>
        /// <returns><see langword="true"/> when the active signals represent a critical combination.</returns>
        public bool IsCriticalCombination()
        {
            // Critical: Reflection + Encoded data
            if (HasSuspiciousReflection && HasEncodedStrings)
                return true;

            // Critical: Reflection + Sensitive path
            if (HasSuspiciousReflection && UsesSensitiveFolder)
                return true;

            // Critical: Encoded strings + Process execution
            if (HasEncodedStrings && HasProcessLikeCall)
                return true;

            // Critical: Sensitive path + File write + Process call
            if (UsesSensitiveFolder && HasFileWrite && HasProcessLikeCall)
                return true;

            // High: Network + Sensitive path + File write
            if (HasNetworkCall && UsesSensitiveFolder && HasFileWrite)
                return true;

            return false;
        }

        /// <summary>
        /// Determines whether the current signal mix matches an elevated-risk combination.
        /// </summary>
        /// <returns><see langword="true"/> when the active signals represent a high-risk combination.</returns>
        public bool IsHighRiskCombination()
        {
            // High risk requires dangerous signal combinations that can be abused maliciously
            // NOT just any 2+ signals - common update/download/telemetry patterns stay Low/Medium

            // Sensitive folder + network = potential exfiltration
            if (UsesSensitiveFolder && HasNetworkCall)
                return true;

            // Sensitive folder + process = run malware from hidden location
            if (UsesSensitiveFolder && HasProcessLikeCall)
                return true;

            // Base64 + process = obfuscated payload execution
            if (HasBase64 && HasProcessLikeCall)
                return true;

            // Encoded strings + dangerous execution
            if (HasEncodedStrings && (HasProcessLikeCall || HasNetworkCall))
                return true;

            return false;
        }

        /// <summary>
        /// Builds a human-readable description of the active signals.
        /// </summary>
        /// <returns>A stable, concatenated description of the currently set signals.</returns>
        public string GetCombinationDescription()
        {
            var signals = new List<string>();
            if (HasEncodedStrings)
                signals.Add("encoded strings");
            if (HasSuspiciousReflection)
                signals.Add("suspicious reflection");
            if (UsesSensitiveFolder)
                signals.Add("sensitive folder access");
            if (HasProcessLikeCall)
                signals.Add("process execution");
            if (HasBase64)
                signals.Add("Base64 decoding");
            if (HasNetworkCall)
                signals.Add("network call");
            if (HasFileWrite)
                signals.Add("file write");
            if (HasSuspiciousLocalVariables)
                signals.Add("suspicious variable types");
            if (HasSuspiciousExceptionHandling)
                signals.Add("exception handler patterns");

            return string.Join(" + ", signals);
        }
    }
}
