namespace MLVScan.Models
{
    /// <summary>
    /// Tracks suspicious signals detected within a single method for multi-pattern analysis
    /// </summary>
    public class MethodSignals
    {
        public bool HasEncodedStrings { get; set; }
        public bool HasSuspiciousReflection { get; set; }
        public bool UsesSensitiveFolder { get; set; }
        public bool HasProcessLikeCall { get; set; }
        public bool HasBase64 { get; set; }
        public bool HasNetworkCall { get; set; }
        public bool HasFileWrite { get; set; }
        public bool HasSuspiciousLocalVariables { get; set; }
        public bool HasSuspiciousExceptionHandling { get; set; }
        
        private HashSet<string> _triggeredRuleIds = new HashSet<string>();
        
        /// <summary>
        /// Marks a rule as having been triggered in this method/type
        /// </summary>
        public void MarkRuleTriggered(string ruleId)
        {
            if (!string.IsNullOrEmpty(ruleId))
            {
                _triggeredRuleIds.Add(ruleId);
            }
        }
        
        /// <summary>
        /// Checks if any rule other than the specified one has been triggered
        /// </summary>
        public bool HasTriggeredRuleOtherThan(string ruleId)
        {
            if (string.IsNullOrEmpty(ruleId))
            {
                return _triggeredRuleIds.Count > 0;
            }
            return _triggeredRuleIds.Count > 0 && !_triggeredRuleIds.All(id => id == ruleId);
        }
        
        /// <summary>
        /// Checks if any rule has been triggered
        /// </summary>
        public bool HasAnyTriggeredRule()
        {
            return _triggeredRuleIds.Count > 0;
        }
        
        /// <summary>
        /// Gets all triggered rule IDs
        /// </summary>
        public IEnumerable<string> GetTriggeredRuleIds()
        {
            return _triggeredRuleIds.ToList();
        }

        public int SignalCount
        {
            get
            {
                int count = 0;
                if (HasEncodedStrings) count++;
                if (HasSuspiciousReflection) count++;
                if (UsesSensitiveFolder) count++;
                if (HasProcessLikeCall) count++;
                if (HasBase64) count++;
                if (HasNetworkCall) count++;
                if (HasFileWrite) count++;
                if (HasSuspiciousLocalVariables) count++;
                if (HasSuspiciousExceptionHandling) count++;
                return count;
            }
        }

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

        public bool IsHighRiskCombination()
        {
            // High risk requires dangerous signal combinations that can be abused maliciously
            // NOT just any 2+ signals - precursors alone stay Low/Medium
            
            // Sensitive folder + network = potential exfiltration
            if (UsesSensitiveFolder && HasNetworkCall)
                return true;
            
            // Sensitive folder + process = run malware from hidden location
            if (UsesSensitiveFolder && HasProcessLikeCall)
                return true;
            
            // Network + file write = download & execute payload
            if (HasNetworkCall && HasFileWrite)
                return true;
            
            // Base64 + network or process = obfuscated payload execution
            if (HasBase64 && (HasNetworkCall || HasProcessLikeCall))
                return true;
            
            // Encoded strings + dangerous execution
            if (HasEncodedStrings && (HasProcessLikeCall || HasNetworkCall))
                return true;
            
            return false;
        }

        public string GetCombinationDescription()
        {
            var signals = new List<string>();
            if (HasEncodedStrings) signals.Add("encoded strings");
            if (HasSuspiciousReflection) signals.Add("suspicious reflection");
            if (UsesSensitiveFolder) signals.Add("sensitive folder access");
            if (HasProcessLikeCall) signals.Add("process execution");
            if (HasBase64) signals.Add("Base64 decoding");
            if (HasNetworkCall) signals.Add("network call");
            if (HasFileWrite) signals.Add("file write");
            if (HasSuspiciousLocalVariables) signals.Add("suspicious variable types");
            if (HasSuspiciousExceptionHandling) signals.Add("exception handler patterns");

            return string.Join(" + ", signals);
        }
    }
}
