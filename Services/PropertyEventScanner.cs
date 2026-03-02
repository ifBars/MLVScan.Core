using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Services
{
    /// <summary>
    /// Scans property accessors (get/set) and event handlers (add/remove/invoke) for malicious code.
    /// Malware can hide in these accessors to evade basic scanning.
    /// </summary>
    public class PropertyEventScanner
    {
        private readonly MethodScanner _methodScanner;
        private readonly ScanConfig _config;

        public PropertyEventScanner(MethodScanner methodScanner, ScanConfig config)
        {
            _methodScanner = methodScanner ?? throw new ArgumentNullException(nameof(methodScanner));
            _config = config ?? new ScanConfig();
        }

        public IEnumerable<ScanFinding> ScanProperties(TypeDefinition type, string typeFullName)
        {
            var findings = new List<ScanFinding>();

            if (!_config.AnalyzePropertyAccessors || !type.HasProperties)
                return findings;

            try
            {
                foreach (var property in type.Properties)
                {
                    // Scan property getter
                    if (property.GetMethod?.HasBody == true)
                    {
                        var getterFindings =
                            ScanPropertyAccessor(property.GetMethod, property.Name, "getter", typeFullName);
                        findings.AddRange(getterFindings);
                    }

                    // Scan property setter
                    if (property.SetMethod?.HasBody == true)
                    {
                        var setterFindings =
                            ScanPropertyAccessor(property.SetMethod, property.Name, "setter", typeFullName);
                        findings.AddRange(setterFindings);
                    }
                }
            }
            catch (Exception)
            {
                // Skip if property scanning fails
            }

            return findings;
        }

        public IEnumerable<ScanFinding> ScanEvents(TypeDefinition type, string typeFullName)
        {
            var findings = new List<ScanFinding>();

            if (!_config.AnalyzePropertyAccessors || !type.HasEvents)
                return findings;

            try
            {
                foreach (var evt in type.Events)
                {
                    // Scan event add handler
                    if (evt.AddMethod?.HasBody == true)
                    {
                        var addFindings = ScanEventHandler(evt.AddMethod, evt.Name, "add", typeFullName);
                        findings.AddRange(addFindings);
                    }

                    // Scan event remove handler
                    if (evt.RemoveMethod?.HasBody == true)
                    {
                        var removeFindings = ScanEventHandler(evt.RemoveMethod, evt.Name, "remove", typeFullName);
                        findings.AddRange(removeFindings);
                    }

                    // Scan event invoke handler
                    if (evt.InvokeMethod?.HasBody == true)
                    {
                        var invokeFindings = ScanEventHandler(evt.InvokeMethod, evt.Name, "invoke", typeFullName);
                        findings.AddRange(invokeFindings);
                    }
                }
            }
            catch (Exception)
            {
                // Skip if event scanning fails
            }

            return findings;
        }

        private IEnumerable<ScanFinding> ScanPropertyAccessor(MethodDefinition method, string propertyName,
            string accessorType, string typeFullName)
        {
            var findings = new List<ScanFinding>();

            try
            {
                var result = _methodScanner.ScanMethod(method, typeFullName);

                // Add context to findings about property location
                foreach (var finding in result.Findings)
                {
                    var contextualFinding = new ScanFinding(
                        finding.Location,
                        finding.Description + $" (found in property {accessorType}: {propertyName})",
                        finding.Severity,
                        finding.CodeSnippet)
                    {
                        RuleId = finding.RuleId,
                        DeveloperGuidance = finding.DeveloperGuidance,
                        CallChain = finding.CallChain,
                        DataFlowChain = finding.DataFlowChain,
                        BypassCompanionCheck = finding.BypassCompanionCheck,
                        RiskScore = finding.RiskScore
                    };

                    findings.Add(contextualFinding);
                }
            }
            catch (Exception)
            {
                // Skip if accessor scanning fails
            }

            return findings;
        }

        private IEnumerable<ScanFinding> ScanEventHandler(MethodDefinition method, string eventName, string handlerType,
            string typeFullName)
        {
            var findings = new List<ScanFinding>();

            try
            {
                var result = _methodScanner.ScanMethod(method, typeFullName);

                // Add context to findings about event location
                foreach (var finding in result.Findings)
                {
                    var contextualFinding = new ScanFinding(
                        finding.Location,
                        finding.Description + $" (found in event {handlerType}: {eventName})",
                        finding.Severity,
                        finding.CodeSnippet)
                    {
                        RuleId = finding.RuleId,
                        DeveloperGuidance = finding.DeveloperGuidance,
                        CallChain = finding.CallChain,
                        DataFlowChain = finding.DataFlowChain,
                        BypassCompanionCheck = finding.BypassCompanionCheck,
                        RiskScore = finding.RiskScore
                    };

                    findings.Add(contextualFinding);
                }
            }
            catch (Exception)
            {
                // Skip if handler scanning fails
            }

            return findings;
        }
    }
}
