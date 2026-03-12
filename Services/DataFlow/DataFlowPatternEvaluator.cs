using MLVScan.Models;
using MLVScan.Models.DataFlow;

namespace MLVScan.Services.DataFlow
{
    internal sealed class DataFlowPatternEvaluator
    {
        public DataFlowPattern RecognizePattern(IReadOnlyList<DataFlowInterestingOperation> operations)
        {
            if (HasResourceSource(operations) && HasProcessStart(operations) && (HasFileWrite(operations) || HasTransform(operations)))
            {
                return DataFlowPattern.EmbeddedResourceDropAndExecute;
            }

            if (HasNetworkSource(operations) && HasFileWrite(operations) && HasProcessStart(operations))
            {
                return DataFlowPattern.DownloadAndExecute;
            }

            if ((HasFileSource(operations) || HasRegistrySource(operations)) && HasNetworkSink(operations))
            {
                return DataFlowPattern.DataExfiltration;
            }

            if ((HasNetworkSource(operations) || HasFileSource(operations)) && HasAssemblyLoad(operations))
            {
                return DataFlowPattern.DynamicCodeLoading;
            }

            if (HasFileSource(operations) && HasNetworkSink(operations))
            {
                return DataFlowPattern.CredentialTheft;
            }

            if (HasTransform(operations) && HasRegistrySink(operations))
            {
                return DataFlowPattern.ObfuscatedPersistence;
            }

            if (HasNetworkSource(operations) && !HasDangerousSink(operations))
            {
                return DataFlowPattern.RemoteConfigLoad;
            }

            return DataFlowPattern.Unknown;
        }

        public Severity DetermineSeverity(DataFlowPattern pattern)
        {
            return pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => Severity.Critical,
                DataFlowPattern.DownloadAndExecute => Severity.Critical,
                DataFlowPattern.DataExfiltration => Severity.Critical,
                DataFlowPattern.DynamicCodeLoading => Severity.Critical,
                DataFlowPattern.CredentialTheft => Severity.Critical,
                DataFlowPattern.ObfuscatedPersistence => Severity.High,
                DataFlowPattern.RemoteConfigLoad => Severity.Medium,
                _ => Severity.Low
            };
        }

        public double CalculateConfidence(DataFlowPattern pattern, IReadOnlyList<DataFlowInterestingOperation> operations)
        {
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
            {
                return 0.5;
            }

            var confidence = 0.7;

            if (operations.Count >= 3)
            {
                confidence += 0.1;
            }

            if (operations.Count >= 4)
            {
                confidence += 0.1;
            }

            var hasAllTypes = operations.Any(static operation => operation.NodeType == DataFlowNodeType.Source) &&
                              operations.Any(static operation => operation.NodeType == DataFlowNodeType.Transform) &&
                              operations.Any(static operation => operation.NodeType == DataFlowNodeType.Sink);

            if (hasAllTypes)
            {
                confidence += 0.1;
            }

            return Math.Min(confidence, 1.0);
        }

        public string BuildSummary(DataFlowPattern pattern, int operationCount)
        {
            var summary = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute =>
                    "Suspicious data flow: Extracts embedded resource to disk and executes it via native shell API",
                DataFlowPattern.DownloadAndExecute =>
                    "Suspicious data flow: Downloads data from network, processes it, and executes as a program",
                DataFlowPattern.DataExfiltration =>
                    "Suspicious data flow: Reads sensitive data and sends it over the network",
                DataFlowPattern.DynamicCodeLoading =>
                    "Suspicious data flow: Loads and executes code dynamically at runtime",
                DataFlowPattern.CredentialTheft =>
                    "Suspicious data flow: Accesses files and sends data to network (potential credential theft)",
                DataFlowPattern.ObfuscatedPersistence =>
                    "Suspicious data flow: Encodes data before writing to registry (persistence with obfuscation)",
                DataFlowPattern.RemoteConfigLoad => "Data flow: Downloads configuration from network",
                _ => "Suspicious data flow detected"
            };

            return $"{summary} ({operationCount} operations)";
        }

        public ScanFinding CreateFinding(DataFlowChain chain)
        {
            return new ScanFinding(
                chain.MethodLocation,
                chain.ToDetailedDescription(),
                chain.Severity,
                chain.ToCombinedCodeSnippet())
            {
                RuleId = "DataFlowAnalysis",
                DataFlowChain = chain
            };
        }

        public bool ShouldEmitFinding(DataFlowPattern pattern)
        {
            return pattern == DataFlowPattern.EmbeddedResourceDropAndExecute ||
                   pattern == DataFlowPattern.DownloadAndExecute ||
                   pattern == DataFlowPattern.DynamicCodeLoading ||
                   pattern == DataFlowPattern.ObfuscatedPersistence;
        }

        private static bool HasNetworkSource(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Source &&
                (operation.Operation.Contains("Http", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("Web", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("Network", StringComparison.OrdinalIgnoreCase)));
        }

        private static bool HasFileSource(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Source &&
                operation.Operation.Contains("File", StringComparison.OrdinalIgnoreCase));
        }

        private static bool HasRegistrySource(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Source &&
                operation.Operation.Contains("Registry", StringComparison.OrdinalIgnoreCase));
        }

        private static bool HasResourceSource(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Source &&
                (operation.Operation.Contains("GetManifestResourceStream", StringComparison.OrdinalIgnoreCase) ||
                 operation.DataDescription.Contains("embedded resource", StringComparison.OrdinalIgnoreCase)));
        }

        private static bool HasTransform(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation => operation.NodeType == DataFlowNodeType.Transform);
        }

        private static bool HasFileWrite(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Sink &&
                (((operation.Operation.Contains("Write", StringComparison.OrdinalIgnoreCase) ||
                   operation.Operation.Contains("Create", StringComparison.OrdinalIgnoreCase)) &&
                  operation.Operation.Contains("File", StringComparison.OrdinalIgnoreCase)) ||
                 operation.Operation.Contains("FileStream", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("DownloadFile", StringComparison.OrdinalIgnoreCase)));
        }

        private static bool HasProcessStart(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Sink &&
                (operation.Operation.Contains("Process.Start", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("PInvoke.ShellExecute", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("PInvoke.CreateProcess", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("PInvoke.WinExec", StringComparison.OrdinalIgnoreCase)));
        }

        private static bool HasNetworkSink(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Sink &&
                (operation.Operation.Contains("Http", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("Web", StringComparison.OrdinalIgnoreCase) ||
                 operation.Operation.Contains("Network", StringComparison.OrdinalIgnoreCase)));
        }

        private static bool HasRegistrySink(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Sink &&
                operation.Operation.Contains("Registry", StringComparison.OrdinalIgnoreCase));
        }

        private static bool HasAssemblyLoad(IEnumerable<DataFlowInterestingOperation> operations)
        {
            return operations.Any(static operation =>
                operation.Operation.Contains("Assembly", StringComparison.OrdinalIgnoreCase) &&
                operation.Operation.Contains("Load", StringComparison.OrdinalIgnoreCase));
        }

        private static bool HasDangerousSink(IReadOnlyList<DataFlowInterestingOperation> operations)
        {
            return HasProcessStart(operations) || HasFileWrite(operations) || HasRegistrySink(operations);
        }
    }
}
