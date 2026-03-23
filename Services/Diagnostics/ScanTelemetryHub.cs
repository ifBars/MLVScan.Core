using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace MLVScan.Services.Diagnostics
{
    internal sealed class ScanTelemetryHub
    {
        private ScanProfileSnapshot? _lastSnapshot;

#if MLVSCAN_PROFILING
        private ScanProfileSession? _currentSession;
#endif

        public void BeginAssembly(string assemblyId)
        {
#if MLVSCAN_PROFILING
            _currentSession = new ScanProfileSession(assemblyId);
#else
            _ = assemblyId;
#endif
            _lastSnapshot = null;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public long StartTimestamp()
        {
#if MLVSCAN_PROFILING
            return Stopwatch.GetTimestamp();
#else
            return 0;
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void AddPhaseElapsed(string phaseName, long startTimestamp)
        {
#if MLVSCAN_PROFILING
            if (_currentSession == null || startTimestamp == 0)
            {
                return;
            }

            _currentSession.AddPhaseElapsed(phaseName, Stopwatch.GetTimestamp() - startTimestamp);
#else
            _ = phaseName;
            _ = startTimestamp;
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void IncrementCounter(string counterName, long delta = 1)
        {
#if MLVSCAN_PROFILING
            if (_currentSession == null)
            {
                return;
            }

            _currentSession.IncrementCounter(counterName, delta);
#else
            _ = counterName;
            _ = delta;
#endif
        }

        public void RecordTypeSample(
            string typeName,
            long startTimestamp,
            int methodCount,
            int nestedTypeCount,
            int findingsCount,
            int pendingReflectionCount)
        {
#if MLVSCAN_PROFILING
            if (_currentSession == null || startTimestamp == 0)
            {
                return;
            }

            _currentSession.AddTypeSample(
                typeName,
                Stopwatch.GetTimestamp() - startTimestamp,
                methodCount,
                nestedTypeCount,
                findingsCount,
                pendingReflectionCount);
#else
            _ = typeName;
            _ = startTimestamp;
            _ = methodCount;
            _ = nestedTypeCount;
            _ = findingsCount;
            _ = pendingReflectionCount;
#endif
        }

        public void RecordMethodSample(
            string methodName,
            long startTimestamp,
            int instructionCount,
            int findingsCount,
            int localVariableCount,
            int exceptionHandlerCount,
            int pendingReflectionCount)
        {
#if MLVSCAN_PROFILING
            if (_currentSession == null || startTimestamp == 0)
            {
                return;
            }

            _currentSession.AddMethodSample(
                methodName,
                Stopwatch.GetTimestamp() - startTimestamp,
                instructionCount,
                findingsCount,
                localVariableCount,
                exceptionHandlerCount,
                pendingReflectionCount);
#else
            _ = methodName;
            _ = startTimestamp;
            _ = instructionCount;
            _ = findingsCount;
            _ = localVariableCount;
            _ = exceptionHandlerCount;
            _ = pendingReflectionCount;
#endif
        }

        public void CompleteAssembly(int findingsBeforeFilter, int findingsAfterFilter)
        {
#if MLVSCAN_PROFILING
            if (_currentSession == null)
            {
                _lastSnapshot = null;
                return;
            }

            _currentSession.IncrementCounter("Findings.BeforeFilter", findingsBeforeFilter);
            _currentSession.IncrementCounter("Findings.AfterFilter", findingsAfterFilter);
            _currentSession.TotalElapsedTicks = Stopwatch.GetTimestamp() - _currentSession.StartTimestamp;
            _lastSnapshot = _currentSession.ToSnapshot();
            _currentSession = null;
#else
            _ = findingsBeforeFilter;
            _ = findingsAfterFilter;
            _lastSnapshot = null;
#endif
        }

        public ScanProfileSnapshot? GetLastSnapshot()
        {
            return _lastSnapshot;
        }
    }

    internal sealed class ScanProfileSnapshot
    {
        public string AssemblyId { get; set; } = string.Empty;

        public long TotalElapsedTicks { get; set; }

        public IReadOnlyList<ScanProfilePhaseTiming> Phases { get; set; } = Array.Empty<ScanProfilePhaseTiming>();

        public IReadOnlyDictionary<string, long> Counters { get; set; } =
            new Dictionary<string, long>(StringComparer.Ordinal);

        public IReadOnlyList<ScanProfileTypeSample> SlowTypes { get; set; } = Array.Empty<ScanProfileTypeSample>();

        public IReadOnlyList<ScanProfileMethodSample> SlowMethods { get; set; } =
            Array.Empty<ScanProfileMethodSample>();
    }

    internal sealed class ScanProfilePhaseTiming
    {
        public string Name { get; set; } = string.Empty;

        public long ElapsedTicks { get; set; }

        public int Count { get; set; }
    }

    internal sealed class ScanProfileTypeSample
    {
        public string TypeName { get; set; } = string.Empty;

        public long ElapsedTicks { get; set; }

        public int MethodCount { get; set; }

        public int NestedTypeCount { get; set; }

        public int FindingsCount { get; set; }

        public int PendingReflectionCount { get; set; }
    }

    internal sealed class ScanProfileMethodSample
    {
        public string MethodName { get; set; } = string.Empty;

        public long ElapsedTicks { get; set; }

        public int InstructionCount { get; set; }

        public int FindingsCount { get; set; }

        public int LocalVariableCount { get; set; }

        public int ExceptionHandlerCount { get; set; }

        public int PendingReflectionCount { get; set; }
    }

#if MLVSCAN_PROFILING
    internal sealed class ScanProfileSession
    {
        private const int MaxTopSamples = 20;

        private readonly Dictionary<string, ScanPhaseAccumulator> _phases = new(StringComparer.Ordinal);
        private readonly Dictionary<string, long> _counters = new(StringComparer.Ordinal);
        private readonly List<ScanProfileTypeSample> _typeSamples = new();
        private readonly List<ScanProfileMethodSample> _methodSamples = new();

        public ScanProfileSession(string assemblyId)
        {
            AssemblyId = assemblyId;
            StartTimestamp = Stopwatch.GetTimestamp();
        }

        public string AssemblyId { get; }

        public long StartTimestamp { get; }

        public long TotalElapsedTicks { get; set; }

        public void AddPhaseElapsed(string phaseName, long elapsedTicks)
        {
            if (!_phases.TryGetValue(phaseName, out var accumulator))
            {
                accumulator = new ScanPhaseAccumulator();
                _phases[phaseName] = accumulator;
            }

            accumulator.ElapsedTicks += elapsedTicks;
            accumulator.Count++;
        }

        public void IncrementCounter(string counterName, long delta)
        {
            _counters[counterName] = _counters.TryGetValue(counterName, out var current)
                ? current + delta
                : delta;
        }

        public void AddTypeSample(
            string typeName,
            long elapsedTicks,
            int methodCount,
            int nestedTypeCount,
            int findingsCount,
            int pendingReflectionCount)
        {
            _typeSamples.Add(new ScanProfileTypeSample
            {
                TypeName = typeName,
                ElapsedTicks = elapsedTicks,
                MethodCount = methodCount,
                NestedTypeCount = nestedTypeCount,
                FindingsCount = findingsCount,
                PendingReflectionCount = pendingReflectionCount
            });
        }

        public void AddMethodSample(
            string methodName,
            long elapsedTicks,
            int instructionCount,
            int findingsCount,
            int localVariableCount,
            int exceptionHandlerCount,
            int pendingReflectionCount)
        {
            _methodSamples.Add(new ScanProfileMethodSample
            {
                MethodName = methodName,
                ElapsedTicks = elapsedTicks,
                InstructionCount = instructionCount,
                FindingsCount = findingsCount,
                LocalVariableCount = localVariableCount,
                ExceptionHandlerCount = exceptionHandlerCount,
                PendingReflectionCount = pendingReflectionCount
            });
        }

        public ScanProfileSnapshot ToSnapshot()
        {
            return new ScanProfileSnapshot
            {
                AssemblyId = AssemblyId,
                TotalElapsedTicks = TotalElapsedTicks,
                Phases = _phases
                    .OrderByDescending(static pair => pair.Value.ElapsedTicks)
                    .Select(static pair => new ScanProfilePhaseTiming
                    {
                        Name = pair.Key,
                        ElapsedTicks = pair.Value.ElapsedTicks,
                        Count = pair.Value.Count
                    })
                    .ToArray(),
                Counters = new Dictionary<string, long>(_counters, StringComparer.Ordinal),
                SlowTypes = _typeSamples
                    .OrderByDescending(static sample => sample.ElapsedTicks)
                    .Take(MaxTopSamples)
                    .ToArray(),
                SlowMethods = _methodSamples
                    .OrderByDescending(static sample => sample.ElapsedTicks)
                    .Take(MaxTopSamples)
                    .ToArray()
            };
        }
    }

    internal sealed class ScanPhaseAccumulator
    {
        public long ElapsedTicks { get; set; }

        public int Count { get; set; }
    }
#endif
}
