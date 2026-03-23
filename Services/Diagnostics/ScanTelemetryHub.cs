using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace MLVScan.Services.Diagnostics
{
    /// <summary>
    /// Collects optional scan profiling data when <c>MLVSCAN_PROFILING</c> is enabled.
    /// </summary>
    internal sealed class ScanTelemetryHub
    {
        private ScanProfileSnapshot? _lastSnapshot;

#if MLVSCAN_PROFILING
        private ScanProfileSession? _currentSession;
#endif

        /// <summary>
        /// Starts a new telemetry session for the supplied assembly identifier.
        /// </summary>
        /// <param name="assemblyId">An identifier for the assembly being scanned.</param>
        public void BeginAssembly(string assemblyId)
        {
#if MLVSCAN_PROFILING
            _currentSession = new ScanProfileSession(assemblyId);
#else
            _ = assemblyId;
#endif
            _lastSnapshot = null;
        }

        /// <summary>
        /// Gets the current high-resolution timestamp for profiling measurements.
        /// </summary>
        /// <returns>A timestamp from <see cref="Stopwatch.GetTimestamp"/> when profiling is enabled; otherwise <c>0</c>.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public long StartTimestamp()
        {
#if MLVSCAN_PROFILING
            return Stopwatch.GetTimestamp();
#else
            return 0;
#endif
        }

        /// <summary>
        /// Records the elapsed time for a named scan phase.
        /// </summary>
        /// <param name="phaseName">The phase name being measured.</param>
        /// <param name="startTimestamp">The timestamp returned by <see cref="StartTimestamp"/>.</param>
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

        /// <summary>
        /// Increments a profiling counter.
        /// </summary>
        /// <param name="counterName">The counter name to increment.</param>
        /// <param name="delta">The amount to add to the counter.</param>
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

        /// <summary>
        /// Records a type-level profiling sample.
        /// </summary>
        /// <param name="typeName">The type name being sampled.</param>
        /// <param name="startTimestamp">The timestamp returned by <see cref="StartTimestamp"/>.</param>
        /// <param name="methodCount">The number of methods seen in the type.</param>
        /// <param name="nestedTypeCount">The number of nested types seen in the type.</param>
        /// <param name="findingsCount">The number of findings emitted while scanning the type.</param>
        /// <param name="pendingReflectionCount">The number of deferred reflection findings for the type.</param>
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

        /// <summary>
        /// Records a method-level profiling sample.
        /// </summary>
        /// <param name="methodName">The method name being sampled.</param>
        /// <param name="startTimestamp">The timestamp returned by <see cref="StartTimestamp"/>.</param>
        /// <param name="instructionCount">The number of IL instructions in the method.</param>
        /// <param name="findingsCount">The number of findings emitted while scanning the method.</param>
        /// <param name="localVariableCount">The number of local variables seen in the method.</param>
        /// <param name="exceptionHandlerCount">The number of exception handlers seen in the method.</param>
        /// <param name="pendingReflectionCount">The number of deferred reflection findings for the method.</param>
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

        /// <summary>
        /// Completes the current assembly profiling session and stores the resulting snapshot.
        /// </summary>
        /// <param name="findingsBeforeFilter">The number of findings before filtering.</param>
        /// <param name="findingsAfterFilter">The number of findings after filtering.</param>
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

        /// <summary>
        /// Gets the most recently completed profiling snapshot.
        /// </summary>
        /// <returns>The last completed snapshot, or <see langword="null"/> if profiling is disabled or no session completed.</returns>
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
