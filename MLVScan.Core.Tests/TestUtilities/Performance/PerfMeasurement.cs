using System.Diagnostics;

namespace MLVScan.Core.Tests.TestUtilities.Performance;

internal sealed class PerfMeasurement
{
    public required string Name { get; init; }
    public required IReadOnlyList<long> DurationsMs { get; init; }

    public long MinMs => DurationsMs.Count == 0 ? 0 : DurationsMs.Min();
    public long MaxMs => DurationsMs.Count == 0 ? 0 : DurationsMs.Max();
    public double AverageMs => DurationsMs.Count == 0 ? 0 : DurationsMs.Average();
    public long P95Ms => Percentile(95);

    public static PerfMeasurement Measure(string name, int warmupRuns, int measuredRuns, Action action)
    {
        for (var i = 0; i < warmupRuns; i++)
        {
            action();
        }

        var runs = new List<long>(measuredRuns);
        for (var i = 0; i < measuredRuns; i++)
        {
            var sw = Stopwatch.StartNew();
            action();
            sw.Stop();
            runs.Add(sw.ElapsedMilliseconds);
        }

        return new PerfMeasurement
        {
            Name = name,
            DurationsMs = runs
        };
    }

    private long Percentile(int percentile)
    {
        if (DurationsMs.Count == 0)
        {
            return 0;
        }

        var sorted = DurationsMs.OrderBy(v => v).ToArray();
        var rank = (percentile / 100.0) * (sorted.Length - 1);
        var index = (int)Math.Ceiling(rank);
        return sorted[Math.Clamp(index, 0, sorted.Length - 1)];
    }
}
