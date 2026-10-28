namespace MLVScan.Models.Rules.Helpers;

internal sealed class ValueResolutionLimits(ScanConfig config)
{
    internal static ValueResolutionLimits Standard { get; } = new(new ScanConfig());
    internal int Work { get; } = Math.Clamp(config.MaxValueResolutionWork, 1, 1_000_000);
    internal int Depth { get; } = Math.Clamp(config.MaxValueResolutionDepth, 1, 128);
    internal int Alternatives { get; } = Math.Clamp(config.MaxValueResolutionAlternatives, 1, 256);
}
