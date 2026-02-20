namespace MLVScan.Models.CrossAssembly;

public enum QuarantinePolicy
{
    CallerOnly = 0,
    CallerAndCallee = 1,
    DependencyCluster = 2
}
