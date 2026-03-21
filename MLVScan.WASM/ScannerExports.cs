using System.Runtime.InteropServices.JavaScript;

namespace MLVScan.WASM;

/// <summary>
/// JavaScript-exported entry points for the browser-hosted MLVScan.WASM runtime.
/// These methods are invoked by the <c>@mlvscan/wasm-core</c> package after the .NET runtime loads.
/// </summary>
public partial class ScannerExports
{
#pragma warning disable CS0618
    private static readonly WasmScanner _scanner = new WasmScanner();
#pragma warning restore CS0618

    /// <summary>
    /// Scans an uploaded assembly and returns the shared scan result schema as JSON.
    /// </summary>
    /// <param name="assemblyBytes">Raw bytes of the uploaded assembly.</param>
    /// <param name="fileName">Original file name to record in the scan result.</param>
    /// <returns>Serialized <see cref="Models.Dto.ScanResultDto"/> JSON.</returns>
    [JSExport]
    public static string ScanAssembly(byte[] assemblyBytes, string fileName)
    {
#pragma warning disable CS0618
        return _scanner.ScanAssembly(assemblyBytes, fileName);
#pragma warning restore CS0618
    }

    /// <summary>
    /// Scans an uploaded assembly using a caller-supplied <see cref="Models.ScanConfig"/>.
    /// </summary>
    /// <param name="assemblyBytes">Raw bytes of the uploaded assembly.</param>
    /// <param name="fileName">Original file name to record in the scan result.</param>
    /// <param name="configJson">JSON representation of <see cref="Models.ScanConfig"/>.</param>
    /// <returns>Serialized <see cref="Models.Dto.ScanResultDto"/> JSON.</returns>
    [JSExport]
    public static string ScanAssemblyWithConfig(byte[] assemblyBytes, string fileName, string configJson)
    {
#pragma warning disable CS0618
        return _scanner.ScanAssemblyWithConfig(assemblyBytes, fileName, configJson);
#pragma warning restore CS0618
    }

    /// <summary>
    /// Gets the current WASM package version.
    /// </summary>
    /// <returns>Version string for the browser-hosted scanner.</returns>
    [JSExport]
    public static string GetVersion()
    {
#pragma warning disable CS0618
        return WasmScanner.GetVersion();
#pragma warning restore CS0618
    }

    /// <summary>
    /// Gets the schema version returned by this WASM scanner build.
    /// </summary>
    /// <returns>Shared scan-result schema version.</returns>
    [JSExport]
    public static string GetSchemaVersion()
    {
#pragma warning disable CS0618
        return WasmScanner.GetSchemaVersion();
#pragma warning restore CS0618
    }
}
