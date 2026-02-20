using System.Runtime.InteropServices.JavaScript;

namespace MLVScan.WASM;

public partial class ScannerExports
{
    private static readonly WasmScanner _scanner = new WasmScanner();

    [JSExport]
    public static string ScanAssembly(byte[] assemblyBytes, string fileName)
    {
        return _scanner.ScanAssembly(assemblyBytes, fileName);
    }

    [JSExport]
    public static string ScanAssemblyWithConfig(byte[] assemblyBytes, string fileName, string configJson)
    {
        return _scanner.ScanAssemblyWithConfig(assemblyBytes, fileName, configJson);
    }

    [JSExport]
    public static string GetVersion()
    {
        return WasmScanner.GetVersion();
    }

    [JSExport]
    public static string GetSchemaVersion()
    {
        return WasmScanner.GetSchemaVersion();
    }
}
