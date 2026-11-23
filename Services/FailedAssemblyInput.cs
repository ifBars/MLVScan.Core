namespace MLVScan.Services;

/// <summary>Inspects headers only after Cecil rejects an input. Never admits or skips a scan.</summary>
internal sealed class FailedAssemblyInput
{
    private FailedAssemblyInput(string summary, string ruleId = "AssemblyScanner")
    {
        Summary = summary;
        RuleId = ruleId;
    }

    public string Summary { get; }
    public string RuleId { get; }

    public static FailedAssemblyInput? Describe(Stream input)
    {
        if (!input.CanSeek || !input.CanRead) return null;
        try
        {
            var position = input.Position;
            try
            {
                input.Position = 0;
                using var reader = new BinaryReader(input, System.Text.Encoding.UTF8, leaveOpen: true);
                return Inspect(reader, input) switch
                {
                    "native_pe" => new("Native PE file. MLVScan analyzes managed .NET code. This file has no CLR directory.", "NativePeInput"),
                    "apple_double" => new("This AppleDouble sidecar stores file metadata. Managed analysis does not apply.", "AppleDoubleInput"),
                    "non_pe" => new("The file could not be scanned as a managed assembly. It lacks a PE image signature. Check that you supplied the assembly itself. Failure category: non_pe."),
                    "invalid_cli_metadata" => new("The file could not be scanned as a managed assembly. Its headers declare CLR data, but managed assembly metadata could not be read. Verify the file is intact. Failure category: invalid_cli_metadata."),
                    _ => new("The file could not be scanned as a managed assembly. Its PE headers are incomplete or inconsistent. Verify the file is intact. Failure category: malformed_pe.")
                };
            }
            finally
            {
                input.Position = position;
            }
        }
        catch (Exception error) when (error is IOException or NotSupportedException or ObjectDisposedException)
        {
            return null;
        }
    }

    // AppleDouble v2 uses big-endian descriptors. Require a bounded, intact table and payload.
    private static bool IsAppleDouble(BinaryReader reader, Stream input, long length)
    {
        if (reader.ReadUInt32() != 0x00000200) return false;
        input.Position = 24;
        int entries = (reader.ReadByte() << 8) | reader.ReadByte();
        long headerSize = 26 + 12L * entries;
        if (entries is 0 or > 64 || headerSize > length) return false;
        bool hasMetadata = false;
        for (int i = 0; i < entries; i++)
        {
            var id = System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
            long offset = System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
            long size = System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
            if (id is 0 or 1 || offset < headerSize || offset + size > length) return false;
            if (id is 2 or 9 && size > 0) hasMetadata = true;
        }
        return hasMetadata;
    }

    private static string Inspect(BinaryReader reader, Stream input)
    {
        long length = input.Length;
        if (length >= 26 && reader.ReadUInt32() == 0x07160500 && IsAppleDouble(reader, input, length))
            return "apple_double";
        input.Position = 0;
        if (length == 0 || reader.ReadByte() != 'M') return "non_pe";
        if (length == 1) return "malformed_pe";
        if (reader.ReadByte() != 'Z') return "non_pe";
        if (length < 64) return "malformed_pe";
        input.Position = 60;
        long pe = reader.ReadUInt32();
        if (pe < 64 || pe + 24 > length) return "malformed_pe";
        input.Position = pe;
        if (reader.ReadUInt32() != 0x4550) return "malformed_pe";
        input.Position = pe + 6;
        int sections = reader.ReadUInt16();
        input.Position = pe + 20;
        int optionalSize = reader.ReadUInt16();
        long optional = pe + 24;
        long sectionTable = optional + optionalSize;
        if (sections is < 1 or > 96 || optionalSize < 2 || sectionTable + sections * 40 > length)
            return "malformed_pe";

        input.Position = optional;
        int directories = reader.ReadUInt16() switch { 0x10b => 96, 0x20b => 112, _ => 0 };
        if (directories == 0 || optionalSize < directories) return "malformed_pe";
        input.Position = optional + directories - 4;
        uint directoryCount = reader.ReadUInt32();
        if (directoryCount > (optionalSize - directories) / 8) return "malformed_pe";
        for (int i = 0; i < sections; i++)
        {
            input.Position = sectionTable + i * 40 + 16;
            long size = reader.ReadUInt32();
            long offset = reader.ReadUInt32();
            if (size > 0 && (offset < sectionTable + sections * 40 || offset + size > length))
                return "malformed_pe";
        }

        if (directoryCount <= 14) return "native_pe";
        input.Position = optional + directories + 14 * 8;
        uint rva = reader.ReadUInt32();
        uint cliSize = reader.ReadUInt32();
        return rva == 0 && cliSize == 0 ? "native_pe" : "invalid_cli_metadata";
    }
}
