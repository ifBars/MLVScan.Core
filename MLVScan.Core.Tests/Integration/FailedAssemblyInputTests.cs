using System.Reflection.PortableExecutable;
using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

public class FailedAssemblyInputTests
{
    [Fact]
    public void ManagedAssemblyWithSidecarNameStillReceivesManagedAnalysis()
    {
        using var assembly = TestAssemblyBuilder.Create("Managed")
            .AddType("Sample").AddMethod("Run").EmitString("example")
            .EmitCall("System.Diagnostics.Process", "Start").EndMethod().EndType().Build();
        using var input = new MemoryStream();
        assembly.Write(input);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var findings = scanner.Scan(input, "._library.dll");
        var result = ScanResultMapper.ToDto(findings, "._library.dll", input.ToArray(), false);
        result.AnalysisCompleteness.Status.Should().Be("Complete");
        result.Findings.Should().Contain(f => f.RuleId == "ProcessStartRule");
    }

    [Theory]
    [InlineData("native_pe")]
    [InlineData("apple_double")]
    [InlineData("non_pe")]
    [InlineData("damaged_sidecar")]
    [InlineData("malformed_pe")]
    [InlineData("invalid_cli_metadata")]
    public void RejectedBytesRemainUnclearedOnBothEntryPoints(string category)
    {
        using var assembly = TestAssemblyBuilder.Create("Input").AddType("Sample").EndType().Build();
        using var output = new MemoryStream();
        assembly.Write(output);
        var bytes = output.ToArray();
        using var pe = new PEReader(new MemoryStream(bytes));
        var directory = pe.PEHeaders.PEHeaderStartOffset +
            (pe.PEHeaders.PEHeader!.Magic == PEMagic.PE32 ? 96 : 112) + 14 * 8;

        switch (category)
        {
            case "apple_double":
            case "damaged_sidecar":
                bytes = new byte[70];
                new byte[] { 0, 5, 22, 7, 0, 2, 0, 0 }.CopyTo(bytes, 0);
                bytes[25] = 1;
                bytes[29] = 9;
                bytes[33] = 38;
                bytes[37] = category == "damaged_sidecar" ? (byte)33 : (byte)32;
                break;
            case "non_pe": bytes = [0x50, 0x4b, 3, 4]; break;
            case "malformed_pe": bytes = bytes[..60]; break;
            case "native_pe": Array.Clear(bytes, directory, 8); break;
            case "invalid_cli_metadata": bytes[pe.PEHeaders.MetadataStartOffset] = 0; break;
        }

        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, bytes);
            var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
            using var input = new MemoryStream(bytes);
            foreach (var findings in new[] { scanner.Scan(path).ToList(), scanner.Scan(input, "example.dll").ToList() })
            {
                var warning = findings.Should().ContainSingle().Subject;
                if (category is not ("native_pe" or "apple_double"))
                    AnalysisCompletenessEvaluator.GetDiagnosticReasonCategory(warning.RuleId, warning.Description).Should().Be(category == "damaged_sidecar" ? "non_pe" : category);
                var dto = ScanResultMapper.ToDto(findings, "example.dll", bytes, false);
                dto.AnalysisCompleteness.IsComplete.Should().BeFalse();
                var outsideScope = category is "native_pe" or "apple_double";
                dto.Disposition!.Classification.Should().Be(outsideScope ? "NotApplicable" : "ManualReviewRequired");
                dto.AnalysisCompleteness.ReviewRecommended.Should().Be(!outsideScope);
                dto.Disposition.BlockingRecommended.Should().Be(!outsideScope);
                if (outsideScope) dto.Findings.Should().BeEmpty();
            }
        }
        finally
        {
            File.Delete(path);
        }
    }
}
