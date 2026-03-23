using FluentAssertions;
using MLVScan.Models.Rules.Helpers;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models.Rules.Helpers;

public class InvisibleUnicodeAnalyzerTests
{
    [Fact]
    public void Analyze_DecodesVariationSelectorPayload()
    {
        string encoded = "\U000E0143\U000E0169\U000E0163\U000E0164\U000E0155\U000E015D\U000E011E\U000E0134\U000E0159\U000E0151\U000E0157\U000E015E\U000E015F\U000E0163\U000E0164\U000E0159\U000E0153\U000E0163\U000E011E\U000E0140\U000E0162\U000E015F\U000E0153\U000E0155\U000E0163\U000E0163";

        var analysis = InvisibleUnicodeAnalyzer.Analyze(encoded);

        analysis.HasVariationSelectorPayload.Should().BeTrue();
        analysis.DecodedText.Should().Be("System.Diagnostics.Process");
        analysis.VariationSelectorCount.Should().BeGreaterThan(20);
    }

    [Fact]
    public void Analyze_DoesNotFlagNormalText()
    {
        var analysis = InvisibleUnicodeAnalyzer.Analyze("Hello World");

        analysis.HasVariationSelectorPayload.Should().BeFalse();
        analysis.DecodedText.Should().BeNull();
    }
}
