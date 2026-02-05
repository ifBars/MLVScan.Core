using FluentAssertions;
using MLVScan.Services;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class CodeSnippetBuilderTests
{
    [Fact]
    public void BuildSnippet_WithMiddleIndex_IncludesContextAndPointer()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ldstr, "payload"),
            Instruction.Create(OpCodes.Ret)
        };

        var builder = new CodeSnippetBuilder();

        var snippet = builder.BuildSnippet(instructions, 1, 1);

        snippet.Should().Contain(">>> ");
        snippet.Should().Contain("ldstr \"payload\"");
        snippet.Should().Contain("nop");
        snippet.Should().Contain("ret");
    }

    [Fact]
    public void BuildSnippet_WithIndexAtStart_ClampsRangeToBeginning()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ret)
        };

        var builder = new CodeSnippetBuilder();

        var snippet = builder.BuildSnippet(instructions, 0, 5);

        snippet.Should().Contain(">>> ");
        snippet.Should().Contain("nop");
        snippet.Should().Contain("ret");
    }

    [Fact]
    public void BuildSnippet_DoesNotLeaveTrailingNewLine()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop)
        };

        var builder = new CodeSnippetBuilder();

        var snippet = builder.BuildSnippet(instructions, 0, 0);

        snippet.Should().EndWith("nop");
        snippet.Should().NotEndWith("\n");
        snippet.Should().NotEndWith("\r");
    }
}
