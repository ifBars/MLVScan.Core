using FluentAssertions;
using MLVScan.Services.Helpers;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.Helpers;

public class InstructionHelperTests
{
    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_ReturnsValue()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ldc_I4, 42),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 2);

        result.Should().Be(42);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_S_ReturnsValue()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)10),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 2);

        result.Should().Be(10);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_0_Returns0()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 2);

        result.Should().Be(0);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_1_Returns1()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(1);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_2_Returns2()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_2),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(2);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_3_Returns3()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_3),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(3);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_4_Returns4()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_4),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(4);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_5_Returns5()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_5),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(5);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_6_Returns6()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_6),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(6);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_7_Returns7()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_7),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(7);
    }

    [Fact]
    public void ExtractFolderPathArgument_Ldc_I4_8_Returns8()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_8),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 1);

        result.Should().Be(8);
    }

    [Fact]
    public void ExtractFolderPathArgument_NoIntegerConstant_ReturnsNull()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ldstr, "test"),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 2);

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractFolderPathArgument_EmptyInstructions_ReturnsNull()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 0);

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractFolderPathArgument_SearchesWithin5InstructionsBack()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, 99),  // Index 0 - Should NOT be found (6 instructions back)
            Instruction.Create(OpCodes.Nop),          // Index 1
            Instruction.Create(OpCodes.Ldc_I4, 42),  // Index 2 - Should be found (4 instructions back)
            Instruction.Create(OpCodes.Nop),          // Index 3
            Instruction.Create(OpCodes.Nop),          // Index 4
            Instruction.Create(OpCodes.Nop),          // Index 5
            Instruction.Create(OpCodes.Nop)  // Index 6 - Current
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 6);

        // Should find 42 at index 2 (4 instructions back), not 99 at index 0 (6 instructions back)
        result.Should().Be(42);
    }

    [Fact]
    public void ExtractFolderPathArgument_CurrentIndexAtStart_HandlesGracefully()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 0);

        result.Should().BeNull(); // No instructions before index 0
    }

    [Fact]
    public void ExtractFolderPathArgument_FindsFirstMatch()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, 10),
            Instruction.Create(OpCodes.Ldc_I4, 20),
            Instruction.Create(OpCodes.Nop)
        };

        var result = InstructionHelper.ExtractFolderPathArgument(instructions, 2);

        // Should find the first match (10 at index 0)
        result.Should().Be(10);
    }
}
