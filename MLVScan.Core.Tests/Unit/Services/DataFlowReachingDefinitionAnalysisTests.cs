using FluentAssertions;
using MLVScan.Models.DataFlow;
using MLVScan.Services.DataFlow;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DataFlowReachingDefinitionAnalysisTests
{
    [Fact]
    public void RepeatedLocalStoreQuery_ReusesControlFlowGraphAndCachedResult()
    {
        using var module = ModuleDefinition.CreateModule("ReachingDefinitionCacheTest", ModuleKind.Dll);
        var method = CreateMethod(module, "Cache");
        var local = new VariableDefinition(module.TypeSystem.Int32);
        method.Body.Variables.Add(local);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Stloc, local);
        for (var index = 0; index < 32; index++)
        {
            il.Emit(OpCodes.Nop);
        }

        il.Emit(OpCodes.Ldloc, local);
        var consumerIndex = method.Body.Instructions.Count - 1;
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var analysis = new DataFlowReachingDefinitionAnalysis(method.Body.Instructions);

        analysis.TryGetReachingLocalStoreIndexes(consumerIndex, local.Index, out var first).Should().BeTrue();
        var workAfterFirstQuery = analysis.WorkUnitsConsumed;
        analysis.TryGetReachingLocalStoreIndexes(consumerIndex, local.Index, out var second).Should().BeTrue();

        first.Should().ContainSingle().Which.Should().Be(1);
        second.Should().BeEquivalentTo(first);
        analysis.ControlFlowGraphBuildCount.Should().Be(1);
        analysis.WorkUnitsConsumed.Should().Be(workAfterFirstQuery,
            "an identical reaching-definition query should be served from the per-method cache");
    }

    [Fact]
    public void DistinctAdversarialQueries_CannotExceedLinearPerMethodWorkBudget()
    {
        using var module = ModuleDefinition.CreateModule("ReachingDefinitionBudgetTest", ModuleKind.Dll);
        var method = CreateMethod(module, "Stress");
        var local = new VariableDefinition(module.TypeSystem.Int32);
        method.Body.Variables.Add(local);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Stloc, local);

        var consumerIndexes = new List<int>();
        for (var index = 0; index < 1_000; index++)
        {
            il.Emit(OpCodes.Ldloc, local);
            consumerIndexes.Add(method.Body.Instructions.Count - 1);
            il.Emit(OpCodes.Pop);
        }

        il.Emit(OpCodes.Ret);
        var analysis = new DataFlowReachingDefinitionAnalysis(method.Body.Instructions);

        var completedAllQueries = true;
        foreach (var consumerIndex in consumerIndexes)
        {
            if (!analysis.TryGetReachingLocalStoreIndexes(consumerIndex, local.Index, out _))
            {
                completedAllQueries = false;
                break;
            }
        }

        completedAllQueries.Should().BeFalse();
        analysis.IsComplete.Should().BeFalse();
        analysis.ControlFlowGraphBuildCount.Should().Be(1);
        analysis.WorkBudget.Should().Be(Math.Max(16_384, method.Body.Instructions.Count * 256),
            "the cumulative budget must remain linear in the method instruction count");
        analysis.WorkUnitsConsumed.Should().Be(analysis.WorkBudget);

        analysis.TryGetReachingLocalStoreIndexes(
                consumerIndexes[0],
                local.Index,
                out var definitionsAfterExhaustion)
            .Should().BeFalse("no cached answer should be served after the method budget is exhausted");
        definitionsAfterExhaustion.Should().BeEmpty();
    }

    [Fact]
    public void TryGetReachingInstructionIndexes_WithNullPredicate_ThrowsArgumentNullException()
    {
        using var module = ModuleDefinition.CreateModule("ReachingDefinitionNullPredicateTest", ModuleKind.Dll);
        var method = CreateMethod(module, "NullPredicate");
        method.Body.GetILProcessor().Emit(OpCodes.Ret);
        var analysis = new DataFlowReachingDefinitionAnalysis(method.Body.Instructions);

        var act = () => analysis.TryGetReachingInstructionIndexes(0, null!, out _);

        act.Should().Throw<ArgumentNullException>().WithParameterName("isDefinition");
    }

    [Fact]
    public void SeparateMethodAnalysisHelpers_DoNotShareBudgetState()
    {
        using var module = ModuleDefinition.CreateModule("ReachingDefinitionIsolationTest", ModuleKind.Dll);
        var method = CreateMethod(module, "Isolation");
        var local = new VariableDefinition(module.TypeSystem.Int32);
        method.Body.Variables.Add(local);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Stloc, local);

        var consumerIndexes = new List<int>();
        for (var index = 0; index < 1_000; index++)
        {
            il.Emit(OpCodes.Ldloc, local);
            consumerIndexes.Add(method.Body.Instructions.Count - 1);
            il.Emit(OpCodes.Pop);
        }

        il.Emit(OpCodes.Ret);
        var firstHelper = new DataFlowInstructionHelper(method.Body.Instructions);
        var firstAnalysis = firstHelper.GetReachingDefinitionAnalysis(method.Body.Instructions);

        foreach (var consumerIndex in consumerIndexes)
        {
            if (firstHelper.GetReachingLocalStoreIndexes(
                    method.Body.Instructions,
                    consumerIndex,
                    local.Index).Count == 0)
            {
                break;
            }
        }

        firstAnalysis.IsComplete.Should().BeFalse();

        var secondHelper = new DataFlowInstructionHelper(method.Body.Instructions);
        var secondAnalysis = secondHelper.GetReachingDefinitionAnalysis(method.Body.Instructions);
        var definitions = secondHelper.GetReachingLocalStoreIndexes(
            method.Body.Instructions,
            consumerIndexes[0],
            local.Index);

        secondAnalysis.IsComplete.Should().BeTrue();
        secondAnalysis.WorkUnitsConsumed.Should().BeGreaterThan(0);
        definitions.Should().ContainSingle().Which.Should().Be(1);
    }

    [Fact]
    public void StoreMethodAnalysis_WhenCompleteResultReplacesIncomplete_ClearsIncompleteMarker()
    {
        var state = new DataFlowAnalysisState();
        const string methodKey = "Test.Type::Method()";

        state.StoreMethodAnalysis(new DataFlowMethodAnalysisResult
        {
            MethodKey = methodKey,
            AnalysisComplete = false
        });
        state.IncompleteMethodKeys.Should().Contain(methodKey);

        state.StoreMethodAnalysis(new DataFlowMethodAnalysisResult
        {
            MethodKey = methodKey,
            AnalysisComplete = true
        });

        state.IncompleteMethodKeys.Should().NotContain(methodKey);
    }

    private static MethodDefinition CreateMethod(ModuleDefinition module, string name)
    {
        return new MethodDefinition(
            name,
            MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
    }
}
