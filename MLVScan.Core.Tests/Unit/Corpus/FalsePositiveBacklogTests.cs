using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models.Dto;
using Xunit;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Unit.Corpus;

public class FalsePositiveBacklogTests
{
    [Fact]
    public void AssertExpectedProfile_RecordedProfilesPass()
    {
        foreach (var entry in FalsePositiveBacklog.Entries.Values)
        {
            FalsePositiveBacklog.AssertExpectedProfile(CreateResult(entry), entry);
        }
    }

    [Theory]
    [InlineData("changed-bytes")]
    [InlineData("blocking-verdict")]
    [InlineData("new-family")]
    [InlineData("new-critical-finding")]
    [InlineData("changed-location")]
    [InlineData("removed-noise")]
    public void AssertExpectedProfile_DriftRequiresReview(string change)
    {
        var entry = FalsePositiveBacklog.Entries["BackpackInventoryQoL.dll"];
        var result = CreateResult(entry);
        switch (change)
        {
            case "changed-bytes":
                result.Input.Sha256Hash = new string('0', 64);
                break;
            case "blocking-verdict":
                result.Disposition!.Classification = "Suspicious";
                break;
            case "new-family":
                result.ThreatFamilies = [new ThreatFamilyDto { FamilyId = "unexpected-family" }];
                break;
            case "new-critical-finding":
                result.Findings.Add(new FindingDto { RuleId = "ProcessStartRule", Severity = "Critical", Location = "Other.Run:1" });
                break;
            case "changed-location":
                result.Findings[0].Location = "Other.Run:1";
                break;
            case "removed-noise":
                result.Findings.Clear();
                break;
        }

        Action validate = () => FalsePositiveBacklog.AssertExpectedProfile(result, entry);
        validate.Should().Throw<XunitException>();
    }

    [Fact]
    public void AssertExpectedProfile_DifferentCompletenessReasonRequiresReview()
    {
        var entry = FalsePositiveBacklog.Entries.Values.Single(entry => entry.Disposition == "ManualReviewRequired");
        var result = CreateResult(entry);
        result.AnalysisCompleteness.Reasons[0].RuleId = "MethodScanWarning";

        Action validate = () => FalsePositiveBacklog.AssertExpectedProfile(result, entry);
        validate.Should().Throw<XunitException>();
    }

    [Fact]
    public void AssertExpectedProfile_SuspiciousEntryPinsBlockingAndVisibility()
    {
        var entry = FalsePositiveBacklog.Entries.Values.Single(entry => entry.Disposition == "Suspicious");
        var blocking = CreateResult(entry);
        blocking.Disposition!.BlockingRecommended = true;
        var hidden = CreateResult(entry);
        hidden.Findings[0].Visibility = "Advanced";

        Action validateBlocking = () => FalsePositiveBacklog.AssertExpectedProfile(blocking, entry);
        Action validateHidden = () => FalsePositiveBacklog.AssertExpectedProfile(hidden, entry);
        validateBlocking.Should().Throw<XunitException>();
        validateHidden.Should().Throw<XunitException>();
    }

    private static ScanResultDto CreateResult(FalsePositiveBacklog.Entry entry)
    {
        bool suspicious = entry.Disposition == "Suspicious";
        bool complete = entry.Disposition == "Clean" || suspicious;
        return new ScanResultDto
        {
            Input = new ScanInputDto { Sha256Hash = entry.Sha256.ToLowerInvariant() },
            Disposition = new ThreatDispositionDto
            {
                Classification = entry.Disposition,
                BlockingRecommended = suspicious ? entry.BlockingRecommended ?? true : !complete
            },
            Findings = entry.HighFindings.Select(finding => new FindingDto
            {
                RuleId = finding.RuleId,
                Severity = finding.Severity,
                Location = finding.Location,
                Visibility = suspicious ? "Default" : "Advanced"
            }).ToList(),
            AnalysisCompleteness = new AnalysisCompletenessDto
            {
                IsComplete = complete,
                ReviewRecommended = !complete,
                Status = complete ? "Complete" : "Partial",
                Reasons = complete ? [] : [new AnalysisCompletenessReasonDto
                {
                    ReasonId = "scanner-incomplete", RuleId = "DataFlowScanWarning",
                    Location = "Cross-method data flow analysis", Summary = "Cross-method analysis reached its bounded work limit."
                }]
            }
        };
    }
}
