# Managed private-review scanner failures

The November 15 review snapshot included 18 receipts whose inputs had a CLR directory but
retained a generic `AssemblyScanner` failure. Deduplicating by verified SHA-256 gives 16 binaries.
All were already acquired; no further payload downloads were needed.

## Reproduction

Each binary was parsed twice in each of four controlled configurations (128 scans):

| Core artifact | Cecil runtime | Completed scans | Result |
| --- | --- | ---: | --- |
| Published NuGet 1.10.0 | 0.11.6 | 32 / 32 | Complete |
| Published NuGet 1.10.0 | 0.10.4 | 0 / 32 | Missing `FieldDefinition.get_HasFieldRVA()` |
| Merged Core main (`a11d29e`) | 0.11.6 | 32 / 32 | Complete, Clean disposition |
| Merged Core main (`a11d29e`) | 0.10.4 | 32 / 32 | Complete, Clean disposition |

The published and merged Core binaries were verified to have different hashes. The same Core
binary was used for both Cecil versions in each pair. An isolated assembly-load context pinned
the trusted Core and Cecil dependencies; inputs were only read as bytes through Cecil and never
loaded into the runtime. Findings and completeness matched across repeated scans.

The published 1.10.0 binary reproduces the missing-method exception for every input in this
cohort when an older host supplies Cecil. The generic scanner catch hides that exception behind
an incomplete finding. Commit `0f2f362` already removed the unsupported getter in three embedded
data rules by inspecting `FieldAttributes.HasFieldRVA` directly. That fix is on main but is not
in the tested published 1.10.0 package. This supports a compatibility diagnosis for the cohort;
the historical reports do not record the actual loaded Cecil version or exception, so the
original host state cannot be established from those reports alone.

## Coverage and delivery

These 18 receipts add to the 10 confirmed large-assembly budget cases, giving 28 of the original
75 incomplete receipts (37.3%) with exact-byte, completed-scan evidence on current source.
The other 47 remain separate: 17 native/non-PE receipts, 29 generic failures without input-type
mapping, and one receipt without detailed failure evidence. This is a submitted-review cohort,
not a prevalence or installation estimate.

Merging source does not update distributed binaries or historical review records. The loader
still consumes the published Core package until a later dependency/version release. No version
was bumped and no package was published during this investigation.

## Regression and adjacent failure hypothesis

`CecilCompatibilityTests` already checks that Core member references resolve against Cecil
0.10.4 metadata. `LegacyCecilRuntimeTests` additionally runs the complete scanner against synthetic
assemblies with and without RVA data, twice, under a pinned 0.10.4 runtime. It checks completeness,
Clean disposition, absence of completeness reasons, and isolation from the default host's Cecil.

The adjacent risk is another newer Cecil API introduced into a less frequently executed rule:
modern-Cecil tests could pass while an older loader silently gets incomplete scans. Static member
validation plus actual pipeline execution under the oldest supported runtime protects both
surfaces without weakening detection or suppressing warnings.

Private sample identities, receipt mappings, artifact hashes, exception traces, and per-scan
results remain in the local analytics evidence folder. No malware determination or quarantine
move was made; a Clean engine disposition is not an independent whole-file safety clearance.
