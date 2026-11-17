# Large managed assembly completeness

The November 2026 private-review investigation reproduced bounded-analysis failures on two
large managed assemblies. These changes address those managed inputs; native executables,
archives, and malformed inputs are a separate intake problem.

## Changes

- Cross-method correlation charges its edge budget only for scanned callee bodies that meet
  the existing necessary conditions for a forward or return-value flow. External calls still
  receive method-level inspection. Calls between intermediary helpers still receive deep-chain
  inspection under the existing separate traversal budget.
- Static RVA collection inspects every eligible initializer and retains only the 23 fixed
  markers consumed by the reflection-stager heuristic. The existing 4,096-byte per-field
  eligibility limit is unchanged. Retained marker memory is constant; unrelated strings no
  longer exhaust a module-wide retained-string/byte budget before later evidence is reached.
- Work limits for actual candidate flows, deep traversal, methods, and retained chains remain
  finite. Exhaustion still produces an incomplete result and prevents a clean verdict.
- Previously pending diagnostics categorize incomplete reasons using a fixed vocabulary.
  Literal assembly display-name lookups and file timestamp getters no longer become unrelated
  byte-flow sinks; dynamic/path/byte-array loads remain covered.

## Static reproduction

Samples stayed inert under `TO_ANALYZE`; they were parsed by Cecil and never executed or loaded
as runtime assemblies. No new sample was moved to quarantine.

| Input | Bytes | Before | After |
| --- | ---: | --- | --- |
| MoonRocks.dll | 42,305,024 | Cross-method limit; manual review | Complete; no retained findings |
| Microsoft.Windows.SDK.NET.dll | 25,131,040 | Cross-method and RVA limits; manual review | Complete; same two ordinary rule findings retained; final disposition Clean |

The reviewed `BUTR.CrashReport.dll` corpus case also completes. Its FP-004 limitation
profile was retired and replaced with a hash-pinned ordinary regression test.

The SDK reproduction contains 237,654 methods (214,765 with bodies) and 2,316,458 inspected IL
instructions. Completion does not imply that every possible large or adversarial assembly will
finish within the remaining finite limits.

The private evaluation harness uses `AssemblyScanner` with default `ScanConfig`, then
`ScanResultMapper.ToDto` for the primary disposition. It records completeness, fixed rule counts,
normalized finding hashes, allocation totals, process peak working set, and the compile-gated
profile (`EnableMlvScanProfiling=true`). Host timestamps and random DTO finding IDs are excluded
from deterministic comparisons. Raw evidence remains outside Git.

Timings were collected alongside other validation jobs and are not a controlled speed benchmark.
The SDK scan still allocates about 10.2 GB cumulatively and peaks near 1.4 GB process working set;
reducing method-analysis allocation and latency remains a separate performance opportunity.

## Regression coverage

- Real candidate edges still exhaust a deliberately tiny edge budget and require review.
- A three-method embedded dropper retains its execution chain with 32 unrelated external calls
  preceding it, under a two-edge correlation budget.
- Both return-value and direct data-flow paths remain covered, including deep-scan retry modes.
- RVA markers after 256 unrelated strings or 256 KiB of padding remain visible, with fewer than
  32 retained marker strings. Oversized padding cannot hide a later eligible marker.
- Named-load branch entry, dynamic names, byte-array loads, path loads, and file setters protect
  the boundary of the pending false-positive refinements.
- Generated schema verification passes; no shared result-contract change is required.

Final corpus and repeat-scan results are recorded in the pull request validation notes.
