# False-positive and analysis-completeness backlog

These are known limitations of the default scan, confirmed against the local corpus
on 2026-10-26. They are test expectations, not production allowlists or fixes.
The executable expectations live in `TestUtilities/FalsePositiveBacklog.cs`.

| ID | Corpus sample | Expected current result | Follow-up work |
|---|---|---|---|
| FP-001 | `BackpackInventoryQoL.dll` | Clean; one Advanced High `ProcessStartRule` finding | Resolve the framework-provided Mods directory and distinguish opening a folder through the OS shell from concealed executable launch. Avoid broad `UseShellExecute` suppression. |
| FP-002 | `Polyfill.Boot.dll` | Clean; one Advanced High `AssemblyDynamicLoadRule` finding | Distinguish local compatibility assembly probing in `ReflectionFallback.BySimpleName` from staged payload loading. Preserve download/decoded-byte loader coverage. |
| FP-003 | `Polyfill.dll` | Clean; two Advanced High dynamic-load findings and three Advanced High reflection findings | Model diagnostic `ConsoleCommands.Probe` / `ProbeMember` operations without masking execution of untrusted stages. |
| FP-004 | `Nexus Bannerlord/ButterLib-2.12.0/Modules/Bannerlord.ButterLib/bin/Win64_Shipping_Client/BUTR.CrashReport.dll` | ManualReviewRequired; Partial analysis; blocking recommended; one cross-method work-limit reason | Investigate bounded cross-method data-flow work. Measure any budget/algorithm change; do not silently grant Clean to incomplete analysis or just raise limits globally. |

All four entries require the exact reviewed SHA-256, exact disposition, no threat
family matches, and the documented High finding identities (rule, severity and
location). FP-004 also checks its specific completeness reason. Unexpected
High/Critical findings, changed bytes, changed verdicts or additional completeness reasons fail
the tests. An improvement also fails the pinned profile so the entry can be
deliberately updated or removed rather than becoming a permanent exemption.

The aggregate corpus checks remain strict for all other inputs. The separate
`KnownLimitation` test category makes the backlog visible and runnable:

```powershell
dotnet test MLVScan.Core.Tests/MLVScan.Core.Tests.csproj --filter "Category=KnownLimitation"
```

When resolving an item, first reproduce its desired behavior with focused tests,
then validate the real sample and the false-positive/quarantine corpus. Remove
or narrow the matching backlog profile and retain an ordinary regression test.
The older explicitly skipped cases in `FalsePositiveScanTests.cs` are separate
existing work; this list records the four profiles behind the recent aggregate
failures.

## Quarantine tracking correction

`UniverseLib.Mono.dll` was missing from the tracked top-level test manifest. Its
SHA-256 is `2c754bcd9532ea2d2b75a37d456cb36e97ae341eb388dd29805a081174de83cb`.
Static decompilation of `ByteArrayTypeInfoMembership.Awake` shows a hidden
`cmd.exe` command that downloads an EXE with `curl` into TEMP and starts it.
It belongs in quarantine despite its library-like filename. A dedicated test now
requires its Critical staged-execution evidence, Suspicious disposition, complete
analysis and blocking recommendation. There is no confirmed family match yet;
the test records that limitation without inventing an attribution.

No sample was executed and no referenced payload was fetched.
