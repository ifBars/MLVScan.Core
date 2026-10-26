# Synthetic detection coverage

Verified on 2026-10-26 against the local synthetic corpus. All 18 focused probes
and the legacy `MTEST.dll` produce evidence. Each was scanned twice without
executing its code; findings and dispositions matched across both scans.

| Sample | Disposition | Default / total findings |
|---|---|---|
| Base64CommandExecution | Suspicious | 2 / 4 |
| CharArrayCommandSplit | Suspicious | 2 / 2 |
| COMShellInvoke | Suspicious | 1 / 7 |
| CoordinatedRemoteDelivery | Suspicious | 3 / 6 |
| DynamicEmitAssembly | Suspicious | 1 / 3 |
| EmbeddedResourceStageLoad | Suspicious | 2 / 3 |
| HexCommandExecution | Suspicious | 2 / 5 |
| HiddenWindowCmdLauncher | Suspicious | 1 / 1 |
| HttpWebRequestExfil | Clean | 0 / 1 |
| MTEST (legacy) | Suspicious | 5 / 7 |
| PInvokeWinExec | Suspicious | 1 / 1 |
| ReflectionProcessInvoke | Suspicious | 2 / 3 |
| RegistryRunKeyPersistence | Suspicious | 2 / 2 |
| ReversedStringCommand | Suspicious | 2 / 2 |
| StartupFolderPersistence | Clean | 0 / 1 |
| UnityWebRequestPostExfil | Clean | 0 / 1 |
| WmiProcessLauncher | Suspicious | 1 / 1 |
| XorBlobAssemblyLoad | Suspicious | 1 / 5 |
| ZipArchiveStageDrop | Clean | 0 / 1 |

All Suspicious results recommend blocking. All synthetic scans completed.
The four Clean fixtures send constant test reports or write/extract text files;
their evidence remains Advanced. Separate portable tests exercise sensitive file
contents reaching network sinks, executable/script Startup writes, and executable
archive staging. Those stronger variants receive Suspicious dispositions.

## Implementation and test surfaces

Coverage extends existing process-start, obfuscated-execution, exfiltration,
persistence and archive rules, shared IL/value resolution, and disposition
correlation. No new rule IDs, threat families or public schema fields were added.

- `Unit/Rules/ExecutionEvasionTests.cs` covers reflected/emitted process targets,
  reconstructed targets, WMI class/member identity, XOR array identity and paths.
- `Unit/Rules/ExfiltrationEvasionTests.cs` checks sensitive source-to-send linkage
  and unrelated-read negative cases.
- `Unit/Rules/EmbeddedArchiveExtractionTests.cs` checks archive entry types and
  staging destinations, including executable entries after 300 text entries.
- `Integration/SyntheticCoverageTests.cs` scans the optional local corpus and
  checks repeat-scan determinism, disposition, retained evidence and family absence.

The optional corpus is discovered in a workspace-level `SYNTHETIC_SAMPLES/`
directory; the focused fixtures originate in the sibling `MLVSyntheticSamples/`
source folder. Neither sample binaries nor raw scan artifacts are included here.
The portable Cecil tests run without those local files; the optional corpus cases
skip when the files are unavailable.

## Validation

The functional suite completed with **1,823 passed, 18 skipped, 0 failed**:

```powershell
dotnet test MLVScan.Core.sln -c Release --no-restore --filter "Category!=Performance"
```

The three earlier aggregate failures are now handled by real coverage of the
disguised UniverseLib downloader and exact test-only backlog profiles. See
[FALSE_POSITIVE_BACKLOG.md](FALSE_POSITIVE_BACKLOG.md) for current limitations and
follow-up work. Production detection is unchanged by those backlog expectations.
