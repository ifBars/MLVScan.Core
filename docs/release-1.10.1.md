# MLVScan.Core 1.10.1

- Fixes incomplete scans in hosts using Mono.Cecil 0.10.4. Embedded-data rules now use APIs supported by that runtime.
- Improves completion of large managed assemblies by spending cross-method analysis budgets on candidate data flows instead of unrelated calls.
- Inspects all eligible static RVA initializers while retaining a fixed set of detection markers, so unrelated data cannot exhaust the retained-string budget before later evidence.
- Refines data-flow classification for literal assembly-name lookups and file timestamp getters while preserving dynamic, path-based, and byte-array load coverage.
- Adds bounded diagnostic categories for incomplete scans without exposing exception messages or paths.

Analysis safeguards remain active: inputs that exhaust a remaining work limit still require review. Large assemblies can still require substantial memory and scan time. The result schema remains at 1.4.0.
