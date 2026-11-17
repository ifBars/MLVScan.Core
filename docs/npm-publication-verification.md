# npm accepted uploads and public availability

An accepted upload is not proof of a downloadable release. For `@mlvscan/wasm-core@1.10.1`,
Bun reported a successful publish, public version/tarball reads returned 404, and one retry
returned `409 Cannot publish over previously staged version`. The authenticated `ifbars`
owner's `/-/stage` query returned HTTP 200 with zero records, matching the empty account UI.

The conflict message alone does not establish that a maintainer must approve a package.
Check the authenticated staging queue before requesting 2FA approval. Similar inconsistent
registry state is reported in https://github.com/npm/cli/issues/9889.

`Inspect npm staged release` reads the publishing credential's identity and package-filtered
stage metadata. It never approves, rejects, republishes, or changes package permissions, and
does not print tokens, raw responses, or private download URLs.

`Verify npm release availability` uses the original publish workflow's `npm-package` artifact.
It reads that artifact's manifest and SHA-1, waits for matching public metadata, downloads the
public tarball, and checks its bytes against the artifact. It performs no registry writes.
Future `Publish to npm` runs use the same verification before reporting success.

An empty approval queue with a reserved version is a registry availability problem, not
evidence that the user missed an approval step. A verification timeout leaves the existing
upload intact and reports the remaining publication gap.
