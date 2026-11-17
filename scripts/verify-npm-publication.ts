const registry = 'https://registry.npmjs.org'
type Request = (url: string) => Promise<Response>

/** Public metadata and tarball bytes must both agree with the uploaded artifact. */
export async function inspectPublication(
  packageName: string, version: string, expectedSha1: string,
  request: Request = url => fetch(url, { redirect: 'error', signal: AbortSignal.timeout(30_000) }),
): Promise<'pending' | 'published'> {
  async function read(url: string) {
    try { return await request(url) } catch { return null }
  }
  const response = await read(`${registry}/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}`)
  if (!response?.ok) return 'pending'
  const metadata = await response.json() as { version: string, dist: { shasum: string, tarball: string } }
  if (metadata.version !== version || metadata.dist?.shasum !== expectedSha1)
    throw new Error('Published npm metadata differs from the release artifact; refusing to accept it')
  const tarballUrl = new URL(metadata.dist.tarball)
  if (tarballUrl.origin !== registry) throw new Error('Unexpected npm tarball origin')
  const tarball = await read(tarballUrl.href)
  if (!tarball?.ok) return 'pending'
  const actual = new Bun.CryptoHasher('sha1').update(await tarball.arrayBuffer()).digest('hex')
  if (actual !== expectedSha1) throw new Error('Downloaded npm tarball differs from the release artifact')
  return 'published'
}

if (import.meta.main) {
  const tarball = Bun.argv[2]
  if (!tarball) throw new Error('Provide the release tarball path')
  const manifest = await Bun.file('MLVScan.WASM/npm/package.json').json()
  const expectedSha1 = new Bun.CryptoHasher('sha1').update(await Bun.file(tarball).arrayBuffer()).digest('hex')
  const timeoutSeconds = Number(process.env.NPM_PUBLICATION_TIMEOUT_SECONDS ?? 3600)
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 3600)
    throw new Error('Publication verification timeout must be between 1 and 3600 seconds')
  const started = Date.now()
  let attempt = 0
  while (true) {
    attempt++
    const status = await inspectPublication(manifest.name, manifest.version, expectedSha1)
    if (status === 'published') {
      console.log(`Verified public npm metadata and downloaded tarball: ${manifest.name}@${manifest.version}; SHA-1 ${expectedSha1}`)
      break
    }
    if (Date.now() - started >= timeoutSeconds * 1000)
      throw new Error('npm accepted the release artifact but it is still not publicly downloadable; no automatic approval or republish was attempted')
    if (attempt === 1 || attempt % 4 === 0)
      console.log(`npm version is not publicly downloadable yet (${Math.round((Date.now() - started) / 1000)}s); waiting without republishing`)
    await Bun.sleep(Math.min(30_000, timeoutSeconds * 1000 - (Date.now() - started)))
  }
}
