// Read-only diagnostics. Never print credentials, raw response bodies, or private tarball URLs.
const registry = 'https://registry.npmjs.org'
const packageName = '@mlvscan/wasm-core'
const token = process.env.NPM_TOKEN
if (!token) throw new Error('NPM_TOKEN is not configured')

async function read(path: string) {
  const response = await fetch(new URL(path, registry), {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Cache-Control': 'no-cache' },
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  })
  console.log(JSON.stringify({ endpoint: path.split('?')[0], status: response.status }))
  if (!response.ok) return null
  return response.json() as Promise<Record<string, any>>
}

const identity = await read('/-/whoami')
console.log(JSON.stringify({ publisher: identity?.username ?? null }))

let matched = 0
for (let page = 0; page < 10; page++) {
  const query = new URLSearchParams({ package: packageName, page: String(page), perPage: '100' })
  const result = await read(`/-/stage?${query}`)
  if (!result) break
  const items = Array.isArray(result.items) ? result.items : []
  console.log(JSON.stringify({ page, total: result.total ?? null, returned: items.length }))
  for (const item of items) {
    if (item.packageName !== packageName) continue
    matched++
    const metadata = Object.fromEntries(
      ['id', 'packageName', 'version', 'status', 'tag', 'createdAt', 'actor', 'actorType', 'shasum']
        .filter(key => ['string', 'number', 'boolean'].includes(typeof item[key]))
        .map(key => [key, item[key]]),
    )
    console.log(JSON.stringify({ stagedPackage: metadata }))
  }
  if (items.length < 100 || (page + 1) * 100 >= Number(result.total)) break
}
console.log(JSON.stringify({ packageName, stagedVersionsFound: matched }))
