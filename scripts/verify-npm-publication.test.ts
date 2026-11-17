import { describe, expect, test } from 'bun:test'
import { inspectPublication } from './verify-npm-publication'

const bytes = new TextEncoder().encode('verified release artifact')
const hash = new Bun.CryptoHasher('sha1').update(bytes).digest('hex')
const metadata = { version: '1.10.1', dist: { shasum: hash, tarball: 'https://registry.npmjs.org/example/-/example-1.10.1.tgz' } }

describe('public npm release verification', () => {
  test('an accepted upload without public metadata stays pending', async () => {
    expect(await inspectPublication('example', '1.10.1', hash, async () => new Response('', { status: 404 }))).toBe('pending')
  })
  test('transient registry failures stay pending', async () => {
    expect(await inspectPublication('example', '1.10.1', hash, async () => { throw new Error('offline') })).toBe('pending')
  })
  test('metadata alone does not establish downloadable publication', async () => {
    expect(await inspectPublication('example', '1.10.1', hash, async url => url.endsWith('.tgz')
      ? new Response('', { status: 404 }) : Response.json(metadata))).toBe('pending')
  })
  test('metadata and actual downloaded bytes establish publication', async () => {
    expect(await inspectPublication('example', '1.10.1', hash, async url => url.endsWith('.tgz')
      ? new Response(bytes) : Response.json(metadata))).toBe('published')
  })
  test('conflicting metadata is rejected', async () => {
    await expect(inspectPublication('example', '1.10.1', 'different', async () => Response.json(metadata))).rejects.toThrow('metadata differs')
  })
  test('conflicting tarball bytes are rejected', async () => {
    await expect(inspectPublication('example', '1.10.1', hash, async url => url.endsWith('.tgz')
      ? new Response('changed') : Response.json(metadata))).rejects.toThrow('tarball differs')
  })
})
