/**
 * Copies the full _framework from the .NET WASM AppBundle into npm/dist/_framework.
 * Run from repo root after building the WASM project, e.g.:
 *   cd MLVScan.Core/MLVScan.WASM && dotnet publish -c Release
 *   cd npm && node scripts/copy-framework.cjs
 * Or from npm folder: npm run copy:framework
 */
const fs = require('node:fs')
const path = require('node:path')

const npmDir = path.resolve(__dirname, '..')
const appBundleFramework = path.join(npmDir, '..', 'bin', 'Release', 'net8.0', 'browser-wasm', 'AppBundle', '_framework')
const destFramework = path.join(npmDir, 'dist', '_framework')

if (!fs.existsSync(appBundleFramework)) {
  console.warn(
    `[@mlvscan/wasm-core] AppBundle _framework not found at ${appBundleFramework}. ` +
    'Build the WASM project first: dotnet publish -c Release (from MLVScan.WASM folder).'
  )
  process.exit(0)
}

if (!fs.existsSync(path.join(npmDir, 'dist'))) {
  fs.mkdirSync(path.join(npmDir, 'dist'), { recursive: true })
}

function copyRecursive(src, dest) {
  const stat = fs.statSync(src)
  if (stat.isDirectory()) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true })
    for (const name of fs.readdirSync(src)) {
      copyRecursive(path.join(src, name), path.join(dest, name))
    }
  } else {
    fs.copyFileSync(src, dest)
  }
}

copyRecursive(appBundleFramework, destFramework)
console.log(`[@mlvscan/wasm-core] Copied _framework to dist/_framework`)
