# @mlvscan/wasm-core

WebAssembly core for MLVScan – scanning Unity mods in the browser.

## Local development (before publishing)

1. Build the .NET WASM app from the `MLVScan.WASM` project folder:
   ```bash
   dotnet publish -c Release
   ```
2. Copy the built `_framework` into this package’s `dist` so the package is self-contained:
   ```bash
   npm run copy:framework
   ```
3. Consuming projects (e.g. MLVScan.Web.v2) can depend on this package via `"file:../MLVScan.Core/MLVScan.WASM/npm"` and run `npm install`. The web app will serve and copy `_framework` from `node_modules/@mlvscan/wasm-core/dist/_framework`.

## Publish

Run `tsc` and `copy:framework` (after building the .NET project), then `npm pack` or publish to a registry.
