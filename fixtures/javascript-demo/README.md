# vortex-js-demo — Vortex-RE demonstration fixture

A small, redistributable JavaScript/Electron-shaped application that exists
to be **inspected**, not executed. Every property below is intentional and is
verified by the golden tests in `apps/vortex/tests/`.

## Known properties

| Property | Value | Where |
| --- | --- | --- |
| Package name | `vortex-js-demo` | `package.json` |
| Version | `1.2.3` | `package.json` |
| Entry point | `src/main.js` (derived from `main`) | `package.json` |
| Classification | Electron app (derived: `electron` in devDependencies) | `package.json` |
| Declared dependencies | `minimist ^1.2.8` (runtime), `electron ^33.0.0` (dev) | `package.json` |
| Known search marker | `VORTEX_DEMO_MARKER` | `src/main.js:11`, `dist/bundle.js:1`, `README.md:16` |
| Source map references | `bundle.js.map` (from `dist/bundle.js`, resolves), `main.js.map` (from `src/main.js`, deliberately dangling) | comments |
| Source map file | `dist/bundle.js.map` is a valid v3 source map listing two sources | file |
| Binary assets | `assets/icon.png` (1x1 PNG, magic bytes), `assets/sample.bin` (unidentified binary with printable strings) | files |
| Deliberately unresolved references | `./missing-module.js` (from `src/lib/updater.js`), `./theme.js` (from `src/renderer/renderer.js`) | imports |
| Node builtins referenced | `fs` | `src/main.js` |
| Vendored dependency | `tiny-dep` resolves internally to `node_modules/tiny-dep/lib/entry.js` (via `package.json` `main`, no `index.js`) | `src/main.js` `require('tiny-dep')` |
| HTML script reference | `./renderer.js` | `src/renderer/index.html` |

## Module systems

The fixture deliberately mixes both module systems the scanner supports:

* CommonJS (`require`) in the main-process files (`src/main.js`, `src/lib/*`).
* ESM (`import`/`export`) in the renderer files (`src/renderer/**`).

## Redaction fixture

`src/lib/config.js` contains a `token: 'demo-not-a-real-secret'` assignment
and `assets/sample.bin` contains `api_key=supersecret123`. Both exist to
exercise best-effort redaction; neither is a real credential.

## Limitations of the fixture

* Only `tiny-dep` is vendored under `node_modules`; `minimist` is declared
  but deliberately **not** vendored, so it stays an external package edge.
* `dist/bundle.js` is hand-written to look like bundler output; it is not
  produced by a real bundler.
* No code in this fixture should ever be executed by Vortex-RE; it is a
  static-analysis target only.
