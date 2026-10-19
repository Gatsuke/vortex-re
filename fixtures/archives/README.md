# Archive fixtures

## `demo.asar` (+ `demo.asar.unpacked/`)

An Electron asar archive produced by the **official `asar` tool (v3.2.0)**
— not by our own writer — specifically so the parser is validated against
the real format rather than a reimplementation of our assumptions. It
contains five files:

| Path | Notes |
| --- | --- |
| `package.json` | packed |
| `README.md` | packed |
| `src/app/main.js` | packed |
| `src/lib/util.js` | packed |
| `asset.bin` | unpacked (`--unpack "*.bin"`), lives in `demo.asar.unpacked/`, header carries an integrity block |

Regenerate with:

```sh
npm install asar
asar pack <dir-with-those-files> demo.asar --unpack "*.bin"
```

Zip-family fixtures (normal archives, APKs, bombs, traversal/symlink
members) are generated at test time by the Rust test suite itself using
the `zip` crate, so adversarial cases stay reproducible from source
alone.
