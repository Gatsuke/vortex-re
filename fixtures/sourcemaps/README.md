# Source map fixtures (Phase Four)

Regenerate with `python3 gen.py`. The generator is deterministic: it
always writes byte-identical files, so the committed output is the source
of truth for tests.

`gen.py` hand-designs a mapping table, encodes it with its own VLQ
encoder, and asserts the encoded `mappings` string equals the hand-written
literal `AAAA,gBCCAA,c;AACIC,oBDDJ`. The Rust golden test
(`apps/vortex/tests/sourcemaps.rs`) pins the decoded results: 4 mapped
segments + 1 column-only over 2 generated lines, 2 named sources + 1
null, `sourcesContent` present for source 0 only. If the generator and
the parser ever disagree, the test fails loudly.

## Files

| File | Purpose |
|------|---------|
| `app.js` | A 3-line "bundle" whose third line is the `sourceMappingURL` comment; lines 1-2 carry the mapped code |
| `app.js.map` | A rich, valid v3 map for `app.js` (2 sources on disk + 1 null source, 2 names, embedded content for source 0) |
| `src/orig/main.js` | Source 0 of the map, present on disk so `maps_to_source` resolves |
| `src/orig/util.js` | Source 1 of the map, present on disk |
| `broken.map` | A map whose second segment points at an out-of-range source index: parsing degrades with an exact count |
| `garbage.map` | Not JSON at all: the honest failure path (warning + limitation, no fabricated findings) |
| `wrongversion.map` | `version: 2`: parsed structurally with an explicit caution note |

## Safety notes

All files exist to be inspected, never executed; the `sourcesContent`
strings are inert text. No fixture contains secrets.
