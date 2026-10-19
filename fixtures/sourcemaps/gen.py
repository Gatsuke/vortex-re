#!/usr/bin/env python3
"""Generate the fixtures/sourcemaps corpus deterministically.

The mapping table below is hand-designed and cross-checked: gen.py encodes
it with its own VLQ encoder, and apps/vortex/tests/sourcemaps.rs pins the
DECODED results (stats, samples, per-source aggregates) against the same
table. If the encoder and the Rust decoder ever disagree, the Rust test
fails loudly.

Layout:
    app.js                 the "bundle" (3 lines; line 3 is the map comment)
    app.js.map             rich map: 2 named sources + 1 null, 2 names,
                           sourcesContent for source 0, 4 mappings + 1
                           column-only segment over 2 generated lines
    src/orig/main.js       the map's source 0 (exists on disk)
    src/orig/util.js       the map's source 1 (exists on disk)
    broken.map             source index out of range on segment 1
    garbage.map            not JSON at all
    wrongversion.map       version 2 (parser targets version 3)
"""

import json
from pathlib import Path

BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def vlq(value: int) -> str:
    sign = 1 if value < 0 else 0
    encoded = (abs(value) << 1) | sign
    out = []
    while True:
        digit = encoded & 0x1F
        encoded >>= 5
        cont = 0x20 if encoded else 0
        out.append(BASE64[digit | cont])
        if not encoded:
            return "".join(out)


# Hand-designed mapping table (generated column delta, source index delta,
# source line delta, source column delta, name delta).
# Absolute values after deltas:
#   line 1: (1:0)->main.js 1:0            seg 0
#           (1:16)->util.js 2:0  [makeSum] seg 1
#           (1:30) column-only             seg 2
#   line 2: (2:0)->util.js 3:4   [log]     seg 3
#           (2:20)->main.js 2:0            seg 4
SEGMENTS = {
    1: [
        (0, 0, 0, 0, None),   # seg 0: gen 1:0  -> src 0 (main.js) 1:0
        (16, 1, 1, 0, 0),     # seg 1: gen 1:16 -> src 1 (util.js) 2:0, name 0
        (14, None, None, None, None),  # seg 2: column-only at 1:30
    ],
    2: [
        (0, 0, 1, 4, 1),      # seg 3: gen 2:0  -> src 1 (util.js) 3:4, name 1
        (20, -1, -1, -4, None),  # seg 4: gen 2:20 -> src 0 (main.js) 2:0
    ],
}


def encode_mappings(table: dict) -> str:
    lines = []
    # Running per-field state across lines (source-family persists; the
    # generated column resets per line).
    prev = {"src": 0, "line": 0, "col": 0, "name": 0}
    for line_no in sorted(table):
        parts = []
        for seg in table[line_no]:
            if len(seg) == 1 or seg[1] is None:
                parts.append(vlq(seg[0]))
                continue
            gen_delta, src_delta, line_delta, col_delta, name_delta = seg
            prev["src"] += src_delta
            prev["line"] += line_delta
            prev["col"] += col_delta
            fields = [vlq(gen_delta), vlq(src_delta), vlq(line_delta), vlq(col_delta)]
            if name_delta is not None:
                prev["name"] += name_delta
                fields.append(vlq(name_delta))
            parts.append("".join(fields))
        lines.append(",".join(parts))
    return ";".join(lines)


MAPPINGS = encode_mappings(SEGMENTS)

# Cross-check against the hand-computed literal (the Rust test pins the
# decoded table, this pins the encoding).
assert MAPPINGS == "AAAA,gBCCAA,c;AACIC,oBDDJ", MAPPINGS

MAIN_CONTENT = (
    "// original entry for the demo bundle\n"
    "export function makeWidget(n) { return n + 1; }\n"
)
UTIL_CONTENT = (
    "// original util for the demo bundle\n"
    "export const makeSum = (a, b) => a + b;\n"
    "export function log(x) { console.log(x); }\n"
)


def write_map(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    here = Path(__file__).resolve().parent

    (here / "src" / "orig").mkdir(parents=True, exist_ok=True)
    (here / "src" / "orig" / "main.js").write_text(MAIN_CONTENT, encoding="utf-8")
    (here / "src" / "orig" / "util.js").write_text(UTIL_CONTENT, encoding="utf-8")

    (here / "app.js").write_text(
        '!function(){var e=1,t=2;function n(){return e+t}console.log(n())}();\n'
        'console.log("VORTEX_SOURCEMAP_DEMO second generated line");\n'
        '//# sourceMappingURL=app.js.map\n',
        encoding="utf-8",
    )

    write_map(
        here / "app.js.map",
        {
            "version": 3,
            "file": "app.js",
            "sourceRoot": "",
            "sources": ["src/orig/main.js", "src/orig/util.js", None],
            "sourcesContent": [MAIN_CONTENT, None, None],
            "names": ["makeSum", "log"],
            "mappings": MAPPINGS,
        },
    )

    write_map(
        here / "broken.map",
        {
            "version": 3,
            "file": "broken.js",
            "sources": ["only.js"],
            "sourcesContent": [],
            "names": [],
            # seg 1 points at source index 1 with one source declared.
            "mappings": "AAAA,ICCC",
        },
    )

    (here / "garbage.map").write_text("{ this is not json", encoding="utf-8")

    write_map(
        here / "wrongversion.map",
        {
            "version": 2,
            "file": "old.js",
            "sources": ["a.js"],
            "sourcesContent": [],
            "names": [],
            "mappings": "AAAA",
        },
    )

    print("mappings:", MAPPINGS)
    print("fixtures written under", here)


if __name__ == "__main__":
    main()
