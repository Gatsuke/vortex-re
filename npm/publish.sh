# Assemble and (optionally) publish the vortex-re npm package.
#
# Usage:
#   ./publish.sh assemble   # stage prebuilds + rust-source + docs into npm/
#   ./publish.sh pack       # assemble + npm pack (dry run, produces tarball)
#   ./publish.sh publish    # assemble + npm publish
#
# Everything is local-first: the prebuilt binary is copied from the local
# musl build; rust-source is a git archive of HEAD. No network downloads.

set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-assemble}"
NPM_DIR="npm"
MUSL_BIN="target/x86_64-unknown-linux-musl/release/vortex"

command -v npm >/dev/null || { echo "npm not found" >&2; exit 1; }
[ -f "$MUSL_BIN" ] || { echo "musl binary missing; run: cargo build --release --target x86_64-unknown-linux-musl" >&2; exit 1; }

echo "==> staging prebuilt (linux-x64, static musl)"
mkdir -p "$NPM_DIR/prebuilds/linux-x64"
cp "$MUSL_BIN" "$NPM_DIR/prebuilds/linux-x64/vortex"
chmod 755 "$NPM_DIR/prebuilds/linux-x64/vortex"

echo "==> staging bundled rust source (git archive HEAD)"
rm -rf "$NPM_DIR/rust-source"
mkdir -p "$NPM_DIR/rust-source"
git archive --format=tar HEAD | tar -x -C "$NPM_DIR/rust-source"

echo "==> staging docs and licenses"
cp README.md "$NPM_DIR/README.md"
cp LICENSE-MIT "$NPM_DIR/LICENSE-MIT"
cp LICENSE-APACHE "$NPM_DIR/LICENSE-APACHE"
cp THIRD_PARTY_NOTICES.md "$NPM_DIR/THIRD_PARTY_NOTICES.md"

case "$MODE" in
  assemble)
    echo "==> assembled under $NPM_DIR/ (not packed)"
    ;;
  pack)
    (cd "$NPM_DIR" && npm pack --dry-run && npm pack)
    ;;
  publish)
    (cd "$NPM_DIR" && npm publish)
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 1
    ;;
esac
