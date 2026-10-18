// Vortex-RE postinstall.
//
// Strategy (honest, no silent failures):
//   - If a prebuilt binary matches this platform: verify it runs. Done.
//   - Otherwise: build from the bundled rust-source/ with cargo into
//     build/. If cargo is missing, print clear instructions and leave the
//     launcher to explain at run time (the launcher's help text covers it).
//
// This script executes only the vortex build/binary itself. Vortex-RE never
// executes inspected targets, and this installer never downloads anything:
// everything needed is already inside this package (local-first).

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const pkgRoot = __dirname;
const platform = `${process.platform}-${process.arch}`;
const prebuilt =
  path.join(pkgRoot, "prebuilds", platform, process.platform === "win32" ? "vortex.exe" : "vortex");
const sourceDir = path.join(pkgRoot, "rust-source");
const buildDir = path.join(pkgRoot, "build");

function note(msg) {
  process.stdout.write(`[vortex-re] ${msg}\n`);
}
function warn(msg) {
  process.stderr.write(`[vortex-re] ${msg}\n`);
}

function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, Object.assign({ stdio: "inherit" }, opts || {}));
  return r.status === 0;
}

// 1) Prebuilt path.
if (fs.existsSync(prebuilt)) {
  const ver = spawnSync(prebuilt, ["--version"], { encoding: "utf8" });
  if (ver.status === 0) {
    note(`prebuilt binary ok (${platform}): ${ver.stdout.trim()}`);
    process.exit(0);
  }
  warn(`prebuilt binary exists but failed to run (${platform}); falling back to source build`);
}

// 2) Source build path (non-matching platforms).
if (!fs.existsSync(path.join(sourceDir, "Cargo.toml"))) {
  warn("bundled rust-source/ is missing; cannot build from source");
  process.exit(0);
}

const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";
const haveCargo = spawnSync(cargo, ["--version"], { encoding: "utf8" }).status === 0;
if (!haveCargo) {
  warn(`no prebuilt binary for ${platform} and no Rust toolchain (cargo) found.`);
  warn(`install Rust from https://rustup.rs, then reinstall this package, or see:`);
  warn(`https://github.com/Gatsuke/vortex-re#build-and-install`);
  process.exit(0); // do not hard-fail the whole npm install; launcher explains.
}

note(`no prebuilt for ${platform}; building vortex from bundled source (a few minutes)...`);
fs.mkdirSync(buildDir, { recursive: true });
const ok = run(cargo, ["build", "--release", "--locked", "--target-dir", buildDir], {
  cwd: sourceDir,
});
const stamp = process.platform === "win32" ? "vortex.exe" : "vortex";
const built = path.join(buildDir, "release", stamp);
if (ok && fs.existsSync(built)) {
  fs.copyFileSync(built, path.join(buildDir, stamp));
  note(`built successfully: ${path.join(buildDir, stamp)}`);
  process.exit(0);
}
warn("source build failed; see compiler output above.");
warn("you can retry inside the package: cd rust-source && cargo build --release --locked");
process.exit(1);
