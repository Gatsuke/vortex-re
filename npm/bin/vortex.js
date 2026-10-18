#!/usr/bin/env node
// Vortex-RE launcher.
//
// Locates the platform binary for this npm installation and executes it with
// the raw stdio streams (stdin/stdout are passed through untouched, which the
// MCP stdio transport requires).
//
// Binary resolution order:
//   1. prebuilds/<platform>-<arch>/vortex   (shipped with this package)
//   2. build/vortex                          (built from bundled rust-source
//                                             by install.js when no prebuilt
//                                             matches and cargo is available)
//   3. $VORTEX_BIN                           (escape hatch: explicit override)
//
// Vortex-RE performs static analysis only; inspected targets are never
// executed. This launcher executes only the vortex binary itself.

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const pkgRoot = path.resolve(__dirname, "..");

function candidatePaths() {
  const platform = `${process.platform}-${process.arch}`;
  const list = [];
  if (process.env.VORTEX_BIN) {
    list.push(process.env.VORTEX_BIN);
  }
  list.push(path.join(pkgRoot, "prebuilds", platform, "vortex"));
  list.push(path.join(pkgRoot, "prebuilds", platform, "vortex.exe"));
  list.push(path.join(pkgRoot, "build", "vortex"));
  list.push(path.join(pkgRoot, "build", "vortex.exe"));
  return list;
}

function findBinary() {
  for (const p of candidatePaths()) {
    try {
      if (fs.existsSync(p)) {
        fs.accessSync(p, fs.constants.X_OK);
        return p;
      }
    } catch (_) {
      /* not executable; keep looking */
    }
  }
  return null;
}

function helpText() {
  const platform = `${process.platform}-${process.arch}`;
  return [
    `vortex-re: no usable vortex binary found for ${platform}.`,
    ``,
    `This package ships a prebuilt static binary for linux-x64.`,
    `On other platforms it builds from the bundled Rust source at install`,
    `time when a Rust toolchain (cargo) is available.`,
    ``,
    `Options:`,
    `  1. Install Rust (https://rustup.rs) and reinstall this package:`,
    `       npm install -g vortex-re`,
    `     The postinstall step will then build from the bundled source.`,
    `  2. Build from the repository:`,
    `       git clone https://github.com/Gatsuke/vortex-re`,
    `       cd vortex-re && cargo build --release --locked`,
    `  3. Set VORTEX_BIN to an existing vortex binary.`,
    ``,
    `Prebuilt releases: https://github.com/Gatsuke/vortex-re/releases`,
  ].join("\n");
}

const binary = findBinary();
if (!binary) {
  process.stderr.write(helpText() + "\n");
  process.exit(127);
}

const result = spawnSync(binary, process.argv.slice(2), {
  stdio: "inherit",
  env: process.env,
});

// Propagate signals the way a plain exec would.
const sig = result.signal;
if (sig) {
  if (sig === "SIGINT") process.exit(130);
  if (sig === "SIGTERM") process.exit(143);
  process.exit(128);
}
process.exit(result.status === null ? 1 : result.status);
