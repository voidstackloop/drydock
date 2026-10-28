#!/usr/bin/env node
// `npx leakcheck` / `leakcheck` after install: run the vendored binary
// with the user's terminal attached.
"use strict";
const { spawnSync } = require("node:child_process");
const { binaryPath } = require("../index.js");

let bin;
try {
  bin = binaryPath();
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
process.exit(r.status === null ? 1 : r.status);
