// Minimal Node API over the vendored leakcheck binary.
// Every function that runs the tool resolves { code, report } where report
// is the parsed `-f json -o -` document. The binary exits 2 on findings,
// which is a normal result here, not an exception.
"use strict";

const { spawn } = require("node:child_process");
const { existsSync, readdirSync, readFileSync, unlinkSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

function binaryPath() {
  const vendor = join(__dirname, "vendor");
  const exe = process.platform === "win32" ? "leakcheck.exe" : "leakcheck";
  // Layout after install: vendor/leakcheck-<version>-<platform>/bin/leakcheck
  // (or vendor/leakcheck directly when CPP_LEAKCHECK_BINARY was used).
  const direct = join(vendor, exe);
  if (existsSync(direct)) return direct;
  if (existsSync(vendor))
    for (const entry of readdirSync(vendor, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const p = join(vendor, entry.name, "bin", exe);
      if (existsSync(p)) return p;
    }
  throw new Error(
    "cpp-leakcheck: binary not installed (offline postinstall?). " +
    "Set CPP_LEAKCHECK_BINARY=/path/to/leakcheck and reinstall, or file a bug."
  );
}

// Raw escape hatch: run the CLI exactly as given, get text back.
function run(args, opts = {}) {
  return new Promise((resolve, reject) => {
    let bin;
    try {
      bin = binaryPath();
    } catch (err) {
      return reject(err);
    }
    const child = spawn(bin, args, { ...opts, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function report(mode, target, opts = {}) {
  // Dynamic writes its JSON to the report file (only static/scan stream it
  // with -o -), so every mode goes through a temp file, like the test suite.
  const { args = [], ...spawnOpts } = opts;
  const path = join(tmpdir(), `leakcheck-${process.pid}-${Date.now()}.json`);
  try {
    const { code, stderr } = await run(["-f", "json", "-o", path, mode, target, ...args], spawnOpts);
    const text = existsSync(path) ? readFileSync(path, "utf8") : "";
    if (!text.trim()) throw new Error(`leakcheck produced no JSON (exit ${code}): ${stderr.trim()}`);
    return { code, report: JSON.parse(text) };
  } finally {
    try {
      unlinkSync(path);
    } catch {}
  }
}

// leakcheck static <file|dir> — analyse sources without running them.
function analyze(target, opts) {
  return report("static", target, opts);
}

// leakcheck scan <file|dir> — malware and disguise signatures.
function scan(target, opts) {
  return report("scan", target, opts);
}

// leakcheck dynamic <program...> — run the program under the watcher.
function dynamic(program, programArgs = [], opts = {}) {
  return report("dynamic", program, { ...opts, args: [...programArgs, ...(opts.args || [])] });
}

module.exports = { binaryPath, run, report, analyze, scan, dynamic };
