// npm test: the binary answers --version and the JS API parses a report.
// Uses the vendored binary, or CPP_LEAKCHECK_BINARY for a local build:
//   CPP_LEAKCHECK_BINARY=$PWD/build/leakcheck npm test
"use strict";
const assert = require("node:assert");
const api = require("../index.js");

(async () => {
  const bin = api.binaryPath();
  console.log("binary:", bin);
  const v = await api.run(["--version"]);
  assert.equal(v.code, 0, v.stderr);
  assert.match(v.stdout, /leakcheck/, v.stdout);
  console.log(v.stdout.trim().split("\n")[0]);
  // Static over this package's own JS is meaningless; scan this directory
  // for a real JSON report shape instead.
  const { code, report } = await api.scan(__dirname);
  assert.ok(typeof code === "number");
  assert.ok(report && typeof report === "object", "report parses as JSON");
  console.log("scan exit:", code, "| findings:", report.findings?.length ?? "?");
  console.log("smoke: ok");
})().catch((err) => {
  console.error("smoke: FAIL", err.message);
  process.exit(1);
});
