// Downloads the prebuilt leakcheck archive for this platform from the
// GitHub release matching this package's version, and unpacks it into
// vendor/. No dependencies: this runs as a postinstall script.
//
// Env overrides (local builds, offline machines, air-gapped CI):
//   CPP_LEAKCHECK_BINARY=/path/to/leakcheck  use it instead of downloading
//   CPP_LEAKCHECK_MIRROR=https://...          release base URL (default: the
//                                            repo's GitHub releases)
"use strict";

const { createWriteStream, existsSync, mkdirSync, copyFileSync, chmodSync, readdirSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, basename, dirname } = require("node:path");
const { get } = require("node:https");
const { execFileSync } = require("node:child_process");

const VERSION = require("./package.json").version;
const REPO = "voidstackloop/drydock";
const VENDOR = join(__dirname, "vendor");

function platformAsset() {
  // Mirrors the release workflow's archive names.
  if (process.platform === "linux" && process.arch === "x64")
    return `leakcheck-${VERSION}-linux-x86_64.tar.gz`;
  if (process.platform === "linux" && process.arch === "arm64")
    return `leakcheck-${VERSION}-linux-aarch64.tar.gz`;
  if (process.platform === "darwin")
    return `leakcheck-${VERSION}-macos-universal.tar.gz`;
  if (process.platform === "win32" && process.arch === "x64")
    return `leakcheck-${VERSION}-windows-x86_64.zip`;
  throw new Error(`cpp-leakcheck: no prebuilt binary for ${process.platform}-${process.arch}`);
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    get(url, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location)
        return download(res.headers.location, dest).then(resolve, reject);
      if (res.statusCode !== 200)
        return reject(new Error(`cpp-leakcheck: download failed: ${res.statusCode} ${url}`));
      res.pipe(createWriteStream(dest)).on("finish", resolve).on("error", reject);
    }).on("error", reject);
  });
}

function exe() {
  return process.platform === "win32" ? "leakcheck.exe" : "leakcheck";
}

function unpack(archive) {
  if (archive.endsWith(".zip"))
    if (process.platform === "win32")
      execFileSync("powershell", ["-NoProfile", "-Command", "Expand-Archive", "-Path", archive, "-DestinationPath", VENDOR, "-Force"], { stdio: "inherit" });
    else
      execFileSync("unzip", ["-oq", archive, "-d", VENDOR], { stdio: "inherit" });
  else
    execFileSync("tar", ["-xzf", archive, "-C", VENDOR], { stdio: "inherit" });
}

async function main() {
  mkdirSync(VENDOR, { recursive: true });
  if (process.env.CPP_LEAKCHECK_BINARY) {
    const src = process.env.CPP_LEAKCHECK_BINARY;
    if (!existsSync(src)) throw new Error(`cpp-leakcheck: ${src} does not exist`);
    const dst = join(VENDOR, basename(src));
    copyFileSync(src, dst);
    if (process.platform !== "win32") chmodSync(dst, 0o755);
    // dynamic mode needs the preload library beside the binary; the release
    // archives already lay it out that way, so mirror that for local copies.
    for (const entry of readdirSync(dirname(src))) {
      if (/^l?leakcheck_preload\.(so|dylib|dll)$/.test(entry) || /^libleakcheck_preload\./.test(entry)) {
        copyFileSync(join(dirname(src), entry), join(VENDOR, entry));
        console.log(`cpp-leakcheck: also using local ${entry}`);
      }
    }
    console.log(`cpp-leakcheck: using local binary ${dst}`);
    return;
  }
  const asset = platformAsset();
  const mirror = (process.env.CPP_LEAKCHECK_MIRROR || `https://github.com/${REPO}/releases/download/v${VERSION}`).replace(/\/$/, "");
  const tmp = join(tmpdir(), asset);
  console.log(`cpp-leakcheck: downloading ${asset}`);
  await download(`${mirror}/${asset}`, tmp);
  unpack(tmp);
  // The tarball keeps its executable bits, but a copy (or Windows unzip)
  // may not: make sure the binary runs.
  for (const entry of readdirSync(VENDOR, { withFileTypes: true })) {
    const bin = join(VENDOR, entry.name, entry.isDirectory() ? join("bin", exe()) : exe());
    if (existsSync(bin)) {
      if (process.platform !== "win32") chmodSync(bin, 0o755);
      console.log(`cpp-leakcheck: installed ${bin}`);
      return;
    }
  }
  throw new Error("cpp-leakcheck: archive unpacked but no binary found");
}

if (require.main === module) main().catch((err) => {
  console.error(err.message);
  // Never break `npm install` of a parent project when offline: the JS API
  // reports a clear error if the binary is missing at call time.
  process.exit(0);
});
else module.exports = { platformAsset, VENDOR, VERSION };
