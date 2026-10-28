# cpp-leakcheck

[Leakcheck](https://github.com/voidstackloop/drydock#readme) for Node: memory bugs,
resource leaks, trojan behaviour and malware signatures in C/C++ programs — as a
CLI and as a small promise API. (`leakcheck` itself is taken on npm; the tool
inside is still called `leakcheck`.)

```sh
npm i cpp-leakcheck
npx leakcheck --version
npx leakcheck static ./src -f json -o report.json
```

```js
const lc = require("cpp-leakcheck");

// JSON report for a source tree (exit 2 means findings — normal, not an error)
const { code, report } = await lc.analyze("./src");
console.log(code, report.findings.length);

// Malware/disguise scan, and running a program under the watcher
await lc.scan("./dist");
await lc.dynamic("./build/my_server", ["--port", "8080"]);
```

## How the binary gets here

`postinstall` downloads the prebuilt archive for your platform from the
GitHub release matching this package's version (linux x64/arm64, macOS
universal, Windows x64) into `npm/vendor/` — no build tools needed. Keep the
`version` in `npm/package.json` in step with the repo's `VERSION` file when
you bump it, or the download 404s.

Local build instead of a download (and offline machines):

```sh
CPP_LEAKCHECK_BINARY=$PWD/build/leakcheck npm install ./npm
```

`npm test` runs the smoke test against the vendored binary (or
`CPP_LEAKCHECK_BINARY`).

## Publish

```sh
cd npm
npm version 1.0.1   # keep in step with the repo VERSION
npm publish --access public
```
