# Changelog

The version lives in [`VERSION`](VERSION); `leakcheck --version` prints it with
the commit and build type. Release notes starting with 1.0.0 list only what a
user of the binary would notice.

## 1.0.0

First release.

- `dynamic`: leaks, double and invalid frees, use after free, overflows,
  descriptor and process leaks, deadlocks, and the behaviour of a trojan, on
  Linux, macOS and 64-bit Windows.
- `static`: the same memory and resource checks from source, plus the source
  weaknesses (format string, command injection, unbounded copy, hard-coded
  secret, TOCTOU, weak crypto, integer overflow, and the rest of the CWE list).
- `scan`: malware signatures, disguised executables, obfuscated scripts,
  packed and import-table anomalies, and the opt-in `--ai` classifier.
- 100 named malware families with `--malware`.
- Console, JSON and SARIF 2.1.0 reports; glob suppressions; exit status 2 on
  findings.
- `--version`, `cmake --install`, a man page, and release archives for Linux
  (x86_64, aarch64), macOS (arm64, x86_64) and Windows (x86_64) with SHA-256
  checksums and build-provenance attestations.
