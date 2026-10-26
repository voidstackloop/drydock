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
- Console, JSON, SARIF 2.1.0, JUnit, Markdown (`-f md`), CSV (`-f csv`), GitLab Code Quality (`-f gitlab`), SonarQube Generic Issue Import (`-f sonarqube`), and auto-fix patch generation (`-f patch`); glob suppressions; exit status
  2 on findings. `-o -` explicitly sends static and scan reports to stdout.
- Security debt & metrics: `--metrics` / `--stats` appends codebase file counts, LOC, finding densities, and technical debt score.
- PR & Gating enhancements: `--diff-base <ref>` restricts static analysis findings to changed lines; `leakcheck triage` provides an interactive terminal workflow for reviewing and baselining findings.
- 11 new static security detectors: `insecure-tempfile` (CWE-377), `hardcoded-key-iv` (CWE-321/329), `unchecked-security-return` (CWE-252), `uncleared-sensitive-data` (CWE-14), `return-stack-address` (CWE-562), `uninitialized-variable` (CWE-457), `timing-attack` (CWE-208/385), `zip-slip` (CWE-29/22), `insecure-deserialization` (CWE-502), `insecure-bind-all` (CWE-1327), and `high-entropy-secret` (CWE-798 Shannon entropy analyzer).
- Per-rule severity overrides in `leakcheck.toml` under `[rules.<id>]` (`severity = "error"|"warning"|"note"`).
- The gate: `--baseline write|compare` with fingerprints that survive
  reformatting and moved code, `leakcheck.toml`, `--exclude` and
  `.leakcheckignore` with ordered `!` re-includes, `--min-severity`, suppression
  rules with `reason=` and `expires=` (an expired rule is an error, and a bad
  file is rejected before the target runs), `--audit-suppressions`, `--rule-list`
  and `--print-config`.
  Per-rule policy can be set globally or per mode with `enable-rules` and
  `disable-rules`, then overridden by repeatable `--enable-rule` and
  `--disable-rule` flags; unknown IDs fail before analysis.
  Exit status is 0 clean, 2 findings, 1 could not analyse, 3 bad config.
- Big trees: an incremental static cache keyed by content, parser version and
  flags; `--changed-only <ref>` for pull requests; `-j` in all three modes.
- The build systems and pipelines teams already use: a CMake module, a Bazel
  rule, a pre-commit hook, a distroless image, a GitHub Action and a GitLab CI
  snippet.
- Hardening: six libFuzzer targets with a checked-in corpus, ASan/UBSan in CI
  over every test suite except the runtime's own, a malformed-file test per format, and a determinism check that compares JSON
  and SARIF from Linux, Windows and macOS byte for byte. Release archives ship
  with a CycloneDX SBOM; the tool has no third-party libraries.
- Fixed: SARIF `partialFingerprints` were taken from `std::hash` and the
  checkout's absolute path, so the same finding looked new on another machine
  or with another standard library. They are now FNV-1a over the path relative
  to the scanned tree. A model file claiming a negative node count made the
  loader reserve until `std::length_error`; every count is bounded now.
  `--print-config` no longer requires a mode, so it can explain a broken
  invocation. A `scan` baseline no longer fingerprints the byte offset of a
  hit, so editing a line above a signature does not turn it into a new
  finding.
  The MinGW build no longer changes into the source directory for `windres`,
  so it also works when the checkout is reached through a WSL UNC path.
  The Avaddon indicator row is encoded at rest and decoded once at startup, so
  Defender no longer quarantines the Windows scanner for carrying its signatures.
- macOS: the injected runtime now compiles. `sys_signame` replaces glibc's
  `sigabbrev_np`, `sig_t` replaces `sighandler_t`, stdio is included for
  `fseeko`/`ftello`, `signal()` installs through the wrapper instead of
  libSystem, and the dyld interpose table no longer names `accept4`, `pipe2`
  or `fexecve`.
- `--version`, `cmake --install`, a man page, and release archives for Linux
  (x86_64, aarch64), Windows (x86_64) and macOS (universal: arm64 + x86_64)
  with SHA-256 checksums, an SBOM and build-provenance attestations.
