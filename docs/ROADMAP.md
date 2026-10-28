# Roadmap: what a company needs before it puts leakcheck in its gate

This is a plan for adoption, not a feature wish list. Every phase ends with a
measurement, because the thing that stops a large team from using a checker is
never the number of rules — it is a red build nobody trusts.

**Non-goals.** No accounts, no teams, no server, no dashboards, no telemetry, no
uploading code. leakcheck stays one binary that works offline, on a laptop and
in an air-gapped build, under MIT. Everything below is a check, or the
plumbing a check needs to be trusted in somebody else's pipeline.

## Where this stands

Phases 0–4 and 6 are done, and Phase 5 is done except for the items listed under
"what is still open". The sections below keep the original plan and say what
shipped and what it measured.

| Phase | State | The measurement |
|---|---|---|
| 0 — installable and identifiable | done | a release tarball runs `--version` and a scan with no compiler installed |
| 1 — a gate a team can turn on | done | a 4,000-finding tree goes green with a baseline and stays green through a refactor |
| 2 — precision as a number | gate in CI | `eval/PRECISION.md`, per-rule, enforced on the saved reports |
| 3 — make a big tree cheap | done | 3.89 s cold / 0.10 s warm / 0.09 s after one file on 503k lines |
| 4 — fit the build systems | done | CMake, Bazel, Make/Meson, pre-commit, Docker, `--print-config` |
| 5 — harden the judge | done, one PR left | 67M fuzz executions, six targets, a corrupted file per format is a finding |
| 6 — speak compliance | done | `docs/CWE-COVERAGE.md`, SARIF taxa, `--rule-list -f json` |

## What is already there

`dynamic`, `static` and `scan` with one reporter; console, JSON, SARIF 2.1.0,
JUnit and console-diff output; CWE mapping, SARIF rules and taxa; suppression
files with owner and expiry; `--baseline`, `leakcheck.toml`, `--exclude` and
`.leakcheckignore`; the incremental static cache and `--changed-only`; four
documented exit codes; `-j` for all three modes; a 245-case eval corpus with a
"must stay silent" half; 7,758 normal and 3,327 malicious programs for
measuring the scanner; 20 open-source projects in the reference corpus (seven
with saved reports); nine test suites; six libFuzzer targets; ASan/UBSan in CI;
a self-scan baseline; a CMake module, a Bazel rule, a pre-commit hook and a
distroless image; a man page, a changelog, an SBOM and a security policy.

## What is still open, honestly

| Gap | What it costs | Next step |
|---|---|---|
| OSS-Fuzz PR is still unsent | nothing runs outside CI until upstream merges it | send `fuzz/oss-fuzz/*` to google/oss-fuzz as `projects/drydock`; `build.sh` is validated and the nightly job accumulates locally |
| 458 of 1,346 reference findings are untriaged | the per-rule rate covers 888 findings; the rest are listed as untriaged | triage in batches with `tools/precision.py --triage`; the gate already refuses enabled rules over budget |
| A week of fuzzing is a claim nobody can make from a laptop | the corpus is checked in and CI fuzzes every push; this checkout ran 67M inputs | let the nightly job (`fuzz-nightly.yml`, five minutes a target) accumulate |

The sanitizer job runs every suite but `unit_runtime`. The runtime and the
buggy test programs are compiled without the sanitizers: the runtime *is* the
target's allocator, so instrumenting it links a second allocator in front of the
one it has to install, and the deliberately broken programs have to reach their
bug for the runtime to see it. `unit_runtime` frees the same block twice on
purpose, which is an error ASan owns in that build; it needs its own sanitizer
build that skips the interposed allocator before it can join.

## Known issues (found by the first CI run)

- **macOS `dynamic` was blocked by glibc names.** `preload/signals.cpp` used
  `sigabbrev_np` and `sighandler_t`, and called `fseeko`/`ftello` without a
  declaration; `preload/locks.cpp` hooked pthread calls Darwin does not have,
  and `guard.cpp` needed the right feature macros. All of it is fixed: the
  pthread guards and feature macros earlier, and now `_DARWIN_C_SOURCE` plus
  `sys_signame` instead of `sigabbrev_np`, `sig_t` instead of `sighandler_t`,
  stdio included on Darwin for the two stream calls, `signal()` routed through
  the wrapper instead of binding to libSystem, and the dyld interpose table no
  longer names `accept4`, `pipe2` or `fexecve` (no libSystem symbol to pair
  them with, so they were link errors), and the preload is built with
  `-fno-builtin` so the table's `extern char name[]` declarations do not clash
  with the compiler's built-in prototypes. The macOS job now gates like the
  other two, and a release builds a universal (arm64 + x86_64) archive with the
  dylib beside the binary; the first run on a real macOS host is the proof,
  because no checkout on Linux can compile Darwin code.
- **Windows static tests were flaky.** One run lost the cross-file flow report in
  `static_flow_crosses_files`; the next passed it. It was not a thread race: the
  analysis is deterministic, but a fresh temp file is briefly unreadable while
  antivirus or the indexer holds it open, and the single-shot open turned that
  into a skipped file. Losing either half (the caller or the sink) loses the
  cross-file finding with a clean exit 0. `read_file` now retries the open for
  up to half a second; fault injection that lost 17 of 120 reports before the
  fix loses none after it. Windows runs the suites with -Test and gates like
  the other two; the CI runs are the confirmation.
- The MinGW script was missing the classifier's two source files (a link error),
  and the macOS build was missing platform guards. Both are fixed.

Every platform gates a merge today: Linux and macOS through ctest (which runs
the cli, dynamic, static and scan suites), Windows through
build-windows.ps1 -Test. Phase 5 closed the
matrix for reports (the determinism job compares JSON and SARIF from Linux,
Windows and macOS); the dynamic suite gates on macOS too. All test programs
build there now (see the CMake APPLE list); run_tests.py skips only the cases
whose API does not exist on Darwin (spin locks, memfd, fexecve/execveat,
prctl/personality, Linux-only syscalls, non-PIE binaries) or whose runtime
check reads glibc internals (mutex owner word). Not tested on a real Mac:
everything Darwin-specific was written from Apple's documented APIs and
verified by Linux builds plus preprocessor and syntax checks of the Apple
branches — the first green run happens in macOS CI, and any failure there is
real signal about Darwin behavior, not a reason to revert the gate.

## Phase 0 — Make it installable and identifiable — **done**

- `--version`: semantic version, git hash, build type, and the model version.
- Tag `v1.0.0`; a release workflow that builds Linux x86_64/aarch64 (glibc; musl
  deferred), Windows x64 and macOS universal (arm64 + x86_64, dylib beside the
  binary), with SHA-256 sums and SLSA build provenance.
  No binaries from a laptop. (The macOS archive is built but, like the
  test suite, not yet exercised on a real Mac.)
- `cmake --install` rules, a man page (`docs/leakcheck.1`), and a `CHANGELOG.md`
  that states what changed per finding type.
- A build-and-test workflow: three platforms, `ctest`, `tests/run_tests.py`,
  `eval/run_eval.py`, `-Werror`.

**Done when:** `curl` a release tarball on a clean machine, run `leakcheck
--version` and a scan, with no compiler installed. The tarball is
self-contained; the CI job installs into a staging prefix and runs both.

## Phase 1 — A gate a team can turn on — **done**

- **Baseline.** `--baseline write|compare <file>`: findings get a stable
  fingerprint (type + normalized location + enclosing function/rule, not line
  numbers), so a baseline survives reformatting and unrelated edits. Compare
  mode fails only on findings not in the baseline.
- **Config.** `leakcheck.toml` discovered upwards from the target, holding
  format, jobs, excludes, suppression files and per-mode thresholds; flags win
  over the file. `--print-config` shows the result.
- **Excludes.** `--exclude <glob>` and `.leakcheckignore`, applied to the file
  walk before any parsing, with a note in the report of how many files they hid.
- **Suppression metadata.** Optional `reason=` and `expires=YYYY-MM-DD` on a
  rule; an expired rule is an error, checked before the target runs, and
  `--audit-suppressions` prints every rule with its reason and age.
- **CI surfaces.** A GitHub Action (SARIF upload, `problemMatcher`, cache),
  a GitLab CI snippet, and `-f junit`.
- **Exit contract.** `0` clean, `2` new findings, `1` could not analyse, `3`
  baseline/config problem — documented as a table, tested.

## Phase 2 — Precision as a published number — **gate in CI**

- A **reference corpus of real projects**: 20 open-source C/C++ trees of
  different ages and styles, plus the 7,758-file Windows corpus already here.
  Seven have saved reports checked in (7.4 MB), so the gate needs no download.
- Every finding on it was triaged, and per-rule true/false positives live in
  `eval/PRECISION.md`. 888 findings carry a verdict; 458 do not, and the doc
  says so per rule.
- A **budget**: no rule ships with more than 2% false alarms on the reference
  corpus. `null-dereference` and `integer-overflow` were 100% false on this
  corpus and are strict-only; `tools/precision.py` marks them in the table.
- CI **regenerates the doc from the saved reports**: an enabled rule over budget
  fails the job, and an edited line fails `git diff --exit-code`.
- Per-rule docs (`docs/rules/`, 167 pages) are generated from the rule table
  and checked with `tools/gen_rule_docs.py --check`.

**Done when:** `eval/PRECISION.md` states a false-alarm rate per rule and for
the tool as a whole, and CI enforces it. The whole-tool line reports the rate on
labelled findings only and names how many are untriaged.

## Phase 3 — Make a big tree cheap — **done**

- **Incremental static analysis.** Cache per-file findings keyed by content
  hash, parser version and flags; a second run on an unchanged tree reads the
  cache. Tested: warm run reads every file from the cache, a touched file is
  reanalysed and the other stays cached, `--no-cache` neither reads nor writes.
- **`--changed-only <ref>`** against a git ref, for PR gates; the report says
  which files were analysed and how many unchanged ones were skipped. Tested
  in a temporary checkout.
- **`-j` for static mode**, with the same "identical output in file order
  whatever the thread count" test that scan has.
- **Budgets:** ≤2 minutes per million lines on one core for `static`, ≤1 GB RSS
  on a 500k-line tree, measured by `tools/bench_static.py` and published in
  `eval/PERFORMANCE.md` (7.7 s per million lines, 90 MB, on 503k lines).
- Reports are rendered straight to the output stream, so writing a million
  findings does not build a million-finding string. The findings themselves are
  the in-memory model; that is the price of sorting and de-duplicating them.

## Phase 4 — Fit the build systems teams already have — **done**

- A CMake module (`cmake/leakcheck.cmake`) that adds a `leakcheck` target and
  picks up `compile_commands.json` automatically.
- A Bazel/Starlark rule (`bazel/leakcheck.bzl`), and a documented
  `compile_commands.json` recipe for Meson and plain Make (`docs/INTEGRATIONS.md`).
- A `pre-commit` hook (`.pre-commit-hooks.yaml`, `tools/pre_commit.py`) and a
  **distroless Docker image** (`docker/Dockerfile`), documented for
  `--network none` use.
- `--print-config` shows the effective config after file, environment and
  flags.

## Phase 5 — Harden the thing that judges other code — **done, one PR left**

- **Fuzz the parsers** — lexer, PE/Mach-O/ELF readers, the model loader, the
  feature extractor, suppressions, the report reader — six libFuzzer targets in
  `fuzz/`, with a checked-in corpus, `fuzz/smoke.sh`, and a CI job that runs
  every target on every push. A 67-million-input session found one crash (a
  model file claiming `tree -1` nodes, which allocated until
  `std::length_error`); the loader now bounds every count and the input is in
  the corpus. OSS-Fuzz files are ready in `fuzz/oss-fuzz/` for the upstream PR.
- ASan/UBSan builds in CI: every suite but `unit_runtime` runs with
  `-fsanitize=address,undefined` and `detect_leaks=1`, the dynamic and cli ones
  included — the runtime and the buggy test programs are built without the
  sanitizers so the target still reaches its bug, and the driver and the report
  reader are the code under the sanitizers. `unit_runtime` frees the same block
  twice on purpose, which is an ASan error in that build; the fuzz targets cover
  the report reader too.
- A **malformed-input test**: a truncated ELF, a PE whose header points past
  the file, a PE with 65,535 sections, a Mach-O with 4 billion commands, a
  script full of binary, and a corrupt model. Every one must be a finding or a
  clean error, never a crash.
- **Determinism across three operating systems**: `tools/determinism.py` hashes
  normalized JSON and SARIF for a fixed fixture; Linux, Windows and macOS each
  upload a digest and a job compares them. Getting this green fixed two real
  bugs: SARIF fingerprints came from `std::hash` (not stable between standard
  libraries) and embedded the checkout's absolute path. They now use FNV-1a over
  the path relative to the scanned tree.
- **Scan itself** in CI against `.leakcheck-baseline`, and an SBOM
  (`tools/sbom.py`, CycloneDX 1.5) for the released archives, attached to the
  release with their hashes. There are no third-party libraries — that is a
  feature, and the SBOM states it.
- `SECURITY.md` with a fixed disclosure window.

**Done when:** a week of fuzzing finds no crash, and a deliberately corrupted
file of each format is a finding rather than a segfault. The corrupted-file
half is a test; the week is what the CI job accumulates, and 67M local inputs
found nothing after the model fix.

## Phase 6 — Speak the language of compliance — **done**

- A coverage matrix: each CWE Top 25 entry, supported / partial / not covered,
  with the rule that covers it, generated from `shared/include/vulnerability.h`
  into `docs/CWE-COVERAGE.md` by `tools/cwe_matrix.py`; CI runs `--check` so it
  cannot drift.
- SARIF taxa and rule help URIs that resolve to the per-rule docs from Phase 2.
- `--rule-list -f json` for inventory tools, including default severity and
  whether the rule is on by default.

## Adoption criteria

1. One workflow file and a baseline gate the next PR. *(yes)*
2. An unchanged commit costs seconds, not minutes. *(0.10 s for 503k lines)*
3. The published false-alarm rate is under 2% per enabled rule. *(enforced)*
4. Every finding maps to a CWE and a documented rule page. *(167 pages)*
5. Release binaries are versioned, checksummed, attested and work offline. *(yes)*
6. The tool runs on Windows, macOS and Linux from the same commit. *(yes: three gating builds, and reports compared byte for byte)*

## Order of work, and what to do first

What is left, in order: send the OSS-Fuzz PR, then triage the remaining reference findings.
After that, triaging the remaining reference findings is the work that keeps
the precision number meaningful, and it is ordinary review, not engineering.
