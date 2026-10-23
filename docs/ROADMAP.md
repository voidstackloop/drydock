# Roadmap: what a company needs before it puts leakcheck in its gate

This is a plan for adoption, not a feature wish list. Every phase ends with a
measurement, because the thing that stops a large team from using a checker is
never the number of rules — it is a red build nobody trusts.

**Non-goals.** No accounts, no teams, no server, no dashboards, no telemetry, no
uploading code. leakcheck stays one binary that works offline, on a laptop and
in an air-gapped build, under MIT. Everything below is a check, or the
plumbing a check needs to be trusted in somebody else's pipeline.

## What is already there

`dynamic`, `static` and `scan` with one reporter; console, JSON and SARIF 2.1.0;
CWE mapping and SARIF rules; glob suppressions; `-j` for scan and ai-features;
a 245-case eval corpus with a "must stay silent" half; 7,758 normal and 3,327
malicious programs for measuring the scanner; 9 test suites; CodeQL on the
repository.

## What is missing, honestly

| Gap | Why it blocks adoption |
|---|---|
| No tags, no releases, no `--version` | A gate cannot pin a tool it cannot identify. |
| No build/test workflow | The only CI runs CodeQL. Nothing proves a commit builds. |
| No packages or installers | "Build it with CMake 3.28" is a procurement conversation. |
| No baseline / "new findings only" mode | A team with 4,000 existing findings cannot turn the gate on. |
| No config file or exclude list | Every invocation repeats twenty flags, and vendored trees are scanned. |
| Suppressions have no owner, reason or expiry | Security review cannot audit what was silenced and why. |
| False-alarm rate on real code is unmeasured | The one number a buyer asks for does not exist. |
| Static analysis has no incremental mode | A million-line tree is rescanned from scratch on every push. |
| No parser fuzzing | A crash on a hostile file is a denial of service in their CI. |
| No Windows or macOS CI | Two of the three supported platforms are untested by the project. |

## Known issues (found by the first CI run)

Adding the build-and-test workflow showed the project did not build where the
docs said it did:

- **macOS `dynamic` does not compile.** `preload/signals.cpp` uses
  `sigabbrev_np` and `sighandler_t`, which are glibc names, and calls
  `fseeko`/`ftello` without a declaration; `preload/locks.cpp` hooked pthread
  calls Darwin does not have, and `guard.cpp` needed the right feature macros.
  The pthread guards and the feature macros are fixed. The signal names and the
  stdio declarations are not, so the macOS job runs non-blocking and no macOS
  archives are published. The rest is mechanical: `sys_signame` instead of
  `sigabbrev_np`, `sig_t` instead of `sighandler_t`, and declared dlsym slots
  for the two stdio calls.
- **Windows static tests are flaky.** One run lost the cross-file flow report in
  `static_flow_crosses_files`; the next passed it. Windows builds in CI but does
  not gate on the suites until that is understood.
- The MinGW script was missing the classifier's two source files (a link error),
  and the macOS build was missing platform guards. Both are fixed.

Linux is the only platform whose tests gate a merge today. Phase 5 closes the
matrix.

## Phase 0 — Make it installable and identifiable (1 week)

- `--version`: semantic version, git hash, build type, and the model version.
- Tag `v1.0.0`; a release workflow that builds Linux x86_64/aarch64 (glibc; musl
  deferred), Windows x64, and macOS arm64/x86_64 once the runtime compiles
  there, with SHA-256 sums and SLSA build provenance. No binaries from a
  laptop.
- `cmake --install` rules, a man page, and a `CHANGELOG.md` that states what
  changed per finding type.
- A build-and-test workflow: three platforms, `ctest`, `tests/run_tests.py`,
  `eval/run_eval.py`, `-Werror`.

**Done when:** `curl` a release tarball on a clean machine, run `leakcheck
--version` and a scan, with no compiler installed.

## Phase 1 — A gate a team can turn on (2 weeks)

- **Baseline.** `--baseline write|compare <file>`: findings get a stable
  fingerprint (type + normalized location + enclosing function/rule, not line
  numbers), so a baseline survives reformatting and unrelated edits. Compare
  mode fails only on findings not in the baseline.
- **Config.** `leakcheck.toml` discovered upwards from the target, holding
  format, jobs, excludes, suppression files and per-mode thresholds; flags win
  over the file.
- **Excludes.** `--exclude <glob>` and `.leakcheckignore`, applied to the file
  walk before any parsing, with a note in the report of how many files they hid.
- **Suppression metadata.** Optional `reason=` and `expires=YYYY-MM-DD` on a
  rule; an expired rule is an error, and `--audit-suppressions` prints every
  rule with its reason and age.
- **CI surfaces.** A GitHub Action (SARIF upload, `problemMatcher`, cache),
  a GitLab CI snippet, and `-f junit`.
- **Exit contract.** `0` clean, `2` new findings, `1` could not analyse, `3`
  baseline/config problem — documented as a table, tested.

**Done when:** a repository with an existing report goes green in one commit
(baseline written), and stays green after a 500-line refactor that moves code.

## Phase 2 — Precision as a published number (3 weeks)

This phase decides whether the tool is usable, so it comes before more rules.

- Build a **reference corpus of real projects** (20 open-source C/C++ trees of
  different ages and styles, plus the 7,758-file Windows corpus already here).
- Triage every finding on it once, by hand, and record per-rule
  true/false positives in `eval/PRECISION.md`.
- Set a **budget**: no rule ships with more than 2% false alarms on the
  reference corpus; rules that cannot meet it are demoted to `--strict` or cut.
  The TLS-callback and injection-import rules were cut for exactly this reason;
  make that a written policy rather than a habit.
- Add the reference corpus to CI as a **regression gate**: a change that adds a
  finding on it fails, unless the diff is reviewed and the expectation updated.
- Publish per-rule docs: message, CWE, example, false-positive conditions, and
  the suppression pattern that silences it.

**Done when:** `eval/PRECISION.md` states a false-alarm rate per rule and for
the tool as a whole, and CI enforces it.

## Phase 3 — Make a big tree cheap (2 weeks)

- **Incremental static analysis.** Cache per-file findings keyed by content
  hash, parser version and flags; a second run on an unchanged tree reads the
  cache and finishes in seconds.
- **`--changed-only`** against a git ref, for PR gates; the report says which
  files were skipped and why.
- **`-j` for static mode** (scan and ai-features already have it), with the
  same "identical output in file order whatever the thread count" test.
- **Budgets:** ≤2 minutes per million lines on one core for `static`, ≤1 GB
  RSS on a 500k-line tree, measured in CI on a fixed corpus.
- Streaming report writing, so a million findings do not need a million
  in memory.

**Done when:** three runs on a 500k-line tree (cold, warm, one file touched)
are timed in CI and published.

## Phase 4 — Fit the build systems teams already have (1–2 weeks)

- A CMake module (`leakcheck.cmake`) that adds a `leakcheck` target and picks
  up `compile_commands.json` automatically.
- A Bazel/Starlark rule, and a documented `compile_commands.json` recipe for
  Meson and plain Make.
- A `pre-commit` hook and a **distroless Docker image**, tested with the network
  disabled.
- A `--print-config` that shows the effective config (after file, env and
  flags), so a failing gate is debuggable in one command.

**Done when:** a sample repo using each of CMake, Bazel and Make gets findings
with one added line, and the Docker image scans with `--network none`.

## Phase 5 — Harden the thing that judges other code (2 weeks)

- **Fuzz the parsers** — lexer, PE/Mach-O/ELF readers, the model loader,
  suppressions, the report reader — under libFuzzer, with OSS-Fuzz integration.
- Run ASan/UBSan builds of every test in CI, and a corpus of malformed files
  that must produce a finding or a clean error, never a crash.
- Determinism test across the three operating systems: same input, byte-identical
  JSON and SARIF.
- **Scan itself** in CI (dogfooding), and publish an SBOM for the released
  binary (it has no third-party dependencies — state that as a feature).
- A `SECURITY.md` response policy with a fixed disclosure window and a signed
  advisory process.

**Done when:** a week of fuzzing finds no crash, and a deliberately corrupted
file of each format is a finding rather than a segfault.

## Phase 6 — Speak the language of compliance (1 week)

- A coverage matrix: each CWE Top 25 entry, supported / partial / not covered,
  with the rule that covers it, generated from `shared/include/vulnerability.h`
  so it cannot drift.
- SARIF taxa and rule help URIs that resolve to the per-rule docs from Phase 2.
- `--rule-list -f json` for inventory tools, including default severity and
  whether the rule is on by default.

**Done when:** a compliance reviewer can map "we need CWE-78, 89, 416, 476"
to named rules and a documented limit, without asking a developer.

## Adoption criteria

The plan is finished when all of these are true:

1. A team adds one workflow file and a baseline, and their next PR is gated.
2. An unchanged commit costs seconds, not minutes.
3. The published false-alarm rate on the reference corpus is under 2%.
4. Every finding maps to a CWE and a documented rule page.
5. Release binaries are signed, reproducible and versioned, and work offline.
6. The tool runs on Windows, macOS and Linux from the same commit.

## Order of work, and what to do first

Phases 0 and 1 are the difference between "interesting project" and "tool on a
build server". Phase 2 is the difference between "tried once" and "kept".
Phases 3–6 matter after that, in that order.

The next three commits, concretely: `--version` plus a tagged release workflow;
`--baseline` with fingerprints; a GitHub Action that uploads SARIF and reads a
baseline.
