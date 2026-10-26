# Putting leakcheck in a build

Every recipe below ends in the same contract: status 0 clean, 2 new findings,
1 nothing could be analysed, 3 the config, baseline or suppressions are wrong.
A gate never passes because its own inputs broke.

## CMake

```cmake
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(leakcheck)
leakcheck_add_target(leakcheck_check
    ARGS --baseline compare .leakcheck-baseline.txt -s ci/leakcheck.supp)
```

`cmake --build . --target leakcheck_check` fails on findings. With no `TARGET`,
the module uses `compile_commands.json` when the build wrote one (the list of
translation units the compiler actually saw) and the source directory
otherwise. `leakcheck_add_target` uses the `leakcheck` target when this build
has one, which keeps the tool and the check on the same commit.

## Make and Meson

Both can write a compilation database; leakcheck reads it directly.

* Make: `bear -- make` (or `compiledb make`) writes `compile_commands.json`,
  then `leakcheck static -f sarif -o leakcheck.sarif compile_commands.json`.
* Meson: `meson setup build` writes `build/compile_commands.json`, then
  `leakcheck static build/compile_commands.json`.

## Bazel

```python
load("//bazel:leakcheck.bzl", "leakcheck_report")

leakcheck_report(
    name = "leakcheck",
    tool = "@leakcheck//:leakcheck",
    srcs = glob(["src/**/*.c", "src/**/*.h"]),
    args = ["--baseline", "compare", "ci/leakcheck-baseline.txt"],
)
```

`bazel build //:leakcheck` fails on findings and writes `leakcheck.sarif` into
`bazel-bin`. The rule analyses the directory holding the sources, not one
translation unit at a time, because the cross-file checks need the whole tree.
The rule is in `bazel/leakcheck.bzl`; it has no dependencies outside Starlark.

## pre-commit

```yaml
repos:
  - repo: https://github.com/OWNER/leakcheck
    rev: v1.0.0
    hooks:
      - id: leakcheck
```

The hook runs `static` on each staged C/C++ file and compares it with
`.leakcheck-baseline.txt` found upwards from the repository root. The full tree,
with the cross-file checks, belongs in CI.

## Docker, offline

```sh
docker build -f docker/Dockerfile -t leakcheck:1.0.0 .
docker run --rm --network none -v "$PWD:/src:ro" leakcheck:1.0.0 \
    static -f sarif -o /dev/stdout /src
```

The image is distroless: no shell, no package manager, no network. The preload
library shipped beside the binary is only used by `dynamic`; `static` and `scan`
never execute the input.

## GitHub Actions

`docs/github-actions.yml` is a complete workflow, and the action itself is in
`.github/actions/leakcheck`: it runs the binary already on `PATH`, registers a
problem matcher for console findings, uploads SARIF, and fails with leakcheck's
own status. It needs `permissions: security-events: write`.

## GitLab CI

`docs/gitlab-ci.yml` publishes `-f junit` as the merge request's test report,
so a finding is a failed test case with its file and line.

## Making a gate go green on an existing tree

```sh
leakcheck static --baseline write .leakcheck-baseline.txt .
git add .leakcheck-baseline.txt leakcheck.toml
```

The write run exits 0 and records every current finding (a fingerprint of type,
file relative to the baseline, enclosing function and message, without line
numbers). Later runs add `--baseline compare .leakcheck-baseline.txt` and fail
only on findings that are not in it. A finding that is moved or reformatted
keeps its fingerprint, so the baseline does not have to be rewritten after an
unrelated refactor.
