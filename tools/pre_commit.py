#!/usr/bin/env python3
"""pre-commit entry point: analyse the C/C++ files the commit touches.

    - repo: https://github.com/OWNER/leakcheck
      rev: v1.0.0
      hooks:
        - id: leakcheck

The baseline is looked up from the working directory upwards, the same way
leakcheck finds leakcheck.toml. A file at a time keeps a commit fast; the full
tree (and the cross-file checks) belong in CI, where the action runs it.
"""
import os
import subprocess
import sys

EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx")


def find_upwards(name, start="."):
    directory = os.path.abspath(start)
    while True:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(directory)
        if parent == directory:
            return None
        directory = parent


def main():
    files = [f for f in sys.argv[1:] if f.lower().endswith(EXTS) and os.path.isfile(f)]
    if not files:
        return 0
    tool = os.environ.get("LEAKCHECK", "leakcheck")
    baseline = find_upwards(".leakcheck-baseline.txt")
    failed = False
    for path in files:
        args = [tool, "static", path]
        if baseline:
            args += ["--baseline", "compare", baseline]
        p = subprocess.run(args)
        failed = failed or p.returncode != 0
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
