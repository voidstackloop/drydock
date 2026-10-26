#!/usr/bin/env python3
"""Clone the pinned reference corpus into eval/corpus (git-ignored).

    python3 tools/fetch_corpus.py [--only redis,curl] [--force]

Each line of eval/corpus.tsv is: name, url, ref, note. A ref that looks like a
commit is fetched directly (a shallow clone cannot check an arbitrary commit
out); anything else is treated as a tag or branch. The resolved commit is
printed, which is what eval/PRECISION.md records.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def read_manifest(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                sys.exit("%s: expected name<TAB>url<TAB>ref" % path)
            rows.append(parts[:4])
    return rows


def is_commit(ref):
    return 7 <= len(ref) <= 40 and all(c in "0123456789abcdef" for c in ref.lower())


def git(*args, cwd=None):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args), p.stderr.strip()[-800:]))
    return p.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=os.path.join(ROOT, "eval", "corpus.tsv"))
    ap.add_argument("--dest", default=os.path.join(ROOT, "eval", "corpus"))
    ap.add_argument("--only", default="")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    wanted = {s for s in args.only.split(",") if s}
    os.makedirs(args.dest, exist_ok=True)
    failures = 0
    for name, url, ref, note in read_manifest(args.manifest):
        if wanted and name not in wanted:
            continue
        dest = os.path.join(args.dest, name)
        if os.path.isdir(os.path.join(dest, ".git")) and not args.force:
            print("%-16s present at %s" % (name, git("rev-parse", "--short", "HEAD", cwd=dest)))
            continue
        if args.force:
            subprocess.run(["rm", "-rf", dest])
        try:
            if is_commit(ref):
                os.makedirs(dest, exist_ok=True)
                git("init", "-q", cwd=dest)
                git("remote", "add", "origin", url, cwd=dest)
                git("fetch", "-q", "--depth", "1", "origin", ref, cwd=dest)
                git("checkout", "-q", "FETCH_HEAD", cwd=dest)
            else:
                git("clone", "-q", "--depth", "1", "--branch", ref, url, dest)
            print("%-16s %s  (%s)" % (name, git("rev-parse", "--short", "HEAD", cwd=dest), note))
        except RuntimeError as e:
            failures += 1
            print("%-16s FAILED: %s" % (name, e), file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
