#!/usr/bin/env python3
"""Time static analysis on a fixed 500,000-line tree and enforce the budgets.

    python3 tools/bench_static.py --build build [--lines 500000] [--update-doc]

Budgets (docs/ROADMAP.md, Phase 3): no more than 2 minutes per million lines on
one core, and no more than 1 GB of RSS on a 500k-line tree.

The tree is made from this repository's own sources, copied under new names
until it is the requested size. It is deterministic, so the numbers compare
across commits and machines. Cold deletes the cache; warm reruns on the same
tree; touched appends one comment to one file.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

BUDGET_SECONDS_PER_MILLION = 120.0
BUDGET_RSS_MB = 1024.0
EXE = ".exe" if os.name == "nt" else ""


def sources(source):
    roots = ["static-engine/src", "reporter/src", "dynamic-engine/src/preload"]
    out = []
    for root in roots:
        for base, _, names in os.walk(os.path.join(source, root)):
            for name in names:
                if name.endswith((".c", ".cc", ".cpp")):
                    out.append(os.path.join(base, name))
    return sorted(out)


def make_tree(source, dest, lines):
    files = sources(source)
    if not files:
        sys.exit("no sources to build the benchmark from")
    total = 0
    index = 0
    while total < lines:
        src = files[index % len(files)]
        with open(src, encoding="utf-8", errors="replace") as f:
            text = f.read()
        text = "// benchmark copy %d of %s\n" % (index, os.path.basename(src)) + text
        path = os.path.join(dest, "bench_%05d%s" % (index, os.path.splitext(src)[1]))
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        total += text.count("\n")
        index += 1
    return total, index


def run_one(leakcheck, tree, output):
    started = time.perf_counter()
    before = os.times()
    p = subprocess.run([leakcheck, "static", "-j", "1", "-f", "json", "-o", output, tree],
                       capture_output=True, text=True)
    elapsed = time.perf_counter() - started
    after = os.times()
    if p.returncode not in (0, 2):
        sys.exit("leakcheck failed (%d): %s" % (p.returncode, p.stderr[-2000:]))
    # ru_maxrss of children is in KB on Linux, bytes on macOS. The CI job runs
    # on Linux; the other platforms only report the wall time.
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        rss_mb = rss / (1024.0 * 1024.0) if sys.platform == "darwin" else rss / 1024.0
    except Exception:
        rss_mb = float("nan")
    del before, after
    return elapsed, rss_mb, p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="build")
    ap.add_argument("--source", default=".")
    ap.add_argument("--lines", type=int, default=500000)
    ap.add_argument("--update-doc", action="store_true")
    args = ap.parse_args()

    leakcheck = os.path.abspath(os.path.join(args.build, "leakcheck" + EXE))
    if not os.path.exists(leakcheck):
        sys.exit("no %s: build first" % leakcheck)

    with tempfile.TemporaryDirectory(prefix="leakcheck-bench-") as tmp:
        tree = os.path.join(tmp, "src")
        os.makedirs(tree)
        lines, count = make_tree(args.source, tree, args.lines)
        output = os.path.join(tmp, "report.json")

        shutil.rmtree(os.path.join(tree, ".leakcheck-cache"), ignore_errors=True)
        cold, cold_rss, _ = run_one(leakcheck, tree, output)
        warm, warm_rss, _ = run_one(leakcheck, tree, output)
        with open(os.path.join(tree, "bench_00000.c"), "a") as f:
            f.write("// touched\n")
        touched, touched_rss, p = run_one(leakcheck, tree, output)

        # The same tree with eight workers must produce the same report.
        threaded = os.path.join(tmp, "threaded.json")
        subprocess.run([leakcheck, "static", "-j", "8", "-f", "json", "-o", threaded, tree],
                       capture_output=True, text=True)
        same = json.load(open(output))["findings"] == json.load(open(threaded))["findings"]

    rate = cold / (lines / 1_000_000.0)
    ok = rate <= BUDGET_SECONDS_PER_MILLION and cold_rss <= BUDGET_RSS_MB and same
    table = [
        "| Run | Seconds | RSS (MB) |",
        "|---|---|---|",
        "| cold (`--no-cache` equivalent) | %.2f | %.0f |" % (cold, cold_rss),
        "| warm (cache) | %.2f | %.0f |" % (warm, warm_rss),
        "| one file touched | %.2f | %.0f |" % (touched, touched_rss),
        "",
        "* %s lines in %d files" % (format(lines, ","), count),
        "* %.1f s per million lines on one core (budget %.0f)" % (rate, BUDGET_SECONDS_PER_MILLION),
        "* %s at 8 workers" % ("same findings" if same else "DIFFERENT findings"),
        "* %s" % ("within budget" if ok else "OVER BUDGET"),
    ]
    text = "\n".join(table)
    print(text)
    if args.update_doc:
        doc = [
            "# Static analysis performance",
            "",
            "Generated by `tools/bench_static.py`; do not edit by hand.",
            "",
            *table,
            "",
            "The tree is deterministic (copies of this repository's sources under new",
            "names), so a commit that makes analysis slower shows up as a change here.",
            "",
        ]
        with open(os.path.join(args.source, "eval", "PERFORMANCE.md"), "w") as f:
            f.write("\n".join(doc))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
