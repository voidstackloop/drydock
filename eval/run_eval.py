#!/usr/bin/env python3
"""Graded evaluation: how well leakcheck finds bugs at three levels.

Each program in eval/cases declares in its first lines:
    // level: basic | hard | expert
    // mode: dynamic | static | scan
    // expect: <finding type> ... | none      (none: a trap, correct code)
    // what: one line on the bug
    // args: extra leakcheck options          (optional)
    // env: NAME=value ...                    (optional)
    // with: parts/x.c ...                    (static: the program's other files)

A case passes when the problem findings (errors and warnings) are exactly
the expected types: a missing one is a MISS, an extra one a FALSE ALARM.

usage: eval/run_eval.py [--build DIR] [--out RESULTS.md] [filter]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LEVELS = ["basic", "hard", "expert"]


def meta(path):
    m = {"args": "", "env": "", "expect": "none", "what": "", "level": "", "mode": "dynamic",
         "with": ""}
    with open(path) as f:
        for line in f.read().splitlines()[:12]:
            hit = re.match(r"\s*//\s*(level|mode|expect|what|args|env|with):\s*(.*)", line)
            if hit:
                m[hit.group(1)] = hit.group(2).strip()
    m["expect"] = set() if m["expect"] == "none" else set(m["expect"].split())
    return m


def run_case(path, m, lc, work):
    name = os.path.splitext(os.path.basename(path))[0]
    out = os.path.join(work, name + ".json")
    env = dict(os.environ)
    for kv in m["env"].split():
        k, _, v = kv.partition("=")
        env[k] = v
    if m["mode"] == "static":
        target = path
        if m["with"]:  # other files of the same program (cases/parts/...)
            target = os.path.join(work, name + "_src")
            os.makedirs(target)
            for p in [path] + [os.path.join(os.path.dirname(path), w) for w in m["with"].split()]:
                shutil.copy(p, target)
        cmd = [lc, "-f", "json", "-o", out, "static", target]
    elif m["mode"] == "scan":
        # The case file carries the header. A companion (// with:) is the
        # file whose name and bytes are scanned; otherwise the case itself.
        target = path
        if m["with"]:
            target = os.path.join(work, name + "_files")
            os.makedirs(target)
            for w in m["with"].split():
                src = os.path.join(os.path.dirname(path), w)
                shutil.copy(src, os.path.join(target, os.path.basename(src)))
        cmd = [lc, "-f", "json", "-o", out, "scan", target]
    else:
        binary = os.path.join(work, name)
        cc = "g++" if path.endswith(".cpp") else "gcc"
        std = ["-std=c++17"] if cc == "g++" else []
        build = subprocess.run([cc, *std, "-g", "-O0", "-pthread", "-w", "-o", binary, path],
                               capture_output=True, text=True)
        if build.returncode != 0:
            return None, "compile error: " + build.stderr.strip().splitlines()[0]
        cmd = [lc, "-f", "json", "-o", out, "dynamic", *m["args"].split(), binary]
    t0 = time.time()
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env,
                       stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, "timed out (the program hung)"
    took = time.time() - t0
    try:
        with open(out) as f:
            report = json.load(f)
    except (OSError, ValueError):
        return None, "no report"
    found = sorted({f["type"] for f in report["findings"]
                    if f.get("severity") in ("error", "warning")})
    return (set(found), took), ""


def verdict(expect, found):
    if not expect:
        return "PASS" if not found else "FALSE ALARM"
    if not expect <= found:
        return "MISS"
    return "PASS" if found == expect else "PASS + EXTRA"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=os.path.join(HERE, "..", "build"))
    ap.add_argument("--out", default=os.path.join(HERE, "RESULTS.md"))
    ap.add_argument("filter", nargs="?", default="")
    a = ap.parse_args()
    lc = os.path.abspath(os.path.join(a.build, "leakcheck"))
    cases_dir = os.path.join(HERE, "cases")
    cases = sorted(os.path.join(cases_dir, f) for f in os.listdir(cases_dir)
                   if f.endswith((".c", ".cpp")) and a.filter in f)
    rows = []
    with tempfile.TemporaryDirectory() as work:
        for path in cases:
            m = meta(path)
            res, err = run_case(path, m, lc, work)
            found, took = res if res else (set(), 0.0)
            v = verdict(m["expect"], found) if res else "ERROR"
            rows.append((m, os.path.basename(path), found, v, took, err))
            print(f"{v:<12} {m['level']:<6} {m['mode']:<7} {os.path.basename(path):<34} "
                  f"expect {' '.join(sorted(m['expect'])) or 'none'}; "
                  f"found {' '.join(sorted(found)) or 'none'} {err}", flush=True)

    lines = ["# leakcheck evaluation", "",
             "Generated by `eval/run_eval.py`. A case passes when its problem findings",
             "(errors and warnings) are exactly the expected types; traps are correct",
             "programs that must produce none.", "",
             "| Level | Bug cases found | Traps silent | Extra findings |",
             "|---|---|---|---|"]
    for level in LEVELS:
        mine = [r for r in rows if r[0]["level"] == level]
        bugs = [r for r in mine if r[0]["expect"]]
        traps = [r for r in mine if not r[0]["expect"]]
        found = sum(r[3].startswith("PASS") for r in bugs)
        silent = sum(r[3] == "PASS" for r in traps)
        extra = sum(r[3] == "PASS + EXTRA" for r in bugs)
        lines.append(f"| {level} | {found} of {len(bugs)} | {silent} of {len(traps)} | {extra} |")
    lines += ["", "| Case | Level | Mode | What | Expected | Found | Verdict |",
              "|---|---|---|---|---|---|---|"]
    for m, name, found, v, took, err in rows:
        lines.append(f"| `{name}` | {m['level']} | {m['mode']} | {m['what']} | "
                     f"{' '.join(sorted(m['expect'])) or 'none'} | "
                     f"{' '.join(sorted(found)) or err or 'none'} | **{v}** |")
    with open(a.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    bad = [r for r in rows if not r[3].startswith("PASS")]
    print(f"\n{len(rows) - len(bad)} of {len(rows)} cases pass; results in {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
