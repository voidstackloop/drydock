#!/usr/bin/env python3
"""Measure per-rule false alarms on the reference corpus.

    python3 tools/precision.py --build build --write-doc
    python3 tools/precision.py --build build --triage     # label findings by hand

Findings are identified by the same fingerprint `--baseline` uses (type, file
relative to the project, enclosing function, message without line numbers), so a
label survives a reformat. Labels live in eval/precision-labels.tsv:

    <fingerprint>\\ttp|fp\\t<note>

The budget is policy (docs/ROADMAP.md, Phase 2): a rule with at least 20
labelled findings may not exceed 2% false alarms. A rule that does is demoted to
--strict, or cut. `--require-labels` makes CI fail while any finding on the
corpus is untriaged.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

BUDGET = 0.02
MIN_SAMPLE = 20
EXE = ".exe" if os.name == "nt" else ""


def fnv1a(text):
    h = 1469598103934665603
    for b in text.encode("utf-8"):
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def without_lines(message):
    return re.sub(r"line \d+", "line #", message)


def relative_to(path, root):
    if not path:
        return ""
    path = os.path.normpath(path)
    root = os.path.normpath(root)
    try:
        rel = os.path.relpath(path, root)
    except ValueError:  # another drive on Windows
        rel = path
    return rel.replace(os.sep, "/")


def relative_to_repo(path, name):
    """The path inside a corpus checkout, found by the project's directory name.

    A report saved on one machine has that machine's absolute paths. The label
    has to mean the same finding on another machine, or the precision gate
    cannot run in CI from the checked-in reports; the project directory is the
    one part of the path that does not move with the checkout.
    """
    p = path.replace("\\", "/")
    marker = "/" + name + "/"
    at = p.find(marker)
    return None if at < 0 else p[at + len(marker):]


def fingerprint(finding, root, repo=""):
    loc = finding.get("location", {})
    rel = relative_to_repo(loc.get("file", ""), repo) if repo else None
    key = "\x1f".join([
        finding.get("type", ""),
        rel if rel is not None else relative_to(loc.get("file", ""), root),
        loc.get("function", ""),
        without_lines(finding.get("message", "")),
    ])
    return "%016x" % fnv1a(key)


def read_manifest(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                rows.append(parts[:4])
    return rows


def read_labels(path):
    labels = {}
    if not os.path.exists(path):
        return labels
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2 or parts[1] not in ("tp", "fp"):
                sys.exit("%s:%d: expected <fingerprint>\\ttp|fp\\t<note>" % (path, no))
            labels[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
    return labels


def write_labels(path, labels):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# fingerprint\tverdict\tnote\n")
        for fp in sorted(labels):
            verdict, note = labels[fp]
            f.write("%s\t%s\t%s\n" % (fp, verdict, note))


def run_corpus(build, dest, manifest, reports, reuse, include_synthetic=False):
    leakcheck = os.path.join(build, "leakcheck" + EXE)
    if not os.path.exists(leakcheck):
        sys.exit("no %s: build first" % leakcheck)
    os.makedirs(reports, exist_ok=True)
    findings = []
    seen, missing = [], []
    for name, url, ref, note in read_manifest(manifest):
        if not include_synthetic and note.startswith("synthetic"):
            continue
        repo = os.path.join(dest, name)
        out = os.path.join(reports, name + ".json")
        saved = reuse and os.path.exists(out)
        if not os.path.isdir(repo) and not saved:
            missing.append(name)
            continue
        if not saved:
            p = subprocess.run([leakcheck, "static", "--no-cache", "--strict", "-f", "json",
                                "-o", out, repo],
                               capture_output=True, text=True, timeout=900)
            if p.returncode not in (0, 2):
                sys.exit("%s failed (%d): %s" % (name, p.returncode, p.stderr[-1000:]))
        report = json.load(open(out, encoding="utf-8"))
        seen.append((name, report.get("summary", {}).get("files_analyzed", 0)))
        for finding in report.get("findings", []):
            findings.append({"repo": name, "root": repo, "finding": finding,
                             "fp": fingerprint(finding, repo, name)})
    return findings, seen, missing


def triage(findings, labels, path):
    pending = [x for x in findings if x["fp"] not in labels]
    print("%d finding(s), %d already labelled, %d to look at"
          % (len(findings), len(findings) - len(pending), len(pending)))
    for n, item in enumerate(pending, 1):
        f = item["finding"]
        loc = f.get("location", {})
        print("\n[%d/%d] %s  %s:%s  %s"
              % (n, len(pending), f.get("type", "?"),
                 relative_to(loc.get("file", ""), item["root"]), loc.get("line", "?"),
                 f.get("message", "")[:220]))
        answer = input("true positive? [t/f/s/q] ").strip().lower()
        if answer == "q":
            break
        if answer in ("t", "f"):
            note = input("note (optional): ").strip()
            labels[item["fp"]] = ("tp" if answer == "t" else "fp", note)
            write_labels(path, labels)
        elif answer == "s":
            continue
    write_labels(path, labels)


def rates(findings, labels):
    per = {}
    for item in findings:
        rule = item["finding"].get("type", "?")
        r = per.setdefault(rule, {"total": 0, "tp": 0, "fp": 0, "unlabeled": 0})
        r["total"] += 1
        verdict = labels.get(item["fp"])
        if verdict is None:
            r["unlabeled"] += 1
        else:
            r["tp" if verdict[0] == "tp" else "fp"] += 1
    return per


def rule_enabled(build):
    """Rule id -> whether a default run reports it (strict-only rules are off)."""
    leakcheck = os.path.join(build, "leakcheck" + EXE)
    p = subprocess.run([leakcheck, "--rule-list", "-f", "json"], capture_output=True, text=True)
    if p.returncode != 0:
        return {}
    return {r["id"]: bool(r.get("enabled", True)) for r in json.loads(p.stdout)}


def doc_lines(findings, per, labels, seen, missing, corpus, enabled):
    total_tp = sum(r["tp"] for r in per.values())
    total_fp = sum(r["fp"] for r in per.values())
    labelled = total_tp + total_fp
    overall = (100.0 * total_fp / labelled) if labelled else None
    out = [
        "# Precision on the reference corpus",
        "",
        "Generated by `tools/precision.py`; do not edit by hand. Labels are in",
        "`eval/precision-labels.tsv` and are reviewed like code.",
        "",
        "## Policy",
        "",
        "* A rule with at least %d labelled findings may have at most %.0f%% false" % (MIN_SAMPLE, BUDGET * 100),
        "  alarms on this corpus. A rule that cannot meet it is demoted to `--strict`",
        "  or cut. CI regenerates this file from the saved reports and fails when an",
        "  enabled rule is over budget or a line of this file changed; the corpora",
        "  themselves are fetched only to label new findings, so the gate needs no",
        "  download.",
        "* The scanner's own false-alarm number is the per-rule table below, not an",
        "  average that a good rule can hide. A rule that is off by default still",
        "  shows its rate, marked `strict-only`, so demoting one is visible.",
        "",
        "## Corpus",
        "",
        "| Project | Files analysed |",
        "|---|---|",
    ]
    out += ["| %s | %d |" % (name, count) for name, count in seen]
    if missing:
        out += ["", "Not fetched (run `tools/fetch_corpus.py`): " + ", ".join(missing)]
    out += [
        "",
        "## Rule precision",
        "",
        "| Rule | Findings | Labelled | True | False | False-alarm rate | Budget |",
        "|---|---|---|---|---|---|---|",
    ]
    for rule, r in sorted(per.items(), key=lambda kv: (-kv[1]["total"], kv[0])):
        judged = r["tp"] + r["fp"]
        rate = ("%.1f%%" % (100.0 * r["fp"] / judged)) if judged else "—"
        strict_only = not enabled.get(rule, True)
        if judged < MIN_SAMPLE:
            status = "not triaged" if judged == 0 else "sample too small"
        elif strict_only:
            status = "strict-only (demoted)"
        else:
            status = "**OVER**" if r["fp"] / judged > BUDGET else "within"
        out.append("| `%s` | %d | %d | %d | %d | %s | %s |"
                   % (rule, r["total"], judged, r["tp"], r["fp"], rate, status))
    out += [
        "",
        "## Whole tool",
        "",
        ("* %d labelled finding(s): %d true, %d false" % (labelled, total_tp, total_fp))
        if labelled else "* No finding has been triaged yet.",
        ("* False-alarm rate on the labelled findings: **%.1f%%**" % overall)
        if overall is not None else
        "* False-alarm rate: not measured — `--triage` has not been run.",
        "* Untriaged findings: **%d** of %d (the rate above does not speak for them)"
        % (sum(r["unlabeled"] for r in per.values()), len(findings)),
        "",
        "## How the corpus is run",
        "",
        "`tools/fetch_corpus.py` clones the pinned trees in `eval/corpus.tsv` into",
        "`eval/corpus/` (git-ignored). Each is analysed once with `--no-cache`; the",
        "reports are kept under `eval/reports/` so a triage session does not re-run",
        "the analysis. Synthetic suites (Juliet) are listed but are not evidence of",
        "precision on real code.",
        "",
        "Corpus source: " + os.path.basename(corpus),
        "",
    ]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="build")
    ap.add_argument("--manifest", default="eval/corpus.tsv")
    ap.add_argument("--corpus", default="eval/corpus")
    ap.add_argument("--labels", default="eval/precision-labels.tsv")
    ap.add_argument("--reports", default="eval/reports")
    ap.add_argument("--doc", default="eval/PRECISION.md")
    ap.add_argument("--reuse", action="store_true", help="use saved reports")
    ap.add_argument("--include-synthetic", action="store_true",
                    help="also count the Juliet suite, which is not real code")
    ap.add_argument("--triage", action="store_true")
    ap.add_argument("--label-rule", action="append", default=[], metavar="RULE=TP|FP",
                    help="label every unlabelled finding of one rule (a rule-level decision)")
    ap.add_argument("--require-labels", action="store_true")
    ap.add_argument("--write-doc", action="store_true")
    args = ap.parse_args()

    findings, seen, missing = run_corpus(args.build, args.corpus, args.manifest,
                                         args.reports, args.reuse, args.include_synthetic)
    labels = read_labels(args.labels)
    for spec in args.label_rule:
        rule, _, verdict = spec.partition("=")
        verdict = verdict.lower()
        if verdict not in ("tp", "fp"):
            sys.exit("--label-rule expects RULE=TP or RULE=FP, not %r" % spec)
        n = 0
        for item in findings:
            if item["finding"].get("type") == rule and item["fp"] not in labels:
                labels[item["fp"]] = (verdict, "rule-level decision (%s)" % rule)
                n += 1
        print("labelled %d %s finding(s) as %s" % (n, rule, verdict))
        write_labels(args.labels, labels)
    if args.triage:
        triage(findings, labels, args.labels)
    per = rates(findings, labels)

    enabled = rule_enabled(args.build)
    over = [rule for rule, r in per.items()
            if enabled.get(rule, True) and r["tp"] + r["fp"] >= MIN_SAMPLE
            and r["fp"] / (r["tp"] + r["fp"]) > BUDGET]
    unlabeled = sum(r["unlabeled"] for r in per.values())
    if args.write_doc:
        with open(args.doc, "w", encoding="utf-8") as f:
            f.write("\n".join(doc_lines(findings, per, labels, seen, missing, args.manifest,
                                      enabled)))
        print("wrote %s (%d finding(s), %d untriaged)" % (args.doc, len(findings), unlabeled))
    if over:
        print("over budget: " + ", ".join(sorted(over)), file=sys.stderr)
        return 1
    if args.require_labels and unlabeled:
        print("%d finding(s) are not triaged; run --triage" % unlabeled, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
