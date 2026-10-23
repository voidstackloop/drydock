#!/usr/bin/env python3
"""Score a folder of Windows programs with the shipped --ai model and print how it did.

    tools/evaluate.py samples/benign samples/malware
    tools/evaluate.py --threshold 0.9 downloads/            # what a stricter bar does
    tools/evaluate.py --json out.json mine:benign theirs:malware

Each argument is a folder, optionally with the answer: ``folder:benign`` or
``folder:malware``. Without one, the folder name decides (clean, normal, good,
benign, ... against bad, virus, malicious, ...); a folder named neither is
scored and listed, but no rate is computed for it.

This is the number to trust for your own files: the model is judged on what you
give it, not on the collection it was trained on. It reads the same numbers the
scanner reads (``leakcheck ai-features``), through the same text model, so a
disagreement with ``leakcheck scan --ai`` is a bug worth reporting. Both leave
out images with no code in them (.mui and other resource-only files), which the
classifier never judges.

Needs numpy (as training does) and a built ``build/leakcheck``.
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_ai  # noqa: E402  (the model reader is shared with the trainer)

BENIGN_NAMES = {"benign", "clean", "normal", "good", "safe", "legit", "whitelist", "white"}
MALWARE_NAMES = {"malware", "malicious", "virus", "viruses", "bad", "infected", "blacklist",
                 "black", "evil"}


def parse_argument(text):
    folder, _, label = text.rpartition(":")
    if not folder:  # no colon: the whole text is the folder
        folder, label = text, ""
    label = label.lower()
    if label and label not in ("benign", "malware"):
        sys.exit(f"{text}: the label after ':' must be benign or malware")
    if not label:
        guess = os.path.basename(folder.rstrip("/")).lower()
        label = "benign" if guess in BENIGN_NAMES else "malware" if guess in MALWARE_NAMES else ""
    return folder, label


def features_of(leakcheck, folder, names):
    """Rows of numbers for the Windows programs under `folder`."""
    if not os.path.isdir(folder):
        sys.exit(f"{folder} is not a directory")
    run = subprocess.run([leakcheck, "ai-features", folder], capture_output=True, text=True)
    if run.returncode != 0:
        sys.exit(f"leakcheck ai-features {folder} failed:\n{run.stderr}")
    lines = [line for line in run.stdout.splitlines() if line and not line.startswith("#")]
    if not lines:
        return None, [], run.stderr.strip()
    rows, paths = train_ai.parse_rows(lines, names)
    return rows, paths, run.stderr.strip()


def rates(scores, truth, threshold):
    guess = [score >= threshold for score in scores]
    tp = int(sum(1 for g, t in zip(guess, truth) if g and t))
    fp = int(sum(1 for g, t in zip(guess, truth) if g and not t))
    fn = int(sum(1 for g, t in zip(guess, truth) if not g and t))
    tn = int(sum(1 for g, t in zip(guess, truth) if not g and not t))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    return {
        "threshold": round(float(threshold), 3),
        "accuracy": (tp + tn) / max(1, len(truth)),
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(1e-9, precision + recall),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("folders", nargs="+", help="folder[:benign|malware] ...")
    p.add_argument("--leakcheck", default=os.path.join(HERE, "..", "build", "leakcheck"))
    p.add_argument("--model", default=os.path.join(HERE, "..", "model", "pe-malware.ai"))
    p.add_argument("--threshold", type=float, default=None,
                   help="score above which a file counts as malware (default: the model's)")
    p.add_argument("--sweep", action="store_true",
                   help="also show false alarms against detections for rising thresholds")
    p.add_argument("--examples", type=int, default=5,
                   help="how many mistakes of each kind to name (0: none)")
    p.add_argument("--json", default="", help="write the result as JSON here")
    args = p.parse_args()

    leakcheck = os.path.normpath(args.leakcheck)
    model_path = os.path.normpath(args.model)
    if not os.path.isfile(leakcheck):
        sys.exit(f"{leakcheck} not found: build the project first (cmake --build build)")
    if not os.path.isfile(model_path):
        sys.exit(f"{model_path} not found: train one with tools/train_ai.py")

    # The headers are read from a file no model can be built for, so the model's
    # own count decides what the columns are. It is checked against each folder's
    # rows, so a model and a build that disagree are caught here, not in a scan.
    names = train_ai.feature_names(leakcheck)
    with open(model_path, encoding="utf-8") as f:
        header = {}
        for line in f:
            key, _, value = line.partition(" ")
            if key in ("features", "threshold", "trained_on", "evaluation", "accuracy"):
                header[key] = value.strip()
            if key == "trees":
                break
    model_features = int(header.get("features", 0))
    if model_features != len(names):
        sys.exit(f"{model_path} was trained on {model_features} numbers but this build reads "
                 f"{len(names)}: rebuild the model with tools/train_ai.py")
    threshold = args.threshold if args.threshold is not None else float(header.get("threshold", 0.5))

    print(f"model: {model_path}")
    print(f"  trained on {header.get('trained_on', '?')}")
    print(f"  evaluation: {header.get('evaluation', '?')} "
          f"(accuracy {float(header.get('accuracy', 0)):.3f})")
    print(f"threshold: {threshold:.2f}\n")

    result = {"model": model_path, "threshold": threshold, "folders": [], "pooled": None}
    pooled_scores, pooled_truth, pooled_paths = [], [], []
    for text in args.folders:
        folder, label = parse_argument(text)
        rows, paths, note = features_of(leakcheck, folder, names)
        if rows is None:
            print(f"{folder}: no Windows programs ({note or 'nothing readable'})")
            continue
        scores, _ = train_ai.predict_text_model(model_path, rows)
        named = f"{folder} ({label})" if label else f"{folder} (no label: listed only)"
        print(f"{named}: {len(paths)} Windows program(s)")
        flagged = [(path, float(score)) for path, score in zip(paths, scores)
                   if score >= threshold]
        entry = {"folder": folder, "label": label, "windows_programs": len(paths),
                 "flagged": len(flagged)}
        if label:
            truth = [label == "malware"] * len(paths)
            pooled_scores.extend(float(s) for s in scores)
            pooled_truth.extend(truth)
            pooled_paths.extend(paths)
            r = rates([float(s) for s in scores], truth, threshold)
            entry.update(r)
            what = "detected" if label == "malware" else "false alarms"
            print(f"  {what}: {r['tp'] + r['fp']} of {len(paths)} "
                  f"({100 * (r['tp'] + r['fp']) / len(paths):.1f}%)")
            mistakes = [(path, float(score)) for path, score in zip(paths, scores)
                        if (score >= threshold) != (label == "malware")]
            should = "missed" if label == "malware" else "false alarm"
            shown = sorted(mistakes, key=lambda kv: -kv[1])[: max(0, args.examples)]
            for path, score in shown:
                print(f"    {should}: {score:.3f}  {path}")
        else:
            for path, score in sorted(flagged, key=lambda kv: -kv[1])[: max(0, args.examples)]:
                print(f"    flagged: {score:.3f}  {path}")
        result["folders"].append(entry)

    if pooled_truth:
        pooled = rates(pooled_scores, pooled_truth, threshold)
        result["pooled"] = pooled
        print(f"\nevery labelled file together ({len(pooled_truth)}):")
        # Precision and recall need both kinds of file: with only normal folders
        # given, "0% precision" would read as a failure instead of as no answer.
        if pooled["tp"] + pooled["fn"] and pooled["fp"] + pooled["tn"]:
            print(f"  accuracy {pooled['accuracy']:.1%}   precision {pooled['precision']:.1%}   "
                  f"recall {pooled['recall']:.1%}   f1 {pooled['f1']:.3f}")
        else:
            print(f"  accuracy {pooled['accuracy']:.1%}")
        print(f"  false alarms {pooled['fp']}   missed {pooled['fn']}")
        if args.sweep:
            print("\nthreshold   false alarms   detections")
            for cut in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
                r = rates(pooled_scores, pooled_truth, cut)
                total_bad = r["tp"] + r["fn"]
                total_good = r["fp"] + r["tn"]
                print(f"  {cut:.2f}        {r['fp']:5d} of {total_good:<5d}   "
                      f"{r['tp']:5d} of {total_bad:<5d} ({100 * r['tp'] / max(1, total_bad):.1f}%)")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"\nwritten to {args.json}")


if __name__ == "__main__":
    main()
