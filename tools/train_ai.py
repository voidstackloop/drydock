#!/usr/bin/env python3
"""Train the model behind ``leakcheck scan --ai`` and export it for the C++ loader.

The classifier is a gradient-boosted forest of small decision trees (LightGBM)
over the numbers ``leakcheck ai-features`` reads out of a Windows program: header
fields, section layout, import names, entropy and string counts. Training data
are the PE files under ``data/samples/``: a ``benign*`` folder (label 0) and a
``malware*`` folder (label 1), from tools/fetch_dataset.py and
tools/fetch_benign.py.

    python3 -m venv .venv-train
    .venv-train/bin/pip install numpy lightgbm
    .venv-train/bin/python tools/train_ai.py

It prints the measured quality on samples the model never saw, writes
``model/pe-malware.ai`` (the text model the scanner loads) and
``model/pe-malware.metrics.json``.

The split is by sample family, not by file: two files with the same import
table (the same imphash) stay on one side, so a model that only memorises a
family cannot look accurate on its own copies. ``--split random`` reproduces
the older, more flattering split for comparison.

Accuracy here is accuracy on this dataset. The samples are real binaries, but
they are a fixed, fairly old, mostly unpacked collection: a model that scores
0.9x on this split will score lower on a fresh sample of the modern internet,
on packed or heavily obfuscated files, and on 64-bit installers that look
nothing like either class. That is why a verdict is reported as a warning with
the score, not as proof.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

import numpy as np

SEED = 7
# Every `benign*` folder under --samples is label 0, every `malware*` folder label
# 1, so benign-modern/ (tools/fetch_benign.py) sits next to the old corpus
# instead of replacing it.
ORIGIN_NAMES = {
    "benign": "crovax/CNN_Project (an old Windows system)",
    "benign-modern": "a Windows 11 installation",
    "malware": "crovax/CNN_Project",
    "malware-bazaar": "MalwareBazaar daily batches (recent droppers, packed, 64-bit)",
}
READ_LIMIT = 16 << 20  # same prefix the scanner reads
# Features the shipped model leaves out, because on this collection they mark
# the source rather than the program. The normal programs are a Windows
# installation's files (100% have a debug directory and a PDB path, 98% a Rich
# header) and the malicious ones were stripped (8%, 6%, 54%). Every malicious
# sample is also a 32-bit executable, so bitness would read as "32-bit means
# malware". Measured with them gone: same 100% on the family-grouped split, and
# fewer false alarms on normal 32-bit programs the model never saw.
SHORTCUT_FEATURES = (
    "dir_debug_log",
    "pdb_path",
    "rich_header",
    "checksum_nonzero",
    "timestamp_zero",
    "dll_characteristics",
    "pe32_plus",
)


def class_folders(samples):
    """(folder, label, name) for each benign*/malware* directory under `samples`."""
    found = []
    for entry in sorted(os.scandir(samples), key=lambda e: e.name):
        if not entry.is_dir():
            continue
        name = entry.name.lower()
        label = 0 if name.startswith("benign") else 1 if name.startswith("malware") else None
        if label is not None:
            found.append((entry.path, label, entry.name))
    if not found:
        sys.exit(f"no benign*/malware* folder under {samples}")
    return found


def folder_stamp(folder):
    """How many files the folder holds and when it last changed."""
    count, newest = 0, 0
    for entry in os.scandir(folder):
        if entry.is_file():
            count += 1
            newest = max(newest, entry.stat().st_mtime_ns)
    return count, newest


# Raised when `leakcheck ai-features` changes which files it lists a row for, so a
# cache written by an older build is read again instead of trained on.
FEATURE_READER = 2


def features_of(leakcheck, folder, cache, force, columns):
    """Run `leakcheck ai-features` and keep the rows, one line per PE file.

    The cached rows carry a stamp of the folder and of the column count: a
    sample set that grew or changed since the last run, or a build that reads
    more numbers per file, is read again instead of training on a stale
    picture of it.
    """
    stamp = folder_stamp(folder)
    if not force and os.path.exists(cache):
        with open(cache, encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
        if lines and lines[0] == f"#stamp {FEATURE_READER} {stamp[0]} {stamp[1]} {columns}":
            print(f"  {folder}: using {cache} ({len(lines) - 1} rows)")
            return lines[1:]
    started = time.time()
    print(f"  {folder}: reading features", end="", flush=True)
    run = subprocess.run([leakcheck, "ai-features", folder], capture_output=True, text=True)
    if run.returncode != 0:
        sys.exit(f"leakcheck ai-features {folder} failed:\n{run.stderr}")
    lines = [line for line in run.stdout.splitlines() if line and not line.startswith("#")]
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    with open(cache, "w", encoding="utf-8") as f:
        f.write(f"#stamp {FEATURE_READER} {stamp[0]} {stamp[1]} {columns}\n" + "\n".join(lines) + "\n")
    print(f": {len(lines)} file(s) in {time.time() - started:.1f}s")
    return lines


def feature_names(leakcheck):
    # Any file will do: the header is printed whether or not it is a PE.
    run = subprocess.run([leakcheck, "ai-features", leakcheck], capture_output=True, text=True)
    for line in run.stdout.splitlines():
        if line.startswith("#features"):
            return line.split()[1:]
    sys.exit("could not read the feature names from leakcheck ai-features")


def parse_rows(lines, names):
    """Rows of numbers, refusing anything whose column count does not match."""
    rows, paths = [], []
    for line in lines:
        path, _, value = line.partition("\t")
        numbers = (value if value else line).split()
        if len(numbers) != len(names):
            sys.exit(f"a features line has {len(numbers)} values, expected {len(names)}")
        rows.append([float(x) for x in numbers])
        paths.append(path)
    return np.asarray(rows, dtype=np.float64), paths


# ---- the same program, reached by its import table --------------------------------
#
# imphash is the hash VirusTotal and the malware corpora use to say "these files
# are the same family": the imported "dll.function" pairs, renamed to one string
# and hashed. Two builds of one family with different section names or timestamps
# still share it, which is exactly the pair that must not sit on two sides of the
# split.


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0] if o + 2 <= len(b) else 0


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0] if o + 4 <= len(b) else 0


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0] if o + 8 <= len(b) else 0


def _cstring(b, o, limit=512):
    if o <= 0 or o >= len(b):
        return ""
    end = b.find(b"\0", o, min(len(b), o + limit))
    if end < 0:
        return ""
    return b[o:end].decode("latin-1", "replace")


def imphash(raw):
    """The imphash of a PE image, or "" when it cannot be read."""
    if len(raw) < 64 or raw[:2] != b"MZ":
        return ""
    pe = _u32(raw, 0x3C)
    if pe + 24 > len(raw) or raw[pe : pe + 4] != b"PE\0\0":
        return ""
    opt = pe + 24
    optsize = _u16(raw, pe + 20)
    magic = _u16(raw, opt)
    if magic == 0x20B:
        plus = True
    elif magic == 0x10B:
        plus = False
    else:
        return ""
    dd = opt + (112 if plus else 96)
    imp_rva, imp_size = _u32(raw, dd + 8), _u32(raw, dd + 12)
    if not imp_rva or not imp_size:
        return ""

    sections = []
    for i in range(min(_u16(raw, pe + 6), 96)):
        s = opt + optsize + i * 40
        if s + 40 > len(raw):
            break
        sections.append((_u32(raw, s + 8), _u32(raw, s + 12), _u32(raw, s + 16), _u32(raw, s + 20)))

    def off_of(rva):
        for vsize, vaddr, rawsize, rawptr in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize) and rva - vaddr < rawsize:
                return rawptr + (rva - vaddr)
        return 0

    def name_of(rva):
        off = off_of(rva)
        return _cstring(raw, off) if off else ""

    parts, width = [], 8 if plus else 4
    at = off_of(imp_rva)
    for d in range(512):
        if not at:
            break
        desc = at + d * 20
        if desc + 20 > len(raw):
            break
        original, name_rva, first = (
            _u32(raw, desc),
            _u32(raw, desc + 12),
            _u32(raw, desc + 16),
        )
        thunk_rva = original or first
        if not name_rva and not thunk_rva:
            break
        dll = name_of(name_rva).lower()
        for ext in (".dll", ".ocx", ".sys"):
            if dll.endswith(ext):
                dll = dll[: -len(ext)]
        thunk = off_of(thunk_rva)
        if not thunk:
            continue
        ordinal_bit = 1 << (63 if plus else 31)
        for k in range(4096):
            where = thunk + k * width
            if where + width > len(raw):
                break
            value = _u64(raw, where) if plus else _u32(raw, where)
            if not value:
                break
            if value & ordinal_bit:
                parts.append(f"{dll}.ord{value & (ordinal_bit - 1)}")
            else:
                parts.append(f"{dll}.{name_of(value & 0x7FFFFFFF).lower()}")
    if not parts:
        return ""
    return hashlib.md5(",".join(parts).encode()).hexdigest()


def cluster_keys(paths, cache):
    """One group id per path: the imphash, or the file itself when it has none.

    Cached by path, size and change time, so a second run does not read 3.6 GB
    of samples again.
    """
    saved = {}
    if os.path.exists(cache):
        with open(cache, encoding="utf-8") as f:
            for line in f:
                path, mtime, size, key = line.rstrip("\n").split("\t")
                saved[path] = (mtime, size, key)
    keys, changed, out = [], 0, {}
    started = time.time()
    for path in paths:
        st = os.stat(path)
        mtime, size = str(st.st_mtime_ns), str(st.st_size)
        old = saved.get(path)
        if old and old[0] == mtime and old[1] == size:
            out[path] = old[2]
            continue
        try:
            with open(path, "rb") as f:
                raw = f.read(READ_LIMIT)
        except OSError:
            raw = b""
        key = imphash(raw)
        out[path] = "imphash:" + key if key else "file:" + hashlib.md5(raw).hexdigest()
        changed += 1
    if changed:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        with open(cache, "w", encoding="utf-8") as f:
            for path, st in ((p, os.stat(p)) for p in paths):
                f.write(f"{path}\t{st.st_mtime_ns}\t{st.st_size}\t{out[path]}\n")
        print(f"  grouped {len(paths)} files in {time.time() - started:.1f}s "
              f"({changed} read, {len(saved) - changed if changed else 0} cached)")
    keys = [out[p] for p in paths]
    return keys


# ---- splits ----------------------------------------------------------------------


def split_index(y, fraction, rng):
    """Stratified: each class is cut in the same proportions."""
    picked = []
    for label in np.unique(y):
        idx = np.flatnonzero(y == label)
        rng.shuffle(idx)
        picked.append(idx[: int(round(fraction * len(idx)))])
    return np.concatenate(picked)


def split_by_group(y, groups, rng, test=0.15, valid=0.15):
    """70/15/15 by group: no two files of one family end up on different sides."""
    members = {}
    for i, g in enumerate(groups):
        members.setdefault(g, []).append(i)
    test_groups, valid_groups = set(), set()
    for label in (0, 1):
        ids = [g for g, rows in members.items() if y[rows[0]] == label]
        rng.shuffle(ids)
        total = sum(len(members[g]) for g in ids)
        got = 0
        for g in ids:
            if got >= round(test * total):
                break
            test_groups.add(g)
            got += len(members[g])
        got = 0
        for g in ids:
            if g in test_groups:
                continue
            if got >= round(valid * total):
                break
            valid_groups.add(g)
            got += len(members[g])
    test_idx = np.array([i for i, g in enumerate(groups) if g in test_groups], dtype=int)
    valid_idx = np.array([i for i, g in enumerate(groups) if g in valid_groups], dtype=int)
    train_idx = np.array(
        [i for i, g in enumerate(groups) if g not in test_groups and g not in valid_groups],
        dtype=int,
    )
    return train_idx, valid_idx, test_idx


def measure(score, truth, threshold):
    """Accuracy, precision, recall, F1, AUC at one threshold."""
    guess = score >= threshold
    tp = int(np.sum(guess & truth))
    fp = int(np.sum(guess & ~truth))
    fn = int(np.sum(~guess & truth))
    tn = int(np.sum(~guess & ~truth))
    accuracy = (tp + tn) / max(1, len(truth))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    order = np.argsort(score)
    ranks = np.empty(len(score))
    ranks[order] = np.arange(1, len(score) + 1)
    auc = (np.sum(ranks[truth]) - np.sum(truth) * (np.sum(truth) + 1) / 2) / max(
        1, np.sum(truth) * np.sum(~truth)
    )
    specificity = tn / max(1, tn + fp)
    return {
        "accuracy": float(accuracy),
        # the two classes no longer hold equal numbers, so this is the accuracy a
        # model that always answered "normal" would not get by accident
        "balanced_accuracy": float((recall + specificity) / 2),
        "precision": float(precision),
        "recall": float(recall),
        "specificity": float(specificity),
        "f1": float(f1),
        "auc": float(auc),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def best_threshold(score, truth):
    """Highest F1, but never below 1/2: a file is called malware only when the
    model is more sure than not. A lower bar would find a little more and
    accuse far more."""
    best = (0.0, 0.5)
    for cut in np.arange(0.5, 0.96, 0.01):
        f1 = measure(score, truth, cut)["f1"]
        if f1 > best[0]:
            best = (f1, float(cut))
    return round(best[1], 2)


def export_model(booster, names, model_names, feature_map, threshold, metrics, trained_on, path,
                 evaluation):
    """The text format static-engine/src/ai_model.cpp reads.

    The model always declares every feature the scanner computes (`model_names`),
    and each split is written at the column it has in that full vector. A model
    trained on a subset (--exclude) therefore still fits the numbers the scanner
    hands it, instead of being refused for a count mismatch.
    """
    dump = booster.dump_model(num_iteration=booster.best_iteration)
    if dump.get("average_output"):
        sys.exit("refusing to export: LightGBM folded a bias into the leaves "
                 "(train with boost_from_average=false)")

    def node_lines(node, out):
        """Append the subtree to `out` and return the index of its root.

        The parent is reserved first, so a subtree's nodes follow it in order and
        every index can be written once its children are known.
        """
        if "leaf_index" in node and "split_index" not in node:
            index = len(out)
            out.append((-1, 0.0, 0, 0, 1, node["leaf_value"]))
            return index
        index = len(out)
        out.append(None)
        left = node_lines(node["left_child"], out)
        right = node_lines(node["right_child"], out)
        out[index] = (node["split_feature"], node["threshold"], left, right, 0, 0.0)
        return index

    with open(path, "w", encoding="utf-8") as f:
        f.write("leakcheck-ai 1\n")
        f.write(f"features {len(model_names)}\n")
        f.write("feature_names " + " ".join(model_names) + "\n")
        f.write(f"trained_on {trained_on}\n")
        f.write(f"evaluation {evaluation}\n")
        f.write(f"threshold {threshold:.6f}\n")
        f.write(f"accuracy {metrics['accuracy']:.6f}\n")
        f.write(f"precision {metrics['precision']:.6f}\n")
        f.write(f"recall {metrics['recall']:.6f}\n")
        trees = dump["tree_info"]
        f.write(f"trees {len(trees)}\n")
        for tree in trees:
            nodes = []
            node_lines(tree["tree_structure"], nodes)
            assert all(n is not None for n in nodes)
            f.write(f"tree {len(nodes)}\n")
            for feature, cut, left, right, leaf, value in nodes:
                column = feature_map[feature] if feature >= 0 else -1
                f.write(f"{column} {cut:.17g} {left} {right} {leaf} {value:.17g}\n")
        f.write("end\n")
    return len(trees)


def predict_text_model(path, x):
    """Inference over the exported file, to prove the export is what LightGBM says."""
    trees = []
    threshold = 0.5
    features = 0
    with open(path, encoding="utf-8") as f:
        tokens = f.read().split("\n")
    i = 0
    while i < len(tokens):
        line = tokens[i]
        if line.startswith("threshold "):
            threshold = float(line.split()[1])
        elif line.startswith("features "):
            features = int(line.split()[1])
        elif line.startswith("trees "):
            count = int(line.split()[1])
            for _ in range(count):
                i += 1
                nodes = int(tokens[i].split()[1])
                tree = []
                for _ in range(nodes):
                    i += 1
                    tree.append(tokens[i].split())
                trees.append(tree)
        i += 1
    if not trees or not features:
        sys.exit("the exported model could not be read back")
    raw = np.zeros(len(x))
    for tree in trees:
        at = np.zeros(len(x), dtype=np.int64)
        done = np.zeros(len(x), dtype=bool)
        for _ in range(len(tree)):
            feature = np.array([int(n[0]) for n in tree])
            cut = np.array([float(n[1]) for n in tree])
            left = np.array([int(n[2]) for n in tree])
            right = np.array([int(n[3]) for n in tree])
            value = np.array([float(n[5]) for n in tree])
            leaf = np.array([int(n[4]) for n in tree])
            here = at
            take = x[np.arange(len(x)), feature[here]] <= cut[here]
            nxt = np.where(take, left[here], right[here])
            is_leaf = (leaf[here] == 1) & ~done
            raw += np.where(is_leaf, value[here], 0.0)
            done |= is_leaf
            at = np.where(done, here, nxt)
            if done.all():
                break
    return 1.0 / (1.0 + np.exp(-raw)), threshold


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--samples", default="data/samples",
                   help="benign*/ and malware*/ folders under it")
    p.add_argument("--cache", default="data/features", help="where the extracted numbers are kept")
    p.add_argument("--leakcheck", default="build/leakcheck")
    p.add_argument("--model", default="model/pe-malware.ai")
    p.add_argument("--trees", type=int, default=400, help="boosting rounds (the ceiling)")
    p.add_argument("--exclude", default=",".join(SHORTCUT_FEATURES),
                   help="comma-separated feature names to leave out (default: "
                        "the features that mark how a sample was built or collected; "
                        "--exclude '' keeps everything)")
    p.add_argument("--split", choices=("grouped", "random"), default="grouped",
                   help="grouped keeps one family on one side of the split (default)")
    p.add_argument("--modern-weight", type=float, default=1.0,
                   help="weight of the extra normal folders (benign-modern/) against the "
                        "old corpus, 1.0 for equal weight (default: 1.0; lower trades "
                        "false alarms on today's programs for the old corpus)")
    p.add_argument("--force", action="store_true", help="ignore the cached features")
    args = p.parse_args()

    leakcheck = args.leakcheck
    if not os.path.isfile(leakcheck):
        sys.exit(f"{leakcheck} not found: build the project first (cmake --build build)")
    try:
        import lightgbm as lgb
    except ImportError:
        sys.exit("lightgbm is missing: pip install numpy lightgbm (or use .venv-train)")

    read_names = feature_names(leakcheck)  # every column this build prints
    dropped = [name.strip() for name in args.exclude.split(",") if name.strip()]
    missing = [name for name in dropped if name not in read_names]
    if missing:
        sys.exit(f"--exclude does not know: {', '.join(missing)}")
    columns = [i for i, name in enumerate(read_names) if name not in dropped]
    names = [read_names[i] for i in columns]
    print(f"{len(names)} of {len(read_names)} features"
          + (f" ({len(dropped)} left out)" if dropped else ""))

    xs, full_xs, ys, paths, origins = [], [], [], [], []
    for path, label, name in class_folders(args.samples):
        cache = os.path.join(args.cache, f"{name}.tsv")
        lines = features_of(leakcheck, path, cache, args.force, len(read_names))
        if not lines:
            print(f"  {name}: no Windows programs, skipped")
            continue
        rows, row_paths = parse_rows(lines, read_names)
        print(f"  {name}: {len(rows)} samples")
        xs.append(rows[:, columns])
        full_xs.append(rows)
        ys.append(np.full(len(rows), label))
        paths.extend(row_paths)
        origins.extend([name] * len(rows))
    if not xs:
        sys.exit(f"no Windows programs under {args.samples}: run tools/fetch_dataset.py first")
    x = np.vstack(xs)
    x_full = np.vstack(full_xs)
    y = np.concatenate(ys)

    # Two files with identical numbers are one sample: keeping both would put a
    # copy of a training file into the test split and inflate the score.
    _, unique = np.unique(x, axis=0, return_index=True)
    if len(unique) < len(x):
        print(f"dropped {len(x) - len(unique)} duplicate feature row(s)")
        keep = np.sort(unique)
        x, x_full, y = x[keep], x_full[keep], y[keep]
        paths = [paths[i] for i in keep]
        origins = [origins[i] for i in keep]

    # Nothing is thrown away any more: the classes are balanced by the weight of
    # each row, so the old corpus and the modern one can both be learned at once.
    # (Cutting rows to fit used to leave 255 of the old normal files, and those
    # were exactly the ones the model then got wrong.)
    weights = np.ones(len(x))
    modern = np.array([i for i, o in enumerate(origins) if o != "benign" and y[i] == 0])
    if args.modern_weight != 1.0 and len(modern):
        weights[modern] = args.modern_weight
    mass = [float(weights[y == k].sum()) for k in (0, 1)]
    if mass[0] > 0 and mass[1] > 0 and mass[0] != mass[1]:
        # "accuracy" has to mean something: on a set that is two thirds normal,
        # always answering "normal" would already be right two times in three.
        up = max(mass) / min(mass)
        weights[y == int(np.argmin(mass))] *= up
        mass = [float(weights[y == k].sum()) for k in (0, 1)]
    print(f"{len(x)} samples kept ({int(np.sum(y == 1))} malicious, {int(np.sum(y == 0))} "
          f"normal), weighted {mass[0]:.0f} against {mass[1]:.0f}")

    rng = np.random.default_rng(SEED)
    if args.split == "grouped":
        groups = cluster_keys(paths, os.path.join(args.cache, "imphash.tsv"))
        sizes = {}
        for g in groups:
            sizes[g] = sizes.get(g, 0) + 1
        biggest = max(sizes.values()) if sizes else 0
        print(f"{len(sizes)} cluster(s) of files that share an import table "
              f"(largest: {biggest} files)")
        train_idx, valid_idx, test_idx = split_by_group(y, groups, rng)
        evaluation = "grouped by imphash: no cluster on two sides of the split"
    else:
        test_idx = split_index(y, 0.15, rng)
        rest = np.setdiff1d(np.arange(len(y)), test_idx)
        valid_idx = rest[split_index(y[rest], 0.176, rng)]  # 15% of everything
        train_idx = np.setdiff1d(rest, valid_idx)
        evaluation = "random: samples of one family may sit on both sides"
    print(f"train {len(train_idx)}, validate {len(valid_idx)}, test {len(test_idx)}")
    for split, idx in (("train", train_idx), ("validate", valid_idx), ("test", test_idx)):
        if len(idx) == 0:
            sys.exit(f"the {split} split is empty: too few samples for a {args.split} split")

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "min_data_in_leaf": 20,
        "feature_fraction": 0.85,
        "bagging_fraction": 0.85,
        "bagging_freq": 1,
        "lambda_l2": 1.0,
        "boost_from_average": False,  # the exported model adds no hidden bias
        "num_threads": os.cpu_count() or 4,
        "verbose": -1,
        "seed": SEED,
        "deterministic": True,
    }
    train = lgb.Dataset(x[train_idx], label=y[train_idx], weight=weights[train_idx],
                        feature_name=names)
    valid = lgb.Dataset(x[valid_idx], label=y[valid_idx], weight=weights[valid_idx],
                        feature_name=names, reference=train)
    booster = lgb.train(params, train, num_boost_round=args.trees, valid_sets=[valid],
                        callbacks=[lgb.early_stopping(40, verbose=False),
                                   lgb.log_evaluation(50)])

    # The threshold is chosen on the validation split alone.
    p_valid = booster.predict(x[valid_idx], num_iteration=booster.best_iteration)
    threshold = best_threshold(p_valid, y[valid_idx] == 1)

    # What is reported is the test split: neither training nor the threshold ever
    # looked at it.
    p_test = booster.predict(x[test_idx], num_iteration=booster.best_iteration)
    truth = y[test_idx] == 1
    used = {name: origins.count(name) for name in sorted(set(origins))}
    metrics = measure(p_test, truth, threshold)
    # A single accuracy hides which programs it is getting wrong. This collection
    # is mostly 64-bit DLLs on the normal side and 32-bit executables on the
    # malicious side, so a model can win by learning "64-bit DLL means safe".
    # The cell that holds no such shortcut is the 32-bit executable one; the
    # false-alarm rate there is the number to watch.
    cells = {}
    plus_column = read_names.index("pe32_plus")
    for row, label, called in zip(test_idx, truth, p_test >= threshold):
        bits = "64" if x_full[row, plus_column] else "32"
        ext = os.path.splitext(paths[row])[1].lower()
        kind = "dll" if ext in (".dll", ".ocx", ".cpl", ".sys", ".drv") else "exe"
        name = f"{'malware' if label else 'normal'} {bits}-bit {kind}"
        cell = cells.setdefault(name, {"n": 0, "called_malware": 0})
        cell["n"] += 1
        cell["called_malware"] += int(called)
    metrics["cells"] = cells
    extra = [k for k, i in enumerate(test_idx) if origins[i] != "benign" and y[i] == 0]
    metrics["extra_normal"] = {
        "n": len(extra),
        "called_malware": int(np.sum(p_test[extra] >= threshold)) if extra else 0,
        "weight": args.modern_weight,
    }
    metrics.update({
        "threshold": threshold,
        "accuracy_at_0.5": float(np.mean((p_test >= 0.5) == truth)),
        "test_size": int(len(test_idx)),
        "trees": int(booster.best_iteration),
        "features": len(names),
        "model_features": len(read_names),
        "origins": used,
        "excluded": dropped,
        "split": args.split,
        "samples": int(len(x)),
    })
    if args.split == "grouped":
        train_groups = set(groups[i] for i in train_idx)
        test_groups = set(groups[i] for i in test_idx)
        metrics["clusters"] = {
            "all": len(set(groups)),
            "train": len(train_groups),
            "test": len(test_groups),
            "test_shared_with_train": len(test_groups & train_groups),
        }

    model_folder = os.path.dirname(args.model)
    if model_folder:
        os.makedirs(model_folder, exist_ok=True)
    sources = ", ".join(ORIGIN_NAMES.get(name, name) for name, n in used.items()
                        if n and not name.startswith("malware"))
    trained_on = (f"{len(x)} Windows programs ({int(np.sum(y == 1))} malicious, "
                  f"{int(np.sum(y == 0))} normal) from {sources}")
    count = export_model(booster, names, read_names, columns, threshold, metrics, trained_on,
                         args.model, evaluation)

    # The exported text must reproduce LightGBM's own scores, or the scanner would
    # report something other than what was measured here.
    sample = np.random.default_rng(SEED).choice(len(x), size=min(2000, len(x)), replace=False)
    p_text, _ = predict_text_model(args.model, x_full[sample])
    p_ref = booster.predict(x[sample], num_iteration=booster.best_iteration)
    drift = float(np.max(np.abs(p_text - p_ref)))
    metrics["export_max_drift"] = drift

    with open(os.path.splitext(args.model)[0] + ".metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nmodel: {args.model} ({count} trees, threshold {threshold:.2f}, "
          f"{len(names)} features, {args.split} split)")
    print(f"export drift vs lightgbm: {drift:.2e}")
    print(f"\nheld-out test split ({len(test_idx)} samples the model never saw):")
    print(f"  accuracy   {metrics['accuracy']:.3f}   (balanced {metrics['balanced_accuracy']:.3f})")
    print(f"  precision  {metrics['precision']:.3f}   "
          f"({metrics['confusion']['fp']} normal programs called malware)")
    print(f"  recall     {metrics['recall']:.3f}   "
          f"({metrics['confusion']['fn']} malware missed)")
    print(f"  f1         {metrics['f1']:.3f}")
    print(f"  roc auc    {metrics['auc']:.3f}")
    print(f"  accuracy at threshold 0.5: {metrics['accuracy_at_0.5']:.3f}")
    print("\nby kind of program (test split):")
    for name in sorted(cells):
        cell = cells[name]
        share = cell["called_malware"] / max(1, cell["n"])
        print(f"  {name:<20} {cell['n']:4d} tested, {cell['called_malware']:4d} called "
              f"malware ({share:5.1%})")
    importance = sorted(zip(names, booster.feature_importance("gain")), key=lambda kv: -kv[1])
    print("\nwhat the model leans on:")
    for name, gain in importance[:12]:
        print(f"  {name:<22} {gain:10.0f}")

    if drift > 1e-9:
        sys.exit("the exported model does not reproduce the trained one: do not use it")
    if metrics["accuracy"] < 0.9:
        print(f"\nNOTE: {metrics['accuracy']:.1%} is below the 90% target on this split.")


if __name__ == "__main__":
    main()
