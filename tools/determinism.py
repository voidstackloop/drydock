#!/usr/bin/env python3
"""Prove that the same input gives byte-identical JSON and SARIF everywhere.

    python3 tools/determinism.py --leakcheck build/leakcheck --out digests.json
    python3 tools/determinism.py --compare digests-linux.json digests-windows.json

The fixture is built in a temporary directory and that directory's path is
replaced with `<tmp>` before hashing, because it is the only part of a report
that legitimately differs between machines. Everything else has to match: key
order, numbers, message text, rule order, line endings. A renderer that
iterates a hash map, a rule that reads the locale, or a report whose file order
follows the threads fails the comparison between the CI jobs that produce these
digests.

`scan` is the mode used: it needs no compiler or runtime and produces the same
findings from the same bytes on all three systems. The unit and command-line
suites already compare static output across thread counts.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

# Split so this source file is not itself a file the scanner reports: the
# fixture is assembled at run time.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
         "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def run(leakcheck, args):
    p = subprocess.run([leakcheck] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    if p.returncode not in (0, 2):
        raise SystemExit(f"determinism: {' '.join(args)} exited {p.returncode}: {p.stderr}")


def normalise(text, root):
    # The temporary directory, in either separator style, is the one honest
    # difference between the systems.
    for form in {root, root.replace("\\", "/"), root.replace("/", "\\")}:
        text = text.replace(form, "<tmp>")
    return text


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_fixture(root):
    with open(os.path.join(root, "invoice.pdf.exe"), "w", encoding="utf-8", newline="\n") as f:
        f.write("echo hi\n")
    with open(os.path.join(root, "note.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("all clear\n")
    with open(os.path.join(root, "eicar.com"), "w", encoding="utf-8", newline="\n") as f:
        f.write(EICAR + "\n")


def produce(leakcheck, out_path):
    with tempfile.TemporaryDirectory() as root:
        write_fixture(root)
        target = os.path.join(root, "fixture")
        os.makedirs(target)
        for name in os.listdir(root):
            if name != "fixture":
                os.replace(os.path.join(root, name), os.path.join(target, name))
        digests, saved = {}, {}
        for name, extra in (("scan", []), ("scan-malware", ["--malware"])):
            for fmt in ("json", "sarif"):
                report = os.path.join(root, name + "." + fmt)
                run(leakcheck, ["-f", fmt, "-o", report, "scan"] + extra + [target])
                with open(report, encoding="utf-8") as f:
                    text = normalise(f.read(), root)
                digests[f"{name}.{fmt}"] = digest(text)
                saved[f"{name}.{fmt}"] = text
        p = subprocess.run([leakcheck, "--rule-list", "-f", "json"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if p.returncode != 0:
            raise SystemExit(f"determinism: --rule-list exited {p.returncode}: {p.stderr}")
        digests["rule-list.json"] = digest(p.stdout)
        saved["rule-list.json"] = p.stdout
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"format": 1, "digests": digests}, f, indent=2, sort_keys=True)
        f.write("\n")
    return digests, saved


def compare(paths):
    loaded = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            loaded.append((os.path.basename(path), json.load(f)["digests"]))
    keys = sorted(set().union(*(d for _, d in loaded)))
    bad = 0
    for key in keys:
        values = [(name, d[key]) for name, d in loaded if key in d]
        first = values[0][1]
        if any(v != first for _, v in values):
            bad += 1
            print(f"DIFFERS {key}")
            for name, v in values:
                print(f"  {name}: {v}")
        else:
            print(f"same    {key}  {first[:16]}")
    missing = [(name, key) for name, d in loaded for key in keys if key not in d]
    for name, key in missing:
        bad += 1
        print(f"MISSING {key} in {name}")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--leakcheck", help="the binary to run")
    ap.add_argument("--out", help="write the digests here")
    ap.add_argument("--save", help="keep the normalised reports, for a failing diff")
    ap.add_argument("--compare", nargs="+", metavar="DIGESTS",
                    help="compare digest files from different systems")
    args = ap.parse_args()
    if args.compare:
        return compare(args.compare)
    if not args.leakcheck or not args.out:
        ap.error("--leakcheck and --out are needed unless --compare is used")
    digests, saved = produce(os.path.abspath(args.leakcheck), args.out)
    if args.save:
        os.makedirs(args.save, exist_ok=True)
        for name, text in saved.items():
            with open(os.path.join(args.save, name), "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
    for key in sorted(digests):
        print(f"{key}: {digests[key][:16]}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
