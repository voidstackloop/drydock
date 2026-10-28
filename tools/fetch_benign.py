#!/usr/bin/env python3
"""Copy a bounded sample of benign modern Windows programs out of a Windows installation.

The malware corpus is old and the normal side of it is an old system's DLLs, so
the classifier had never seen a current installer, a .NET assembly, protected
media code or a kernel driver. This gathers that population:

    python3 tools/fetch_benign.py --windows /mnt/c/Windows
    # or, in Windows:  python tools\\fetch_benign.py

It writes ``data/samples/benign-modern/`` (gitignored: the files are Microsoft's,
and the model is what ships, not the samples) and a manifest next to it with the
SHA-256 and origin of every copy, so a training run can be described years later.

The sample is deterministic: for each source the files are sorted by name and an
evenly spaced subset is taken, so running it twice on the same installation
copies the same files. It never executes anything; it reads a file's first two
bytes to check for ``MZ`` and copies the rest.

Taxonomy it aims for, one directory each:

| prefix | from | what it teaches |
|---|---|---|
| ``system32-exe-`` | System32\\*.exe (all) | current native utilities, installers, resource-heavy programs |
| ``system32-dll-`` | System32\\*.dll (sampled) | current DLLs, including resource-only ones |
| ``syswow64-exe-`` | SysWOW64\\*.exe (all) | the same, 32-bit |
| ``syswow64-dll-`` | SysWOW64\\*.dll (sampled) | the same, 32-bit |
| ``dotnet-`` | Microsoft.NET\\Framework64\\v4.0.30319\\*.dll | managed assemblies |
| ``dotnetexe-`` | Microsoft.NET\\Framework64\\v4.0.30319\\*.exe | managed executables |
| ``dotnet32-`` | Microsoft.NET\\Framework\\v4.0.30319\\*.dll | 32-bit managed assemblies |
| ``dotnet32exe-`` | Microsoft.NET\\Framework\\v4.0.30319\\*.exe | 32-bit managed executables |
| ``winsxs-`` | WinSxS\\x86_*\\*.dll, wow64_*, msil_* | 32-bit and neutral side-by-side DLLs |
| ``powershell-`` | System32 and SysWOW64 WindowsPowerShell\\v1.0\\*.exe | PowerShell's host programs |
| ``driver-`` | System32\\drivers\\*.sys | kernel drivers |
| ``driverstore-sys-`` | DriverStore\\FileRepository (recursive) | third-party drivers |
| ``driverstore-dll-`` | DriverStore\\FileRepository (recursive) | third-party code: graphics and audio runtimes, protected media code |

The two DriverStore lines matter most: the code that ships with other
vendors' hardware is not in System32, and it is the shape (large, protected,
resource-heavy) the classifier had never seen when it called three Microsoft
DLLs malicious.
"""

import argparse
import hashlib
import os
import shutil
import sys

# (prefix, relative folder, globs, how many to keep, largest file to copy)
SOURCES = (
    ("system32-exe-", "System32", ("*.exe", "*.scr", "*.cpl"), 700, 12 << 20),
    ("system32-dll-", "System32", ("*.dll", "*.ocx"), 1200, 12 << 20),
    ("syswow64-exe-", "SysWOW64", ("*.exe", "*.scr", "*.cpl"), 400, 12 << 20),
    ("syswow64-dll-", "SysWOW64", ("*.dll", "*.ocx"), 700, 12 << 20),
    ("dotnet-", os.path.join("Microsoft.NET", "Framework64", "v4.0.30319"), ("*.dll",), 250, 12 << 20),
    ("dotnetexe-", os.path.join("Microsoft.NET", "Framework64", "v4.0.30319"), ("*.exe",), 50, 12 << 20),
    ("dotnet32-", os.path.join("Microsoft.NET", "Framework", "v4.0.30319"), ("*.dll",), 250, 12 << 20),
    ("dotnet32exe-", os.path.join("Microsoft.NET", "Framework", "v4.0.30319"), ("*.exe",), 50, 12 << 20),
    # Flat arch patterns, not **: a full recursive walk of WinSxS is minutes
    # on a slow mount; the component folders themselves are flat.
    ("winsxs-", "WinSxS", ("x86_*/*.dll", "wow64_*/*.dll", "msil_*/*.dll"),
     500, 12 << 20),
    ("powershell-", os.path.join("System32", "WindowsPowerShell", "v1.0"), ("*.exe",), 20, 12 << 20),
    ("pswow-", os.path.join("SysWOW64", "WindowsPowerShell", "v1.0"), ("*.exe",), 20, 12 << 20),
    ("driver-", os.path.join("System32", "drivers"), ("*.sys",), 500, 12 << 20),
    ("driverstore-sys-", os.path.join("System32", "DriverStore", "FileRepository"),
     ("**/*.sys",), 400, 12 << 20),
    ("driverstore-dll-", os.path.join("System32", "DriverStore", "FileRepository"),
     ("**/*.dll",), 400, 12 << 20),
)


def candidates(folder, patterns, limit):
    """Sorted PE files under one source, evenly thinned to `limit`, each with its size."""
    import glob

    found = []
    for pattern in patterns:
        for path in glob.glob(os.path.join(folder, pattern), recursive=True):
            if not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as f:
                    if f.read(2) != b"MZ":
                        continue  # a text file with a .dll name; the model reads PE only
            except OSError:
                continue
            found.append((os.path.basename(path).lower(), path, size))
    found.sort()
    # WinSxS holds one component per folder, so one basename repeats across
    # versions; keep the first or a later copy silently overwrites it and the
    # manifest counts a file that is not on disk.
    seen = set()
    unique = []
    for row in found:
        if row[0] not in seen:
            seen.add(row[0])
            unique.append(row)
    found = unique
    available = len(found)
    if available > limit:
        step = (available - 1) / (limit - 1)
        found = [found[int(round(i * step))] for i in range(limit)]
    return found, available


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--windows", default=os.environ.get("WINDIR", r"C:\Windows"),
                   help="the Windows folder (default: %%WINDIR%%)")
    p.add_argument("--out", default=os.path.join("data", "samples", "benign-modern"))
    p.add_argument("--force", action="store_true", help="replace what is already there")
    args = p.parse_args()

    windows = args.windows
    if not os.path.isdir(windows):
        sys.exit(f"{windows} is not a folder: pass --windows <the Windows folder>")
    if os.path.isdir(args.out):
        count = len([n for n in os.listdir(args.out) if os.path.isfile(os.path.join(args.out, n))])
        if count and not args.force:
            sys.exit(f"{args.out} already holds {count} file(s): pass --force to replace them")
        if count:  # started from an older sampling: do not mix the two
            shutil.rmtree(args.out)

    os.makedirs(args.out, exist_ok=True)
    manifest = []
    total = 0
    for prefix, relative, patterns, limit, largest in SOURCES:
        folder = os.path.join(windows, relative)
        if not os.path.isdir(folder):
            print(f"  {relative}: not there, skipped")
            continue
        found, available = candidates(folder, patterns, limit)
        kept, size_sum = 0, 0
        for name, path, size in found:
            if size > largest:
                continue
            target = os.path.join(args.out, prefix + name)
            try:
                shutil.copyfile(path, target)
            except OSError as error:
                print(f"  cannot copy {path}: {error}")
                continue
            with open(target, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            manifest.append(f"{digest}\t{size}\t{path}\t{os.path.basename(target)}")
            kept += 1
            size_sum += size
        total += kept
        print(f"  {relative}: {kept} of {available} file(s), {size_sum / (1 << 20):.1f} MB")

    manifest_path = args.out.rstrip("/\\") + ".manifest.tsv"
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("#sha256\tsize\tsource\tcopy\n" + "\n".join(manifest) + "\n")
    print(f"\n{total} file(s) under {args.out}, manifest {manifest_path}")
    print("train with: .venv-train/bin/python tools/train_ai.py")


if __name__ == "__main__":
    main()
