#!/usr/bin/env python3
"""Fetch modern Windows malware from MalwareBazaar's public hourly batches.

The old corpus (tools/fetch_dataset.py) is 32-bit, mostly unpacked, and from a
decade ago; this adds what it never saw: recent droppers, packed binaries and
64-bit samples. The source is abuse.ch's bulk feed, which needs no API key:

    python3 tools/fetch_bazaar.py --hours 48 --max-files 1500

Files land in ``data/samples/malware-bazaar/<sha256><ext>`` with a manifest
next to the folder, so a training run can be described years later. Reruns only
fill what is missing. Batches are read newest-first and stop as soon as
--max-files new PE files are kept, so a second run costs one HEAD probe per
hour until it finds an hour with something new.

The samples are live malicious code. Keep the directory out of version control,
never run anything in it, and delete it when the model has been trained.
Nothing here executes: each entry is decrypted with the published password
(``infected``), checked for the ``MZ`` magic as bytes, hashed and written out.
"""

import argparse
import datetime
import hashlib
import os
import sys
import tempfile
import urllib.request
import zipfile

BASE = "https://datalake.abuse.ch/malware-bazaar/hourly"
PASSWORD = b"infected"
LARGEST = 16 << 20  # the scanner reads the first 16 MB; it skips bigger files too
UA = {"User-Agent": "leakcheck-fetch/1.0"}


def hour_name(moment):
    return moment.strftime("%Y-%m-%d-%H") + ".zip"


def batch_size(name):
    """Published size of one batch, or -1 when it is not there (yet)."""
    req = urllib.request.Request(f"{BASE}/{name}", method="HEAD", headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return int(r.headers.get("Content-Length", -1))
    except Exception:
        return -1


def download(name, tmp):
    req = urllib.request.Request(f"{BASE}/{name}", headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=600) as r, open(tmp, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    return True
                f.write(chunk)
    except Exception as e:
        print(f"  {name}: {e}")
        return False


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hours", type=int, default=48, help="recent hourly batches to read")
    p.add_argument("--max-files", type=int, default=1500, help="new PE files to keep")
    p.add_argument("--max-batch-mb", type=int, default=750,
                   help="skip a batch bigger than this (GB-scale outliers)")
    p.add_argument("--out", default=os.path.join("data", "samples", "malware-bazaar"))
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)
    manifest_path = args.out.rstrip("/\\") + ".manifest.tsv"
    if not os.path.isfile(manifest_path):
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write("#sha256\tsize\tbatch\tsource\n")

    now = datetime.datetime.now(datetime.timezone.utc).replace(minute=0, second=0, microsecond=0)
    kept = 0
    with open(manifest_path, "a", encoding="utf-8") as manifest:
        for back in range(args.hours + 8):
            if kept >= args.max_files:
                break
            name = hour_name(now - datetime.timedelta(hours=back))
            size = batch_size(name)
            if size < 0:
                continue  # not published yet; an older hour will be
            if size > args.max_batch_mb << 20:
                print(f"  {name}: {size / (1 << 30):.1f} GB, over the cap, skipped")
                continue
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp_path = tmp.name
            try:
                print(f"  {name} ({size / (1 << 20):.0f} MB) ...")
                if not download(name, tmp_path):
                    continue
                try:
                    batch = zipfile.ZipFile(tmp_path)
                except zipfile.BadZipFile as e:
                    print(f"  {name}: not a zip ({e})")
                    continue
                with batch:
                    batch.setpassword(PASSWORD)
                    new = 0
                    for info in sorted(batch.infolist(), key=lambda i: i.filename):
                        if kept >= args.max_files:
                            break
                        if info.is_dir() or info.file_size < 64 or info.file_size > LARGEST:
                            continue
                        try:
                            data = batch.read(info.filename)
                        except Exception:
                            continue  # a damaged entry; the next batch has more
                        if data[:2] != b"MZ":
                            continue  # scripts, documents, ELF, archives: not PE
                        digest = hashlib.sha256(data).hexdigest()
                        ext = os.path.splitext(info.filename)[1].lower()[:8]
                        target = os.path.join(args.out, digest + ext)
                        if os.path.exists(target):
                            continue
                        with open(target, "wb") as f:
                            f.write(data)
                        manifest.write(f"{digest}\t{len(data)}\t{name}\t{info.filename}\n")
                        kept += 1
                        new += 1
                print(f"  {name}: {new} new PE file(s)")
            finally:
                os.unlink(tmp_path)

    print(f"\n{kept} new file(s) under {args.out}, manifest {manifest_path}")
    print("train with: .venv-train/bin/python tools/train_ai.py")


if __name__ == "__main__":
    main()
