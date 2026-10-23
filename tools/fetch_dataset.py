#!/usr/bin/env python3
"""Download the PE samples used to train --ai, without the whole archive.

The source is the Hugging Face dataset crovax/CNN_Project: a 2.8 GB zip holding
5,001 benign Windows programs and 5,001 malicious ones, as raw bytes. Its central
directory is read with HTTP range requests, then only the chosen entries are
fetched, decompressed and written out. Nothing is ever executed: every file is
read as bytes and nothing else.

    tools/fetch_dataset.py --per-class 4000 --out data/samples

Files land in <out>/benign/<crc>-<name> and <out>/malware/<crc>-<name>: the
prefix keeps two samples with one name apart. Existing files are skipped, so a
second run only fills what is missing.

The samples are live malicious code. Keep the directory out of version control,
never run anything in it, and delete it when the model has been trained.
"""

import argparse
import os
import struct
import sys
import threading
import time
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor

DEFAULT_URL = "https://huggingface.co/datasets/crovax/CNN_Project/resolve/main/malware_dataset.zip"
CLASSES = {"benign": "malware_dataset/benign_samples/", "malware": "malware_dataset/malicious_samples/"}


def fetch(url, start, end, tries=4):
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            if len(data) != end - start + 1:
                raise IOError(f"short read: {len(data)} of {end - start + 1}")
            return data
        except Exception:  # a dropped connection is normal over a few hundred MB
            if attempt + 1 == tries:
                raise
            time.sleep(1.5 * (attempt + 1))


def central_directory(url):
    head = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(head, timeout=60) as r:
        size = int(r.headers["Content-Length"])
    tail_at = max(0, size - 65536)
    tail = fetch(url, tail_at, size - 1)
    at = tail.rfind(b"PK\x05\x06")
    if at < 0:
        sys.exit("no end-of-central-directory record: is this a zip?")
    _, _, _, _, count, cd_size, cd_off, _ = struct.unpack("<IHHHHIIH", tail[at:at + 22])
    cd = fetch(url, cd_off, cd_off + cd_size - 1)
    entries, pos = [], 0
    for _ in range(count):
        if cd[pos:pos + 4] != b"PK\x01\x02":
            sys.exit("a damaged central directory")
        (_, _, _, flags, method, _, _, crc, csize, usize, nlen, elen, clen, _, _, _, off) = struct.unpack(
            "<IHHHHHHIIIHHHHHII", cd[pos:pos + 46])
        name = cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        pos += 46 + nlen + elen + clen
        entries.append({"name": name, "method": method, "flags": flags, "crc": crc,
                        "csize": csize, "usize": usize, "offset": off})
    return entries


def data_range(url, entry):
    start, end = entry["offset"], entry["offset"] + 29
    head = fetch(url, start, end)
    if head[:4] != b"PK\x03\x04":
        raise IOError("not a local file header")
    nlen, elen = struct.unpack("<HH", head[26:30])
    first = entry["offset"] + 30 + nlen + elen
    return first, first + entry["csize"] - 1


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=DEFAULT_URL)
    p.add_argument("--per-class", type=int, default=4000, help="how many of each class (the set has 5,001)")
    p.add_argument("--out", default="data/samples")
    p.add_argument("--workers", type=int, default=24)
    args = p.parse_args()

    print(f"reading the archive listing ({args.url.rsplit('/', 1)[-1]})")
    entries = central_directory(args.url)
    chosen = {}
    for label, folder in CLASSES.items():
        have = sorted((e for e in entries if e["name"].startswith(folder) and not e["name"].endswith("/")),
                      key=lambda e: e["name"])
        if not have:
            sys.exit(f"no files under {folder}")
        step = max(1, len(have) // args.per_class)
        chosen[label] = have[::step][:args.per_class]
        print(f"  {label}: {len(have)} in the set, taking {len(chosen[label])}")

    lock = threading.Lock()
    done = {"n": 0, "bytes": 0}
    total = sum(len(v) for v in chosen.values())
    started = time.time()

    def one(label, entry):
        folder = os.path.join(args.out, label)
        os.makedirs(folder, exist_ok=True)
        name = entry["name"].rsplit("/", 1)[-1].replace("\\", "_").replace("\x00", "")
        target = os.path.join(folder, f"{entry['crc']:08x}-{name}")
        if os.path.exists(target) and os.path.getsize(target) == entry["usize"]:
            with lock:
                done["n"] += 1
            return
        raw = fetch(args.url, *data_range(args.url, entry))
        data = raw if entry["method"] == 0 else zlib.decompress(raw, -15)
        if len(data) != entry["usize"] or zlib.crc32(data) & 0xFFFFFFFF != entry["crc"]:
            print(f"  damaged: {entry['name']}", file=sys.stderr)
            return
        with open(target, "wb") as f:
            f.write(data)
        with lock:
            done["n"] += 1
            done["bytes"] += len(data)
            if done["n"] % 500 == 0:
                rate = done["bytes"] / max(1.0, time.time() - started) / 1e6
                print(f"  {done['n']}/{total} files, {done['bytes'] / 1e9:.2f} GB, {rate:.1f} MB/s")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for label, items in chosen.items():
            for entry in items:
                pool.submit(one, label, entry)
    print(f"done: {done['n']} files, {done['bytes'] / 1e9:.2f} GB in {time.time() - started:.0f}s")
    for label in CLASSES:
        folder = os.path.join(args.out, label)
        print(f"  {label}: {len(os.listdir(folder)) if os.path.isdir(folder) else 0}")


if __name__ == "__main__":
    main()
