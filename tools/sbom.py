#!/usr/bin/env python3
"""Write the released artifacts' SBOM, in CycloneDX 1.5 JSON.

    python3 tools/sbom.py --version 1.0.0 --out dist/SBOM.cdx.json dist/*.tar.gz

leakcheck is one binary with no third-party libraries, so the honest SBOM is
short: the tool itself, the archives it ships in, and a property saying there is
nothing else to list. Generating it here instead of with an ecosystem tool is
the point -- there is no dependency tree to discover, and a scanner that asks
"what is in this binary?" gets an answer that is true because it is small.

The hash of each file is computed, so the SBOM can be checked against
SHA256SUMS and the provenance attestation.
"""
import argparse
import hashlib
import json
import sys

TOOL = "leakcheck"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--repo", default="https://github.com/voidstackloop/drydock")
    ap.add_argument("--out", required=True)
    ap.add_argument("files", nargs="+", help="the released archives")
    args = ap.parse_args()

    components = []
    for path in args.files:
        name = path.replace("\\", "/").rsplit("/", 1)[-1]
        components.append({
            "type": "application",
            "name": name,
            "version": args.version,
            "hashes": [{"alg": "SHA-256", "content": sha256(path)}],
            "properties": [
                {"name": "leakcheck:third-party-dependencies", "value": "none"},
            ],
        })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": TOOL, "name": "tools/sbom.py"}],
            "component": {
                "type": "application",
                "name": TOOL,
                "version": args.version,
                "licenses": [{"license": {"id": "MIT"}}],
                "externalReferences": [{"type": "vcs", "url": args.repo}],
                "properties": [
                    {"name": "leakcheck:third-party-dependencies", "value": "none"},
                ],
            },
        },
        "components": sorted(components, key=lambda c: c["name"]),
    }
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(bom, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {args.out}: {len(components)} component(s), no third-party libraries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
