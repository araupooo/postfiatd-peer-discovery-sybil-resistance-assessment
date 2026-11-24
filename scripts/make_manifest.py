#!/usr/bin/env python3
"""make_manifest.py — write the pack manifest (file list with SHA-256).

Usage:
    python3 scripts/make_manifest.py

Writes manifest.json at the pack root: every file under the pack except
outputs/run_all.log (transient, holds the wall-clock start line),
manifest.json itself, and SHA256SUMS. SHA256SUMS is excluded on purpose:
it contains manifest.json's digest, so including it in the manifest
would make the two files chase each other and never reproduce
byte-identically across runs. Deterministic: sorted paths, fixed
separators.
"""

import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)

EXCLUDE = {"manifest.json", "SHA256SUMS",
           os.path.join("outputs", "run_all.log")}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    entries = []
    for root, dirs, files in os.walk(PACK):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, PACK)
            if rel in EXCLUDE:
                continue
            entries.append({"path": rel, "sha256": sha256_file(path),
                            "bytes": os.path.getsize(path)})
    manifest = {"files": entries, "count": len(entries)}
    with open(os.path.join(PACK, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print("manifest: %d files" % len(entries))


if __name__ == "__main__":
    main()
