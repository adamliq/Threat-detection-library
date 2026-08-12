#!/usr/bin/env python3
"""
Build index.html from index.template.html + data/detections.json.

Run this after editing data/detections.json (adding a new batch of
detections, fixing a field, etc.) to regenerate the static, self-contained
index.html that GitHub Pages / file:// serves.

Usage:
    python3 tools/build.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "detections.json"
TEMPLATE_FILE = ROOT / "index.template.html"
OUTPUT_FILE = ROOT / "index.html"
MARKER = "__DETECTIONS_JSON__"


def main():
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))

    ids = [d["id"] for d in data]
    if len(ids) != len(set(ids)):
        seen = set()
        dupes = sorted({i for i in ids if i in seen or seen.add(i)})
        sys.exit(f"Duplicate detection id(s) in {DATA_FILE.name}: {dupes}")

    template = TEMPLATE_FILE.read_text(encoding="utf-8")
    if MARKER not in template:
        sys.exit(f"Marker {MARKER} not found in {TEMPLATE_FILE.name}")

    payload = json.dumps(data, indent=2, ensure_ascii=False)
    # The payload sits inside a <script type="application/json"> element, so
    # only closing </script> sequences need escaping to stay well-formed HTML.
    payload = payload.replace("</script", "<\\/script")

    output = template.replace(MARKER, payload)
    OUTPUT_FILE.write_text(output, encoding="utf-8")
    print(f"Built {OUTPUT_FILE.relative_to(ROOT)} from {len(data)} detection(s).")


if __name__ == "__main__":
    main()
