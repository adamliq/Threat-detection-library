#!/usr/bin/env python3
"""
Build aria-catalogue.html from aria-catalogue.template.html + data/aria-detections.json.

Run this after editing data/aria-detections.json directly, or after
re-running tools/import_aria_catalogue.py, to regenerate the static,
self-contained aria-catalogue.html.

Usage:
    python3 tools/build_aria.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "aria-detections.json"
TEMPLATE_FILE = ROOT / "aria-catalogue.template.html"
OUTPUT_FILE = ROOT / "aria-catalogue.html"
MARKER = "__ARIA_DETECTIONS_JSON__"


def main():
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))

    ids = [d["id"] for d in data]
    if len(ids) != len(set(ids)):
        seen = set()
        dupes = sorted({i for i in ids if i in seen or seen.add(i)})
        sys.exit(f"Duplicate detection id(s) in {DATA_FILE.name}: {dupes}")

    all_ids = set(ids)
    for d in data:
        for r in d.get("related_detections", []):
            if r not in all_ids:
                sys.exit(f"{d['id']}: related_detections references unknown id {r!r}")

    template = TEMPLATE_FILE.read_text(encoding="utf-8")
    if MARKER not in template:
        sys.exit(f"Marker {MARKER} not found in {TEMPLATE_FILE.name}")

    payload = json.dumps(data, indent=2, ensure_ascii=False)
    payload = payload.replace("</script", "<\\/script")

    output = template.replace(MARKER, payload)
    OUTPUT_FILE.write_text(output, encoding="utf-8")
    print(f"Built {OUTPUT_FILE.relative_to(ROOT)} from {len(data)} detection(s).")


if __name__ == "__main__":
    main()
