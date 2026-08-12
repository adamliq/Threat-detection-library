#!/usr/bin/env python3
"""
Build index.html from index.template.html + data/detections.json +
data/aria-detections.json + data/redhat-detections.json.

index.html is the combined library: it embeds the ESXi/Splunk SPL, VMware
Aria Operations for Logs, and Red Hat (RHEL/IdM/IPA/FreeIPA/AAP/Satellite)
Splunk SPL catalogues and lets you filter across all three. Run this after
editing any data file (adding a new batch, fixing a field, etc.) to
regenerate the static, self-contained index.html that GitHub Pages /
file:// serves.

Usage:
    python3 tools/build.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "detections.json"
ARIA_DATA_FILE = ROOT / "data" / "aria-detections.json"
REDHAT_DATA_FILE = ROOT / "data" / "redhat-detections.json"
TEMPLATE_FILE = ROOT / "index.template.html"
OUTPUT_FILE = ROOT / "index.html"
MARKER = "__DETECTIONS_JSON__"
ARIA_MARKER = "__ARIA_DETECTIONS_JSON__"
REDHAT_MARKER = "__REDHAT_DETECTIONS_JSON__"


def check_ids(data, source_name):
    ids = [d["id"] for d in data]
    if len(ids) != len(set(ids)):
        seen = set()
        dupes = sorted({i for i in ids if i in seen or seen.add(i)})
        sys.exit(f"Duplicate detection id(s) in {source_name}: {dupes}")


def to_payload(data):
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    # The payload sits inside a <script type="application/json"> element, so
    # only closing </script> sequences need escaping to stay well-formed HTML.
    return payload.replace("</script", "<\\/script")


def main():
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    check_ids(data, DATA_FILE.name)

    aria_data = json.loads(ARIA_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(aria_data, ARIA_DATA_FILE.name)

    redhat_data = json.loads(REDHAT_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(redhat_data, REDHAT_DATA_FILE.name)

    template = TEMPLATE_FILE.read_text(encoding="utf-8")
    for marker in (MARKER, ARIA_MARKER, REDHAT_MARKER):
        if marker not in template:
            sys.exit(f"Marker {marker} not found in {TEMPLATE_FILE.name}")

    output = (
        template.replace(MARKER, to_payload(data))
        .replace(ARIA_MARKER, to_payload(aria_data))
        .replace(REDHAT_MARKER, to_payload(redhat_data))
    )
    OUTPUT_FILE.write_text(output, encoding="utf-8")
    print(
        f"Built {OUTPUT_FILE.relative_to(ROOT)} from {len(data)} ESXi/Splunk SPL + "
        f"{len(aria_data)} Aria + {len(redhat_data)} Red Hat detection(s)."
    )


if __name__ == "__main__":
    main()
