# Threat Detection Library

A searchable, self-contained library of platform-specific threat detections —
technique description, data sources, detection logic, MITRE ATT&CK mapping,
known false positives, investigation steps, and references — in the same
spirit as [Splunk-spl-library](https://github.com/adamliq/Splunk-spl-library),
but for full detection rules rather than raw SPL snippets.

Open `index.html` directly in a browser, or serve the repo statically (e.g.
GitHub Pages) — there's no build step or server dependency to browse it.
Search, filter by MITRE ATT&CK tactic / severity / method / data source,
open any card for the full write-up, copy the search or CLI reference, and
export the current (filtered) result set as JSON.

## Batch 1: VMware ESXi

The first 18 detections cover the command-line and API techniques attackers
use against VMware ESXi hosts in the run-up to ransomware deployment —
deleting snapshots, disabling autostart, powering off VMs, tampering with
syslog/firewall/coredump/VIB-acceptance settings, enabling SSH, and
enumerating the host — modeled on real campaigns (ESXiArgs, LockBit, Black
Basta, Akira, and the VirtualPita/VirtualPie/VirtualGate ESXi implants) and
public guidance from CISA, VMware/Broadcom, and Mandiant. See each entry's
**References** section for sources.

| # | Detection | Method | Severity |
|---|---|---|---|
| 1 | ESXi Virtual Machine Snapshots Deleted via API | API | High |
| 2 | ESXi Autostart Settings Modified via API | API | Medium |
| 3 | ESXi Virtual Machine Powered Off via ESXi API | API | Critical |
| 4 | ESXi Syslog Configuration Changed via ESXCLI | ESXCLI | High |
| 5 | ESXi Welcome Message Changed via ESXCLI | ESXCLI | Medium |
| 6 | ESXi VM Snapshots Deleted via VIM-CMD | VIM-CMD | High |
| 7 | ESXi VM Autostart Disabled via VIM-CMD | VIM-CMD | Medium |
| 8 | ESXi Coredump Generation Disabled via ESXCLI | ESXCLI | Medium |
| 9 | ESXi Firewall Disabled via ESXCLI | ESXCLI | High |
| 10 | SSH Enable on ESXi Host via VIM-CMD | VIM-CMD | Critical |
| 11 | ESXi VM IDs Enumerated via ESXCLI or VIM-CMD | ESXCLI / VIM-CMD | Low |
| 12 | ESXi System Network Information Enumerated via ESXCLI | ESXCLI | Low |
| 13 | ESXi System Information Discovery via VIM-CMD | VIM-CMD | Low |
| 14 | ESXi System Storage Enumerated via ESXCLI | ESXCLI | Low |
| 15 | ESXi System Users Enumerated via ESXCLI | ESXCLI | Low |
| 16 | ESXi Firewall Default Action Set to Pass | ESXCLI | High |
| 17 | ESXi VM Powered Off via VIM-CMD | VIM-CMD | Critical |
| 18 | ESXi VIB Acceptance Level Set to Community Supported via ESXCLI | ESXCLI | Critical |

## Repository layout

```
data/detections.json        Canonical source of truth — one JSON object per detection.
schema/detection.schema.json  JSON Schema describing every field in an entry.
index.template.html         Page shell (CSS/JS) with a __DETECTIONS_JSON__ marker.
index.html                  Generated file: template + data, ready to open/deploy.
tools/build.py               Regenerates index.html from the template + data file.
```

`index.html` is generated, not hand-edited — see **Adding a new batch** below.

## Detection schema

Every entry in `data/detections.json` follows `schema/detection.schema.json`.
The key fields:

- `id` — stable, kebab-case slug (never rename once published; other entries
  reference each other by id via `related_detections`)
- `title`, `description`, `type`, `status`, `severity`, `confidence`
- `platform`, `product_version`, `method` — what's being detected and how
- `mitre_attack.tactics[]` / `mitre_attack.techniques[]` — ATT&CK mapping
- `data_sources[]` — log/telemetry source name, path, and what it captures
- `detection_logic` — plain-English description of the detection
- `spl` — an illustrative Splunk search; sourcetypes/fields are written to be
  adapted to whatever TA/forwarding setup you actually run (VMware log
  formats and field names vary by ESXi build)
- `cli_reference` — the exact command(s)/API call(s) that generate the
  evidence
- `how_to_implement`, `known_false_positives`, `investigation_steps[]`
- `references[]` — supporting sources (CISA, VMware/Broadcom, vendor blogs)
- `related_detections[]` — ids of other entries in this library
- `author`, `created`, `modified`, `version`

## Adding a new batch

1. Append new detection objects to `data/detections.json` (validate against
   `schema/detection.schema.json`).
2. If you need to change the page itself (layout, filters, styling), edit
   `index.template.html` — leave the `__DETECTIONS_JSON__` marker in place.
3. Regenerate the static page:

   ```bash
   python3 tools/build.py
   ```

4. Commit both the data file and the regenerated `index.html`.

## Disclaimer

These detections are provided as-is for detection engineering and security
research. Log field names, sourcetypes, and even VOB event IDs vary across
ESXi versions and TA/forwarding configurations — validate every search
against your own environment before relying on it operationally.
