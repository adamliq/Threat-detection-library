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

The repo currently holds two independent catalogues, cross-linked from each
page's header/footer:

| Catalogue | Page | Query language | Scope |
|---|---|---|---|
| ESXi / Splunk | `index.html` | Splunk SPL | 31 detections, VMware ESXi hypervisor only |
| VMware Aria Operations for Logs | `aria-catalogue.html` | Aria search expressions | 150 detections, the whole vSphere stack (vCenter, SSO, ESXi, storage, networking, cluster) |

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

## Batch 2: MITRE-ATT&CK-driven gap fill (ESXi)

Sourced by diffing the library against `data/mitre-attack-esxi.json` — every
entry below is grounded in a real MITRE ATT&CK Detection Analytic for the
ESXi platform (see each entry's `mitre_analytics` field for the exact
analytic ID). Raised ESXi ATT&CK technique coverage from 7/117 to 22/117.

| # | Detection | Method | Severity |
|---|---|---|---|
| 19 | ESXi Lockdown Mode Disabled via ESXCLI or VIM-CMD | ESXCLI / VIM-CMD | Critical |
| 20 | ESXi Local Account Removed or Password Reset via ESXCLI | ESXCLI | Critical |
| 21 | SSH Authorized Keys Modified on ESXi Host | Shell | Critical |
| 22 | ESXi Malicious VIB Installed via ESXCLI | ESXCLI | Critical |
| 23 | New Local Account Created on ESXi Host via ESXCLI | ESXCLI | High |
| 24 | ESXi Root/Default Account Login Anomaly | Shell / API | High |
| 25 | ESXi Shell Command History Cleared or Disabled | Shell | High |
| 26 | ESXi Log Files or Artifacts Deleted via Shell | Shell | High |
| 27 | ESXi Host Logs Enumerated via Shell | Shell | Low |
| 28 | ESXi VM/Datastore File Permissions Modified via Shell | Shell | Medium |
| 29 | ESXi Host Shutdown or Rebooted via ESXCLI/VIM-CMD | ESXCLI / VIM-CMD | High |
| 30 | ESXi Guest Operations API Abused for Command Execution | API | High |
| 31 | ESXi VM Escape Attempt (Hypervisor Anomaly) | Hypervisor | Critical (hunting) |

**Also corrected in this pass:** MITRE's current ESXi platform data no
longer includes any `T1562.*` (Impair Defenses) sub-techniques — they were
retired in favor of new top-level techniques under a new **Defense
Impairment** tactic (`TA0112`). Five batch-1 entries (syslog, coredump,
firewall ×2, VIB acceptance level) were retagged from `T1562.001/.004/.006`
to `T1685`/`T1686` accordingly.

## VMware Aria Operations for Logs Catalogue

`aria-catalogue.html` is a second, independent catalogue: 150 detections
(`VMW-001`–`VMW-150`) spanning the full vSphere stack — vCenter/SSO
identity and access, ESXi host security configuration, virtual networking,
storage/datastores, cluster HA/DRS, the vCenter control plane, content
libraries, and guest operations — written as **VMware Aria Operations for
Logs search expressions** rather than Splunk SPL, since Aria is a different
query language with its own field-extraction model per content pack.

Its canonical source is human-authored markdown, not hand-written JSON:
[`docs/aria-catalogue-source.md`](docs/aria-catalogue-source.md) holds one
`### VMW-XXX` section per detection (component, severity, MITRE tactic and
technique, Aria query, tuning notes) plus the catalogue's suggested
detection groups and a priority implementation set. `data/aria-detections.json`
is generated from that document; the remaining schema-required fields
(description, data sources, false positives, investigation steps,
references) are synthesized from each entry's component and MITRE tactic
via templates in the importer, and `related_detections` are auto-linked
from "Correlate with VMW-XXX" mentions and singular/mass title pairs (e.g.
"Snapshot deleted" ↔ "Mass snapshot deletion").

To edit a detection or add a new one: edit `docs/aria-catalogue-source.md`
in the same `### VMW-XXX` format, then run:

```bash
python3 tools/import_aria_catalogue.py   # docs/aria-catalogue-source.md -> data/aria-detections.json
python3 tools/build_aria.py              # data/aria-detections.json -> aria-catalogue.html
```

Editing `data/aria-detections.json` directly also works for one-off fixes
(e.g. a description tweak) that don't belong in the source markdown — just
re-run `tools/build_aria.py` afterward and skip the importer so your edit
isn't overwritten.

## Repository layout

```
data/detections.json           Canonical source of truth for the ESXi/Splunk catalogue.
data/mitre-attack-esxi.json    MITRE ATT&CK techniques + official Detection Analytics for ESXi.
data/aria-detections.json      Canonical data for the Aria Operations for Logs catalogue (generated - see below).
docs/aria-catalogue-source.md  Human-authored source markdown for the Aria catalogue.
schema/detection.schema.json   JSON Schema for data/detections.json entries.
schema/aria-detection.schema.json  JSON Schema for data/aria-detections.json entries.
index.template.html            ESXi/Splunk page shell (CSS/JS) with a __DETECTIONS_JSON__ marker.
index.html                     Generated: template + data/detections.json.
aria-catalogue.template.html   Aria catalogue page shell with an __ARIA_DETECTIONS_JSON__ marker.
aria-catalogue.html            Generated: template + data/aria-detections.json.
tools/build.py                 Regenerates index.html.
tools/fetch_mitre_platform.py  Regenerates data/mitre-attack-esxi.json from the official MITRE ATT&CK dataset.
tools/import_aria_catalogue.py Regenerates data/aria-detections.json from docs/aria-catalogue-source.md.
tools/build_aria.py            Regenerates aria-catalogue.html.
```

Both `index.html` and `aria-catalogue.html` are generated, not hand-edited
— see **Adding a new batch** and **VMware Aria Operations for Logs
Catalogue** above.

### MITRE ATT&CK coverage data

`data/mitre-attack-esxi.json` is fetched at runtime by `index.html` (the
**ATT&CK Coverage** button in the header) — it is *not* baked into the page,
so it can be refreshed independently of a detection batch. It's built
straight from MITRE's official STIX corpus
([mitre/cti](https://github.com/mitre/cti)) and contains, for the ESXi
platform:

- every non-deprecated **technique** MITRE scopes to `ESXi`, its tactic(s),
  and whether this library currently has a detection for it
  (`covered_by_library`) — a live gap list for planning the next batch
- every official MITRE **Detection Analytic** scoped to `ESXi` (MITRE's
  newer Analytics/Detection Strategy model, distinct from and complementary
  to this library's own detections), with its log sources, mutable
  elements, and parent technique(s)

Because it's fetched with `fetch()`, the coverage button only works when the
page is served over http(s) (e.g. GitHub Pages, `python3 -m http.server`) —
browsers block `fetch` of local files, so it degrades to a toast message
when opened via `file://`, same as the rest of the page's data does not.

Regenerate it after a new MITRE ATT&CK release with:

```bash
python3 tools/fetch_mitre_platform.py --platform ESXi
```

## Detection schema

Every entry in `data/detections.json` follows `schema/detection.schema.json`.
The key fields:

- `id` — stable, kebab-case slug (never rename once published; other entries
  reference each other by id via `related_detections`)
- `title`, `description`, `type`, `status`, `severity`, `confidence`
- `platform`, `product_version`, `method` — what's being detected and how
- `mitre_attack.tactics[]` / `mitre_attack.techniques[]` — ATT&CK mapping
- `mitre_analytics[]` *(optional)* — provenance link(s) to the official
  MITRE ATT&CK Detection Analytic(s) this entry is grounded in (see
  `data/mitre-attack-esxi.json`)
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
against your own environment before relying on it operationally. The Aria
catalogue's generated description/false-positive/investigation-step text is
templated from each entry's component and MITRE tactic rather than
individually authored — treat it as a reasonable starting point, not a
substitute for reviewing the underlying Aria query and tuning it to your
environment.
