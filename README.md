# Threat Detection Library

A searchable, self-contained library of platform-specific threat detections —
technique description, data sources, detection logic, MITRE ATT&CK mapping,
known false positives, investigation steps, and references — in the same
spirit as [Splunk-spl-library](https://github.com/adamliq/Splunk-spl-library),
but for full detection rules rather than raw SPL snippets.

Open `index.html` directly in a browser, or serve the repo statically (e.g.
GitHub Pages) — there's no build step or server dependency to browse it.
Search, filter by catalogue/tool, MITRE ATT&CK tactic, severity, method,
component, or data source, open any card for the full write-up, copy the
search/query/CLI reference, and export the current (filtered) result set
as JSON.

The repo holds three catalogues of detection content, spanning two
different query languages and five platform families — combined into one
filterable view:

| Catalogue | Query language | Scope | Detections |
|---|---|---|---|
| ESXi / Splunk | Splunk SPL | VMware ESXi hypervisor only | 31 |
| VMware Aria Operations for Logs | Aria search expressions | The whole vSphere stack (vCenter, SSO, ESXi, storage, networking, cluster) | 150 |
| Red Hat / Splunk | Splunk SPL | RHEL, Red Hat IdM/IPA/FreeIPA, Ansible Automation Platform, Satellite, plus cross-platform (`RH-X-###`) correlations | 171 |

`index.html` is the **combined library** — all 352 detections from all
three catalogues, filterable by a **Catalogue / Tool** facet (so you can
view any one alone or all together) alongside the usual tactic/severity/
component/method/data-source facets. A detail card renders whichever
query type applies (a Splunk SPL search block for ESXi and Red Hat
entries, an Aria search query block for Aria entries) plus a CLI/API
reference or auditd rule set where one exists. `aria-catalogue.html`
remains available as a lighter, Aria-only view for people who only want
that slice; the two pages are cross-linked from each other's header and
footer.

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

## Red Hat Threat Detection Library

`data/redhat-detections.json` is a third, independent catalogue: 171
Splunk SPL detections covering RHEL, Red Hat IdM/IPA/FreeIPA, Red Hat
Ansible Automation Platform (AAP), Red Hat Satellite, and 10 cross-platform
`RH-X-###` correlations that join saved searches across those platforms by
identity/timing to catch attacks on the Red Hat management plane itself
(e.g. a compromised IdM admin account used to SSH into the fleet, or an
AAP job template modified to disable security controls fleet-wide).

| Namespace | Platform | Detections |
|---|---|---|
| `RHEL-###` | RHEL (auditd, PAM, SELinux, sudo, SSH, systemd, fapolicyd, kernel, cron/at) | 70 |
| `IPA-###` | Red Hat IdM/IPA/FreeIPA (Kerberos KDC, 389 DS, Dogtag PKI, HBAC, sudo rules, trusts) | 31 |
| `AAP-###` | Ansible Automation Platform (Controller, credentials, EE, EDA, Automation Hub, receptor) | 33 |
| `SAT-###` | Red Hat Satellite (Foreman, Candlepin, Pulp, Katello, Capsule, REX, kickstart) | 27 |
| `RH-X-###` | Cross-platform correlations | 10 |

Every entry follows `schema/redhat-detection.schema.json` — a superset of
the ESXi schema's fields with the additions the Red Hat catalogue needed:
`component`, `detection_type`, `required_fields`, `threshold`,
`tuning_guidance`, `response_guidance`, `telemetry_requirement`,
`requires_auditd`, `audit_rules`, `detection_maturity`,
`false_positive_rating`, and `risk_scoring` (`severity × confidence ×
impact`, 1–5 each, max 125). All 171 entries' MITRE ATT&CK tactic/technique
IDs are validated against the current ATT&CK STIX corpus at generation
time — invalid or platform-mismatched IDs fail the build rather than
silently shipping (this caught several IDs that exist in MITRE's data but
were the wrong platform or tactic for the detection in question, e.g.
`T1685.001` being Windows-only despite `T1685.004`/`T1685.006` being the
correct Linux siblings).

Two companion documents ship alongside the data:

- [`docs/redhat-audit-policy.md`](docs/redhat-audit-policy.md) — every
  `auditd` rule any RHEL detection depends on, consolidated into one
  deployable ruleset and organized into the categories a Linux audit
  policy is expected to cover (Identity, Authentication, Privilege,
  Persistence, Audit protection, Security controls, Kernel, Network,
  Package management, Credentials, Destructive activity), each rule
  cross-referenced back to the detection ID(s) it supports. Includes a
  gap-analysis summary and a small set of clearly-labeled supplemental
  rules for the two categories (Network, Package management) no single
  detection's telemetry currently depends on.
- [`docs/redhat-detection-library.md`](docs/redhat-detection-library.md) —
  coverage matrices (platform × severity, detection type, maturity,
  telemetry requirement, false-positive rating, component), Priority
  Detection Packs (Tier 1: 32 highest-confidence/lowest-noise detections
  to deploy first; Tier 2: 99 more; Tier 3: 40 hunting/low-confidence
  searches) plus themed packs (Defense-Impairment, Persistence,
  Software Supply-Chain, Fleet-Wide Correlation, Credential Access,
  Identity & Privileged Access), a normalized field schema, and the
  risk-scoring/maturity-ladder reference.

This is a deliberately-scoped first release (171 detections, not padded to
an arbitrary target) covering every required section from the spec with
real, non-fabricated telemetry — extendable in future batches the same way
the ESXi catalogue grew from 18 to 31.

## Repository layout

```
data/detections.json           Canonical source of truth for the ESXi/Splunk catalogue.
data/aria-detections.json      Canonical data for the Aria Operations for Logs catalogue (generated - see below).
data/redhat-detections.json    Canonical source of truth for the Red Hat (RHEL/IdM/AAP/Satellite) catalogue.
data/mitre-attack-esxi.json    MITRE ATT&CK ESXi techniques + official Detection Analytics, coverage computed across the ESXi/Splunk and Aria catalogues.
docs/aria-catalogue-source.md  Human-authored source markdown for the Aria catalogue.
docs/redhat-audit-policy.md    Consolidated auditd ruleset the Red Hat catalogue's RHEL detections depend on, by category.
docs/redhat-detection-library.md  Coverage matrices, Priority Detection Packs, and field-schema reference for the Red Hat catalogue.
schema/detection.schema.json   JSON Schema for data/detections.json entries.
schema/aria-detection.schema.json  JSON Schema for data/aria-detections.json entries.
schema/redhat-detection.schema.json  JSON Schema for data/redhat-detections.json entries.
index.template.html            Combined-library page shell (CSS/JS) with __DETECTIONS_JSON__, __ARIA_DETECTIONS_JSON__, and __REDHAT_DETECTIONS_JSON__ markers.
index.html                     Generated: template + all three data files. The primary, combined, filterable page.
aria-catalogue.template.html   Aria-only page shell with an __ARIA_DETECTIONS_JSON__ marker.
aria-catalogue.html            Generated: template + data/aria-detections.json. Aria catalogue on its own.
tools/build.py                 Regenerates index.html from data/detections.json + data/aria-detections.json + data/redhat-detections.json.
tools/fetch_mitre_platform.py  Regenerates data/mitre-attack-esxi.json from the official MITRE ATT&CK dataset.
tools/import_aria_catalogue.py Regenerates data/aria-detections.json from docs/aria-catalogue-source.md.
tools/build_aria.py            Regenerates aria-catalogue.html from data/aria-detections.json.
```

Both `index.html` and `aria-catalogue.html` are generated, not hand-edited
— see **Adding a new batch** and **VMware Aria Operations for Logs
Catalogue** below. Whenever you touch any data file, re-run
`tools/build.py` so the combined page picks up the change (and
`tools/build_aria.py` too if you touched `data/aria-detections.json`, to
keep the Aria-only page in sync).

### MITRE ATT&CK coverage data

`data/mitre-attack-esxi.json` is fetched at runtime by `index.html` (the
**ATT&CK Coverage** button in the header) — it is *not* baked into the page,
so it can be refreshed independently of a detection batch. It's built
straight from MITRE's official STIX corpus
([mitre/cti](https://github.com/mitre/cti)) and contains, for the ESXi
platform:

- every non-deprecated **technique** MITRE scopes to `ESXi`, its tactic(s),
  and whether this library currently has a detection for it
  (`covered_by_library`) — a live gap list for planning the next batch.
  Coverage is computed across `data/detections.json` and
  `data/aria-detections.json`, since an ESXi technique covered only in the
  Aria catalogue still counts. It does not include `data/redhat-detections.json`
  (a different platform scope — RHEL/IdM/AAP/Satellite, not ESXi — so an
  ESXi-platform coverage file isn't the right place to fold it in; a
  separate Red Hat ATT&CK coverage file would be the natural next step).
- every official MITRE **Detection Analytic** scoped to `ESXi` (MITRE's
  newer Analytics/Detection Strategy model, distinct from and complementary
  to this library's own detections), with its log sources, mutable
  elements, and parent technique(s)

Because it's fetched with `fetch()`, the coverage button only works when the
page is served over http(s) (e.g. GitHub Pages, `python3 -m http.server`) —
browsers block `fetch` of local files, so it degrades to a toast message
when opened via `file://`, same as the rest of the page's data does not.

Regenerate it after a new MITRE ATT&CK release, or after adding detections
to either catalogue, with:

```bash
python3 tools/fetch_mitre_platform.py --platform ESXi
# cross-references data/detections.json + data/aria-detections.json by default;
# pass --detections explicitly (repeatable) to override which file(s) to check.
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

1. Append new detection objects to `data/detections.json` (ESXi/Splunk),
   `data/aria-detections.json` (Aria), or `data/redhat-detections.json`
   (RHEL/IdM/AAP/Satellite), validating against the matching schema file in
   `schema/`.
2. If you need to change the combined page itself (layout, filters,
   styling), edit `index.template.html` — leave the `__DETECTIONS_JSON__`,
   `__ARIA_DETECTIONS_JSON__`, and `__REDHAT_DETECTIONS_JSON__` markers in
   place.
3. Regenerate the static page:

   ```bash
   python3 tools/build.py
   ```

4. Commit the data file(s) and the regenerated `index.html`.

## Disclaimer

These detections are provided as-is for detection engineering and security
research. Log field names, sourcetypes, and even VOB event IDs vary across
ESXi versions and TA/forwarding configurations — validate every search
against your own environment before relying on it operationally. The Aria
catalogue's generated description/false-positive/investigation-step text is
templated from each entry's component and MITRE tactic rather than
individually authored — treat it as a reasonable starting point, not a
substitute for reviewing the underlying Aria query and tuning it to your
environment. The Red Hat catalogue's SPL assumes specific log sources are
onboarded (in particular Linux `auditd` EXECVE/SYSCALL telemetry — see
`docs/redhat-audit-policy.md` for the ruleset each detection needs; 55 of
171 detections are marked `requires_auditd: true` and will not fire
without it) — check each entry's `telemetry_requirement` and `data_sources`
fields against what you actually collect before deploying it, and never run
any of these searches in a way that would surface plaintext credentials,
private keys, or secrets in shared dashboards or alert output.
