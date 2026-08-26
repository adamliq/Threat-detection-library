# Validations

`data/rhel-privileged-action-validations.json` (204 entries) backs this
library's **Validations** page — a new top-level view, alongside
**Detections** and **Heat Coverage**, and this library's first entry in a
new content type: a **validation catalogue**, not a detection catalogue.

## Why this is a separate content type, not a fifteenth detection catalogue

Every one of this library's fourteen detection catalogues is a shippable
production rule — SPL plus severity, confidence, false-positive rating,
investigation steps, and a risk score, meant to run continuously against
live traffic. A validation entry isn't that. Its distinguishing fields —
`safe_test`, `test_step`, `rollback_step`, `test_result` — describe
executing one privileged action once in a lab and confirming the expected
telemetry/detection actually fired. Its `validation_spl` field is a
one-shot presence check ("did the expected event show up in the last 15
minutes"), not a tuned detection rule with false-positive handling.

Put simply: a detection catalogue entry watches continuously for an
action happening. A validation entry is a recipe for causing that action
to happen once, on purpose, in a controlled environment, so you can
confirm the watching actually works — a test-execution reference for the
existing catalogues (principally the Red Hat catalogue), not a new
production capability of its own. See the Validations page's own intro
text for the same explanation in the UI.

## Source and conversion

The source is an uploaded workbook, "RHEL Privileged User Actions
(Enriched)" — a `Privileged Actions` sheet (204 rows, `RHEL-PRIV-001`
through `RHEL-PRIV-204`), a `Column Dictionary`, and a `Summary` sheet.
Each row covers one privileged RHEL action across 36 categories (User,
Sudo, SSH, SELinux, Service, Firewall, Scheduled tasks, Containers, and
more) with the exact command to generate it, expected auditd
key/syscall/AUID-UID-EUID semantics, Splunk sourcetype/CIM mapping, a
detection-priority rating, and CIS/STIG/ISM compliance-reference
placeholders.

Converted programmatically (not hand-transcribed) into
`data/rhel-privileged-action-validations.json`, one entry per row,
against `schema/rhel-privileged-action-validation.schema.json`.

## MITRE ATT&CK mapping: resolved live, not copied from the workbook

The workbook's own `ATT&CK Tactic` column still uses the pre-split
"Defense Evasion" tactic name — MITRE has since divided that tactic into
**Stealth** and **Defense Impairment**, the same split this library's
other fourteen catalogues already reflect. Rather than guess which
successor tactic each row meant, every entry's `mitre_attack.tactics` is
**resolved from the technique's own current, live tactic membership in
the MITRE ATT&CK STIX corpus** (`mitre/cti`), the same "verify against
the source, don't trust a stale label" discipline this library has
applied to every MITRE-derived batch this session. The workbook's
`ATT&CK Tactic` text is only used as a fallback for the 53 rows with no
technique to anchor a lookup, with "Defense Evasion" itself dropped
there too (ambiguous which successor applies without a technique) — 13
of those 53 still land a fallback tactic this way; the remaining 40
entries carry no tactic/technique at all rather than a forced guess.

**A second, more consequential discrepancy turned up doing this:** three
of the workbook's technique IDs — `T1562`, `T1562.001`, `T1562.004` —
have been **revoked** in the current MITRE ATT&CK release, renumbered to
`T1685` (Disable or Modify Tools), `T1685` again, and `T1686` (Disable or
Modify System Firewall) respectively. (This library has hit this exact
technique family's renumbering before — see the git history around
"Fix Aria's 26 stale T1562 technique IDs.") Rather than silently drop
these 29 rows' mappings, the conversion follows MITRE's own `revoked-by`
STIX relationship to the current technique ID, and records the redirect
in the entry's `mitre_attack.techniques[].note` field for transparency
(e.g. `"T1562.001 -> T1685 (MITRE renumbered this technique)"`). This
also surfaced a workbook labeling error along the way: several rows
labeled `T1562.001` with the *parent* technique's name ("Impair
Defenses") rather than the sub-technique's actual name ("Disable or
Modify Tools") — preserved in the same note field rather than silently
corrected, so the discrepancy is visible.

**Result:** 151 of 204 entries (74%) carry a resolved, currently-valid
MITRE technique; 20 distinct techniques across 9 tactics (Persistence,
Privilege Escalation, Credential Access, Defense Impairment, Stealth,
Execution, Lateral Movement, Command and Control, Impact). The remaining
53 entries have no technique in the source workbook at all (mostly
generic operational actions — service restarts, log rotation
configuration — that don't map cleanly to a single ATT&CK technique) and
are shown with an empty tactic/technique set rather than a forced
mapping.

## What's in each entry

`platform` is an array (matching the same field's convention on
`data/redhat-detections.json`) and is `["RHEL"]` on every entry today —
this catalogue's scope is entirely RHEL. It's a real facet in the
Validations page's filter sidebar, not just a data-model formality: a
future validation catalogue for another platform (e.g. Windows
privileged actions) would widen the schema's `platform` enum and slot
into the same page and filter set rather than needing its own.

| Field group | Fields |
|---|---|
| Identity | `id`, `platform`, `category`, `category_sub`, `event_type`, `title`, `description` |
| The action itself | `typical_mechanism`, `action`, `object_type`, `privilege_level`, `privilege_transition`, `expected_result`, `status` |
| MITRE ATT&CK | `mitre_attack.tactics[]`, `mitre_attack.techniques[]` (resolved live — see above) |
| Test execution | `safe_test`, `test_step`, `test_environment`, `rollback_step`, `evidence_expected`, `telemetry_coverage`, `test_result` |
| Expected auditd telemetry | `audit_key`, `audit_record_types[]`, `expected_syscall`, `expected_executable`, `expected_path`, `expected_auid`, `expected_uid`, `expected_euid`, `expected_command`, `expected_fields[]` |
| Splunk mapping | `validation_spl`, `splunk_sourcetype[]`, `cim_data_model`, `cim_action` |
| Detection & compliance | `detection_priority`, `detection_required`, `alert_required`, `compliance_relevant`, `cis_reference`, `stig_reference`, `ism_reference` |
| Provenance | `notes`, `author`, `created`, `modified`, `version` |

`test_result` ships as `"Not Tested"` on every entry — it's a field for
whoever actually runs the validation in their own environment to fill
in, not something this library can populate on their behalf.
`cis_reference`/`stig_reference`/`ism_reference` similarly ship as
placeholder text from the source workbook ("TBD — map to deployed
CIS RHEL benchmark/version") — they need to be filled in against your
own organization's specific benchmark/STIG/ISM baseline version, which
this library has no way to know.

## By the numbers

| Category (top 10 of 36) | Count |
|---|---:|
| User | 20 |
| File | 17 |
| Service | 13 |
| SSH | 10 |
| Sudo | 9 |
| SELinux | 8 |
| Storage | 8 |
| Software | 7 |
| Sensitive File | 7 |
| Settings | 7 |

| Detection Priority | Count | | SAFE Test | Count |
|---|---:|---|---|---:|
| Critical | 77 | | Yes (lab-safe) | 83 |
| High | 109 | | No | 121 |
| Medium | 17 | | | |
| Low | 1 | | | |

Priority skews heavily Critical/High (186 of 204) because privileged
RHEL actions are, definitionally, the actions worth watching — this
workbook wasn't sampling routine activity. `SAFE Test` skews the other
way (121 of 204 not lab-safe) because a majority of these actions are
inherently disruptive (disabling a firewall, stopping the audit daemon,
locking an account, rebooting) — the field exists precisely to flag
which ones you can actually exercise in a shared/production-adjacent lab
without extra care.

## Design: same page, new content type

The Validations page reuses the Detections page's exact visual and
interaction design — search bar, collapsible filter sidebar, card grid,
shared detail overlay — per its own dedicated toolbar and sidebar (styled
identically via the same CSS classes, functionally independent so
neither page's state leaks into the other, the same pattern the Heat
Coverage tab already established). Facets: Category, Event Type,
Detection Priority, MITRE ATT&CK Tactic, SAFE Test. The detail panel adds
sections this content type needs that a detection entry doesn't —
Test Step (with a Copy button), Validation & Rollback, Expected auditd
Telemetry, Splunk Mapping, Detection & Compliance.

## Attribution and license

This catalogue's structure and MITRE ATT&CK resolution are this
project's own work; its source content (the 204 privileged-action
definitions, test steps, and telemetry mappings) comes from the uploaded
workbook. `mitre_attack` fields are resolved against the official MITRE
ATT&CK STIX corpus ([mitre/cti](https://github.com/mitre/cti),
Apache-2.0-licensed on `mitre-attack`, CC-BY-4.0 on ATT&CK-name content).
