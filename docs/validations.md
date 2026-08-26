# Validations

Two catalogues back this library's **Validations** page — a top-level
view, alongside **Detections** and **Heat Coverage**, and this library's
first entries in a new content type: a **validation catalogue**, not a
detection catalogue.

- `data/rhel-privileged-action-validations.json` (204 entries, `RHEL`)
- `data/fortigate-privileged-admin-validations.json` (146 entries, `FortiGate`)

Both share one page, one card grid, one detail-panel design, and one
`platform` filter facet to tell them apart — the same "many sources, one
page" pattern the Detections page already uses for its fourteen
catalogues.

## Why this is a separate content type, not a fifteenth detection catalogue

Every one of this library's fourteen detection catalogues is a shippable
production rule — SPL plus severity, confidence, false-positive rating,
investigation steps, and a risk score, meant to run continuously against
live traffic. A validation entry isn't that. Its distinguishing fields —
`safe_test`, `test_step`, `rollback_step`, `test_result` — describe
executing one privileged action once (in a lab, or against a controlled
device) and confirming the expected telemetry/detection actually fired.
Its `validation_spl` field is a one-shot presence check ("did the
expected event show up in the last 15 minutes"), not a tuned detection
rule with false-positive handling.

Put simply: a detection catalogue entry watches continuously for an
action happening. A validation entry is a recipe for causing that action
to happen once, on purpose, in a controlled environment, so you can
confirm the watching actually works — a test-execution reference for the
existing catalogues (the Red Hat and Fortinet catalogues, respectively),
not a new production capability of its own. See the Validations page's
own intro text for the same explanation in the UI.

## RHEL Privileged Action Validation Catalogue

### Source and conversion

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

### MITRE ATT&CK mapping: resolved live, not copied from the workbook

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

### RHEL by the numbers

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

## FortiGate Privileged Admin Action Validation Catalogue

### Source and conversion

The source is a second uploaded workbook, "FortiGate Privileged Admin
Actions (Enriched)" — the same three-sheet shape as the RHEL workbook
(`Privileged Actions`, `Column Dictionary`, `Summary`), 146 rows,
`FGT-PRIV-001` through `FGT-PRIV-146`, across 36 categories
(Administrator, Firewall Policy, IPsec VPN, HA, Logging, Certificate,
and more). In place of RHEL's auditd-specific columns, this workbook
carries FortiOS-specific ones — CLI Context, Expected Config Path,
Expected Log Type/Subtype, Expected Admin/User, Expected Source IP,
Expected Interface/UI, Expected Command/Change — reflecting that a
firewall's privileged-action evidence is a config/CLI/log-subtype trail,
not a Linux syscall/AUID one.

Converted the same way: programmatically, one entry per row, into
`data/fortigate-privileged-admin-validations.json` against
`schema/fortigate-privileged-admin-validation.schema.json`. `platform`
is `["FortiGate"]` on every entry — the same exact string
`data/fortinet-detections.json`'s `fortinet_product` field already uses
for this device, so the two catalogues stay consistent about what to
call it.

### MITRE ATT&CK mapping: the same two discrepancies recur, plus a third

This workbook's `ATT&CK Tactic` column has the identical pre-split
"Defense Evasion" problem the RHEL workbook had, resolved the same way —
live, from the technique's current tactic membership, never copied
verbatim. And the **exact same** `T1562`/`T1562.001`/`T1562.004`
revoked-technique family reappears here too (18, 13, and 12 rows
respectively use one of these three IDs) — this is now the *third* time
in this library's history this specific technique family's renumbering
has had to be corrected (Aria, then RHEL, now FortiGate), for the same
reason each time: none of the source material was regenerated after
MITRE's Defense Evasion split.

This workbook's `ATT&CK Technique` column is also messier than RHEL's —
most rows use the `Txxxx - Name (context note)` shape, but a few use
`Txxxx / note` instead, and two rows have no real technique code at all,
just a free-text guess ("Network configuration manipulation (context
dependent)"). All 16 distinct raw values in the column were inspected by
hand rather than parsed with one general-purpose regex, to avoid
mis-parsing the irregular ones. One of those irregular rows resolved to
a technique whose live tactic flatly disagreed with the workbook's own
tactic column: the workbook tagged `T1587.003` as "Credential Access;
Defense Evasion", but MITRE's current corpus places T1587.003 (Digital
Certificates) under **Resource Development** — resolving live caught
this the same way it caught the Defense Evasion split.

**Result:** 107 of 146 entries (73%) carry a resolved, currently-valid
MITRE technique; 11 distinct techniques across 11 tactics. Of the 39
entries with no technique, 20 still land a tactic from the workbook's
own tactic column (with "Defense Evasion" dropped as ambiguous, same
rule as RHEL); the remaining 19 carry no tactic/technique at all.

### FortiGate by the numbers

| Category (top 10 of 36) | Count |
|---|---:|
| System | 16 |
| Administrator | 15 |
| Firewall Policy | 13 |
| Routing | 8 |
| Logging | 8 |
| HA | 7 |
| Interface | 6 |
| Diagnostics | 6 |
| IPsec VPN | 5 |
| SSL VPN | 4 |

| Detection Priority | Count | | SAFE Test | Count |
|---|---:|---|---|---:|
| Critical | 70 | | Yes (lab-safe) | 70 |
| High | 69 | | No | 76 |
| Medium | 7 | | | |

Priority again skews heavily Critical/High (139 of 146) for the same
reason as RHEL — this workbook targets privileged administrative
actions specifically, not a random activity sample. `SAFE Test` is
close to an even split (70/146 lab-safe) since many FortiGate privileged
actions are disruptive by nature (disabling HA, changing routing,
modifying a firewall policy, rebooting) but a meaningful share (creating
test objects, viewing configuration) are safe to exercise directly.

## What's in each entry

`platform` is an array on every entry (`["RHEL"]` or `["FortiGate"]`
today) and is a real facet in the Validations page's filter sidebar, not
just a data-model formality — it's what lets one page and one card grid
serve multiple validation catalogues without them being confused for
each other. A future validation catalogue for another platform slots in
the same way: its own schema, its own data file, a new entry in the
page's `VALIDATIONS` array, and (if its raw telemetry fields don't match
an existing platform's) a new telemetry field group in the detail-panel
renderer.

Most field groups are shared verbatim across both catalogues today — the
telemetry group is the one place they diverge, since a Linux auditd
trail and a FortiGate CLI/log trail are genuinely different kinds of
evidence:

| Field group | Fields |
|---|---|
| Identity | `id`, `platform`, `category`, `category_sub`, `event_type`, `title`, `description` |
| The action itself | `typical_mechanism`, `action`, `object_type`, `privilege_level`, `privilege_transition`, `expected_result`, `status` |
| MITRE ATT&CK | `mitre_attack.tactics[]`, `mitre_attack.techniques[]` (resolved live — see above) |
| Test execution | `safe_test`, `test_step`, `test_environment`, `rollback_step`, `evidence_expected`, `telemetry_coverage`, `test_result` |
| Expected telemetry (RHEL) | `audit_key`, `audit_record_types[]`, `expected_syscall`, `expected_executable`, `expected_path`, `expected_auid`, `expected_uid`, `expected_euid`, `expected_command`, `expected_fields[]` |
| Expected telemetry (FortiGate) | `fortigate_cli_context`, `expected_config_path`, `expected_log_type_subtype`, `expected_admin_user`, `expected_source_ip`, `expected_interface_ui`, `expected_command_change`, `expected_fields[]` |
| Splunk mapping | `validation_spl`, `splunk_sourcetype[]`, `cim_data_model`, `cim_action` |
| Detection & compliance | `detection_priority`, `detection_required`, `alert_required`, `compliance_relevant`, `cis_reference`, `stig_reference`, `ism_reference` |
| Provenance | `notes`, `author`, `created`, `modified`, `version` |

`test_result` ships as `"Not Tested"` on every entry — it's a field for
whoever actually runs the validation in their own environment to fill
in, not something this library can populate on their behalf.
`cis_reference`/`stig_reference`/`ism_reference` similarly ship as
placeholder text from the source workbook ("TBD — map to deployed CIS
benchmark/version") — they need to be filled in against your own
organization's specific benchmark/STIG/ISM baseline version, which this
library has no way to know.

## Design: same page, new content type

The Validations page reuses the Detections page's exact visual and
interaction design — search bar, collapsible filter sidebar, card grid,
shared detail overlay — via its own dedicated toolbar and sidebar (styled
identically via the same CSS classes, functionally independent so
neither page's state leaks into the other, the same pattern the Heat
Coverage tab already established). Facets: Platform, Category, Event
Type, Detection Priority, MITRE ATT&CK Tactic, SAFE Test. The detail
panel adds sections this content type needs that a detection entry
doesn't — Test Step (with a Copy button), Validation & Rollback, an
Expected Telemetry section whose fields and title depend on which
platform the entry belongs to (auditd for RHEL, CLI/log context for
FortiGate), Splunk Mapping, and Detection & Compliance.

## Attribution and license

These catalogues' structure and MITRE ATT&CK resolution are this
project's own work; their source content (the privileged-action
definitions, test steps, and telemetry mappings) comes from the two
uploaded workbooks. `mitre_attack` fields are resolved against the
official MITRE ATT&CK STIX corpus ([mitre/cti](https://github.com/mitre/cti),
Apache-2.0-licensed on `mitre-attack`, CC-BY-4.0 on ATT&CK-name content).
