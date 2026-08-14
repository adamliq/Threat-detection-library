# Splunk Security Content (ESCU) — Windows Endpoint Catalogue

Companion index to `data/splunk-escu-detections.json` (265 Splunk SPL
detections). Unlike every other catalogue in this library, **these
detections are not authored for this project.** They are a curated,
schema-converted subset of the Windows-scoped detections in Splunk's own
official [`security_content`](https://github.com/splunk/security_content)
project (Splunk Enterprise Security Content Updates, "ESCU") —
Apache-2.0-licensed, actively maintained by Splunk's threat research team,
and running in production Splunk ES deployments today.

Every detection ID below is a stable reference into
`data/splunk-escu-detections.json` — look it up by `id` for the full SPL,
investigation steps, and response guidance.

## Why this catalogue exists, and why it's built differently

Every other catalogue in this library was authored specifically for this
project — AI-generated content grounded in documented log formats and
validated MITRE ATT&CK IDs, but not sourced from a single upstream project.
This catalogue inverts that: the detection logic, false-positive
characterization, and implementation guidance are Splunk's own, written and
tuned by their threat research team against real telemetry. This project's
contribution here is **curation and schema conversion**, not authorship —
selecting the highest-value ~20% of a much larger corpus and mapping it
into this library's schema so it's searchable and filterable alongside the
other ten catalogues, not rewriting the underlying analytics.

That distinction is reflected directly in the schema
(`schema/splunk-escu-detection.schema.json`), which adds four fields no
other catalogue in this library has: `source_id`, `source_url`,
`source_version`, and `source_author` — every entry traces back to the
exact upstream file, its Splunk-assigned UUID, and the researcher credited
for it. `analytic_story[]` is also preserved verbatim: Splunk's own
grouping of detections by the specific threat (a ransomware family, an APT
campaign, a technique family) each one supports.

## Scope and curation methodology

`splunk/security_content`'s `detections/endpoint` directory holds **1,500**
files spanning Windows, Linux, macOS, and cross-platform EDR-based content.
Classifying by `data_source` signal (Sysmon EventID, Windows Event Log,
PowerShell Script Block Logging) and Windows-specific keyword matching
identified **~1,250 as Windows-scoped** — larger than this entire library's
prior 1,870-detection total across ten catalogues combined. Bringing in
everything Windows-scoped in one batch was explicitly decided against;
what's here is a **curated subset of 265**, selected as follows:

1. **Status filter**: `status: production` only (1,224 of 1,250 qualify;
   the 26 `experimental` entries were excluded).
2. **Kerberos/DCSync overlap exclusion**: 16 files whose content directly
   duplicates ground this library's `AD-KRB-###`/`AD-ACL-###`/`AD-REPL-###`
   namespaces already cover in comparable or greater depth (Kerberoasting,
   AS-REP roasting, DCSync via replication rights) were excluded by name —
   e.g. `kerberoasting_spn_request_with_rc4_encryption.yml`,
   `windows_ad_domain_replication_acl_addition.yml`. This was a small,
   targeted list (16 of 1,250): the overwhelming majority of
   Active-Directory-tagged ESCU content turned out to be genuinely
   complementary rather than duplicative — see below.
3. **Scoring**: each remaining candidate was scored by `type` (TTP/
   Correlation weighted highest, then Anomaly, then Hunting), the number
   and notability of its `analytic_story` tags (ransomware families, APT
   campaigns, CISA advisories, wiper malware weighted up), and whether it
   carries a `finding.entity.score` (a signal of more actively-maintained,
   risk-scored content).
4. **Per-tactic caps**: rather than simply taking the top-N by score
   (which would have skewed heavily toward whichever tactic happens to
   have the most content), candidates were grouped by primary MITRE
   tactic and capped per group (30 for Stealth/Defense Impairment, down
   to 4 for the rarely-applicable Resource Development) — so the final
   265 covers the full kill chain rather than one or two tactics.

### Why "Active Directory"-tagged ESCU content isn't mostly redundant

At first glance, `analytic_story` tags like "Active Directory Discovery,"
"Active Directory Lateral Movement," and "Sneaky Active Directory
Persistence Tricks" look like they'd duplicate this library's `AD-###`
catalogue. In practice they don't, because they operate on a different
telemetry layer: this library's `AD-###` catalogue is built almost
entirely around **domain-controller-side Security event log auditing**
(4662/5136/4769/4728, Directory Service Access auditing) — what happened
*inside AD*. ESCU's Windows-endpoint content is built around **host-side
Sysmon/EDR process-execution telemetry** — what ran *on a workstation or
member server* (`adfind.exe`, `bloodhound`/`sharphound`, `dsquery.exe`
abuse, `certutil` misuse, PowerView cmdlets via Script Block Logging).
Only the narrow slice that used the *same* DC-Security-log telemetry this
library's AD catalogue already covers (direct Kerberoasting/DCSync
searches) was excluded; the process-execution-based AD-attack-tooling
detections were kept as a genuinely complementary layer.

## Namespace coverage matrix

| Namespace | Primary MITRE tactic | Detections |
|---|---|---:|
| `ESCU-IMPAIR-###` | Defense Impairment (TA0112) | 30 |
| `ESCU-STEALTH-###` | Stealth (TA0005 — MITRE's current name for the classic "Defense Evasion" tactic) | 30 |
| `ESCU-EXEC-###` | Execution | 25 |
| `ESCU-CRED-###` | Credential Access | 22 |
| `ESCU-DISC-###` | Discovery | 22 |
| `ESCU-PERSIST-###` | Persistence | 20 |
| `ESCU-LM-###` | Lateral Movement | 18 |
| `ESCU-PRIV-###` | Privilege Escalation | 18 |
| `ESCU-IMPACT-###` | Impact | 18 |
| `ESCU-INIT-###` | Initial Access | 15 |
| `ESCU-C2-###` | Command and Control | 15 |
| `ESCU-COLL-###` | Collection | 12 |
| `ESCU-EXFIL-###` | Exfiltration | 8 |
| `ESCU-RECON-###` | Reconnaissance | 8 |
| `ESCU-RESDEV-###` | Resource Development | 4 |
| **Total** | | **265** |

Each entry's namespace reflects its *primary* tactic (the first tactic
resolved from its first MITRE technique ID) — many entries legitimately
map to additional tactics too; see each entry's full `mitre_attack.tactics`
array rather than relying on the ID prefix alone for tactic filtering.

**141 distinct MITRE ATT&CK techniques** are represented across the 265
entries — every technique ID was validated against the current MITRE
ATT&CK Enterprise STIX corpus (spec version 3.3.0), the same validation
this library's own generator scripts apply to their own content.

## Severity, confidence, and false positives

| Severity | Count | | Confidence | Count | | FP Rating | Count |
|---|---:|---|---|---:|---|---|---:|
| Medium | 118 | | High | 234 | | Low | 185 |
| Critical | 63 | | Medium | 26 | | Medium | 78 |
| High | 58 | | Low | 5 | | High | 2 |
| Low | 26 | | | | | | |

Severity/confidence/`risk_scoring` were **derived, not copied** — the
source project doesn't carry this library's 1–5 severity/confidence/impact
model. Severity starts from `type` (TTP/Correlation baseline higher than
Anomaly/Hunting), then gets a bump *only* for tactics where the individual
action is inherently high-stakes regardless of campaign (Credential
Access, Impact, Lateral Movement, Privilege Escalation, Defense
Impairment, Initial Access) — deliberately **not** for every entry tagged
to a marquee `analytic_story` like a named ransomware family, since a
Discovery-tactic technique (e.g. enumerating AD accounts) isn't more
severe on its own merits just because it's also relevant to a ransomware
campaign. `false_positive_rating` is derived from the source project's own
`known_false_positives` free-text guidance via phrase matching (the
Low-heavy skew reflects that most of the curated set is `type: TTP` —
narrowly-scoped behavioral detections that Splunk's own guidance
characterizes as low-noise, versus the broader Hunting/Anomaly searches
that generate more caveat text).

## Detection type, maturity, and search cost

| Type | Count | | Maturity | Count | | Search cost | Count |
|---|---:|---|---|---:|---|---|---:|
| TTP | 233 | | Level 3 — behavioral | 233 | | Low cost | 183 |
| Anomaly | 26 | | Level 2 — threshold | 26 | | Medium cost | 81 |
| Hunting | 5 | | Level 1 — indicator | 5 | | High cost | 1 |
| Correlation | 1 | | Level 4 — correlation | 1 | | | |

`detection_type` is preserved **verbatim** from the source project's own
`type` field — this is the one field in this catalogue's schema that
intentionally does *not* use this library's locally-defined vocabulary,
because the source project's TTP/Anomaly/Hunting/Correlation distinction
is itself meaningful and worth keeping legible rather than force-fitting
into a different taxonomy.

`Low cost` dominates because 183 of 265 entries use `| tstats` against an
accelerated data model (`Endpoint.Processes`) rather than a raw
`search`/`stats` pipeline — this is Splunk's own production-tuned SPL, not
this library's authored SPL, and it shows.

## Telemetry requirements

| Requirement | Count | Meaning |
|---|---:|---|
| Essential | 118 | Relies on Sysmon or native Windows Event Log Security auditing — foundational telemetry most environments already collect. |
| Recommended | 147 | Relies on PowerShell Script Block Logging (requires explicit GPO enablement) or CrowdStrike Falcon-specific fields (third-party EDR-specific, not portable to every environment). |

## Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 25 | Page immediately / Tier 1 candidate |
| 60–99 | 94 | Investigate same business day |
| 30–59 | 93 | Queue for triage / hunting |
| < 30 | 53 | Enrichment / context-only |

## Top analytic_story tags represented

The `analytic_story` field is Splunk's own grouping of detections around a
specific threat. Filtering `data/splunk-escu-detections.json` on any of
these surfaces every curated detection relevant to that threat:

| Story | Detections | | Story | Detections |
|---|---:|---|---|---:|
| Compromised Windows Host | 87 | | Hermetic Wiper | 30 |
| CISA AA23-347A | 51 | | Hellcat Ransomware | 27 |
| Data Destruction | 45 | | Windows Defense Evasion Tactics | 27 |
| Ransomware | 37 | | Graceful Wipe Out Attack | 26 |
| Living Off The Land | 36 | | Medusa Ransomware | 24 |
| APT37 Rustonotto and FadeStealer | 35 | | Active Directory Lateral Movement | 23 |
| Scattered Lapsus$ Hunters | 33 | | BlackByte Ransomware | 22 |
| Windows Registry Abuse | 31 | | Prestige Ransomware | 22 |

## SPL notes: this is Splunk's production SPL, not this library's house style

Two things are worth knowing before deploying any entry from this
catalogue, both flagged per-entry in `tuning_guidance`:

- **security_content app macro dependencies.** Much of the SPL calls
  macros like `` `security_content_summariesonly` ``,
  `` `security_content_ctime(firstTime)` ``, `` `drop_dm_object_name(...)` ``,
  and a per-detection `` `<detection_name>_filter` `` macro. These are
  defined by the ESCU/Enterprise Security Content Update Splunkbase app —
  running this SPL standalone (without that app installed) requires either
  installing it or manually recreating the macro definitions. Every
  affected entry's `tuning_guidance` says so explicitly.
- **`| tstats` against `datamodel=Endpoint.Processes`.** The `Low cost`
  majority of this catalogue depends on the CIM Endpoint data model being
  populated and accelerated in your environment (via the Splunk Common
  Information Model add-on and an accelerated data model), not on raw
  index search — different from most of this library's other catalogues,
  which search raw indexed events directly.

## Attribution and license

Every detection's `references[]` array includes a direct link back to its
source file on GitHub and to the `splunk/security_content` project itself.
`source_author` preserves the original researcher credit. The upstream
project is licensed under the
[Apache License 2.0](https://github.com/splunk/security_content/blob/develop/LICENSE) —
permissive, redistribution- and derivative-work-friendly with attribution,
which this catalogue provides via the `source_*` fields and reference
links on every entry, consistent with the license's requirements.

**This library did not modify the detection logic.** The `spl` field is
the source project's own search, reformatted only for whitespace — no
technique, threshold, or filter was altered. Everything this project added
(severity/confidence/risk scoring, `detection_maturity`,
`false_positive_rating`, `response_guidance`, `data_sources[].description`,
`event_ids`, `required_fields`) is clearly this project's own derived
metadata layered on top, not a claim about what Splunk's original
detection said.

---

*Generated from `data/splunk-escu-detections.json` (265 entries), curated
from `splunk/security_content` at the `develop` branch HEAD as of
2026-08-14. Regenerate these tables after any future curation change — the
counts above are a snapshot, not a live query. To pull a different or
larger slice, see the curation methodology above and
`tools/fetch_mitre_platform.py`'s sibling scripts for the pattern.*
