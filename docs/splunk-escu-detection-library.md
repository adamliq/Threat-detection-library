# Splunk Security Content (ESCU) Catalogue

Companion index to `data/splunk-escu-detections.json` (556 Splunk SPL
detections). Unlike every other catalogue in this library, **these
detections are not authored for this project.** They are a curated,
schema-converted subset of detections from Splunk's own official
[`security_content`](https://github.com/splunk/security_content) project
(Splunk Enterprise Security Content Updates, "ESCU") —
Apache-2.0-licensed, actively maintained by Splunk's threat research team,
and running in production Splunk ES deployments today.

The catalogue draws from three upstream source directories, brought in as
four separate batches (`detections/endpoint` contributed two: Windows,
then Linux):

- **`detections/endpoint`, Windows-scoped** (265 entries,
  `component: "Windows Endpoint"`) — Windows-scoped Sysmon/EDR host
  telemetry. See "Scope and curation methodology" below.
- **`detections/application`** (29 entries, `component: "ESXi"` or
  `"Splunk Platform"`) — VMware ESXi syslog and Splunk's own internal
  telemetry. See "The `detections/application` batch: ESXi and Splunk"
  below.
- **`detections/network`** (77 entries, `component: "Cisco Network"`,
  `"Windows Network Telemetry"`, `"F5 BIG-IP"`, or generic `"Network"`) —
  network-perimeter telemetry: Cisco IOS/Secure Firewall/SD-WAN/Secure
  Access, Zeek/Suricata/Splunk Stream network-sensor data, Palo Alto
  Networks, AWS VPC Flow Logs, and Windows-network-visible behavior. See
  "The `detections/network` batch: everything that qualified" below.
- **`detections/endpoint`, Linux-scoped** (185 entries,
  `component: "Linux"`) — Sysmon-for-Linux and Linux auditd host
  telemetry. See "The Linux batch: all of `detections/endpoint`'s
  `linux_*` files" below.

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
selecting the highest-value slice of a much larger corpus and mapping it
into this library's schema so it's searchable and filterable alongside the
other eleven catalogues, not rewriting the underlying analytics.

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
prior 1,870-detection total across eleven catalogues combined. Bringing in
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

## The `detections/application` batch: ESXi and Splunk

A second, smaller batch (29 entries) was pulled from
`security_content`'s `detections/application` directory, filtered to
files named for VMware ESXi (23) and Splunk itself (8, of which 6 were
kept). Unlike the endpoint batch's ~1,250-candidate pool, this directory
had a naturally small, fully-reviewable set — every candidate file was
read individually rather than scored/capped algorithmically.

**Curation for this batch:**

- **Status filter, applied the same way**: `splunk_secure_application_alerts_for_runtime_security.yml`
  is `status: experimental` and was excluded.
- **MITRE-mapping requirement, applied the same way**: `splunk_appdynamics_secure_application_alerts.yml`
  carries `mitre_attack_id: []` (no ATT&CK mapping — it's a third-party
  AppDynamics alert-passthrough correlator, not a MITRE-technique-grounded
  detection) and was excluded for the same reason every other catalogue in
  this library requires a validated technique mapping on every entry.
- **No overlap exclusions were needed**, despite real topical overlap with
  this library's existing content — see below for why.

**Why the ESXi entries aren't redundant with this library's existing
31-entry ESXi/Splunk catalogue**, despite many sharing a topic (firewall
disable, VIB tampering, lockdown mode, SSH enablement, VM discovery): the
telemetry layer is different. This library's own ESXi catalogue detects
via `shell.log`/`hostd.log` — ESXi's local command-history and
task-completion logs, which require pulling files directly off the host
(via SSH/API or a scripted export). Every one of these 23 new entries
instead reads `` `esxi_syslog` `` — the standard **syslog stream** ESXi
emits when configured to forward logs remotely, the far more common
baseline most VMware hardening guides recommend as a first step. A
security team with only basic syslog forwarding configured (no
shell.log/hostd.log collection pipeline) gets real coverage from this
batch that the original catalogue's `shell.log`/`hostd.log`-dependent
entries can't provide them, and vice versa — treat the two as two
independent telemetry bets on the same attacker behaviors, not a
duplicate pair.

**Why the Splunk entries aren't redundant with this library's existing
337-entry Splunk Platform catalogue**: that catalogue was deliberately
built around administrative/configuration abuse and behavioral anomalies
(and explicitly avoids claiming CVE-specific exploit-signature detection).
These 6 entries are the opposite: real exploit-signature detections for
*specific, named Splunk CVEs* (CVE-2023-46214 XSLT RCE, CVE-2024-45731/
-45733 arbitrary file write, CVE-2024-29945/-45738/-45739 debug-log
information disclosure, CVE-2021-33845 user enumeration, CVE-2024-36992
dashboard XSS), sourced from Splunk's own security advisories and grounded
in real `_internal`/`_audit` log patterns — a genuinely different, and
genuinely useful, complementary angle this library's own catalogue chose
not to cover.

## The `detections/network` batch: everything that qualified

A third batch (77 entries) brings in **every qualifying file** from
`security_content`'s `detections/network` directory — no topical-overlap
curation was applied this time, unlike the first two batches. "Qualifying"
still means the same two hard, library-wide non-negotiables every other
catalogue in this project is held to:

- **`status: production` only.** 22 of the directory's 101 files are
  `experimental` and were excluded.
- **A non-empty, validated MITRE ATT&CK technique mapping.** 2 more files
  (`cisco_secure_firewall___bits_network_activity.yml`,
  `protocols_passing_authentication_in_cleartext.yml`) are `production`
  but carry `mitre_attack_id: []` and were excluded for the same reason
  `splunk_appdynamics_secure_application_alerts.yml` was excluded from the
  application batch. All 30 distinct technique IDs used by the remaining
  77 files validated against the current MITRE ATT&CK Enterprise STIX
  corpus with zero invalid IDs.

That leaves **77 of 101** files, spanning Cisco IOS/Secure Firewall
(Snort IPS)/SD-WAN/Secure Access (Umbrella), generic network-sensor data
(Zeek `conn.log`, Suricata, Splunk Stream), Palo Alto Networks, F5 BIG-IP,
AWS VPC Flow Logs, and Windows-network-visible behavior (AD replication
traffic, rogue domain controllers, SIGRed via Zeek/Stream, RDP brute
force over the wire). `component` reflects the vendor/telemetry source:
`Cisco Network` (45), generic `Network` (25, the Zeek/Suricata/Stream/
cross-vendor entries), `Windows Network Telemetry` (6), `F5 BIG-IP` (1).

**Primary tactic assignment reverts to the mechanical rule** used by the
original endpoint batch (the first tactic of the first listed MITRE
technique ID) rather than the application batch's hand-curated approach —
at 77 files this is large enough that individual review of every
multi-tactic technique's best-fit tactic wasn't practical, and the
mechanical rule is the same one already used for 265 of this catalogue's
371 entries.

**On overlap with this library's own catalogues:** a number of these
entries are topically adjacent to existing content — `detect_rogue_dhcp_
server.yml` to this library's `DHCP-NET-###` rogue-DHCP detections,
`windows_remote_desktop_network_bruteforce_attempt.yml` and
`remote_desktop_network_traffic.yml` to `RDP-AUTH-###`/`RDP-NET-###`. As
with the application batch, the telemetry layer differs — these entries
are network-sensor perspective (Zeek/Suricata/Stream watching the wire)
rather than the Windows-Event-Log-based perspective this library's own
DHCP/RDP catalogues use — but unlike the application batch, **that
distinction wasn't used to decide inclusion here**; every qualifying file
was brought in regardless of overlap, per explicit instruction for this
batch. Treat entries that read like duplicates of existing content as a
second telemetry angle on the same behavior, and check each entry's
`data_sources[]` before assuming redundancy.

## The Linux batch: all of `detections/endpoint`'s `linux_*` files

A fourth batch (185 entries) returns to `detections/endpoint` — the same
directory the original Windows batch drew from — and takes every file
matching the project's own `linux_*.yml` naming convention (185 of the
directory's 1,500 files; `windows_*` accounts for 767, `macos_*` for 14,
the rest are unprefixed/cross-platform and out of scope for this batch).
This convention is unambiguous and consistently applied upstream, so no
separate platform-classification heuristic was needed the way it was for
the original ~1,250-candidate Windows batch.

**Every one of the 185 files already met this library's two hard bars
with no exclusions needed**: all 185 are `status: production`, and all
185 carry a non-empty MITRE technique mapping (71 distinct technique IDs
used, all validated against the current ATT&CK STIX corpus with zero
invalid IDs). Telemetry is Sysmon for Linux (process/file/network
events), Linux auditd (EXECVE/PROCTITLE/SYSCALL/PATH/CWD records),
traditional syslog (`/var/log/messages`, `/var/log/secure`), or — for 4
container-aware entries — Cisco Isovalent (Cilium/eBPF) process-execution
telemetry. `component` is `"Linux"` for all 185.

**Be aware of real overlap with this library's own Red Hat catalogue.**
Unlike the ESXi and network batches, where a genuine telemetry-layer
difference justified including topically-similar content, this batch
shares the *same* telemetry mechanism (Linux auditd) as significant parts
of `data/redhat-detections.json`'s `RHEL-###` namespace. Concretely:
`RHEL-025` ("auditd Service Stopped or Failed") overlaps
`linux_auditd_auditd_service_stop.yml`/`linux_auditd_auditd_daemon_abort.yml`;
`RHEL-044` ("Crontab or /etc/cron.d Entry Added") overlaps
`linux_add_files_in_known_crontab_directories.yml`; `RHEL-017` ("SSH
authorized_keys Created or Modified") overlaps
`linux_account_manipulation_of_ssh_config_and_keys.yml`. This is a
materially different situation from the earlier batches' "different
telemetry layer" framing, and it's called out plainly rather than papered
over: per explicit instruction to bring in **all** Linux content from
this directory, no exclusion was applied for this overlap. If you're
deploying both catalogues, expect some genuine duplicate coverage in the
auditd-based Linux/RHEL space and plan detection-rule deconfliction
accordingly — this library did not attempt to deconflict it for you.

## Namespace coverage matrix

| Namespace | Primary MITRE tactic | Detections |
|---|---|---:|
| `ESCU-IMPAIR-###` | Defense Impairment (TA0112) | 52 |
| `ESCU-STEALTH-###` | Stealth (TA0005 — MITRE's current name for the classic "Defense Evasion" tactic) | 56 |
| `ESCU-EXEC-###` | Execution | 61 |
| `ESCU-CRED-###` | Credential Access | 35 |
| `ESCU-DISC-###` | Discovery | 40 |
| `ESCU-PERSIST-###` | Persistence | 44 |
| `ESCU-LM-###` | Lateral Movement | 29 |
| `ESCU-PRIV-###` | Privilege Escalation | 78 |
| `ESCU-IMPACT-###` | Impact | 33 |
| `ESCU-INIT-###` | Initial Access | 36 |
| `ESCU-C2-###` | Command and Control | 39 |
| `ESCU-COLL-###` | Collection | 15 |
| `ESCU-EXFIL-###` | Exfiltration | 20 |
| `ESCU-RECON-###` | Reconnaissance | 13 |
| `ESCU-RESDEV-###` | Resource Development | 5 |
| **Total** | | **556** |

Each entry's namespace reflects its *primary* tactic — the first tactic
resolved from its first MITRE technique ID for the endpoint, network, and
Linux batches (265 + 77 + 185 = 527 of 556 entries); a hand-assigned
primary tactic based on the detection's actual description, for the
smaller, individually-reviewed application batch (29 entries), where its
technique(s) mapped to more than one tactic. Many entries legitimately map
to additional tactics too; see each entry's full `mitre_attack.tactics`
array rather than relying on the ID prefix alone for tactic filtering.
`ESCU-C2-###` and `ESCU-INIT-###` grew the most from the network batch;
`ESCU-PRIV-###` grew the most from the Linux batch (Linux privilege
escalation — sudo/SUID/capability abuse, kernel exploits — is one of the
most heavily represented technique families in the source project's own
Linux content).

**217 distinct MITRE ATT&CK techniques** are represented across the 556
entries — every technique ID was validated against the current MITRE
ATT&CK Enterprise STIX corpus (spec version 3.3.0), the same validation
this library's own generator scripts apply to their own content.

| Component | Detections |
|---|---:|
| Windows Endpoint | 265 |
| Linux | 185 |
| Cisco Network | 45 |
| Network (generic/cross-vendor) | 25 |
| ESXi | 23 |
| Windows Network Telemetry | 6 |
| Splunk Platform | 6 |
| F5 BIG-IP | 1 |

## Severity, confidence, and false positives

| Severity | Count | | Confidence | Count | | FP Rating | Count |
|---|---:|---|---|---:|---|---|---:|
| Medium | 235 | | High | 337 | | Low | 379 |
| Low | 131 | | Medium | 192 | | Medium | 160 |
| High | 100 | | Low | 27 | | High | 17 |
| Critical | 90 | | | | | | |

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
| TTP | 333 | | Level 3 — behavioral | 333 | | Low cost | 337 |
| Anomaly | 192 | | Level 2 — threshold | 192 | | Medium cost | 215 |
| Hunting | 27 | | Level 1 — indicator | 27 | | High cost | 4 |
| Correlation | 4 | | Level 4 — correlation | 4 | | | |

`detection_type` is preserved **verbatim** from the source project's own
`type` field — this is the one field in this catalogue's schema that
intentionally does *not* use this library's locally-defined vocabulary,
because the source project's TTP/Anomaly/Hunting/Correlation distinction
is itself meaningful and worth keeping legible rather than force-fitting
into a different taxonomy.

`Low cost` dominates because 337 of 556 entries use `| tstats` against an
accelerated CIM data model (`Endpoint.Processes` for the endpoint and
Linux batches; `Network_Traffic`, `Network_Resolution`, `Web`, or
`Risk.All_Risk` for the network batch) rather than a raw `search`/`stats`
pipeline — this is Splunk's own production-tuned SPL, not this library's
authored SPL, and it shows. The application batch added no new `tstats`
entries (ESXi syslog and Splunk `_internal`/`_audit` aren't
CIM-accelerated data models in this catalogue); the network batch brought
32 more `Low cost` entries alongside 45 `Medium cost` ones; the Linux
batch — heavily `Sysmon for Linux EventID 1` process-creation searches
against `Endpoint.Processes` — brought 122 more `Low cost` entries
alongside 61 `Medium cost` and 2 `High cost` ones.

## Telemetry requirements

| Requirement | Count | Meaning |
|---|---:|---|
| Essential | 340 | Relies on Sysmon (Windows or Linux), native Windows Event Log Security auditing, Linux auditd, VMware ESXi Syslog forwarding, or a network-sensor feed (Zeek/Suricata/Splunk Stream) — foundational telemetry most environments already collect or can enable with a single configuration change. |
| Recommended | 216 | Relies on PowerShell Script Block Logging (requires explicit GPO enablement), CrowdStrike Falcon-specific fields (third-party EDR-specific), Splunk's own `_internal`/`_audit` indexes, or a specific network-appliance vendor's proprietary event log (Cisco Secure Firewall, Cisco SD-WAN, Palo Alto, F5 BIG-IP) that not every environment has deployed. |

## Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 38 | Page immediately / Tier 1 candidate |
| 60–99 | 143 | Investigate same business day |
| 30–59 | 200 | Queue for triage / hunting |
| < 30 | 175 | Enrichment / context-only |

## Top analytic_story tags represented

The `analytic_story` field is Splunk's own grouping of detections around a
specific threat. Filtering `data/splunk-escu-detections.json` on any of
these surfaces every curated detection relevant to that threat:

| Story | Detections | | Story | Detections |
|---|---:|---|---|---:|
| Linux Privilege Escalation | 131 | | China-Nexus Threat Activity | 48 |
| Linux Persistence Techniques | 99 | | Scattered Lapsus$ Hunters | 46 |
| Compromised Windows Host | 88 | | Ransomware | 43 |
| Linux Living Off The Land | 86 | | Cisco Secure Firewall Threat Defense Analytics | 39 |
| Data Destruction | 76 | | Hellcat Ransomware | 38 |
| Compromised Linux Host | 63 | | Living Off The Land | 37 |
| CISA AA23-347A | 51 | | Salt Typhoon | 36 |

`Linux Privilege Escalation`, `Linux Persistence Techniques`, `Linux
Living Off The Land`, and `Compromised Linux Host` are the Linux batch's
own headline stories — together they account for the majority of the
185 new entries, and directly explain why `ESCU-PRIV-###` grew the most
of any namespace in this batch (see above). `Cisco Secure Firewall Threat
Defense Analytics` (39) is the network batch's own headline story,
spanning the 45 Cisco-named entries plus several generic ones; `Salt
Typhoon` (36, a Cisco/telecom-focused nation-state campaign) picked up
more entries from the Linux batch too. `China-Nexus Threat Activity`
first appeared with the application batch and grew further with both the
network and Linux batches — every ESXi entry is tagged to the `ESXi Post
Compromise` story (23 detections, not shown above since it ties with
several other stories) alongside one or more named-campaign tags, since
VMware ESXi has been a documented target of several of the campaigns
represented here.

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

*Generated from `data/splunk-escu-detections.json` (556 entries: 265
Windows-scoped and 185 Linux-scoped from `detections/endpoint`, 29 from
`detections/application`, 77 from `detections/network`), curated from
`splunk/security_content` at the `develop` branch HEAD as of 2026-08-14.
Regenerate these tables after any future curation change — the counts
above are a snapshot, not a live query. To pull a different or larger
slice, see the curation methodology above and `tools/fetch_mitre_platform.py`'s
sibling scripts for the pattern.*
