# Changelog

All notable changes to this project are documented here. Versioning
follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR** — breaking changes (an entry ID scheme changes, a schema
  drops/renames a required field, a data file's shape changes in a way
  that breaks an existing integration).
- **MINOR** — new catalogues, new platforms, new pages/features (a new
  detection catalogue, a new MITRE ATT&CK Coverage platform, a new
  validation catalogue, a new tab/view).
- **PATCH** — bug fixes, data corrections, and documentation-only
  updates that don't add or remove content.

The current version lives in [`VERSION`](VERSION) (the single source of
truth — `tools/build.py` reads it and stamps it into the page header)
and is echoed near the top of [`README.md`](README.md).

## [1.0.0] - 2026-08-26

Initial versioned baseline. This release starts version tracking for
the library going forward — it does not retroactively assign version
numbers to the project's prior history, which predates this scheme.
What's included as of this baseline:

- Fourteen detection catalogues sharing the Detections page: ESXi/Splunk
  SPL, VMware Aria Operations for Logs, Red Hat (RHEL/IdM/IPA/FreeIPA/
  AAP/Satellite), Fortinet Security Fabric, Dell iDRAC, HPE iLO, Windows
  DHCP Server, Windows RDP, VMware Cloud Foundation, Splunk Platform,
  Active Directory, Splunk Security Content (ESCU), Cisco Network
  Device, and Windows Endpoint — 4,017 detections total.
- An ATT&CK Coverage browser spanning ten MITRE ATT&CK platforms: ESXi,
  Windows, Cisco, SaaS, Identity Provider, Containers, Linux, IaaS,
  Office Suite, and macOS.
- A Heat Coverage tab (technique × tactic matrix shaded by detection
  density across the whole library).
- A Validations page holding this library's first validation
  catalogues — a distinct content type from the detection catalogues
  (see [`docs/validations.md`](docs/validations.md)): RHEL Privileged
  Action (204 entries), FortiGate Privileged Admin Action (146
  entries), and Cisco SD-WAN Privileged Admin Action (145 entries) — 495
  validation entries total, sharing one page via a `platform` filter
  facet.
