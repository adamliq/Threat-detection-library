# VMware Aria Operations for Logs Threat Detection Catalogue

This catalogue is designed for **VMware Aria Operations for Logs / VMware Aria Operations for Logs search** and intentionally uses **Aria search expressions rather than Splunk SPL**.

This is the canonical source document for [`data/aria-detections.json`](../data/aria-detections.json),
which feeds these detections into the combined [`index.html`](../index.html) library.
Each `### VMW-XXX` entry below
is parsed by [`tools/import_aria_catalogue.py`](../tools/import_aria_catalogue.py) into a
schema-compliant record (see [`schema/aria-detection.schema.json`](../schema/aria-detection.schema.json));
the description, data sources, false-positive notes, and investigation steps in the JSON are
generated from this entry's Component/Severity/MITRE tactic/tuning fields, so if you edit an
entry here, re-run the importer rather than hand-editing the JSON out of sync.

## Query syntax assumptions

Aria field names depend on the VMware content pack, source product version, extracted fields, and whether logs come directly from vCenter, ESXi, VCSA, NSX, or another VMware component. The queries therefore use a combination of:

- Full-text terms in quotes, for example `"lockdown mode"`.
- Boolean operators: `AND`, `OR`, `NOT`.
- Field searches such as `user:root`, `host:*`, `vm_name:*`.
- Parentheses for grouped Boolean expressions.
- Wildcards where commonly supported by the Aria search UI.

**Important:** Treat these as detection search templates. Replace generic fields such as `user`, `username`, `src`, `source_ip`, `vm_name`, `datastore`, and `principal` with the actual fields extracted in your Aria environment.

For count/burst detections, use the Aria UI's time range, grouping, aggregation, and alert threshold functions rather than trying to embed Splunk-style statistical commands in the query.

## Recommended common fields

`user`, `username`, `vc_username`, `src`, `source_ip`, `host`, `hostname`, `vm_name`, `cluster`, `datacenter`, `datastore`, `operation`, `event_type`, `object`, `object_type`, `principal`, `role`, `service`, `result`, `message`

## Catalogue

### VMW-001 - Repeated failed vCenter logins
- **Component:** vCenter / SSO
- **Severity:** High
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1110 Brute Force
- **Aria search query:**

```text
("login failed" OR "authentication failed" OR "invalid credentials") AND (vc_username:* OR user:*)
```
- **Detection logic / tuning:** Threshold: >=5 failures for same user or source in 5 minutes.

### VMW-002 - Successful login after repeated failures
- **Component:** vCenter / SSO
- **Severity:** High
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
("login successful" OR "authentication succeeded") AND (vc_username:* OR user:*)
```
- **Detection logic / tuning:** Correlate with VMW-001 for the same user/source within 15 minutes.

### VMW-003 - Login from unusual source IP
- **Component:** vCenter / SSO
- **Severity:** High
- **MITRE tactic:** Initial Access
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
("login successful" OR "authentication succeeded") AND (src:* OR source_ip:*)
```
- **Detection logic / tuning:** Baseline source IPs per administrator/service account.

### VMW-004 - Privileged administrator login
- **Component:** vCenter / SSO
- **Severity:** High
- **MITRE tactic:** Privilege Escalation
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
(user:administrator OR user:root OR vc_username:administrator OR vc_username:root)
```
- **Detection logic / tuning:** Expand with known privileged accounts/groups.

### VMW-005 - Direct ESXi host login
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Lateral Movement
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
("login" OR "session opened") AND (hostd OR ESXi) AND (user:* OR username:*)
```
- **Detection logic / tuning:** Alert when access is outside approved jump hosts/vCenter paths.

### VMW-006 - Direct ESXi root login
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Privilege Escalation
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
(user:root OR username:root) AND ("login" OR "session opened")
```
- **Detection logic / tuning:** High-value control for ransomware and hypervisor compromise.

### VMW-007 - ESXi SSH service enabled
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562.001 Impair Defenses
- **Aria search query:**

```text
("SSH" AND ("enabled" OR "started")) OR ("TSM-SSH" AND ("start" OR "enable"))
```
- **Detection logic / tuning:** Exclude authorized maintenance windows.

### VMW-008 - ESXi Shell enabled
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1059 Command and Scripting Interpreter
- **Aria search query:**

```text
("ESXi Shell" AND ("enabled" OR "started")) OR ("TSM" AND "LocalShell" AND ("start" OR "enable"))
```
- **Detection logic / tuning:** Critical when enabled outside maintenance.

### VMW-009 - SSH session established to ESXi
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Lateral Movement
- **MITRE technique:** T1021.004 SSH
- **Aria search query:**

```text
("sshd" AND ("Accepted password" OR "Accepted publickey" OR "session opened"))
```
- **Detection logic / tuning:** Capture source IP and user.

### VMW-010 - ESXi shell session used
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Execution
- **MITRE technique:** T1059 Command and Scripting Interpreter
- **Aria search query:**

```text
("shell" AND "session opened") OR ("UserLoginSessionEvent" AND host:*)
```
- **Detection logic / tuning:** Correlate with service enablement.

### VMW-011 - New ESXi local user
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1136 Create Account
- **Aria search query:**

```text
("user" AND ("created" OR "added")) AND (hostd OR "ESXi")
```
- **Detection logic / tuning:** Suppress known provisioning accounts.

### VMW-012 - ESXi local user deleted
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1531 Account Access Removal
- **Aria search query:**

```text
("user" AND ("deleted" OR "removed")) AND (hostd OR "ESXi")
```
- **Detection logic / tuning:** Useful for anti-forensics/admin lockout.

### VMW-013 - ESXi password changed
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("password" AND ("changed" OR "reset")) AND (hostd OR "ESXi")
```
- **Detection logic / tuning:** Prioritize root/admin account changes.

### VMW-014 - vCenter SSO user created
- **Component:** vCenter / SSO
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1136 Create Account
- **Aria search query:**

```text
("SSO" OR "vCenter") AND ("user created" OR "account created" OR "principal added")
```
- **Detection logic / tuning:** Track actor, target account and source.

### VMW-015 - vCenter SSO user deleted
- **Component:** vCenter / SSO
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1531 Account Access Removal
- **Aria search query:**

```text
("SSO" OR "vCenter") AND ("user deleted" OR "account removed" OR "principal removed")
```
- **Detection logic / tuning:** Investigate unexpected administrative deletions.

### VMW-016 - Role created
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Privilege Escalation
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("role" AND ("created" OR "added")) AND (vpxd OR "vCenter")
```
- **Detection logic / tuning:** Review role privileges.

### VMW-017 - Role modified
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Privilege Escalation
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("role" AND ("modified" OR "updated" OR "changed")) AND (vpxd OR "vCenter")
```
- **Detection logic / tuning:** Critical if admin-like privileges are added.

### VMW-018 - Permission assigned
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Privilege Escalation
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("permission" AND ("assigned" OR "added" OR "set")) AND (user:* OR principal:*)
```
- **Detection logic / tuning:** Track principal, role and object scope.

### VMW-019 - Permission removed
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1531 Account Access Removal
- **Aria search query:**

```text
("permission" AND ("removed" OR "deleted")) AND (user:* OR principal:*)
```
- **Detection logic / tuning:** Can indicate lockout or cover-up.

### VMW-020 - Global permission modified
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Privilege Escalation
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("global permission" OR "GlobalPermission") AND ("add" OR "set" OR "update" OR "remove")
```
- **Detection logic / tuning:** One of the highest-value vCenter privilege detections.

### VMW-021 - Identity source added
- **Component:** vCenter / SSO
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("identity source" AND ("added" OR "created")) OR ("LDAP" AND "configured")
```
- **Detection logic / tuning:** Detect rogue AD/LDAP identity providers.

### VMW-022 - Identity source modified
- **Component:** vCenter / SSO
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("identity source" AND ("modified" OR "updated" OR "changed"))
```
- **Detection logic / tuning:** Capture old/new configuration when available.

### VMW-023 - Identity source removed
- **Component:** vCenter / SSO
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1531 Account Access Removal
- **Aria search query:**

```text
("identity source" AND ("removed" OR "deleted"))
```
- **Detection logic / tuning:** Can disrupt authentication.

### VMW-024 - SSO domain/configuration changed
- **Component:** vCenter / SSO
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("SSO" AND ("domain" OR "configuration") AND ("changed" OR "updated" OR "modified"))
```
- **Detection logic / tuning:** Review any unexpected SSO changes.

### VMW-025 - VM created
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Persistence
- **MITRE technique:** T1584 Compromise Infrastructure
- **Aria search query:**

```text
("VirtualMachine" OR vm_name:*) AND ("created" OR "CreateVM" OR "VmCreatedEvent")
```
- **Detection logic / tuning:** Baseline expected provisioning systems.

### VMW-026 - VM cloned
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("clone" OR "CloneVM" OR "VmClonedEvent") AND (vm_name:* OR "VirtualMachine")
```
- **Detection logic / tuning:** Especially sensitive for domain controllers and admin systems.

### VMW-027 - VM exported as OVF/OVA
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Exfiltration
- **MITRE technique:** T1048 Exfiltration Over Alternative Protocol
- **Aria search query:**

```text
("export" AND ("OVF" OR "OVA" OR "virtual machine"))
```
- **Detection logic / tuning:** High-confidence data-theft signal.

### VMW-028 - VM deleted
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1485 Data Destruction
- **Aria search query:**

```text
("DestroyVM" OR "VmRemovedEvent" OR ("virtual machine" AND ("deleted" OR "destroyed")))
```
- **Detection logic / tuning:** Correlate with actor/source.

### VMW-029 - Multiple VMs deleted
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1485 Data Destruction
- **Aria search query:**

```text
("DestroyVM" OR "VmRemovedEvent" OR ("virtual machine" AND ("deleted" OR "destroyed")))
```
- **Detection logic / tuning:** Use Aria aggregation: count distinct VM/object >=5 in 5 minutes.

### VMW-030 - VM powered off
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("PowerOffVM" OR "VmPoweredOffEvent" OR ("virtual machine" AND "powered off"))
```
- **Detection logic / tuning:** Suppress routine orchestration.

### VMW-031 - Mass VM power-off
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("PowerOffVM" OR "VmPoweredOffEvent" OR ("virtual machine" AND "powered off"))
```
- **Detection logic / tuning:** Aggregate distinct VMs >=5 in 5 minutes.

### VMW-032 - VM reset
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("ResetVM" OR "VmResettingEvent" OR ("virtual machine" AND "reset"))
```
- **Detection logic / tuning:** Higher priority for critical workloads.

### VMW-033 - Snapshot created
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("CreateSnapshot" OR "snapshot created" OR "VmSnapshot")
```
- **Detection logic / tuning:** Snapshot creation can precede data theft or ransomware.

### VMW-034 - Mass snapshot creation
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("CreateSnapshot" OR "snapshot created" OR "VmSnapshot")
```
- **Detection logic / tuning:** Aggregate distinct VMs >=5 in 10 minutes.

### VMW-035 - Snapshot deleted
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1490 Inhibit System Recovery
- **Aria search query:**

```text
("RemoveSnapshot" OR "snapshot removed" OR "snapshot deleted")
```
- **Detection logic / tuning:** Prioritize protected workloads.

### VMW-036 - Mass snapshot deletion
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1490 Inhibit System Recovery
- **Aria search query:**

```text
("RemoveSnapshot" OR "snapshot removed" OR "snapshot deleted")
```
- **Detection logic / tuning:** Aggregate distinct VMs >=5 in 5 minutes.

### VMW-037 - All snapshots removed
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1490 Inhibit System Recovery
- **Aria search query:**

```text
("RemoveAllSnapshots" OR "remove all snapshots")
```
- **Detection logic / tuning:** Strong ransomware/recovery inhibition indicator.

### VMW-038 - Virtual disk added
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("virtual disk" OR "VMDK") AND ("added" OR "attached")
```
- **Detection logic / tuning:** Review source and target VM.

### VMW-039 - Existing VMDK attached to another VM
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("VMDK" OR "virtual disk") AND ("reconfigured" OR "attached") AND ("existing" OR "backing")
```
- **Detection logic / tuning:** Can expose offline credentials and sensitive files.

### VMW-040 - Virtual disk removed
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1485 Data Destruction
- **Aria search query:**

```text
("virtual disk" OR "VMDK") AND ("removed" OR "detached")
```
- **Detection logic / tuning:** Alert on critical VMs.

### VMW-041 - ISO mounted
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Execution
- **MITRE technique:** T1204 User Execution
- **Aria search query:**

```text
("CD/DVD" OR "ISO") AND ("mounted" OR "connected" OR "configured")
```
- **Detection logic / tuning:** Useful for tooling/malware introduction.

### VMW-042 - Suspicious ISO mounted
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Execution
- **MITRE technique:** T1204 User Execution
- **Aria search query:**

```text
("ISO" AND ("mounted" OR "connected")) AND NOT ("tools" OR "VMware Tools")
```
- **Detection logic / tuning:** Maintain allowlist of approved ISO paths.

### VMW-043 - Virtual NIC added
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("network adapter" OR "virtual nic" OR "vNIC") AND ("added" OR "created")
```
- **Detection logic / tuning:** Review sensitive workloads.

### VMW-044 - VM network changed
- **Component:** vCenter / Networking
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("network adapter" OR "portgroup" OR "network") AND ("changed" OR "reconfigured") AND vm_name:*
```
- **Detection logic / tuning:** Detect segmentation bypass.

### VMW-045 - VM MAC address changed
- **Component:** vCenter / Networking
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1036 Masquerading
- **Aria search query:**

```text
("MAC address" OR mac:*) AND ("changed" OR "modified")
```
- **Detection logic / tuning:** Can facilitate impersonation.

### VMW-046 - Promiscuous mode enabled
- **Component:** vSphere Networking
- **Severity:** Critical
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1040 Network Sniffing
- **Aria search query:**

```text
("promiscuous" AND ("enabled" OR "true" OR "accept"))
```
- **Detection logic / tuning:** High-confidence sniffing risk.

### VMW-047 - Forged transmits enabled
- **Component:** vSphere Networking
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1036 Masquerading
- **Aria search query:**

```text
("forged transmits" AND ("enabled" OR "true" OR "accept"))
```
- **Detection logic / tuning:** Review distributed/standard switch policy.

### VMW-048 - MAC changes enabled
- **Component:** vSphere Networking
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1036 Masquerading
- **Aria search query:**

```text
("MAC changes" AND ("enabled" OR "true" OR "accept"))
```
- **Detection logic / tuning:** Can weaken L2 controls.

### VMW-049 - Port group created
- **Component:** vSphere Networking
- **Severity:** Medium
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("portgroup" OR "port group") AND ("created" OR "added")
```
- **Detection logic / tuning:** Baseline automation-created networks.

### VMW-050 - Port group modified
- **Component:** vSphere Networking
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("portgroup" OR "port group") AND ("modified" OR "changed" OR "reconfigured")
```
- **Detection logic / tuning:** Track VLAN/security policy changes.

### VMW-051 - Distributed switch modified
- **Component:** vSphere Networking
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("distributed switch" OR "dvSwitch" OR "VDS") AND ("modified" OR "changed" OR "reconfigured")
```
- **Detection logic / tuning:** Critical for broad network impact.

### VMW-052 - VLAN changed
- **Component:** vSphere Networking
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("VLAN" AND ("changed" OR "modified" OR "reconfigured"))
```
- **Detection logic / tuning:** Useful for segmentation bypass.

### VMW-053 - ESXi firewall rule changed
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562.004 Disable or Modify System Firewall
- **Aria search query:**

```text
("firewall" AND ("rule" OR "ruleset") AND ("changed" OR "enabled" OR "disabled" OR "updated"))
```
- **Detection logic / tuning:** Capture ruleset and actor.

### VMW-054 - ESXi firewall disabled
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562.004 Disable or Modify System Firewall
- **Aria search query:**

```text
("firewall" AND ("disabled" OR "off")) AND (ESXi OR hostd)
```
- **Detection logic / tuning:** Strong compromise indicator.

### VMW-055 - NTP configuration changed
- **Component:** ESXi / vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1070 Indicator Removal
- **Aria search query:**

```text
("NTP" OR "time server") AND ("changed" OR "updated" OR "configured" OR "removed")
```
- **Detection logic / tuning:** Time manipulation can undermine investigations.

### VMW-056 - DNS configuration changed
- **Component:** ESXi / vCenter
- **Severity:** High
- **MITRE tactic:** Command and Control
- **MITRE technique:** T1584 Infrastructure
- **Aria search query:**

```text
("DNS" AND ("changed" OR "updated" OR "configured")) AND (ESXi OR vCenter OR hostd)
```
- **Detection logic / tuning:** Detect redirection/manipulation.

### VMW-057 - Syslog destination changed
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562.002 Disable Windows Event Logging
- **Aria search query:**

```text
("Syslog.global.logHost" OR "syslog destination" OR "remote syslog") AND ("changed" OR "updated" OR "set")
```
- **Detection logic / tuning:** ATT&CK sub-technique name is Windows-specific; map more generally to impair logging where preferred.

### VMW-058 - Remote syslog disabled
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("syslog" AND ("disabled" OR "removed" OR "stopped"))
```
- **Detection logic / tuning:** High-value anti-forensics detection.

### VMW-059 - Log level reduced
- **Component:** ESXi / vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("log level" AND ("changed" OR "reduced" OR "disabled"))
```
- **Detection logic / tuning:** Review old/new levels.

### VMW-060 - Audit logging configuration changed
- **Component:** ESXi / vCenter
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("audit" AND ("logging" OR "log") AND ("changed" OR "disabled" OR "modified"))
```
- **Detection logic / tuning:** Prioritize security/audit components.

### VMW-061 - Lockdown mode disabled
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("lockdown mode" AND ("disabled" OR "off"))
```
- **Detection logic / tuning:** Strong control-bypass signal.

### VMW-062 - Lockdown mode changed
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("lockdown mode" AND ("changed" OR "enabled" OR "disabled"))
```
- **Detection logic / tuning:** Track actor/source.

### VMW-063 - Lockdown exception user added
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("lockdown" AND ("exception" OR "exception user") AND ("added" OR "created"))
```
- **Detection logic / tuning:** High priority for privileged accounts.

### VMW-064 - Secure Boot state changed
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1542 Pre-OS Boot
- **Aria search query:**

```text
("Secure Boot" AND ("disabled" OR "changed" OR "not enabled"))
```
- **Detection logic / tuning:** Hardware/firmware support affects expected behavior.

### VMW-065 - VIB installed
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1547 Boot or Logon Autostart Execution
- **Aria search query:**

```text
("VIB" AND ("installed" OR "added"))
```
- **Detection logic / tuning:** Allowlist approved vendor packages.

### VMW-066 - Unsigned or untrusted VIB
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1547 Boot or Logon Autostart Execution
- **Aria search query:**

```text
("VIB" AND ("unsigned" OR "untrusted" OR "acceptance level" OR "CommunitySupported"))
```
- **Detection logic / tuning:** Critical hypervisor persistence indicator.

### VMW-067 - Acceptance level weakened
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("acceptance level" AND ("changed" OR "CommunitySupported" OR "PartnerSupported"))
```
- **Detection logic / tuning:** Baseline expected acceptance level.

### VMW-068 - ESXi software component installed
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1547 Boot or Logon Autostart Execution
- **Aria search query:**

```text
("software component" OR "offline bundle" OR "image profile") AND ("installed" OR "updated" OR "added")
```
- **Detection logic / tuning:** Review maintenance window and signer.

### VMW-069 - ESXi advanced setting changed
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("advanced setting" OR "AdvancedOption" OR "config option") AND ("changed" OR "set" OR "updated")
```
- **Detection logic / tuning:** Create allowlist for managed configuration changes.

### VMW-070 - Host entered maintenance mode
- **Component:** ESXi / vCenter
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("maintenance mode" AND ("entered" OR "enter"))
```
- **Detection logic / tuning:** High priority if multiple hosts or no change record.

### VMW-071 - Host exited maintenance mode unexpectedly
- **Component:** ESXi / vCenter
- **Severity:** Medium
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("maintenance mode" AND ("exited" OR "exit"))
```
- **Detection logic / tuning:** Useful operationally and for change monitoring.

### VMW-072 - Host disconnected from vCenter
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("host" AND ("disconnected" OR "not responding")) AND (vCenter OR vpxd)
```
- **Detection logic / tuning:** Can indicate management-plane evasion.

### VMW-073 - Multiple hosts disconnected
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1499 Endpoint Denial of Service
- **Aria search query:**

```text
("host" AND ("disconnected" OR "not responding")) AND (vCenter OR vpxd)
```
- **Detection logic / tuning:** Aggregate distinct hosts >=3 in 5 minutes.

### VMW-074 - ESXi host rebooted
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("reboot" OR "restarted" OR "HostRebootedEvent") AND (ESXi OR hostd)
```
- **Detection logic / tuning:** Correlate with actor/task.

### VMW-075 - Multiple ESXi hosts rebooted
- **Component:** ESXi / vCenter
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("reboot" OR "restarted" OR "HostRebootedEvent") AND (ESXi OR hostd)
```
- **Detection logic / tuning:** Aggregate distinct hosts >=3 in 10 minutes.

### VMW-076 - Datastore created
- **Component:** Storage
- **Severity:** Medium
- **MITRE tactic:** Persistence
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
("datastore" AND ("created" OR "added"))
```
- **Detection logic / tuning:** Baseline storage provisioning.

### VMW-077 - Datastore removed
- **Component:** Storage
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1485 Data Destruction
- **Aria search query:**

```text
("datastore" AND ("removed" OR "deleted"))
```
- **Detection logic / tuning:** Critical if backing production workloads.

### VMW-078 - Datastore unmounted
- **Component:** Storage
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1486 Data Encrypted for Impact
- **Aria search query:**

```text
("datastore" AND ("unmounted" OR "unmount"))
```
- **Detection logic / tuning:** Can precede destructive storage actions.

### VMW-079 - Datastore file deleted
- **Component:** Storage
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1485 Data Destruction
- **Aria search query:**

```text
("datastore" AND ("file deleted" OR "delete file" OR "removed file"))
```
- **Detection logic / tuning:** Prioritize .vmdk, .vmx, snapshots.

### VMW-080 - Datastore browsing by unusual user
- **Component:** Storage
- **Severity:** Medium
- **MITRE tactic:** Discovery
- **MITRE technique:** T1083 File and Directory Discovery
- **Aria search query:**

```text
("datastore" AND ("browse" OR "browser" OR "list files")) AND (user:* OR username:*)
```
- **Detection logic / tuning:** Baseline admin/service accounts.

### VMW-081 - VMDK copied
- **Component:** Storage
- **Severity:** Critical
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("VMDK" AND ("copy" OR "copied" OR "clone"))
```
- **Detection logic / tuning:** Potential offline credential/data theft.

### VMW-082 - VMDK downloaded
- **Component:** Storage
- **Severity:** Critical
- **MITRE tactic:** Exfiltration
- **MITRE technique:** T1048 Exfiltration Over Alternative Protocol
- **Aria search query:**

```text
("VMDK" AND ("download" OR "export"))
```
- **Detection logic / tuning:** Very high-value data exfiltration signal.

### VMW-083 - VMX file modified
- **Component:** Storage / VM
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1547 Boot or Logon Autostart Execution
- **Aria search query:**

```text
(".vmx" AND ("modified" OR "changed" OR "written"))
```
- **Detection logic / tuning:** Detect offline VM config manipulation.

### VMW-084 - Encryption configuration changed
- **Component:** vCenter / KMS
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1486 Data Encrypted for Impact
- **Aria search query:**

```text
("encryption" AND ("configuration" OR "policy") AND ("changed" OR "updated" OR "disabled"))
```
- **Detection logic / tuning:** Investigate immediately.

### VMW-085 - KMS/key provider added
- **Component:** vCenter / KMS
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1486 Data Encrypted for Impact
- **Aria search query:**

```text
("KMS" OR "key provider") AND ("added" OR "created" OR "configured")
```
- **Detection logic / tuning:** Potential ransomware/control-plane takeover.

### VMW-086 - KMS/key provider changed
- **Component:** vCenter / KMS
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1486 Data Encrypted for Impact
- **Aria search query:**

```text
("KMS" OR "key provider") AND ("changed" OR "modified" OR "updated" OR "removed")
```
- **Detection logic / tuning:** Track actor and endpoint.

### VMW-087 - Backup account anomalous login
- **Component:** vCenter / Backup
- **Severity:** High
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
("login successful" OR "authentication succeeded") AND (user:*backup* OR username:*backup*)
```
- **Detection logic / tuning:** Replace wildcard with known backup accounts if parser does not support substring wildcard.

### VMW-088 - Backup snapshot deletion
- **Component:** vCenter / Backup
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1490 Inhibit System Recovery
- **Aria search query:**

```text
("snapshot" AND ("deleted" OR "removed")) AND (backup OR "VADP" OR "proxy")
```
- **Detection logic / tuning:** Tune to backup product naming.

### VMW-089 - HA disabled
- **Component:** Cluster
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1490 Inhibit System Recovery
- **Aria search query:**

```text
("HA" OR "High Availability") AND ("disabled" OR "turned off")
```
- **Detection logic / tuning:** Strong resilience-degradation signal.

### VMW-090 - Admission control disabled
- **Component:** Cluster
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1490 Inhibit System Recovery
- **Aria search query:**

```text
("admission control" AND ("disabled" OR "off"))
```
- **Detection logic / tuning:** Can weaken HA guarantees.

### VMW-091 - DRS disabled
- **Component:** Cluster
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("DRS" AND ("disabled" OR "turned off"))
```
- **Detection logic / tuning:** Review in conjunction with cluster changes.

### VMW-092 - Cluster configuration changed
- **Component:** Cluster
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("cluster" AND ("configuration changed" OR "reconfigured" OR "modified"))
```
- **Detection logic / tuning:** Baseline scheduled changes.

### VMW-093 - vMotion of sensitive VM
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Lateral Movement
- **MITRE technique:** T1021 Remote Services
- **Aria search query:**

```text
("vMotion" OR "migrated") AND (vm_name:* OR "virtual machine")
```
- **Detection logic / tuning:** Filter to crown-jewel VM list.

### VMW-094 - Bulk vMotion
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Lateral Movement
- **MITRE technique:** T1021 Remote Services
- **Aria search query:**

```text
("vMotion" OR "migrated") AND (vm_name:* OR "virtual machine")
```
- **Detection logic / tuning:** Aggregate distinct VMs >=5 in 10 minutes.

### VMW-095 - Storage vMotion
- **Component:** vCenter / Storage
- **Severity:** High
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("Storage vMotion" OR "storage migration" OR "relocate virtual machine")
```
- **Detection logic / tuning:** Detect movement of VM disks.

### VMW-096 - Unexpected cross-datastore migration
- **Component:** vCenter / Storage
- **Severity:** High
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("relocate" OR "migration") AND ("datastore" OR datastore:*)
```
- **Detection logic / tuning:** Baseline approved source/destination datastores.

### VMW-097 - vCenter certificate changed
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1553 Subvert Trust Controls
- **Aria search query:**

```text
("certificate" AND ("changed" OR "replaced" OR "renewed")) AND (vCenter OR vpxd OR SSO)
```
- **Detection logic / tuning:** Investigate unscheduled certificate operations.

### VMW-098 - vCenter certificate trust failure
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1553 Subvert Trust Controls
- **Aria search query:**

```text
("certificate" AND ("untrusted" OR "validation failed" OR "trust failure")) AND (vCenter OR vpxd)
```
- **Detection logic / tuning:** Can indicate interception or bad replacement.

### VMW-099 - vCenter service stopped
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1489 Service Stop
- **Aria search query:**

```text
("service" AND ("stopped" OR "terminated")) AND (vpxd OR vCenter OR "vmware-vpxd")
```
- **Detection logic / tuning:** Prioritize core management services.

### VMW-100 - Repeated vCenter service crashes
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1489 Service Stop
- **Aria search query:**

```text
((vpxd OR vCenter) AND ("crash" OR "terminated unexpectedly" OR "core dump"))
```
- **Detection logic / tuning:** Threshold repeated occurrences within short interval.

### VMW-101 - vCenter API authentication failures
- **Component:** vCenter API
- **Severity:** High
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1110 Brute Force
- **Aria search query:**

```text
("API" OR "REST" OR "SOAP") AND ("authentication failed" OR "unauthorized" OR "401")
```
- **Detection logic / tuning:** Group by source/user.

### VMW-102 - High-volume API activity
- **Component:** vCenter API
- **Severity:** High
- **MITRE tactic:** Execution
- **MITRE technique:** T1059 Command and Scripting Interpreter
- **Aria search query:**

```text
("API" OR "REST" OR "SOAP") AND (user:* OR src:*)
```
- **Detection logic / tuning:** Aggregate request count by user/source and compare to baseline.

### VMW-103 - Unexpected service-account interactive login
- **Component:** vCenter / ESXi
- **Severity:** High
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
("login successful" OR "session opened") AND (user:*svc* OR username:*svc*)
```
- **Detection logic / tuning:** Replace with explicit service account list.

### VMW-104 - Administrative activity outside maintenance window
- **Component:** vCenter / ESXi
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
("reconfigured" OR "changed" OR "created" OR "deleted" OR "enabled" OR "disabled") AND (user:* OR username:*)
```
- **Detection logic / tuning:** Implement schedule/context in alert logic.

### VMW-105 - New vCenter extension registered
- **Component:** vCenter
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1505 Server Software Component
- **Aria search query:**

```text
("extension" AND ("registered" OR "added" OR "installed")) AND (vCenter OR vpxd)
```
- **Detection logic / tuning:** Review extension key/vendor and initiating user.

### VMW-106 - vCenter extension removed
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("extension" AND ("unregistered" OR "removed" OR "deleted")) AND (vCenter OR vpxd)
```
- **Detection logic / tuning:** Can disable security/backup integrations.

### VMW-107 - vCenter plugin installed or enabled
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1505 Server Software Component
- **Aria search query:**

```text
("plugin" AND ("installed" OR "enabled" OR "activated")) AND (vCenter OR "vSphere Client")
```
- **Detection logic / tuning:** Allowlist approved plugins.

### VMW-108 - vCenter plugin disabled or removed
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("plugin" AND ("disabled" OR "removed" OR "uninstalled")) AND (vCenter OR "vSphere Client")
```
- **Detection logic / tuning:** Prioritize monitoring/security plugins.

### VMW-109 - Host certificate replaced
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Persistence
- **MITRE technique:** T1553 Subvert Trust Controls
- **Aria search query:**

```text
("certificate" AND ("replaced" OR "changed")) AND (hostd OR ESXi)
```
- **Detection logic / tuning:** Check signer/fingerprint and maintenance context.

### VMW-110 - Host certificate trust warning
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Credential Access
- **MITRE technique:** T1553 Subvert Trust Controls
- **Aria search query:**

```text
("certificate" AND ("untrusted" OR "invalid" OR "expired" OR "trust")) AND (hostd OR ESXi)
```
- **Detection logic / tuning:** Useful for interception/misconfiguration.

### VMW-111 - Host configuration restored
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("configuration" AND ("restored" OR "restore")) AND (ESXi OR hostd)
```
- **Detection logic / tuning:** Unexpected config restoration can overwrite controls.

### VMW-112 - Host configuration backup downloaded
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("configuration" AND ("backup" OR "download")) AND (ESXi OR hostd)
```
- **Detection logic / tuning:** May expose credentials/configuration secrets.

### VMW-113 - SNMP configuration changed
- **Component:** ESXi / vCenter
- **Severity:** High
- **MITRE tactic:** Command and Control
- **MITRE technique:** T1041 Exfiltration Over C2 Channel
- **Aria search query:**

```text
("SNMP" AND ("changed" OR "configured" OR "enabled" OR "community"))
```
- **Detection logic / tuning:** Detect rogue monitoring/exfiltration configuration.

### VMW-114 - SNMP enabled
- **Component:** ESXi / vCenter
- **Severity:** Medium
- **MITRE tactic:** Command and Control
- **MITRE technique:** T1041 Exfiltration Over C2 Channel
- **Aria search query:**

```text
("SNMP" AND ("enabled" OR "started"))
```
- **Detection logic / tuning:** Baseline expected management hosts.

### VMW-115 - Host proxy settings changed
- **Component:** ESXi / vCenter
- **Severity:** High
- **MITRE tactic:** Command and Control
- **MITRE technique:** T1090 Proxy
- **Aria search query:**

```text
("proxy" AND ("configured" OR "changed" OR "updated")) AND (ESXi OR vCenter)
```
- **Detection logic / tuning:** Potential traffic redirection.

### VMW-116 - vCenter outbound proxy changed
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Command and Control
- **MITRE technique:** T1090 Proxy
- **Aria search query:**

```text
("proxy" AND ("configured" OR "changed" OR "updated")) AND (vCenter OR VCSA)
```
- **Detection logic / tuning:** Review destination and initiator.

### VMW-117 - New scheduled task
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1053 Scheduled Task/Job
- **Aria search query:**

```text
("scheduled task" AND ("created" OR "added"))
```
- **Detection logic / tuning:** Look for destructive or privileged operations.

### VMW-118 - Scheduled task modified
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1053 Scheduled Task/Job
- **Aria search query:**

```text
("scheduled task" AND ("modified" OR "changed" OR "updated"))
```
- **Detection logic / tuning:** Capture target action and account.

### VMW-119 - Scheduled task deleted
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1070 Indicator Removal
- **Aria search query:**

```text
("scheduled task" AND ("deleted" OR "removed"))
```
- **Detection logic / tuning:** Can remove monitoring/backup tasks.

### VMW-120 - Alarm disabled
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("alarm" AND ("disabled" OR "turned off"))
```
- **Detection logic / tuning:** Prioritize security/availability alarms.

### VMW-121 - Alarm definition changed
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("alarm" AND ("changed" OR "modified" OR "reconfigured"))
```
- **Detection logic / tuning:** Baseline expected admin activity.

### VMW-122 - Event/alarm action removed
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("alarm" AND "action" AND ("removed" OR "deleted" OR "disabled"))
```
- **Detection logic / tuning:** Can suppress notification/automation.

### VMW-123 - VM guest operations executed
- **Component:** vCenter / Guest Operations
- **Severity:** High
- **MITRE tactic:** Execution
- **MITRE technique:** T1059 Command and Scripting Interpreter
- **Aria search query:**

```text
("GuestOperations" OR "guest operation" OR "process manager") AND ("start" OR "execute" OR "run")
```
- **Detection logic / tuning:** Very valuable where guest operations are rare.

### VMW-124 - Guest file copied into VM
- **Component:** vCenter / Guest Operations
- **Severity:** High
- **MITRE tactic:** Execution
- **MITRE technique:** T1105 Ingress Tool Transfer
- **Aria search query:**

```text
("guest file" OR "FileManager") AND ("copy" OR "upload" OR "transfer")
```
- **Detection logic / tuning:** Potential payload transfer.

### VMW-125 - Guest file copied out of VM
- **Component:** vCenter / Guest Operations
- **Severity:** High
- **MITRE tactic:** Exfiltration
- **MITRE technique:** T1048 Exfiltration Over Alternative Protocol
- **Aria search query:**

```text
("guest file" OR "FileManager") AND ("download" OR "copy out" OR "transfer")
```
- **Detection logic / tuning:** Potential data theft.

### VMW-126 - VMware Tools upgrade initiated unusually
- **Component:** vCenter / VM
- **Severity:** Medium
- **MITRE tactic:** Execution
- **MITRE technique:** T1105 Ingress Tool Transfer
- **Aria search query:**

```text
("VMware Tools" AND ("upgrade" OR "install"))
```
- **Detection logic / tuning:** Baseline automation and maintenance.

### VMW-127 - Guest OS shutdown initiated from vCenter
- **Component:** vCenter / VM
- **Severity:** Medium
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("ShutdownGuest" OR "guest shutdown" OR "shut down guest")
```
- **Detection logic / tuning:** Higher priority for multiple VMs.

### VMW-128 - Guest OS reboot initiated from vCenter
- **Component:** vCenter / VM
- **Severity:** Medium
- **MITRE tactic:** Impact
- **MITRE technique:** T1529 System Shutdown/Reboot
- **Aria search query:**

```text
("RebootGuest" OR "guest reboot" OR "restart guest")
```
- **Detection logic / tuning:** Correlate with admin activity.

### VMW-129 - VM console opened by unusual user
- **Component:** vCenter / VM
- **Severity:** High
- **MITRE tactic:** Lateral Movement
- **MITRE technique:** T1021 Remote Services
- **Aria search query:**

```text
("console" AND ("opened" OR "connected" OR "session")) AND (user:* OR username:*)
```
- **Detection logic / tuning:** Baseline helpdesk/admin users.

### VMW-130 - VM remote console ticket requested
- **Component:** vCenter / VM
- **Severity:** Medium
- **MITRE tactic:** Lateral Movement
- **MITRE technique:** T1021 Remote Services
- **Aria search query:**

```text
("console ticket" OR "AcquireTicket" OR "webmks")
```
- **Detection logic / tuning:** Useful where VMRC/WebMKS access is controlled.

### VMW-131 - Content library item created
- **Component:** vCenter Content Library
- **Severity:** Medium
- **MITRE tactic:** Persistence
- **MITRE technique:** T1105 Ingress Tool Transfer
- **Aria search query:**

```text
("content library" AND ("item created" OR "created item" OR "added"))
```
- **Detection logic / tuning:** Review source and publisher.

### VMW-132 - Content library item downloaded
- **Component:** vCenter Content Library
- **Severity:** High
- **MITRE tactic:** Collection
- **MITRE technique:** T1005 Data from Local System
- **Aria search query:**

```text
("content library" AND ("download" OR "export"))
```
- **Detection logic / tuning:** Potential image/template exfiltration.

### VMW-133 - Content library subscription changed
- **Component:** vCenter Content Library
- **Severity:** High
- **MITRE tactic:** Command and Control
- **MITRE technique:** T1105 Ingress Tool Transfer
- **Aria search query:**

```text
("content library" AND ("subscription" OR "publisher") AND ("changed" OR "added" OR "modified"))
```
- **Detection logic / tuning:** Detect rogue external publishers.

### VMW-134 - Content library external URL changed
- **Component:** vCenter Content Library
- **Severity:** Critical
- **MITRE tactic:** Command and Control
- **MITRE technique:** T1105 Ingress Tool Transfer
- **Aria search query:**

```text
("content library" AND ("URL" OR "endpoint") AND ("changed" OR "modified" OR "configured"))
```
- **Detection logic / tuning:** Potential malicious content source.

### VMW-135 - Tag assigned to sensitive VM
- **Component:** vCenter
- **Severity:** Low
- **MITRE tactic:** Discovery
- **MITRE technique:** T1087 Account Discovery
- **Aria search query:**

```text
("tag" AND ("assigned" OR "attached")) AND (vm_name:* OR "virtual machine")
```
- **Detection logic / tuning:** Useful for governance/automation abuse detection.

### VMW-136 - Folder or resource pool permission changed
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Privilege Escalation
- **MITRE technique:** T1098 Account Manipulation
- **Aria search query:**

```text
(("folder" OR "resource pool") AND "permission" AND ("changed" OR "added" OR "removed"))
```
- **Detection logic / tuning:** Can silently broaden scope of access.

### VMW-137 - Resource pool limits changed
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Impact
- **MITRE technique:** T1496 Resource Hijacking
- **Aria search query:**

```text
("resource pool" AND ("limit" OR "reservation" OR "shares") AND ("changed" OR "reconfigured"))
```
- **Detection logic / tuning:** Can degrade workloads or enable resource abuse.

### VMW-138 - VM CPU or memory unexpectedly increased
- **Component:** vCenter
- **Severity:** Medium
- **MITRE tactic:** Impact
- **MITRE technique:** T1496 Resource Hijacking
- **Aria search query:**

```text
("reconfigured" AND ("CPU" OR "memory") AND vm_name:*)
```
- **Detection logic / tuning:** Use baseline/change context.

### VMW-139 - VM CPU or memory unexpectedly decreased
- **Component:** vCenter
- **Severity:** High
- **MITRE tactic:** Impact
- **MITRE technique:** T1496 Resource Hijacking
- **Aria search query:**

```text
("reconfigured" AND ("CPU" OR "memory") AND ("decreased" OR "reduced" OR "changed"))
```
- **Detection logic / tuning:** Can create denial-of-service conditions.

### VMW-140 - USB device attached to VM
- **Component:** vCenter / VM
- **Severity:** High
- **MITRE tactic:** Execution
- **MITRE technique:** T1120 Peripheral Device Discovery
- **Aria search query:**

```text
("USB" AND ("attached" OR "connected" OR "added")) AND (vm_name:* OR "virtual machine")
```
- **Detection logic / tuning:** Potential removable-media/passthrough risk.

### VMW-141 - PCI passthrough device added
- **Component:** vCenter / ESXi
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("PCI" AND ("passthrough" OR "DirectPath") AND ("added" OR "enabled" OR "configured"))
```
- **Detection logic / tuning:** Review hardware/security impact.

### VMW-142 - Host service policy changed
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Persistence
- **MITRE technique:** T1543 Create or Modify System Process
- **Aria search query:**

```text
("service policy" OR "startup policy") AND ("changed" OR "modified") AND (hostd OR ESXi)
```
- **Detection logic / tuning:** Detect services configured to start automatically.

### VMW-143 - Unexpected ESXi service started
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Execution
- **MITRE technique:** T1543 Create or Modify System Process
- **Aria search query:**

```text
("service" AND ("started" OR "running")) AND (hostd OR ESXi)
```
- **Detection logic / tuning:** Use allowlist of expected services.

### VMW-144 - Unexpected ESXi service stopped
- **Component:** ESXi
- **Severity:** High
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1489 Service Stop
- **Aria search query:**

```text
("service" AND ("stopped" OR "disabled")) AND (hostd OR ESXi)
```
- **Detection logic / tuning:** Prioritize security, time, logging and management services.

### VMW-145 - Host advanced crypto setting changed
- **Component:** ESXi
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1562 Impair Defenses
- **Aria search query:**

```text
("crypto" OR "encryption") AND ("advanced setting" OR "configuration") AND ("changed" OR "modified")
```
- **Detection logic / tuning:** Investigate immediately.

### VMW-146 - TPM attestation failure
- **Component:** ESXi / vCenter
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1542 Pre-OS Boot
- **Aria search query:**

```text
("TPM" OR "attestation") AND ("failed" OR "alarm" OR "not trusted")
```
- **Detection logic / tuning:** May indicate boot-chain or hardware trust issue.

### VMW-147 - Host integrity/attestation status changed
- **Component:** ESXi / vCenter
- **Severity:** Critical
- **MITRE tactic:** Defense Evasion
- **MITRE technique:** T1542 Pre-OS Boot
- **Aria search query:**

```text
("attestation" OR "integrity") AND ("changed" OR "untrusted" OR "failed")
```
- **Detection logic / tuning:** Correlate with Secure Boot/TPM.

### VMW-148 - Unusual configuration burst by single account
- **Component:** vCenter / ESXi
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1078 Valid Accounts
- **Aria search query:**

```text
("reconfigured" OR "changed" OR "enabled" OR "disabled" OR "deleted" OR "created") AND (user:* OR username:*)
```
- **Detection logic / tuning:** Aggregate >=20 administrative events for one account in 5 minutes.

### VMW-149 - Ransomware sequence precursor
- **Component:** vCenter / ESXi
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1490 Inhibit System Recovery
- **Aria search query:**

```text
("SSH" AND ("enabled" OR "started")) OR ("ESXi Shell" AND ("enabled" OR "started")) OR ("snapshot" AND ("deleted" OR "removed")) OR ("virtual machine" AND "powered off")
```
- **Detection logic / tuning:** Correlate stages: shell/SSH enable -> power off -> snapshot deletion.

### VMW-150 - Ransomware destructive burst
- **Component:** vCenter / ESXi / Storage
- **Severity:** Critical
- **MITRE tactic:** Impact
- **MITRE technique:** T1486 Data Encrypted for Impact
- **Aria search query:**

```text
("RemoveSnapshot" OR "snapshot deleted" OR "DestroyVM" OR "powered off" OR "datastore unmounted" OR "VMDK" AND "deleted")
```
- **Detection logic / tuning:** Aggregate distinct objects/actions; strongest when multiple categories occur for same actor/source in 10 minutes.
## Suggested detection groups

1. **Identity & Access** - VMW-001 to VMW-024
2. **VM Lifecycle & Guest Operations** - VMW-025 to VMW-045, VMW-123 to VMW-130
3. **Virtual Networking** - VMW-046 to VMW-052
4. **ESXi Security Configuration** - VMW-053 to VMW-075, VMW-109 to VMW-116, VMW-140 to VMW-147
5. **Storage & Datastores** - VMW-076 to VMW-086
6. **Backup & Recovery** - VMW-087 to VMW-090
7. **Cluster / HA / DRS** - VMW-089 to VMW-096
8. **vCenter Control Plane** - VMW-097 to VMW-122
9. **Content Library / Supply Chain** - VMW-131 to VMW-134
10. **Behavioural / Ransomware Correlation** - VMW-148 to VMW-150

## Priority implementation set

If implementing in stages, start with:

- VMW-006 - Direct ESXi root login
- VMW-007 - ESXi SSH enabled
- VMW-008 - ESXi Shell enabled
- VMW-018 - Permission assigned
- VMW-020 - Global permission modified
- VMW-021 - Identity source added
- VMW-029 - Multiple VMs deleted
- VMW-031 - Mass VM power-off
- VMW-036 - Mass snapshot deletion
- VMW-037 - All snapshots removed
- VMW-039 - Existing VMDK attached elsewhere
- VMW-046 - Promiscuous mode enabled
- VMW-053 - ESXi firewall rules changed
- VMW-054 - ESXi firewall disabled
- VMW-057 - Syslog destination changed
- VMW-058 - Remote syslog disabled
- VMW-061 - Lockdown mode disabled
- VMW-066 - Unsigned/untrusted VIB
- VMW-067 - Acceptance level weakened
- VMW-073 - Multiple hosts disconnected
- VMW-077 - Datastore removed
- VMW-078 - Datastore unmounted
- VMW-082 - VMDK downloaded
- VMW-085/086 - KMS/key provider changes
- VMW-089 - HA disabled
- VMW-097 - vCenter certificate changed
- VMW-105 - New vCenter extension
- VMW-123 - Guest operations executed
- VMW-146/147 - TPM/attestation failures
- VMW-149/150 - Ransomware correlation
