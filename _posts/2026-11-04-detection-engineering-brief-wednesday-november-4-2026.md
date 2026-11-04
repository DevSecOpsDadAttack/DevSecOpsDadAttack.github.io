---
layout: post
title: "Detection Engineering Brief - Wednesday, November 4, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-04
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Inno
  - Windows
  - T1059
  - T1106
---

## Detection Engineering Summary

This brief produced 1 detection candidate.

0 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

1 detection include KQL. 1 include ATT&CK mappings. 1 include triage guidance.

Search metadata extracted for this run includes: Inno, Windows, T1059, T1106.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Trojanized Inno Setup Installer Spawning Scripting Engine or Network Tool.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Trojanized Inno Setup Installer Spawning Scripting Engine or Network Tool

### Detection Opportunity

Trojanized Inno Setup installer spawning unexpected child processes such as scripting engines or network utilities as part of a fake-download campaign delivering monetization payloads

### Intelligence Context

- Microsoft Security Blog: Fake-download campaign uses trojanized installers to deliver monetization payloads — [https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/](https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/)
  - Context: Trojanized Inno Setup installers were observed delivering multiple monetization payloads by spawning unexpected child processes during the installer session. Microsoft confirmed detection guidance covers the complete installer session.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1106
- Products: Inno
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Inno, Windows, T1059, T1106

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (high); execution: T1106 Native API (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let suspiciousChildren = dynamic([
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "curl.exe",
    "wmic.exe", "regsvr32.exe"
]);
let knownDeploymentParents = dynamic([
    "msiexec.exe", "ccmexec.exe", "intunemanagementextension.exe",
    "trustedinstaller.exe", "wusa.exe"
]);
let userWritablePaths = dynamic([
    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\",
    "\\desktop\\", "\\users\\"
]);
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where FileName in~ (suspiciousChildren)
| where InitiatingProcessFileName has_any ("setup", "install", "installer")
| where tolower(InitiatingProcessFolderPath) has_any (userWritablePaths)
| where InitiatingProcessParentFileName !in~ (knownDeploymentParents)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    AccountDomain,
    InstallerProcess = InitiatingProcessFileName,
    InstallerFolderPath = InitiatingProcessFolderPath,
    InstallerCommandLine = InitiatingProcessCommandLine,
    InstallerSHA256 = InitiatingProcessSHA256,
    ParentOfInstaller = InitiatingProcessParentFileName,
    SpawnedChild = FileName,
    ChildCommandLine = ProcessCommandLine,
    ChildFolderPath = FolderPath,
    ChildSHA256 = SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Inno Setup-packaged software (e.g., open-source tools, freeware) that invokes PowerShell or cmd.exe as part of a post-install script.
- Developer workstations where software is compiled and installed locally from Temp or Downloads directories.
- IT-managed software that uses Inno Setup and legitimately calls certutil or bitsadmin during installation.
- Security tools or endpoint agents that use Inno Setup packaging and spawn scripting engines during self-update routines.

**Tuning notes:**
- Add specific known-good installer SHA256 hashes from the environment to an exclusion list to suppress recurring false positives from legitimate Inno-packaged software.
- Narrow the suspiciousChildren list based on observed legitimate installer behavior; for example, if cmd.exe is routinely spawned by legitimate installers in the environment, consider removing it or adding a ProcessCommandLine filter to scope it.
- Add a FolderPath filter on ChildFolderPath (e.g., has_any userWritablePaths) to further restrict results to children also executing from user-writable locations.
- Consider adding an InitiatingProcessCommandLine filter to look for Inno-specific runtime arguments such as '/SILENT', '/VERYSILENT', or '/SP-' which are common in trojanized installer campaigns.

**Risks / caveats:**
- DeviceProcessEvents requires Microsoft Defender for Endpoint (MDE) P1 or P2 licensing with process creation telemetry enabled; environments without MDE will have no data in this table.
- Filename substring matching on 'setup', 'install', 'installer' is a broad heuristic; legitimate Inno-packaged software with these naming patterns will generate false positives that require per-environment allowlisting.
- The userWritablePaths filter uses tolower() string matching on FolderPath, which may miss edge cases with non-standard path casing or junction points; validate path coverage in the target environment.
- No lookback window is enforced in the query; when scheduled, a lookback of 1 hour is recommended to balance detection latency against result volume.

### Triage Runbook

**First 15 minutes:**
- Confirm the installer process, parent process, and child process chain on the affected device; focus on whether the installer launched PowerShell, cmd.exe, wscript.exe, cscript.exe, mshta.exe, certutil.exe, bitsadmin.exe, curl.exe, wmic.exe, or regsvr32.exe.
- Check the installer path and launch context; prioritize cases where the installer ran from Downloads, Temp, AppData, Desktop, or another user-writable location rather than Program Files or a managed deployment path.
- Review the installer command line and child command line for silent install switches, download URLs, encoded commands, script execution, or staged payload extraction behavior.
- Identify the user account and whether the activity aligns with a known software install request, helpdesk ticket, or approved application rollout.
- Look for immediate follow-on activity from the same host, especially additional child processes, file drops, or outbound connections shortly after the installer spawned the suspicious child.

**Evidence to collect:**
- DeviceProcessEvents for the full installer session, including the initiating process, spawned child process, and any subsequent descendants.
- Installer and child SHA256 values, plus file paths for the installer and any dropped or executed payloads.
- User identity, logon session context, and whether the account is a standard user or local admin.
- Any related DeviceNetworkEvents from the same DeviceId within a short window after process creation to identify outbound downloads or C2-like traffic.
- Any file creation or modification evidence on the host that indicates payload staging, persistence, or script drop locations.

**Pivot points:**
- DeviceProcessEvents: pivot on DeviceId and InitiatingProcessSHA256 to enumerate the complete process tree for the installer session.
- DeviceNetworkEvents: pivot on DeviceId and Timestamp to identify outbound connections made by the installer or its child processes.
- DeviceFileEvents: pivot on DeviceId and the installer/child SHA256 values to find dropped files, renamed payloads, or script artifacts.
- DeviceLogonEvents: pivot on AccountName and AccountDomain to validate whether the user session matches expected software installation activity.

**Benign explanations:**
- Legitimate Inno Setup-packaged software may spawn PowerShell, cmd.exe, or other utilities as part of a normal post-install script.
- Developer or IT-admin workstations may run locally built installers from Temp or Downloads during testing or packaging.
- Some sanctioned software updaters and security tools use Inno Setup and may legitimately invoke scripting engines or network utilities during installation.
- Managed software deployment can still appear suspicious if the installer was launched from a user-writable path, so validate against approved software inventory before escalating.

**Escalation criteria:**
- The installer originated from a user-writable path and spawned a scripting engine or network utility without a clear business justification.
- The child process executed encoded commands, downloaded content, or launched additional suspicious processes after the installer started.
- The installer hash is unknown, unsigned, or not present in the organization’s approved software inventory.
- Network activity, dropped files, or persistence artifacts appear shortly after the installer session on the same host.
- The affected user reports an unexpected download, fake software prompt, or suspicious installer behavior.

**Containment actions:**
- If triage indicates likely compromise, isolate the host from the network to stop further payload download or execution.
- Terminate the suspicious installer and any spawned scripting or network utility processes if they are still active and containment is approved.
- Block the installer hash and any confirmed malicious child hashes in endpoint protection if validated as malicious.
- Reset credentials for the affected user if there is evidence of malicious execution under their account or follow-on credential abuse.

**Closure criteria:**
- The installer is confirmed as approved software from a trusted source and the child process behavior matches documented installation logic.
- The installer hash matches a known-good internal package or vendor-signed installer with no additional suspicious follow-on activity.
- No suspicious network connections, dropped files, persistence, or additional malicious process activity are found on the host.
- The alert is attributable to a documented software deployment, developer test activity, or sanctioned endpoint agent update.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Trojanized Inno Setup Installer Spawning Scripting Engine or Network Tool: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Trojanized Inno Setup Installer Spawning Scripting Engine or Network Tool.

### Hunting Agenda and Promotion Criteria

- Trojanized Inno Setup Installer Spawning Scripting Engine or Network Tool: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
