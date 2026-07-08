---
layout: post
title: "Detection Engineering Brief - Wednesday, July 8, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-08
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Windows
  - Vidar Stealer
  - Microsoft 365
  - Entra ID
  - T1027
  - T1036
  - T1528
  - T1566
  - T1566.002
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

2 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: Windows, Vidar Stealer, Microsoft 365, Entra ID, T1027, T1036, T1528, T1566, T1566.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Vidar - Abnormally Large Executable or DLL Dropped by Non-Installer Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Vidar - Fake MpClient.dll Loaded Outside Legitimate Windows Defender Path

### Detection Opportunity

Go-compiled fake MpClient.dll sideloaded by a process outside the legitimate Windows Defender installation directory

### Intelligence Context

- Unit 42: Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation — [https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)
  - Context: Vidar Stealer delivery used a Go-compiled fake MpClient.dll placed outside the legitimate Windows Defender directory and sideloaded by a signed binary, combining DLL sideloading with code signing abuse as a delivery mechanism.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1027, T1036
- Products: Not specified
- Platforms: Windows
- Malware: Vidar Stealer
- Tools: Not specified
- Search tags: Windows, Vidar Stealer, T1027, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1027 Obfuscated Files or Information (medium); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceImageLoadEvents

### KQL

```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName =~ "MpClient.dll"
| where not (
    FolderPath startswith @"C:\Program Files\Windows Defender"
    or FolderPath startswith @"C:\ProgramData\Microsoft\Windows Defender"
    or FolderPath startswith @"C:\Windows\System32"
    or FolderPath startswith @"C:\Windows\SysWOW64"
)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    FolderPath,
    FileName,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    InitiatingProcessAccountName,
    InitiatingProcessAccountDomain
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security products that bundle their own copy of MpClient.dll (rare but possible with some AV interoperability shims).
- Enterprise software deployment tools that stage Defender components in non-standard paths before installation.
- Defender updates that temporarily write MpClient.dll to a staging directory before moving it to the final path.

**Tuning notes:**
- Add a FileSize > 52428800 condition if the environment generates noise from small legitimate MpClient.dll copies outside Defender paths.
- Add SysWOW64 to the exclusion list if 32-bit Defender components are observed loading from that path in the environment.
- Scope to specific high-value device groups using DeviceName in~ or DeviceId in~ if initial rollout volume is high.

**Risks / caveats:**
- DeviceImageLoadEvents requires Defender for Endpoint Plan 2 (or equivalent MDE license tier that enables image load telemetry). Plan 1 does not surface this table.
- If Defender for Endpoint is deployed to a non-standard installation root (e.g. a custom Program Files drive letter), the exclusion list will not cover it and false positives will occur; add the custom path to the startswith exclusions.
- File inflation characteristic (large file size) is not checked here; combine with the companion large-PE detection for higher-confidence Vidar attribution.
- The detection fires on any MpClient.dll outside the exclusion paths regardless of whether the DLL is actually malicious; SHA256 enrichment via MDE file page or external threat intel is required to confirm.

### Triage Runbook

**First 15 minutes:**
- Confirm the DLL path is outside standard Windows Defender locations and note the initiating process name, path, and command line.
- Check the initiating process SHA256 and DLL SHA256 against Defender file reputation, prevalence, and any threat intel hits.
- Review whether the loader is signed, recently dropped, or executing from user-writable locations such as Downloads, Temp, AppData, or ProgramData.
- Look for nearby process creation, network, and file write activity on the same host around the alert time to identify follow-on execution or staging.

**Evidence to collect:**
- DeviceName, DeviceId, Timestamp, FolderPath, FileName, SHA256 for the loaded DLL.
- InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, and initiating account context.
- Any related process tree entries showing the parent, child, and sibling processes around the load event.
- Recent file writes, downloads, or archive extraction activity on the same device within the prior 24 hours.

**Pivot points:**
- DeviceImageLoadEvents for additional MpClient.dll loads on the same host or across the environment.
- DeviceProcessEvents to reconstruct the process tree for the initiating binary and identify launch source.
- DeviceFileEvents to find the DLL dropper, staging files, and any recent PE writes from the same process.
- Advanced Hunting file reputation or file profile pivots using the DLL and loader SHA256.

**Benign explanations:**
- Rare security interoperability software may bundle a copy of MpClient.dll outside the standard Defender path.
- Enterprise deployment or imaging tools may temporarily stage Defender components in non-standard directories.
- A Defender update or repair workflow may briefly place the DLL in a staging location before moving it to the final path.

**Escalation criteria:**
- The initiating process is unsigned, newly seen, or launched from a user-writable directory.
- The DLL or loader hash is low prevalence, known malicious, or matches Vidar-related intelligence.
- The host also shows suspicious network connections, credential theft behavior, or additional malware artifacts.
- Multiple endpoints show the same non-standard MpClient.dll path or the same loader hash.

**Containment actions:**
- Isolate the host if the loader is suspicious, the DLL hash is malicious, or there is evidence of active malware execution.
- Quarantine the initiating binary and the fake MpClient.dll if supported by your tooling.
- Block the initiating process hash and any confirmed malicious hashes at the endpoint and email/web layers if applicable.

**Closure criteria:**
- The DLL load is explained by a known, approved software deployment or security product and the hashes are benign.
- No suspicious process tree, network activity, or additional malware artifacts are found on the host.
- The path is added to an approved allowlist only after validation with the endpoint owner and security engineering.

<br/>
---
<br/>

## Detection 2: Vidar - Abnormally Large Executable or DLL Dropped by Non-Installer Process

### Detection Opportunity

File inflation used as an evasion technique: oversized PE files dropped by non-installer processes to evade static analysis

### Intelligence Context

- Unit 42: Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation — [https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)
  - Context: Vidar Stealer employed file inflation as a novel evasion layer, producing executables or DLLs with anomalously large file sizes to bypass static analysis and sandbox scanning thresholds.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1027, T1036
- Products: Not specified
- Platforms: Windows
- Malware: Vidar Stealer
- Tools: Not specified
- Search tags: Windows, Vidar Stealer, T1027, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Defense Evasion: T1027 Obfuscated Files or Information (medium); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".exe" or FileName endswith ".dll"
| where isnotnull(FileSize) and FileSize > 52428800
| where not (
    InitiatingProcessFileName has_any (
        "msiexec.exe", "setup.exe", "install.exe", "winget.exe",
        "MicrosoftEdgeUpdate.exe", "WindowsUpdateBox.exe",
        "wuauclt.exe", "TiWorker.exe", "TrustedInstaller.exe"
    )
)
| where not (
    FolderPath startswith @"C:\Windows\"
    or FolderPath startswith @"C:\Program Files\"
    or FolderPath startswith @"C:\Program Files (x86)\"
)
| extend HighRiskPath = (
    FolderPath has_any ("AppData", "Temp", "Downloads", "Desktop", "Public")
)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    FileName,
    FolderPath,
    FileSize,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    HighRiskPath
| order by FileSize desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Game clients and launchers (Steam, Epic, Battle.net) that write large game binaries to user-writable directories.
- Development tools (Visual Studio, JetBrains IDEs) that produce large compiled artifacts.
- Browser update processes not covered by the exclusion list.
- Enterprise backup or sync agents writing large archive files with .exe or .dll extensions.

**Tuning notes:**
- Run the query without the FileSize filter first to understand the distribution of large PE writes in the environment before committing to the 52428800 threshold.
- Add FolderPath startswith filters for any enterprise software staging directories that produce large binaries.
- Consider adding a SHA256 lookup against MDE's file prevalence data (FileProfile() function) to surface low-prevalence large files as the highest priority.
- To promote to a scheduled rule, first build an allowlist of known-good (SHA256, InitiatingProcessFileName) pairs observed during the hunting phase.

**Risks / caveats:**
- FileSize is not guaranteed to be populated in DeviceFileEvents for all ActionType values or all MDE sensor versions; a null FileSize will cause the FileSize > 52428800 filter to silently drop those rows. Validate FileSize population rate before relying on this filter.
- DeviceFileEvents requires Defender for Endpoint Plan 2 for full file event telemetry coverage.
- The 50 MB threshold is a starting point derived from the Vidar campaign; legitimate large binaries in the environment may require raising this threshold after baselining.
- The initiating process exclusion list is not exhaustive; enterprise software deployment tools (SCCM, Intune, custom updaters) will generate false positives until their process names are added.

### Triage Runbook

**First 15 minutes:**
- Validate the file size, extension, folder path, and initiating process to see whether the write came from a known installer or updater.
- Check whether the file was written to a user-writable or high-risk path such as Downloads, Temp, AppData, Desktop, or Public.
- Review the initiating process command line and SHA256 to identify whether the writer is a browser, archive tool, script host, or unknown binary.
- Compare the file hash and prevalence against known-good software, internal development artifacts, and threat intelligence.

**Evidence to collect:**
- FileName, FolderPath, FileSize, SHA256, and Timestamp for the dropped file.
- InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, and InitiatingProcessSHA256.
- Whether the file is signed, who signed it, and whether the signature is valid.
- Any related archive extraction, download, or script execution events immediately before the file write.

**Pivot points:**
- DeviceFileEvents for other large PE writes from the same initiating process or host.
- DeviceProcessEvents to identify the parent process and any script or installer chain.
- DeviceImageLoadEvents to see whether the dropped file was later executed or loaded as a DLL.
- File reputation or prevalence pivots on the SHA256 to determine whether the file is rare or known-good.

**Benign explanations:**
- Software installers, updaters, and enterprise deployment tools can legitimately write large executables or DLLs.
- Game launchers, development tools, and build systems often create large binaries in user-writable directories.
- Backup, sync, or packaging tools may produce large files that happen to use .exe or .dll extensions.

**Escalation criteria:**
- The initiating process is not a recognized installer, updater, or enterprise deployment tool.
- The file is unsigned, low prevalence, or has a suspicious name/path combination inconsistent with the writer.
- The same host also shows suspicious network activity, persistence, or additional malware drops.
- The file is later executed, loaded, or copied into a Defender-related or other masqueraded path.

**Containment actions:**
- If the file is confirmed malicious or clearly part of an active intrusion, isolate the host.
- Quarantine the dropped file and the initiating process if your endpoint tooling supports it.
- Block the file hash if it is confirmed malicious and not a legitimate internal build artifact.

**Closure criteria:**
- The file is attributed to a known installer, updater, or approved internal build process.
- The hash is confirmed benign and the file path matches expected software behavior.
- No execution, persistence, or additional suspicious activity is found after review.

<br/>
---
<br/>

## Detection 3: Device Code Phishing - Token Acquired via Device Code Flow Followed by M365 Resource Access

### Detection Opportunity

OAuth 2.0 device code flow abused to acquire tokens, followed by Microsoft 365 resource access from an anomalous client

### Intelligence Context

- Securelist: When checking the URL isn't enough: a Device Code Phishing attack via a Microsoft website — [https://securelist.com/microsoft-device-code-phishing-attack/120350/](https://securelist.com/microsoft-device-code-phishing-attack/120350/)
  - Context: Threat actors weaponized the OAuth 2.0 device authorization flow via a legitimate Microsoft website to trick users into granting tokens, which were then used to access Microsoft 365 resources. The attack is notable because the URL presented to the victim appears legitimate, defeating URL-based phishing defenses.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1528, T1566, T1566.002
- Products: Microsoft 365, Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft 365, Entra ID, T1528, T1566, T1566.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1528 Steal Application Access Token (medium); Initial Access: T1566 Phishing/ T1566.002 Spearphishing Link (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs, OfficeActivity

### KQL

```kql
let LookbackWindow = 1d;
let CorrelationWindow = 30m;
let DeviceCodeSignins = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where AuthenticationProtocol =~ "deviceCode"
| where ResultType == 0
| extend NormalizedUPN = tolower(UserPrincipalName)
| project
    SigninTime = TimeGenerated,
    NormalizedUPN,
    UserPrincipalName,
    SigninIP = IPAddress,
    ClientAppUsed,
    AppDisplayName,
    ConditionalAccessStatus,
    DeviceDetail;
let OfficeAccess = OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where isnotempty(ClientIP)
| extend NormalizedUPN = tolower(UserId)
| project
    AccessTime = TimeGenerated,
    NormalizedUPN,
    Operation,
    ClientIP,
    UserAgent,
    OfficeWorkload = RecordType;
DeviceCodeSignins
| join kind=inner OfficeAccess on NormalizedUPN
| where AccessTime between (SigninTime .. (SigninTime + CorrelationWindow))
| where ClientIP != SigninIP
| project
    SigninTime,
    AccessTime,
    UserPrincipalName,
    SigninIP,
    ClientIP,
    ClientAppUsed,
    AppDisplayName,
    ConditionalAccessStatus,
    Operation,
    UserAgent,
    OfficeWorkload
| order by SigninTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who authenticate via device code flow on a corporate network (e.g. a shared NAT IP) and then access M365 resources from a different egress IP due to split-tunnel VPN or load-balanced proxies.
- Mobile users who complete device code flow on a home network and then switch to cellular data before accessing M365 resources.
- Automated service accounts that use device code flow for initial token acquisition and then operate from a different IP.
- Users behind carrier-grade NAT where the source IP changes between authentication and resource access.

**Tuning notes:**
- Add an Operation filter (e.g. Operation in ("MailItemsAccessed", "FileDownloaded", "Send")) to focus on high-value post-compromise actions and reduce volume.
- Add a geolocation-based filter using the geo_info_from_ip_address() function to flag cases where SigninIP and ClientIP resolve to different countries.
- Consider adding a watchlist of known corporate egress IPs to exclude legitimate split-tunnel VPN scenarios from the IP mismatch condition.
- If the tenant uses Conditional Access policies that block device code flow, this detection can be scoped to ConditionalAccessStatus != 'success' to surface policy bypass attempts.

**Risks / caveats:**
- SigninLogs requires the Azure Active Directory (Entra ID) diagnostic settings connector to be enabled in Microsoft Sentinel; without it the table will be empty.
- OfficeActivity requires the Microsoft 365 (Office 365) connector to be enabled in Microsoft Sentinel; without it the table will be empty.
- AuthenticationProtocol is populated in SigninLogs only for interactive and non-interactive sign-in events that include protocol-level detail; some tenants may see this field as null or empty for a subset of device code flows depending on Entra ID diagnostic log verbosity settings.
- UserId in OfficeActivity contains the UserPrincipalName string in most tenants but may contain an object GUID in some audit log configurations; validate the join key format before deploying.

### Triage Runbook

**First 15 minutes:**
- Confirm the sign-in was successful, the authentication protocol was device code, and the follow-on Office activity occurred within the correlation window.
- Compare SigninIP and ClientIP, then assess whether the mismatch is explainable by VPN, mobile network changes, or shared NAT.
- Review the user’s recent sign-in history for unfamiliar locations, impossible travel, MFA prompts, or repeated device code attempts.
- Identify the Office operation performed after token use and determine whether it indicates mailbox access, file access, sharing, or data exfiltration.

**Evidence to collect:**
- SigninTime, AccessTime, UserPrincipalName, SigninIP, ClientIP, ClientAppUsed, AppDisplayName, ConditionalAccessStatus.
- Operation, UserAgent, and OfficeWorkload for the correlated Office activity.
- Entra ID sign-in details including device information, MFA/CA results, and any risk indicators.
- Mailbox, file, or audit events showing what content was accessed or modified after token acquisition.

**Pivot points:**
- SigninLogs for all recent device code sign-ins by the same user and from the same IPs.
- OfficeActivity for additional operations by the user in the same time window, especially mail access, downloads, sends, or sharing.
- Audit logs or related M365 workload logs to determine whether data was accessed or exfiltrated.
- Conditional Access and risk logs to see whether the sign-in was challenged, blocked, or flagged.

**Benign explanations:**
- The user may have legitimately used device code flow on one network and then switched networks before accessing M365.
- Split-tunnel VPN, shared corporate NAT, or mobile carrier IP changes can create an IP mismatch without compromise.
- Some service or automation accounts may use device code flow in controlled workflows, though this should be rare.

**Escalation criteria:**
- The user does not recognize the device code prompt or the subsequent M365 activity.
- The correlated Office activity includes suspicious actions such as mass file downloads, mailbox rule changes, forwarding, or unusual sharing.
- The sign-in originated from an unfamiliar country, TOR/VPN, or a high-risk IP and the user reports no legitimate activity.
- Multiple users or repeated device code attempts indicate a broader phishing campaign.

**Containment actions:**
- Disable the user session and revoke refresh tokens if the activity is suspicious or confirmed malicious.
- Reset the user password and require MFA re-registration if token theft is suspected.
- Block the source IPs or suspicious client patterns if they are clearly malicious and not shared with legitimate users.

**Closure criteria:**
- The user confirms the device code flow and follow-on access were legitimate and consistent with their work.
- IP mismatch is explained by an approved VPN, NAT, or mobile network transition and no suspicious Office actions are found.
- No additional risky sign-ins, token abuse, or data access is identified after reviewing the user’s recent activity.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- Vidar - Fake MpClient.dll Loaded Outside Legitimate Windows Defender Path: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- Vidar - Abnormally Large Executable or DLL Dropped by Non-Installer Process: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Vidar - Fake MpClient.dll Loaded Outside Legitimate Windows Defender Path; Device Code Phishing - Token Acquired via Device Code Flow Followed by M365 Resource Access.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Vidar - Abnormally Large Executable or DLL Dropped by Non-Installer Process.

### Hunting Agenda and Promotion Criteria

- Vidar - Abnormally Large Executable or DLL Dropped by Non-Installer Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
