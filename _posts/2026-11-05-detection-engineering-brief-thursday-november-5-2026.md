---
layout: post
title: "Detection Engineering Brief - Thursday, November 5, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-05
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Storm-2603
  - T1190
  - SharePoint
  - Windows
  - Inno
  - T1071
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 3 hunting-only, 0 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: Storm-2603, T1190, SharePoint, Windows, Inno, T1071.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Storm-2603 ToolShell: Anomalous SharePoint Operations from Non-Interactive or Unexpected Sources; Trojanized Inno Installer Spawning Unexpected Child Processes and Dropping Payloads to Suspicious Paths; Trojanized Inno Installer Child Process Making Outbound Network Connection During Setup Session.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Storm-2603 ToolShell: SharePoint Worker Process Spawning Anomalous Child Process

### Detection Opportunity

SharePoint IIS worker process (w3wp.exe) spawning unexpected child processes following ToolShell exploitation, indicating fileless post-exploitation activity in memory

### Intelligence Context

- Securelist: The SOC Files 5: Ghost in the pipeline, or a fileless SharePoint breach by Storm-2603 — [https://securelist.com/storm-2603-fileless-toolshell-attack/121467/](https://securelist.com/storm-2603-fileless-toolshell-attack/121467/)
  - Context: Storm-2603 exploited SharePoint via ToolShell and performed fileless runtime subversion post-exploitation. The attack chain involves the SharePoint IIS worker process being abused to execute in-memory payloads, making child process spawning from w3wp.exe a key detection pivot.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2603
- ATT&CK tags: T1190
- Products: SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-2603, T1190, SharePoint, Windows

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let suspiciousChildren = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "net.exe", "net1.exe", "whoami.exe", "nltest.exe",
    "ipconfig.exe", "systeminfo.exe", "msiexec.exe", "regasm.exe",
    "installutil.exe", "odbcconf.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (suspiciousChildren)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Other IIS-hosted web applications on the same host running w3wp.exe may spawn some of the listed child processes for legitimate administrative or diagnostic purposes.
- Automated monitoring agents or backup tools that invoke cmd.exe or powershell.exe under IIS worker processes will trigger this rule.
- SharePoint health analyzer or timer jobs may spawn net.exe, ipconfig.exe, or systeminfo.exe legitimately.

**Tuning notes:**
- Add a DeviceName filter using a known SharePoint server list or Defender for Endpoint device tag to reduce cross-IIS noise: → where DeviceName in~ (<sharepoint_server_list>) or use DeviceTvmSoftwareInventory to dynamically identify SharePoint hosts.
- Build a baseline of legitimate w3wp.exe child processes in the environment over 30 days before scheduling as an alert to establish an accurate exclusion list.
- Consider lowering the lookback to 1 day for scheduled rule execution and relying on alert aggregation rather than a 7-day hunting window.

**Risks / caveats:**
- DeviceProcessEvents is only populated for devices onboarded to Microsoft Defender for Endpoint. SharePoint servers must be onboarded for this query to produce results.
- Without scoping DeviceName to SharePoint servers, this query will fire on any IIS-hosted application running w3wp.exe across the estate, producing significant noise in environments with many IIS workloads.
- The 7-day lookback window may miss dwell time exceeding one week; adjust to match the organization's threat hunting cadence.
- Fileless execution that does not produce a child process (e.g., direct .NET assembly load into w3wp.exe memory) will not be detected by this process-creation-based rule.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a SharePoint server and identify the exact timestamp, account context, and child process name/command line from the alert.
- Check whether the child process is one of the high-risk LOLBins or scripting tools listed in the detection, especially powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe, mshta.exe, or certutil.exe.
- Review the parent and grandparent process chain to verify the child truly originated from w3wp.exe and not from a legitimate IIS application or maintenance task.
- Look for concurrent signs of exploitation on the same host, including unusual web requests, new files under SharePoint directories, suspicious scheduled tasks, or additional process creation from w3wp.exe.
- If the child process is clearly malicious or the host shows multiple suspicious indicators, treat as likely compromise and begin incident handling immediately.

**Evidence to collect:**
- Alert timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FileName, ProcessCommandLine, FolderPath, and SHA256.
- Process tree for w3wp.exe and the spawned child process, including any subsequent descendants.
- Recent SharePoint/IIS logs around the alert window, including request paths, source IPs, and any unusual POST or upload activity.
- Any file writes, dropped web shells, or new executables on the SharePoint server near the alert time.
- Host telemetry showing network connections, service creation, scheduled task creation, or credential access activity after the process spawn.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and a wider time window to reconstruct the full process tree.
- DeviceFileEvents to find dropped files, modified web content, or suspicious executables on the SharePoint host.
- DeviceNetworkEvents to identify outbound connections from the child process or related descendants.
- SharePoint/IIS logs or web server logs to correlate the process spawn with suspicious requests and source IPs.
- Microsoft Defender for Endpoint device timeline for the host to review adjacent alerts and related activity.

**Benign explanations:**
- Legitimate SharePoint administration or health-check activity can occasionally cause w3wp.exe to spawn helper processes.
- Backup, monitoring, or endpoint management tools may run under IIS-hosted contexts and launch cmd.exe or powershell.exe.
- Other IIS-hosted applications on the same server may generate similar child process behavior unrelated to SharePoint exploitation.

**Escalation criteria:**
- The child process is a scripting or LOLBin executable with suspicious command-line arguments or network activity.
- Multiple w3wp.exe child processes appear in a short period, especially with web shell-like behavior or file drops.
- There is evidence of web shell placement, unauthorized file modification, credential access, or outbound connections from the SharePoint host.
- The host is internet-facing and the activity aligns with known ToolShell exploitation patterns.

**Containment actions:**
- Isolate the SharePoint server from the network if malicious child process activity is confirmed or strongly suspected.
- Preserve volatile evidence before rebooting or cleaning the host, including process tree, memory capture if available, and relevant logs.
- Disable or restrict external access to the affected SharePoint service until the exposure path is understood and remediated.
- Block any confirmed malicious child process hashes or related outbound destinations if identified during triage.

**Closure criteria:**
- The spawned child process is validated as a known legitimate SharePoint or IIS administrative action.
- No supporting evidence of exploitation, web shell activity, suspicious file writes, or malicious network activity is found.
- The host is confirmed to be outside the SharePoint server scope or the alert is attributable to a documented benign maintenance workflow.
- Any required exclusions or tuning notes are documented for the environment baseline.

<br/>
---
<br/>

## Detection 2: Storm-2603 ToolShell: Anomalous SharePoint Operations from Non-Interactive or Unexpected Sources

### Detection Opportunity

Anomalous SharePoint audit operations consistent with ToolShell web shell exploitation, including file access or page requests from unexpected IP addresses or with suspicious user-agent patterns

### Intelligence Context

- Securelist: The SOC Files 5: Ghost in the pipeline, or a fileless SharePoint breach by Storm-2603 — [https://securelist.com/storm-2603-fileless-toolshell-attack/121467/](https://securelist.com/storm-2603-fileless-toolshell-attack/121467/)
  - Context: Storm-2603 exploited SharePoint via ToolShell, which operates as a web shell producing anomalous web request patterns. OfficeActivity logs capture SharePoint operations including the ClientIP and UserAgent fields that can surface exploitation attempts from non-user sources.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2603
- ATT&CK tags: T1190
- Products: SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-2603, T1190, SharePoint, Windows

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let knownClientPatterns = dynamic([
    "Mozilla", "Chrome", "Safari", "Edge", "Firefox",
    "OneDrive", "MSAL", "Microsoft Office", "SharePointOnline"
]);
OfficeActivity
| where TimeGenerated > ago(7d)
| where RecordType == "SharePointFileOperation"
| where isnotempty(UserAgent)
| where not(UserAgent has_any (knownClientPatterns))
| where isnotempty(ClientIP)
| where not(UserId has_any ("#microsoft.com", "app@sharepoint", "SHAREPOINT\\system"))
| summarize
    OperationCount = count(),
    Operations = make_set(Operation, 50),
    Sites = make_set(SiteUrl, 20),
    Objects = make_set(OfficeObjectId, 20)
    by ClientIP, UserAgent, UserId, bin(TimeGenerated, 1h)
| where OperationCount > 3
| order by OperationCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- SharePoint migration tools, backup agents, and third-party integrations that use non-browser HTTP clients will trigger this rule.
- Microsoft Graph API calls from legitimate applications will appear with non-browser user-agent strings.
- Power Automate flows and Logic Apps accessing SharePoint will produce non-browser user-agent patterns.
- SharePoint Online Management Shell and PnP PowerShell operations will match the non-browser filter.

**Tuning notes:**
- Run a frequency analysis of UserAgent values in OfficeActivity over 30 days to build an accurate exclusion list before scheduling.
- Consider correlating flagged ClientIP values against Azure AD sign-in logs (SigninLogs) to determine whether the IP has any associated authenticated user sessions, which would reduce false positives from legitimate API integrations.
- The 1-hour bin and OperationCount threshold should be calibrated against observed baseline non-browser operation rates in the specific tenant.

**Risks / caveats:**
- OfficeActivity RecordType for SharePoint file operations is the string 'SharePointFileOperation' in some tenants but may be represented differently depending on the Microsoft 365 audit log connector version and Sentinel workspace configuration. Validate RecordType values present in the workspace before deploying.
- OfficeActivity requires the Microsoft 365 (Office 365) data connector to be enabled in Sentinel and SharePoint audit logging to be activated in the Microsoft Purview compliance portal. If either is absent, this query returns no results.
- UserAgent field population in OfficeActivity is not guaranteed for all SharePoint operation types; some operations may log an empty or null UserAgent even for legitimate interactive sessions.
- The non-browser user-agent heuristic is trivially bypassed by an attacker who sets a browser-like user-agent string in their web shell requests.

### Triage Runbook

**First 15 minutes:**
- Review the alert for ClientIP, UserAgent, UserId, SiteUrl, OperationCount, and the specific operations performed.
- Check whether the source IP is expected for a user, service, migration tool, or integration in your tenant.
- Validate whether the UserAgent is consistent with a known browser, Microsoft client, sync tool, or approved automation platform.
- Look for bursts of file access, unusual page requests, or repeated operations against the same site or object in a short time window.
- If the source is unknown, the UserAgent is non-browser, and the activity is concentrated on a sensitive site, escalate as likely exploitation.

**Evidence to collect:**
- Alert fields including TimeGenerated, UserId, ClientIP, UserAgent, SiteUrl, OfficeObjectId, Operations, and OperationCount.
- Related OfficeActivity records for the same UserId, ClientIP, or SiteUrl before and after the alert window.
- Any Azure AD sign-in records or identity logs tied to the UserId or source IP to determine whether the activity aligns with a real authenticated session.
- SharePoint audit details for the affected site or object, including file access patterns and any unusual downloads or modifications.
- A baseline comparison of whether this UserAgent and ClientIP have previously performed similar operations in the tenant.

**Pivot points:**
- OfficeActivity for the same ClientIP, UserId, SiteUrl, or OfficeObjectId over a wider time range.
- SigninLogs to determine whether the source IP is associated with legitimate user sign-ins or service activity.
- SharePoint audit logs or Purview audit search for the same site and object.
- Defender for Cloud Apps or other proxy logs if available to identify whether the source is a sanctioned integration.
- Identity and device inventory to determine whether the UserId is a service account, automation account, or human user.

**Benign explanations:**
- Migration tools, backup agents, and third-party integrations often use non-browser clients and can generate similar operations.
- Power Automate, Logic Apps, Graph API clients, and SharePoint administration tools may appear as non-browser activity.
- Some legitimate Microsoft-native clients or sync tools may have unusual or incomplete UserAgent strings.

**Escalation criteria:**
- The source IP is unfamiliar, external, or not tied to any approved integration or user activity.
- The UserAgent is empty, clearly non-browser, or inconsistent with the claimed source of activity.
- There is a burst of operations against sensitive sites, unusual file access, or evidence of unauthorized content enumeration.
- The activity aligns with a suspected web shell or follows other signs of SharePoint exploitation.

**Containment actions:**
- If malicious activity is confirmed, disable or restrict the implicated account or service principal and block the source IP where appropriate.
- Suspend or review any suspicious SharePoint integrations or automation accounts associated with the activity.
- Increase monitoring on the affected site and preserve audit logs for incident response.
- If the activity is clearly tied to exploitation, coordinate with SharePoint administrators to restrict external access until remediated.

**Closure criteria:**
- The source is validated as a known approved automation, migration, or sync workflow.
- The UserAgent and ClientIP are matched to documented tenant activity and no unauthorized access is found.
- No additional suspicious SharePoint operations, identity anomalies, or related alerts are present.
- The event is documented as a benign baseline exception or tuning candidate.

<br/>
---
<br/>

## Detection 3: Trojanized Inno Installer Spawning Unexpected Child Processes and Dropping Payloads to Suspicious Paths

### Detection Opportunity

Inno Setup installer process spawning non-standard child executables and writing files to user-writable temporary or AppData paths, consistent with trojanized installer delivering monetization payloads

### Intelligence Context

- Microsoft Security Blog: Fake-download campaign uses trojanized installers to deliver monetization payloads — [https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/](https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/)
  - Context: Trojanized Inno Setup installers were used in a fake-download campaign to deliver multiple monetization payloads during the installer session. The attack produces detectable process creation and file drop events where the Inno installer spawns unexpected child processes and writes payload files to temp or AppData directories.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071
- Products: Inno
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Inno, Windows, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 7d;
let sessionWindowMinutes = 15;
let suspiciousChildren = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "setup.exe"
| where InitiatingProcessCommandLine has_any ("inno", "innounp", "is-", "_isetup")
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\", "\\AppData\\Roaming\\")
| where FileName !in~ ("setup.exe", "uninst.exe", "unins000.exe")
| project
    DeviceId,
    DeviceName,
    AccountName,
    ChildProcessId = ProcessId,
    ChildProcess = FileName,
    ChildFolderPath = FolderPath,
    ChildCommandLine = ProcessCommandLine,
    InstallerCommandLine = InitiatingProcessCommandLine,
    ChildTimestamp = Timestamp;
let payloadDrops = DeviceFileEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "setup.exe"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\", "\\AppData\\Roaming\\")
| where FileName endswith ".exe" or FileName endswith ".dll"
| where ActionType == "FileCreated"
| project
    DeviceId,
    DroppedFile = FileName,
    DroppedPath = FolderPath,
    DroppedSHA256 = SHA256,
    DropTimestamp = Timestamp;
suspiciousChildren
| join kind=inner payloadDrops on DeviceId
| where abs(datetime_diff('minute', DropTimestamp, ChildTimestamp)) <= sessionWindowMinutes
| project
    Timestamp = ChildTimestamp,
    DeviceName,
    AccountName,
    InstallerCommandLine,
    ChildProcess,
    ChildFolderPath,
    ChildCommandLine,
    DroppedFile,
    DroppedPath,
    DroppedSHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Many legitimate commercial applications use Inno Setup and install helper executables to AppData or Temp during setup, including games, developer tools, and productivity software.
- Software update mechanisms that use a setup.exe wrapper with Inno may spawn child processes and drop files to AppData as part of normal update workflows.

**Tuning notes:**
- After initial hunting runs, collect SHA256 hashes of legitimate Inno-packaged installers in the environment and add them to an exclusion filter on InstallerCommandLine or a separate hash-based allowlist.
- Consider adding a filter on the ChildProcess name to focus on high-risk executables (e.g., powershell.exe, cmd.exe, rundll32.exe) rather than any executable in Temp/AppData to reduce noise.
- Adjust sessionWindowMinutes based on observed installer session durations in the environment.

**Risks / caveats:**
- DeviceFileEvents and DeviceProcessEvents are only available for devices onboarded to Microsoft Defender for Endpoint. Endpoints without MDE onboarding will not appear in results.
- FolderPath in DeviceProcessEvents reflects the process image path, not the working directory. The has_any filter on FolderPath for Temp and AppData paths will only match if the child executable itself resides in those paths, which is the intended behavior but should be confirmed against the actual telemetry.
- The Inno Setup identification via command-line string matching on setup.exe is a heuristic that will produce false positives from any Inno-packaged legitimate software installer that happens to install components to AppData or Temp.
- The 15-minute session window is an assumption about installer session duration; multi-stage or slow installers may exceed this window and be missed.

### Triage Runbook

**First 15 minutes:**
- Identify the installer source, file name, command line, and the spawned child process names from the alert.
- Check whether the child processes are common installer helpers or suspicious executables such as powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe, or unknown binaries in Temp/AppData.
- Review the dropped file paths and hashes to see whether executables or DLLs were written to user-writable locations during the install session.
- Confirm whether the installation was user-initiated and whether the software is approved in your environment.
- If the installer is unapproved, unsigned, or clearly drops suspicious payloads, escalate for malware investigation.

**Evidence to collect:**
- InstallerCommandLine, ChildProcess, ChildCommandLine, ChildFolderPath, DroppedFile, DroppedPath, DroppedSHA256, and AccountName.
- The original installer hash and source location if available.
- Process tree showing the installer and any child processes spawned during the session.
- File creation evidence for payloads written to Temp or AppData paths.
- Any subsequent persistence, network activity, or execution of the dropped files.

**Pivot points:**
- DeviceProcessEvents to reconstruct the installer session and identify all child processes.
- DeviceFileEvents to confirm file drops, file names, and hashes in Temp or AppData locations.
- DeviceNetworkEvents to determine whether any child process contacted external infrastructure.
- Software deployment records or endpoint management logs to verify whether the installer was approved.
- Defender for Endpoint file and reputation lookups for the dropped SHA256 values.

**Benign explanations:**
- Many legitimate applications use Inno Setup and may spawn helper processes or write to AppData during installation.
- Software updaters and game installers often unpack components into Temp or user profile directories.
- Some vendor installers legitimately launch post-install configuration tools or runtime prerequisites.

**Escalation criteria:**
- The installer is not from an approved software source or is associated with a user-initiated fake download.
- Dropped files are executables or DLLs in suspicious paths and are not part of a documented installation package.
- The child process behavior includes scripting, credential access, persistence, or follow-on network activity.
- The same installer or hash appears on multiple endpoints or is linked to other suspicious alerts.

**Containment actions:**
- Quarantine the installer file and any confirmed malicious dropped payloads if they are still present on the host.
- Isolate the endpoint if the dropped payload has executed or persistence is observed.
- Block the installer hash and any confirmed malicious child hashes in endpoint protection.
- Remove or disable any persistence mechanisms created by the installer if confirmed malicious.

**Closure criteria:**
- The installer is verified as legitimate and matches an approved software deployment or user request.
- Dropped files are consistent with the vendor package and no suspicious child process behavior is found.
- No malicious network activity, persistence, or follow-on execution is observed.
- The event is documented as a benign installer baseline case or allowlist candidate.

<br/>
---
<br/>

## Detection 4: Trojanized Inno Installer Child Process Making Outbound Network Connection During Setup Session

### Detection Opportunity

Child processes spawned by an Inno Setup installer making outbound network connections during the installer session, consistent with monetization payload download or command-and-control activity

### Intelligence Context

- Microsoft Security Blog: Fake-download campaign uses trojanized installers to deliver monetization payloads — [https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/](https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/)
  - Context: The trojanized Inno installer campaign delivers monetization payloads during the installer session. Payload delivery implies outbound network connections from installer child processes to retrieve or activate payloads, which is detectable by correlating process parentage with network connection events.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071
- Products: Inno
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Inno, Windows, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 7d;
let sessionWindowMinutes = 15;
let installerChildren = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "setup.exe"
| where InitiatingProcessCommandLine has_any ("inno", "innounp", "is-", "_isetup")
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\", "\\AppData\\Roaming\\")
| where FileName !in~ ("setup.exe", "uninst.exe", "unins000.exe")
| project
    DeviceId,
    DeviceName,
    AccountName,
    ChildProcessId = ProcessId,
    ChildFileName = FileName,
    ChildFolderPath = FolderPath,
    ChildCommandLine = ProcessCommandLine,
    InstallerCommandLine = InitiatingProcessCommandLine,
    ChildTimestamp = Timestamp;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where isnotempty(RemoteIP)
| join kind=inner installerChildren on DeviceId, $left.InitiatingProcessId == $right.ChildProcessId
| where abs(datetime_diff('minute', Timestamp, ChildTimestamp)) <= sessionWindowMinutes
| project
    Timestamp,
    DeviceName,
    AccountName,
    InstallerCommandLine,
    ChildFileName,
    ChildFolderPath,
    ChildCommandLine,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Many legitimate software installers make outbound connections during setup for license activation, telemetry reporting, or downloading additional components.
- Inno-packaged games and developer tools frequently download additional assets during installation from CDN endpoints.

**Tuning notes:**
- After initial hunting runs, build an exclusion list of known legitimate RemoteIP and RemoteUrl values observed from verified software installers in the environment.
- Adjust sessionWindowMinutes based on observed installer session durations; some multi-stage installers may require a longer window.
- Consider adding a filter to exclude connections to RFC1918 private IP ranges if internal payload staging is not a concern, to reduce noise from legitimate internal software distribution servers.

**Risks / caveats:**
- DeviceNetworkEvents.InitiatingProcessId must match DeviceProcessEvents.ProcessId for reliable process-to-network correlation. ProcessId values are reused by the OS over time; the join must also constrain on DeviceId and a time window to avoid cross-process false correlations.
- RemoteUrl is not always populated in DeviceNetworkEvents; it depends on whether DNS resolution or HTTP inspection is available for the connection. Queries relying on RemoteUrl may miss connections where only RemoteIP is logged.
- ProcessId reuse by the OS means that even with DeviceId and time-window constraints, there is a small residual risk of false ProcessId correlation if the same ProcessId is reused within the session window on a high-churn system.
- The Inno identification heuristic on InitiatingProcessCommandLine will miss trojanized installers that do not include Inno-specific strings in their command line.

### Triage Runbook

**First 15 minutes:**
- Review the child process name, command line, RemoteIP, RemoteUrl, RemotePort, and the installer command line from the alert.
- Confirm the connection occurred during an active installation session and that the child process belongs to the installer tree.
- Check whether the destination is a known vendor CDN, update service, license server, or internal software distribution endpoint.
- Look for repeated connections, unusual ports, or connections to newly observed external destinations.
- If the destination is unknown or the child process is suspicious, escalate and correlate with file drops or persistence.

**Evidence to collect:**
- InstallerCommandLine, ChildFileName, ChildCommandLine, ChildFolderPath, RemoteIP, RemoteUrl, RemotePort, and AccountName.
- Process tree and timing information showing the child process and its network activity.
- Any file creation or execution events tied to the same child process.
- DNS, proxy, or firewall logs for the destination to determine whether the connection is expected.
- Hash and reputation data for the child process and any downloaded content if available.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and time window to identify all outbound connections from the installer child.
- DeviceProcessEvents to validate the parent-child relationship and identify any follow-on processes.
- DeviceFileEvents to look for downloaded or dropped payloads associated with the child process.
- Proxy, firewall, or DNS logs to classify the destination as approved vendor infrastructure or suspicious external hosting.
- Threat intelligence or reputation sources for the RemoteIP and RemoteUrl.

**Benign explanations:**
- Legitimate installers often contact vendor servers for license validation, telemetry, updates, or additional component downloads.
- Inno-packaged games and developer tools may fetch assets or prerequisites during installation.
- Some enterprise software installers use CDN-backed endpoints that can look unusual without vendor context.

**Escalation criteria:**
- The destination is not a known vendor or approved internal endpoint.
- The child process is unexpected, unsigned, or has suspicious command-line arguments.
- The connection is followed by file drops, persistence, or additional suspicious process activity.
- Multiple endpoints show the same installer behavior or the destination is associated with known malicious infrastructure.

**Containment actions:**
- Block the suspicious RemoteIP or RemoteUrl if confirmed malicious and not required for business operations.
- Isolate the endpoint if the child process has executed payloads or shows additional malicious behavior.
- Quarantine the installer and any downloaded artifacts if they are confirmed malicious.
- Coordinate with software owners to disable the installer source if it is a fake-download or trojanized package.

**Closure criteria:**
- The network destination is verified as legitimate vendor, update, or internal distribution infrastructure.
- The child process behavior is consistent with approved installation activity and no malicious artifacts are found.
- No suspicious follow-on process, file, or persistence activity is present.
- The event is documented as benign installer network traffic or added to an allowlist baseline.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Storm-2603 ToolShell: Anomalous SharePoint Operations from Non-Interactive or Unexpected Sources: Do not schedule yet; validate as an analyst-led hunt first.
- Trojanized Inno Installer Spawning Unexpected Child Processes and Dropping Payloads to Suspicious Paths: Do not schedule yet; validate as an analyst-led hunt first.
- Trojanized Inno Installer Child Process Making Outbound Network Connection During Setup Session: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by Storm-2603 ToolShell: SharePoint Worker Process Spawning Anomalous Child Process; Trojanized Inno Installer Spawning Unexpected Child Processes and Dropping Payloads to Suspicious Paths; Trojanized Inno Installer Child Process Making Outbound Network Connection During Setup Session

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Storm-2603 ToolShell: SharePoint Worker Process Spawning Anomalous Child Process.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Storm-2603 ToolShell: Anomalous SharePoint Operations from Non-Interactive or Unexpected Sources; Trojanized Inno Installer Spawning Unexpected Child Processes and Dropping Payloads to Suspicious Paths; Trojanized Inno Installer Child Process Making Outbound Network Connection During Setup Session.

### Hunting Agenda and Promotion Criteria

- Storm-2603 ToolShell: Anomalous SharePoint Operations from Non-Interactive or Unexpected Sources: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Trojanized Inno Installer Spawning Unexpected Child Processes and Dropping Payloads to Suspicious Paths: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Trojanized Inno Installer Child Process Making Outbound Network Connection During Setup Session: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
