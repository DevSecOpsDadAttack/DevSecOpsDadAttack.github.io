---
layout: post
title: "Detection Engineering Brief - Monday, July 6, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-06
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1021.002
  - Windows
  - Metasploit
  - PsExec
  - Meterpreter
  - T1190
  - Peyara Remote Mouse
  - Armored Likho
  - T1566
  - Python
  - BusySnake Stealer
  - Microsoft
  - OAuth 2.0 Device Authorization Grant
  - Microsoft identity
  - T1059.006
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1021.002, Windows, Metasploit, PsExec, Meterpreter, T1190, Peyara Remote Mouse, Armored Likho, T1566, Python, BusySnake Stealer, Microsoft, OAuth 2.0 Device Authorization Grant, Microsoft identity, T1059.006.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: PsExec SMB Lateral Movement Followed by Outbound SMB to Non-DC Host; Peyara Remote Mouse Spawning Unexpected Child Process; Python Stealer Execution from Unusual Parent Process on Windows; SMB Logon Followed by New Service or Interactive Process Creation on Same Host.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: PsExec SMB Lateral Movement Followed by Outbound SMB to Non-DC Host

### Detection Opportunity

PsExec used to facilitate SMB session upgrade to Meterpreter by spawning processes over SMB to non-domain-controller hosts.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/)
  - Context: Rapid7 reported a new Metasploit module that uses PsExec over SMB to upgrade an existing SMB session to a Meterpreter session, enabling post-exploitation on remote Windows hosts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002
- Products: PsExec, Meterpreter
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit, PsExec, Meterpreter
- Search tags: T1021.002, Windows, Metasploit, PsExec, Meterpreter

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021.002 SMB/Windows Admin Shares/ T1021.002 SMB/Windows Admin Shares (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let psexecEvents = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe", "psexec64.exe")
    or ProcessCommandLine has_any ("psexec.exe", "psexec64.exe")
| project DeviceName, PsExecTime = Timestamp, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessAccountName,
    InitiatingProcessId, ProcessId;
let smbOutbound = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project DeviceName, SmbTime = Timestamp, RemoteIP,
    InitiatingProcessFileName, InitiatingProcessAccountName;
psexecEvents
| join kind=inner smbOutbound on DeviceName
| where SmbTime between (PsExecTime .. (PsExecTime + 2m))
| summarize
    DistinctRemoteIPs = dcount(RemoteIP),
    RemoteIPList = make_set(RemoteIP, 20),
    FirstSmbTime = min(SmbTime),
    LastSmbTime = max(SmbTime)
    by DeviceName, PsExecTime, ProcessCommandLine,
       InitiatingProcessFileName, InitiatingProcessAccountName
| order by PsExecTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IT administrators using PsExec for remote management will trigger this detection.
- Automated deployment tools that invoke PsExec and immediately open SMB connections will match the timing window.
- Patch management or software distribution systems using PsExec-style execution over SMB.

**Tuning notes:**
- To exclude domain controllers, add a lookup against a watchlist or dynamic list of DC IPs and filter RemoteIPList accordingly.
- The PSEXESVC service string appears in process events on the target host (the remote side), not the source; if monitoring target hosts, add ProcessCommandLine has 'PSEXESVC' as an alternative detection branch.
- Adjust the 2-minute window to match observed PsExec-to-SMB timing in your environment by reviewing legitimate admin sessions first.
- Add InitiatingProcessFileName exclusions for known IT management binaries such as sccm.exe or landesk.exe if present in the environment.

**Risks / caveats:**
- Domain controller IP exclusion is not implemented in the query; analysts must manually filter RemoteIPList against known DC addresses during triage.
- The 2-minute join window may miss delayed SMB connections or produce excess matches in high-SMB environments; baseline the window against normal admin activity.
- PsExec renamed to a different filename will evade the FileName filter; the ProcessCommandLine filter partially compensates but is not exhaustive.
- Ingestion delay between DeviceProcessEvents and DeviceNetworkEvents may cause missed correlations in high-latency MDE pipelines.

### Triage Runbook

**First 15 minutes:**
- Identify the source host, target RemoteIP(s), and the account used; confirm whether the account is a known admin or service account.
- Check whether the RemoteIP is a domain controller, jump host, patching server, or other approved management system; if yes, validate the change ticket or maintenance window.
- Review the PsExec command line and parent process for signs of interactive use, scripted deployment, or suspicious execution from an unusual parent.
- Look for multiple distinct RemoteIPs from the same device in the alert window, which increases the likelihood of lateral movement rather than a single admin action.

**Evidence to collect:**
- DeviceProcessEvents for the PsExec execution: DeviceName, Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId, InitiatingProcessId.
- DeviceNetworkEvents for SMB connections: RemoteIP, RemotePort, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName.
- Any nearby process creation on the target host that indicates service creation, remote shell activity, or Meterpreter-like staging.
- Asset context for the source and target hosts: role, admin workstation status, and whether the target is a server, workstation, or domain controller.

**Pivot points:**
- DeviceProcessEvents on the source host for additional PsExec executions, child processes, or suspicious command lines around the alert time.
- DeviceNetworkEvents on the source host for other outbound SMB connections to non-DC hosts in the same time window.
- DeviceLogonEvents and DeviceProcessEvents on the target host for remote service creation or unusual process ancestry.
- If available, endpoint inventory or CMDB to confirm whether the source account and host are approved for remote administration.

**Benign explanations:**
- IT administrators using PsExec for legitimate remote maintenance or software deployment.
- Patch management, software distribution, or orchestration tools that invoke PsExec-style remote execution.
- A known admin workstation connecting to a non-DC server during a documented change window.

**Escalation criteria:**
- The source account is not a known admin/service account or the activity occurred outside an approved maintenance window.
- The RemoteIP is a workstation, server, or other host not normally managed with PsExec.
- Multiple non-DC RemoteIPs are contacted in a short period, or the source host shows additional lateral movement behavior.
- Follow-on evidence shows service creation, suspicious child processes, or other post-exploitation activity on the target host.

**Containment actions:**
- If unauthorized activity is confirmed or strongly suspected, isolate the source host from the network.
- Disable or reset the credentials used if they are not a managed service account and compromise is plausible.
- Block the source-to-target SMB path temporarily if lateral movement is ongoing and business impact is acceptable.

**Closure criteria:**
- The RemoteIP is confirmed as an approved management target and the activity matches a documented admin action.
- The initiating account and parent process are consistent with normal remote administration tooling.
- No additional suspicious SMB connections, service creation, or post-exploitation activity is found on the source or target host.

<br/>
---
<br/>

## Detection 2: Peyara Remote Mouse Spawning Unexpected Child Process

### Detection Opportunity

Unauthenticated RCE exploit against Peyara Remote Mouse v1.0.1 causes the application to spawn unexpected child processes on the endpoint.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/)
  - Context: Rapid7 published a Metasploit exploit module targeting an unauthenticated RCE vulnerability in Peyara Remote Mouse v1.0.1. Successful exploitation results in arbitrary process execution under the application's context.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1021.002
- Products: Peyara Remote Mouse
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Peyara Remote Mouse, Windows, Metasploit, T1021.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Lateral Movement: T1021.002 SMB/Windows Admin Shares/ T1021.002 SMB/Windows Admin Shares (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("RemoteMouse", "PeyaraMouse", "remote_mouse")
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "python.exe", "pythonw.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe"
  )
| project Timestamp, DeviceName, InitiatingProcessFileName,
    InitiatingProcessFolderPath, InitiatingProcessAccountName,
    FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Any application whose executable name partially matches RemoteMouse, PeyaraMouse, or remote_mouse will generate false positives.
- Legitimate scripting or automation invoked by the actual Remote Mouse application if it has plugin or macro functionality.

**Tuning notes:**
- Run a software inventory query against DeviceTvmSoftwareInventory or DeviceInfo to locate the actual Peyara Remote Mouse executable name before deploying.
- Once the binary name is confirmed, replace the has_any partial match with an exact in~ comparison to eliminate false positives from name collisions.
- If the application is only installed on a known set of devices, add a DeviceName in~ filter scoped to those hosts.

**Risks / caveats:**
- InitiatingProcessFileName for Peyara Remote Mouse is unconfirmed; the partial string matches (RemoteMouse, PeyaraMouse, remote_mouse) are guesses and may match unrelated processes or miss the actual binary entirely. The exact filename must be confirmed from endpoint software inventory before this query is meaningful.
- The Peyara Remote Mouse executable name is unconfirmed; the query must be updated with the verified binary name before it produces reliable results.
- Low install base of this application means MDE telemetry coverage may be zero in most environments.
- No CVE is associated with this detection; if a CVE is published, adding it to search_tags and correlating with vulnerability scan data would improve confidence.

### Triage Runbook

**First 15 minutes:**
- Confirm the endpoint actually has Peyara Remote Mouse installed and identify the exact binary name and install path.
- Review the spawned child process name and command line; focus on shells, scripting engines, downloaders, or LOLBins.
- Check whether the parent process path and account are expected for the application and whether the activity occurred on a device known to use the software.
- Look for repeated child process spawning or a chain of suspicious children from the same parent within a short time window.

**Evidence to collect:**
- DeviceProcessEvents for the parent and child process chain: DeviceName, Timestamp, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName, FileName, ProcessCommandLine, SHA256.
- Software inventory or endpoint inventory confirming the Peyara Remote Mouse executable name and deployment scope.
- Any related file creation or modification events from the same parent process that indicate payload drop or staging.
- User context for the endpoint: logged-on user, device role, and whether the application is expected on that host.

**Pivot points:**
- DeviceProcessEvents on the same host for all children of the Peyara Remote Mouse process around the alert time.
- DeviceFileEvents for file writes by the same parent or child process to Temp, AppData, or other user-writable paths.
- DeviceInfo or software inventory tables to confirm installed application names and versions.
- If available, network events from the host to identify outbound connections immediately after the child process starts.

**Benign explanations:**
- The application may legitimately launch helper processes, scripts, or update components on some installations.
- A partial filename match may have matched an unrelated application with a similar name.
- The endpoint may be a test or lab system where the software is intentionally exercised.

**Escalation criteria:**
- The child process is a shell, scripting engine, downloader, or other process not expected from the application.
- The endpoint is not known to have Peyara Remote Mouse installed, or the parent filename/path does not match the verified binary.
- Additional suspicious activity appears, such as file drops, persistence, or outbound connections after the child process starts.
- The same behavior is seen on multiple endpoints, suggesting active exploitation rather than a one-off anomaly.

**Containment actions:**
- If exploitation is suspected, isolate the endpoint from the network.
- Terminate the suspicious child process and any related spawned processes if they are still active.
- Preserve the parent and child process hashes and command lines before remediation.

**Closure criteria:**
- The exact application binary is confirmed and the child process is documented as expected behavior for that version.
- The endpoint is in a known software deployment group and no other suspicious activity is present.
- No additional malicious process creation, file writes, or network activity is observed from the host.

<br/>
---
<br/>

## Detection 3: Python Stealer Execution from Unusual Parent Process on Windows

### Detection Opportunity

BusySnake Stealer, a Python-based credential stealer, executed on Windows endpoints via python.exe or pythonw.exe spawned from an unusual or document-handling parent process.

### Intelligence Context

- Securelist: Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign — [https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/](https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/)
  - Context: Armored Likho delivered BusySnake Stealer via spear-phishing with AI-generated loaders. The stealer is Python-based and executes on Windows, with the infection chain passing through document or loader processes before spawning the Python interpreter.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1566, T1059.006
- Products: Not specified
- Platforms: Windows, Python
- Malware: BusySnake Stealer
- Tools: Not specified
- Search tags: Armored Likho, T1566, Windows, Python, BusySnake Stealer, T1059.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059.006 Command and Scripting Interpreter/ T1059.006 Python (medium); Initial Access: T1566 Phishing (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let suspiciousParents = dynamic([
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "foxitreader.exe", "7zfm.exe", "winrar.exe",
    "wscript.exe", "cscript.exe", "mshta.exe"
]);
let pythonFromParent = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python.exe", "pythonw.exe")
| where InitiatingProcessFileName in~ (suspiciousParents)
| project
    SignalType = "PythonFromSuspiciousParent",
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    FolderPath = "",
    SHA256;
let pythonToSuspiciousPath = DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe", "pythonw.exe")
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\", "\\AppData\\Roaming\\")
| project
    SignalType = "PythonWriteToUserPath",
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine = "",
    FolderPath,
    SHA256;
pythonFromParent
| union pythonToSuspiciousPath
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Python scripts legitimately invoked by Office macros or automation in business workflows.
- Python package managers (pip) writing to AppData or Temp during installation.
- Legitimate scripting automation tools that use wscript.exe or cscript.exe to launch Python.
- Developer environments where Python is routinely spawned from document-handling contexts.

**Tuning notes:**
- Add device group or tag exclusions for developer workstations to reduce noise from legitimate Python development.
- If BusySnake Stealer file hashes become available from threat intelligence, add a SHA256 in~ filter to the pythonToSuspiciousPath branch for high-confidence alerting.
- Extend suspiciousParents to include any AI-generated loader or custom dropper filenames identified in the Armored Likho campaign as intelligence becomes available.
- Consider correlating both branches on the same DeviceName within a short time window to require both signals before alerting, which would significantly reduce false positives.

**Risks / caveats:**
- Python development activity on endpoints will generate false positives from both branches; the detection requires analyst review of each result.
- The suspiciousParents list uses exact in~ matching; Python spawned by renamed or less common loader processes will not be detected.
- No file hashes for BusySnake Stealer components are available to add as high-confidence filters; if hashes are published, adding them as a SHA256 in~ filter would significantly improve precision.
- The FolderPath has_any filter matches any write to Temp or AppData by Python, which includes legitimate package installation activity.

### Triage Runbook

**First 15 minutes:**
- Identify which branch fired: Python spawned from a suspicious parent or Python writing to user-writable paths; treat either as potentially malicious until explained.
- Review the parent process, command line, and account context to see whether Python was launched from Office, a document handler, archive tool, or script host.
- Check whether the endpoint is a developer workstation, automation host, or user endpoint; developer systems require stronger corroboration before escalation.
- Look for immediate follow-on behavior such as credential access, additional script execution, or file drops in Temp or AppData.

**Evidence to collect:**
- DeviceProcessEvents for the full parent-child chain: InitiatingProcessFileName, InitiatingProcessAccountName, FileName, ProcessCommandLine, SHA256, DeviceName, Timestamp.
- DeviceFileEvents for Python-related file creation or modification in Temp and AppData paths, including FolderPath and SHA256.
- Any nearby process events showing Office, archive, script host, or browser-originated execution preceding Python.
- User and device context: logged-on user, device role, and whether Python development or automation is expected.

**Pivot points:**
- DeviceProcessEvents on the host for all python.exe/pythonw.exe executions in the same day to identify repeated launches or unusual parents.
- DeviceFileEvents for Python writes to user-writable paths and any subsequent execution of those written files.
- DeviceNetworkEvents from the host for outbound connections after Python starts, especially to uncommon destinations.
- If available, endpoint software inventory or device tags to determine whether the host is a developer workstation.

**Benign explanations:**
- Legitimate Python development, testing, or package installation activity on developer endpoints.
- Automation or scripting workflows that use Office macros, wscript, cscript, or archive tools to launch Python.
- pip or other package managers writing to AppData or Temp during normal installation or update activity.

**Escalation criteria:**
- Python is launched from an unusual parent on a non-developer endpoint, especially from Office, a document handler, or script host.
- The Python process writes executable or script content to Temp/AppData and then executes or stages additional payloads.
- The host shows credential theft indicators, suspicious network connections, or repeated Python launches from the same suspicious parent.
- The SHA256 matches threat intelligence or the same behavior appears across multiple endpoints.

**Containment actions:**
- If malicious behavior is likely, isolate the host from the network.
- Kill the suspicious Python process tree and preserve hashes, command lines, and dropped files.
- Reset exposed credentials if the host shows signs of credential theft or token abuse.

**Closure criteria:**
- The activity is confirmed as approved development or automation on a known-good endpoint.
- The parent process and file writes are consistent with normal Python installation or package management.
- No additional suspicious child processes, file drops, or network activity are found.

<br/>
---
<br/>

## Detection 4: OAuth Device Code Flow Authentication Followed by Anomalous Resource Access

### Detection Opportunity

Threat actors abused the OAuth 2.0 device code authorization flow to phish user credentials and obtain tokens, then used those tokens to access resources under the victim identity.

### Intelligence Context

- Securelist: When checking the URL isn't enough: a Device Code Phishing attack via a Microsoft website — [https://securelist.com/microsoft-device-code-phishing-attack/120350/](https://securelist.com/microsoft-device-code-phishing-attack/120350/)
  - Context: Securelist reported that threat actors weaponized the OAuth 2.0 device code flow by directing victims to a legitimate Microsoft URL, causing them to authenticate and hand over tokens. The attack is notable because the URL appears legitimate, making URL-based detection ineffective; the signal lies in the device code grant event itself combined with subsequent resource access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566
- Products: Microsoft, OAuth 2.0 Device Authorization Grant
- Platforms: Microsoft identity
- Malware: Not specified
- Tools: Not specified
- Search tags: T1566, Microsoft, OAuth 2.0 Device Authorization Grant, Microsoft identity

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing (medium)

### Deployment Gates

- The AuthenticationProtocol field is only populated in the NonInteractiveUserSignInLogs and SigninLogs tables when the Entra ID P1 or P2 license is active; tenants without this license may not have this field populated.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let deviceCodeSignins = SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol in ("deviceCode", "device_code")
    or ClientAppUsed == "Device Code Flow"
| where ResultType == 0
| project
    UserPrincipalName,
    SigninTime = TimeGenerated,
    IPAddress,
    ClientAppUsed,
    ConditionalAccessStatus,
    AppDisplayName,
    Location,
    CorrelationId;
let followOnActivity = AuditLogs
| where TimeGenerated > ago(7d)
| where Category in ("ApplicationManagement", "RoleManagement", "GroupManagement")
    or OperationName has_any ("Consent to application", "Add member to role", "Update user")
| extend UPN = tostring(InitiatedBy.user.userPrincipalName)
| extend AuditInitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| project
    UPN,
    AuditTime = TimeGenerated,
    OperationName,
    Category,
    AuditInitiatedByIP;
deviceCodeSignins
| join kind=inner followOnActivity on $left.UserPrincipalName == $right.UPN
| where AuditTime between (SigninTime .. (SigninTime + 30m))
| project
    UserPrincipalName,
    SigninTime,
    IPAddress,
    AppDisplayName,
    Location,
    ClientAppUsed,
    ConditionalAccessStatus,
    CorrelationId,
    AuditTime,
    OperationName,
    Category,
    AuditInitiatedByIP
| order by SigninTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate device code sign-ins from IoT devices, shared terminals, or CLI tooling followed by routine administrative operations.
- Helpdesk or IT administrators who use device code flow for delegated access and then perform role or group management within the correlation window.
- Automated pipelines using device code flow for service authentication followed by application management operations.

**Tuning notes:**
- Validate the AuthenticationProtocol field by running: SigninLogs → where TimeGenerated > ago(1d) → summarize count() by AuthenticationProtocol → order by count_ desc
- Narrow the AuditLogs OperationName filter to 'Consent to application' and 'Add member to role' as the highest-risk post-authentication actions to reduce noise.
- Add a UserPrincipalName not in~ exclusion list for known service accounts and IoT device identities that legitimately use device code flow.
- Consider adding a new-IP heuristic by joining against a 30-day baseline of IPAddress values per UserPrincipalName to surface first-seen IPs.

**Risks / caveats:**
- SigninLogs and AuditLogs require the Microsoft Entra ID (Azure Active Directory) diagnostic settings data connector to be configured in Sentinel. If this connector is absent, both tables will be empty and the query will return no results.
- The AuthenticationProtocol field is only populated in the NonInteractiveUserSignInLogs and SigninLogs tables when the Entra ID P1 or P2 license is active; tenants without this license may not have this field populated.
- The AuthenticationProtocol field value for device code flow varies across Entra ID tenants and log schema versions; validate the exact string present in your SigninLogs before scheduling.
- The 30-minute correlation window may be too broad in tenants with high audit log volume; baseline the window against normal post-sign-in audit activity.

### Triage Runbook

**First 15 minutes:**
- Confirm the user, IP address, app display name, and whether the sign-in was expected for that user or device.
- Review the follow-on audit operation and decide whether it is high risk, such as consent grants, role changes, or group membership changes.
- Check whether the sign-in came from a new or unusual IP, location, or client app for the user.
- Validate whether the user reports using device code flow for CLI tools, shared devices, or IoT workflows.

**Evidence to collect:**
- SigninLogs for the user: AuthenticationProtocol, ClientAppUsed, ResultType, ConditionalAccessStatus, AppDisplayName, Location, IPAddress, CorrelationId, TimeGenerated.
- AuditLogs for the correlated action: Category, OperationName, InitiatedBy, InitiatedBy.user.ipAddress, TimeGenerated, and affected object details.
- User baseline for normal sign-in locations, device code usage, and recent administrative activity.
- Any related consent, role assignment, or application management events around the same time.

**Pivot points:**
- SigninLogs for the same user over the prior 30 days to identify first-seen IPs, locations, or device code usage patterns.
- AuditLogs for the same user and time window to find additional consent, role, or group changes.
- Entra ID sign-in and audit data for other users from the same IP or app to identify broader abuse.
- If available, identity protection or risk events associated with the account.

**Benign explanations:**
- Legitimate device code flow used by CLI tools, shared kiosks, IoT devices, or delegated admin workflows.
- Helpdesk or IT staff using device code authentication for routine administration.
- Automated pipelines or service workflows that rely on device code sign-in and then perform expected management actions.

**Escalation criteria:**
- The follow-on audit action is high risk, such as consent grant, role assignment, or privileged group modification.
- The sign-in IP, location, or client app is unusual for the user and cannot be explained by normal work patterns.
- The user denies the activity or there are signs of account compromise, token abuse, or additional suspicious sign-ins.
- Multiple users or multiple high-risk audit actions are linked to the same source IP or application.

**Containment actions:**
- If compromise is suspected, disable the account or force sign-out and revoke active sessions/tokens.
- Reset the password and review or revoke recent consent grants and role assignments as appropriate.
- Block or investigate the source IP if it is clearly malicious and not shared infrastructure.

**Closure criteria:**
- The device code sign-in is confirmed as expected and the follow-on audit action is authorized.
- The user, app, IP, and location align with known administrative or automation behavior.
- No additional suspicious sign-ins, consent grants, or privilege changes are found.

<br/>
---
<br/>

## Detection 5: SMB Logon Followed by New Service or Interactive Process Creation on Same Host

### Detection Opportunity

Metasploit SMB-to-Meterpreter session upgrade module authenticates over SMB and then causes a new service or interactive process to be created on the target host within a short time window.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/)
  - Context: Rapid7 described a Metasploit module that upgrades an SMB session to Meterpreter. The upgrade involves an SMB network logon followed by the creation of a new process on the target host, which is the Meterpreter stager being executed remotely.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002
- Products: Meterpreter
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit, Meterpreter
- Search tags: T1021.002, Windows, Metasploit, Meterpreter

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021.002 SMB/Windows Admin Shares/ T1021.002 SMB/Windows Admin Shares (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceLogonEvents, DeviceProcessEvents

### KQL

```kql
let smbLogons = DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "Network"
| where AccountName !endswith "$"
| where AccountName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| project DeviceName, LogonTime = Timestamp, AccountName, RemoteIP, Protocol;
let newProcesses = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "services.exe", "svchost.exe", "lsass.exe"
  )
| where FileName !in~ (
    "conhost.exe", "WerFault.exe", "SearchIndexer.exe",
    "TiWorker.exe", "TrustedInstaller.exe", "MpCmdRun.exe",
    "SgrmBroker.exe", "spoolsv.exe", "msiexec.exe"
  )
| project DeviceName, ProcTime = Timestamp, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessAccountName, SHA256;
smbLogons
| join kind=inner newProcesses on DeviceName
| where ProcTime between (LogonTime .. (LogonTime + 3m))
| project
    DeviceName,
    LogonTime,
    AccountName,
    RemoteIP,
    Protocol,
    ProcTime,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    SHA256
| order by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote management platforms (SCCM, Intune, Ansible) that authenticate via SMB and deploy services.
- Patch management systems that install services following network authentication.
- Domain join and group policy processing that triggers service creation after network logon.
- Backup agents and monitoring tools that authenticate via SMB and spawn child processes.

**Tuning notes:**
- Validate LogonType string values in your environment by running: DeviceLogonEvents → where Timestamp > ago(1d) → summarize count() by LogonType → order by count_ desc
- Check Protocol field population rate with: DeviceLogonEvents → where Timestamp > ago(1d) → summarize Populated = countif(isnotempty(Protocol)), Total = count()
- Reduce the correlation window to 90 seconds if the environment has high SMB logon volume to improve signal precision.
- Add FileName in~ filters for known Meterpreter stager names or suspicious executable patterns (e.g., random alphanumeric names) to increase specificity.

**Risks / caveats:**
- The Protocol field in DeviceLogonEvents is not consistently populated across all MDE-onboarded endpoints and Windows versions. The query falls back to LogonType == 'Network' alone when Protocol is empty, which broadens the match to all network logons, not just SMB. Validate Protocol field population in your environment before relying on it as a filter.
- The Protocol field is frequently empty in DeviceLogonEvents; the query relies on LogonType == 'Network' as the primary SMB indicator, which matches all network logons regardless of protocol.
- The 3-minute correlation window will produce a high volume of matches in environments with frequent SMB-based service deployments; baseline the window against normal activity before scheduling.
- The process exclusion list is not exhaustive; additional legitimate service-spawned processes in the environment will require ongoing tuning.

### Triage Runbook

**First 15 minutes:**
- Identify the source RemoteIP, account name, and target host role; confirm whether the account is a machine account, SYSTEM, or a known admin/service account.
- Check whether the target host is a server managed by patching, backup, or orchestration tools that commonly create services after SMB logon.
- Review the spawned process name and command line for service installation, scripting, or suspicious stagers.
- Look for repeated SMB logons or multiple process creations on the same host in the same time window.

**Evidence to collect:**
- DeviceLogonEvents for the SMB/network logon: DeviceName, LogonTime, AccountName, RemoteIP, Protocol, LogonType.
- DeviceProcessEvents for the follow-on process: ProcTime, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, SHA256.
- Any service creation, scheduled task creation, or remote execution artifacts on the target host.
- Host role and management context: whether the target is a server, workstation, or managed endpoint with approved remote tooling.

**Pivot points:**
- DeviceProcessEvents on the target host for all processes spawned by services.exe, svchost.exe, or lsass.exe around the alert time.
- DeviceLogonEvents for the same source IP or account across other hosts to identify lateral movement spread.
- DeviceNetworkEvents for SMB connections from the source host to other systems in the same period.
- If available, endpoint management or patching logs to confirm whether the activity aligns with an approved deployment.

**Benign explanations:**
- Legitimate remote management, patching, or software deployment tools that authenticate over SMB and create services.
- Backup, monitoring, or orchestration agents that perform service-based actions after network logon.
- Domain or enterprise administration activity during a maintenance window.

**Escalation criteria:**
- The source account is not authorized for remote administration or the activity is outside a maintenance window.
- The spawned process is unusual for service activity, or the command line suggests remote stager execution.
- The same source host or account touches multiple targets in a short period, indicating lateral movement.
- Additional evidence of Meterpreter, remote shell, or service installation is found on the target host.

**Containment actions:**
- If unauthorized lateral movement is likely, isolate the source host and the affected target host if feasible.
- Disable or reset the account used for the SMB logon if it is not a managed service account.
- Block the source host from further SMB connections while investigation continues.

**Closure criteria:**
- The SMB logon and process creation are confirmed as approved remote management activity.
- The account, source IP, and target host are all expected and documented.
- No additional suspicious processes, service creations, or lateral movement are observed.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- PsExec SMB Lateral Movement Followed by Outbound SMB to Non-DC Host: Do not schedule yet; validate as an analyst-led hunt first.
- Python Stealer Execution from Unusual Parent Process on Windows: Do not schedule yet; validate as an analyst-led hunt first.
- SMB Logon Followed by New Service or Interactive Process Creation on Same Host: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Peyara Remote Mouse Spawning Unexpected Child Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Licensing / identity risk fields:**
- OAuth Device Code Flow Authentication Followed by Anomalous Resource Access: The AuthenticationProtocol field is only populated in the NonInteractiveUserSignInLogs and SigninLogs tables when the Entra ID P1 or P2 license is active; tenants without this license may not have this field populated.

**Shared-table notes:**
- DeviceProcessEvents: shared by PsExec SMB Lateral Movement Followed by Outbound SMB to Non-DC Host; Peyara Remote Mouse Spawning Unexpected Child Process; Python Stealer Execution from Unusual Parent Process on Windows; SMB Logon Followed by New Service or Interactive Process Creation on Same Host

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: OAuth Device Code Flow Authentication Followed by Anomalous Resource Access.
2. Resolve environment-mapping detections next: Peyara Remote Mouse Spawning Unexpected Child Process.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: PsExec SMB Lateral Movement Followed by Outbound SMB to Non-DC Host; Python Stealer Execution from Unusual Parent Process on Windows; SMB Logon Followed by New Service or Interactive Process Creation on Same Host.

### Hunting Agenda and Promotion Criteria

- PsExec SMB Lateral Movement Followed by Outbound SMB to Non-DC Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Python Stealer Execution from Unusual Parent Process on Windows: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- SMB Logon Followed by New Service or Interactive Process Creation on Same Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Peyara Remote Mouse Spawning Unexpected Child Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
