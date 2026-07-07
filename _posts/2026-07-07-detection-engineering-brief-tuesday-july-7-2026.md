---
layout: post
title: "Detection Engineering Brief - Tuesday, July 7, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-07
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Microsoft
  - web
  - Armored Likho
  - BusySnake Stealer
  - Windows
  - Metasploit
  - PsExec
  - Meterpreter
  - SMB
  - Peyara Remote Mouse 1.0.1
  - T1528
  - T1566.002
  - T1566
  - T1059.006
  - T1036.005
  - T1059
  - T1036
  - T1190
  - T1203
  - T1105
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Microsoft, web, Armored Likho, BusySnake Stealer, Windows, Metasploit, PsExec, Meterpreter, SMB, Peyara Remote Mouse 1.0.1, T1528, T1566.002, T1566, T1059.006, T1036.005, T1059, T1036, T1190, T1203, T1105.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Device Code Flow OAuth Authentication with Anomalous Context; Python Stealer Execution from Suspicious Parent Process or User-Writable Path; Peyara Remote Mouse Process Spawning Unexpected Child or Making Outbound Connection.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Device Code Flow OAuth Authentication with Anomalous Context

### Detection Opportunity

OAuth 2.0 device authorization flow used as phishing mechanism via a Microsoft-hosted page to harvest tokens from victims

### Intelligence Context

- Securelist: When checking the URL isn't enough: a Device Code Phishing attack via a Microsoft website — [https://securelist.com/microsoft-device-code-phishing-attack/120350/](https://securelist.com/microsoft-device-code-phishing-attack/120350/)
  - Context: Attackers abused the OAuth 2.0 device authorization grant flow via a legitimate Microsoft website to phish tokens from victims. The attack exploits the device code flow to obtain access tokens without requiring the victim to enter credentials on an attacker-controlled page.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1528, T1566.002, T1566
- Products: Microsoft
- Platforms: web
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft, web, T1528, T1566.002, T1566

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1528 Steal Application Access Token (high); Initial Access: T1566 Phishing/ T1566.002 Spearphishing Link (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- SigninLogs

### KQL

```kql
let TargetResources = dynamic([
    "Microsoft Graph",
    "Office 365 Exchange Online",
    "SharePoint Online",
    "Microsoft Teams",
    "Azure Active Directory"
]);
let DeviceCodeSignIns =
    union isfuzzy=true
        (
            SigninLogs
            | where TimeGenerated >= ago(7d)
            | where AuthenticationProtocol =~ "deviceCode" or ClientAppUsed has "Device Code"
            | where ResultType == 0
            | where ResourceDisplayName in (TargetResources)
            | extend SignInSource = "Interactive"
        ),
        (
            AADNonInteractiveUserSignInLogs
            | where TimeGenerated >= ago(7d)
            | where AuthenticationProtocol =~ "deviceCode" or ClientAppUsed has "Device Code"
            | where ResultType == 0
            | where ResourceDisplayName in (TargetResources)
            | extend SignInSource = "NonInteractive"
        )
    | extend
        RiskLevel = tostring(RiskLevelDuringSignIn),
        CAStatus = tostring(ConditionalAccessStatus)
    | extend CorrelatedRisk = case(
        RiskLevel in ("medium", "high"), "RiskElevated",
        CAStatus == "failure", "CAFailure",
        "None"
      )
    | where CorrelatedRisk != "None";
DeviceCodeSignIns
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    ResourceDisplayName,
    ClientAppUsed,
    AuthenticationProtocol,
    RiskLevel,
    CAStatus,
    CorrelatedRisk,
    UserAgent,
    SignInSource,
    ResultType
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate device enrollments for shared kiosk or conference room accounts that use device code flow by design.
- Bulk device onboarding scenarios where multiple device code sign-ins occur in a short window.
- Tenants with Conditional Access policies that intentionally block device code flow will generate CA failure events for all such attempts including legitimate ones.

**Tuning notes:**
- If RiskLevelDuringSignIn is consistently empty, remove the RiskElevated branch and rely solely on CAStatus == 'failure' combined with resource scope.
- To convert to a scheduled rule, add a summarize step grouping by UserPrincipalName and apply a SignInCount threshold appropriate to the environment's device enrollment baseline.
- Consider adding a watchlist of known device enrollment service accounts to exclude from alerting.

**Risks / caveats:**
- RiskLevelDuringSignIn is only populated when Azure AD Identity Protection (P2 license) is active. Tenants without P2 will see this field as empty, causing the risk-based filter branch to produce no results.
- AuthenticationProtocol field availability in SigninLogs depends on the tenant's Entra ID diagnostic settings version. Older log schema versions may not populate this field; AADNonInteractiveUserSignInLogs may be required as a supplementary source.
- The 7-day lookback window may miss slow-burn campaigns; extend to 14 or 30 days for periodic hunting runs.
- AADNonInteractiveUserSignInLogs may not be enabled in all tenants; confirm the diagnostic setting is active before relying on the union branch.

### Triage Runbook

**First 15 minutes:**
- Confirm whether the UserPrincipalName belongs to a kiosk, shared device, helpdesk, or automation account that legitimately uses device code flow.
- Review the sign-in context for the alerting event: IPAddress, Location, UserAgent, ResourceDisplayName, RiskLevelDuringSignIn, and ConditionalAccessStatus.
- Check whether the same account had other sign-ins from the same IP or location in the preceding and following hour, especially to Microsoft Graph, Exchange Online, SharePoint Online, Teams, or Azure Active Directory.
- If RiskLevelDuringSignIn is medium or high, treat as likely compromise until disproven and look for mailbox, file, or consent activity after the sign-in.

**Evidence to collect:**
- SigninLogs and AADNonInteractiveUserSignInLogs entries for the account around the alert time.
- Conditional Access policy results and any risk events tied to the account.
- UserAgent and IP reputation/geo history for the source address.
- Audit logs for consent grants, mailbox rule creation, app registrations, or unusual token use after the sign-in.

**Pivot points:**
- SigninLogs
- AADNonInteractiveUserSignInLogs
- AuditLogs
- OfficeActivity
- CloudAppEvents

**Benign explanations:**
- Planned device enrollment or kiosk login using device code flow.
- Helpdesk or admin-assisted authentication for a managed device.
- Bulk onboarding or conference-room/shared-account activity that intentionally uses device code flow.
- Conditional Access failures caused by a policy that blocks device code flow for all users, including legitimate attempts.

**Escalation criteria:**
- RiskLevelDuringSignIn is medium or high and the account is not a known device-enrollment or shared-device account.
- The same account shows successful access to Microsoft 365 resources from an unfamiliar IP or geography shortly after the device code event.
- There is evidence of consent grant abuse, mailbox rule creation, or other post-authentication activity consistent with token misuse.
- Multiple users report unexpected device code prompts or phishing messages tied to the same campaign window.

**Containment actions:**
- Disable or reset the affected account if there is evidence of token theft or unauthorized access.
- Revoke active refresh tokens/sessions for the account and force reauthentication.
- Block the source IP or user agent only if it is clearly malicious and not shared by legitimate users.
- If a phishing campaign is confirmed, notify email security to search for and remove related lures.

**Closure criteria:**
- The account is confirmed as a legitimate device-enrollment/shared-device workflow and no suspicious follow-on activity is found.
- Risk and sign-in context match an approved admin or helpdesk process.
- No additional anomalous sign-ins, consent events, or resource access are observed within the investigation window.
- Any false-positive source, such as a kiosk or onboarding account, is documented for tuning or watchlisting.

<br/>
---
<br/>

## Detection 2: Python Stealer Execution from Suspicious Parent Process or User-Writable Path

### Detection Opportunity

Python-based BusySnake Stealer executed on Windows endpoints, spawned from unusual parent processes or writing to user-writable directories

### Intelligence Context

- Securelist: Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign — [https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/](https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/)
  - Context: Armored Likho deployed BusySnake Stealer, a Python-based credential and data theft tool, delivered via spear-phishing with AI-generated loaders on Windows systems. The stealer executes via the Python interpreter and is expected to write artifacts to user-accessible paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1059.006, T1036.005, T1059, T1036
- Products: Not specified
- Platforms: Windows
- Malware: BusySnake Stealer
- Tools: Not specified
- Search tags: Armored Likho, BusySnake Stealer, Windows, T1059.006, T1036.005, T1059, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high); Defense Evasion: T1036 Masquerading/ T1036.005 Match Legitimate Name or Location (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let KnownDevParents = dynamic([
    "code.exe", "devenv.exe", "pycharm64.exe",
    "conda.exe", "jupyter.exe", "idle.exe",
    "jupyter-notebook.exe", "spyder.exe"
]);
let KnownPythonPaths = dynamic([
    "\\Python3", "\\Python2", "\\Anaconda", "\\miniconda",
    "\\Program Files\\Python", "\\Program Files (x86)\\Python"
]);
let SuspiciousWritePaths = dynamic([
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\ProgramData\\",
    "\\Users\\Public\\"
]);
let SuspiciousPythonProcs = DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("python.exe", "pythonw.exe")
| where not(InitiatingProcessFileName in~ (KnownDevParents))
| where not(FolderPath has_any (KnownPythonPaths))
| project
    DeviceName, AccountName,
    ProcTimestamp = Timestamp,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FolderPath, SHA256,
    ProcessId;
let SuspiciousFileWrites = DeviceFileEvents
| where Timestamp >= ago(7d)
| where InitiatingProcessFileName in~ ("python.exe", "pythonw.exe")
| where FolderPath has_any (SuspiciousWritePaths)
| project
    DeviceName,
    FileWriteTime = Timestamp,
    WrittenPath = FolderPath,
    WrittenFile = FileName,
    InitiatingProcessId;
SuspiciousPythonProcs
| join kind=inner (
    SuspiciousFileWrites
  ) on DeviceName
| where FileWriteTime between (ProcTimestamp .. (ProcTimestamp + 5m))
| project
    DeviceName, AccountName,
    ProcTimestamp, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FolderPath, SHA256,
    FileWriteTime, WrittenPath, WrittenFile
| sort by ProcTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workstations running Python scripts that write output to AppData or Temp directories.
- Automated build or CI/CD agents invoking Python from non-standard parent processes.
- Python-based system management tools (e.g., Ansible, Salt) that write to ProgramData.

**Tuning notes:**
- Run the SuspiciousPythonProcs subquery alone over 30 days to identify additional legitimate parent processes to add to KnownDevParents.
- Scope DeviceName to non-developer endpoint groups using a device tag filter or a watchlist of developer hostnames to reduce volume.
- Consider adding SHA256 lookup against threat intelligence if available to prioritize results.

**Risks / caveats:**
- DeviceFileEvents telemetry for file writes initiated by Python processes requires that Microsoft Defender for Endpoint advanced hunting is licensed and the device is onboarded. Endpoints not onboarded to MDE will produce no results.
- Custom-renamed Python interpreters will evade filename-based detection.
- The 5-minute join window may miss cases where the stealer writes files after a delay; adjust based on observed stealer behavior.
- Developer workstations will still generate false positives if their IDE parent processes are not in the exclusion list; expand KnownDevParents as needed.

### Triage Runbook

**First 15 minutes:**
- Identify the endpoint owner and whether the device is a developer workstation, build agent, or standard user system.
- Review the parent process, command line, and folder path to see whether python.exe/pythonw.exe was launched from a user-writable location or by an unusual parent.
- Check for concurrent file writes to Temp, AppData, ProgramData, or Public directories and note any newly created scripts, archives, or executables.
- Look for signs of credential theft or staging such as browser data access, archive creation, PowerShell use, or outbound connections from the same host.

**Evidence to collect:**
- DeviceProcessEvents for the Python process and its parent chain.
- DeviceFileEvents for files written by python.exe/pythonw.exe around the same timestamp.
- SHA256 for the Python process and any dropped files.
- DeviceNetworkEvents for outbound connections from the host during the execution window.
- User and device context to determine whether the activity matches a developer or automation baseline.

**Pivot points:**
- DeviceProcessEvents
- DeviceFileEvents
- DeviceNetworkEvents
- DeviceTvmSoftwareInventory

**Benign explanations:**
- Developer activity from IDEs, notebooks, or conda environments.
- Automation or CI/CD jobs that invoke Python from non-standard parents.
- Legitimate scripting tools or system management frameworks that use Python and write to ProgramData or Temp.
- User-launched Python scripts from Downloads or AppData during software testing or package installation.

**Escalation criteria:**
- Python is launched by an unexpected parent and writes artifacts to user-writable paths on a non-developer endpoint.
- The same host shows suspicious outbound connections, archive creation, or browser credential access around the event.
- The SHA256 is unknown or matches threat intelligence for BusySnake Stealer or related loaders.
- Multiple endpoints show the same pattern, suggesting a campaign rather than isolated admin activity.

**Containment actions:**
- Isolate the endpoint if the Python execution is accompanied by suspicious file drops, credential access, or outbound C2-like traffic.
- Terminate the malicious process tree if confirmed and preserve memory and disk evidence first when possible.
- Quarantine or remove dropped artifacts and block known malicious hashes if identified.
- Reset credentials for any accounts used on the host if credential theft is suspected.

**Closure criteria:**
- The activity is confirmed as legitimate developer, automation, or software deployment behavior.
- No suspicious file writes, network activity, or credential-access behavior is found.
- The parent process and path align with an approved baseline for that device group.
- Any benign parent processes or paths are documented for tuning or exclusion.

<br/>
---
<br/>

## Detection 3: Loader Executing from User-Writable Path Spawning Python Interpreter

### Detection Opportunity

AI-generated loader executing from user-writable directories and spawning a Python interpreter as part of the BusySnake Stealer delivery chain

### Intelligence Context

- Securelist: Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign — [https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/](https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/)
  - Context: Armored Likho used AI-generated loaders as the first stage of the BusySnake Stealer campaign. These loaders are expected to execute from user-writable paths and subsequently spawn the Python interpreter to run the stealer payload, forming a distinctive parent-child process chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1059.006, T1036.005, T1059, T1036
- Products: Not specified
- Platforms: Windows
- Malware: BusySnake Stealer
- Tools: Not specified
- Search tags: Armored Likho, BusySnake Stealer, Windows, T1059.006, T1036.005, T1059, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high); Defense Evasion: T1036 Masquerading/ T1036.005 Match Legitimate Name or Location (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let KnownDevParents = dynamic([
    "code.exe", "devenv.exe", "pycharm64.exe",
    "conda.exe", "jupyter.exe", "idle.exe",
    "jupyter-notebook.exe", "spyder.exe",
    "explorer.exe"
]);
let UserWritablePaths = dynamic([
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\Users\\Public\\",
    "\\ProgramData\\",
    "\\Downloads\\"
]);
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("python.exe", "pythonw.exe")
| where not(InitiatingProcessFileName in~ (KnownDevParents))
| where
    InitiatingProcessCommandLine has_any (UserWritablePaths)
    or FolderPath has_any (UserWritablePaths)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software deployment tools that stage Python installers or scripts in ProgramData before execution.
- User-initiated Python scripts launched from Downloads after downloading a legitimate Python package.
- Automated testing frameworks that invoke Python from temp directories.

**Tuning notes:**
- Scope to non-developer device groups using a device tag filter to reduce false positive volume on developer workstations.
- Add additional user-writable path fragments if non-standard staging directories are observed in the environment.
- Consider adding a SHA256 allowlist for known-good Python installers that legitimately execute from Downloads.

**Risks / caveats:**
- InitiatingProcessCommandLine may not be populated for all process events depending on MDE sensor configuration and Windows audit policy. If this field is empty, the path-based filter on the initiating process will not fire and the query will fall back to FolderPath matching only.
- Custom-renamed Python interpreters will not be detected by filename matching.
- Loaders installed to system paths will not be caught by the user-writable path filter.
- Environments without Python installed on endpoints will produce no results, which is a true negative rather than a detection gap.

### Triage Runbook

**First 15 minutes:**
- Inspect the initiating process command line and folder path to determine whether the loader executed from Temp, Downloads, AppData, ProgramData, or Public.
- Check whether the loader spawned python.exe/pythonw.exe and whether the parent-child chain matches a known installer, updater, or developer tool.
- Review the account context and device role to see if the endpoint is expected to run Python-based tooling.
- Look for immediate follow-on activity such as additional child processes, file drops, or outbound connections from the same host.

**Evidence to collect:**
- DeviceProcessEvents for the loader and spawned Python process.
- SHA256 for both the loader and Python interpreter if available.
- DeviceNetworkEvents for outbound connections from the host during and after execution.
- Any files created in the same directory as the loader or in adjacent user-writable paths.
- Device inventory or software inventory data to confirm whether the application is approved on the endpoint.

**Pivot points:**
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceTvmSoftwareInventory

**Benign explanations:**
- Legitimate software installers or updaters staged in Downloads or ProgramData.
- User-launched Python scripts from a downloaded package or lab environment.
- Automation tools or testing frameworks that stage temporary loaders in user-writable locations.
- Approved enterprise software that uses a bootstrapper before launching Python components.

**Escalation criteria:**
- The loader is unsigned, unknown, or not associated with an approved application and spawns Python from a user-writable path.
- The host shows additional suspicious child processes, file drops, or external network connections after the loader runs.
- The same loader hash or path appears on multiple endpoints.
- The endpoint is not a developer or test system and the behavior is inconsistent with its baseline.

**Containment actions:**
- Isolate the endpoint if the loader and Python chain is not explainable by approved software.
- Terminate the process tree and preserve the loader and any dropped files for analysis.
- Block the loader hash or path if confirmed malicious and distribute detections to other endpoints.
- Reset credentials if the host shows signs of credential theft or token access.

**Closure criteria:**
- The loader is confirmed as a legitimate installer, updater, or approved automation component.
- The Python spawn is expected for the application and no suspicious follow-on activity exists.
- File hashes, signer information, and endpoint role match a documented baseline.
- Any approved loader paths or hashes are added to tuning or allowlists.

<br/>
---
<br/>

## Detection 4: PsExec Spawning Suspicious Child Process Consistent with Meterpreter Staging over SMB

### Detection Opportunity

PsExec used to upgrade an existing SMB session to a Meterpreter shell by spawning unusual child processes on the target host

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026)
  - Context: A new Metasploit module uses PsExec to upgrade an existing authenticated SMB session to a Meterpreter shell. This creates a distinctive process chain where psexesvc.exe or psexec.exe spawns a child process that establishes an outbound connection consistent with Meterpreter staging.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1203, T1105
- Products: SMB, Meterpreter
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit, PsExec, Meterpreter
- Search tags: Metasploit, PsExec, Meterpreter, SMB, Windows, T1190, T1203, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1203 Exploitation for Client Execution (medium); Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let PsExecChildren = DeviceProcessEvents
| where Timestamp >= ago(1d)
| where InitiatingProcessFileName in~ ("psexec.exe", "psexesvc.exe", "psexec64.exe")
| where FileName !in~ ("conhost.exe", "csrss.exe", "werfault.exe")
| project
    DeviceName, AccountName,
    ChildProcess = FileName,
    ChildCommandLine = ProcessCommandLine,
    ChildPID = ProcessId,
    ChildSHA256 = SHA256,
    SpawnTime = Timestamp;
let OutboundConns = DeviceNetworkEvents
| where Timestamp >= ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (445, 139, 135, 3389)
| where not(
    RemoteIP startswith "10."
    or RemoteIP startswith "192.168."
    or (RemoteIP startswith "172." and
        split(RemoteIP, ".")[1] >= "16" and
        split(RemoteIP, ".")[1] <= "31")
    or RemoteIP == "127.0.0.1"
    or RemoteIP == "::1"
  )
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe", "MsMpEng.exe")
| project
    DeviceName,
    ConnProcess = InitiatingProcessFileName,
    ConnPID = InitiatingProcessId,
    RemoteIP, RemotePort,
    ConnTime = Timestamp;
PsExecChildren
| join kind=inner (
    OutboundConns
  ) on DeviceName
| where ConnTime between (SpawnTime .. (SpawnTime + 2m))
| where ConnPID == ChildPID or ConnProcess =~ ChildProcess
| project
    DeviceName, AccountName, SpawnTime,
    ChildProcess, ChildCommandLine, ChildSHA256,
    RemoteIP, RemotePort, ConnTime
| sort by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate PsExec-based remote administration where the spawned process makes an outbound connection to a monitoring or update service.
- Security scanning tools that use PsExec to deploy agents that phone home to internal-but-non-RFC1918 management infrastructure.
- PsExec used by software deployment systems that subsequently invoke processes making outbound connections.

**Tuning notes:**
- Add additional internal IP prefixes specific to the environment to the exclusion list.
- If legitimate PsExec-based admin tools spawn processes that make outbound connections, add those child process names to the exclusion list.
- Adjust the lookback window from 1d to a longer period for periodic hunting; 1d is appropriate for a scheduled rule running every 24 hours.
- Consider adding a SHA256 lookup against known Meterpreter stager hashes if threat intelligence integration is available.

**Risks / caveats:**
- DeviceNetworkEvents requires Microsoft Defender for Endpoint with network protection or advanced hunting enabled. Endpoints without MDE onboarding will not appear in this table.
- psexesvc.exe as an InitiatingProcessFileName in DeviceProcessEvents requires that the service execution context is captured by the MDE sensor on the target host, not just the source host running psexec.exe.
- The 172.16.0.0/12 range check using string comparison on the second octet is an approximation; environments with non-standard internal ranges should add explicit CIDR exclusions.
- Internal pivoting via Meterpreter to RFC1918 targets will not be detected by the external IP filter.

### Triage Runbook

**First 15 minutes:**
- Identify the source and target hosts and confirm whether the PsExec use was approved by IT or operations.
- Review the child process spawned by psexec.exe or psexesvc.exe and determine whether it is expected for remote administration.
- Check the outbound connection details for the child process, especially RemoteIP, RemotePort, and whether the destination is external or unusual for the host.
- Look for additional signs of lateral movement or post-exploitation activity on the target host, including new services, scheduled tasks, or credential access.

**Evidence to collect:**
- DeviceProcessEvents for the PsExec service and child process chain.
- DeviceNetworkEvents for outbound connections from the spawned child process.
- AccountName and DeviceName for both source and target systems.
- Child process command line and SHA256 for hash-based validation.
- Any service creation, remote execution, or logon events around the same time.

**Pivot points:**
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceLogonEvents
- DeviceServiceEvents

**Benign explanations:**
- Authorized remote administration using PsExec by IT or endpoint support teams.
- Software deployment or patching tools that use PsExec to run maintenance tasks.
- Security tooling or remote management agents that legitimately spawn child processes and connect to internal services.
- Administrative scripts that launch cmd.exe or similar processes for routine maintenance.

**Escalation criteria:**
- The child process is unusual for the environment or attempts an external connection not associated with approved management infrastructure.
- The source account or host is not authorized for PsExec use.
- There are signs of lateral movement, credential dumping, or additional remote execution on the target host.
- The same pattern appears across multiple hosts, suggesting active intrusion tooling.

**Containment actions:**
- Disable or restrict the source account if unauthorized PsExec use is confirmed.
- Isolate the target host if the spawned process or network activity indicates active compromise.
- Block the external RemoteIP if it is clearly malicious and not shared by legitimate services.
- Preserve process, network, and service-creation evidence before remediation when possible.

**Closure criteria:**
- PsExec use is confirmed as authorized and the child process/network behavior matches the approved admin workflow.
- No suspicious external connections or follow-on activity are found.
- The source account, source host, and target host are documented as legitimate for remote administration.
- Any approved PsExec child processes or management destinations are added to tuning guidance.

<br/>
---
<br/>

## Detection 5: Peyara Remote Mouse Process Spawning Unexpected Child or Making Outbound Connection

### Detection Opportunity

Unauthenticated RCE against Peyara Remote Mouse 1.0.1 resulting in unexpected child process execution or outbound network connection from the application process

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026)
  - Context: A Metasploit module was released exploiting an unauthenticated RCE vulnerability in Peyara Remote Mouse 1.0.1. Successful exploitation would result in the Peyara process spawning an unexpected child process or making an outbound connection to attacker infrastructure as part of Meterpreter or shell staging.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1203, T1105
- Products: Peyara Remote Mouse 1.0.1
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: Peyara Remote Mouse 1.0.1, Metasploit, Windows, T1190, T1203, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1203 Exploitation for Client Execution (medium); Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- DeviceTvmSoftwareInventory requires Microsoft Defender Vulnerability Management licensing. If unavailable, remove the PeyaraDevices scoping step and accept broader scope.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let PeyaraProcessName = "RemoteMouse.exe";
let PeyaraDevices = DeviceTvmSoftwareInventory
| where SoftwareName has_any ("Remote Mouse", "Peyara")
| distinct DeviceName;
let PeyaraChildren = DeviceProcessEvents
| where Timestamp >= ago(7d)
| where DeviceName in (PeyaraDevices)
| where InitiatingProcessFileName =~ PeyaraProcessName
| project
    Timestamp, DeviceName,
    EventType = "ChildProcess",
    Detail = strcat(FileName, " | ", ProcessCommandLine),
    ChildSHA256 = SHA256;
let PeyaraConns = DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where DeviceName in (PeyaraDevices)
| where InitiatingProcessFileName =~ PeyaraProcessName
| where ActionType == "ConnectionSuccess"
| where not(
    RemoteIP startswith "10."
    or RemoteIP startswith "192.168."
    or (RemoteIP startswith "172." and
        split(RemoteIP, ".")[1] >= "16" and
        split(RemoteIP, ".")[1] <= "31")
    or RemoteIP == "127.0.0.1"
    or RemoteIP == "::1"
  )
| project
    Timestamp, DeviceName,
    EventType = "OutboundConnection",
    Detail = strcat(RemoteIP, ":", tostring(RemotePort)),
    ChildSHA256 = "";
union PeyaraChildren, PeyaraConns
| project Timestamp, DeviceName, EventType, Detail, ChildSHA256
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate outbound connections from Peyara Remote Mouse to its own update or telemetry infrastructure if the application makes such connections by design.
- False negatives if the executable name does not match RemoteMouse.exe.

**Tuning notes:**
- Before deploying, run: DeviceProcessEvents → where FileName has_any('mouse','peyara') → summarize count() by FileName, FolderPath to confirm the correct executable name.
- If DeviceTvmSoftwareInventory is not available, replace the PeyaraDevices scoping step with a static device list or remove the scope filter entirely.
- Add known Peyara update or telemetry IP ranges to the RFC1918 exclusion block once confirmed from vendor documentation.

**Risks / caveats:**
- The Peyara Remote Mouse executable name 'RemoteMouse.exe' is an assumption and has not been confirmed from endpoint inventory or vendor documentation. If the actual binary name differs, the query will produce no results and provide false assurance.
- Peyara Remote Mouse has low deployment prevalence. Before running this query, confirm the application is present in the environment by searching DeviceProcessEvents or DeviceTvmSoftwareInventory for the application name.
- The executable name 'RemoteMouse.exe' must be confirmed from endpoint inventory before this query can be trusted to produce meaningful results. If the name is wrong, the query will silently return no results.
- DeviceTvmSoftwareInventory requires Microsoft Defender Vulnerability Management licensing. If unavailable, remove the PeyaraDevices scoping step and accept broader scope.

### Triage Runbook

**First 15 minutes:**
- Confirm that Peyara Remote Mouse is actually installed on the endpoint and that the executable name matches the environment.
- Review whether the application spawned any child process or made an outbound connection that is not part of its normal behavior.
- Check the device role and user context to see whether the host is a workstation, support machine, or a low-prevalence application host.
- Look for evidence of exploitation such as unexpected command shells, scripting interpreters, or connections to unfamiliar external IPs.

**Evidence to collect:**
- DeviceProcessEvents for the Peyara process and any child processes.
- DeviceNetworkEvents for outbound connections from the application process.
- DeviceTvmSoftwareInventory or endpoint inventory confirming installation and version.
- SHA256 for the application binary and any spawned child process.
- Any crash, service restart, or exploit-like logon activity around the same time.

**Pivot points:**
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceTvmSoftwareInventory
- DeviceLogonEvents

**Benign explanations:**
- Legitimate application startup or update behavior if the vendor is known to make outbound connections.
- Support or remote-assistance workflows that intentionally use the application on a small set of hosts.
- False positives caused by an incorrect executable name assumption or by a different binary name in the environment.
- Rare but legitimate child processes created by the application during normal operation, if documented by the vendor.

**Escalation criteria:**
- The application is confirmed installed and the process spawns an unexpected shell, scripting interpreter, or other suspicious child.
- The process makes an external connection to an unfamiliar IP or host immediately after startup or user interaction.
- The endpoint is not expected to run Peyara Remote Mouse, or the binary name does not match the approved inventory.
- Multiple hosts show the same pattern, indicating possible exploitation at scale.

**Containment actions:**
- Isolate the host if the application is confirmed exploited or is making suspicious outbound connections.
- Terminate the application process and any spawned child processes if compromise is likely.
- Block the external destination if it is clearly malicious and not part of approved vendor infrastructure.
- Remove or disable the vulnerable application after evidence collection if the environment does not require it.

**Closure criteria:**
- The executable name and installed application are confirmed and the observed behavior matches documented normal operation.
- No suspicious child processes, shells, or external connections are found.
- The host is not exposed to the vulnerable application or the application is removed from the environment.
- Any confirmed benign process names or vendor destinations are added to tuning or allowlists.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Device Code Flow OAuth Authentication with Anomalous Context: Do not schedule yet; validate as an analyst-led hunt first.
- Python Stealer Execution from Suspicious Parent Process or User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.
- Peyara Remote Mouse Process Spawning Unexpected Child or Making Outbound Connection: DeviceTvmSoftwareInventory requires Microsoft Defender Vulnerability Management licensing. If unavailable, remove the PeyaraDevices scoping step and accept broader scope.

**Other deployment dependency:**
- Python Stealer Execution from Suspicious Parent Process or User-Writable Path: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceProcessEvents: shared by Python Stealer Execution from Suspicious Parent Process or User-Writable Path; Loader Executing from User-Writable Path Spawning Python Interpreter; PsExec Spawning Suspicious Child Process Consistent with Meterpreter Staging over SMB; Peyara Remote Mouse Process Spawning Unexpected Child or Making Outbound Connection
- DeviceNetworkEvents: shared by PsExec Spawning Suspicious Child Process Consistent with Meterpreter Staging over SMB; Peyara Remote Mouse Process Spawning Unexpected Child or Making Outbound Connection

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Loader Executing from User-Writable Path Spawning Python Interpreter; PsExec Spawning Suspicious Child Process Consistent with Meterpreter Staging over SMB.
2. Resolve environment-mapping detections next: Peyara Remote Mouse Process Spawning Unexpected Child or Making Outbound Connection.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Device Code Flow OAuth Authentication with Anomalous Context; Python Stealer Execution from Suspicious Parent Process or User-Writable Path.

### Hunting Agenda and Promotion Criteria

- Device Code Flow OAuth Authentication with Anomalous Context: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Python Stealer Execution from Suspicious Parent Process or User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Peyara Remote Mouse Process Spawning Unexpected Child or Making Outbound Connection: DeviceTvmSoftwareInventory requires Microsoft Defender Vulnerability Management licensing. If unavailable, remove the PeyaraDevices scoping step and accept broader scope.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
