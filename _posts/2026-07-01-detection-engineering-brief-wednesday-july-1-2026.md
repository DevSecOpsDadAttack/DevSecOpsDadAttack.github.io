---
layout: post
title: "Detection Engineering Brief - Wednesday, July 1, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-01
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - ScreenConnect
  - Windows
  - AsyncRAT
  - ToddyCat
  - Gmail
  - Google services
  - Google Workspace
  - Umbrij
  - T1036
  - T1106
  - T1547
  - T1078
  - T1078.004
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 2 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: ScreenConnect, Windows, AsyncRAT, ToddyCat, Gmail, Google services, Google Workspace, Umbrij, T1036, T1106, T1547, T1078, T1078.004.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: AsyncRAT C2 Outbound Connections from ScreenConnect-Related Processes; Trojanized ScreenConnect Installer Dropping Executables to User-Writable Paths; OAuth Token Grant to Unfamiliar Application Followed by Google Workspace Resource Access; OAuth Token Use from New Geographic Location for Google Workspace Access.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

---

## Detection 1: ScreenConnect Spawning Suspicious Child Processes

### Detection Opportunity

Compromised ScreenConnect software spawns child processes consistent with AsyncRAT payload delivery.

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: Trojanized ScreenConnect software was used to drop AsyncRAT. The reporting explicitly identifies ScreenConnect as the delivery mechanism, making parent-child process relationships the primary detection surface.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1036, T1106, T1547
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, Windows, AsyncRAT, T1036, T1106, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: defense-evasion: T1036 Masquerading (medium); execution: T1106 Native API (low); persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "connectwisecontrol.clientservice.exe"
)
| where tolower(FileName) in (
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe"
)
or FolderPath has_any (
    "\\AppData\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\"
)
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "connectwisecontrol.clientservice.exe"
)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    FileName,
    ProcessCommandLine,
    ProcessId,
    FolderPath,
    SHA256
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate ScreenConnect sessions where a support technician launches cmd.exe or powershell.exe interactively during a remote support session.
- Managed software deployment tools that use ScreenConnect as a delivery channel and write to ProgramData as part of normal operation.
- Custom-branded ConnectWise deployments using executable names not covered by the parent filter.

Tuning notes:
- Query the environment for all distinct InitiatingProcessFileName values associated with ScreenConnect before enabling to identify any custom-branded executable names.
- Build an allowlist of AccountName values for known IT support personnel who legitimately use ScreenConnect to launch shells, and exclude them with a not(AccountName in (allowlist)) filter.
- If ProgramData writes are common in the environment for legitimate software deployment, narrow the FolderPath match to AppData and Users\Public only.

Risks / caveats:
- Defender for Endpoint agent must be deployed and process creation telemetry enabled on monitored endpoints; endpoints without MDE coverage will produce no results.
- Custom-branded ScreenConnect deployments using non-standard executable names will not be caught by the parent filter; enumerate environment-specific names and add them to the InitiatingProcessFileName list.
- Legitimate remote support sessions where technicians interactively launch cmd.exe or powershell.exe will generate alerts; consider adding an AccountName exclusion list for known support accounts.
- The 7-day lookback window may produce high initial volume; consider reducing to 1d for scheduled rule cadence and relying on continuous scheduling for coverage.

### Triage Runbook

First 15 minutes:
- Confirm the parent process is a ScreenConnect/ConnectWise Control binary and note the exact child process name, command line, and user context.
- Check whether the alert aligns with an active helpdesk or remote support session and identify the technician account involved.
- Review the process tree around the child process for follow-on activity such as PowerShell, cmd, script hosts, LOLBINs, or additional payloads.
- Inspect the child process hash and folder path for execution from user-writable locations or temporary directories.
- If the child process is not expected for the support session, treat the host as potentially compromised and begin incident escalation.

Evidence to collect:
- Parent and child process names, command lines, process IDs, timestamps, and SHA256 hashes.
- User account and domain associated with the ScreenConnect session and the spawned process.
- Process tree showing any subsequent child processes or repeated launches from the same parent.
- Any files written to AppData, Temp, Public, or ProgramData around the alert time.
- ScreenConnect session logs or remote support ticket references for the same time window.

Pivot points:
- DeviceProcessEvents for the same DeviceId and time window to expand the process tree.
- DeviceFileEvents to identify dropped payloads or staging artifacts.
- DeviceNetworkEvents to see whether the spawned process made outbound connections.
- ScreenConnect administrative logs or ticketing records to validate whether the activity was authorized.
- DeviceLogonEvents or related identity logs to confirm who was logged on during the session.

Benign explanations:
- A legitimate support technician used ScreenConnect to open cmd.exe or PowerShell during troubleshooting.
- A managed software deployment or update workflow used ScreenConnect as a delivery channel.
- A custom-branded ScreenConnect deployment uses executable names not covered by the parent filter, causing unusual but authorized child process launches.

Escalation criteria:
- The child process is a scripting host, LOLBIN, or downloader and is not explained by the support ticket.
- The spawned process executes from a user-writable path or drops additional files.
- There is evidence of follow-on persistence, credential access, or outbound command-and-control activity.
- The ScreenConnect session is unauthorized, unexpected, or associated with a suspicious user account.
- Multiple hosts show the same ScreenConnect-to-child-process pattern within a short period.

Containment actions:
- Isolate the host from the network if the child process is unapproved or clearly malicious.
- Disable or suspend the associated ScreenConnect account or technician access if abuse is suspected.
- Terminate the suspicious process tree and preserve volatile evidence before rebooting.
- Block the dropped file hash and any related child process hashes if confirmed malicious.
- Reset credentials for the affected user and any support accounts used in the session if compromise is likely.

Closure criteria:
- The spawned process is confirmed as part of an approved support activity and no additional suspicious behavior is present.
- No malicious file writes, network connections, or persistence artifacts are found after process-tree review.
- The ScreenConnect session is validated against a legitimate ticket and the account is known and approved.
- Any suspicious hashes or paths are added to allowlists or detections as appropriate after validation.

---

## Detection 2: AsyncRAT C2 Outbound Connections from ScreenConnect-Related Processes

### Detection Opportunity

AsyncRAT establishes outbound C2 connections on characteristic ports from processes spawned by or associated with ScreenConnect.

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: The campaign used malicious C2 infrastructure to support AsyncRAT delivery via ScreenConnect. AsyncRAT is known to use ports 6606, 7707, and 8808 for C2 communications. Correlating network connections on these ports with ScreenConnect-associated processes provides a compound behavioral signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1036, T1106, T1547
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, Windows, AsyncRAT, T1036, T1106, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: defense-evasion: T1036 Masquerading (medium); execution: T1106 Native API (low); persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Defender for Endpoint network telemetry must be enabled; endpoints with network inspection disabled will produce no DeviceNetworkEvents rows.

Required telemetry:
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let ScreenConnectParents = DeviceProcessEvents
| where Timestamp > ago(1d)
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "connectwisecontrol.clientservice.exe"
)
| project
    DeviceId,
    SpawnedProcess = FileName,
    SpawnedProcessId = ProcessId,
    SpawnedProcessCommandLine = ProcessCommandLine,
    SpawnedProcessSHA256 = SHA256,
    AccountName,
    AccountDomain,
    SpawnTime = Timestamp;
let DirectScreenConnectC2 = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (6606, 7707, 8808)
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "connectwisecontrol.clientservice.exe"
)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    RemoteIP,
    RemotePort,
    LocalIP,
    ActionType,
    SpawnedProcess = InitiatingProcessFileName,
    SpawnedProcessCommandLine = InitiatingProcessCommandLine,
    SpawnedProcessSHA256 = "",
    AccountName = InitiatingProcessAccountName,
    AccountDomain = InitiatingProcessAccountDomain;
let ChildProcessC2 = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (6606, 7707, 8808)
| join kind=inner ScreenConnectParents
    on DeviceId,
    $left.InitiatingProcessId == $right.SpawnedProcessId
| project
    Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    RemoteIP,
    RemotePort,
    LocalIP,
    ActionType,
    SpawnedProcess,
    SpawnedProcessCommandLine,
    SpawnedProcessSHA256,
    AccountName,
    AccountDomain;
union DirectScreenConnectC2, ChildProcessC2
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Any legitimate application in the environment that happens to use ports 6606, 7707, or 8808 for non-malicious purposes.
- Security testing tools or red team infrastructure using AsyncRAT default ports.

Tuning notes:
- Run DeviceNetworkEvents | where RemotePort in (6606, 7707, 8808) | summarize count() by InitiatingProcessFileName, DeviceName to baseline port usage before scheduling.
- If dwell time between ScreenConnect installation and C2 callback exceeds 1 day in observed incidents, extend both let block lookbacks to 7d.
- Consider promoting to a scheduled rule once port baseline confirms no legitimate traffic on these ports in the environment.

Risks / caveats:
- DeviceNetworkEvents ActionType value 'ConnectionSuccess' must be confirmed in the target tenant; some MDE configurations surface 'NetworkConnectionEvents' with different ActionType values depending on agent version.
- Defender for Endpoint network telemetry must be enabled; endpoints with network inspection disabled will produce no DeviceNetworkEvents rows.
- ProcessId values can be reused by the OS within the 1-day window; a spawned ProcessId may be reassigned to an unrelated process before the network event occurs, causing a false join match in rare cases.
- The 1-day lookback window may miss campaigns with longer dwell time between ScreenConnect installation and AsyncRAT C2 callback; extend to 7d for broader hunting coverage at the cost of increased join volume.

### Triage Runbook

First 15 minutes:
- Verify the remote IP, remote port, and initiating process ID to confirm the network event belongs to the suspicious process instance.
- Check whether the connection is on one of the characteristic ports and whether the process is a ScreenConnect binary or a child process spawned by it.
- Review the process command line and hash for signs of payload execution, staging, or encoded commands.
- Look for repeated connections, short periodic beacons, or multiple destinations from the same process.
- If the connection is not attributable to an approved support workflow, escalate immediately as likely malware C2.

Evidence to collect:
- Remote IP, remote port, local IP, action type, timestamp, and initiating process details.
- Spawned process name, command line, SHA256, and process ID linked to the network event.
- Any preceding ScreenConnect process activity on the same host within the last day.
- Firewall, proxy, or DNS logs showing whether the destination is newly seen or repeatedly contacted.
- User and device context for the session, including account name and domain.

Pivot points:
- DeviceNetworkEvents for the same DeviceId to identify all connections from the process and related processes.
- DeviceProcessEvents to reconstruct the parent-child chain leading to the network activity.
- DeviceFileEvents to find dropped payloads or supporting files.
- DNS or proxy telemetry to determine whether the destination domain or IP is associated with other hosts.
- Threat intelligence or internal blocklists for the remote IP and port usage pattern.

Benign explanations:
- A legitimate application or test tool in the environment happens to use one of the same ports.
- A support technician launched a tool through ScreenConnect that made outbound connections during troubleshooting.
- A red team or security validation exercise intentionally used AsyncRAT-like ports and behavior.

Escalation criteria:
- The process is not part of an approved support session and the destination is external or suspicious.
- The same host shows repeated beaconing or multiple suspicious child processes.
- The remote IP is unknown, newly registered, or associated with other malicious activity.
- Additional indicators appear, such as persistence, credential theft, or lateral movement.
- Multiple endpoints show the same port-and-process pattern, suggesting a broader campaign.

Containment actions:
- Isolate the endpoint from the network if C2 is confirmed or strongly suspected.
- Block the remote IPs and ports at the firewall or proxy if they are not business-critical.
- Terminate the suspicious process and any related child processes after preserving evidence.
- Disable ScreenConnect access for the affected account until the session is validated.
- Collect memory and disk artifacts before remediation if the host is likely to contain additional payloads.

Closure criteria:
- The network connection is validated as benign support or approved testing activity.
- No additional suspicious process, file, or persistence activity is found on the host.
- The destination and port are confirmed to be non-malicious and documented in the environment baseline.
- Any confirmed malicious indicators are blocked and the host is remediated or rebuilt.

---

## Detection 3: Trojanized ScreenConnect Installer Dropping Executables to User-Writable Paths

### Detection Opportunity

Trojanized ScreenConnect installer writes executable files to temporary or user-writable directories during installation.

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: The trojanized ScreenConnect installer drops AsyncRAT to disk during the installation process. File creation events from ScreenConnect installer processes writing executables to AppData, Temp, or Public directories are anomalous relative to legitimate ScreenConnect installation behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1036, T1106, T1547
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, Windows, AsyncRAT, T1036, T1106, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: defense-evasion: T1036 Masquerading (medium); execution: T1106 Native API (low); persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "connectwisecontrol.clientservice.exe"
)
| where FolderPath has_any (
    "\\AppData\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\",
    "\\Windows\\Temp\\"
)
| where tolower(FileName) has_any (".exe", ".dll", ".bat", ".ps1")
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    FileName,
    FolderPath,
    SHA256
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate ScreenConnect service writing temporary files to ProgramData as part of update or plugin workflows.
- Other software using ScreenConnect as a delivery channel that legitimately writes to AppData during installation.

Tuning notes:
- Run DeviceFileEvents | where InitiatingProcessFileName has 'ScreenConnect' | summarize count() by FolderPath to baseline legitimate ScreenConnect file write paths before enabling as a scheduled rule.
- If the environment uses custom-branded ScreenConnect executables, add those names to the InitiatingProcessFileName filter.
- For active incident response, extend the query with setup.exe and installer.exe as additional parent names and narrow the time window to the suspected compromise period.

Risks / caveats:
- DeviceFileEvents requires Defender for Endpoint file creation telemetry to be enabled; environments with file monitoring disabled will produce no results.
- Legitimate ScreenConnect update or plugin mechanisms may write DLL or EXE files to ProgramData as part of normal operation; baseline ScreenConnect file write behavior in the environment before scheduling.
- The query does not cover the scenario where the trojanized installer runs under a generic setup.exe name; analysts should run a separate ad-hoc query with setup.exe and installer.exe as parents during active incident investigation.
- SHA256 values from results should be submitted to threat intelligence platforms to confirm malicious classification before escalating.

### Triage Runbook

First 15 minutes:
- Confirm the initiating process is a ScreenConnect-related binary and note the exact file names and paths created.
- Check whether the dropped files are executable, script, or DLL content and whether they were written to Temp, AppData, Public, or ProgramData.
- Review the file hashes and compare them against known-good software deployment artifacts or internal package repositories.
- Look for immediate execution of the dropped files or follow-on process creation from the same directory.
- If the files are unexpected or the installer source is untrusted, escalate as probable trojanized installer activity.

Evidence to collect:
- Created file names, folder paths, SHA256 hashes, timestamps, and the initiating process command line.
- Parent process ID and user context for the installer execution.
- Any subsequent process launches from the same folder or by the same user.
- Installer source details such as download origin, ticket reference, or software distribution method.
- Related file creation events on the same host during the same time window.

Pivot points:
- DeviceFileEvents to identify all files created by the same initiating process.
- DeviceProcessEvents to see whether the dropped files were executed.
- DeviceNetworkEvents to determine whether the installer or dropped payload contacted external infrastructure.
- Software deployment or package management logs to validate whether the write activity was expected.
- Threat intelligence or internal hash reputation sources for the dropped files.

Benign explanations:
- A legitimate ScreenConnect update or plugin installation wrote temporary executables or DLLs during installation.
- An approved software deployment used ScreenConnect as a delivery mechanism and staged files in ProgramData or AppData.
- A custom-branded ScreenConnect deployment wrote files under a different but legitimate process name, making the activity appear unusual.

Escalation criteria:
- The dropped files are unsigned, unknown, or match malware-like naming patterns.
- The files are executed shortly after creation or spawn additional suspicious processes.
- The installer source is untrusted, user-downloaded, or not tied to an approved deployment.
- The same behavior occurs on multiple endpoints or is accompanied by network beaconing.
- The file hashes are confirmed malicious or associated with prior incidents.

Containment actions:
- Isolate the host if the dropped files are suspicious or have already executed.
- Quarantine or delete the dropped files after preserving copies for analysis.
- Block the file hashes in endpoint protection if confirmed malicious.
- Suspend the ScreenConnect account or deployment channel used to deliver the installer until validated.
- Reimage the host if execution or persistence is confirmed and trust cannot be restored.

Closure criteria:
- The file writes are matched to an approved installer or update workflow.
- The dropped files are benign, signed, and consistent with known-good package behavior.
- No execution, persistence, or outbound communication is observed from the created files.
- Any suspicious artifacts are collected, blocked, and documented for future allowlisting or detection tuning.

---

## Detection 4: OAuth Token Grant to Unfamiliar Application Followed by Google Workspace Resource Access

### Detection Opportunity

OAuth authorization tokens are stolen or abused to gain unauthorized access to Google Workspace services, consistent with ToddyCat Umbrij tooling.

### Intelligence Context

- Securelist: ToddyCat: your hidden email assistant. Part 2 — [https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/](https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/)
  - Context: ToddyCat used the Umbrij tool to compromise corporate Gmail accounts by targeting OAuth authorization tokens. The attack chain involves OAuth token issuance to an unauthorized application followed by access to Google Workspace services. Detection focuses on OAuth consent grants to applications not previously seen in the tenant, correlated with subsequent resource access.

### Search Metadata

- CVEs: Not specified
- Threat actors: ToddyCat
- ATT&CK tags: T1078, T1078.004, T1036
- Products: Gmail, Google services, Google Workspace
- Platforms: Not specified
- Malware: Not specified
- Tools: Umbrij
- Search tags: ToddyCat, Gmail, Google services, Google Workspace, Umbrij, T1078, T1078.004, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: valid-accounts: T1078 Valid Accounts/ T1078.004 Cloud Accounts (high); defense-evasion: T1036 Masquerading (low)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

Required telemetry:
- AuditLogs, SigninLogs

### KQL

```kql
let lookback = 30d;
let alertWindow = 1d;
let newAppConsents = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any ("Consent to application", "Add OAuth2PermissionGrant")
| extend UPN = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| where isnotempty(UPN) and isnotempty(AppName)
| summarize FirstConsent = min(TimeGenerated) by UPN, AppName
| where FirstConsent > ago(alertWindow);
SigninLogs
| where TimeGenerated > ago(alertWindow)
| where ResultType == 0
| where AppDisplayName has_any ("Google", "Gmail", "Google Workspace", "Google APIs")
    or ResourceDisplayName has_any ("Google", "Gmail", "Google Workspace")
| join kind=inner newAppConsents
    on $left.UserPrincipalName == $right.UPN
| extend RiskSignal = case(
    RiskLevelDuringSignIn in ("medium", "high"), "ElevatedRisk",
    ConditionalAccessStatus == "failure", "CAFailure",
    "NoRiskSignal"
)
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    AppName,
    ResourceDisplayName,
    IPAddress,
    Location,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    RiskSignal,
    CorrelationId
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate new OAuth application deployments rolled out to users for the first time will trigger the novelty check.
- Users signing in to a newly registered Google Workspace application from a new location for legitimate business travel.
- Automated service accounts that periodically re-consent to OAuth applications as part of token refresh workflows.

Tuning notes:
- Before enabling, run AuditLogs | where OperationName has 'Consent to application' | summarize count() by OperationName to confirm consent events are present in the tenant.
- Run SigninLogs | where AppDisplayName has 'Google' | summarize count() by AppDisplayName to identify the exact application registration names used in the tenant and update the filter accordingly.
- Add a not(UserPrincipalName in (service_account_list)) exclusion for known automated service accounts that perform OAuth re-consent as part of normal workflows.
- If Entra ID Protection P2 is not available, consider removing the RiskLevelDuringSignIn filter and relying solely on the consent novelty signal, accepting higher false positive volume.

Risks / caveats:
- Google Workspace OAuth consent events will only appear in AuditLogs if the tenant has federated Google Workspace identity with Entra ID and the Microsoft Entra ID connector is configured to ingest these events; without this, the newAppConsents subquery returns zero rows.
- RiskLevelDuringSignIn and ConditionalAccessStatus are only populated with Entra ID Protection P2 licensing; without P2, the final where clause eliminates all results and the query produces no alerts.
- AppDisplayName values for Google Workspace applications in SigninLogs depend on how the OAuth application is registered in the tenant; the filter strings 'Google', 'Gmail', 'Google Workspace', 'Google APIs' may not match actual registration names in all tenants.
- In tenants without Entra ID Protection P2, RiskLevelDuringSignIn will be empty for all rows; the RiskSignal column will show 'NoRiskSignal' for all results, increasing analyst triage burden.

### Triage Runbook

First 15 minutes:
- Identify the user who granted consent, the application name, and whether the app is expected in the tenant.
- Check whether the same user subsequently accessed Google Workspace resources from the same or a related IP address.
- Review sign-in risk, conditional access outcome, and any unusual location or device context associated with the access.
- Confirm whether the consent was user-initiated, admin-initiated, or part of a sanctioned application rollout.
- If the app is unfamiliar or the access is unexpected, escalate as likely cloud account compromise.

Evidence to collect:
- UserPrincipalName, AppDisplayName, ResourceDisplayName, IPAddress, location, risk level, and conditional access status.
- Consent event details including operation name, initiator, target resource, and correlation ID.
- Any subsequent Google Workspace sign-ins or resource accesses by the same account.
- Tenant records showing whether the application is approved, newly deployed, or previously seen.
- Identity protection and audit logs for the same user around the alert time.

Pivot points:
- AuditLogs to inspect the consent grant and application registration details.
- SigninLogs to trace subsequent access to Google Workspace services.
- Entra ID application and service principal records to validate whether the app is sanctioned.
- Mailbox or Google Workspace audit logs, if available, to identify accessed resources.
- Identity protection logs for additional risk signals or repeated anomalous sign-ins.

Benign explanations:
- A legitimate new Google Workspace application was rolled out and users consented for the first time.
- An administrator granted consent for a sanctioned business application.
- A service account or automation workflow re-consented as part of normal token refresh or app maintenance.

Escalation criteria:
- The application is not approved and the user did not expect to grant consent.
- The same account shows suspicious resource access immediately after consent.
- Risk signals, conditional access failures, or unusual locations accompany the access.
- Multiple users consent to the same unfamiliar application in a short period.
- The app requests excessive or unusual permissions relative to its business purpose.

Containment actions:
- Revoke the OAuth consent or disable the service principal if the app is unauthorized.
- Reset the affected user’s credentials and revoke active sessions or refresh tokens.
- Block the application tenant-wide if it is confirmed malicious or broadly abused.
- Notify the Google Workspace or identity administration team to review mailbox and resource access.
- Increase monitoring for the affected account and related users until scope is understood.

Closure criteria:
- The application is verified as approved and the consent is documented as legitimate.
- Subsequent Google Workspace access is consistent with the user’s normal behavior and business need.
- No additional suspicious sign-ins, risky sessions, or unauthorized resource access are found.
- Any unauthorized consent is revoked and the account is remediated or monitored per incident procedure.

---

## Detection 5: OAuth Token Use from New Geographic Location for Google Workspace Access

### Detection Opportunity

Threat actor accesses Google Workspace services using stolen OAuth tokens from anomalous locations not previously associated with the user account.

### Intelligence Context

- Securelist: ToddyCat: your hidden email assistant. Part 2 — [https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/](https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/)
  - Context: ToddyCat used stolen OAuth tokens to access Google services. The reporting indicates the threat actor accessed Google Workspace from locations and devices inconsistent with the legitimate user's baseline. This detection correlates first-seen country access to Google Workspace applications with elevated sign-in risk, providing a compound signal beyond a standalone location anomaly.

### Search Metadata

- CVEs: Not specified
- Threat actors: ToddyCat
- ATT&CK tags: T1078, T1078.004, T1036
- Products: Gmail, Google services, Google Workspace
- Platforms: Not specified
- Malware: Not specified
- Tools: Umbrij
- Search tags: ToddyCat, Gmail, Google services, Google Workspace, Umbrij, T1078, T1078.004, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: valid-accounts: T1078 Valid Accounts/ T1078.004 Cloud Accounts (high); defense-evasion: T1036 Masquerading (low)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

Required telemetry:
- SigninLogs

### KQL

```kql
let baselineStart = ago(30d);
let baselineEnd = ago(1d);
let alertWindow = 1d;
let baseline = SigninLogs
| where TimeGenerated between (baselineStart .. baselineEnd)
| where AppDisplayName has_any ("Google", "Gmail", "Google Workspace")
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize BaselineCountries = make_set(Country) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(alertWindow)
| where AppDisplayName has_any ("Google", "Gmail", "Google Workspace")
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| join kind=inner baseline on UserPrincipalName
| where not(Country in (BaselineCountries))
| extend RiskSignal = case(
    RiskLevelDuringSignIn in ("medium", "high"), "ElevatedRisk",
    ConditionalAccessStatus == "failure", "CAFailure",
    "NoRiskSignal"
)
| where RiskLevelDuringSignIn in ("medium", "high")
    or ConditionalAccessStatus == "failure"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country,
    BaselineCountries,
    AppDisplayName,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    RiskSignal,
    DeviceDetail,
    CorrelationId
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Users traveling to countries not visited in the prior 30 days for legitimate business purposes.
- Users accessing Google Workspace via VPN exit nodes in countries not in their baseline.
- New employees or accounts with less than 30 days of sign-in history will have empty baselines and may generate alerts on first access from any country.

Tuning notes:
- Run SigninLogs | where AppDisplayName has 'Google' | summarize count() by AppDisplayName to confirm Google Workspace sign-in events are present and to identify exact AppDisplayName values before scheduling.
- Run the baseline subquery independently and review BaselineCountries distributions to identify users with unusually broad or narrow baselines before enabling.
- If Entra ID Protection P2 is not available, remove the RiskLevelDuringSignIn and ConditionalAccessStatus filters and add analyst review as a compensating control for the increased false positive volume.
- Add a not(UserPrincipalName in (known_traveler_list)) exclusion for users with documented frequent international travel patterns.

Risks / caveats:
- Google Workspace sign-in events will only appear in SigninLogs if the tenant has federated Google Workspace identity with Entra ID; without federation, both the baseline and alert subqueries return zero rows.
- RiskLevelDuringSignIn is only populated with Entra ID Protection P2 licensing; without P2, the risk filter eliminates all results and the query produces no output.
- LocationDetails.countryOrRegion is a dynamic nested field; if the field path changes across Sentinel schema versions, the tostring() extraction will return empty strings and the baseline will not function correctly.
- In tenants without Entra ID Protection P2, RiskLevelDuringSignIn will be empty for all rows and the final where clause will eliminate all results; remove the risk filter and rely solely on the new-country signal if P2 is not available, accepting higher false positive volume.

### Triage Runbook

First 15 minutes:
- Identify the user, source IP, country, device detail, and whether the location is new relative to the user’s baseline.
- Check whether the sign-in was successful, risky, or blocked by conditional access.
- Compare the access time with the user’s work schedule, travel status, and recent helpdesk or identity events.
- Review whether the same account has recent consent grants, password resets, MFA changes, or token revocations.
- If the location is not explainable by travel or VPN use, escalate as likely token abuse or account compromise.

Evidence to collect:
- UserPrincipalName, IPAddress, country, device detail, risk level, conditional access status, and correlation ID.
- Baseline countries for the account and any prior sign-ins from the same IP or region.
- Recent identity events such as password changes, MFA resets, consent grants, or session revocations.
- Google Workspace resource access history immediately before and after the alert.
- Any VPN, proxy, or remote access logs that could explain the apparent country change.

Pivot points:
- SigninLogs to review the full sign-in history for the account and nearby time window.
- AuditLogs to check for recent OAuth consent or application changes.
- Identity Protection logs for risk events tied to the same user or IP.
- VPN or proxy telemetry to determine whether the country is an exit node rather than the true origin.
- Google Workspace audit logs, if available, to identify accessed mailboxes or files.

Benign explanations:
- The user is traveling or working remotely from a new country.
- The user is connecting through a corporate VPN or cloud proxy that exits in a different country.
- The account is new or has limited history, making the baseline incomplete or misleading.

Escalation criteria:
- The country is not explainable by travel, VPN, or known business operations.
- The sign-in is accompanied by elevated risk, conditional access failure, or repeated suspicious attempts.
- The account shows recent consent grants, token activity, or other signs of cloud account abuse.
- The same IP or country is used to access multiple accounts unexpectedly.
- The user denies the activity and no legitimate explanation is found.

Containment actions:
- Revoke active sessions and refresh tokens for the affected account if compromise is suspected.
- Force password reset and MFA revalidation if the account is at risk.
- Block or challenge the source IP or country only if it is not a business-required access path.
- Coordinate with identity administrators to review OAuth grants and mailbox access.
- Escalate to incident response if multiple accounts or repeated suspicious geolocations are involved.

Closure criteria:
- The location is confirmed as legitimate travel, VPN, or approved remote access.
- No additional suspicious sign-ins, token abuse, or resource access is observed.
- Identity and audit logs support a benign explanation and the user confirms the activity.
- Any unauthorized sessions are revoked and the account is returned to normal monitoring.

---

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- AsyncRAT C2 Outbound Connections from ScreenConnect-Related Processes: Do not schedule yet; validate as an analyst-led hunt first.
- Trojanized ScreenConnect Installer Dropping Executables to User-Writable Paths: Do not schedule yet; validate as an analyst-led hunt first.

Telemetry availability:
- AsyncRAT C2 Outbound Connections from ScreenConnect-Related Processes: Defender for Endpoint network telemetry must be enabled; endpoints with network inspection disabled will produce no DeviceNetworkEvents rows.

Licensing / identity risk fields:
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

Shared-table notes:
- DeviceProcessEvents: shared by ScreenConnect Spawning Suspicious Child Processes; AsyncRAT C2 Outbound Connections from ScreenConnect-Related Processes
- SigninLogs: shared by OAuth Token Grant to Unfamiliar Application Followed by Google Workspace Resource Access; OAuth Token Use from New Geographic Location for Google Workspace Access

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: ScreenConnect Spawning Suspicious Child Processes.
2. Resolve environment-mapping detections next: OAuth Token Grant to Unfamiliar Application Followed by Google Workspace Resource Access; OAuth Token Use from New Geographic Location for Google Workspace Access.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: AsyncRAT C2 Outbound Connections from ScreenConnect-Related Processes; Trojanized ScreenConnect Installer Dropping Executables to User-Writable Paths.

### Hunting Agenda and Promotion Criteria

- AsyncRAT C2 Outbound Connections from ScreenConnect-Related Processes: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Trojanized ScreenConnect Installer Dropping Executables to User-Writable Paths: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- OAuth Token Grant to Unfamiliar Application Followed by Google Workspace Resource Access: Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.; baseline expected benign activity and define an alert-volume threshold.
- OAuth Token Use from New Geographic Location for Google Workspace Access: Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
