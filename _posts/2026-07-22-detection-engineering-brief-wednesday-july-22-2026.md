---
layout: post
title: "Detection Engineering Brief - Wednesday, July 22, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-22
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - BitLocker
  - T1486
  - Windows
  - RDP
  - MSSQL
  - RMM tools
  - web shells
  - T1105
  - T1059
  - Web servers
  - Microsoft Graph
  - Outlook
  - T1071.003
  - T1071.004
  - DNS
  - CVE-2026-63030
  - T1190
  - WordPress
  - WordPress Core
  - WordPress REST API batch endpoint
  - T1505
  - T1505.003
  - T1071
  - T1003
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: BitLocker, T1486, Windows, RDP, MSSQL, RMM tools, web shells, T1105, T1059, Web servers, Microsoft Graph, Outlook, T1071.003, T1071.004, DNS, CVE-2026-63030, T1190, WordPress, WordPress Core, WordPress REST API batch endpoint, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Unauthorized App Accessing Outlook Calendar via Microsoft Graph in Non-Interactive Context; Web Shell File Write Followed by Sensitive File Access - WordPress Post-Exploitation Host Compromise.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: BitLocker Encryption via manage-bde Invoked by Non-System Process

### Detection Opportunity

manage-bde executed by a non-system initiating process as part of BitLocker-based extortion chain

### Intelligence Context

- Securelist: A new extortion cocktail: office printers, small ransoms, and BitLocker — [https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/](https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/)
  - Context: Threat actors used manage-bde or equivalent BitLocker tooling to encrypt victim systems as the final stage of an extortion chain that included RDP, MSSQL, and RMM tool abuse.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1486, T1505, T1505.003
- Products: BitLocker
- Platforms: Windows
- Malware: Not specified
- Tools: RDP, MSSQL, RMM tools
- Search tags: BitLocker, T1486, Windows, RDP, MSSQL, RMM tools, T1505, T1505.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where FileName =~ "manage-bde.exe"
| where InitiatingProcessFileName !in~ ("services.exe", "svchost.exe", "msiexec.exe")
| where ProcessCommandLine has_any ("-on", "-protectors", "-forcerecovery", "-lock")
| project Timestamp, DeviceName, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FileName, ProcessCommandLine
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT administrators running manage-bde manually from cmd.exe or PowerShell during BitLocker enrollment or troubleshooting.
- RMM agents or endpoint management tools that invoke manage-bde directly and are not yet in the exclusion list.
- Automated scripts run by management platforms such as SCCM or Intune that call manage-bde outside of svchost.exe context.

**Tuning notes:**
- Expand InitiatingProcessFileName exclusions to include any approved IT management binaries confirmed in your environment.
- Consider scoping to server device groups via a DeviceName or DeviceId join against a device group tag if workstation BitLocker enrollment via manage-bde is routine.
- If SYSTEM-context invocations from non-service binaries are expected in your environment, add an AccountName exclusion for SYSTEM.

**Risks / caveats:**
- Environments where RMM tools or endpoint management agents invoke manage-bde directly will generate FPs until those initiating process names are added to the exclusion list.
- Workstation environments with self-service BitLocker enrollment via scripts may produce FPs if the script host (e.g., powershell.exe) is not excluded.
- The command-line filter covers the most common attack verbs but does not cover all manage-bde subcommands; an attacker using an unlisted verb would not be caught.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process, parent process, and account context; treat non-service, non-approved RMM launch paths as suspicious.
- Check whether the device is a workstation or server and whether BitLocker enrollment, recovery, or troubleshooting was expected at the alert time.
- Look for concurrent signs of intrusion on the same host such as RDP logons, MSSQL activity, RMM agent abuse, new admin accounts, or unusual remote sessions.
- Assess whether the command line indicates encryption, protector changes, or forced recovery rather than routine status checks.
- If the host is actively encrypting or multiple hosts are affected, move immediately to incident handling.

**Evidence to collect:**
- DeviceProcessEvents for manage-bde and the full process tree around the alert time.
- Recent logon and remote access evidence for the same account and host, especially RDP, MSSQL, and RMM-related activity.
- BitLocker state and recovery events on the device, including protector changes and recovery key prompts.
- Any nearby process or script activity from PowerShell, cmd.exe, wscript.exe, or approved management tools.
- Device name, account name, account domain, and whether the initiating process is on the approved allowlist.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName over the prior 24 hours.
- DeviceLogonEvents or equivalent sign-in telemetry for remote interactive access to the host.
- DeviceNetworkEvents for RDP, MSSQL, or RMM tool connections around the alert time.
- BitLocker or endpoint management logs to confirm whether the action was initiated by an approved workflow.
- Recent process ancestry for the initiating binary to identify script or remote tool abuse.

**Benign explanations:**
- IT staff manually enabling or troubleshooting BitLocker during deployment or recovery.
- An approved RMM or endpoint management agent invoking manage-bde during device provisioning.
- A scripted enrollment workflow from SCCM, Intune, or similar tooling that is not yet allowlisted.
- A local administrator performing recovery or protector changes during maintenance.

**Escalation criteria:**
- The command was launched from an unapproved remote tool, script host, or interactive admin session with no change record.
- There are signs of concurrent intrusion such as suspicious remote logons, lateral movement, or multiple hosts receiving similar commands.
- manage-bde is being used to force recovery, lock volumes, or enable encryption unexpectedly on production systems.
- The host is already showing user impact, ransom notes, or mass encryption behavior.

**Containment actions:**
- Isolate the host from the network if encryption is in progress or if the launch path is clearly malicious.
- Disable or reset the involved account if it appears compromised and is not a shared admin account.
- Preserve volatile evidence and process trees before rebooting or remediating the system.
- Coordinate with endpoint management to stop any malicious or unauthorized RMM job if one is identified.

**Closure criteria:**
- Confirmed approved BitLocker enrollment, recovery, or maintenance activity with matching change record.
- Initiating process and account are on the approved allowlist and no other intrusion indicators are present.
- No additional suspicious remote access, lateral movement, or encryption activity is found on the host or nearby systems.
- Alert is documented as benign with tuning feedback for future allowlisting.

<br/>
---
<br/>

## Detection 2: Web Shell Written to Web Root by Web Server Worker Process

### Detection Opportunity

Script file created in a web-accessible directory by a web server worker process during intrusion

### Intelligence Context

- Securelist: A new extortion cocktail: office printers, small ransoms, and BitLocker — [https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/](https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/)
  - Context: Threat actors deployed web shells on web servers as part of the intrusion chain preceding BitLocker extortion, using the web shell for persistent access and lateral movement.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1105, T1059, T1505, T1505.003
- Products: web shells
- Platforms: Windows, Web servers
- Malware: Not specified
- Tools: RDP, MSSQL, RMM tools
- Search tags: web shells, T1105, T1059, Windows, Web servers, RDP, MSSQL, RMM tools, T1505, T1505.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where InitiatingProcessFileName in~ ("w3wp.exe", "php-cgi.exe", "httpd.exe", "nginx.exe", "php.exe")
| where FileName endswith_cs ".php"
    or FileName endswith_cs ".asp"
    or FileName endswith_cs ".aspx"
    or FileName endswith_cs ".jsp"
    or FileName endswith_cs ".jspx"
    or FileName endswith_cs ".shtml"
| where FolderPath has_any ("wwwroot", "htdocs", "public_html", "webroot", "inetpub")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256, ActionType
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated CI/CD deployment pipelines that use web server processes to write script files to web root directories.
- CMS plugin or theme installation workflows where the web server process writes PHP files as part of legitimate update operations.
- Web application frameworks that generate or cache PHP/ASP files at runtime in the web root.

**Tuning notes:**
- Add FolderPath exclusions for known CI/CD deployment directories where legitimate script files are written by web server processes.
- Add .php5, .phtml, .phar to the extension list if the environment runs PHP applications that use those extensions.
- Scope DeviceName to web server device groups to reduce noise from developer workstations running local web servers.

**Risks / caveats:**
- DeviceFileEvents file access telemetry must be enabled in MDE; if only process telemetry is collected, file creation events will not appear.
- Web root paths that do not contain any of the listed directory name fragments will not be covered; environments with non-standard web root naming conventions require FolderPath additions.
- Legitimate CMS update and plugin installation workflows may generate FPs until CI/CD and deployment paths are excluded.
- The endswith_cs approach does not cover double-extension evasion such as shell.php5 or shell.phtml; additional extensions can be added if observed in the environment.

### Triage Runbook

**First 15 minutes:**
- Verify the file path, extension, and initiating process to confirm the write occurred in a true web root from a web server worker context.
- Inspect the file name and hash for known web shell patterns, recent changes, or matches to threat intelligence.
- Check whether the write aligns with a planned deployment, CMS/plugin update, or maintenance window.
- Look for immediate follow-on activity from the same host such as shell spawning, outbound connections, or additional file writes.
- If the file is suspicious, preserve it and prevent further access before attempting cleanup.

**Evidence to collect:**
- The created or renamed file path, file name, SHA256, and timestamp.
- InitiatingProcessFileName, InitiatingProcessCommandLine, and initiating account for the write event.
- Nearby DeviceProcessEvents and DeviceNetworkEvents from the same host around the file creation time.
- Any web server logs or deployment records that explain why the worker process wrote the file.
- A copy of the file for offline analysis if policy allows.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and FolderPath to find other recent web root writes.
- DeviceProcessEvents for the initiating process and any child shells or interpreters.
- DeviceNetworkEvents for outbound connections from the web server process after the write.
- Web server access logs or application logs for requests that may have triggered the write.
- Threat intelligence or file reputation checks using the SHA256.

**Benign explanations:**
- A legitimate CMS update, plugin installation, or theme deployment performed by the web application.
- A CI/CD pipeline or deployment tool writing application files into the web root.
- A framework-generated cache or runtime file created by the application.
- A maintenance task by a web administrator during a change window.

**Escalation criteria:**
- The file is a script in a web-accessible directory with suspicious content, obfuscation, or command execution logic.
- There is no approved deployment or maintenance activity that explains the write.
- The same host shows shell spawning, suspicious outbound traffic, or additional web root modifications.
- Multiple web servers or multiple files are affected in a short time window.

**Containment actions:**
- Remove external access to the affected web application or place it behind maintenance mode if the file is confirmed malicious.
- Quarantine or isolate the host if there are signs of active exploitation or additional compromise.
- Delete or quarantine the malicious file only after preserving evidence and confirming the scope of compromise.
- Rotate application secrets and credentials if the web server or app account may have been exposed.

**Closure criteria:**
- The file is confirmed to be part of an approved deployment or application workflow.
- File content, hash, and surrounding activity are consistent with a benign update and no other suspicious behavior is present.
- No additional web root writes, shell spawns, or suspicious network activity are observed on the host.
- The alert is documented and any necessary allowlist or path exclusions are proposed.

<br/>
---
<br/>

## Detection 3: Unauthorized App Accessing Outlook Calendar via Microsoft Graph in Non-Interactive Context

### Detection Opportunity

Unknown or unrecognized application registration reading or writing Outlook calendar events via Microsoft Graph API without user interaction, consistent with CAV3RN C2 channel

### Intelligence Context

- Securelist: New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA records for configuration recovery — [https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/](https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/)
  - Context: The CAV3RN framework uses Microsoft Graph API to read and write Outlook calendar events as a covert C2 channel, with the malware operating as an application accessing calendar data programmatically outside of normal user-driven browser sessions.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071.003, T1071
- Products: Microsoft Graph, Outlook
- Platforms: DNS
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Graph, Outlook, T1071.003, T1071.004, DNS, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.003 Mail Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Calendar-specific Operation values such as CalendarItemCreated and CalendarItemAccessed are not standard OfficeActivity Exchange audit operations; the actual logged operation names for calendar access via Graph are typically Set-MailboxCalendarFolder, UpdateCalendarItem, or similar Exchange audit schema names that vary by tenant audit configuration.
- The Office 365 Unified Audit Log connector must be enabled and Exchange workload audit logging must be configured to capture calendar operations; without this, the table will contain no relevant records.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in ("UpdateCalendarItem", "CreateCalendarItem", "DeleteCalendarItem", "Set-MailboxCalendarFolder", "MoveToDeletedItems")
| where isnotempty(UserAgent)
| where UserAgent !has "Mozilla"
    and UserAgent !has "Outlook"
    and UserAgent !has "Microsoft Office"
    and UserAgent !has "MacOutlook"
| summarize
    OperationCount = count(),
    DistinctOps = dcount(Operation),
    Operations = make_set(Operation, 10),
    EarliestEvent = min(TimeGenerated),
    LatestEvent = max(TimeGenerated)
    by UserId, UserAgent, ClientIP
| where OperationCount > 5
| project EarliestEvent, LatestEvent, UserId, UserAgent, ClientIP, OperationCount, DistinctOps, Operations
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate enterprise calendar integration applications such as room booking systems, scheduling assistants, or HR platforms that access calendar data via Graph with non-browser user agents.
- Monitoring or compliance tools that read calendar data programmatically.
- Migration tools that bulk-read or write calendar items during mailbox migrations.

**Tuning notes:**
- Run a survey query against OfficeActivity where OfficeWorkload == 'Exchange' and Operation contains 'Calendar' to enumerate the actual operation names present in the tenant before scheduling.
- Add a ClientAppId or AppId allowlist exclusion for known approved enterprise calendar integrations once the field availability is confirmed.
- Adjust the OperationCount threshold after baselining normal Graph-based calendar access volume in the environment.
- Consider extending the detection to AuditLogs (Azure AD sign-in logs) to correlate non-interactive service principal sign-ins to the Microsoft Graph resource with calendar scope claims.

**Risks / caveats:**
- OfficeActivity does not consistently populate a ClientAppId field for Exchange calendar operations; this field may be absent or null in most records, causing the summarize grouping to collapse results incorrectly.
- Calendar-specific Operation values such as CalendarItemCreated and CalendarItemAccessed are not standard OfficeActivity Exchange audit operations; the actual logged operation names for calendar access via Graph are typically Set-MailboxCalendarFolder, UpdateCalendarItem, or similar Exchange audit schema names that vary by tenant audit configuration.
- UserAgent is not reliably populated for Microsoft Graph API calls in OfficeActivity Exchange records; absence of this field would cause the UserAgent filter to drop all events.
- The Office 365 Unified Audit Log connector must be enabled and Exchange workload audit logging must be configured to capture calendar operations; without this, the table will contain no relevant records.

### Triage Runbook

**First 15 minutes:**
- Identify the user or service principal behind the activity and confirm whether the app is approved in the tenant.
- Review the operation pattern and volume to see whether it matches normal scheduling integration or repeated automated access.
- Check whether the source IP, user agent, and timing align with a known service, migration tool, or browser-based user session.
- Look for related Azure AD sign-ins, consent events, or unusual app registrations tied to the same identity.
- If the app is unknown and the activity is sustained or high-volume, treat it as suspicious and investigate further.

**Evidence to collect:**
- OfficeActivity records for the same UserId, ClientIP, UserAgent, and operations around the alert window.
- Azure AD sign-in logs or AuditLogs for the app registration, service principal, and consent history.
- Application inventory or approved integration list to confirm whether the app is sanctioned.
- Mailbox or calendar audit details showing what items were read or modified and at what frequency.
- Any related alerts for the same identity, tenant, or source IP.

**Pivot points:**
- OfficeActivity filtered to the same UserId and ClientIP over the prior 24 hours.
- AuditLogs or Entra ID sign-in logs for service principal sign-ins to Microsoft Graph.
- App registration and consent records for the suspected application or service principal.
- Exchange audit or mailbox audit logs for calendar item operations by the same identity.
- Device or network telemetry if the source IP maps to an internal host or proxy.

**Benign explanations:**
- A room booking, scheduling, or HR integration that legitimately reads and updates calendars.
- A migration or synchronization tool performing bulk calendar operations.
- A monitoring or compliance platform that accesses calendar data programmatically.
- A service principal used by an approved business application with non-browser user agents.

**Escalation criteria:**
- The application or service principal is unknown, unapproved, or recently consented without business justification.
- The activity is high-volume, persistent, or occurs across multiple mailboxes with no user interaction.
- There are signs of malicious app registration, suspicious consent, or other tenant compromise indicators.
- The same identity is also associated with suspicious sign-ins, token abuse, or other Graph API misuse.

**Containment actions:**
- Disable or revoke the suspicious application registration or service principal if it is confirmed unauthorized.
- Revoke active sessions and refresh tokens for the affected identity if compromise is suspected.
- Block the source IP or conditional access path if it is clearly malicious and not shared infrastructure.
- Coordinate with messaging and identity teams to preserve audit evidence before making tenant-wide changes.

**Closure criteria:**
- The activity is matched to a known approved integration, migration, or compliance tool.
- The app registration, consent, and source IP are validated and no other suspicious tenant activity is present.
- Operation volume and timing are consistent with normal business use after baselining.
- The alert is closed with documented allowlist or threshold tuning if needed.

<br/>
---
<br/>

## Detection 4: Web Server Worker Process Spawning Shell or Interpreter - WordPress CVE-2026-63030 RCE

### Detection Opportunity

Web server worker process spawning cmd.exe, powershell.exe, or sh as a child process following REST API batch endpoint activity, indicating post-exploitation code execution

### Intelligence Context

- SANS ISC: WordPress Exploitation Underway (CVE-2026-63030), (Mon, Jul 20th) — [https://isc.sans.edu/diary/rss/33168](https://isc.sans.edu/diary/rss/33168)
  - Context: Active exploitation of CVE-2026-63030 was observed shortly after disclosure. The vulnerability allows unauthenticated RCE via the WordPress REST API batch endpoint, with exploitation resulting in child process execution from the web server worker process.

### Search Metadata

- CVEs: CVE-2026-63030
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: WordPress, WordPress Core, WordPress REST API batch endpoint
- Platforms: Web servers
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63030, T1190, T1059, WordPress, WordPress Core, WordPress REST API batch endpoint, Web servers

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "php-cgi.exe", "httpd.exe", "php.exe", "nginx.exe", "apache2", "httpd")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "dash", "python.exe", "python3", "perl.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256, ProcessId, InitiatingProcessId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developers running local web servers on workstations who launch shells from within the web server process context during debugging.
- Legitimate administrative scripts that invoke shells from web server processes during maintenance windows.
- Web application health check or deployment scripts that spawn interpreters from the web server process.

**Tuning notes:**
- Scope the query to web server device groups using a DeviceId or DeviceName join against a device group tag to eliminate developer workstation noise.
- Add AccountName exclusions for known administrative accounts that legitimately run shells from web server contexts during maintenance.
- Consider adding a second-stage correlation with DeviceNetworkEvents to identify inbound connections to the REST API batch endpoint path immediately before the process spawn.

**Risks / caveats:**
- Developer workstations running local web servers will generate FPs until scoped to a web server device group.
- Legitimate maintenance scripts that spawn shells from web server processes will generate FPs until those AccountName values are excluded.
- The query does not correlate with HTTP request logs to confirm the REST API batch endpoint was the trigger; a network-layer correlation would increase confidence but requires IIS or web access log ingestion.

### Triage Runbook

**First 15 minutes:**
- Verify the parent-child process chain and confirm the spawning process is a web server worker on a production web host.
- Check the command line of the spawned shell or interpreter for download, execution, or post-exploitation behavior.
- Determine whether the host is a WordPress server and whether any maintenance, deployment, or debugging activity was scheduled.
- Look for nearby signs of exploitation such as suspicious HTTP requests, new files in the web root, or outbound connections from the spawned process.
- If the process is unexpected or interactive, treat the host as potentially compromised.

**Evidence to collect:**
- DeviceProcessEvents showing the full process tree, command lines, and account context.
- DeviceNetworkEvents for outbound connections from the spawned shell or interpreter.
- Web server or application logs around the alert time, especially requests to the REST API batch endpoint.
- Any file creation or modification events in the web root or adjacent directories.
- Host role, WordPress version, and whether the server is internet-facing.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to find additional child processes or repeated spawns.
- DeviceNetworkEvents for the same host and process to identify downloads or command-and-control traffic.
- DeviceFileEvents for recent web root writes or suspicious script drops.
- Web access logs or reverse proxy logs for requests to WordPress endpoints before the spawn.
- Asset inventory or CMDB to confirm the host is a WordPress server and whether it is production.

**Benign explanations:**
- A legitimate administrator using a shell from a web server during maintenance.
- A deployment script or health check that invokes an interpreter from the web server context.
- A local development or staging web server on a workstation used for debugging.
- An application plugin or automation task that legitimately shells out from the web process.

**Escalation criteria:**
- The shell command line shows download-and-execute, credential access, or persistence behavior.
- The host is internet-facing and there is no approved maintenance activity to explain the spawn.
- Additional indicators appear, such as web shell writes, suspicious outbound traffic, or lateral movement.
- Multiple web servers show the same pattern, suggesting active exploitation at scale.

**Containment actions:**
- Isolate the web server if exploitation is confirmed or strongly suspected.
- Disable external access to the vulnerable WordPress application until patched and validated.
- Preserve process trees, logs, and any dropped files before remediation.
- Rotate application secrets and review privileged credentials used on the host if compromise is likely.

**Closure criteria:**
- The process spawn is tied to an approved maintenance or deployment activity with supporting records.
- No suspicious command line, network activity, or follow-on compromise is found.
- The host is patched or otherwise protected and no additional exploitation indicators are present.
- The alert is documented with any required scoping to the web server device group.

<br/>
---
<br/>

## Detection 5: Web Shell File Write Followed by Sensitive File Access - WordPress Post-Exploitation Host Compromise

### Detection Opportunity

Web server worker process writes a script file to the web root and subsequently accesses sensitive file system paths, indicating full host compromise following WordPress RCE exploitation

### Intelligence Context

- Rapid7: CVE-2026-63030: wp2shell a Critical Remote Code Execution Vulnerability in WordPress Core — [https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core)
  - Context: Rapid7 assessed CVE-2026-63030 as capable of resulting in complete compromise of the website and underlying host. Post-exploitation activity includes file system access beyond the web root, consistent with credential harvesting or persistence establishment after initial web shell deployment.

### Search Metadata

- CVEs: CVE-2026-63030
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1505, T1505.003, T1003
- Products: WordPress, WordPress Core, WordPress REST API batch endpoint
- Platforms: Web servers
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63030, T1190, T1059, WordPress, WordPress Core, WordPress REST API batch endpoint, Web servers, T1505, T1505.003, T1003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (high); Credential Access: T1003 OS Credential Dumping (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let WebShellWrites = DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where InitiatingProcessFileName in~ ("w3wp.exe", "php-cgi.exe", "httpd.exe", "php.exe", "nginx.exe")
| where FileName endswith_cs ".php"
    or FileName endswith_cs ".asp"
    or FileName endswith_cs ".aspx"
    or FileName endswith_cs ".jsp"
    or FileName endswith_cs ".jspx"
| where FolderPath has_any ("wwwroot", "htdocs", "public_html", "webroot", "inetpub")
| project DeviceName, WebShellTime = Timestamp, WebShellFile = FileName, WebShellPath = FolderPath, WebWorker = InitiatingProcessFileName, WebShellAccountName = InitiatingProcessAccountName;
let SensitiveFileAccess = DeviceFileEvents
| where FolderPath has_any ("\\Windows\\System32\\config", "\\Windows\\NTDS", "wp-config.php", "\\etc\\passwd", "\\etc\\shadow")
| where InitiatingProcessFileName in~ ("w3wp.exe", "php-cgi.exe", "httpd.exe", "php.exe", "cmd.exe", "powershell.exe", "sh", "bash")
| project DeviceName, AccessTime = Timestamp, AccessedFile = FileName, AccessedPath = FolderPath, AccessProcess = InitiatingProcessFileName, AccessAccountName = InitiatingProcessAccountName, AccessedFileSHA256 = SHA256;
WebShellWrites
| join kind=inner SensitiveFileAccess on DeviceName
| where AccessTime between (WebShellTime .. (WebShellTime + 30m))
| project WebShellTime, AccessTime, DeviceName, WebShellFile, WebShellPath, WebWorker, WebShellAccountName, AccessedFile, AccessedPath, AccessProcess, AccessAccountName, AccessedFileSHA256
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- WordPress core updates or plugin installations that write PHP files to the web root and then read wp-config.php as part of the update process.
- Automated backup tools running under web server account context that write temporary files and then read configuration files.
- CI/CD pipelines that deploy script files and then validate configuration by reading config files within the correlation window.

**Tuning notes:**
- Replace the wp-config.php fragment in SensitiveFileAccess with a more specific path such as the full relative path if the environment uses a consistent WordPress installation structure.
- Add FolderPath exclusions in WebShellWrites for known CI/CD deployment directories.
- Consider reducing the correlation window to 10 minutes if the environment shows that legitimate deployment pipelines complete within that time.
- To promote to production_candidate, add a process lineage filter that requires the AccessProcess in SensitiveFileAccess to be a child of the same WebWorker process using InitiatingProcessId linkage if available in the environment.

**Risks / caveats:**
- DeviceFileEvents file access telemetry must be enabled in MDE; if only file creation events are collected and file read events are not, the SensitiveFileAccess subquery will return no results for read-based credential access.
- The join on DeviceName alone without a shared process or session identifier means events from unrelated processes on the same host within the 30-minute window can be correlated; this is an inherent limitation of file event correlation without process tree linkage.
- The wp-config.php fragment in SensitiveFileAccess will match normal WordPress startup reads of the configuration file, which is a significant FP source in environments where WordPress restarts or updates occur within 30 minutes of any file write to the web root.
- File read events may not be collected by MDE depending on the audit policy configuration; if only file write events are collected, the SensitiveFileAccess subquery will return no results.

### Triage Runbook

**First 15 minutes:**
- Treat this as likely post-exploitation until proven otherwise because it combines web shell creation with sensitive file access.
- Validate the timing and process lineage of both events to see whether the same web server context performed the write and the access.
- Identify which sensitive paths were touched and whether they include Windows credential stores, Linux shadow files, or WordPress configuration files.
- Check for additional compromise indicators such as outbound connections, new accounts, privilege escalation, or lateral movement.
- If the sensitive access is confirmed and not clearly benign, escalate as an active host compromise.

**Evidence to collect:**
- The web shell file name, path, hash, and creation time.
- The sensitive file path, access time, and initiating process for the follow-on access.
- Full DeviceProcessEvents and DeviceFileEvents around the 30-minute correlation window.
- Any web access logs, reverse proxy logs, or application logs showing the triggering request.
- Credential-related artifacts, persistence changes, and outbound network activity from the host.

**Pivot points:**
- DeviceFileEvents for the same DeviceName to find additional web shell writes or sensitive file reads.
- DeviceProcessEvents for child shells, interpreters, or credential-dumping tools on the host.
- DeviceNetworkEvents for suspicious outbound traffic after the file write.
- Identity and logon telemetry for new admin sessions or lateral movement from the host.
- Web server logs to correlate the exploit request with the file write and access sequence.

**Benign explanations:**
- A WordPress update or plugin installation that writes files and reads wp-config.php as part of normal operation.
- A backup, migration, or validation workflow that accesses configuration files after deployment.
- A maintenance script running under the web server account that touches both web root and config files.
- A false correlation between unrelated file events on the same host within the time window.

**Escalation criteria:**
- The accessed files include credential stores, shadow copies, NTDS, or other high-value secrets.
- The web shell content is malicious or the file path is not part of an approved deployment.
- There is evidence of additional attacker activity such as persistence, privilege escalation, or outbound C2.
- The correlation is repeated or appears on multiple hosts, indicating broader compromise.

**Containment actions:**
- Isolate the host if the web shell or sensitive file access is confirmed malicious.
- Disable external access to the affected web application and preserve evidence before cleanup.
- Rotate credentials and secrets that may have been exposed, including application and administrative accounts.
- Coordinate incident response to remove persistence and assess lateral movement or data theft.

**Closure criteria:**
- The web shell write and sensitive access are explained by a documented, approved maintenance or deployment workflow.
- File content, access paths, and process lineage do not indicate malicious behavior after review.
- No additional suspicious process, network, or identity activity is found on the host.
- The alert is closed with any needed tuning for known deployment or backup paths.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- Web Shell Written to Web Root by Web Server Worker Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.
- Web Shell File Write Followed by Sensitive File Access - WordPress Post-Exploitation Host Compromise: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- Unauthorized App Accessing Outlook Calendar via Microsoft Graph in Non-Interactive Context: Do not schedule yet; validate as an analyst-led hunt first.
- Unauthorized App Accessing Outlook Calendar via Microsoft Graph in Non-Interactive Context: Calendar-specific Operation values such as CalendarItemCreated and CalendarItemAccessed are not standard OfficeActivity Exchange audit operations; the actual logged operation names for calendar access via Graph are typically Set-MailboxCalendarFolder, UpdateCalendarItem, or similar Exchange audit schema names that vary by tenant audit configuration.
- Web Shell File Write Followed by Sensitive File Access - WordPress Post-Exploitation Host Compromise: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Unauthorized App Accessing Outlook Calendar via Microsoft Graph in Non-Interactive Context: The Office 365 Unified Audit Log connector must be enabled and Exchange workload audit logging must be configured to capture calendar operations; without this, the table will contain no relevant records.

**Shared-table notes:**
- DeviceProcessEvents: shared by BitLocker Encryption via manage-bde Invoked by Non-System Process; Web Server Worker Process Spawning Shell or Interpreter - WordPress CVE-2026-63030 RCE
- DeviceFileEvents: shared by Web Shell Written to Web Root by Web Server Worker Process; Web Shell File Write Followed by Sensitive File Access - WordPress Post-Exploitation Host Compromise

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: BitLocker Encryption via manage-bde Invoked by Non-System Process; Web Shell Written to Web Root by Web Server Worker Process; Web Server Worker Process Spawning Shell or Interpreter - WordPress CVE-2026-63030 RCE.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Unauthorized App Accessing Outlook Calendar via Microsoft Graph in Non-Interactive Context; Web Shell File Write Followed by Sensitive File Access - WordPress Post-Exploitation Host Compromise.

### Hunting Agenda and Promotion Criteria

- Unauthorized App Accessing Outlook Calendar via Microsoft Graph in Non-Interactive Context: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Web Shell File Write Followed by Sensitive File Access - WordPress Post-Exploitation Host Compromise: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
