---
layout: post
title: "Detection Engineering Brief - Sunday, June 28, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-28
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1204
  - T1059
  - Windows
  - Node.js
  - T1190
  - LiteLLM
  - Metasploit Framework
  - Next.js
  - Audiobookshelf
  - T1053
  - T1053.005
  - T1059.007
  - T1547
  - T1547.001
---

## Executive Signal

This brief produced 5 detection candidates.

0 production candidates, 2 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1204, T1059, Windows, Node.js, T1190, LiteLLM, Metasploit Framework, Next.js, Audiobookshelf, T1053, T1053.005, T1059.007, T1547, T1547.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Node.js Implant Execution from LNK File in ZIP Extraction Path; Node.js Implant Persistence via Registry Run Key or Scheduled Task; LiteLLM Proxy SQL Injection Attempt with Metasploit User-Agent; Next.js Middleware Authorization Bypass Scanning via Anomalous Authorization Headers; Audiobookshelf Unauthenticated API Bypass Scanning from Single Source.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Node.js Implant Execution from LNK File in ZIP Extraction Path

### Detection Opportunity

Fake image shortcut (LNK) file spawning node.exe from a ZIP extraction directory such as Downloads or Temp

### Intelligence Context

- Microsoft Security Blog: Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access — [https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
  - Context: The campaign delivers photo-themed ZIP archives containing fake image LNK shortcut files. When executed by the user, the LNK triggers node.exe to run a malicious script, establishing a persistent Node.js implant on Windows hosts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1059, T1053, T1053.005, T1059.007, T1547, T1547.001
- Products: Not specified
- Platforms: Windows, Node.js
- Malware: Not specified
- Tools: Not specified
- Search tags: T1204, T1059, Windows, Node.js, T1053, T1053.005, T1059.007, T1547, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (high); Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Persistence: T1053 Scheduled Task/Job/ T1053.005 Scheduled Task (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lnk_creation = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".lnk"
| where tolower(FolderPath) has_any ("downloads", "temp", "appdata")
| project DeviceId, LnkCreatedTime = Timestamp, LnkFile = FileName, LnkPath = FolderPath;
let node_exec = DeviceProcessEvents
| where tolower(FileName) == "node.exe"
| where tolower(InitiatingProcessFileName) in ("explorer.exe", "7zg.exe", "7zfm.exe", "winrar.exe")
| where tolower(ProcessCommandLine) has_any ("downloads", "temp", "appdata")
| project DeviceId, DeviceName, AccountName, NodeExecTime = Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, NodeFolderPath = FolderPath, SHA256;
node_exec
| join kind=inner lnk_creation on DeviceId
| where NodeExecTime between (LnkCreatedTime .. (LnkCreatedTime + 5m))
| project DeviceId, DeviceName, AccountName, LnkCreatedTime, LnkFile, LnkPath, NodeExecTime, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, NodeFolderPath, SHA256
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer machines where node.exe is legitimately invoked from Downloads or AppData during package installation.
- CI/CD agents that extract ZIP artifacts to Temp and execute node.exe scripts.
- Archive utilities legitimately extracting LNK files (e.g., desktop shortcuts) coincidentally near node.exe execution.

Tuning notes:
- Remove wscript.exe and cmd.exe from the initiating process list unless command-line constraints are added to scope them to LNK-launched execution.
- Consider adding a SHA256 allowlist for known-good node.exe binaries to reduce noise from legitimate installs.
- Extend the join window to 15 minutes if ZIP extraction and LNK execution are observed to be temporally separated in real telemetry.

Risks / caveats:
- DeviceFileEvents ActionType 'FileCreated' must be confirmed as populated for LNK files in the deployment; some MDE configurations suppress shortcut file creation events depending on onboarding profile and OS version.
- The 5-minute correlation window between LNK creation and node.exe execution may miss delayed execution scenarios; consider extending to 15 minutes if telemetry shows gaps.
- Broad path tokens (downloads, temp, appdata) will match any process or file in those directories, not just ZIP extraction artifacts; no reliable ZIP extraction marker is available in DeviceFileEvents without correlating the archive utility process.
- Developer and CI/CD machine exclusions must be applied manually or via device group filtering before scheduling.

### Triage Runbook

First 15 minutes:
- Confirm the alerting host, user, and exact LNK and node.exe timestamps; verify the node.exe launch occurred within minutes of the shortcut creation.
- Review the node.exe command line and initiating process to determine whether execution came from Explorer or an archive utility and whether the script path points to Downloads, Temp, or AppData.
- Check for any immediate follow-on activity from the same account or host, especially registry run key creation, scheduled task creation, unusual child processes, or additional script interpreters.
- Assess whether the device is a developer workstation, CI/CD agent, or known Node.js test machine that could explain legitimate node.exe activity from user-writable paths.

Evidence to collect:
- Device name, account name, LNK file name, LNK path, LNK creation time, node.exe execution time, and full process command line.
- SHA256 of node.exe and any referenced script or payload if available, plus the initiating process command line.
- Any related DeviceRegistryEvents and DeviceEvents around the same time window for Run key or scheduled task creation.
- Parent/child process tree for node.exe and any subsequent network or file activity from the same host.

Pivot points:
- DeviceProcessEvents for node.exe executions on the host and account in the prior and subsequent 24 hours.
- DeviceFileEvents for other shortcut, archive, or script file creations in Downloads, Temp, AppData, and related extraction paths.
- DeviceRegistryEvents for Run/RunOnce modifications and DeviceEvents for scheduled task creation on the same device.
- If available, endpoint network telemetry or proxy logs to identify outbound connections immediately after node.exe starts.

Benign explanations:
- A user legitimately opened a ZIP archive containing a shortcut or installer that launched a Node.js-based application.
- Developer tooling or package installation on a workstation invoked node.exe from a user-writable directory.
- A CI/CD or automation host extracted artifacts to Temp or Downloads and executed a Node.js script as part of a build or test workflow.

Escalation criteria:
- Escalate immediately if the node.exe command line references an unexpected script in a user-writable path, especially if the host is not a developer or automation system.
- Escalate if you find any persistence activity, suspicious child processes, or outbound connections that are not consistent with the user’s normal workflow.
- Escalate if the LNK originated from an external email, download, or archive source and the user did not expect the file.
- Escalate if multiple hosts or multiple users show the same pattern within a short time window.

Containment actions:
- If the host is not a known developer or automation system and the activity appears malicious, isolate the endpoint from the network.
- Disable or reset the affected user account if there is evidence of malicious execution beyond a single accidental launch.
- Quarantine the suspicious ZIP, LNK, script, and any related payloads from the endpoint and mail/download source.
- Preserve volatile evidence before rebooting or cleaning the system.

Closure criteria:
- The node.exe activity is confirmed as legitimate software installation, development, or automation on an approved host.
- No suspicious persistence, lateral movement, credential access, or outbound command-and-control behavior is found.
- The LNK and any related archive are identified as benign and removed or accounted for, and the host/user context matches expected behavior.
- Document the rationale for the false positive and add the host or workflow to an approved exclusion or watchlist if appropriate.

---

## Detection 2: Node.js Implant Persistence via Registry Run Key or Scheduled Task

### Detection Opportunity

node.exe executing scripts from non-standard paths combined with registry run key or scheduled task creation for persistence

### Intelligence Context

- Microsoft Security Blog: Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access — [https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
  - Context: The campaign deploys a persistent Node.js implant on Windows. Persistence is established following initial execution of the malicious LNK, with node.exe running scripts from non-standard user-writable directories and a persistence mechanism such as a registry run key or scheduled task being created in close temporal proximity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1059, T1053, T1053.005, T1059.007, T1547, T1547.001
- Products: Not specified
- Platforms: Windows, Node.js
- Malware: Not specified
- Tools: Not specified
- Search tags: T1204, T1059, Windows, Node.js, T1053, T1053.005, T1059.007, T1547, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (high); Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Persistence: T1053 Scheduled Task/Job/ T1053.005 Scheduled Task (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceRegistryEvents, DeviceEvents

### KQL

```kql
let node_exec = DeviceProcessEvents
| where tolower(FileName) == "node.exe"
| where tolower(FolderPath) has_any ("downloads", "temp", "appdata", "programdata")
| project DeviceId, DeviceName, AccountName, NodeTime = Timestamp, ProcessCommandLine, NodeFolderPath = FolderPath, SHA256, InitiatingProcessFileName;
let reg_persist = DeviceRegistryEvents
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any ("\\Run", "\\RunOnce")
| project DeviceId, PersistenceTime = Timestamp, PersistenceType = ActionType, PersistenceDetail = strcat(RegistryKey, " | ", RegistryValueName, " | ", RegistryValueData);
let task_persist = DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| project DeviceId, PersistenceTime = Timestamp, PersistenceType = ActionType, PersistenceDetail = tostring(AdditionalFields);
let reg_hits = node_exec
| join kind=inner reg_persist on DeviceId
| where PersistenceTime between (NodeTime .. (NodeTime + 10m))
| project DeviceId, DeviceName, AccountName, NodeTime, ProcessCommandLine, NodeFolderPath, SHA256, InitiatingProcessFileName, PersistenceTime, PersistenceType, PersistenceDetail;
let task_hits = node_exec
| join kind=inner task_persist on DeviceId
| where PersistenceTime between (NodeTime .. (NodeTime + 10m))
| project DeviceId, DeviceName, AccountName, NodeTime, ProcessCommandLine, NodeFolderPath, SHA256, InitiatingProcessFileName, PersistenceTime, PersistenceType, PersistenceDetail;
reg_hits
| union task_hits
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Node.js-based application installers that write run keys as part of legitimate setup from AppData or ProgramData.
- Developer tooling that creates scheduled tasks for build automation while node.exe is active.
- Software update agents that use node.exe and register scheduled tasks for update checks.

Tuning notes:
- Add FolderPath exclusions for legitimate Node.js application directories specific to the environment before scheduling.
- Consider narrowing the registry key filter to HKCU\Software\Microsoft\Windows\CurrentVersion\Run and HKLM equivalent paths for precision.
- Extend the correlation window to 20 minutes if persistence is observed to be established later in the attack chain in real telemetry.

Risks / caveats:
- DeviceEvents ActionType 'ScheduledTaskCreated' availability depends on MDE sensor version and Windows audit policy; this event is not guaranteed to be populated in all MDE deployments and should be confirmed before relying on the scheduled task branch.
- DeviceRegistryEvents RegistryValueData field population varies by MDE configuration; absence of this field will not break the query but reduces triage fidelity.
- The 10-minute correlation window may produce false positives if unrelated software installs run node.exe and create persistence mechanisms in the same window on the same device.
- RunServices registry key filter removed as it is not a standard modern Windows persistence path; if the threat actor uses it, the reg_persist filter will miss it unless re-added.

### Triage Runbook

First 15 minutes:
- Confirm the timing relationship between node.exe execution and the registry or scheduled task event; verify both occurred on the same host and account context.
- Inspect the persistence detail to identify the exact Run key, RunOnce value, or scheduled task name, command, and target binary/script.
- Determine whether the persistence points back to a script or executable in Downloads, Temp, AppData, or ProgramData and whether it is consistent with a legitimate application install.
- Check for additional suspicious activity on the host, including repeated node.exe launches, script execution, or unusual network connections.

Evidence to collect:
- Device name, account name, node.exe command line, node.exe folder path, SHA256, and initiating process file name.
- Registry key, value name, value data, and timestamp for any Run/RunOnce persistence.
- Scheduled task name, action, trigger, and any AdditionalFields captured for the task event.
- Any related file creation or modification events for the script, shortcut, or payload referenced by the persistence mechanism.

Pivot points:
- DeviceRegistryEvents for the same host and account to find other Run, RunOnce, or startup-related changes.
- DeviceEvents for scheduled task creation and related task modification events on the host.
- DeviceProcessEvents for repeated node.exe launches or child processes from the same user-writable directories.
- DeviceFileEvents for payloads, scripts, or shortcut files created near the node.exe execution time.

Benign explanations:
- A legitimate Node.js application installer or updater created a Run key or scheduled task as part of setup.
- Developer tooling or build automation on a sanctioned machine created a scheduled task for maintenance or testing.
- A software update agent or enterprise application used node.exe and registered persistence for a valid operational reason.

Escalation criteria:
- Escalate if the persistence points to a script or binary in a user profile, Temp, Downloads, or another unexpected writable location.
- Escalate if the host is not a known developer, test, or automation system and the persistence was created without a clear business justification.
- Escalate if the persistence is accompanied by outbound connections, additional script execution, or evidence of user deception.
- Escalate if multiple persistence mechanisms are present or if the same account appears on other affected hosts.

Containment actions:
- If malicious persistence is confirmed or strongly suspected, isolate the endpoint from the network.
- Remove or disable the malicious Run key or scheduled task only after evidence is preserved and the payload is captured.
- Reset credentials for the affected account if there is any indication of credential theft or broader compromise.
- Block the identified script, hash, or associated payload across the environment if it is confirmed malicious.

Closure criteria:
- The registry or scheduled task change is verified as part of a legitimate, approved application installation or automation workflow.
- The referenced node.exe activity is explained by a known-good application and no other suspicious host activity is present.
- No additional persistence, lateral movement, or malicious network behavior is found after review.
- The event is documented with the approved software owner or device group context and excluded if appropriate.

---

## Detection 3: LiteLLM Proxy SQL Injection Attempt with Metasploit User-Agent

### Detection Opportunity

SQL injection payloads targeting LiteLLM proxy endpoints, correlated with Metasploit default user-agent strings

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: A new Metasploit module for LiteLLM proxy SQL injection was published. The module targets LiteLLM proxy HTTP endpoints with SQL injection payloads. Metasploit modules emit recognizable default user-agent strings that can be correlated with SQL injection signatures in HTTP logs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: LiteLLM, Metasploit Framework
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit Framework
- Search tags: T1190, LiteLLM, Metasploit Framework

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog RequestBody field is not populated by most WAF and proxy connectors; SQL injection detection via RequestBody will produce no results if this field is empty or absent for the log source in use.
- LiteLLM proxy traffic must be forwarded to Sentinel via a WAF, reverse proxy, or syslog connector that maps HTTP request data to CommonSecurityLog fields; without this connector, the query returns no results.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where RequestURL has "litellm"
    or (
        RequestURL has_any ("/v1/", "/api/")
        and tolower(UserAgent) has_any ("ruby", "python-requests", "go-http-client", "metasploit")
    )
| where (
    RequestURL has_any ("'", "--", "UNION", "SELECT", "DROP", "xp_")
    or RequestBody has_any ("'", "--", "UNION SELECT", "OR 1=1", "xp_")
    or tolower(UserAgent) has_any ("ruby", "python-requests", "go-http-client", "metasploit")
)
| summarize
    RequestCount = count(),
    ResponseCodes = make_set(ResponseCode),
    Methods = make_set(RequestMethod),
    Paths = make_set(RequestURL)
    by SourceIP, UserAgent, DeviceVendor, DeviceProduct, DestinationPort, bin(TimeGenerated, 5m)
| where RequestCount > 3
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Internal penetration testing or vulnerability scanning activity against LiteLLM endpoints.
- WAF false-positive alerts on legitimate API requests containing apostrophes or semicolons in parameter values.
- Generic API clients using python-requests or curl user-agents for legitimate LiteLLM API calls.

Tuning notes:
- Once LiteLLM-specific URL path patterns are confirmed in RequestURL, replace the broad /v1/ and /api/ tokens with those specific paths.
- Increase RequestCount threshold based on observed baseline traffic volume to LiteLLM endpoints.
- If RequestBody is not populated by the log source, remove the RequestBody branch to avoid misleading null matches.

Risks / caveats:
- CommonSecurityLog RequestBody field is not populated by most WAF and proxy connectors; SQL injection detection via RequestBody will produce no results if this field is empty or absent for the log source in use.
- LiteLLM proxy traffic must be forwarded to Sentinel via a WAF, reverse proxy, or syslog connector that maps HTTP request data to CommonSecurityLog fields; without this connector, the query returns no results.
- CommonSecurityLog is a legacy Sentinel table; environments using the newer AMA-based connector may ingest equivalent data into a custom table rather than CommonSecurityLog.
- RequestBody is frequently empty or truncated in CommonSecurityLog; the SQL injection detection branch relying on RequestBody may produce no results depending on the WAF or proxy connector.

### Triage Runbook

First 15 minutes:
- Confirm the source IP, request URL, user-agent, response codes, and request volume to determine whether this is a short probe or sustained attack.
- Check whether the source IP belongs to an internal vulnerability scanner, penetration test, reverse proxy, or other approved security tool.
- Review the targeted LiteLLM endpoint and response behavior to see whether the application returned errors, unusual 200s, or signs of successful injection.
- Assess whether the traffic is external and whether the affected service is internet-facing or exposed through a reverse proxy.

Evidence to collect:
- Source IP, destination port, request URL samples, request method, user-agent, response codes, and request count over time.
- DeviceVendor and DeviceProduct to identify the logging source and whether the data came from a WAF, proxy, or firewall.
- Any available request body or matched SQL-like tokens, noting that request body may be absent or truncated.
- Service owner, deployment environment, and whether the LiteLLM instance is production, test, or development.

Pivot points:
- CommonSecurityLog for the same SourceIP across the last 24 hours to identify other targeted paths or services.
- CommonSecurityLog for the same RequestURL patterns and user-agent strings across all source IPs to determine campaign scope.
- WAF or reverse proxy logs, if available, to validate whether the request body or SQL payload was actually blocked.
- Application logs for LiteLLM to check for errors, authentication anomalies, or backend database exceptions around the same time.

Benign explanations:
- An internal security scanner or penetration test intentionally probed the LiteLLM endpoint.
- A legitimate API client or automation tool generated unusual request patterns that resemble injection strings.
- A WAF false positive triggered on benign input containing quotes, semicolons, or SQL-like tokens.

Escalation criteria:
- Escalate if the source is external, untrusted, or not on an approved testing list.
- Escalate if the requests are sustained, distributed, or accompanied by application errors, database exceptions, or unexpected 200 responses.
- Escalate if the same source also targets other public-facing services or shows clear Metasploit-style behavior.
- Escalate if there is any evidence the injection may have succeeded or altered application behavior.

Containment actions:
- If the source is external and the activity is clearly malicious, block the source IP at the WAF or perimeter control.
- Rate-limit or temporarily restrict the exposed LiteLLM endpoint if attack volume is high and the service is at risk.
- Notify the application owner to review logs and validate whether the endpoint is patched and protected.
- Preserve relevant WAF and application logs before making blocking changes.

Closure criteria:
- The source is confirmed as an authorized scanner, test, or internal monitoring system.
- The requests are determined to be benign or blocked with no evidence of successful exploitation.
- The LiteLLM service owner confirms no application impact, no database errors, and no unauthorized access.
- Any necessary allowlist or scanner exclusions are documented and approved.

---

## Detection 4: Next.js Middleware Authorization Bypass Scanning via Anomalous Authorization Headers

### Detection Opportunity

Metasploit scanner sending anomalous HTTP requests to Next.js middleware paths with authorization bypass patterns

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: A new Metasploit scanner module for Next.js middleware authorization bypass was published. The scanner probes Next.js middleware-protected routes with crafted requests designed to bypass authorization checks, producing anomalous HTTP patterns detectable in WAF or proxy logs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Next.js, Metasploit Framework
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit Framework
- Search tags: T1190, Next.js, Metasploit Framework

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Next.js application traffic must be forwarded to Sentinel via a WAF or reverse proxy that maps HTTP response codes and URL paths to CommonSecurityLog; without this connector, the query returns no results.
- CommonSecurityLog ResponseCode field must be populated as an integer by the log source; some connectors log it as a string or leave it null, which will cause countif comparisons to return zero.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where RequestURL has_any ("/_next/", "/api/", "/middleware")
| where RequestMethod in ("GET", "POST", "HEAD")
| summarize
    TotalRequests = count(),
    Codes200 = countif(ResponseCode == 200),
    Codes401 = countif(ResponseCode == 401),
    Codes403 = countif(ResponseCode == 403),
    UserAgents = make_set(UserAgent),
    Paths = make_set(RequestURL)
    by SourceIP, DeviceVendor, DeviceProduct, DestinationPort, bin(TimeGenerated, 5m)
| where TotalRequests > 10 and Codes401 > 0 and Codes200 > 0
| extend BypassRatio = todouble(Codes200) / todouble(TotalRequests)
| where BypassRatio > 0.3
| order by TotalRequests desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- CDN or reverse proxy health checks that probe protected routes and receive mixed response codes.
- Legitimate users with expired sessions generating 401 responses followed by re-authentication 200 responses in rapid succession.
- Internal security scanners probing Next.js routes as part of authorized testing.

Tuning notes:
- Narrow RequestURL filter to specific middleware-protected route prefixes for the Next.js application once they are confirmed in telemetry.
- Increase TotalRequests threshold to 20 or higher if legitimate retry behavior generates noise.
- Restrict SourceIP to external network ranges by joining with a known internal IP range exclusion list.

Risks / caveats:
- Next.js application traffic must be forwarded to Sentinel via a WAF or reverse proxy that maps HTTP response codes and URL paths to CommonSecurityLog; without this connector, the query returns no results.
- CommonSecurityLog ResponseCode field must be populated as an integer by the log source; some connectors log it as a string or leave it null, which will cause countif comparisons to return zero.
- CommonSecurityLog is a legacy Sentinel table; environments using AMA-based connectors may ingest equivalent data into a custom table.
- The /_next/ path prefix matches Next.js static asset requests which are legitimately unauthenticated; this may inflate Codes200 counts and BypassRatio for normal traffic.

### Triage Runbook

First 15 minutes:
- Confirm the source IP, request paths, response codes, and request volume to see whether the pattern is consistent with scanning or normal user retries.
- Check whether the source is an approved internal scanner, CDN, load balancer, or health-check system that could generate mixed 200/401 responses.
- Review the targeted paths to determine whether they are actual middleware-protected routes or generic Next.js static asset requests.
- Assess whether the traffic is external and whether the application is internet-facing.

Evidence to collect:
- Source IP, destination port, request URL samples, request method, user-agent, and response code distribution.
- Total request count, counts of 200/401/403, and the bypass ratio for the alert window.
- DeviceVendor and DeviceProduct to identify the log source and confirm the data path.
- Application owner confirmation of which routes are protected by middleware and which responses are expected.

Pivot points:
- CommonSecurityLog for the same SourceIP over the last 24 hours to identify broader probing of the application or related services.
- CommonSecurityLog for the same URL paths across all sources to determine whether the pattern is isolated or widespread.
- Reverse proxy or WAF logs to validate whether the requests were blocked, challenged, or passed through.
- Application logs for authentication failures, middleware exceptions, or unusual route access around the alert time.

Benign explanations:
- A CDN, reverse proxy, or health-check system probed protected routes and produced mixed response codes.
- A legitimate user with an expired session retried requests and generated both 401 and 200 responses.
- An internal security test or vulnerability scan intentionally exercised the middleware paths.

Escalation criteria:
- Escalate if the source is external and not on an approved testing or infrastructure list.
- Escalate if the same source shows repeated probing across multiple protected routes or a high bypass ratio over time.
- Escalate if application logs show unexpected 200 responses for routes that should require authorization.
- Escalate if the activity is accompanied by other exploit attempts against the same host or application stack.

Containment actions:
- If the source is clearly malicious and external, block or rate-limit the IP at the WAF or perimeter.
- Coordinate with the application owner to tighten middleware rules or temporarily restrict exposed routes if exploitation is suspected.
- Preserve proxy and application logs before making blocking or configuration changes.
- If there is evidence of successful bypass, initiate incident response and assess for unauthorized access to the application.

Closure criteria:
- The source is confirmed as an approved scanner, health-check, CDN, or legitimate user behavior.
- The response pattern is explained by normal application behavior and no unauthorized access is found.
- The application owner confirms the observed routes and response codes are expected for the deployment.
- Any required tuning for known infrastructure sources is documented and approved.

---

## Detection 5: Audiobookshelf Unauthenticated API Bypass Scanning from Single Source

### Detection Opportunity

Repeated unauthenticated requests to Audiobookshelf API endpoints returning HTTP 200 from a single source IP, consistent with authentication bypass scanning

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: A new Metasploit scanner module for Audiobookshelf unauthenticated API authentication bypass was published. The scanner sends unauthenticated requests to Audiobookshelf API endpoints and identifies instances where the application returns HTTP 200 without valid credentials, indicating a bypass vulnerability.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Audiobookshelf, Metasploit Framework
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit Framework
- Search tags: T1190, Audiobookshelf, Metasploit Framework

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Audiobookshelf traffic must be forwarded to Sentinel via a WAF or reverse proxy connector that maps HTTP request data to CommonSecurityLog; without this connector, the query returns no results.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where RequestURL has_any ("/api/", "/audiobookshelf", "/login", "/auth")
| where ResponseCode == 200
| where tolower(UserAgent) has_any ("python-requests", "ruby", "go-http-client", "curl", "metasploit", "libwww-perl", "wget")
| summarize
    SuccessfulRequests = count(),
    DistinctPaths = dcount(RequestURL),
    UserAgents = make_set(UserAgent),
    Methods = make_set(RequestMethod)
    by SourceIP, DeviceVendor, DeviceProduct, DestinationPort, bin(TimeGenerated, 10m)
| where SuccessfulRequests > 5 and DistinctPaths > 1
| order by SuccessfulRequests desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate API clients using curl or python-requests for Audiobookshelf integrations or automation.
- Internal monitoring tools that probe Audiobookshelf health endpoints and receive HTTP 200 responses.
- Authorized penetration testing activity against Audiobookshelf deployments.

Tuning notes:
- Replace generic path tokens with Audiobookshelf-specific API endpoint paths once confirmed in RequestURL telemetry.
- Remove curl and wget from the UserAgent filter if legitimate automation uses these agents in the environment.
- Increase SuccessfulRequests threshold based on observed baseline for the Audiobookshelf deployment.
- Add SourceIP exclusions for known internal monitoring and health-check systems.

Risks / caveats:
- Audiobookshelf traffic must be forwarded to Sentinel via a WAF or reverse proxy connector that maps HTTP request data to CommonSecurityLog; without this connector, the query returns no results.
- CommonSecurityLog does not have a standard Authorization header field; the original logic using UserAgent as a proxy for unauthenticated access is an indirect signal and cannot confirm the absence of an Authorization header.
- CommonSecurityLog ResponseCode must be populated as an integer by the log source; string or null values will cause the ResponseCode == 200 filter to return no results.
- The query cannot confirm the absence of an Authorization header because CommonSecurityLog does not expose individual HTTP request headers as standard fields; the UserAgent filter is an indirect proxy for unauthenticated scanner activity.

### Triage Runbook

First 15 minutes:
- Confirm the source IP, request paths, methods, user-agent, and response codes to determine whether the activity is a short test or sustained probing.
- Check whether the source is an internal monitoring system, approved scanner, or known automation client that legitimately accesses Audiobookshelf.
- Review whether the API endpoints returned 200 responses without expected authentication and whether the paths are specific to Audiobookshelf.
- Assess whether the service is internet-facing and whether the source is external or internal.

Evidence to collect:
- Source IP, destination port, request URL samples, request method, user-agent, and response code.
- Successful request count, distinct path count, and time window of the activity.
- DeviceVendor and DeviceProduct to identify the logging source and connector type.
- Application owner confirmation of expected API clients and any known health checks or integrations.

Pivot points:
- CommonSecurityLog for the same SourceIP across the last 24 hours to identify other endpoints or repeated probing.
- CommonSecurityLog for Audiobookshelf-related paths across all sources to see whether the pattern is isolated or part of a broader scan.
- Reverse proxy or WAF logs to validate whether requests were authenticated, blocked, or passed through.
- Audiobookshelf application logs to check for authentication anomalies, unusual API access, or errors around the alert time.

Benign explanations:
- A legitimate API client, integration, or automation script accessed Audiobookshelf endpoints with a non-browser user-agent.
- An internal monitoring or health-check system generated repeated successful requests.
- An authorized penetration test or vulnerability scan targeted the service.

Escalation criteria:
- Escalate if the source is external, untrusted, or not on an approved testing list.
- Escalate if the requests are sustained, cover multiple API paths, or show repeated 200 responses where authentication should be required.
- Escalate if application logs show unexpected access to user data, admin functions, or other sensitive endpoints.
- Escalate if the same source also targets other public-facing services or shows scanner-like behavior across the environment.

Containment actions:
- If the source is clearly malicious and external, block or rate-limit the IP at the WAF or perimeter.
- Notify the application owner to review authentication controls and confirm whether the exposed endpoints are intended to be public.
- Preserve proxy and application logs before blocking or changing access controls.
- If there is evidence of successful unauthorized access, initiate incident response and assess account and data exposure.

Closure criteria:
- The source is confirmed as an approved scanner, integration, or internal monitoring system.
- The requests are determined to be benign and no unauthorized access or data exposure is found.
- The Audiobookshelf owner confirms the observed behavior matches expected application use.
- Any required exclusions or tuning for known clients are documented and approved.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- Node.js Implant Execution from LNK File in ZIP Extraction Path: Do not schedule yet; validate as an analyst-led hunt first.
- Node.js Implant Persistence via Registry Run Key or Scheduled Task: Do not schedule yet; validate as an analyst-led hunt first.

Telemetry availability:
- LiteLLM Proxy SQL Injection Attempt with Metasploit User-Agent: CommonSecurityLog RequestBody field is not populated by most WAF and proxy connectors; SQL injection detection via RequestBody will produce no results if this field is empty or absent for the log source in use.
- LiteLLM Proxy SQL Injection Attempt with Metasploit User-Agent: LiteLLM proxy traffic must be forwarded to Sentinel via a WAF, reverse proxy, or syslog connector that maps HTTP request data to CommonSecurityLog fields; without this connector, the query returns no results.
- Next.js Middleware Authorization Bypass Scanning via Anomalous Authorization Headers: Next.js application traffic must be forwarded to Sentinel via a WAF or reverse proxy that maps HTTP response codes and URL paths to CommonSecurityLog; without this connector, the query returns no results.
- Next.js Middleware Authorization Bypass Scanning via Anomalous Authorization Headers: CommonSecurityLog ResponseCode field must be populated as an integer by the log source; some connectors log it as a string or leave it null, which will cause countif comparisons to return zero.

Shared-table notes:
- DeviceProcessEvents: shared by Node.js Implant Execution from LNK File in ZIP Extraction Path; Node.js Implant Persistence via Registry Run Key or Scheduled Task
- CommonSecurityLog: shared by LiteLLM Proxy SQL Injection Attempt with Metasploit User-Agent; Next.js Middleware Authorization Bypass Scanning via Anomalous Authorization Headers; Audiobookshelf Unauthenticated API Bypass Scanning from Single Source

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: LiteLLM Proxy SQL Injection Attempt with Metasploit User-Agent; Next.js Middleware Authorization Bypass Scanning via Anomalous Authorization Headers; Audiobookshelf Unauthenticated API Bypass Scanning from Single Source.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Node.js Implant Execution from LNK File in ZIP Extraction Path; Node.js Implant Persistence via Registry Run Key or Scheduled Task.

### Hunting Agenda and Promotion Criteria

- Node.js Implant Execution from LNK File in ZIP Extraction Path: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Node.js Implant Persistence via Registry Run Key or Scheduled Task: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- LiteLLM Proxy SQL Injection Attempt with Metasploit User-Agent: CommonSecurityLog RequestBody field is not populated by most WAF and proxy connectors; SQL injection detection via RequestBody will produce no results if this field is empty or absent for the log source in use.; baseline expected benign activity and define an alert-volume threshold.
- Next.js Middleware Authorization Bypass Scanning via Anomalous Authorization Headers: Next.js application traffic must be forwarded to Sentinel via a WAF or reverse proxy that maps HTTP response codes and URL paths to CommonSecurityLog; without this connector, the query returns no results.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Audiobookshelf Unauthenticated API Bypass Scanning from Single Source: Audiobookshelf traffic must be forwarded to Sentinel via a WAF or reverse proxy connector that maps HTTP request data to CommonSecurityLog; without this connector, the query returns no results.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
