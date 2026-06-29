---
layout: post
title: "Detection Engineering Brief - Monday, June 29, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-29
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Node.js
  - Windows
  - T1204
  - T1059
  - T1190
  - Next.js
  - Metasploit Framework
  - Metasploit
  - Dalfox
  - LiteLLM
  - T1547.001
  - T1547
---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Node.js, Windows, T1204, T1059, T1190, Next.js, Metasploit Framework, Metasploit, Dalfox, LiteLLM, T1547.001, T1547.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Node.js Implant Spawned from Shell After ZIP Extraction with LNK Execution; Metasploit Next.js Middleware Authorization Bypass Scan Pattern in HTTP Logs; Dalfox Service Spawning Unexpected Child Process Indicating Deserialization RCE; SQL Injection Payload Patterns in HTTP Requests Targeting LiteLLM Proxy API Endpoints.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Node.js Implant Spawned from Shell After ZIP Extraction with LNK Execution

### Detection Opportunity

Fake image shortcut (.lnk) file executed from ZIP archive spawns node.exe as a persistent implant

### Intelligence Context

- Microsoft Security Blog: Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access — [https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
  - Context: Attackers delivered photo-themed ZIP archives containing fake image LNK shortcut files. When executed, the LNK triggered node.exe to run a persistent implant. The campaign targeted the hospitality industry on Windows endpoints.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1059, T1547.001, T1547
- Products: Node.js
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Node.js, Windows, T1204, T1059, T1547.001, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let lnkCreation = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileExtension =~ "lnk"
| where FolderPath has_any (@"\Users\", "\Downloads\", "\Desktop\", "\AppData\", "\Temp\")
| where InitiatingProcessFileName in~ ("explorer.exe", "7zFM.exe", "winrar.exe", "svchost.exe")
| project DeviceId, LnkCreateTime = Timestamp, LnkFile = FileName, LnkFolder = FolderPath;
let nodeExec = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "node.exe"
| where InitiatingProcessFileName in~ ("explorer.exe", "cmd.exe", "wscript.exe", "powershell.exe", "mshta.exe")
| project DeviceId, DeviceName, NodeExecTime = Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
lnkCreation
| join kind=inner nodeExec on DeviceId
| where NodeExecTime between (LnkCreateTime .. (LnkCreateTime + 5m))
| project DeviceId, DeviceName, LnkCreateTime, LnkFile, LnkFolder, NodeExecTime, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by LnkCreateTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer workstations where node.exe is routinely launched from user directories after downloading project archives.
- Automated build or test pipelines that extract ZIP artifacts and invoke node.exe within short time windows.
- Users who legitimately install Node.js applications distributed as ZIP archives with LNK launchers.

Tuning notes:
- Extend the time window beyond 5 minutes if threat intelligence indicates longer delays between ZIP extraction and node.exe launch.
- Add device group exclusions for confirmed developer workstations using a watchlist or dynamic exclusion list.
- Consider adding a ProcessCommandLine filter on node.exe to require that the script path is in a user-writable directory, reducing false positives from system-level node.exe invocations.

Risks / caveats:
- DeviceFileEvents.FileExtension field availability depends on MDE onboarding level and file event collection policy; LNK files may not always populate FileExtension separately from FileName.
- DeviceFileEvents does not capture ZIP extraction as a distinct ActionType; LNK creation attributed to explorer.exe or archiver processes is an inference, not a guaranteed signal.
- The 5-minute correlation window between LNK creation and node.exe execution may miss campaigns with longer dwell between extraction and execution, or generate false positives if node.exe is launched coincidentally.
- FolderPath has_any matching on partial path strings may match unintended paths; validate against the environment's directory structure.

### Triage Runbook

First 15 minutes:
- Confirm the host is not a known developer or build machine where node.exe is expected; if it is, verify whether the command line and parent process are consistent with normal use.
- Review the node.exe ProcessCommandLine and InitiatingProcessCommandLine for a script path in user-writable locations such as Downloads, Desktop, Temp, AppData, or Public.
- Check the LNK file name and folder path to see whether it masquerades as an image or photo file and whether it was created shortly before node.exe execution.
- Identify the user account that interacted with the ZIP/LNK and determine whether the execution was user-initiated or launched by another process.
- Look for additional suspicious child processes, network connections, or repeated node.exe launches from the same host within the same time window.

Evidence to collect:
- DeviceName, DeviceId, LnkCreateTime, LnkFile, and LnkFolder from the alert.
- Full node.exe ProcessCommandLine and InitiatingProcessCommandLine.
- Parent process name and any associated archive tool or shell process.
- User account context and recent logon activity for the endpoint.
- Any related file paths, downloaded archive names, and timestamps around the execution.

Pivot points:
- DeviceProcessEvents for node.exe, its parent process, and any child processes on the same DeviceId.
- DeviceFileEvents for recent .lnk, .zip, and other downloaded files in user-writable paths.
- DeviceNetworkEvents for outbound connections from node.exe or its child processes.
- DeviceLogonEvents to confirm the active user session around the execution time.
- If available, Microsoft Defender for Endpoint file and process timeline for the host.

Benign explanations:
- A developer workstation where node.exe is routinely launched from downloaded project archives.
- A legitimate ZIP extraction where a shortcut file was intentionally used to start a local application.
- An automated build or test pipeline that extracts archives and invokes node.exe in a short time window.

Escalation criteria:
- The node.exe command line references a script in a user-writable directory and the host is not a known developer system.
- The LNK masquerades as a photo or document and execution was followed by suspicious child processes or outbound network activity.
- The same host shows repeated node.exe launches, persistence behavior, or additional suspicious files from the archive.
- The user reports no legitimate reason for opening the ZIP or LNK, or the file originated from an external email or download source.

Containment actions:
- Isolate the endpoint if the node.exe command line, parent process, or follow-on activity indicates likely malicious execution.
- Block or quarantine the suspicious ZIP, LNK, and any related script files if they are still present.
- Disable or reset the affected user account if there is evidence of credential misuse or repeated malicious execution.
- Preserve volatile evidence and process tree before remediation if the host is actively running the suspected implant.

Closure criteria:
- Confirmed developer, build, or sanctioned software activity with a benign command line and expected parent process.
- No suspicious script path, no persistence, no outbound activity, and the LNK/ZIP source is validated as legitimate.
- The alert is attributable to a known false-positive pattern already documented for the device group.
- Any suspicious files were removed and the host shows no further malicious process activity after review and monitoring.

---

## Detection 2: Node.js Persistence via Registry Run Key in Non-Developer User Directory

### Detection Opportunity

node.exe established as a persistent implant via registry run key pointing to a script in a user-writable path

### Intelligence Context

- Microsoft Security Blog: Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access — [https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
  - Context: The campaign delivered a persistent Node.js implant on Windows. Persistence mechanisms such as registry run keys are consistent with maintaining node.exe execution across reboots outside of developer contexts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1059, T1547.001, T1547
- Products: Node.js
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Node.js, Windows, T1204, T1059, T1547.001, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceRegistryEvents, DeviceProcessEvents

### KQL

```kql
let runKeyPersistence = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
| where RegistryValueData has "node.exe"
| where RegistryValueData has_any ("AppData", "Temp", "Downloads", "Public")
| project DeviceId, PersistTime = Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName;
let nodeExec = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "node.exe"
| where FolderPath has_any ("AppData", "Temp", "Downloads", "Public")
| project DeviceId, DeviceName, AccountName, ExecTime = Timestamp, ProcessCommandLine, FolderPath;
runKeyPersistence
| join kind=inner nodeExec on DeviceId
| where ExecTime >= PersistTime and ExecTime <= PersistTime + 24h
| project DeviceId, DeviceName, AccountName, PersistTime, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, ExecTime, ProcessCommandLine, FolderPath
| order by PersistTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer workstations where nvm-windows or similar version managers install node.exe into AppData and configure run key persistence.
- Electron-based applications that bundle node.exe and establish run key persistence for auto-launch from user-writable directories.

Tuning notes:
- Extend the ExecTime upper bound beyond 24 hours if endpoints are rebooted infrequently and the persistence mechanism is only triggered at startup.
- Add a watchlist-based exclusion for known developer devices where node.exe in AppData is expected.
- Consider adding a RegistryValueData filter to require that the path ends in .js to further narrow to script-based node.exe invocations.

Risks / caveats:
- DeviceRegistryEvents.RegistryValueData may be truncated for long registry values in some MDE configurations, potentially missing the full script path.
- The 24-hour upper bound on the join window may miss persistence that is activated after a reboot occurring more than 24 hours after the run key was written; extend the window if the environment has infrequent reboots.
- has_any path matching on partial strings such as 'AppData' will match any path containing that substring, including legitimate application paths; review FolderPath values in results.
- Ingestion delay between DeviceRegistryEvents and DeviceProcessEvents could cause the join to miss events at the boundary of the lookback window.

### Triage Runbook

First 15 minutes:
- Inspect the RegistryKey, RegistryValueName, and RegistryValueData to confirm the run key points to node.exe and a script in AppData, Temp, Downloads, or Public.
- Verify the writing process in InitiatingProcessFileName to see whether the persistence was created by a suspicious installer, script host, or user-launched process.
- Check whether the affected device is a known developer workstation or uses nvm-windows or another legitimate Node.js management tool.
- Review the node.exe ProcessCommandLine and FolderPath to determine whether execution is coming from a user profile rather than a standard installation path.
- Look for immediate post-persistence activity such as repeated node.exe launches, network beacons, or additional registry changes.

Evidence to collect:
- DeviceName, DeviceId, AccountName, PersistTime, RegistryKey, RegistryValueName, and RegistryValueData.
- InitiatingProcessFileName and any available initiating process command line for the registry write.
- ExecTime, ProcessCommandLine, and FolderPath for the node.exe execution.
- Any related script file names, archive names, or downloaded content in the same user directory.
- User logon context and whether the account has a history of legitimate Node.js use.

Pivot points:
- DeviceRegistryEvents for other Run/RunOnce writes on the same DeviceId and AccountName.
- DeviceProcessEvents for node.exe, powershell.exe, cmd.exe, wscript.exe, mshta.exe, and related script interpreters.
- DeviceFileEvents for scripts, archives, and executables in the same user-writable path.
- DeviceNetworkEvents for outbound connections from node.exe or the writing process.
- DeviceLogonEvents to correlate the persistence write with the active user session.

Benign explanations:
- A developer or power user system where Node.js is installed in AppData and a run key is used by a legitimate tool.
- An Electron-based application that legitimately configures auto-start from a user profile path.
- A version manager such as nvm-windows creating expected Node.js-related registry entries on a sanctioned developer machine.

Escalation criteria:
- The registry value launches node.exe from a user-writable path on a non-developer endpoint.
- The persistence was written by a suspicious script host, archive tool, or unknown installer process.
- The node.exe execution is followed by network connections, additional persistence, or other malware-like behavior.
- The registry value data is truncated or partially hidden but still clearly references a suspicious script path and the host is not expected to run Node.js.

Containment actions:
- Isolate the host if the run key is confirmed malicious or if node.exe is actively executing from the persisted path.
- Remove the malicious Run/RunOnce entry and quarantine the referenced script or executable after evidence capture.
- Reset credentials for the affected user if the persistence appears tied to account compromise.
- Block the related file path or hash if available and monitor for re-creation of the registry value.

Closure criteria:
- The registry entry is verified as a legitimate Node.js or application auto-start mechanism on an approved developer system.
- The command line and file path are consistent with sanctioned software and no suspicious follow-on activity is observed.
- The run key was created by a known benign installer or management tool and is documented for the device group.
- No additional persistence, network activity, or suspicious child processes are found after host review.

---

## Detection 3: Metasploit Next.js Middleware Authorization Bypass Scan Pattern in HTTP Logs

### Detection Opportunity

Metasploit scanner module sending authorization bypass probe requests to Next.js middleware endpoints

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: Rapid7 released a Metasploit scanner module for Next.js Middleware Authorization Bypass. The module probes Next.js applications with crafted HTTP requests designed to bypass middleware authorization controls, producing recognizable request signatures in HTTP access logs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Next.js, Metasploit Framework
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Next.js, Metasploit Framework, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the specific WAF or reverse proxy forwarding Next.js traffic must be confirmed to populate this field.
- CommonSecurityLog.ResponseCode may be named differently across vendors (e.g., some use EventOutcome or AdditionalExtensions); field availability must be validated against the specific connector.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where RequestURL has_any ("/_next/", "/__nextjs", "x-middleware-subrequest")
    or RequestURL matches regex @"(?i)(x-middleware-subrequest|x-now-route-matches|%2e%2e|\.\./)" 
| where RequestMethod in ("GET", "POST", "HEAD")
| extend IsToolUA = UserAgent has_any ("Ruby", "python-requests", "Go-http-client", "Metasploit")
| extend IsBypassPattern = RequestURL matches regex @"(?i)(x-middleware-subrequest|x-now-route-matches)"
| where IsToolUA or IsBypassPattern
| summarize RequestCount = count(),
            ResponseCodes = make_set(ResponseCode, 20),
            URLs = make_set(RequestURL, 10),
            UserAgents = make_set(UserAgent, 5),
            DeviceVendors = make_set(DeviceVendor, 3),
            DeviceProducts = make_set(DeviceProduct, 3)
    by SourceIP, bin(TimeGenerated, 5m)
| where RequestCount >= 5
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Internal penetration testing or red team exercises targeting Next.js applications.
- Automated synthetic monitoring tools that probe Next.js API routes.
- CDN or load balancer health checks that traverse /_next/ paths.

Tuning notes:
- Validate that the specific WAF or reverse proxy forwarding Next.js traffic populates RequestURL and UserAgent in CommonSecurityLog before scheduling.
- Add a DeviceVendor or DeviceProduct filter to scope the query to the specific log source fronting the Next.js application.
- Increase RequestCount threshold if the Next.js application receives high legitimate API traffic that matches /_next/ path patterns.

Risks / caveats:
- CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the specific WAF or reverse proxy forwarding Next.js traffic must be confirmed to populate this field.
- CommonSecurityLog.UserAgent is a non-standard CEF extension field and may be absent or mapped differently depending on the log source vendor.
- CommonSecurityLog.ResponseCode may be named differently across vendors (e.g., some use EventOutcome or AdditionalExtensions); field availability must be validated against the specific connector.
- The RequestCount threshold of 5 per 5 minutes is a starting point; environments with high legitimate traffic to Next.js endpoints will require a higher threshold to reduce noise.

### Triage Runbook

First 15 minutes:
- Identify the SourceIP and confirm whether it belongs to an internal scanner, red team, CDN health check, or external internet source.
- Review the RequestURL, RequestMethod, and UserAgent for the x-middleware-subrequest or related bypass pattern and note the targeted host.
- Check the request burst pattern and ResponseCode set to see whether the activity is repetitive probing or a single test request.
- Validate the DeviceVendor and DeviceProduct to ensure the log source is the expected WAF, reverse proxy, or web server in front of Next.js.
- Determine whether the targeted application owner has an approved test window or known synthetic monitoring activity.

Evidence to collect:
- SourceIP, TimeGenerated, RequestCount, ResponseCodes, URLs, UserAgents, DeviceVendor, and DeviceProduct.
- DestinationHostName or the targeted host name if available from the log source.
- Full request samples, including headers if the connector preserves them.
- Any matching WAF blocks, rate-limit events, or application errors around the same time.
- Change tickets, test approvals, or monitoring schedules for the application.

Pivot points:
- CommonSecurityLog for the same SourceIP across a wider time range to see if the probing expands beyond Next.js paths.
- CommonSecurityLog filtered to the same DestinationHostName to identify other suspicious request patterns.
- WAF or reverse proxy logs for blocked requests, rule hits, and request bodies if available.
- Application logs for authentication failures, middleware errors, or unusual 4xx/5xx spikes.
- Threat intel or internal scanner allowlists for the SourceIP and UserAgent.

Benign explanations:
- Authorized penetration testing or red team activity.
- Synthetic monitoring or uptime checks that traverse Next.js paths.
- CDN, load balancer, or health-check traffic that happens to match the path pattern.
- A security scanner using common HTTP libraries that is approved for testing.

Escalation criteria:
- The SourceIP is external and not on an approved allowlist, and the request pattern is repeated or distributed.
- The same source shows additional exploit-like requests or attempts against other public-facing endpoints.
- The activity coincides with application errors, authentication bypass symptoms, or suspicious access to protected content.
- There is no approved test or monitoring activity that explains the traffic.

Containment actions:
- Block or rate-limit the SourceIP at the WAF or reverse proxy if the activity is clearly unauthorized and ongoing.
- Add temporary protections for the targeted Next.js endpoint if bypass probing is active.
- Notify the application owner and web operations team to monitor for successful unauthorized access.
- Preserve relevant WAF and application logs before making filtering changes.

Closure criteria:
- The traffic is confirmed as authorized scanning, monitoring, or health-check activity.
- The SourceIP is validated against an approved allowlist or change record.
- No evidence of successful bypass, unauthorized access, or follow-on exploitation is found.
- The log source and field mapping are confirmed, and the alert pattern is documented as benign for that environment.

---

## Detection 4: Dalfox Service Spawning Unexpected Child Process Indicating Deserialization RCE

### Detection Opportunity

Dalfox process spawning shell or interpreter child processes following deserialization RCE exploitation via Metasploit module

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: Rapid7 released a Metasploit module exploiting a deserialization RCE vulnerability in Dalfox. Successful exploitation results in arbitrary code execution, which would manifest as unexpected child processes spawned by the Dalfox service process.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Dalfox, Metasploit Framework
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Dalfox, Metasploit Framework, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("dalfox", "dalfox.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "zsh", "curl", "wget", "python", "python3", "perl", "nc", "ncat", "netcat")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Automated security testing pipelines where Dalfox is invoked with shell wrappers for output processing.
- Developer environments where Dalfox is run interactively and spawns helper processes.

Tuning notes:
- Confirm whether Dalfox is deployed as a long-running service or invoked on-demand; the detection is most relevant when Dalfox runs as a persistent service that could be exploited remotely.
- Add DeviceName exclusions for known security testing or CI/CD hosts where Dalfox is used legitimately.
- Extend the child process list to include additional scripting interpreters relevant to the OS platform where Dalfox is deployed.

Risks / caveats:
- Dalfox is a security research tool and is unlikely to be present as a running process on MDE-enrolled production endpoints; the query will return no results unless Dalfox is explicitly deployed and monitored in the environment.
- On Linux hosts running Dalfox, the process name may appear without a file extension (dalfox rather than dalfox.exe); Defender for Endpoint Linux sensor behavior for InitiatingProcessFileName must be validated.
- The detection will produce no results in environments where Dalfox is not deployed on MDE-enrolled hosts; confirm Dalfox deployment before scheduling.
- On Linux endpoints, process name casing and extension behavior in InitiatingProcessFileName should be validated against actual MDE Linux sensor telemetry.

### Triage Runbook

First 15 minutes:
- Confirm whether Dalfox is actually deployed on the host and whether it is expected to run as a service or only interactively.
- Review the child process name, command line, and parent/initiating process chain to see if Dalfox spawned a shell, interpreter, or network utility unexpectedly.
- Check the AccountName and DeviceName to identify who or what launched Dalfox and whether the activity aligns with a sanctioned security test.
- Look for additional child processes, outbound connections, or file writes from the same process tree.
- Determine whether the host is a production endpoint, a lab system, or a security testing machine.

Evidence to collect:
- DeviceName, DeviceId, AccountName, Timestamp, FileName, ProcessId, and ProcessCommandLine for the child process.
- InitiatingProcessFileName, InitiatingProcessId, and InitiatingProcessCommandLine for the Dalfox parent.
- Any network connections or file writes associated with the same process tree.
- Host role and whether Dalfox is approved on the system.
- Recent logon activity and any scheduled task or service entries related to Dalfox.

Pivot points:
- DeviceProcessEvents for all processes spawned by Dalfox on the same DeviceId.
- DeviceNetworkEvents for outbound connections from the Dalfox process tree.
- DeviceFileEvents for files created or modified by the child process.
- DeviceRegistryEvents or scheduled task telemetry if the child process attempts persistence.
- Endpoint timeline or process tree view to reconstruct the full execution chain.

Benign explanations:
- A developer or security researcher running Dalfox interactively for testing.
- An approved CI/CD or security testing pipeline that invokes Dalfox and helper tools.
- A lab or red-team host where Dalfox is intentionally used and child shells are expected.
- A legitimate scan that spawns helper utilities such as curl or wget as part of the workflow.

Escalation criteria:
- Dalfox is running on a production or otherwise unexpected host and spawns a shell, interpreter, or network utility without an approved test.
- The child process performs suspicious actions such as downloading payloads, creating files, or establishing outbound connections.
- The process tree shows additional post-exploitation behavior, persistence, or credential access attempts.
- The host owner cannot explain why Dalfox is present or why it is executing on the system.

Containment actions:
- Isolate the host if the process tree indicates active exploitation or unauthorized code execution.
- Terminate the suspicious child process and, if necessary, the Dalfox process after preserving evidence.
- Block outbound connections from the host if the child process is beaconing or downloading content.
- Preserve the process tree and relevant artifacts before remediation.

Closure criteria:
- Dalfox is confirmed as an approved tool on the host and the child process behavior matches expected scanning activity.
- No suspicious network activity, file creation, or persistence is observed from the process tree.
- The alert is attributable to a sanctioned security test or lab environment.
- The host is not running Dalfox as a service and the detection is determined to be a benign interactive use case.

---

## Detection 5: SQL Injection Payload Patterns in HTTP Requests Targeting LiteLLM Proxy API Endpoints

### Detection Opportunity

Metasploit SQL injection module sending crafted payloads to LiteLLM Proxy API endpoints

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: Rapid7 released a Metasploit module for SQL injection against LiteLLM Proxy. The module targets LiteLLM API endpoints with SQL metacharacter payloads, producing detectable patterns in HTTP access logs or WAF telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: LiteLLM, Metasploit Framework
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, LiteLLM, Metasploit Framework, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the WAF or reverse proxy fronting LiteLLM must be confirmed to populate this field.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where RequestURL has_any ("/v1/", "/api/", "/chat/", "/completions", "/models")
| where RequestMethod in ("GET", "POST", "PUT", "PATCH")
| where RequestURL matches regex @"(?i)('|%27|--|%2d%2d|;|%3b|\bunion\b|\bselect\b|\binsert\b|\bdrop\b|sleep\s*\(|benchmark\s*\(|0x[0-9a-f]{2,})"
| summarize RequestCount = count(),
            ResponseCodes = make_set(ResponseCode, 20),
            SampleURLs = make_set(RequestURL, 5),
            UserAgents = make_set(UserAgent, 5),
            DeviceVendors = make_set(DeviceVendor, 3),
            DeviceProducts = make_set(DeviceProduct, 3),
            DestinationHosts = make_set(DestinationHostName, 5)
    by SourceIP, bin(TimeGenerated, 10m)
| where RequestCount >= 3
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Authorized penetration testing or red team exercises targeting the LiteLLM deployment.
- WAF rule testing that sends SQL injection patterns to validate detection coverage.
- Legitimate API requests containing URL-encoded apostrophes or semicolons in user-provided query parameters.

Tuning notes:
- Add a DestinationHostName filter matching the specific hostname of the LiteLLM Proxy deployment to prevent matching unrelated OpenAI-compatible API services.
- Validate that the WAF or reverse proxy fronting LiteLLM populates RequestURL in CommonSecurityLog before scheduling.
- Consider extending detection to cover request body content if the log source captures it in AdditionalExtensions or a custom field.
- Raise the RequestCount threshold after establishing a baseline of normal traffic volume to the LiteLLM API.

Risks / caveats:
- CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the WAF or reverse proxy fronting LiteLLM must be confirmed to populate this field.
- CommonSecurityLog.UserAgent is a non-standard CEF extension field and may be absent or differently mapped depending on the log source vendor.
- The LiteLLM API path patterns /v1/, /chat/, /completions, and /models are shared with many OpenAI-compatible services; without a DestinationHostName or DeviceProduct filter scoped to the LiteLLM instance, the query will match traffic to unrelated AI proxy services.
- The query will match any CommonSecurityLog source forwarding traffic to OpenAI-compatible API paths, not exclusively LiteLLM; add a DeviceProduct or DestinationHostName filter scoped to the LiteLLM instance to reduce scope.

### Triage Runbook

First 15 minutes:
- Confirm the SourceIP and whether it belongs to an approved scanner, red team, or internal test range.
- Review the SampleURLs, RequestMethod, and UserAgents to see whether the payloads contain SQL metacharacters or common injection strings.
- Validate the DestinationHostName and DeviceProduct to ensure the traffic is actually aimed at the LiteLLM instance and not another OpenAI-compatible service.
- Check ResponseCodes for signs of blocking, errors, or successful responses that might indicate the probe reached the application.
- Assess whether the request volume is isolated or part of a broader scan against multiple endpoints.

Evidence to collect:
- SourceIP, TimeGenerated, RequestCount, ResponseCodes, SampleURLs, UserAgents, DeviceVendors, DeviceProducts, and DestinationHostName.
- Any WAF rule hits, blocked requests, or application error logs tied to the same timestamps.
- The exact request paths and whether the payload appears in the URL or query string.
- Change tickets or approvals for penetration testing or WAF validation.
- Application owner confirmation of whether the traffic is expected.

Pivot points:
- CommonSecurityLog for the same SourceIP across a wider time window to identify broader scanning behavior.
- CommonSecurityLog filtered to the same DestinationHostName for other suspicious request patterns or repeated 4xx/5xx responses.
- WAF or reverse proxy logs for blocked SQLi signatures and request bodies if available.
- Application logs for authentication failures, database errors, or unusual latency around the alert time.
- Threat intel or allowlists for the SourceIP and UserAgent.

Benign explanations:
- Authorized penetration testing or red team activity.
- WAF validation or security testing that intentionally sends SQL injection patterns.
- Legitimate API requests containing URL-encoded apostrophes, semicolons, or other special characters in user input.
- Synthetic monitoring or integration tests that use OpenAI-compatible API paths.

Escalation criteria:
- The SourceIP is external and not approved, and the request pattern is repeated or distributed across multiple endpoints.
- The same source shows additional exploit attempts or a progression from probing to authenticated access attempts.
- The application owner reports unexpected errors, database anomalies, or suspicious access around the same time.
- There is evidence the requests reached the application and were not fully blocked by the WAF.

Containment actions:
- Block or rate-limit the SourceIP at the WAF or reverse proxy if the activity is unauthorized and ongoing.
- Tighten or temporarily enable SQL injection protections on the LiteLLM-facing edge if the probe is active.
- Notify the application owner and database/application operations team to watch for exploitation signs.
- Preserve relevant logs before changing filtering or blocking rules.

Closure criteria:
- The traffic is confirmed as authorized testing, monitoring, or benign malformed input.
- The SourceIP is validated against an approved allowlist or change record.
- No evidence of successful injection, unauthorized access, or application impact is found.
- The alert is documented as a known false-positive pattern for the LiteLLM deployment and log source.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- Node.js Implant Spawned from Shell After ZIP Extraction with LNK Execution: Do not schedule yet; validate as an analyst-led hunt first.
- Metasploit Next.js Middleware Authorization Bypass Scan Pattern in HTTP Logs: CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the specific WAF or reverse proxy forwarding Next.js traffic must be confirmed to populate this field.
- SQL Injection Payload Patterns in HTTP Requests Targeting LiteLLM Proxy API Endpoints: CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the WAF or reverse proxy fronting LiteLLM must be confirmed to populate this field.

Telemetry availability:
- Metasploit Next.js Middleware Authorization Bypass Scan Pattern in HTTP Logs: CommonSecurityLog.ResponseCode may be named differently across vendors (e.g., some use EventOutcome or AdditionalExtensions); field availability must be validated against the specific connector.
- Dalfox Service Spawning Unexpected Child Process Indicating Deserialization RCE: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

Shared-table notes:
- DeviceProcessEvents: shared by Node.js Implant Spawned from Shell After ZIP Extraction with LNK Execution; Node.js Persistence via Registry Run Key in Non-Developer User Directory; Dalfox Service Spawning Unexpected Child Process Indicating Deserialization RCE
- CommonSecurityLog: shared by Metasploit Next.js Middleware Authorization Bypass Scan Pattern in HTTP Logs; SQL Injection Payload Patterns in HTTP Requests Targeting LiteLLM Proxy API Endpoints

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Node.js Persistence via Registry Run Key in Non-Developer User Directory.
2. Resolve environment-mapping detections next: Metasploit Next.js Middleware Authorization Bypass Scan Pattern in HTTP Logs; Dalfox Service Spawning Unexpected Child Process Indicating Deserialization RCE; SQL Injection Payload Patterns in HTTP Requests Targeting LiteLLM Proxy API Endpoints.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Node.js Implant Spawned from Shell After ZIP Extraction with LNK Execution.

### Hunting Agenda and Promotion Criteria

- Node.js Implant Spawned from Shell After ZIP Extraction with LNK Execution: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Metasploit Next.js Middleware Authorization Bypass Scan Pattern in HTTP Logs: CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the specific WAF or reverse proxy forwarding Next.js traffic must be confirmed to populate this field.; baseline expected benign activity and define an alert-volume threshold.
- Dalfox Service Spawning Unexpected Child Process Indicating Deserialization RCE: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- SQL Injection Payload Patterns in HTTP Requests Targeting LiteLLM Proxy API Endpoints: CommonSecurityLog.RequestURL is not populated by all CEF-forwarding devices; the WAF or reverse proxy fronting LiteLLM must be confirmed to populate this field.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
