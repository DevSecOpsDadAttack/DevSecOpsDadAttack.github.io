---
layout: post
title: "Detection Engineering Brief - Saturday, June 6, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-06
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1190
  - Apache ActiveMQ
  - Linux
  - Metasploit
  - Gogs
  - WeTransfer
  - Windows
  - MSI
---

## Executive Signal

This brief produced 4 detection candidates.

1 production candidate, 1 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 2 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: T1190, Apache ActiveMQ, Linux, Metasploit, Gogs, WeTransfer, Windows, MSI.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Apache ActiveMQ Jolokia addNetworkConnector RCE Attempt; Gogs Git Rebase Argument Injection via '--exec' Branch Name; WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Apache ActiveMQ Jolokia addNetworkConnector RCE Attempt

### Detection Opportunity

HTTP request to Apache ActiveMQ Jolokia endpoint invoking addNetworkConnector operation, consistent with Metasploit RCE module exploitation.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Apache ActiveMQ RCE, Gogs Rebase RCE, and Windows Kernel Pointer Enum — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026)
  - Context: Rapid7 documented a new Metasploit module exploiting Apache ActiveMQ via the Jolokia addNetworkConnector endpoint to achieve remote code execution. The exploit targets the Jolokia JMX HTTP bridge exposed on the ActiveMQ broker.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Apache ActiveMQ
- Platforms: Linux
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Apache ActiveMQ, Linux, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog.DeviceProduct values for ActiveMQ or Jolokia are not standard CEF product strings; the has_any filter may match nothing if the forwarding device uses a different product identifier.

Required telemetry:
- DeviceNetworkEvents, CommonSecurityLog

### KQL

```kql
let timeframe = 7d;
union isfuzzy=true
(
    DeviceNetworkEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "ConnectionSuccess"
    | where (RemotePort == 8161 or RemoteUrl has "jolokia")
    | where RemoteUrl has "addNetworkConnector"
    | project EventTime = Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemotePort, RemoteIP
    | extend Source = "DeviceNetworkEvents"
),
(
    CommonSecurityLog
    | where TimeGenerated > ago(timeframe)
    | where RequestURL has "jolokia"
    | where RequestURL has "addNetworkConnector"
    | project EventTime = TimeGenerated, DeviceName, RequestURL, RequestMethod, SourceIP, DestinationPort
    | extend Source = "CommonSecurityLog"
)
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Internal vulnerability scanners querying the Jolokia endpoint as part of authenticated scanning.
- Legitimate JMX management consoles or monitoring agents that use the Jolokia HTTP bridge.
- Penetration testing activity against ActiveMQ infrastructure.

Tuning notes:
- If ActiveMQ is deployed on a non-default port, update the RemotePort == 8161 filter to match the actual port.
- Add a where DeviceName in~ (known_activemq_hosts) filter once a host inventory is available to reduce scope to relevant servers.
- For scheduled rule use, reduce timeframe to 1d and set evaluation frequency to 1h with a 1d lookback.

Risks / caveats:
- CommonSecurityLog requires a CEF/Syslog data connector forwarding HTTP access logs from the ActiveMQ host or an upstream proxy; this connector is not universally deployed.
- DeviceNetworkEvents.RemoteUrl is only populated when MDE resolves the HTTP layer of a connection; raw TCP to port 8161 without HTTP inspection will produce no RemoteUrl value and will not match the addNetworkConnector filter.
- The union of CommonSecurityLog (Sentinel-only) and DeviceNetworkEvents (Defender XDR) requires the Defender XDR connector to be enabled in the Sentinel workspace; this query will fail in a standalone Defender XDR Advanced Hunting context.
- CommonSecurityLog.DeviceProduct values for ActiveMQ or Jolokia are not standard CEF product strings; the has_any filter may match nothing if the forwarding device uses a different product identifier.

### Triage Runbook

First 15 minutes:
- Confirm the target host is an ActiveMQ broker and whether Jolokia is intentionally exposed on the observed port.
- Identify the source IP, user agent or proxy path if available, and check whether the source is an approved scanner, admin host, or unknown external address.
- Review nearby ActiveMQ, web proxy, firewall, and host logs for follow-on requests, authentication attempts, process creation, or outbound connections from the broker.
- Check whether the broker was modified, restarted, or showed signs of command execution after the request.

Evidence to collect:
- Source IP, destination host, destination port, request URL, request method, and timestamp from the alert.
- ActiveMQ/Jolokia access logs and any reverse proxy or WAF logs covering the same time window.
- Host telemetry for process creation, network connections, service restarts, and new files on the ActiveMQ server.
- Any evidence of post-exploitation activity such as outbound shell connections, suspicious child processes, or new scheduled tasks.

Pivot points:
- DeviceNetworkEvents for the ActiveMQ host around the alert time.
- CommonSecurityLog or proxy/web access logs for requests to Jolokia and addNetworkConnector.
- DeviceProcessEvents on the broker host for suspicious child processes or command shells.
- Firewall or load balancer logs to confirm whether the request came from the internet or an internal management network.

Benign explanations:
- Authenticated vulnerability scanning against the broker.
- Legitimate JMX or Jolokia-based administration from a known management host.
- Internal monitoring or automation that queries Jolokia endpoints for health or configuration checks.

Escalation criteria:
- The source is unknown, external, or not an approved scanner/admin host.
- You find evidence of command execution, new processes, or outbound connections from the broker after the request.
- The request was followed by repeated exploitation attempts, authentication bypass behavior, or changes to broker configuration.
- The broker is internet-facing and Jolokia exposure was not expected.

Containment actions:
- If exploitation is suspected, isolate the ActiveMQ host from the network or restrict access to the Jolokia port immediately.
- Block the source IP at perimeter controls if it is clearly malicious and not a shared scanner.
- Disable or restrict Jolokia exposure until the broker can be reviewed and patched.
- Preserve logs and memory before rebooting or making disruptive changes if compromise is likely.

Closure criteria:
- The source is confirmed as an approved scanner or admin host and no post-request compromise indicators are present.
- ActiveMQ/Jolokia exposure is expected and the request matches documented maintenance activity.
- No suspicious process, file, or network activity is found on the broker after the event.
- Any required hardening actions, such as access restriction or patching, have been completed or scheduled.

---

## Detection 2: Gogs Git Rebase Argument Injection via '--exec' Branch Name

### Detection Opportunity

Git rebase operation on a Gogs server spawning unexpected child processes, consistent with argument injection via a maliciously named branch containing '--exec'.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Apache ActiveMQ RCE, Gogs Rebase RCE, and Windows Kernel Pointer Enum — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026)
  - Context: Rapid7 documented a Metasploit module exploiting Gogs by naming a branch '--exec' and triggering a rebase, causing the git binary to execute attacker-controlled commands. The exploit results in command execution under the Gogs server process context.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Gogs
- Platforms: Linux
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Gogs, Linux, Metasploit

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
let timeframe = 7d;
let shell_binaries = dynamic(["sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby"]);
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where
    (
        InitiatingProcessFileName in~ ("git", "gogs")
        and FileName in~ (shell_binaries)
        and InitiatingProcessCommandLine has "rebase"
    )
    or
    (
        ProcessCommandLine has "rebase"
        and ProcessCommandLine has "--exec"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Git hooks (pre-rebase, post-rebase) that spawn shell scripts as part of legitimate repository operations.
- CI/CD automation using git rebase --exec for commit validation or linting.
- Developer workstations where git rebase --exec is used interactively.

Tuning notes:
- Add a where DeviceName == '<gogs_server_hostname>' filter once the host name is known to scope results to the server.
- Add a where AccountName != '<ci_runner_account>' exclusion if CI/CD runners on the same host use git rebase --exec legitimately.
- Extend shell_binaries to include any additional scripting runtimes present in the Gogs server environment.

Risks / caveats:
- DeviceProcessEvents on Linux requires the Microsoft Defender for Endpoint Linux agent to be deployed and process event collection to be enabled on the Gogs host; without this, the table will contain no entries for that host.
- Process command-line logging must be explicitly enabled in MDE policy for Linux; it is not on by default in all configurations.
- The Gogs process may appear under a process name other than 'gogs' depending on how it is installed (e.g., wrapped in a systemd service or renamed binary); the InitiatingProcessFileName filter may miss those cases.
- Without scoping to the specific DeviceName hosting Gogs, this query will flag any developer workstation using git rebase --exec interactively, generating significant false positive volume.

### Triage Runbook

First 15 minutes:
- Confirm the alerting host is the Gogs server and identify the account or service context that initiated the git activity.
- Inspect the process tree for git, shell, or scripting child processes spawned by Gogs around the alert time.
- Review the command line for evidence of '--exec', unusual branch names, or rebase activity tied to a repository operation.
- Check whether the activity came from a CI runner, admin workflow, or an external user action through Gogs.

Evidence to collect:
- DeviceProcessEvents for the Gogs host, including parent and child process chains and command lines.
- Gogs application logs, repository access logs, and any audit logs showing the repository, branch name, and user account involved.
- AccountName, DeviceName, FolderPath, and timestamps from the alert to identify the working directory and execution context.
- Any outbound network connections, file writes, or privilege changes that occurred immediately after the rebase event.

Pivot points:
- DeviceProcessEvents on the Gogs host for git, sh, bash, python, perl, ruby, or other child processes.
- Gogs server logs for repository operations, branch creation, pull, merge, and rebase actions.
- DeviceNetworkEvents for outbound connections from the Gogs host after the alert.
- Authentication or SSO logs to identify the user or service account associated with the repository action.

Benign explanations:
- Legitimate repository maintenance using git rebase --exec for validation or linting.
- Git hooks or automation that spawn shell or scripting processes during normal repository operations.
- CI/CD jobs running on the same host that use git rebase as part of build or test workflows.

Escalation criteria:
- Unexpected shell or scripting processes were spawned by the Gogs service context.
- The branch name or repository activity is clearly malicious or not associated with an approved workflow.
- You observe file modification, credential access, or outbound network activity after the rebase event.
- The Gogs host is internet-facing and the activity originated from an untrusted source or user account.

Containment actions:
- Suspend or isolate the Gogs service if command execution is confirmed or strongly suspected.
- Disable the affected repository or user account until the branch and commit history are reviewed.
- Block external access to the Gogs instance if exploitation appears active and the service is exposed.
- Preserve process, application, and repository logs before restarting services or cleaning up artifacts.

Closure criteria:
- The event is tied to approved CI/CD or administrative activity and no unexpected child processes are present.
- Repository logs confirm a benign rebase operation with no malicious branch naming or command execution.
- No follow-on network, file, or privilege activity is found on the Gogs host.
- Any required repository or service hardening actions have been completed.

---

## Detection 3: WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain

### Detection Opportunity

Email containing a WeTransfer link received by a user, followed by a network connection to wetransfer.com and subsequent file download, consistent with phishing payload delivery observed in the Evil MSI campaign.

### Intelligence Context

- SANS ISC: The Evil MSI Background is Back! — [https://isc.sans.edu/diary/rss/33054](https://isc.sans.edu/diary/rss/33054)
  - Context: SANS ISC reported a campaign beginning with an email containing a WeTransfer link. Clicking the link delivered a payload embedded in a JPEG file using an MSI-branded background as a lure. The delivery chain starts with email and proceeds through WeTransfer to file download and execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: WeTransfer
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: WeTransfer, Windows, MSI

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let timeframe = 7d;
let browser_processes = dynamic(["msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe"]);
let wetransfer_downloads =
    DeviceNetworkEvents
    | where Timestamp > ago(timeframe)
    | where RemoteUrl has "wetransfer.com"
    | where InitiatingProcessFileName in~ (browser_processes)
    | project DownloadTime = Timestamp, DeviceName, RemoteUrl, DownloadInitiatingProcess = InitiatingProcessFileName;
let jpeg_writes =
    DeviceFileEvents
    | where Timestamp > ago(timeframe)
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FileName endswith ".jpg" or FileName endswith ".jpeg"
    | where FolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\")
    | project FileWriteTime = Timestamp, DeviceName, FileName, FolderPath, SHA256;
let process_spawns =
    DeviceProcessEvents
    | where Timestamp > ago(timeframe)
    | where FolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\")
    | project ExecTime = Timestamp, DeviceName, ExecFileName = FileName, ProcessCommandLine, ExecFolderPath = FolderPath, ExecInitiatingProcess = InitiatingProcessFileName;
wetransfer_downloads
| join kind=inner jpeg_writes on DeviceName
| where FileWriteTime between (DownloadTime .. (DownloadTime + 10m))
| join kind=inner process_spawns on DeviceName
| where ExecTime between (FileWriteTime .. (FileWriteTime + 5m))
| where ExecFolderPath == FolderPath
| project DownloadTime, FileWriteTime, ExecTime, DeviceName, RemoteUrl, DownloadInitiatingProcess, FileName, FolderPath, SHA256, ProcessCommandLine, ExecInitiatingProcess
| order by DownloadTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Users legitimately downloading JPEG images from WeTransfer followed by opening them in an image viewer that executes from the Downloads folder.
- Software installers or update packages that happen to be downloaded via WeTransfer and execute from Temp or Downloads.
- Browser-based image preview tools that spawn a process when a JPEG is written to disk.

Tuning notes:
- Adjust the 10-minute download-to-file-write window and 5-minute file-write-to-execution window based on observed user behavior in your environment.
- Add SHA256 exclusions for known-good files downloaded via WeTransfer once a baseline is established.
- Consider adding an InitiatingProcessFileName exclusion for known image viewer executables (e.g., Photos.exe, mspaint.exe) in the process_spawns branch to reduce false positives from normal image opening.

Risks / caveats:
- DeviceNetworkEvents.RemoteUrl is only populated when MDE resolves the HTTP layer; connections to wetransfer.com over HTTPS may not carry a resolvable RemoteUrl in all MDE versions, depending on TLS inspection configuration.
- DeviceFileEvents ActionType 'FileCreated' must be confirmed as the correct ActionType for file downloads in the deployed MDE version; some environments observe 'FileRenamed' for browser-downloaded files that are first written with a temporary extension.
- The join on DeviceName without a shared process ID or file path key between the download event and the file write event means any device with a WeTransfer download and any JPEG write in the same 10-minute window will match, even if they are unrelated.
- The ExecFolderPath == FolderPath join condition compares the process working directory to the file write directory, which may not match if the process is launched from a parent directory or a different path.

### Triage Runbook

First 15 minutes:
- Identify the recipient, sender, subject, and message timing of the email containing the WeTransfer link.
- Confirm whether the user clicked the link and whether the download was followed by file creation and execution on the same device.
- Check the downloaded file type, hash, and location to see whether it matches a suspicious JPEG or MSI-lure pattern.
- Look for immediate signs of execution such as new processes, child processes, or script activity from Downloads, Temp, or AppData.

Evidence to collect:
- Email headers, sender address, subject, and URL from the message containing the WeTransfer link.
- DeviceNetworkEvents showing the WeTransfer connection and the initiating browser process.
- DeviceFileEvents for the downloaded file, including filename, folder path, SHA256, and action type.
- DeviceProcessEvents showing any execution from the download path and the full command line.

Pivot points:
- Email or message trace logs to confirm delivery and click timing.
- DeviceNetworkEvents for connections to wetransfer.com or related CDN hostnames.
- DeviceFileEvents for files created or renamed in Downloads, Temp, or AppData after the click.
- DeviceProcessEvents for processes launched from the same directory as the downloaded file.

Benign explanations:
- A user legitimately received a file through WeTransfer and opened it normally.
- A business partner or internal team used WeTransfer for routine file sharing.
- A browser or download manager wrote a temporary file that was later opened by a standard application.

Escalation criteria:
- The downloaded file is followed by execution from the same path or by suspicious child processes.
- The file hash, filename, or lure content matches known malicious campaign behavior.
- Multiple users received similar WeTransfer emails or the sender is untrusted and the message is unexpected.
- The user reports unexpected prompts, installer behavior, or credential requests after opening the file.

Containment actions:
- If execution is confirmed or strongly suspected, isolate the endpoint from the network.
- Quarantine the downloaded file and any related artifacts from the user profile.
- Block the sender and the WeTransfer URL or domain at email and web controls if the campaign is active.
- Reset credentials only if there is evidence the user entered credentials into a malicious prompt or site.

Closure criteria:
- The email and download are confirmed as legitimate business activity with no suspicious execution.
- No malicious file hash, process chain, or follow-on network activity is found.
- The user did not execute the file or the execution is attributable to a benign application.
- Any required user awareness or mail filtering actions have been completed.

---

## Detection 4: JPEG File Written to User Directory Followed by Process Execution - MSI Lure Payload

### Detection Opportunity

A JPEG image file written to a user-accessible directory is followed by process execution originating from the same path, consistent with a payload embedded in an MSI-branded JPEG lure.

### Intelligence Context

- SANS ISC: The Evil MSI Background is Back! — [https://isc.sans.edu/diary/rss/33054](https://isc.sans.edu/diary/rss/33054)
  - Context: SANS ISC reported that the campaign payload was embedded inside a JPEG file styled as an MSI-branded background image. The JPEG served as a delivery container for an executable payload, with execution following the file write to a user directory.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: MSI
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, MSI, WeTransfer

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let timeframe = 7d;
let jpeg_writes =
    DeviceFileEvents
    | where Timestamp > ago(timeframe)
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FileName endswith ".jpg" or FileName endswith ".jpeg"
    | where FolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\")
    | project WriteTime = Timestamp, DeviceName, JpegFileName = FileName, JpegFolderPath = FolderPath, SHA256;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where FolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\")
| join kind=inner jpeg_writes on DeviceName
| where Timestamp between (WriteTime .. (WriteTime + 5m))
| where FolderPath == JpegFolderPath
| project
    WriteTime,
    ExecTime = Timestamp,
    DeviceName,
    AccountName,
    JpegFileName,
    JpegFolderPath,
    SHA256,
    ExecFileName = FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName
| order by WriteTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Software installation packages that write JPEG splash screens or assets to Temp and then execute an installer from the same directory.
- Image editing or conversion tools that write output JPEGs and immediately launch a viewer.
- Automated backup or sync tools that write JPEGs to AppData and spawn a sync process.

Tuning notes:
- Add an InitiatingProcessFileName exclusion list for known image viewer processes (e.g., Photos.exe, mspaint.exe, dllhost.exe) to reduce false positives from normal image opening behavior.
- Extend or reduce the 5-minute execution window based on observed payload behavior in your environment.
- Add SHA256 exclusions for known-good JPEG files identified during baseline review.
- Consider adding an AccountName filter to scope to standard user accounts and exclude service accounts that legitimately write to Temp directories.

Risks / caveats:
- DeviceFileEvents ActionType 'FileCreated' may not capture all browser download scenarios; some browsers write files with a temporary extension first and then rename them, producing a 'FileRenamed' ActionType instead. Including both ActionTypes is recommended.
- The FolderPath equality join between the process working directory and the JPEG write directory may miss cases where the process is launched from a subdirectory of the JPEG write path.
- The 5-minute execution window may miss delayed execution scenarios where the user opens the file manually after a longer delay.
- High-volume environments with frequent software installations writing to Temp directories will generate false positives that require allowlist tuning.

### Triage Runbook

First 15 minutes:
- Identify the user account, device, file path, and timestamp of the JPEG write and the subsequent process execution.
- Inspect the process tree to see what executable launched from the same directory and whether it is a known viewer, installer, or script.
- Check the file hash and filename for signs of a disguised payload, unusual extension behavior, or MSI-themed lure content.
- Review whether the activity was preceded by email, browser download, or archive extraction from the same source path.

Evidence to collect:
- DeviceFileEvents for the JPEG creation or rename event, including SHA256 and folder path.
- DeviceProcessEvents for the execution event, including command line, parent process, and initiating process.
- The exact file name, directory, and any adjacent files in the same folder that may indicate a staged payload.
- User activity context such as email, browser history, or download logs if available.

Pivot points:
- DeviceFileEvents for other files created in the same directory around the same time.
- DeviceProcessEvents for child processes spawned by the executable launched from the JPEG directory.
- DeviceNetworkEvents for outbound connections from the host after the file write and execution.
- Email or browser telemetry to determine whether the JPEG originated from a message or download.

Benign explanations:
- A legitimate image editor, viewer, or conversion tool wrote a JPEG and then launched a related process from the same folder.
- Software installation or extraction activity placed JPEG assets in Temp or Downloads before starting an installer.
- A user opened a downloaded image and the associated application spawned a helper process.

Escalation criteria:
- The launched process is not a known image viewer or installer and appears to be a payload or script.
- The JPEG hash, filename, or surrounding files suggest a lure or disguised executable content.
- There is follow-on network activity, persistence, or additional file creation after the execution.
- The same pattern appears on multiple hosts or user accounts in a short period.

Containment actions:
- If the launched process is suspicious, isolate the endpoint and preserve the file for analysis.
- Quarantine the JPEG and any related files from the user directory.
- Block any outbound connections observed after execution if they are clearly malicious.
- Escalate to incident response if the process tree indicates code execution beyond normal image handling.

Closure criteria:
- The executable is confirmed as a known-good viewer, installer, or helper process.
- The JPEG and surrounding activity are attributable to a benign workflow such as image editing or software installation.
- No suspicious child processes, persistence, or network activity are found.
- The file hash and path are documented and, if needed, added to an allowlist after validation.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- Apache ActiveMQ Jolokia addNetworkConnector RCE Attempt: CommonSecurityLog.DeviceProduct values for ActiveMQ or Jolokia are not standard CEF product strings; the has_any filter may match nothing if the forwarding device uses a different product identifier.
- WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain: Do not schedule yet; validate as an analyst-led hunt first.

Telemetry availability:
- Gogs Git Rebase Argument Injection via '--exec' Branch Name: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

Shared-table notes:
- DeviceNetworkEvents: shared by Apache ActiveMQ Jolokia addNetworkConnector RCE Attempt; WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain
- DeviceProcessEvents: shared by Gogs Git Rebase Argument Injection via '--exec' Branch Name; WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain; JPEG File Written to User Directory Followed by Process Execution - MSI Lure Payload
- DeviceFileEvents: shared by WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain; JPEG File Written to User Directory Followed by Process Execution - MSI Lure Payload

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: JPEG File Written to User Directory Followed by Process Execution - MSI Lure Payload.
2. Resolve environment-mapping detections next: Apache ActiveMQ Jolokia addNetworkConnector RCE Attempt; Gogs Git Rebase Argument Injection via '--exec' Branch Name.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain.

### Hunting Agenda and Promotion Criteria

- WeTransfer Link in Email Followed by File Download - Phishing Delivery Chain: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Apache ActiveMQ Jolokia addNetworkConnector RCE Attempt: CommonSecurityLog.DeviceProduct values for ActiveMQ or Jolokia are not standard CEF product strings; the has_any filter may match nothing if the forwarding device uses a different product identifier.; baseline expected benign activity and define an alert-volume threshold.
- Gogs Git Rebase Argument Injection via '--exec' Branch Name: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
