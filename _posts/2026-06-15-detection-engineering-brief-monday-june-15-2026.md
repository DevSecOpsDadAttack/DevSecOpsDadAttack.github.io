---
layout: post
title: "Detection Engineering Brief - Monday, June 15, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-15
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-35273
  - T1190
  - Oracle PeopleSoft
  - PeopleTools
  - Windows
  - T1059
  - T1218
  - T1218.007
---

## Executive Signal

This brief produced 4 detection candidates.

0 production candidates, 2 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-35273, T1190, Oracle PeopleSoft, PeopleTools, Windows, T1059, T1218, T1218.007.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-35273 PeopleSoft RCE - Suspicious Child Process Spawned from App Server; CVE-2026-35273 PeopleSoft RCE - Webshell or Payload Drop in Web Directory; CVE-2026-35273 PeopleSoft RCE - Compound Inbound Web Request Followed by Child Process Execution; Malicious MSI Execution Spawning Suspicious Child Process via msiexec.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: CVE-2026-35273 PeopleSoft RCE - Suspicious Child Process Spawned from App Server

### Detection Opportunity

Post-exploitation remote code execution spawning unexpected child processes from PeopleSoft application server process following active zero-day exploitation.

### Intelligence Context

- Rapid7: Active Exploitation of Oracle PeopleSoft Zero-Day (CVE-2026-35273) — [https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273](https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273)
  - Context: Rapid7 and Mandiant reported active exploitation of CVE-2026-35273, an unauthenticated RCE vulnerability in Oracle PeopleSoft. Successful exploitation results in remote code execution, typically manifesting as shell or scripting engine processes spawned as children of the PeopleSoft application server process.

### Search Metadata

- CVEs: CVE-2026-35273
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Oracle PeopleSoft, PeopleTools
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-35273, T1190, Oracle PeopleSoft, PeopleTools, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName has_any ("psappsrv.exe", "pswatchsrv.exe", "psadmin.exe")
    or (
        InitiatingProcessFileName =~ "java.exe"
        and InitiatingProcessFolderPath has_any ("peoplesoft", "psft", "pshome", "webserv")
    )
| where FileName has_any (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "bash", "sh", "python", "python3", "perl",
    "curl", "wget", "certutil.exe", "bitsadmin.exe"
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate PeopleSoft administrative scripts executed by administrators via the app server process during maintenance windows.
- Automated deployment or patching tooling that invokes cmd.exe or powershell.exe as a child of the PeopleSoft service account.
- Java-based monitoring agents that spawn shell processes for health checks if java.exe parent filter is not path-scoped.

Tuning notes:
- Replace InitiatingProcessFolderPath path fragments with the exact PeopleSoft installation directory observed in DeviceProcessEvents for the target host.
- Add DeviceName filter scoped to known PeopleSoft server hostnames to eliminate any residual cross-host false positives from java.exe.
- Consider excluding AccountName values corresponding to known PeopleSoft service accounts that legitimately invoke scripting tools.
- Extend lookback to 7d only during initial deployment baselining; revert to 1d for production scheduling.

Risks / caveats:
- InitiatingProcessFolderPath is used to narrow java.exe to PeopleSoft-specific installation paths; if MDE process telemetry does not populate this field for the PeopleSoft host, the java.exe parent filter will require removal or replacement with a device-name scope.
- DeviceProcessEvents requires Microsoft Defender for Endpoint P1/P2 licensing and sensor deployment on the PeopleSoft host; absence of the sensor means no telemetry will be present.
- The InitiatingProcessFolderPath strings (peoplesoft, psft, pshome, webserv) are common path fragment patterns but must be validated against the actual PeopleSoft installation directory in the target environment before scheduling.
- A 1-day lookback is appropriate for scheduled alerting; extend to 7d only for initial baselining or retrospective hunting.

### Triage Runbook

First 15 minutes:
- Confirm the alert is on a known PeopleSoft server and that the parent process path matches the expected PeopleSoft installation directory, not a generic Java application.
- Review the child process name and command line for obvious attacker tradecraft such as cmd.exe, powershell.exe, wscript.exe, cscript.exe, python, curl, wget, or certutil.
- Check the initiating account and domain to see whether the activity came from a service account, deployment account, or an interactive administrator session.
- Look for nearby process activity on the same host within the last 30 minutes, especially additional script interpreters, archive tools, download utilities, or credential access behavior.
- If the child process command line shows payload execution, encoded commands, or network retrieval, treat as likely compromise and escalate immediately.

Evidence to collect:
- DeviceName, Timestamp, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256.
- Any preceding or subsequent process tree entries on the same host that show the same parent spawning multiple suspicious children.
- PeopleSoft server hostname, role, and whether the time of alert overlaps with a maintenance window or deployment activity.
- Any related network connections from the same host around the alert time, especially outbound connections to unfamiliar IPs or domains.
- Any file writes or new files created in the PeopleSoft web or application directories around the same time.

Pivot points:
- DeviceProcessEvents for the same DeviceName and a 1- to 24-hour window around the alert to reconstruct the process tree.
- DeviceNetworkEvents for the same DeviceName and alert window to identify outbound connections after process spawn.
- DeviceFileEvents for the same DeviceName to check for dropped webshells, scripts, or payloads in PeopleSoft paths.
- Identity and sign-in telemetry for AccountName and AccountDomain to determine whether the account was used interactively or anomalously.

Benign explanations:
- Planned PeopleSoft maintenance or patching that legitimately invokes scripting tools from the application server.
- Administrative automation that uses the app server account to run cmd.exe, powershell.exe, or similar tools during deployment.
- Java-based monitoring or orchestration tooling on the same host that spawns shell processes for health checks or housekeeping.

Escalation criteria:
- The child process is a shell, scripting engine, or downloader with a suspicious command line, especially if it references remote content or encoded commands.
- The same host shows multiple suspicious child processes, outbound connections to unknown infrastructure, or file writes to PeopleSoft web directories.
- The initiating account is unexpected, interactive, or not a known PeopleSoft service or deployment account.
- The alert occurs outside a maintenance window and there is no approved change record explaining the activity.

Containment actions:
- Isolate the PeopleSoft host from the network if the child process command line indicates payload execution, remote access, or follow-on tooling.
- Disable or reset credentials for any account observed executing suspicious commands if it is not a tightly controlled service account.
- Preserve volatile evidence before rebooting, including running processes, network connections, and command lines.
- Block any confirmed malicious outbound IPs or domains if they are identified during triage.

Closure criteria:
- The process tree is fully explained by a documented maintenance or deployment activity and no other suspicious host activity is present.
- The parent path, account, and command line match known-good PeopleSoft operational behavior after validation with the application owner.
- No suspicious network, file, or additional process activity is found on the host during the alert window.
- Any false-positive pattern is documented for future allowlisting or tuning.

---

## Detection 2: CVE-2026-35273 PeopleSoft RCE - Webshell or Payload Drop in Web Directory

### Detection Opportunity

File write to PeopleSoft web directories by the application server process following unauthenticated inbound exploitation attempt, consistent with webshell or payload staging.

### Intelligence Context

- Rapid7: Active Exploitation of Oracle PeopleSoft Zero-Day (CVE-2026-35273) — [https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273](https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273)
  - Context: Active exploitation of CVE-2026-35273 enables unauthenticated RCE against PeopleSoft web-facing components. Post-exploitation activity may include writing webshells or payloads to PeopleSoft web root directories, initiated by the application server process account.

### Search Metadata

- CVEs: CVE-2026-35273
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Oracle PeopleSoft, PeopleTools
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-35273, T1190, Oracle PeopleSoft, PeopleTools, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated", "FileModified")
| where (
    InitiatingProcessFileName has_any ("psappsrv.exe", "pswatchsrv.exe", "psadmin.exe")
    or (
        InitiatingProcessFileName =~ "java.exe"
        and InitiatingProcessFolderPath has_any ("peoplesoft", "psft", "pshome", "webserv")
    )
  )
| where (
    FileName has_any (".jsp", ".jspx", ".war", ".php", ".aspx", ".asp", ".py", ".sh", ".pl")
    or FolderPath has_any ("peoplesoft", "psigw", "psc", "psp", "webserv")
  )
| project
    Timestamp,
    DeviceName,
    FolderPath,
    FileName,
    SHA256,
    FileSize,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessAccountName,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate PeopleSoft application deployments or patch installations that write JSP or WAR files to the web directory.
- Automated build or CI/CD pipeline activity that deploys PeopleSoft components via the application server process account.
- Java application server log rotation or configuration writes that match the FolderPath patterns.

Tuning notes:
- Replace FolderPath and InitiatingProcessFolderPath fragment strings with the exact directory paths observed in DeviceFileEvents for the PeopleSoft host.
- Add DeviceName filter scoped to known PeopleSoft server hostnames to eliminate cross-host false positives.
- Exclude InitiatingProcessAccountName values corresponding to known deployment service accounts during confirmed maintenance windows.
- Consider adding a SHA256 allowlist for known-good PeopleSoft deployment artifacts to suppress recurring false positives.

Risks / caveats:
- DeviceFileEvents requires MDE sensor deployment on the PeopleSoft host with file event telemetry enabled; file write events may not be collected if the sensor is in passive or limited mode.
- FileSize is a standard DeviceFileEvents field but may be null for some ActionType values depending on MDE sensor version; query handles this gracefully by projecting rather than filtering on it.
- InitiatingProcessFolderPath availability depends on MDE sensor version; if absent, the java.exe path-scoping condition will not filter correctly.
- FolderPath fragment strings (peoplesoft, psigw, psc, psp, webserv) must be validated against the actual PeopleSoft web root directory structure in the target environment before scheduling.

### Triage Runbook

First 15 minutes:
- Validate the file path and extension to see whether the write landed in a web root or PeopleSoft application directory and whether the file type is executable or scriptable.
- Check the initiating process and account to confirm the write came from the expected PeopleSoft application server process and service account.
- Inspect the file name, size, and SHA256 to determine whether it looks like a real application artifact, an empty placeholder, or a suspicious payload.
- Review nearby file events for the same host to see whether multiple files were created or modified in a short burst.
- If the file is a JSP, WAR, PHP, ASP, script, or other executable web content and is not part of a known deployment, escalate as likely compromise.

Evidence to collect:
- DeviceName, Timestamp, FolderPath, FileName, SHA256, FileSize, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName.
- A copy or hash of the dropped file if available through endpoint response or file retrieval tooling.
- The surrounding file activity on the same host, including whether the file was created, modified, renamed, or followed by execution.
- The maintenance or deployment record for the PeopleSoft server covering the alert time.
- Any related process or network activity from the same host that suggests payload staging or webshell use.

Pivot points:
- DeviceFileEvents for the same DeviceName and a 1- to 24-hour window to identify additional file writes in the same directory.
- DeviceProcessEvents for the same DeviceName to see whether the dropped file was later executed or loaded by a script interpreter.
- DeviceNetworkEvents for the same DeviceName to identify outbound connections after the file write.
- File reputation or sandboxing workflow using the SHA256 if the file is not a known-good deployment artifact.

Benign explanations:
- Legitimate PeopleSoft patching or application deployment that writes JSP, WAR, or related web content to the web directory.
- Automated build or release tooling that stages application files through the PeopleSoft server account.
- Configuration or log management activity that modifies files in directories matching the PeopleSoft path fragments.

Escalation criteria:
- The file is a webshell, script, or payload and is not part of an approved deployment package.
- The file appears in a web-accessible directory with a suspicious name, unusual size, or unknown hash.
- There are multiple file writes, follow-on process spawns, or outbound connections from the same host around the same time.
- The initiating account is not a known deployment or service account, or the activity occurred outside a maintenance window.

Containment actions:
- Quarantine or isolate the host if the dropped file is suspicious and not immediately explainable by a known change.
- Remove or disable web-access to the suspicious file only after preserving evidence and confirming with incident response.
- Block execution or access to the file hash if it is confirmed malicious.
- Reset credentials for any account used in the write if compromise is suspected.

Closure criteria:
- The file is confirmed as a legitimate deployment artifact or maintenance-related write by the application owner.
- The file hash matches a known-good package and the directory placement is expected for the change.
- No additional suspicious file, process, or network activity is found on the host.
- The event is documented as a benign deployment pattern and tuning feedback is captured.

---

## Detection 3: CVE-2026-35273 PeopleSoft RCE - Compound Inbound Web Request Followed by Child Process Execution

### Detection Opportunity

Correlation of inbound unauthenticated network connection to PeopleSoft service port followed within a short window by a suspicious child process spawned on the same host, indicating successful exploitation of CVE-2026-35273.

### Intelligence Context

- Rapid7: Active Exploitation of Oracle PeopleSoft Zero-Day (CVE-2026-35273) — [https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273](https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273)
  - Context: Mandiant and Rapid7 confirmed active exploitation of CVE-2026-35273 as an unauthenticated remote exploit against PeopleSoft web components resulting in RCE. The compound signal of an inbound external connection to PeopleSoft followed by a shell process spawn on the same host provides higher-confidence detection than either signal alone.

### Search Metadata

- CVEs: CVE-2026-35273
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Oracle PeopleSoft, PeopleTools
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-35273, T1190, Oracle PeopleSoft, PeopleTools, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let PeopleSoftPorts = dynamic([80, 443, 8080, 8443]);
let LookbackWindow = ago(7d);
let CorrelationWindowMinutes = 5m;
let InboundConnections =
    DeviceNetworkEvents
    | where Timestamp > LookbackWindow
    | where ActionType == "InboundConnectionAccepted"
    | where LocalPort in (PeopleSoftPorts)
    | where RemoteIPType == "Public"
    | project DeviceName, ConnectionTime = Timestamp, RemoteIP, LocalPort;
let SuspiciousProcesses =
    DeviceProcessEvents
    | where Timestamp > LookbackWindow
    | where (
        InitiatingProcessFileName has_any ("psappsrv.exe", "pswatchsrv.exe", "psadmin.exe")
        or (
            InitiatingProcessFileName =~ "java.exe"
            and InitiatingProcessFolderPath has_any ("peoplesoft", "psft", "pshome", "webserv")
        )
      )
    | where FileName has_any (
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "bash", "sh", "python", "python3",
        "wscript.exe", "cscript.exe"
      )
    | project
        DeviceName,
        ProcessTime = Timestamp,
        InitiatingProcessFileName,
        InitiatingProcessFolderPath,
        FileName,
        ProcessCommandLine,
        AccountName,
        AccountDomain,
        SHA256;
InboundConnections
| join kind=inner SuspiciousProcesses on DeviceName
| where ProcessTime between (ConnectionTime .. (ConnectionTime + CorrelationWindowMinutes))
| extend TimeDeltaSeconds = datetime_diff('second', ProcessTime, ConnectionTime)
| project
    ConnectionTime,
    ProcessTime,
    TimeDeltaSeconds,
    DeviceName,
    RemoteIP,
    LocalPort,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    FileName,
    ProcessCommandLine,
    SHA256
| order by ConnectionTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate external web traffic to PeopleSoft coinciding with scheduled administrative scripts run by the app server process account.
- Security scanning tools that connect to PeopleSoft ports and trigger process spawning on the host within the correlation window.
- Load balancer health checks from public IP ranges coinciding with maintenance scripting activity.
- Non-PeopleSoft Java services on the same host that spawn shell processes for legitimate reasons if InitiatingProcessFolderPath scoping is insufficient.

Tuning notes:
- Add an explicit DeviceName filter on both sub-queries scoped to known PeopleSoft server hostnames to reduce query cost and false-positive volume.
- Reduce CorrelationWindowMinutes to 2m after baselining if legitimate admin activity generates false positives in the 2-5 minute range.
- If the environment uses a reverse proxy, replace RemoteIPType == Public with a filter excluding known internal proxy IP ranges.
- Add non-standard PeopleSoft service ports to PeopleSoftPorts if the deployment uses custom port assignments.

Risks / caveats:
- DeviceNetworkEvents ActionType value InboundConnectionAccepted requires MDE network inspection to be enabled on the PeopleSoft host; if network telemetry is in audit-only or disabled mode, this sub-query will return no results and the join will produce no output.
- RemoteIPType field classification as Public depends on MDE IP categorization; private RFC1918 addresses used by load balancers or reverse proxies in front of PeopleSoft will be classified as Private and excluded, potentially missing exploitation traffic that traverses internal infrastructure.
- If PeopleSoft is deployed behind a reverse proxy or load balancer, inbound connections from the proxy will appear as Private IP type and will be excluded by the RemoteIPType == Public filter, potentially missing exploitation traffic; consider adding the proxy IP range as an additional filter condition.
- The port list (80, 443, 8080, 8443) is generic; if PeopleSoft uses non-standard ports in the target environment, those ports must be added to PeopleSoftPorts.

### Triage Runbook

First 15 minutes:
- Verify the source IP, destination port, and timing relationship between the inbound connection and the suspicious child process.
- Check whether the inbound connection came from a public IP, a reverse proxy, a load balancer, or an internal scanner that could explain the traffic.
- Review the child process command line and parent process path to determine whether the spawned process is consistent with exploitation or normal admin activity.
- Look for additional signs of compromise on the same host, including outbound connections, file writes, or repeated shell launches.
- If the connection-to-process timing is tight and the child process is a shell, scripting engine, or downloader, escalate as probable exploitation.

Evidence to collect:
- ConnectionTime, ProcessTime, TimeDeltaSeconds, DeviceName, RemoteIP, LocalPort, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine, SHA256.
- Any other inbound connections to the same host around the alert time, including repeated attempts from the same source IP.
- Any outbound network activity from the host after the suspicious process spawn.
- Any file creation or modification events on the host that could indicate payload staging or webshell deployment.
- The PeopleSoft host role, exposed ports, and whether a reverse proxy or load balancer sits in front of the service.

Pivot points:
- DeviceNetworkEvents for the same DeviceName to review inbound and outbound traffic around the alert window.
- DeviceProcessEvents for the same DeviceName to reconstruct the process tree and identify follow-on execution.
- DeviceFileEvents for the same DeviceName to check for dropped payloads or webshells.
- Proxy, firewall, or load balancer logs to validate whether the RemoteIP is the true client or an intermediary.

Benign explanations:
- Legitimate external web traffic to PeopleSoft coinciding with scheduled administrative scripting on the host.
- Health checks, vulnerability scans, or load balancer traffic that happen near normal maintenance activity.
- Non-PeopleSoft Java services on the same host if the path scoping is not sufficiently precise.

Escalation criteria:
- The inbound connection is from an untrusted public IP and the process spawn occurs within the correlation window.
- The spawned process is a shell, scripting engine, or downloader with suspicious arguments or network retrieval behavior.
- There is corroborating evidence such as file writes, repeated process spawns, or outbound connections to unknown infrastructure.
- The activity is outside a maintenance window and cannot be tied to an approved change or scanner.

Containment actions:
- Isolate the host if the correlation strongly indicates exploitation and the child process is clearly malicious.
- Block the source IP or related infrastructure if it is confirmed malicious and not a shared proxy or scanner.
- Preserve process, network, and file evidence before remediation actions that could destroy forensic data.
- Disable or reset any account used by the suspicious process if it is not a controlled service account.

Closure criteria:
- The inbound connection is explained by a known proxy, scanner, or maintenance activity and no suspicious process behavior is present.
- The process spawn is validated as legitimate administrative activity with supporting change evidence.
- No additional host compromise indicators are found in process, file, or network telemetry.
- The event is documented with the confirmed benign source and any tuning updates needed for future alerts.

---

## Detection 4: Malicious MSI Execution Spawning Suspicious Child Process via msiexec

### Detection Opportunity

Malicious MSI file executed on a Windows endpoint via msiexec.exe spawning unexpected child processes, consistent with MSI-packaged malware delivery as described in SANS ISC analysis of evil MSI content.

### Intelligence Context

- SANS ISC: Evil MSI Background: BASE64 Statistical Analysis, (Mon, Jun 15th) — [https://isc.sans.edu/diary/rss/33072](https://isc.sans.edu/diary/rss/33072)
  - Context: SANS ISC published analysis of malicious MSI files containing embedded content, including Base64-encoded payloads. The operational behavior of concern is msiexec.exe spawning shell or scripting engine child processes outside of normal software deployment patterns, which indicates MSI-packaged malware execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1218, T1218.007, T1059
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, T1218, T1218.007, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1218 System Binary Proxy Execution/ T1218.007 Msiexec (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "msiexec.exe"
| where FileName has_any (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "curl.exe", "wget.exe", "certutil.exe",
    "bitsadmin.exe", "regsvr32.exe", "rundll32.exe"
  )
| where (
    ProcessCommandLine has_any (
        "-enc", "-EncodedCommand", "FromBase64", "iex ",
        "Invoke-Expression", "http://", "https://", "ftp://"
    )
    or (
        FileName has_any ("cmd.exe", "powershell.exe", "pwsh.exe")
        and ProcessCommandLine matches regex @"[A-Za-z0-9+/]{40,}={0,2}"
    )
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Enterprise software deployment tools that invoke powershell.exe with encoded commands as part of legitimate MSI post-install scripts.
- Security tooling installers that use certutil.exe or bitsadmin.exe for component download during installation.
- IT automation platforms that deploy software via msiexec and use Base64-encoded configuration payloads in post-install scripts.
- Software packaging tools that embed long Base64 strings in installer command lines for legitimate configuration purposes.

Tuning notes:
- Add AccountName exclusions for known software deployment service accounts to suppress recurring false positives from patch management tooling.
- Increase the Base64 regex minimum length from 40 to 60 or higher to reduce matches on short encoded strings in legitimate installer arguments.
- Add InitiatingProcessFolderPath =~ 'C:\\Windows\\System32' to restrict msiexec parent to the expected system location and flag unusual msiexec paths as a separate signal.
- Reduce lookback to 1d and schedule at higher frequency if promoting to a scheduled rule after allowlist tuning.

Risks / caveats:
- DeviceProcessEvents requires MDE P1/P2 licensing and sensor deployment on Windows endpoints; Linux and macOS are not covered by this query.
- The matches regex operator with a complex pattern may time out or be rejected on very large DeviceProcessEvents datasets; if query performance is poor, the regex condition should be moved to a post-filter after the has_any conditions reduce the result set.
- The Base64 regex heuristic will match any 40+ character alphanumeric string with optional padding, which includes legitimate encoded configuration data in enterprise installer scripts; analyst review of each result is required.
- Environments with high-volume software deployment activity will generate elevated result counts during patch cycles; time-scoping the hunt to non-maintenance periods improves signal quality.

### Triage Runbook

First 15 minutes:
- Confirm the parent process is msiexec.exe and review the full command line to see whether it references a local MSI, a network location, or encoded content.
- Inspect the child process command line for indicators of malicious execution such as -enc, -EncodedCommand, Invoke-Expression, URL retrieval, or Base64 blobs.
- Check the account context to determine whether the MSI was launched by a user, software deployment tool, or service account.
- Look for additional child processes from the same msiexec instance, especially powershell.exe, cmd.exe, wscript.exe, cscript.exe, certutil.exe, or bitsadmin.exe.
- If the child process is clearly malicious or the MSI source is unknown, escalate immediately and treat the endpoint as potentially compromised.

Evidence to collect:
- Timestamp, DeviceName, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256.
- The MSI file path or source location if visible in the command line or surrounding telemetry.
- Any additional child processes spawned by the same msiexec.exe instance.
- Any network connections made by the child process, especially to external IPs or domains.
- Any file writes, registry changes, or persistence artifacts created after the MSI execution.

Pivot points:
- DeviceProcessEvents for the same DeviceName and account to reconstruct the full msiexec process tree.
- DeviceNetworkEvents for the same DeviceName to identify outbound connections from the child process.
- DeviceFileEvents and registry-related telemetry, if available, to look for dropped payloads or persistence.
- Endpoint response or file retrieval workflow to inspect the MSI hash and contents if the source file is accessible.

Benign explanations:
- Legitimate software deployment or patching that uses msiexec with post-install scripts.
- Enterprise automation that launches PowerShell or cmd.exe from an MSI for configuration tasks.
- Installer packages that legitimately contain encoded configuration data or download components during setup.

Escalation criteria:
- The child process command line contains encoded commands, remote download behavior, or obvious malware execution patterns.
- The MSI source is untrusted, downloaded from the internet, or not associated with an approved software deployment.
- The same host shows outbound connections, persistence, or additional suspicious child processes after msiexec execution.
- The activity occurs on a user endpoint outside a normal software deployment window and cannot be explained by IT operations.

Containment actions:
- Isolate the endpoint if the MSI execution is clearly malicious or if follow-on activity indicates compromise.
- Terminate the suspicious child process and any related process tree if containment is required and evidence has been captured.
- Block the MSI hash and any confirmed malicious child process hashes or network destinations.
- Reset credentials if the execution was launched under a compromised user or service account.

Closure criteria:
- The msiexec activity is confirmed as a known-good software deployment with matching change records and trusted source.
- The child process command line is explained by approved installer behavior and no other suspicious telemetry is present.
- No persistence, outbound C2, or additional malicious process activity is found on the endpoint.
- Any recurring benign pattern is documented for allowlisting or tuning.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Licensing / identity risk fields:
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

Other deployment dependency:
- CVE-2026-35273 PeopleSoft RCE - Webshell or Payload Drop in Web Directory: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Schema / correlation keys:
- CVE-2026-35273 PeopleSoft RCE - Compound Inbound Web Request Followed by Child Process Execution: Do not schedule yet; validate as an analyst-led hunt first.
- Malicious MSI Execution Spawning Suspicious Child Process via msiexec: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceProcessEvents: shared by CVE-2026-35273 PeopleSoft RCE - Suspicious Child Process Spawned from App Server; CVE-2026-35273 PeopleSoft RCE - Compound Inbound Web Request Followed by Child Process Execution; Malicious MSI Execution Spawning Suspicious Child Process via msiexec

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: CVE-2026-35273 PeopleSoft RCE - Suspicious Child Process Spawned from App Server; CVE-2026-35273 PeopleSoft RCE - Webshell or Payload Drop in Web Directory.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: CVE-2026-35273 PeopleSoft RCE - Compound Inbound Web Request Followed by Child Process Execution; Malicious MSI Execution Spawning Suspicious Child Process via msiexec.

### Hunting Agenda and Promotion Criteria

- CVE-2026-35273 PeopleSoft RCE - Compound Inbound Web Request Followed by Child Process Execution: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Malicious MSI Execution Spawning Suspicious Child Process via msiexec: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-35273 PeopleSoft RCE - Suspicious Child Process Spawned from App Server: Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-35273 PeopleSoft RCE - Webshell or Payload Drop in Web Directory: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
