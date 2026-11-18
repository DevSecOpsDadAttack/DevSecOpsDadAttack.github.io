---
layout: post
title: "Detection Engineering Brief - Wednesday, November 18, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-18
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - GitHub
  - cloud services
  - GitDoor
  - CVE-2026-114938
  - OpenJDK
  - Oracle Java SE
  - Oracle GraalVM
  - Java 17
  - Java
  - AuditTeam
  - OpsAgent
  - Rust
  - GraphDoor
  - T1055
  - T1059
  - T1059.006
  - T1203
  - T1486
  - T1036
  - T1102
  - T1102.002
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 4 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: GitHub, cloud services, GitDoor, CVE-2026-114938, OpenJDK, Oracle Java SE, Oracle GraalVM, Java 17, Java, AuditTeam, OpsAgent, Rust, GraphDoor, T1055, T1059, T1059.006, T1203, T1486, T1036, T1102, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: GitDoor C2 - Non-Browser Process Connecting to GitHub API; GitDoor - Shellcode Injection from Suspicious Process; CVE-2026-114938 - Java Process Spawning Unexpected Child Process After Inbound Connection; GraphDoor C2 - Non-Office Process Connecting to Microsoft Graph API.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: GitDoor C2 - Non-Browser Process Connecting to GitHub API

### Detection Opportunity

GitDoor backdoor using GitHub as command-and-control infrastructure, initiated from non-browser processes.

### Intelligence Context

- Securelist: Operation ShadowCloud: cloud service-based backdoors targeting government networks in Asia and Africa. Part 1 — [https://securelist.com/operation-shadowcloud-gitdoor/122004/](https://securelist.com/operation-shadowcloud-gitdoor/122004/)
  - Context: The GitDoor backdoor uses GitHub as its C2 channel. Reporting confirms outbound connections to GitHub API endpoints initiated by the malware process rather than a legitimate browser or developer tool.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055
- Products: GitHub
- Platforms: cloud services
- Malware: GitDoor
- Tools: Not specified
- Search tags: GitHub, cloud services, GitDoor, T1055

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Defense Evasion: T1055 Process Injection (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let KnownBrowsers = dynamic(["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "safari.exe", "opera.exe", "msedgewebview2.exe"]);
let KnownDevTools = dynamic(["git.exe", "gh.exe", "code.exe", "node.exe", "python.exe", "python3.exe", "curl.exe", "wget.exe", "hub.exe", "github desktop.exe"]);
let SuspiciousPaths = dynamic(["\\temp\\", "\\appdata\\local\\", "\\appdata\\roaming\\", "\\users\\public\\", "\\programdata\\"]);
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has "api.github.com" or RemoteUrl has "raw.githubusercontent.com"
| where not(InitiatingProcessFileName in~ (KnownBrowsers))
| where not(InitiatingProcessFileName in~ (KnownDevTools))
| where SuspiciousPaths has_any (tolower(InitiatingProcessFolderPath))
    or SuspiciousPaths has_any (tolower(InitiatingProcessCommandLine))
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    RemoteUrls = make_set(RemoteUrl, 20)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| where ConnectionCount >= 2
| project FirstSeen, LastSeen, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ConnectionCount, RemoteUrls
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Custom enterprise developer tools, CI/CD agents, or automation scripts not in the KnownDevTools list that legitimately call GitHub API.
- Security tooling or EDR agents that perform GitHub-based update checks.
- Electron-based applications that embed Chromium but do not use chrome.exe as the process name.

**Tuning notes:**
- Expand KnownDevTools to include any custom enterprise automation or scripting tools that call GitHub API.
- If false positive volume from AppData is high due to Electron apps, add specific process names to KnownBrowsers rather than removing the path filter.
- Consider adding a filter for InitiatingProcessIntegrityLevel == 'Low' or 'Medium' to further prioritize suspicious processes.

**Risks / caveats:**
- RemoteUrl population for HTTPS connections depends on Defender for Endpoint network inspection being enabled; if SSL inspection is not configured, RemoteUrl may be empty for many connections.
- KnownDevTools list requires expansion to match all approved developer tooling in the target environment before scheduling as a rule.
- The 7-day lookback window may miss low-frequency C2 polling; consider extending to 14 or 30 days for periodic hunting.
- has_any on tolower(InitiatingProcessFolderPath) performs a substring match; paths that partially match a legitimate directory name may be incorrectly included.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process name, command line, and folder path are not an approved browser, developer tool, CI/CD agent, or security product.
- Check whether the same process made multiple GitHub API connections and whether the activity is periodic or clustered.
- Review the host for concurrent suspicious process behavior such as unusual child processes, script execution, or injection-related telemetry.
- Identify whether the device is a developer workstation, build host, or automation server that may legitimately use GitHub API.

**Evidence to collect:**
- Device name, initiating process file name, folder path, command line, first seen, last seen, and connection count.
- Remote URLs contacted, including whether the traffic is to api.github.com or raw.githubusercontent.com.
- Any related DeviceProcessEvents showing the same process spawning shells, scripting engines, or network utilities.
- User context and device role to determine whether GitHub access is expected.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessFileName over the last 7-30 days.
- DeviceProcessEvents for the same device and time window to look for child processes or suspicious command lines.
- DeviceFileEvents for the same process path to check for dropped binaries or recent file modifications.
- Defender XDR device timeline or advanced hunting pivots from the host entity to related alerts and process trees.

**Benign explanations:**
- Approved developer tooling such as git.exe, gh.exe, code.exe, or automation scripts calling GitHub API.
- Electron-based applications or enterprise tools that embed Chromium and legitimately use GitHub endpoints.
- Security or update agents that check GitHub for releases or signatures.
- A browser-like process name not included in the allowlist but still representing a legitimate application.

**Escalation criteria:**
- The process is unknown, unsigned, or running from Temp, AppData, ProgramData, or Public and is not an approved tool.
- The same host also shows injection, shellcode, suspicious child processes, or other malware-like behavior.
- Connections are repeated and appear beacon-like, especially if the process is not associated with development or automation.
- The host is non-developer, internet-exposed, or contains sensitive data and the activity cannot be explained quickly.

**Containment actions:**
- If the process is unapproved and the host shows additional malicious behavior, isolate the device from the network.
- Terminate the suspicious process only after preserving evidence and confirming it is not a business-critical tool.
- Block the process hash or path if available and validated as malicious.
- Reset credentials for the logged-on user if there is evidence of compromise or token theft.

**Closure criteria:**
- The process is confirmed as an approved developer, automation, or security tool and the activity matches documented behavior.
- No additional suspicious telemetry is found on the host and the process path/command line is consistent with normal operations.
- The detection is attributed to a known benign application and added to the local tuning/allowlist process.
- No repeated GitHub API activity remains after the observation window and there is no evidence of malware execution.

<br/>
---
<br/>

## Detection 2: GitDoor - Shellcode Injection from Suspicious Process

### Detection Opportunity

GitDoor loading shellcode families via process injection techniques during infection.

### Intelligence Context

- Securelist: Operation ShadowCloud: cloud service-based backdoors targeting government networks in Asia and Africa. Part 1 — [https://securelist.com/operation-shadowcloud-gitdoor/122004/](https://securelist.com/operation-shadowcloud-gitdoor/122004/)
  - Context: The GitDoor backdoor loads shellcode families as part of its infection chain. Reporting explicitly identifies shellcode loading as a core component of the malware's execution flow.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055
- Products: GitHub
- Platforms: cloud services
- Malware: GitDoor
- Tools: Not specified
- Search tags: GitHub, cloud services, GitDoor, T1055

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1055 Process Injection (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceEvents, DeviceNetworkEvents

### KQL

```kql
let SuspiciousPaths = dynamic(["\\temp\\", "\\appdata\\local\\", "\\appdata\\roaming\\", "\\users\\public\\", "\\programdata\\"]);
let InjectionEvents =
    DeviceEvents
    | where Timestamp >= ago(7d)
    | where ActionType in ("CreateRemoteThreadApiCall", "ShellcodeInjection", "ProcessInjection")
    | where SuspiciousPaths has_any (tolower(InitiatingProcessFolderPath))
        or SuspiciousPaths has_any (tolower(InitiatingProcessCommandLine))
    | project
        InjectionTime = Timestamp,
        DeviceName,
        InjectionProcessName = InitiatingProcessFileName,
        InjectionProcessCommandLine = InitiatingProcessCommandLine,
        InjectionFolderPath = InitiatingProcessFolderPath,
        InjectionActionType = ActionType,
        InjectionProcessId = InitiatingProcessId;
let GitHubC2 =
    DeviceNetworkEvents
    | where Timestamp >= ago(7d)
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl has "api.github.com" or RemoteUrl has "raw.githubusercontent.com"
    | project
        NetTime = Timestamp,
        DeviceName,
        RemoteUrl,
        NetworkProcessName = InitiatingProcessFileName;
InjectionEvents
| join kind=inner GitHubC2 on DeviceName
| where NetTime >= InjectionTime and NetTime <= InjectionTime + 10m
| project
    InjectionTime,
    NetTime,
    DeviceName,
    InjectionProcessName,
    InjectionProcessCommandLine,
    InjectionFolderPath,
    InjectionActionType,
    InjectionProcessId,
    RemoteUrl,
    NetworkProcessName
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security agents and EDR products that use CreateRemoteThread for legitimate monitoring may trigger injection ActionTypes.
- Software installers running from AppData that perform in-memory operations followed by update checks to GitHub.
- Development tools that use injection-like techniques for debugging and also call GitHub APIs.

**Tuning notes:**
- Verify CreateRemoteThreadApiCall, ShellcodeInjection, and ProcessInjection ActionType values are present in DeviceEvents before relying on this detection.
- Consider narrowing the join by also matching on InitiatingProcessId between injection and network events if the same process initiates both.
- Add exclusions for known security agent process names if they generate CreateRemoteThreadApiCall events at high volume.

**Risks / caveats:**
- ShellcodeInjection and ProcessInjection ActionType values in DeviceEvents are not universally available; availability depends on Defender for Endpoint sensor version and Windows version. Verify these ActionType values exist in the environment before scheduling.
- RemoteUrl population for HTTPS connections depends on Defender for Endpoint network inspection being enabled.
- The 10-minute correlation window is a heuristic; GitDoor's actual dwell time between injection and first C2 beacon may differ.
- The join on DeviceName alone may produce false correlations on high-activity devices with many injection-like events and frequent GitHub connections.

### Triage Runbook

**First 15 minutes:**
- Treat as likely compromise until disproven because injection plus GitHub C2 is a strong malware pattern.
- Confirm the injection event type, source process path, and whether the process ran from a user-writable directory.
- Check the time-ordered sequence: injection event first, then outbound GitHub API traffic within the correlation window.
- Look for additional signs of post-exploitation activity on the same host, including new child processes, persistence, or credential access.

**Evidence to collect:**
- Injection time, network time, device name, injection action type, process name, command line, and process ID.
- Remote URL and the process name responsible for the GitHub connection.
- Process tree around the injection event, including parent and child processes.
- Any related alerts, file drops, registry changes, or scheduled task creation on the same device.

**Pivot points:**
- DeviceEvents for the same DeviceName and InitiatingProcessId to validate the injection sequence and related actions.
- DeviceNetworkEvents for the same device to identify other suspicious outbound destinations or repeated GitHub polling.
- DeviceProcessEvents for the same time window to reconstruct the process tree and spawned children.
- DeviceFileEvents and DeviceRegistryEvents for persistence artifacts or dropped payloads.

**Benign explanations:**
- Legitimate security software or EDR components using remote thread or injection-like techniques for monitoring.
- Software installers or debuggers that perform in-memory operations and then contact update services.
- Developer or diagnostic tools that use advanced process manipulation and also access GitHub for updates.
- False-positive ActionType values on certain sensor versions or OS builds.

**Escalation criteria:**
- The process is unknown, unsigned, or executing from Temp, AppData, Public, or ProgramData.
- The host shows additional malicious behavior such as persistence, credential dumping, or multiple suspicious network destinations.
- The same process or host has repeated injection events or repeated GitHub API connections.
- The device is a server or privileged workstation where injection behavior is not expected.

**Containment actions:**
- Isolate the host if the process is not an approved security or diagnostic tool and the behavior is unexplained.
- Kill the suspicious process only after capturing volatile evidence and confirming it is not a sanctioned agent.
- Block the binary or hash and remove any persistence found during triage.
- Reset impacted user credentials if the host shows signs of interactive compromise.

**Closure criteria:**
- The injection event is confirmed to be from a sanctioned security, debugging, or monitoring tool.
- No corroborating malicious activity is found in process, file, registry, or network telemetry.
- The GitHub traffic is attributable to a known benign application and the event is documented for tuning.
- The host is clean after follow-up review and no further injection or C2 activity is observed.

<br/>
---
<br/>

## Detection 3: CVE-2026-114938 - Java Process Spawning Unexpected Child Process After Inbound Connection

### Detection Opportunity

Unauthenticated remote code execution via CVE-2026-114938 resulting in Java spawning unexpected child processes post-exploitation.

### Intelligence Context

- Rapid7: CVE-2026-114938: Reported Critical Pre-authentication Remote Code Execution in Java 17 — [https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17](https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17)
  - Context: CVE-2026-114938 allows an unauthenticated remote attacker to execute code within a Java process via a heap-based buffer overflow in the hardware-accelerated Base64 decoder. Post-exploitation, the Java process may spawn child processes or initiate outbound connections indicative of code execution.

### Search Metadata

- CVEs: CVE-2026-114938
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.006, T1203
- Products: OpenJDK, Oracle Java SE, Oracle GraalVM, Java 17
- Platforms: Java, OpenJDK
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-114938, OpenJDK, Oracle Java SE, Oracle GraalVM, Java 17, Java, T1059, T1059.006, T1203

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (medium); Execution: T1203 Exploitation for Client Execution (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SuspiciousJavaChildren = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash", "sh", "curl", "wget", "nc", "ncat", "python", "python3", "perl", "bash.exe", "sh.exe"]);
let JavaServicePorts = dynamic([80, 443, 8080, 8443, 8000, 8888, 9090, 9443]);
let JavaSpawn =
    DeviceProcessEvents
    | where Timestamp >= ago(7d)
    | where InitiatingProcessFileName in~ ("java.exe", "java")
    | where FileName in~ (SuspiciousJavaChildren)
    | project
        SpawnTime = Timestamp,
        DeviceName,
        InitiatingProcessFileName,
        ChildProcessName = FileName,
        ProcessCommandLine;
let InboundToJava =
    DeviceNetworkEvents
    | where Timestamp >= ago(7d)
    | where ActionType == "InboundConnectionAccepted"
    | where InitiatingProcessFileName in~ ("java.exe", "java")
    | where RemotePort in (JavaServicePorts)
    | project
        NetTime = Timestamp,
        DeviceName,
        RemoteIP,
        RemotePort;
InboundToJava
| join kind=inner JavaSpawn on DeviceName
| where SpawnTime >= NetTime and SpawnTime <= NetTime + 5m
| project
    NetTime,
    SpawnTime,
    DeviceName,
    InitiatingProcessFileName,
    ChildProcessName,
    ProcessCommandLine,
    RemoteIP,
    RemotePort
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Java application servers that legitimately spawn shell scripts or Python scripts as part of normal application logic.
- Build systems or CI/CD pipelines running on Java that invoke shell commands.
- Java-based monitoring agents that spawn diagnostic utilities.

**Tuning notes:**
- Restrict DeviceName scope to known internet-facing Java application servers using a device group or watchlist to reduce noise from internal developer machines.
- Expand JavaServicePorts to include any custom ports used by Java services in the environment.
- Add exclusions for known legitimate Java child process patterns specific to the application stack deployed in the environment.

**Risks / caveats:**
- InboundConnectionAccepted ActionType in DeviceNetworkEvents may not be populated for all Java service ports depending on Defender for Endpoint network monitoring configuration and whether the device is onboarded with full network telemetry.
- CVE-2026-114938 is dated 2026 and may not yet have public exploit telemetry or confirmed in-the-wild exploitation; the detection is based on post-exploitation behavioral patterns rather than confirmed CVE activity.
- The 5-minute window between inbound connection and child process spawn may miss slow exploitation chains or produce false positives on busy application servers.
- Java processes that accept connections on non-standard ports will not be correlated unless the JavaServicePorts list is expanded.

### Triage Runbook

**First 15 minutes:**
- Confirm the Java process, inbound connection time, remote IP, and port, and verify the child process spawned shortly after the connection.
- Check whether the child process is a shell, scripting engine, downloader, or network utility that is unusual for the application.
- Identify the affected Java application and whether it is internet-facing or exposed to untrusted users.
- Review whether the host has any other signs of exploitation such as new services, persistence, or outbound connections.

**Evidence to collect:**
- Spawn time, network time, device name, Java parent process name, child process name, command line, remote IP, and remote port.
- Full Java command line and application path to determine the service role and expected subprocess behavior.
- Process tree before and after the event, including any subsequent child processes or network activity.
- Any application logs, web server logs, or reverse proxy logs that show the inbound request preceding the spawn.

**Pivot points:**
- DeviceProcessEvents for the same device to enumerate all child processes spawned by java.exe or java.
- DeviceNetworkEvents for inbound connections to the same host and port around the event time.
- DeviceFileEvents for dropped files or modified binaries in the Java application directory.
- Application and server logs for the Java service to correlate the inbound request with the process spawn.

**Benign explanations:**
- Java applications that legitimately launch helper scripts, maintenance jobs, or diagnostic tools.
- Build systems or CI/CD services implemented in Java that invoke shells or scripting interpreters.
- Monitoring or management agents that use Java and spawn utilities for health checks.
- A non-exploited application that normally starts child processes after inbound requests.

**Escalation criteria:**
- The child process is a shell, downloader, or scripting engine and is not part of the documented Java application behavior.
- The inbound connection came from an untrusted or external source and the host is internet-facing.
- There is evidence of follow-on activity such as persistence, lateral movement, or additional suspicious network connections.
- The Java version or application is known to be vulnerable and the behavior matches exploitation timing.

**Containment actions:**
- If exploitation is likely, isolate the host from the network to prevent further post-exploitation activity.
- Stop the affected Java service only if business impact is understood and evidence has been preserved.
- Block the source IP if it is clearly malicious and validated by broader telemetry.
- Initiate credential review for service accounts used by the Java application if compromise is suspected.

**Closure criteria:**
- The spawned child process is confirmed as expected and documented for that Java application.
- No additional suspicious activity is found in process, network, or file telemetry after the inbound connection.
- The event is attributable to normal application behavior or a known maintenance workflow.
- The host is patched or otherwise confirmed not vulnerable, and the alert is explained by benign behavior.

<br/>
---
<br/>

## Detection 4: OpsAgent Ransomware - Mass File Modification by Rust Binary from User-Writable Path

### Detection Opportunity

AuditTeam OpsAgent ransomware implant performing mass file encryption or renaming from a Rust-compiled binary executing in a user-writable directory.

### Intelligence Context

- Securelist: The forced audit: how AuditTeam's OpsAgent framework masks ransomware as consulting — [https://securelist.com/auditteam-opsagent-forced-audit/122031/](https://securelist.com/auditteam-opsagent-forced-audit/122031/)
  - Context: AuditTeam deploys OpsAgent, a Rust-rewritten ransomware implant, which performs file encryption as part of its extortion model. The implant executes from user-writable directories and produces mass file modification events consistent with ransomware encryption activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: AuditTeam
- ATT&CK tags: T1486, T1036
- Products: Not specified
- Platforms: Rust
- Malware: OpsAgent
- Tools: Not specified
- Search tags: AuditTeam, OpsAgent, Rust, T1486, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (high); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let SuspiciousPaths = dynamic(["\\temp\\", "\\appdata\\local\\", "\\appdata\\roaming\\", "\\users\\public\\", "\\programdata\\"]);
DeviceFileEvents
| where Timestamp >= ago(7d)
| where ActionType in ("FileRenamed", "FileModified", "FileCreated")
| where SuspiciousPaths has_any (tolower(InitiatingProcessFolderPath))
| summarize
    FileCount = dcount(strcat(FolderPath, "\\", FileName)),
    FolderCount = dcount(FolderPath),
    StartTime = min(Timestamp),
    EndTime = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, bin(Timestamp, 5m)
| where FileCount >= 100
| where FolderCount >= 5
| extend DurationSeconds = datetime_diff('second', EndTime, StartTime)
| project
    StartTime,
    EndTime,
    DurationSeconds,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileCount,
    FolderCount
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents running from AppData or ProgramData that perform bulk file operations.
- File synchronization clients such as OneDrive or Dropbox during initial sync from user-writable paths.
- Antivirus or EDR products performing bulk file scanning that generates FileModified events.
- File servers with high legitimate write activity may exceed the FileCount threshold.

**Tuning notes:**
- Increase FileCount threshold for file servers or backup agents that legitimately modify large numbers of files; consider scoping those devices out with a separate exclusion.
- Add exclusions for known backup agent process names such as veeam, backup, or robocopy if they generate false positives.
- Consider adding a FileExtension filter for known ransomware extension patterns if extension-based renaming is confirmed in OpsAgent reporting.

**Risks / caveats:**
- InitiatingProcessFolderPath must be populated in DeviceFileEvents; this field is available in Defender for Endpoint but may be empty for system-level processes or events from devices with older sensor versions.
- The FileCount threshold of 100 and FolderCount threshold of 5 are heuristics that should be baselined against normal file activity in the environment, particularly on file servers.
- The 5-minute bin window may split a ransomware event across two bins if it straddles a bin boundary, potentially causing the event to fall below the threshold in each bin.
- Ransomware that operates below the 100-file threshold in a 5-minute window to evade detection will not be caught by this rule.

### Triage Runbook

**First 15 minutes:**
- Assume active ransomware until proven otherwise and verify the file modification rate, folder spread, and process origin path.
- Check whether the process is renaming files, changing extensions, or touching many directories in a short period.
- Identify the user context and whether the binary is signed, known, or associated with a legitimate backup/sync tool.
- Look for concurrent signs of impact such as ransom notes, inaccessible files, or rapid file extension changes.

**Evidence to collect:**
- Start and end time, device name, initiating process name, folder path, command line, file count, and folder count.
- Examples of modified file names and extensions, including whether files were renamed or encrypted.
- Process tree and any parent process that launched the Rust binary.
- Any ransom note files, deleted shadow copies, or related registry/service changes if present.

**Pivot points:**
- DeviceFileEvents for the same device and process to identify the full scope of file modifications.
- DeviceProcessEvents to determine the parent process and any spawned children.
- DeviceRegistryEvents and DeviceServices for persistence or defense evasion artifacts.
- DeviceNetworkEvents for outbound connections that may indicate exfiltration or C2.

**Benign explanations:**
- Backup, sync, or migration tools that legitimately modify many files from user-writable paths.
- Software installers or updaters unpacking and rewriting large numbers of files.
- Antivirus or EDR scanning activity that generates many file events without destructive changes.
- File conversion or compression utilities used by administrators or developers.

**Escalation criteria:**
- Files are being renamed, encrypted, or rendered inaccessible across multiple folders.
- The process is unknown, unsigned, or launched from Temp, AppData, Public, or ProgramData without a business justification.
- There are signs of ransom notes, shadow copy deletion, or additional malicious processes.
- The activity is occurring on a server, file share, or high-value endpoint.

**Containment actions:**
- Immediately isolate the host if ransomware behavior is confirmed or strongly suspected.
- Terminate the malicious process only after preserving evidence and confirming it is not a sanctioned backup or sync agent.
- Disable or reset the affected user account if interactive compromise is suspected.
- Coordinate with incident response to preserve affected files and assess backup integrity.

**Closure criteria:**
- The process is confirmed as a legitimate backup, sync, or administrative tool and the file activity matches expected behavior.
- No file encryption, extension changes, or ransom artifacts are found after review.
- The event is attributed to a known benign bulk file operation and documented for tuning.
- The host is clean after follow-up checks and no further mass modification activity is observed.

<br/>
---
<br/>

## Detection 5: GraphDoor C2 - Non-Office Process Connecting to Microsoft Graph API

### Detection Opportunity

GraphDoor cloud-service backdoor using Microsoft Graph API as C2 channel, initiated from non-Office processes.

### Intelligence Context

- Securelist: Operation ShadowCloud: cloud service-based backdoors targeting government networks in Asia and Africa. Part 2 — [https://securelist.com/operation-shadowcloud-graphdoor/122005/](https://securelist.com/operation-shadowcloud-graphdoor/122005/)
  - Context: GraphDoor is a cloud-service-based backdoor that uses the Microsoft Graph API as its C2 channel. The key detection signal is Graph API connections initiated by processes that are not legitimate Microsoft Office or productivity applications.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1102, T1102.002
- Products: Not specified
- Platforms: cloud services
- Malware: GraphDoor
- Tools: Not specified
- Search tags: cloud services, GraphDoor, T1102, T1102.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1102 Web Service/ T1102.002 Bidirectional Communication (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let LegitGraphProcesses = dynamic(["outlook.exe", "teams.exe", "onedrive.exe", "excel.exe", "word.exe", "powerpnt.exe", "onenote.exe", "msedge.exe", "chrome.exe", "firefox.exe", "msteams.exe", "msedgewebview2.exe", "sharepoint.exe", "lync.exe", "skype.exe"]);
let SuspiciousPaths = dynamic(["\\temp\\", "\\appdata\\local\\", "\\appdata\\roaming\\", "\\users\\public\\", "\\programdata\\"]);
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has "graph.microsoft.com"
| where not(InitiatingProcessFileName in~ (LegitGraphProcesses))
| where SuspiciousPaths has_any (tolower(InitiatingProcessFolderPath))
    or SuspiciousPaths has_any (tolower(InitiatingProcessCommandLine))
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    RemoteUrls = make_set(RemoteUrl, 20)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| where ConnectionCount >= 3
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    ConnectionCount,
    RemoteUrls
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Custom line-of-business applications that use Graph API and run from AppData.
- PowerShell scripts or automation tools that call Graph API from user profile directories.
- Third-party productivity or security tools that integrate with Microsoft 365 via Graph API.
- Electron-based applications that embed a browser runtime and call Graph API.

**Tuning notes:**
- Run the query without the path filter first to enumerate all non-Office processes calling Graph API, then build the exclusion list from that baseline before re-enabling the path filter.
- Expand LegitGraphProcesses to include any custom enterprise or line-of-business applications identified in the baseline review.
- Consider adding a filter for InitiatingProcessIntegrityLevel to prioritize medium or low integrity processes over high integrity system processes.

**Risks / caveats:**
- RemoteUrl population for HTTPS connections to graph.microsoft.com depends on Defender for Endpoint network inspection being enabled; if SSL inspection is not configured, RemoteUrl may be empty for many connections.
- LegitGraphProcesses requires expansion to cover all enterprise applications in the target environment that legitimately call Graph API; this list is not exhaustive.
- The path filter will miss GraphDoor instances that execute from non-user-writable locations if future variants are observed outside AppData or Temp.
- The 7-day lookback window may miss low-frequency C2 polling; consider extending for periodic hunting.

### Triage Runbook

**First 15 minutes:**
- Confirm the process is not an approved Microsoft Office, Teams, OneDrive, browser, or known enterprise application.
- Review whether the process is running from a user-writable directory and whether it made repeated Graph API connections.
- Check the host for other suspicious behavior such as script execution, persistence, or unusual child processes.
- Determine whether the device role or installed software reasonably explains Graph API usage.

**Evidence to collect:**
- Device name, initiating process file name, folder path, command line, first seen, last seen, connection count, and remote URLs.
- Any related process tree or child processes associated with the Graph API caller.
- User context and device role to determine whether the application is expected to integrate with Microsoft 365.
- Additional network destinations contacted by the same process or host.

**Pivot points:**
- DeviceNetworkEvents for the same device and process to review all Microsoft Graph and adjacent cloud-service traffic.
- DeviceProcessEvents for the same time window to identify suspicious child processes or script hosts.
- DeviceFileEvents for dropped binaries or recent modifications in the process path.
- Tenant-wide hunting for the same process name or command line across other devices.

**Benign explanations:**
- Line-of-business applications that legitimately integrate with Microsoft 365 through Graph API.
- PowerShell scripts, automation tools, or RPA workflows that call Graph from user profile directories.
- Third-party productivity, backup, or security tools that use Graph for synchronization or management.
- Electron-based applications that embed browser components and access Graph endpoints.

**Escalation criteria:**
- The process is unknown, unsigned, or executing from Temp, AppData, Public, or ProgramData without approval.
- The host shows repeated Graph API polling plus other suspicious behavior such as persistence or script execution.
- The device is not expected to run Graph-integrated software and the activity cannot be explained quickly.
- The same process is observed on multiple hosts, suggesting a broader campaign.

**Containment actions:**
- If the process is unapproved and additional malicious behavior is present, isolate the host.
- Terminate the suspicious process only after preserving evidence and confirming it is not a sanctioned business application.
- Block the binary or path if validated as malicious and coordinate with identity teams if tokens may be abused.
- Reset credentials or revoke sessions if there is evidence of account or token misuse.

**Closure criteria:**
- The process is confirmed as a legitimate enterprise application or automation workflow with documented Graph usage.
- No additional suspicious telemetry is found on the host and the connection pattern matches normal behavior.
- The event is added to the local allowlist or tuning process after validation.
- The host remains stable with no further Graph API activity from the suspicious process after review.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- GitDoor C2 - Non-Browser Process Connecting to GitHub API: Do not schedule yet; validate as an analyst-led hunt first.
- GitDoor - Shellcode Injection from Suspicious Process: Do not schedule yet; validate as an analyst-led hunt first.
- CVE-2026-114938 - Java Process Spawning Unexpected Child Process After Inbound Connection: Do not schedule yet; validate as an analyst-led hunt first.
- GraphDoor C2 - Non-Office Process Connecting to Microsoft Graph API: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceNetworkEvents: shared by GitDoor C2 - Non-Browser Process Connecting to GitHub API; GitDoor - Shellcode Injection from Suspicious Process; CVE-2026-114938 - Java Process Spawning Unexpected Child Process After Inbound Connection; GraphDoor C2 - Non-Office Process Connecting to Microsoft Graph API

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: OpsAgent Ransomware - Mass File Modification by Rust Binary from User-Writable Path.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: GitDoor C2 - Non-Browser Process Connecting to GitHub API; GitDoor - Shellcode Injection from Suspicious Process; CVE-2026-114938 - Java Process Spawning Unexpected Child Process After Inbound Connection; GraphDoor C2 - Non-Office Process Connecting to Microsoft Graph API.

### Hunting Agenda and Promotion Criteria

- GitDoor C2 - Non-Browser Process Connecting to GitHub API: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- GitDoor - Shellcode Injection from Suspicious Process: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-114938 - Java Process Spawning Unexpected Child Process After Inbound Connection: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- GraphDoor C2 - Non-Office Process Connecting to Microsoft Graph API: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
