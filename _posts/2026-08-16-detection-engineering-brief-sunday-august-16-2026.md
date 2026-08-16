---
layout: post
title: "Detection Engineering Brief - Sunday, August 16, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-16
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - HoneyMyte
  - CoolClient
  - Windows
  - Armored Likho
  - Still Toolkit
  - Telegram
  - T1190
  - Microsoft SharePoint
  - Microsoft products
  - CVE-2026-46300
  - WordPress
  - Ghost CMS
  - Joomla
  - Langflow
  - OpenCATS
  - Pterodactyl Panel
  - SonicWall SMA1000
  - Ray Dashboard
  - Pix-for-WooCommerce
  - Linux
  - Metasploit
  - T1014
  - T1059
  - T1036
  - T1071.001
  - T1095
  - T1071
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 2 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: HoneyMyte, CoolClient, Windows, Armored Likho, Still Toolkit, Telegram, T1190, Microsoft SharePoint, Microsoft products, CVE-2026-46300, WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Linux, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: HoneyMyte CoolClient - Suspicious Kernel-Mode Driver Load from Non-Standard Path; Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Session Data; Armored Likho Still Toolkit - Office or Browser Spawning Scripting Engine Delivering Payload; Metasploit HTTP Malleable C2 - Non-Browser Process Beaconing over HTTP with Consistent Interval.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: HoneyMyte CoolClient - Suspicious Kernel-Mode Driver Load from Non-Standard Path

### Detection Opportunity

Kernel-mode rootkit driver loaded by CoolClient backdoor to hide processes, files, and network connections from security tooling.

### Intelligence Context

- Securelist: APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit — [https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/)
  - Context: HoneyMyte upgraded CoolClient with a kernel-mode rootkit driver that hides malicious processes, files, and network connections from security tools and analysts. The driver load event is the earliest detectable signal before rootkit suppression of subsequent telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: HoneyMyte
- ATT&CK tags: T1014
- Products: Not specified
- Platforms: Windows
- Malware: CoolClient
- Tools: Not specified
- Search tags: HoneyMyte, CoolClient, Windows, T1014

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: defense-evasion: T1014 Rootkit (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents, DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceEvents, DeviceProcessEvents

### KQL

```kql
let KnownDriverPaths = dynamic([@"\Windows\System32\drivers\", @"\Windows\SysWOW64\drivers\"]);
let KnownLoaderProcesses = dynamic(["services.exe", "svchost.exe", "wininit.exe", "setupapi.exe", "drvinst.exe"]);
let DriverLoads = DeviceEvents
| where ActionType == "DriverLoad"
| where not(FolderPath has_any (KnownDriverPaths))
| where not(InitiatingProcessFileName in~ (KnownLoaderProcesses))
| project DeviceId, DeviceName, DriverLoadTime = Timestamp, DriverFileName = FileName, FolderPath, SHA256, LoaderProcess = InitiatingProcessFileName;
let SuspectProcesses = DeviceProcessEvents
| where not(InitiatingProcessFileName in~ (KnownLoaderProcesses))
| project DeviceId, ProcessTime = Timestamp, SpawnedProcess = FileName, ProcessCommandLine = InitiatingProcessCommandLine, ParentProcess = InitiatingProcessFileName;
DriverLoads
| join kind=inner SuspectProcesses on DeviceId
| where ProcessTime between (DriverLoadTime .. (DriverLoadTime + 2m))
| where ParentProcess =~ LoaderProcess
| project DeviceName, DriverLoadTime, DriverFileName, FolderPath, SHA256, LoaderProcess, SpawnedProcess, ProcessCommandLine
| order by DriverLoadTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate third-party security products (EDR agents, AV drivers, VPN kernel components) that install drivers outside System32\drivers during updates or initial deployment.
- Hardware vendor driver installers that temporarily stage drivers in non-standard paths before moving them.
- Software development environments where test-signed drivers are loaded from build output directories.

**Tuning notes:**
- Run a frequency query on DeviceEvents where ActionType == 'DriverLoad' before deploying to confirm telemetry availability and volume.
- Enumerate non-System32 driver paths in the environment (e.g., security product drivers, VPN drivers) and add them to KnownDriverPaths.
- Consider extending the post-load window beyond 2 minutes if rootkit initialization in testing shows delayed process spawning.

**Risks / caveats:**
- ActionType value 'DriverLoad' in DeviceEvents must be verified as populated in the tenant. This event type requires kernel-level DfE sensor coverage and may be absent in environments with degraded sensor mode or older onboarding configurations.
- Once a rootkit driver is active, it may suppress subsequent DeviceProcessEvents telemetry, making the post-load correlation window unreliable. The driver load event itself remains the primary high-fidelity signal.
- The 2-minute post-load correlation window may miss delayed rootkit initialization sequences.
- Legitimate non-System32 driver paths specific to the environment must be added to KnownDriverPaths to reduce false positives before scheduling at high frequency.

### Triage Runbook

**First 15 minutes:**
- Confirm the driver path, file name, and SHA256 against known-good vendor drivers and recent change activity on the host.
- Check whether the initiating process is a recognized installer or system loader; if it is not, treat the load as suspicious.
- Review DeviceEvents and DeviceProcessEvents around the load time for any immediate process creation, service installation, or privilege escalation activity.
- Identify whether the device is a security product, VPN endpoint, hardware driver staging host, or developer/test-signed driver environment that could explain the event.

**Evidence to collect:**
- DeviceName, DriverLoadTime, FileName, FolderPath, SHA256, and InitiatingProcessFileName from the alert.
- Any recent software deployment, driver update, or endpoint protection change on the host.
- DeviceProcessEvents for 10-15 minutes before and after the load, including command lines and parent/child relationships.
- If available, memory or disk acquisition from the host before reboot or remediation, since rootkits may suppress later telemetry.

**Pivot points:**
- DeviceEvents filtered to the same DeviceId and SHA256 to find repeated loads or related driver events.
- DeviceProcessEvents for the same DeviceId and time window to identify the loader process and any spawned utilities.
- DeviceFileEvents for the driver path to determine whether the file was created, modified, or dropped by an unusual process.
- Endpoint inventory or software deployment records to validate whether the driver belongs to a known product.

**Benign explanations:**
- Legitimate EDR, AV, VPN, or hardware vendor drivers staged outside System32\drivers during installation or update.
- Developer or QA systems loading test-signed drivers from build output directories.
- A recent OS or device driver deployment that used a non-standard staging path before moving the file.

**Escalation criteria:**
- The driver is unsigned, unknown, or not attributable to a trusted vendor or approved change.
- The initiating process is not a recognized installer or system loader, or the path is outside expected vendor staging locations.
- There are signs of follow-on malicious activity, missing telemetry, hidden processes, or unexplained network connections after the load.
- The host is a high-value endpoint or contains sensitive credentials, and the driver cannot be quickly validated.

**Containment actions:**
- Isolate the host from the network if the driver cannot be validated or if there are signs of active compromise.
- Preserve volatile evidence before rebooting, because a rootkit may hide itself after restart or suppress telemetry.
- Disable or suspend only if operationally safe and coordinated with endpoint management; avoid rebooting until evidence is captured.
- Block the driver hash or file path in endpoint controls if confirmed malicious.

**Closure criteria:**
- The driver is confirmed as a legitimate, approved vendor component and matches a documented deployment or update.
- No suspicious follow-on activity is found in the surrounding process and file telemetry.
- The file hash, path, and initiating process are validated against change records or vendor documentation.
- Any required environment-specific allowlist entries have been added and the alert is documented as benign.

<br/>
---
<br/>

## Detection 2: Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Session Data

### Detection Opportunity

Malicious toolkit accesses Telegram application data files on Windows to steal credentials and session tokens as part of Armored Likho espionage operations.

### Intelligence Context

- Securelist: Armored Likho expands its cyber-espionage toolkit — [https://securelist.com/armored-likho-still-toolkit/121033/](https://securelist.com/armored-likho-still-toolkit/121033/)
  - Context: Armored Likho's Still Toolkit targets Telegram data on Windows victims, accessing session files and credentials stored in Telegram's AppData profile directory. A non-Telegram process reading these files is a high-fidelity indicator of credential theft activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1059, T1036
- Products: Telegram
- Platforms: Windows
- Malware: Still Toolkit
- Tools: Not specified
- Search tags: Armored Likho, Still Toolkit, Telegram, Windows, T1059, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (high); defense-evasion: T1036 Masquerading (low)

### Deployment Gates

- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let TelegramDataAccess = DeviceFileEvents
| where FolderPath has @"\AppData\Roaming\Telegram Desktop\"
| where InitiatingProcessFileName !in~ ("Telegram.exe", "Updater.exe")
| where ActionType in ("FileRead", "FileAccessed")
| project DeviceId, DeviceName, AccessTime = Timestamp, FileName, FolderPath,
    AccessingProcess = InitiatingProcessFileName,
    AccessingProcessCommandLine = InitiatingProcessCommandLine,
    AccessingProcessId = InitiatingProcessId;
let PostAccessNetwork = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private"
| project DeviceId, NetTime = Timestamp, RemoteIP, RemotePort,
    NetProcess = InitiatingProcessFileName,
    NetProcessId = InitiatingProcessId;
TelegramDataAccess
| join kind=leftouter PostAccessNetwork on DeviceId
| where NetTime between (AccessTime .. (AccessTime + 5m))
| where NetProcess =~ AccessingProcess
| project DeviceName, AccessTime, FileName, FolderPath, AccessingProcess,
    AccessingProcessCommandLine, RemoteIP, RemotePort
| order by AccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents or cloud sync tools (e.g., OneDrive, Dropbox) that index or back up AppData directories may access Telegram session files.
- Antivirus or EDR products performing on-access scanning of AppData directories.
- IT management tools performing file inventory or compliance scanning.

**Tuning notes:**
- Run a frequency query on DeviceFileEvents where ActionType in ('FileRead', 'FileAccessed') and FolderPath has 'Telegram Desktop' before deploying to confirm telemetry availability.
- Add legitimate backup or sync process names to the InitiatingProcessFileName exclusion list after baselining the environment.
- If FileRead/FileAccessed are not available, consider pivoting to FileCreated events in the Telegram directory as a weaker but available signal for file staging.

**Risks / caveats:**
- ActionType values 'FileRead' and 'FileAccessed' in DeviceFileEvents are not universally populated across all DfE sensor configurations. If these values are absent, the file access filter will return no results. Verify with a frequency query before deploying.
- The original query referenced InitiatingProcessFileName1 in the join filter, which is an auto-generated column name from the join that may not reliably match the intended field. This has been corrected in the improved KQL.
- If FileRead/FileAccessed ActionType values are not populated in the tenant, the detection will produce no results. The file access signal is the primary detection anchor.
- Telegram Store (UWP) installations use a different AppData path and are not covered by this query.

### Triage Runbook

**First 15 minutes:**
- Verify the accessing process name, command line, and parent process against known backup, sync, EDR, or IT management tools.
- Confirm whether the accessed files are Telegram session or credential-related files under the Telegram Desktop AppData path.
- Check for immediate outbound connections from the same process within the alert window, especially to external IPs.
- Determine whether the device user recently installed or updated Telegram, a backup tool, or a corporate endpoint agent that could explain the access.

**Evidence to collect:**
- DeviceName, AccessTime, FileName, FolderPath, AccessingProcess, AccessingProcessCommandLine, RemoteIP, and RemotePort from the alert.
- DeviceFileEvents for the same DeviceId and time range to see whether multiple Telegram files were read or accessed.
- DeviceNetworkEvents for the same process and time window to identify possible exfiltration or command-and-control activity.
- User context and recent software installation history for the endpoint.

**Pivot points:**
- DeviceFileEvents filtered to the same DeviceId and Telegram Desktop path to identify all file access patterns by the process.
- DeviceNetworkEvents for the same DeviceId and AccessingProcess to find external connections after file access.
- DeviceProcessEvents for the same process tree to determine whether the process was spawned by Office, browser, script, or another suspicious parent.
- Endpoint software inventory or EDR telemetry to validate whether the process is a known-good enterprise tool.

**Benign explanations:**
- Backup, sync, or cloud storage tools indexing or copying AppData content.
- Antivirus or EDR on-access scanning of Telegram files.
- IT inventory, compliance, or file discovery tooling accessing user profile data.
- A legitimate Telegram update or maintenance process if the process name and path match Telegram.exe or Updater.exe, though those are excluded by the rule.

**Escalation criteria:**
- The process is unknown, unsigned, or launched from a user-writable directory.
- The same process makes external network connections shortly after accessing Telegram data.
- Multiple Telegram session or credential files are accessed, especially by a process unrelated to Telegram.
- The endpoint belongs to a sensitive user, executive, or investigation target.

**Containment actions:**
- Isolate the host if the process is unknown and there is evidence of external communication or broader credential theft.
- Terminate the suspicious process only after preserving command line, parent process, and file evidence if operationally safe.
- Reset or revoke Telegram sessions and related credentials if compromise is confirmed or strongly suspected.
- Block the process hash or path in endpoint controls if confirmed malicious.

**Closure criteria:**
- The accessing process is confirmed as a legitimate enterprise tool with an approved business purpose.
- No external network activity or additional suspicious file access is found.
- The accessed files are not sensitive session artifacts, or the access is consistent with documented maintenance.
- Any required exclusions for known-good tools are documented and approved.

<br/>
---
<br/>

## Detection 3: SharePoint RCE Chain - Web Worker Process Spawning Unexpected Shell

### Detection Opportunity

Critical RCE chain exploited against Microsoft SharePoint servers resulting in web worker processes spawning command interpreters.

### Intelligence Context

- Rapid7: Patch Tuesday - August 2026 — [https://www.rapid7.com/blog/post/em-patch-tuesday-august-2026](https://www.rapid7.com/blog/post/em-patch-tuesday-august-2026)
  - Context: Rapid7 identified a critical SharePoint RCE chain in the August 2026 Patch Tuesday disclosure with confirmed exploitation in the wild. SharePoint RCE chains characteristically result in IIS worker processes (w3wp.exe) spawning command interpreters or scripting engines as post-exploitation shells.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, Microsoft SharePoint, Windows, Microsoft products, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: initial-access: T1190 Exploit Public-Facing Application (high); execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackWindow = 1h;
let ShellProcesses = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "certutil.exe"]);
let SharePointWorkers = dynamic(["w3wp.exe", "owstimer.exe"]);
let SpawnEvents = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where InitiatingProcessFileName in~ (SharePointWorkers)
| where FileName in~ (ShellProcesses)
| project DeviceId, DeviceName, SpawnTime = Timestamp,
    ParentWorker = InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SpawnedShell = FileName,
    SpawnedShellCommandLine = ProcessCommandLine,
    SpawnedProcessId = ProcessId;
let NetworkEvents = DeviceNetworkEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private"
| project DeviceId, NetTime = Timestamp, RemoteIP, RemotePort,
    NetProcessName = InitiatingProcessFileName,
    NetProcessId = InitiatingProcessId;
SpawnEvents
| join kind=leftouter NetworkEvents on DeviceId
| where NetTime between (SpawnTime .. (SpawnTime + 3m))
| where NetProcessName in~ (ShellProcesses)
| project SpawnTime, DeviceName, ParentWorker, InitiatingProcessCommandLine,
    SpawnedShell, SpawnedShellCommandLine, RemoteIP, RemotePort
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SharePoint administrative scripts or maintenance tasks that invoke PowerShell or cmd.exe via scheduled jobs running under w3wp.exe context.
- SharePoint farm configuration scripts executed by owstimer.exe during patching or provisioning.
- Monitoring or management agents that hook into IIS worker processes and spawn diagnostic tools.

**Tuning notes:**
- Filter DeviceName to known SharePoint server hostnames or apply a device group tag filter to reduce noise from other IIS-hosting servers.
- Exclude known legitimate SharePoint administrative PowerShell command-line patterns from SpawnedShellCommandLine after baselining.
- Consider removing certutil.exe from ShellProcesses if it generates excessive false positives from legitimate SharePoint certificate management tasks.

**Risks / caveats:**
- Without filtering DeviceName to known SharePoint server hostnames or a device group, this rule will fire on any IIS-hosting server where w3wp.exe spawns a shell, including non-SharePoint web applications. This increases false positive volume but does not make the detection incorrect.
- The 3-minute network correlation window may miss delayed outbound connections from post-exploitation tooling.
- certutil.exe is included as a shell process proxy but may generate false positives from legitimate certificate operations on SharePoint servers.

### Triage Runbook

**First 15 minutes:**
- Treat the alert as potential active exploitation until proven otherwise and identify the affected server role immediately.
- Validate whether the host is a SharePoint server and whether the shell spawn occurred during patching, maintenance, or an approved administrative task.
- Review the spawned shell command line for download, execution, encoded commands, or suspicious child processes.
- Check for concurrent network connections, new services, scheduled tasks, or webshell-like activity on the same host.

**Evidence to collect:**
- Timestamp, DeviceName, ParentWorker, InitiatingProcessCommandLine, SpawnedShell, SpawnedShellCommandLine, RemoteIP, and RemotePort from the alert.
- DeviceProcessEvents for the same DeviceId around the alert time to identify additional child processes or lateral movement tools.
- DeviceNetworkEvents for the same host to identify outbound connections from the spawned shell or related processes.
- IIS, SharePoint, and Windows event logs if available, including any application errors, authentication anomalies, or web request indicators.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceId and parent worker processes w3wp.exe or owstimer.exe.
- DeviceNetworkEvents for the same DeviceId and spawned shell process name to identify external communications.
- SharePoint and IIS logs to correlate the shell spawn with suspicious web requests or exploit timing.
- DeviceFileEvents for the same host to look for dropped webshells, scripts, or staging files in web directories or temp locations.

**Benign explanations:**
- Approved SharePoint administration or patching tasks that invoke PowerShell or cmd.exe under w3wp.exe or owstimer.exe.
- Farm configuration or provisioning scripts executed during maintenance windows.
- Monitoring or management agents that attach to IIS worker processes and launch diagnostic utilities.

**Escalation criteria:**
- The shell command line is clearly malicious, encoded, or downloads payloads.
- The host is not in a maintenance window and the activity is not attributable to an approved admin task.
- Additional suspicious processes, webshell artifacts, or outbound connections are present.
- The server is internet-facing or hosts sensitive SharePoint content and exploitation is plausible.

**Containment actions:**
- Isolate the SharePoint server if exploitation is confirmed or strongly suspected.
- Disable external access to the affected SharePoint service or place it behind emergency controls if operationally feasible.
- Preserve logs and memory before rebooting or patching, since evidence may be lost.
- Coordinate immediate patching and credential review for the SharePoint service account and any privileged accounts used on the host.

**Closure criteria:**
- The process spawn is tied to a documented administrative action or maintenance activity.
- No suspicious child processes, network activity, or webshell artifacts are found.
- The host is confirmed patched and not exposed to the vulnerable condition.
- The event is documented with a clear benign explanation and any necessary allowlist or maintenance context.

<br/>
---
<br/>

## Detection 4: Armored Likho Still Toolkit - Office or Browser Spawning Scripting Engine Delivering Payload

### Detection Opportunity

Spearphishing lure disguised as a fundraising campaign delivered via Office or browser processes spawning scripting engines or dropping executables to user temp directories on Windows.

### Intelligence Context

- Securelist: Armored Likho expands its cyber-espionage toolkit — [https://securelist.com/armored-likho-still-toolkit/121033/](https://securelist.com/armored-likho-still-toolkit/121033/)
  - Context: Armored Likho used a fundraising-themed spearphishing lure to deliver the Still Toolkit on Windows. The delivery mechanism involves document or browser processes spawning scripting engines or writing executables to user-writable directories as the initial execution stage.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1059, T1036
- Products: Telegram
- Platforms: Windows
- Malware: Still Toolkit
- Tools: Not specified
- Search tags: Armored Likho, Still Toolkit, Telegram, Windows, T1059, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (high); defense-evasion: T1036 Masquerading (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let LookbackWindow = 7d;
let OfficeAndBrowsers = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe", "acrord32.exe"]);
let ScriptEngines = dynamic(["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"]);
let SpawnEvents = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where InitiatingProcessFileName in~ (OfficeAndBrowsers)
| where FileName in~ (ScriptEngines)
| project DeviceId, DeviceName, SpawnTime = Timestamp,
    ParentProcess = InitiatingProcessFileName,
    ChildProcess = FileName,
    ChildCommandLine = ProcessCommandLine,
    SpawnedProcessId = ProcessId;
let DroppedFiles = DeviceFileEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Users\Public\")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
| project DeviceId, FileTime = Timestamp, DroppedFileName = FileName,
    DroppedFilePath = FolderPath,
    DroppedFileSHA256 = SHA256,
    DroppingProcess = InitiatingProcessFileName;
SpawnEvents
| join kind=inner DroppedFiles on DeviceId
| where FileTime between (SpawnTime .. (SpawnTime + 5m))
| where DroppingProcess in~ (ScriptEngines)
| project DeviceName, SpawnTime, ParentProcess, ChildProcess, ChildCommandLine,
    DroppedFileName, DroppedFilePath, DroppedFileSHA256
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Office macro-enabled documents that invoke PowerShell for approved automation tasks.
- Browser-based software installers that download and execute setup files to AppData or Temp directories.
- PDF readers invoking scripts for form processing or digital signature validation.
- Enterprise software deployment tools that use Office or browser processes as delivery vectors for legitimate updates.

**Tuning notes:**
- Run SpawnEvents independently first to understand the volume of Office/browser-to-script-engine spawns in the environment before enabling the full join.
- Add known-good installer or update process command-line patterns to a filter on ChildCommandLine to reduce false positives from legitimate automation.
- Narrow FolderPath filters to the most specific user-writable paths observed in threat intelligence if the broad AppData filter generates excessive noise.
- If converting to a scheduled rule, reduce the lookback window to 1 hour and add a deduplication step on DeviceName and ParentProcess.

**Risks / caveats:**
- The detection relies on a behavioral pattern (Office/browser spawning scripts then dropping files) that is also exhibited by legitimate enterprise software, requiring analyst review of each result.
- The 7-day lookback window is appropriate for hunting but should be reduced to 1-24 hours if converted to a scheduled rule after baselining.
- DroppingProcess correlation on ScriptEngines assumes the scripting engine drops the file directly; multi-stage chains where the script spawns another process to drop the file will not be correlated.
- SHA256 field availability in DeviceFileEvents depends on DfE sensor configuration and may not be populated for all file creation events.

### Triage Runbook

**First 15 minutes:**
- Review the parent process, child script engine, and child command line for signs of download, execution, obfuscation, or user-writable staging.
- Check the dropped file path and hash to see whether the payload is an executable, DLL, or script in Temp, AppData, or Public directories.
- Confirm whether the activity aligns with a known software installer, browser-based update, or approved automation task.
- Look for follow-on process creation, persistence, or network activity from the same host within the alert window.

**Evidence to collect:**
- DeviceName, SpawnTime, ParentProcess, ChildProcess, ChildCommandLine, DroppedFileName, DroppedFilePath, and DroppedFileSHA256 from the alert.
- DeviceProcessEvents for the same DeviceId to identify the full process tree and any subsequent execution of the dropped file.
- DeviceFileEvents to determine whether the file was created, modified, or renamed and by which process.
- Any user-reported email, document, or browser activity that preceded the alert.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceId and parent process names such as winword.exe, excel.exe, chrome.exe, msedge.exe, or firefox.exe.
- DeviceFileEvents for the same DeviceId and dropped file hash or path to identify additional payloads.
- DeviceNetworkEvents for the same DeviceId and child process to identify downloads or outbound callbacks.
- Endpoint software inventory or application control logs to validate whether the behavior matches a known installer or updater.

**Benign explanations:**
- Legitimate Office macro automation or approved scripting used by business workflows.
- Browser-based software installers that download and stage setup files in Temp or AppData.
- Enterprise deployment tools or update mechanisms that use Office or browser processes as launch points.
- PDF or document processing tools that invoke scripts for legitimate form handling or signature validation.

**Escalation criteria:**
- The child command line is obfuscated, downloads content, or launches additional suspicious binaries.
- The dropped file is unknown, unsigned, or later executed from a user-writable directory.
- The parent process is not associated with a known business workflow and the user did not initiate the action.
- There are signs of credential theft, persistence, or lateral movement after the initial spawn.

**Containment actions:**
- If the payload appears malicious, isolate the host and prevent further execution from the dropped path.
- Quarantine or block the dropped file hash if confirmed malicious.
- Disable the user session or reset credentials if the chain suggests phishing-driven compromise.
- Preserve the original document, URL, or browser artifact for investigation before deleting anything.

**Closure criteria:**
- The process chain is matched to a documented, approved installer or automation workflow.
- The dropped file is validated as benign and no additional suspicious activity is present.
- No persistence, credential theft, or external communication is observed.
- The event is recorded with the approved business justification and any necessary exclusions.

<br/>
---
<br/>

## Detection 5: Metasploit HTTP Malleable C2 - Non-Browser Process Beaconing over HTTP with Consistent Interval

### Detection Opportunity

Metasploit HTTP malleable profiles used to shape C2 traffic from non-browser processes to blend with legitimate HTTP traffic.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Lot of summer shells and fit http profiles — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles)
  - Context: Metasploit introduced HTTP malleable profiles to shape C2 traffic to blend with legitimate HTTP, making header-based detection unreliable. Detection relies on identifying beaconing cadence and HTTP connections from non-browser processes as behavioral indicators of active C2 sessions.

### Search Metadata

- CVEs: CVE-2026-46300
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071.001, T1095, T1071
- Products: WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Metasploit
- Platforms: Linux, Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-46300, T1190, WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Linux, Windows, Metasploit, T1071.001, T1095, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: command-and-control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (high); command-and-control: T1095 Non-Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let LookbackWindow = 24h;
let BrowserProcesses = dynamic(["msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "safari.exe", "opera.exe"]);
let SystemProcesses = dynamic(["svchost.exe", "services.exe", "lsass.exe", "wininit.exe", "MsMpEng.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80, 443, 8080, 8443)
| where not(InitiatingProcessFileName in~ (BrowserProcesses))
| where not(InitiatingProcessFileName in~ (SystemProcesses))
| where RemoteIPType != "Private"
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    TimestampList = make_list(Timestamp, 500),
    InitiatingProcessCommandLine = take_any(InitiatingProcessCommandLine)
    by DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where ConnectionCount >= 10
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where DurationMinutes > 10
| extend AvgIntervalSeconds = toreal(DurationMinutes * 60) / toreal(ConnectionCount)
| where AvgIntervalSeconds between (15 .. 300)
| extend IntervalStdDevSeconds = iif(
    array_length(TimestampList) > 1,
    toreal(stdev(TimestampList)),
    toreal(0)
  )
| project DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    RemoteIP, RemotePort, ConnectionCount, AvgIntervalSeconds, IntervalStdDevSeconds,
    FirstSeen, LastSeen
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software update agents (Windows Update components, vendor update services) that poll update servers at regular intervals.
- Endpoint telemetry and monitoring agents that beacon to cloud collection endpoints.
- Enterprise application clients with heartbeat mechanisms (VPN clients, collaboration tools, remote management agents).
- Backup agents with scheduled cloud sync intervals.

**Tuning notes:**
- Validate RemoteIPType population in the tenant before relying on the private IP filter.
- Adjust ConnectionCount threshold and AvgIntervalSeconds range based on observed Metasploit beacon profiles (default Metasploit HTTP beacon interval is approximately 5 seconds; malleable profiles vary widely).
- Add known legitimate periodic HTTP processes specific to the environment to the SystemProcesses or BrowserProcesses exclusion lists.
- Consider adding a low IntervalStdDevSeconds threshold filter (e.g., IntervalStdDevSeconds < 30) to focus on highly regular beacons after validating the stdev calculation output.

**Risks / caveats:**
- RemoteIPType field availability in DeviceNetworkEvents must be verified in the tenant. This field is used to filter private IP destinations and its absence would cause the private IP exclusion to silently fail, allowing internal beaconing to inflate results.
- stdev() on a list of datetime values requires the list to be converted to numeric epoch values for accurate computation. The stdev(TimestampList) call on raw datetime values may not produce meaningful results in all KQL versions; analysts should validate the IntervalStdDevSeconds output against known beacon samples in their environment.
- The 24-hour lookback window means the query will not detect short-lived C2 sessions that complete within minutes.
- Malleable profiles that randomize connection intervals to avoid consistent cadence detection will evade this heuristic entirely.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process and confirm whether it is a known updater, telemetry agent, VPN client, or internal application with regular polling.
- Review the destination IP, port, and any available URL context to see whether the traffic is external and consistent with a known service.
- Check whether the process is signed, installed from a trusted vendor, and expected to make repeated HTTP connections.
- Look for additional suspicious behavior on the host such as new processes, file drops, or unusual parent-child process chains.

**Evidence to collect:**
- DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ConnectionCount, AvgIntervalSeconds, IntervalStdDevSeconds, FirstSeen, and LastSeen from the alert.
- DeviceNetworkEvents for the same DeviceId and process to inspect the full connection pattern and any URL or host details available.
- DeviceProcessEvents for the same host to determine whether the process was spawned by a suspicious parent or followed by payload execution.
- Endpoint software inventory or service records to validate whether the process is a known periodic connector.

**Pivot points:**
- DeviceNetworkEvents filtered to the same DeviceId, RemoteIP, and InitiatingProcessFileName to review all connections over a longer window.
- DeviceProcessEvents for the same DeviceId and process name to identify installation path, parent process, and command line.
- Threat intelligence or proxy logs for the destination IP or URL if available.
- Application and service inventory to confirm whether the process belongs to a legitimate agent or internal application.

**Benign explanations:**
- Software update agents, telemetry collectors, or monitoring tools that poll at regular intervals.
- VPN clients, collaboration tools, or remote management agents with heartbeat traffic.
- Backup or sync clients that connect on a predictable cadence.
- Custom internal applications that use polling architectures over HTTP.

**Escalation criteria:**
- The process is unknown, unsigned, or running from an unusual path.
- The destination is external and not associated with a known vendor or business service.
- The traffic pattern is highly regular and persists over time without a clear business explanation.
- Additional suspicious host activity appears alongside the beaconing, such as shell execution or file staging.

**Containment actions:**
- If the process is unknown and the beaconing is persistent, isolate the host for deeper investigation.
- Block the destination IP or domain at the proxy or firewall if confirmed malicious and operationally safe.
- Terminate the process only after preserving evidence if the host is clearly compromised.
- Escalate to incident response if the beaconing is paired with other compromise indicators.

**Closure criteria:**
- The process is confirmed as a legitimate agent or application with an approved periodic polling pattern.
- The destination and command line are validated against vendor or internal documentation.
- No additional suspicious host activity is found during the observation window.
- The alert is documented with the benign rationale and any required exclusions or thresholds for future tuning.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- HoneyMyte CoolClient - Suspicious Kernel-Mode Driver Load from Non-Standard Path: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents, DeviceProcessEvents before scheduling.
- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

**Schema / correlation keys:**
- Armored Likho Still Toolkit - Office or Browser Spawning Scripting Engine Delivering Payload: Do not schedule yet; validate as an analyst-led hunt first.
- Metasploit HTTP Malleable C2 - Non-Browser Process Beaconing over HTTP with Consistent Interval: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by HoneyMyte CoolClient - Suspicious Kernel-Mode Driver Load from Non-Standard Path; SharePoint RCE Chain - Web Worker Process Spawning Unexpected Shell; Armored Likho Still Toolkit - Office or Browser Spawning Scripting Engine Delivering Payload
- DeviceFileEvents: shared by Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Session Data; Armored Likho Still Toolkit - Office or Browser Spawning Scripting Engine Delivering Payload
- DeviceNetworkEvents: shared by Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Session Data; SharePoint RCE Chain - Web Worker Process Spawning Unexpected Shell; Metasploit HTTP Malleable C2 - Non-Browser Process Beaconing over HTTP with Consistent Interval

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SharePoint RCE Chain - Web Worker Process Spawning Unexpected Shell.
2. Resolve environment-mapping detections next: HoneyMyte CoolClient - Suspicious Kernel-Mode Driver Load from Non-Standard Path; Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Session Data.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Armored Likho Still Toolkit - Office or Browser Spawning Scripting Engine Delivering Payload; Metasploit HTTP Malleable C2 - Non-Browser Process Beaconing over HTTP with Consistent Interval.

### Hunting Agenda and Promotion Criteria

- Armored Likho Still Toolkit - Office or Browser Spawning Scripting Engine Delivering Payload: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Metasploit HTTP Malleable C2 - Non-Browser Process Beaconing over HTTP with Consistent Interval: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- HoneyMyte CoolClient - Suspicious Kernel-Mode Driver Load from Non-Standard Path: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents, DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Session Data: File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.; confirm required file-access telemetry exists and produces representative events; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
