---
layout: post
title: "Detection Engineering Brief - Sunday, July 19, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-19
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-58644
  - T1190
  - Microsoft SharePoint Server
  - Microsoft Defender
  - AMSI
  - CVE-2026-63030
  - WordPress Core
  - WordPress REST API
  - ACR Stealer
  - ClickFix
  - enterprise endpoints
  - T1059
  - T1204.002
  - T1204
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

4 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI, CVE-2026-63030, WordPress Core, WordPress REST API, ACR Stealer, ClickFix, enterprise endpoints, T1059, T1204.002, T1204.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-58644 SharePoint RCE - AMSI Alert Correlation on SharePoint Host.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-58644 SharePoint RCE - Suspicious Child Process from IIS Worker

### Detection Opportunity

Deserialization of untrusted data via CVE-2026-58644 triggering unexpected child process execution from SharePoint IIS worker process (w3wp.exe).

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: Microsoft confirmed active exploitation of CVE-2026-58644, a deserialization RCE vulnerability allowing unauthenticated attackers to execute arbitrary code on SharePoint Server. Exploitation reliably produces anomalous child processes spawned from the IIS worker process w3wp.exe.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "cscript.exe",
    "wscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "net.exe",
    "net1.exe",
    "whoami.exe",
    "ipconfig.exe",
    "nltest.exe",
    "rundll32.exe",
    "regsvr32.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessParentFileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative scripts executed in the context of a SharePoint application pool by operations teams.
- Monitoring or APM agents that spawn cmd.exe or powershell.exe from w3wp.exe for health checks.
- Other IIS-hosted applications on the same host that also run under w3wp.exe.

**Tuning notes:**
- Scope DeviceName to a watchlist or dynamic list of confirmed SharePoint Server hostnames to reduce false positives from other IIS applications.
- Exclude known legitimate ProcessCommandLine patterns observed during baseline review, such as specific monitoring agent invocations.
- Consider adding nltest.exe and rundll32.exe to the child process list based on post-exploitation tradecraft observed in similar IIS RCE campaigns.
- Schedule the rule to run at an interval equal to or shorter than the lookback window to avoid coverage gaps.

**Risks / caveats:**
- Defender for Endpoint must be onboarded on SharePoint Server hosts and process telemetry must be flowing to DeviceProcessEvents; if the agent is not deployed on server-class hosts, the query will return no results.
- Without scoping DeviceName to known SharePoint Server hosts, the rule will fire on any IIS-hosted application that spawns these child processes, increasing false positive volume.
- The 24-hour lookback window may miss low-and-slow exploitation attempts if scheduled rule frequency is not aligned to the lookback period.
- net1.exe and rundll32.exe additions may increase noise in environments with legitimate administrative use of those binaries from IIS context.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is a known SharePoint Server host and that the parent process chain is w3wp.exe with a SharePoint application pool context.
- Review the child process name, command line, and SHA256 to determine whether it matches common post-exploitation tooling or an administrative script.
- Check for nearby AMSI, Defender, or other security alerts on the same host and time window that indicate exploitation or follow-on activity.
- Look for additional suspicious processes spawned from w3wp.exe on the same host within the last 24 hours.

**Evidence to collect:**
- DeviceName, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256, and Timestamp from the alert.
- Any AMSI content, Defender alert titles, and related process events around the same timestamp.
- SharePoint application pool name or IIS site context from the w3wp.exe command line if present.
- Recent process tree activity on the host showing whether the spawned process launched additional shells, scripting engines, or network utilities.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName=w3wp.exe over the last 24 hours.
- DeviceEvents for AmsiScriptDetection or other Defender alerts on the same DeviceName and time range.
- DeviceNetworkEvents for outbound connections from the spawned process or its descendants.
- DeviceFileEvents for newly written web shells, scripts, or suspicious files in SharePoint or IIS directories.

**Benign explanations:**
- A legitimate SharePoint administration script or monitoring agent running under the IIS worker process.
- APM, health-check, or backup tooling that is intentionally launched from the SharePoint application pool.
- Another IIS-hosted application on the same server that is not SharePoint but uses w3wp.exe.

**Escalation criteria:**
- The child process is a shell, scripting interpreter, or LOLBin with an attacker-like command line, especially if it is followed by network activity or file writes.
- Multiple suspicious child processes are spawned from w3wp.exe or the same host also has AMSI/Defender evidence of exploitation.
- The host is internet-facing, the process chain is not tied to a known admin workflow, or the spawned process hash is unknown and suspicious.

**Containment actions:**
- Isolate the SharePoint server from the network if the child process or follow-on activity indicates active compromise.
- Preserve volatile evidence and collect the process tree, command lines, and relevant logs before remediation.
- Disable or restrict external access to the SharePoint service until the exploitation path is understood and patched.

**Closure criteria:**
- The process is confirmed as a known-good SharePoint administrative or monitoring action with matching baseline command line and approved change record.
- No additional suspicious child processes, AMSI hits, network connections, or file modifications are found on the host.
- The host is confirmed patched or otherwise not vulnerable, and the activity is attributable to a benign IIS-hosted application.

<br/>
---
<br/>

## Detection 2: CVE-2026-58644 SharePoint RCE - AMSI Alert Correlation on SharePoint Host

### Detection Opportunity

AMSI telemetry surfacing exploitation attempts of CVE-2026-58644 against SharePoint Server, correlated with Defender security alerts on server-class devices.

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: AMSI integration with Microsoft Defender can surface exploitation attempts against SharePoint. Active exploitation of CVE-2026-58644 was confirmed by Microsoft, making Defender alert correlation on SharePoint hosts a viable secondary detection layer.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI, T1059

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

**Required telemetry:**
- DeviceEvents, DeviceProcessEvents

### KQL

```kql
let AmsiHits = DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "AmsiScriptDetection"
| where InitiatingProcessFileName =~ "w3wp.exe"
| extend ParsedFields = parse_json(AdditionalFields)
| extend AmsiContent = tostring(ParsedFields.ScriptContent)
| project AmsiTime = Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ActionType, AmsiContent, ParsedFields;
let ChildSpawns = DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "cscript.exe",
    "wscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "net.exe",
    "net1.exe",
    "whoami.exe"
)
| project SpawnTime = Timestamp, DeviceName, SpawnedProcess = FileName, ProcessCommandLine, SHA256;
AmsiHits
| join kind=inner ChildSpawns on DeviceName
| where SpawnTime between ((AmsiTime - 2m) .. (AmsiTime + 2m))
| project
    AmsiTime,
    SpawnTime,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    ActionType,
    AmsiContent,
    SpawnedProcess,
    ProcessCommandLine,
    SHA256
| order by AmsiTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate PowerShell-based SharePoint administration scripts scanned by AMSI that coincide with routine w3wp.exe child process activity.
- Security scanning tools or vulnerability scanners that trigger AMSI detections against SharePoint endpoints during authorized assessments.
- Busy IIS hosts where unrelated w3wp.exe child process spawns fall within the correlation window of an AMSI event.

**Tuning notes:**
- Validate that AmsiScriptDetection events are present in DeviceEvents for the target SharePoint hosts before using this query in a hunting session.
- Scope DeviceName to confirmed SharePoint Server hostnames to reduce noise from other IIS-hosted applications.
- Adjust the correlation window from 2 minutes based on observed ingestion latency in the environment.
- Review AdditionalFields schema for AmsiScriptDetection in the target tenant to confirm the ScriptContent field name before relying on AmsiContent projection.

**Risks / caveats:**
- AmsiScriptDetection as an ActionType value in DeviceEvents must be confirmed as populated in the target tenant; AMSI telemetry requires Defender for Endpoint with AMSI integration enabled on the SharePoint Server host. If AMSI telemetry is not flowing, the query will return no results.
- DeviceEvents AdditionalFields schema for AmsiScriptDetection events is not publicly documented as stable; parse_json output fields may vary across Defender versions.
- The two-minute correlation window is a heuristic; environments with high ingestion latency may miss correlated events or produce false negatives.
- Joining on DeviceName alone without a process ID anchor may produce spurious correlations on hosts running multiple w3wp.exe instances simultaneously.

### Triage Runbook

**First 15 minutes:**
- Confirm the AMSI event content and determine whether it contains exploit payloads, script fragments, or suspicious encoded commands.
- Verify the correlated child process was spawned by w3wp.exe on the same host within the expected time window.
- Check whether the host is a SharePoint server and whether the alert aligns with known maintenance or scanning activity.
- Look for additional Defender alerts, process spawns, or network activity from the same host immediately after the AMSI event.

**Evidence to collect:**
- AmsiContent, ActionType, DeviceName, AccountName, InitiatingProcessFileName, SpawnedProcess, ProcessCommandLine, SHA256, AmsiTime, and SpawnTime.
- Any related Defender security alerts and the exact AMSI script content or parsed fields from AdditionalFields.
- Process lineage for the spawned process and any descendant processes.
- Network connections, file writes, and authentication events occurring shortly after the AMSI detection.

**Pivot points:**
- DeviceEvents filtered to AmsiScriptDetection on the same DeviceName.
- DeviceProcessEvents for w3wp.exe child processes and descendants on the same host.
- DeviceNetworkEvents for the spawned process SHA256 or process tree.
- DeviceFileEvents for dropped scripts, web shells, or suspicious files on the SharePoint host.

**Benign explanations:**
- Authorized security testing or vulnerability scanning against the SharePoint server.
- Legitimate SharePoint administration scripts that were scanned by AMSI and coincided with normal w3wp.exe activity.
- Busy IIS hosts where unrelated w3wp.exe child process activity happened to fall within the correlation window.

**Escalation criteria:**
- The AMSI content shows exploit code, obfuscated script, or commands consistent with post-exploitation activity.
- The correlated child process is a shell, scripting interpreter, or LOLBin and is followed by network or file activity.
- The same host generates multiple AMSI detections or additional Defender alerts indicating exploitation or persistence.

**Containment actions:**
- Isolate the SharePoint host if the AMSI content or correlated process indicates active exploitation.
- Preserve the AMSI payload, process tree, and related telemetry for incident response.
- Block external access to the SharePoint service until the server is patched and reviewed.

**Closure criteria:**
- The AMSI event is confirmed to be benign administrative or security testing activity with approved change context.
- No suspicious child process, network, or file activity follows the AMSI event.
- The correlation is determined to be spurious due to unrelated w3wp.exe activity on a busy host.

<br/>
---
<br/>

## Detection 3: CVE-2026-63030 WordPress RCE - Shell Process Spawned from Web Server Process

### Detection Opportunity

Unexpected shell or interpreter process spawned from a web server process on a WordPress host, consistent with unauthenticated RCE exploitation via the WordPress REST API batch endpoint (CVE-2026-63030).

### Intelligence Context

- Rapid7: CVE-2026-63030: wp2shell a Critical Remote Code Execution Vulnerability in WordPress Core — [https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core)
  - Context: CVE-2026-63030 allows unauthenticated attackers to execute code via the WordPress REST API batch endpoint with no account or user interaction required. Successful exploitation reliably produces shell or interpreter processes spawned from the web server process (apache2, nginx, php-fpm).

### Search Metadata

- CVEs: CVE-2026-63030
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: WordPress Core, WordPress REST API
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63030, T1190, WordPress Core, WordPress REST API, T1059

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
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "apache2",
    "httpd",
    "nginx",
    "php",
    "php-fpm",
    "php-cgi",
    "php7.4",
    "php8.0",
    "php8.1",
    "php8.2",
    "php8.3"
)
| where FileName in~ (
    "bash",
    "sh",
    "dash",
    "zsh",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "curl",
    "wget",
    "nc",
    "ncat",
    "whoami",
    "id",
    "uname",
    "awk"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative cron jobs or deployment pipelines that invoke bash or python from a web server process context.
- WordPress CLI (wp-cli) operations that run under the web server user and spawn shell processes.
- Monitoring agents or health check scripts executed in the web server process context.
- PHP-based build or test frameworks that spawn interpreter processes during legitimate operation.

**Tuning notes:**
- Scope DeviceName to a watchlist or dynamic list of confirmed WordPress hosting server hostnames to reduce false positives.
- Exclude known legitimate ProcessCommandLine patterns such as wp-cli invocations, deployment pipeline scripts, and monitoring agent health checks identified during baseline review.
- Add additional php-fpm variant binary names if the environment uses non-standard PHP packaging.
- Consider adding mkfifo, socat, and busybox to the child process list as they are used in reverse shell payloads targeting Linux web servers.

**Risks / caveats:**
- Defender for Endpoint Linux agent must be deployed on WordPress hosting servers and process telemetry must be flowing to DeviceProcessEvents; if the Linux agent is not deployed, the query will return no results.
- Linux process names in DeviceProcessEvents may appear without path prefix depending on agent version and OS configuration; the in~ operator handles case but not path variations.
- Without scoping DeviceName to known WordPress hosting servers, the rule will fire on any Linux web server host running Defender for Endpoint, increasing false positive volume.
- php-fpm worker processes may appear under variant names depending on the PHP version and OS packaging; additional php-fpmX.Y entries may be needed.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a WordPress server and identify the parent process type, such as apache2, nginx, or php-fpm.
- Review the spawned process name and command line for reverse shell behavior, download-and-execute patterns, or reconnaissance commands.
- Check whether the process is tied to a known deployment, cron job, or maintenance workflow on the server.
- Look for immediate follow-on activity such as outbound connections, file writes, or additional child processes.

**Evidence to collect:**
- DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256, and Timestamp.
- Process tree from the web server parent through any descendants.
- Network connections from the spawned process and any files created or modified after execution.
- Any web server, PHP, or application logs showing suspicious REST API requests or command injection indicators.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and web server parent process over the last 24 hours.
- DeviceNetworkEvents for the spawned process SHA256 or process tree.
- DeviceFileEvents for new scripts, web shells, or suspicious binaries on the WordPress host.
- Web server and application logs for unusual REST API batch endpoint activity around the alert time.

**Benign explanations:**
- A legitimate administrative script or deployment pipeline that runs under the web server context.
- wp-cli or maintenance tooling executed by the web server user during normal operations.
- Monitoring or health-check tooling that intentionally spawns shell or interpreter processes.

**Escalation criteria:**
- The spawned process is a shell, interpreter, or network utility with attacker-like arguments or encoded payloads.
- The host shows outbound connections, file drops, or additional suspicious processes after the initial spawn.
- The activity occurs on an internet-facing WordPress server with no approved maintenance window or change record.

**Containment actions:**
- Isolate the WordPress host if the process or follow-on activity indicates active compromise.
- Disable external access to the WordPress site or vulnerable endpoint until patched.
- Preserve process, network, and web log evidence before remediation or reboot.

**Closure criteria:**
- The activity is confirmed as a known-good administrative or deployment action with matching command line and change record.
- No suspicious descendants, network connections, or file modifications are found.
- The host is confirmed not vulnerable or the alert is attributable to a benign web server workflow.

<br/>
---
<br/>

## Detection 4: ACR Stealer - Browser Credential Store Access by Non-Browser Process

### Detection Opportunity

ACR Stealer accessing browser credential stores (Login Data, Cookies) via a non-browser process following ClickFix lure execution on enterprise endpoints.

### Intelligence Context

- Microsoft Security Blog: ACR Stealer: Two observed intrusion chains amid increased threat activity — [https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)
  - Context: ACR Stealer is deployed via ClickFix lure campaigns and steals browser credentials, authentication tokens, and sensitive documents from enterprise endpoints. Accessing browser Login Data and Cookies files from non-browser processes is a defining behavioral characteristic of this stealer.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204.002, T1059, T1204
- Products: Microsoft Defender
- Platforms: enterprise endpoints
- Malware: ACR Stealer
- Tools: ClickFix
- Search tags: ACR Stealer, ClickFix, Microsoft Defender, enterprise endpoints, T1204.002, T1059, T1204

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let BrowserCredAccess = DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName in~ ("Login Data", "Cookies", "Web Data")
| where FolderPath has_any (
    "\\Google\\Chrome\\User Data",
    "\\Microsoft\\Edge\\User Data",
    "\\Mozilla\\Firefox\\Profiles",
    "\\BraveSoftware\\Brave-Browser\\User Data",
    "\\Opera Software\\Opera Stable",
    "\\Vivaldi\\User Data"
)
| where InitiatingProcessFileName !in~ (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe"
)
| project
    FileAccessTime = Timestamp,
    DeviceName,
    AccountName,
    FolderPath,
    FileName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    SHA256;
let LureExecution = DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "explorer.exe"
)
| where FileName in~ (
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "cmd.exe"
)
| project
    LureTime = Timestamp,
    DeviceName,
    LureAccountName = AccountName,
    LureParent = InitiatingProcessFileName,
    LureChild = FileName,
    LureCommandLine = ProcessCommandLine,
    LureSHA256 = SHA256;
BrowserCredAccess
| join kind=inner LureExecution on DeviceName
| where FileAccessTime > LureTime
| where FileAccessTime <= LureTime + 10m
| project
    FileAccessTime,
    LureTime,
    DeviceName,
    AccountName,
    FolderPath,
    FileName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    SHA256,
    LureParent,
    LureChild,
    LureCommandLine,
    LureSHA256
| order by FileAccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise password manager or SSO agents that access browser credential stores as part of legitimate credential synchronization.
- Backup or endpoint management agents that read browser profile directories during scheduled backup operations.
- Security tools performing credential exposure assessments that access Login Data files.
- Browser update or migration utilities that access credential stores during profile migration.

**Tuning notes:**
- Extend the correlation time window beyond 10 minutes if ACR Stealer variants with longer post-execution delays are observed in the environment.
- Add additional browser executable names to the exclusion list if non-standard browsers are deployed in the environment.
- Add ProcessCommandLine exclusions for known legitimate enterprise tools that access browser credential stores, such as password manager agents identified during baseline review.
- Consider adding AccountName to the join condition alongside DeviceName to reduce spurious correlations on multi-user endpoints.

**Risks / caveats:**
- DeviceFileEvents must capture file read/access events for browser profile directories; if Defender for Endpoint file access auditing is not configured or the browser profile paths are not monitored, the credential access events will not appear.
- Firefox stores credentials in a Profiles subdirectory with a randomized profile folder name; the has_any path filter for Firefox may not match all profile path variants depending on the profile name format.
- The 10-minute correlation window between lure execution and credential file access is a heuristic; ACR Stealer variants with longer dwell times between execution and credential theft will not be correlated.
- Joining on DeviceName alone without a process lineage anchor may produce spurious correlations on endpoints where multiple users are active simultaneously.

### Triage Runbook

**First 15 minutes:**
- Confirm the file access occurred after a browser-initiated lure execution on the same device and account.
- Review the accessing process name, command line, and hash to determine whether it is a known browser helper, admin tool, or suspicious binary.
- Check whether the same endpoint has related browser-to-script execution, AMSI, Defender, or network alerts.
- Identify whether the accessed files are browser Login Data, Cookies, or Web Data from Chrome, Edge, Firefox, Brave, Opera, or Vivaldi profiles.

**Evidence to collect:**
- FileAccessTime, LureTime, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, ProcessCommandLine, SHA256, LureParent, LureChild, LureCommandLine, and LureSHA256.
- Any browser-spawned script interpreter events on the same device and account.
- Network connections and file writes from the accessing process and any descendants.
- User activity context, including whether the user reported a ClickFix prompt or pasted commands into a browser page.

**Pivot points:**
- DeviceFileEvents for browser credential store access on the same DeviceName and AccountName.
- DeviceProcessEvents for browser-to-script-interpreter execution on the same endpoint.
- DeviceNetworkEvents for the accessing process SHA256 and its descendants.
- DeviceEvents for AMSI or Defender detections tied to the same device and time window.

**Benign explanations:**
- A legitimate password manager, SSO agent, or browser migration utility accessing browser stores.
- Backup or endpoint management software reading browser profile directories during scheduled operations.
- Security assessment tooling authorized to inspect browser credential storage.

**Escalation criteria:**
- The accessing process is unknown, unsigned, or has a suspicious command line and is not a known enterprise tool.
- The endpoint also shows browser-spawned script execution, credential theft behavior, or outbound connections to suspicious infrastructure.
- Multiple browser credential files are accessed in quick succession or the same user/device shows repeated lure-and-access patterns.

**Containment actions:**
- Isolate the endpoint if the process and surrounding telemetry indicate active credential theft.
- Reset potentially exposed browser, SSO, and enterprise credentials for the affected user if compromise is confirmed.
- Preserve the lure, process, and file access evidence before remediation.

**Closure criteria:**
- The accessing process is confirmed as a sanctioned enterprise tool with expected command line and change record.
- No suspicious browser lure execution, network activity, or additional credential access is found.
- The file access is attributable to backup, migration, or security testing activity already approved by the business.

<br/>
---
<br/>

## Detection 5: ACR Stealer - ClickFix Lure Execution via Script Interpreter Spawned from Browser

### Detection Opportunity

ClickFix lure execution resulting in a script interpreter (PowerShell, mshta, wscript) being spawned from a browser process on enterprise endpoints, consistent with the first intrusion chain stage of ACR Stealer deployment.

### Intelligence Context

- Microsoft Security Blog: ACR Stealer: Two observed intrusion chains amid increased threat activity — [https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)
  - Context: ClickFix campaigns successfully lure users into executing clipboard-pasted commands via browser-initiated prompts. This produces a characteristic pattern of script interpreters (powershell.exe, mshta.exe, wscript.exe) spawned directly from browser processes, which is the initial execution stage of ACR Stealer intrusion chains.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204.002, T1059, T1204
- Products: Microsoft Defender
- Platforms: enterprise endpoints
- Malware: ACR Stealer
- Tools: ClickFix
- Search tags: ACR Stealer, ClickFix, Microsoft Defender, enterprise endpoints, T1204.002, T1059, T1204

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "iexplore.exe"
)
| where FileName in~ (
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "cmd.exe"
)
| where not (
    ProcessCommandLine has "--type=" or
    ProcessCommandLine has "--extension" or
    ProcessCommandLine has "--renderer" or
    ProcessCommandLine has "--gpu-process" or
    ProcessCommandLine has "--utility"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise browser management extensions or group policy integrations that legitimately spawn PowerShell or cmd.exe from the browser process.
- Browser-based developer tools or testing frameworks that invoke script interpreters during legitimate development workflows.
- Electron-based applications that present as browser processes and spawn script interpreters as part of their normal operation.
- Enterprise SSO or authentication helpers that are invoked from the browser context and spawn cmd.exe or PowerShell.

**Tuning notes:**
- Baseline the environment for browser-to-script-interpreter spawn patterns before enabling as a scheduled alert to identify legitimate enterprise tooling that requires ProcessCommandLine exclusions.
- Add ProcessCommandLine exclusions for known legitimate browser helper or enterprise management integrations identified during baseline review.
- Consider correlating alerts from this rule with the companion ACR Stealer credential access detection on the same DeviceName within a 10-minute window to increase confidence before escalating.
- Increase severity to High if the same device also triggers the browser credential store access detection within the correlation window.

**Risks / caveats:**
- Defender for Endpoint must be deployed on enterprise endpoints and DeviceProcessEvents must capture parent-child process relationships; if the agent is not deployed or process telemetry is not flowing, the query will return no results.
- Browser-spawned script interpreter patterns from legitimate enterprise tooling will require environment-specific ProcessCommandLine exclusions identified during baseline review before false positive volume is acceptable for scheduling.
- Electron-based applications that present as browser processes in DeviceProcessEvents may generate false positives that are difficult to distinguish from ClickFix lure execution without additional context.
- The detection fires on the initial execution stage only; without correlation to subsequent credential access or network activity, individual alerts require analyst triage to confirm ACR Stealer involvement.

### Triage Runbook

**First 15 minutes:**
- Review the browser parent process, command line, and the spawned interpreter command line for signs of clipboard-pasted or encoded payloads.
- Check whether the user recently visited a suspicious site, received a prompt to paste commands, or reported a ClickFix-style lure.
- Determine whether the browser process is a standard browser or an enterprise helper, extension host, or Electron-based application.
- Look for a second-stage event on the same device, especially browser credential store access or suspicious outbound connections.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, and SHA256.
- Any browser history, user-reported lure details, or screenshots if available.
- Process tree showing the browser parent and any child processes spawned after the interpreter.
- Network and file activity from the spawned interpreter and any descendants.

**Pivot points:**
- DeviceProcessEvents for browser-spawned interpreters on the same DeviceName and AccountName.
- DeviceFileEvents for browser credential store access after the lure execution.
- DeviceNetworkEvents for the spawned interpreter and its descendants.
- DeviceEvents for AMSI or other Defender detections on the same endpoint.

**Benign explanations:**
- A browser-based enterprise management tool or extension that legitimately launches PowerShell or cmd.exe.
- Developer tooling or testing frameworks that invoke interpreters from a browser context.
- An Electron-based application that appears as a browser process but is not a web browser.

**Escalation criteria:**
- The interpreter command line contains obfuscation, encoded content, download-and-execute behavior, or other malicious indicators.
- The same device later shows browser credential access, suspicious network traffic, or additional malware-like process activity.
- The user reports being instructed to paste commands into a browser page or the browser activity is clearly tied to a ClickFix lure.

**Containment actions:**
- If the command line is clearly malicious or the endpoint shows follow-on activity, isolate the device.
- Preserve the browser and interpreter process tree, command lines, and any related user activity evidence.
- If the event is part of a confirmed ClickFix campaign, reset exposed credentials after compromise is validated.

**Closure criteria:**
- The browser-to-interpreter action is confirmed as a sanctioned enterprise workflow or known browser helper.
- No follow-on credential access, network beaconing, or additional suspicious processes are observed.
- The command line and user context are consistent with benign development, testing, or management activity.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- CVE-2026-58644 SharePoint RCE - AMSI Alert Correlation on SharePoint Host: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by CVE-2026-58644 SharePoint RCE - Suspicious Child Process from IIS Worker; CVE-2026-58644 SharePoint RCE - AMSI Alert Correlation on SharePoint Host; CVE-2026-63030 WordPress RCE - Shell Process Spawned from Web Server Process; ACR Stealer - Browser Credential Store Access by Non-Browser Process; ACR Stealer - ClickFix Lure Execution via Script Interpreter Spawned from Browser

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: CVE-2026-58644 SharePoint RCE - Suspicious Child Process from IIS Worker; CVE-2026-63030 WordPress RCE - Shell Process Spawned from Web Server Process; ACR Stealer - Browser Credential Store Access by Non-Browser Process; ACR Stealer - ClickFix Lure Execution via Script Interpreter Spawned from Browser.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: CVE-2026-58644 SharePoint RCE - AMSI Alert Correlation on SharePoint Host.

### Hunting Agenda and Promotion Criteria

- CVE-2026-58644 SharePoint RCE - AMSI Alert Correlation on SharePoint Host: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
