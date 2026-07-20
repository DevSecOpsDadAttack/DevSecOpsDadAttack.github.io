---
layout: post
title: "Detection Engineering Brief - Monday, July 20, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-20
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-58644
  - T1190
  - Microsoft SharePoint Server
  - Microsoft Defender
  - AMSI
  - Windows Server
  - CVE-2026-63030
  - WordPress Core
  - WordPress REST API
  - ACR Stealer
  - ClickFix
  - Windows
  - Microsoft Defender Experts
  - T1059
  - T1555
  - T1555.003
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI, Windows Server, CVE-2026-63030, WordPress Core, WordPress REST API, ACR Stealer, ClickFix, Windows, Microsoft Defender Experts, T1059, T1555, T1555.003.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Defender Security Alert Referencing SharePoint Exploitation - CVE-2026-58644; Unauthenticated POST to WordPress REST API Batch Endpoint Followed by Process Execution - CVE-2026-63030.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SharePoint Worker Process Spawning Anomalous Child Processes - CVE-2026-58644

### Detection Opportunity

Unauthenticated attacker executes arbitrary code via SharePoint deserialization flaw, resulting in child process spawning from the SharePoint IIS worker process (w3wp.exe).

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: Microsoft confirmed active in-the-wild exploitation of CVE-2026-58644, a deserialization flaw allowing unauthenticated RCE. Rapid7 identified child process spawning from the SharePoint IIS worker process and AMSI telemetry as primary detection signals.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Windows Server
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI, Windows Server

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- AmsiScriptBlockLogged and AmsiScriptDetection ActionType values in DeviceEvents require Defender for Endpoint sensor active on SharePoint hosts with AMSI integration enabled; if AMSI telemetry is not collected, the correlation arm of the query will always be empty but the base child-process detection will still fire.

**Required telemetry:**
- DeviceProcessEvents, DeviceEvents

### KQL

```kql
let LookbackWindow = 1d;
let AmsiWindow = 10;
let SuspiciousChildProcs = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe")
| project DeviceName, ChildProcTime = Timestamp, ChildProc = FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, InitiatingProcessId;
let AmsiBlocks = DeviceEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType in ("AmsiScriptBlockLogged", "AmsiScriptDetection")
| project DeviceName, AmsiTime = Timestamp, AmsiActionType = ActionType, AmsiAdditionalFields = AdditionalFields;
SuspiciousChildProcs
| join kind=leftouter (
    AmsiBlocks
) on DeviceName
| where isempty(AmsiTime) or abs(datetime_diff('minute', ChildProcTime, AmsiTime)) <= AmsiWindow
| summarize
    AmsiCorrelated = max(iff(isnotempty(AmsiTime), true, false)),
    AmsiActionType = take_any(AmsiActionType),
    AmsiAdditionalFields = take_any(AmsiAdditionalFields)
    by DeviceName, ChildProcTime, ChildProc, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, InitiatingProcessId
| extend HighConfidence = AmsiCorrelated
| order by HighConfidence desc, ChildProcTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IIS-hosted applications other than SharePoint that use w3wp.exe may spawn cmd.exe or powershell.exe for administrative tasks; scoping DeviceName to known SharePoint hosts will significantly reduce this.
- Automated deployment or health-check scripts running under IIS application pools may trigger on certutil.exe or bitsadmin.exe child processes.

**Tuning notes:**
- Add a DeviceName filter against a watchlist or dynamic group of known SharePoint Server hostnames to reduce noise from non-SharePoint IIS workloads.
- Adjust AmsiWindow (currently 10 minutes) based on observed AMSI event ingestion latency in the environment.
- Consider promoting HighConfidence=true rows to a higher severity alert tier and treating HighConfidence=false rows as medium severity.

**Risks / caveats:**
- AmsiScriptBlockLogged and AmsiScriptDetection ActionType values in DeviceEvents require Defender for Endpoint sensor active on SharePoint hosts with AMSI integration enabled; if AMSI telemetry is not collected, the correlation arm of the query will always be empty but the base child-process detection will still fire.
- Without scoping DeviceName to known SharePoint Server hostnames, the rule will fire on any IIS application pool spawning these child processes across all enrolled devices.
- The 1-day lookback window for a scheduled rule should be aligned to the rule execution frequency to avoid duplicate alerts or coverage gaps.
- AMSI AdditionalFields content varies by Defender version; analysts should validate the field structure before building automated enrichment on it.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is on a known SharePoint server and not another IIS workload; if the host is not a SharePoint host, treat as likely noise until proven otherwise.
- Review the child process name and command line for obvious attacker tradecraft such as cmd.exe, powershell.exe, mshta.exe, certutil.exe, or encoded/obfuscated arguments.
- Check whether AmsiCorrelated is true; if yes, prioritize as likely active exploitation and inspect the AMSI content for script block or detection details.
- Reconstruct the process tree using InitiatingProcessId and ProcessId to see what w3wp.exe launched and whether additional child processes followed.
- Look for nearby signs of web exploitation or post-exploitation on the same host, including new services, scheduled tasks, suspicious network connections, or additional process launches.

**Evidence to collect:**
- DeviceName, ChildProcTime, ChildProc, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, InitiatingProcessId
- AmsiCorrelated, AmsiActionType, AmsiAdditionalFields
- Any SharePoint application pool or IIS logs around the alert time showing the request path, source IP, and HTTP status
- Recent DeviceProcessEvents on the host to identify follow-on execution, persistence, or credential access
- Any Defender alerts or incident records tied to the same host within the same time window

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and a 24-hour window around ChildProcTime
- DeviceEvents filtered to AmsiScriptBlockLogged and AmsiScriptDetection for the same DeviceName
- DeviceNetworkEvents for outbound connections from the child process or w3wp.exe on the same host
- SharePoint/IIS web logs to identify the triggering request and source IP
- Defender XDR incident and alert timeline for correlated activity on the host

**Benign explanations:**
- A legitimate SharePoint administration or maintenance task may spawn a script interpreter or LOLBin from w3wp.exe.
- A non-SharePoint IIS application hosted on the same server may use w3wp.exe for normal automation or health checks.
- Automated deployment, certificate renewal, or backup tooling may invoke certutil.exe or bitsadmin.exe under an IIS context.

**Escalation criteria:**
- AmsiCorrelated is true and the AMSI content shows suspicious script execution, download, or obfuscation.
- The child process is a high-risk interpreter or LOLBin with attacker-style command-line arguments.
- Multiple suspicious child processes, outbound connections, or persistence artifacts appear on the same host.
- The host is a production SharePoint server exposed to the internet and the alert aligns with recent inbound web traffic.

**Containment actions:**
- Isolate the SharePoint server from the network if there is evidence of active exploitation or follow-on execution.
- Disable or restrict external access to the SharePoint application until the host is validated and patched.
- Preserve volatile evidence and collect process, network, and AMSI telemetry before remediation if possible.
- If a malicious child process is confirmed, terminate the process tree and block any identified malicious binaries or scripts.

**Closure criteria:**
- The host is confirmed to be a legitimate SharePoint/IIS workload and the child process is tied to an approved administrative task.
- No AMSI evidence, no suspicious follow-on activity, and no corroborating web or process telemetry are found after review.
- The alert is attributable to a known allowlisted maintenance script or deployment workflow with documented change evidence.
- The host has been patched or mitigated and no additional suspicious activity is observed during the review window.

<br/>
---
<br/>

## Detection 2: Defender Security Alert Referencing SharePoint Exploitation - CVE-2026-58644

### Detection Opportunity

Exploitation attempts against SharePoint Server surfaced through Microsoft Defender and AMSI telemetry, generating security alerts referencing SharePoint deserialization activity.

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: Rapid7 recommended leveraging Microsoft Defender and AMSI detections to identify exploitation attempts against CVE-2026-58644. Security alerts from Defender referencing SharePoint combined with AMSI scan blocks provide a correlated signal for active exploitation.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Windows Server
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI, Windows Server

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- SecurityAlert, DeviceEvents

### KQL

```kql
let LookbackWindow = 7d;
let CorrelationWindow = 30;
let SharePointAlerts = SecurityAlert
| where TimeGenerated > ago(LookbackWindow)
| where AlertName has_any ("SharePoint", "CVE-2026-58644", "deserialization")
| mv-expand Entity = parse_json(Entities)
| where Entity.Type =~ "host"
| extend DeviceName = tostring(Entity.HostName)
| where isnotempty(DeviceName)
| project AlertTime = TimeGenerated, AlertName, SystemAlertId, Severity, Description = tostring(Description), DeviceName;
let AmsiEvents = DeviceEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType in ("AmsiScriptBlockLogged", "AmsiScriptDetection")
| project DeviceName, AmsiTime = Timestamp, ActionType, AdditionalFields;
SharePointAlerts
| join kind=inner (AmsiEvents) on DeviceName
| where abs(datetime_diff('minute', AlertTime, AmsiTime)) <= CorrelationWindow
| summarize
    AmsiEventCount = count(),
    EarliestAmsiTime = min(AmsiTime),
    LatestAmsiTime = max(AmsiTime),
    AmsiActionTypes = make_set(ActionType),
    SampleAdditionalFields = take_any(AdditionalFields)
    by DeviceName, AlertTime, AlertName, SystemAlertId, Severity, Description
| order by AlertTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Defender alerts referencing SharePoint for unrelated reasons (e.g., SharePoint file download alerts) may match the keyword filter if alert naming conventions overlap.
- AMSI events on SharePoint hosts unrelated to exploitation (e.g., legitimate PowerShell administrative scripts) may produce correlated rows within the 30-minute window.

**Tuning notes:**
- Run the SharePointAlerts subquery independently first to confirm matching alerts exist in the workspace before enabling the full correlation.
- If HostName casing mismatches cause join failures, apply tolower() to both DeviceName fields before joining.
- Adjust CorrelationWindow based on observed ingestion latency between Defender alert pipeline and DeviceEvents pipeline in the workspace.

**Risks / caveats:**
- SecurityAlert requires the Microsoft Defender XDR data connector to be configured and forwarding alerts to the Sentinel workspace; without this connector, the table will be empty.
- Entity extraction from SecurityAlert.Entities using parse_json(Entities)[0].HostName assumes the first entity is always a host, which is not guaranteed by the Defender alert schema and will produce null DeviceName values for alerts where the host entity is not first.
- DeviceEvents AMSI ActionType values (AmsiScriptBlockLogged, AmsiScriptDetection) require Defender for Endpoint sensor with AMSI integration on SharePoint hosts.
- If Defender has not yet released a signature or alert rule referencing 'CVE-2026-58644' or 'deserialization' in the alert name, the SecurityAlert filter will return no results regardless of active exploitation.

### Triage Runbook

**First 15 minutes:**
- Open the Defender alert details and confirm the alert name, severity, and description actually reference SharePoint deserialization or CVE-2026-58644 activity.
- Verify the extracted DeviceName maps to a real SharePoint server and not a misidentified host from the Entities array.
- Review the correlated AMSI events for suspicious script content, encoded commands, or exploit artifacts around the alert time.
- Check whether the same host has additional Defender alerts, especially process, web, or malware detections, within the same time window.
- Determine whether the alert is tied to an externally reachable SharePoint instance and whether recent inbound traffic aligns with the alert time.

**Evidence to collect:**
- AlertName, Severity, Description, SystemAlertId, AlertTime, DeviceName
- AmsiTime, ActionType, AdditionalFields from correlated DeviceEvents
- Any additional Defender alerts on the same DeviceName within the last 24 hours
- SharePoint server logs or IIS logs showing inbound requests near AlertTime
- Any process, network, or file activity on the host that occurred shortly after the alert

**Pivot points:**
- SecurityAlert for related alerts on the same SystemAlertId, DeviceName, or time window
- DeviceEvents for AMSI script block or detection events on the same host
- DeviceProcessEvents for suspicious child processes spawned by w3wp.exe or other web processes
- DeviceNetworkEvents for outbound connections from the SharePoint host after the alert
- IIS or SharePoint logs to identify the source IP and request pattern that preceded the alert

**Benign explanations:**
- Defender may generate a SharePoint-related alert for a blocked or non-exploitable request that did not result in code execution.
- Legitimate administrative PowerShell or script activity on the SharePoint host may correlate with AMSI within the time window.
- Alert naming may overlap with unrelated SharePoint security events, such as file access or content scanning alerts.

**Escalation criteria:**
- AMSI events show exploit-like script content, encoded commands, or suspicious download behavior.
- The host has multiple correlated alerts or process events indicating post-exploitation activity.
- The alert is on a production SharePoint server exposed to the internet and there is evidence of recent inbound attack traffic.
- The alert is accompanied by suspicious child processes, outbound connections, or persistence artifacts.

**Containment actions:**
- Isolate the SharePoint host if AMSI or process evidence indicates active compromise.
- Temporarily restrict external access to the SharePoint service while triage is in progress.
- Preserve Defender alert evidence and host telemetry before remediation if the event appears malicious.
- Block any confirmed malicious source IPs or indicators only after validating they are tied to the incident.

**Closure criteria:**
- The alert is confirmed to be a benign SharePoint-related Defender event with no exploit evidence.
- Correlated AMSI activity is explained by approved administrative or maintenance scripting.
- No suspicious process, network, or file activity is found on the host after review.
- The alert is documented as informational or false positive with supporting evidence and any needed tuning notes.

<br/>
---
<br/>

## Detection 3: Unauthenticated POST to WordPress REST API Batch Endpoint Followed by Process Execution - CVE-2026-63030

### Detection Opportunity

Unauthenticated attacker sends POST requests to the WordPress REST API batch endpoint, followed by anomalous process spawning on the hosting server, indicating code execution via CVE-2026-63030.

### Intelligence Context

- Rapid7: CVE-2026-63030: wp2shell a Critical Remote Code Execution Vulnerability in WordPress Core — [https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core)
  - Context: CVE-2026-63030 allows an unauthenticated attacker to execute code via the WordPress REST API batch endpoint without valid credentials. Rapid7 identified POST requests to the batch endpoint combined with follow-on process execution as the primary detection signal.

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

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- If CommonSecurityLog RequestURL is not populated by the configured log source, the batch endpoint filter will match nothing and the query will return no results regardless of exploitation activity.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let LookbackWindow = 7d;
let ExecWindow = 5;
let BatchRequests = CommonSecurityLog
| where TimeGenerated > ago(LookbackWindow)
| where RequestMethod =~ "POST"
| where RequestURL has "/wp-json/batch/v1" or RequestURL has "/wp/v2/batch"
| extend WebHost = tolower(DeviceName), SourceIP = coalesce(SourceIP, RemoteIP)
| project WebHost, RequestTime = TimeGenerated, SourceIP, RequestURL, RequestMethod, EventOutcome;
let ShellExec = Syslog
| where TimeGenerated > ago(LookbackWindow)
| where SyslogMessage has_any ("sh ", "bash ", "python", "perl", "curl", "wget", "nc ", "ncat")
| extend SyslogHost = tolower(HostName)
| project SyslogHost, SyslogTime = TimeGenerated, SyslogMessage, ProcessName;
BatchRequests
| join kind=inner (
    ShellExec
) on $left.WebHost == $right.SyslogHost
| where SyslogTime >= RequestTime and datetime_diff('minute', SyslogTime, RequestTime) <= ExecWindow
| project WebHost, RequestTime, SourceIP, RequestURL, EventOutcome, SyslogTime, SyslogMessage, ProcessName
| order by RequestTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate WordPress plugins or cron jobs that use the batch REST API endpoint may trigger the web request filter.
- Syslog keyword matching on 'sh', 'bash', 'python', 'curl', 'wget' will match many legitimate administrative and monitoring processes running on the WordPress host.

**Tuning notes:**
- Before running the full correlation, validate CommonSecurityLog contains RequestURL values by running: CommonSecurityLog → where TimeGenerated > ago(1d) → where isnotempty(RequestURL) → summarize count() by DeviceVendor, DeviceProduct.
- Validate Syslog hostname format against CommonSecurityLog DeviceName format and apply additional normalization (e.g., split on '.') if FQDN vs. short hostname mismatch is confirmed.
- Consider replacing Syslog-based process detection with DeviceProcessEvents if the WordPress hosts are enrolled in Defender for Endpoint, which would provide structured process creation telemetry.

**Risks / caveats:**
- CommonSecurityLog.RequestURL and CommonSecurityLog.RequestMethod are only populated when the log source (WAF, reverse proxy, or web server CEF agent) is configured to forward HTTP request details; many CommonSecurityLog sources do not include these fields by default.
- Syslog process execution messages are unstructured and depend on the Linux auditd, syslog, or application logging configuration on the WordPress host; without explicit process execution logging enabled, shell spawning will not appear in SyslogMessage.
- The join key relies on DeviceName in CommonSecurityLog matching HostName in Syslog; these fields are populated by different agents and frequently differ in FQDN vs. short hostname format, causing the inner join to produce no results.
- If CommonSecurityLog RequestURL is not populated by the configured log source, the batch endpoint filter will match nothing and the query will return no results regardless of exploitation activity.

### Triage Runbook

**First 15 minutes:**
- Confirm the request was unauthenticated and targeted the vulnerable batch endpoint path rather than normal WordPress traffic.
- Review the source IP, request URL, and response outcome to see whether the request was successful or blocked.
- Inspect the correlated Syslog process execution event for the spawned process name and command line, focusing on shell, interpreter, or download behavior.
- Validate that the web host and Syslog host refer to the same server and that the process execution occurred after the request.
- Check for additional suspicious activity on the WordPress host, including new child processes, outbound connections, or file changes.

**Evidence to collect:**
- WebHost, RequestTime, SourceIP, RequestURL, RequestMethod, EventOutcome
- SyslogTime, SyslogMessage, ProcessName
- Any web server, reverse proxy, or WAF logs showing the full HTTP request and response
- Any host telemetry showing follow-on process, file, or network activity on the WordPress server
- Any authentication, admin, or deployment activity that could explain the request or process execution

**Pivot points:**
- CommonSecurityLog for additional requests from the same SourceIP or to the same WebHost
- Syslog for nearby process execution events on the same host
- DeviceProcessEvents if the WordPress host is enrolled in Defender for Endpoint
- DeviceNetworkEvents or firewall logs for outbound connections after the request
- Web server logs to confirm whether the batch endpoint request was accepted, blocked, or returned an error

**Benign explanations:**
- A legitimate plugin, cron job, or administrative workflow may use the WordPress batch endpoint.
- A security scanner or synthetic monitoring tool may generate POST requests to the endpoint.
- Syslog process keywords may match normal maintenance commands or monitoring utilities on the host.

**Escalation criteria:**
- The request is unauthenticated, targeted the vulnerable endpoint, and is followed by suspicious shell or interpreter execution.
- The spawned process shows attacker-style command-line arguments, downloads, or encoded content.
- There is evidence of outbound connections, file drops, or persistence on the WordPress host after the request.
- Multiple requests from the same source IP or repeated exploitation attempts are observed.

**Containment actions:**
- If process execution is confirmed and suspicious, isolate the WordPress host from the network.
- Temporarily disable public access to the WordPress site or vulnerable endpoint while triage is underway.
- Preserve web, Syslog, and host telemetry before restarting services or applying cleanup.
- Block confirmed malicious source IPs at the WAF, reverse proxy, or firewall after validation.

**Closure criteria:**
- The request is shown to be legitimate application behavior, maintenance, or approved scanning.
- The correlated process execution is benign and consistent with normal server administration.
- No additional suspicious host activity, outbound connections, or file changes are found.
- The host is patched or otherwise mitigated and the event is documented with supporting evidence.

<br/>
---
<br/>

## Detection 4: ClickFix Lure Initiating Script Interpreter Execution from Browser Process - ACR Stealer

### Detection Opportunity

ClickFix lures cause users to execute script interpreters (PowerShell, mshta, wscript) spawned directly from browser processes, initiating the ACR Stealer intrusion chain.

### Intelligence Context

- Microsoft Security Blog: ACR Stealer: Two observed intrusion chains amid increased threat activity — [https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)
  - Context: Microsoft Defender Experts observed ACR Stealer campaigns using ClickFix lures to trick users into executing script interpreters from browser processes. This parent-child process chain (browser spawning mshta, wscript, or powershell) is the initial execution stage of the intrusion chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1555, T1555.003
- Products: Microsoft Defender Experts
- Platforms: Windows
- Malware: ACR Stealer
- Tools: ClickFix
- Search tags: ACR Stealer, ClickFix, Windows, Microsoft Defender Experts, T1555, T1555.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores/ T1555.003 Credentials from Web Browsers (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 1d;
DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe",
    "iexplore.exe", "brave.exe", "opera.exe"
)
| where FileName in~ (
    "powershell.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "cmd.exe", "rundll32.exe",
    "regsvr32.exe", "msiexec.exe", "scrobj.dll"
)
| where ProcessCommandLine has_any (
    "-enc", "-EncodedCommand", "FromBase64String",
    "IEX", "Invoke-Expression", "hidden", "bypass",
    "http", "https"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId,
    InitiatingProcessId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise IT automation or endpoint management tools that launch PowerShell with encoded commands from browser-based management consoles may trigger this rule.
- Browser-based developer tools or CI/CD integrations that invoke script interpreters with base64-encoded payloads may match the command-line filter.

**Tuning notes:**
- Run the query without the ProcessCommandLine filter first to baseline browser-to-interpreter spawning frequency in the environment before enabling the full rule.
- Add FolderPath exclusions for known-legitimate script execution paths used by IT automation tools (e.g., specific management agent directories) to reduce false positives.
- Consider adding InitiatingProcessFolderPath exclusions for browser installations in non-standard paths if enterprise browser deployments differ from default locations.

**Risks / caveats:**
- The command-line filter includes broad terms such as 'http' and 'https' which may match legitimate browser extensions or update mechanisms that spawn helper processes with URL arguments.
- The 1-day lookback window should be aligned to the scheduled rule execution frequency to avoid duplicate detections or coverage gaps.

### Triage Runbook

**First 15 minutes:**
- Review the parent-child chain to confirm a browser process launched powershell.exe, mshta.exe, wscript.exe, cscript.exe, cmd.exe, or another listed interpreter.
- Inspect the command line for obfuscation indicators such as -enc, -EncodedCommand, FromBase64String, IEX, hidden, or bypass.
- Identify the user account and device involved to determine whether this was a user-driven action or an automated tool.
- Check whether the browser path and command line look normal or whether the browser was launched from an unusual location or with suspicious arguments.
- Look for immediate follow-on activity such as downloads, script execution, credential access, or outbound connections from the same host.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
- FileName, FolderPath, ProcessCommandLine, ProcessId, InitiatingProcessId
- Any browser history, download records, or user-reported lure content if available
- DeviceNetworkEvents for outbound connections from the spawned interpreter or browser
- Any subsequent DeviceProcessEvents showing payload execution, persistence, or credential theft behavior

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName around the alert time
- DeviceNetworkEvents for the child process and browser on the same host
- DeviceFileEvents for downloads or script drops shortly after the browser-to-interpreter launch
- Defender alerts or incidents involving the same user or device
- Email, browser, or proxy logs if available to identify the lure source

**Benign explanations:**
- An IT support portal or browser-based management console may legitimately launch a script interpreter.
- A developer or automation workflow may use browser-triggered scripts with encoded or base64 content.
- Some enterprise tools open browser-based helper flows that invoke command-line utilities from the browser context.

**Escalation criteria:**
- The command line contains clear obfuscation or download behavior and is not tied to an approved tool.
- The same host shows follow-on credential access, file drops, or outbound connections after the browser launch.
- The user reports clicking a lure, entering commands, or seeing a suspicious prompt consistent with ClickFix.
- Multiple suspicious interpreter launches occur from the browser or the host shows additional malware indicators.

**Containment actions:**
- Isolate the endpoint if the interpreter launch appears malicious or if follow-on activity is observed.
- Disable the affected user session or reset credentials if there is evidence the user interacted with a lure and the host is compromised.
- Preserve process and network evidence before remediation if possible.
- Block any confirmed malicious payload URLs, domains, or binaries identified during triage.

**Closure criteria:**
- The browser-to-interpreter launch is tied to an approved administrative or automation workflow.
- The command line and parent process context are consistent with legitimate use and no malicious follow-on activity is found.
- No additional suspicious process, file, or network events are present on the host.
- The event is documented as benign with any necessary allowlist or tuning follow-up.

<br/>
---
<br/>

## Detection 5: Non-Browser Process Accessing Browser Credential Stores - ACR Stealer

### Detection Opportunity

ACR Stealer accesses browser credential store files (Login Data, cookies, token caches) from non-browser processes to steal credentials and authentication tokens from enterprise environments.

### Intelligence Context

- Microsoft Security Blog: ACR Stealer: Two observed intrusion chains amid increased threat activity — [https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)
  - Context: Microsoft Defender Experts confirmed ACR Stealer steals browser credentials, authentication tokens, and sensitive documents from enterprise environments. The stealer accesses browser credential store files and token cache directories from non-browser processes, producing file read events detectable via DeviceFileEvents.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1555, T1555.003
- Products: Microsoft Defender Experts
- Platforms: Windows
- Malware: ACR Stealer
- Tools: ClickFix
- Search tags: ACR Stealer, ClickFix, Windows, Microsoft Defender Experts, T1555, T1555.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores/ T1555.003 Credentials from Web Browsers (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let LookbackWindow = 1d;
let BrowserProcesses = dynamic([
    "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "iexplore.exe"
]);
let DefenderProcesses = dynamic([
    "MsMpEng.exe", "SenseIR.exe", "MsSense.exe",
    "SecurityHealthService.exe", "WdNisSvc.exe"
]);
DeviceFileEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType in ("FileRead", "FileAccessed")
| where (
    FileName in~ ("Login Data", "Cookies", "Web Data", "Local State", "token_state", "Bookmarks")
    or FolderPath has_any (
        "\\User Data\\Default\\",
        "\\Mozilla\\Firefox\\Profiles\\",
        "\\Microsoft\\Edge\\User Data\\",
        "\\Microsoft\\Teams\\Local Storage\\",
        "\\Microsoft\\Teams\\Cookies"
    )
)
| where InitiatingProcessFileName !in~ (BrowserProcesses)
| where InitiatingProcessFileName !in~ (DefenderProcesses)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ActionType,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents (e.g., Veeam, Acronis, Windows Backup) that perform file-level backups of user profile directories will access browser credential store files.
- Endpoint management tools (e.g., SCCM, Intune management extensions) that inventory or migrate user profiles may access browser credential paths.
- Password manager applications that integrate with browser credential stores may trigger on Login Data or Cookies file access.

**Tuning notes:**
- Run the query without the InitiatingProcessFileName exclusion filters first to identify all processes accessing browser credential paths in the environment, then build the exclusion list from observed legitimate processes.
- Validate that FileRead or FileAccessed ActionType values are present in DeviceFileEvents by running: DeviceFileEvents → where Timestamp > ago(1d) → summarize count() by ActionType → order by count_ desc.
- Add known backup agent and endpoint management process names to the DefenderProcesses exclusion list or create a separate dynamic exclusion list for IT tools.

**Risks / caveats:**
- FileRead and FileAccessed ActionType values in DeviceFileEvents depend on Defender for Endpoint sensor configuration; some environments may only surface FileCreated or FileModified events for credential store paths, and file read telemetry may not be collected at all depending on the sensor version and policy.
- FileRead and FileAccessed ActionType values may not be collected in all Defender for Endpoint deployments; if these action types are absent, the query will return no results even when credential store access occurs. Validate ActionType coverage before scheduling.
- The exclusion lists for browser and Defender processes are not exhaustive; additional legitimate processes accessing browser credential stores will need to be identified through baseline review and added to the exclusion lists.
- The 1-day lookback window should be aligned to the scheduled rule execution frequency.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process is not a browser or Defender sensor process and review its name, path, and command line.
- Inspect the accessed file name and folder path to verify it is a browser credential store, cookie database, token cache, or related artifact.
- Check the account context to see whether the access aligns with a user session, service account, or scheduled task.
- Review the SHA256 of the initiating process binary for threat intelligence hits or known-good software identification.
- Look for immediate follow-on signs of credential theft or staging, including archive creation, outbound connections, or access to additional sensitive files.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
- FileName, FolderPath, ActionType, SHA256
- Any related DeviceProcessEvents showing the same process spawning child processes or launching network tools
- Any DeviceNetworkEvents from the initiating process after the file access
- Any backup, endpoint management, or password manager activity on the same host and time window

**Pivot points:**
- DeviceFileEvents for the same DeviceName and InitiatingProcessFileName around the alert time
- DeviceProcessEvents to see whether the process is part of a broader intrusion chain
- DeviceNetworkEvents for outbound connections from the initiating process
- Defender alerts on the same host or user for credential access, malware, or suspicious scripting
- Change or job logs for backup, migration, or endpoint management tools that may explain the access

**Benign explanations:**
- Backup agents may read user profile data, including browser databases, during backup or restore operations.
- Endpoint management or migration tools may inventory or copy browser profile content.
- Password managers or enterprise support tools may legitimately access browser-related files in some environments.

**Escalation criteria:**
- The initiating process is unknown, unsigned, or located in an unusual path and is not a recognized IT tool.
- The process accesses multiple browser credential stores or token caches across users or profiles.
- There is evidence of archive creation, exfiltration, or outbound connections after the file access.
- The same host or user shows additional suspicious process activity consistent with a stealer infection.

**Containment actions:**
- Isolate the endpoint if the process is unknown or if multiple credential store accesses suggest active theft.
- Disable or reset affected user credentials if there is evidence browser tokens or passwords may have been exposed.
- Preserve the process binary and file access evidence before cleanup if possible.
- Block the initiating process hash or path if it is confirmed malicious.

**Closure criteria:**
- The process is identified as a legitimate backup, management, or password-related tool with supporting evidence.
- The file access pattern is consistent with approved operations and no other suspicious activity is found.
- No malicious network, process, or persistence behavior is observed on the host.
- The event is documented as benign and any necessary exclusions or tuning are recorded.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- SharePoint Worker Process Spawning Anomalous Child Processes - CVE-2026-58644: AmsiScriptBlockLogged and AmsiScriptDetection ActionType values in DeviceEvents require Defender for Endpoint sensor active on SharePoint hosts with AMSI integration enabled; if AMSI telemetry is not collected, the correlation arm of the query will always be empty but the base child-process detection will still fire.

**Schema / correlation keys:**
- Defender Security Alert Referencing SharePoint Exploitation - CVE-2026-58644: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- Unauthenticated POST to WordPress REST API Batch Endpoint Followed by Process Execution - CVE-2026-63030: If CommonSecurityLog RequestURL is not populated by the configured log source, the batch endpoint filter will match nothing and the query will return no results regardless of exploitation activity.

**Shared-table notes:**
- DeviceProcessEvents: shared by SharePoint Worker Process Spawning Anomalous Child Processes - CVE-2026-58644; ClickFix Lure Initiating Script Interpreter Execution from Browser Process - ACR Stealer
- DeviceEvents: shared by SharePoint Worker Process Spawning Anomalous Child Processes - CVE-2026-58644; Defender Security Alert Referencing SharePoint Exploitation - CVE-2026-58644

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SharePoint Worker Process Spawning Anomalous Child Processes - CVE-2026-58644; ClickFix Lure Initiating Script Interpreter Execution from Browser Process - ACR Stealer; Non-Browser Process Accessing Browser Credential Stores - ACR Stealer.
2. Resolve environment-mapping detections next: Unauthenticated POST to WordPress REST API Batch Endpoint Followed by Process Execution - CVE-2026-63030.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Defender Security Alert Referencing SharePoint Exploitation - CVE-2026-58644.

### Hunting Agenda and Promotion Criteria

- Defender Security Alert Referencing SharePoint Exploitation - CVE-2026-58644: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Unauthenticated POST to WordPress REST API Batch Endpoint Followed by Process Execution - CVE-2026-63030: If CommonSecurityLog RequestURL is not populated by the configured log source, the batch endpoint filter will match nothing and the query will return no results regardless of exploitation activity.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
