---
layout: post
title: "Detection Engineering Brief - Saturday, July 18, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-18
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-58644
  - T1190
  - T1059
  - Microsoft SharePoint Server
  - Microsoft Defender
  - AMSI
  - Windows
  - CVE-2026-63030
  - WordPress Core
  - WordPress REST API
  - Linux
  - T1056
  - T1555
  - T1528
  - T1005
  - ACR Stealer
  - T1555.003
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

4 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-58644, T1190, T1059, Microsoft SharePoint Server, Microsoft Defender, AMSI, Windows, CVE-2026-63030, WordPress Core, WordPress REST API, Linux, T1056, T1555, T1528, T1005, ACR Stealer, T1555.003.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: ACR Stealer - Non-Browser Process Accessing Browser Credential Stores.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-58644 SharePoint RCE - Suspicious Child Process from w3wp.exe

### Detection Opportunity

Suspicious child process spawned from SharePoint IIS worker process (w3wp.exe) indicating unauthenticated remote code execution via CVE-2026-58644.

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: Microsoft confirmed active exploitation of CVE-2026-58644 allowing unauthenticated attackers to execute arbitrary code on SharePoint Server. Post-exploitation process activity is detectable via Defender for Endpoint EDR by observing shells or script interpreters spawned from the IIS worker process w3wp.exe.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, T1059, Microsoft SharePoint Server, Microsoft Defender, AMSI, Windows

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
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ChildProcess = FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- SharePoint health monitoring or timer jobs that invoke cmd.exe or PowerShell for maintenance tasks.
- Legitimate administrative scripts executed via IIS on non-SharePoint application pools sharing the same host.

**Tuning notes:**
- After initial deployment, collect InitiatingProcessAccountName values for w3wp.exe on SharePoint hosts to identify the specific application pool accounts; use these to scope or exclude known-benign identities.
- Consider adding a ProcessCommandLine filter for encoded commands or download cradles (e.g., has_any("-enc", "DownloadString", "iex")) to increase signal fidelity for PowerShell child processes.
- If bitsadmin.exe or certutil.exe generate noise from legitimate SharePoint operations, add conditional exclusions on ProcessCommandLine patterns rather than removing the process names entirely.

**Risks / caveats:**
- DeviceProcessEvents is only populated when Defender for Endpoint is onboarded on the SharePoint Server host. If the host is not onboarded, the query returns no results.
- Hosts running multiple IIS-hosted applications alongside SharePoint will produce results from non-SharePoint app pools; scoping DeviceName to a confirmed SharePoint host list is recommended after initial baselining.
- The 7-day lookback window may surface historical events unrelated to active exploitation; adjust to a shorter window once the rule is scheduled.
- certutil.exe and bitsadmin.exe have legitimate administrative uses; ProcessCommandLine review is required to distinguish malicious invocations.

### Triage Runbook

**First 15 minutes:**
- Verify the host is a real SharePoint server and that Microsoft Defender for Endpoint is onboarded on it; if not, treat the alert as incomplete telemetry rather than benign.
- Review the child process name, command line, parent command line, and initiating account to determine whether this is a known maintenance task or an attacker shell/script launch.
- Check whether the child process is a LOLBin or interpreter such as cmd.exe, powershell.exe, mshta.exe, wscript.exe, cscript.exe, certutil.exe, or bitsadmin.exe and whether the command line shows download, decode, or execution behavior.
- Look for additional process activity from the same device in the same time window, especially follow-on network, file, or persistence activity.
- If the process tree is clearly malicious or the command line is suspicious, treat the host as potentially compromised and move to containment.

**Evidence to collect:**
- DeviceName, Timestamp, InitiatingProcessAccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, and SHA256 for the alerting process.
- Any related DeviceProcessEvents on the same host within the prior and subsequent 1-2 hours to identify follow-on execution.
- SharePoint application pool identity and whether that account is expected to spawn the observed child process.
- Any Defender, AMSI, or server-side logs showing exploit attempts, web requests, or script content around the alert time.
- Whether the spawned binary resides in an unusual path such as temp, user-writable, or dropped locations.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName = w3wp.exe to find all child processes around the alert time.
- DeviceProcessEvents filtered on the child SHA256 to identify other hosts or repeated executions.
- AlertInfo and AlertEvidence for any Defender or AMSI alerts on the same DeviceName and time window.
- DeviceNetworkEvents for the same DeviceName to look for outbound connections from the child process or its descendants.
- DeviceFileEvents for the same DeviceName to identify dropped payloads or web shell artifacts.

**Benign explanations:**
- SharePoint health monitoring, timer jobs, or scheduled maintenance may legitimately invoke cmd.exe or PowerShell from the IIS worker process.
- Administrative scripts executed through a SharePoint application pool may create expected child processes on a known management host.
- Some environments use IIS-hosted automation that can spawn certutil.exe or bitsadmin.exe for legitimate package retrieval or maintenance.

**Escalation criteria:**
- The child process is a shell, script host, or downloader with suspicious arguments such as encoded commands, download cradles, or execution from temp paths.
- The same host shows additional suspicious processes, outbound connections, or file drops consistent with post-exploitation activity.
- The initiating account is an unexpected application pool identity or the process tree does not match known SharePoint maintenance behavior.
- There are corroborating Defender, AMSI, or web logs indicating exploitation of SharePoint or suspicious remote code execution.

**Containment actions:**
- Isolate the SharePoint server from the network if malicious execution is confirmed or strongly suspected.
- Preserve volatile evidence before rebooting, including process tree, command lines, and any dropped files.
- Disable or rotate credentials for the SharePoint application pool identity if compromise is suspected.
- Block the observed SHA256 or child process path if it is clearly malicious and not a legitimate administrative tool.

**Closure criteria:**
- The child process is confirmed to be a documented SharePoint maintenance or administrative action with matching change records.
- No additional suspicious process, network, or file activity is found on the host after review of the surrounding time window.
- The initiating account and command line match an approved baseline for that SharePoint server.
- Any suspicious binary or command line is attributed to a benign tool and documented for future allowlisting.

<br/>
---
<br/>

## Detection 2: CVE-2026-58644 SharePoint RCE - Defender Alert Correlated with w3wp.exe Process Execution

### Detection Opportunity

Defender or AMSI alert referencing SharePoint exploitation correlated with concurrent suspicious process activity on the same device, indicating active exploitation of CVE-2026-58644.

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: Rapid7 noted that exploitation attempts against CVE-2026-58644 are detectable via Microsoft Defender and AMSI telemetry. Correlating Defender alert signals referencing SharePoint with process execution events on the same host provides a compound high-fidelity detection.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, T1059, Microsoft SharePoint Server, Microsoft Defender, AMSI, Windows

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- AlertInfo and AlertEvidence are only populated when Defender for Endpoint or AMSI detections fire on the host. If no relevant alerts have been generated, the SharePointAlerts subquery returns empty and the join produces no results.

**Required telemetry:**
- AlertInfo, AlertEvidence, DeviceProcessEvents

### KQL

```kql
let SharePointAlerts =
    AlertInfo
    | where Timestamp > ago(7d)
    | where Title has_any ("SharePoint", "CVE-2026-58644") or Category =~ "Exploit"
    | project AlertId, AlertTime = Timestamp, AlertTitle = Title, AlertSeverity = Severity
    | join kind=inner (
        AlertEvidence
        | where Timestamp > ago(7d)
        | where EntityType =~ "Machine"
        | project AlertId, DeviceName
    ) on AlertId
    | project AlertTime, DeviceName, AlertTitle, AlertSeverity;
let SuspiciousProcs =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "w3wp.exe"
    | where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")
    | project ProcTime = Timestamp, DeviceName, ChildProcess = FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256;
SharePointAlerts
| join kind=inner SuspiciousProcs on DeviceName
| extend MinutesDelta = abs(datetime_diff('minute', AlertTime, ProcTime))
| where MinutesDelta <= 60
| project
    AlertTime,
    ProcTime,
    MinutesDelta,
    DeviceName,
    AlertTitle,
    AlertSeverity,
    ChildProcess,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    SHA256
| order by AlertTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Defender alerts for unrelated exploit attempts on the same host that coincide with legitimate w3wp.exe child process activity.
- AMSI detections from PowerShell scripts run by SharePoint administrators that trigger within the correlation window.

**Tuning notes:**
- Add → where AlertSeverity in ('High', 'Medium') to the SharePointAlerts subquery if low-severity AMSI informational alerts generate noise.
- After initial deployment, review MinutesDelta distribution to determine whether the 60-minute window should be tightened.
- If the environment has multiple IIS-hosted applications on SharePoint hosts, add an InitiatingProcessAccountName filter to scope w3wp.exe events to known SharePoint application pool identities.

**Risks / caveats:**
- AlertEvidence EntityType field value for device entities is documented as 'Machine' in Defender XDR; if this value differs in a specific tenant configuration, the filter will drop all device-linked alert records.
- AlertInfo and AlertEvidence are only populated when Defender for Endpoint or AMSI detections fire on the host. If no relevant alerts have been generated, the SharePointAlerts subquery returns empty and the join produces no results.
- DeviceProcessEvents is only populated when Defender for Endpoint is onboarded on the SharePoint Server host.
- The Category =~ 'Exploit' filter is broad and will match any Defender exploit-category alert on the host, not only SharePoint-specific ones; the w3wp.exe process join provides behavioral scoping but does not eliminate all cross-application matches.

### Triage Runbook

**First 15 minutes:**
- Open the Defender or AMSI alert details and confirm the title, severity, and affected device match the SharePoint host in the process event.
- Compare the alert timestamp and process timestamp to ensure they are temporally related and not an unrelated alert on the same server.
- Inspect the child process command line for encoded commands, script execution, download behavior, or other post-exploitation indicators.
- Check whether the alert references SharePoint, exploit activity, or suspicious script content rather than a generic or informational detection.
- If both telemetry sources align and the process is suspicious, escalate as likely active exploitation.

**Evidence to collect:**
- AlertTitle, AlertSeverity, AlertTime, ProcTime, MinutesDelta, DeviceName, ChildProcess, ProcessCommandLine, InitiatingProcessCommandLine, and SHA256.
- Full AlertInfo and AlertEvidence context, including any related entities and detection category.
- Any additional DeviceProcessEvents on the same host before and after the alert to identify follow-on execution.
- Any AMSI script content or Defender remediation details associated with the alert.
- SharePoint host role, application pool identity, and whether the observed process is expected on that server.

**Pivot points:**
- AlertInfo joined with AlertEvidence for all alerts on the same DeviceName and within the same time window.
- DeviceProcessEvents for the same DeviceName to identify all w3wp.exe child processes and descendants.
- DeviceFileEvents for dropped files or web shell artifacts on the same host.
- DeviceNetworkEvents for outbound connections from the child process or related descendants.
- Advanced hunting across AlertInfo for other SharePoint, exploit, or AMSI alerts in the tenant.

**Benign explanations:**
- A benign SharePoint maintenance task may coincide with an unrelated Defender exploit alert on the same host.
- AMSI may flag administrative PowerShell content that is legitimate but resembles exploit behavior.
- The alert may be broad and not specific to CVE-2026-58644, especially if the title only loosely references SharePoint or exploit activity.

**Escalation criteria:**
- The alert and process event are tightly correlated and the child process is clearly malicious or unusual for SharePoint.
- There is evidence of web shell activity, encoded PowerShell, downloader behavior, or dropped payloads.
- Multiple alerts or repeated process executions occur on the same host within a short period.
- The host shows signs of lateral movement, persistence, or credential theft after the initial alert.

**Containment actions:**
- Isolate the SharePoint server if the alert is confirmed to be part of active exploitation.
- Preserve Defender and AMSI evidence before any remediation actions that could destroy forensic artifacts.
- Disable or rotate the SharePoint application pool identity if attacker execution is confirmed.
- Block malicious hashes or paths identified in the correlated process event.

**Closure criteria:**
- The Defender or AMSI alert is determined to be unrelated to the w3wp.exe process activity after review.
- The process command line and alert context match an approved administrative action or known benign script.
- No additional suspicious activity is found on the host during the correlated time window.
- The alert is documented as a false positive with a clear reason and any needed tuning note.

<br/>
---
<br/>

## Detection 3: CVE-2026-63030 WordPress RCE - Shell Spawned from Web Server Process on Linux Host

### Detection Opportunity

Shell or interpreter process spawned from Apache, Nginx, or PHP-FPM on a Linux host, indicating successful unauthenticated RCE via the WordPress REST API batch endpoint (CVE-2026-63030).

### Intelligence Context

- Rapid7: CVE-2026-63030: wp2shell a Critical Remote Code Execution Vulnerability in WordPress Core — [https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core)
  - Context: CVE-2026-63030 allows an unauthenticated attacker to execute code via the WordPress REST API batch endpoint, potentially resulting in complete compromise of the host. Post-exploitation shell spawning from the web server parent process is the primary behavioral indicator on Linux WordPress hosts.

### Search Metadata

- CVEs: CVE-2026-63030
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: WordPress Core, WordPress REST API
- Platforms: Linux, Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63030, T1190, T1059, WordPress Core, WordPress REST API, Linux, Windows

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
let WebServerParents = dynamic([
    "apache2", "httpd", "nginx",
    "php-fpm", "php",
    "php8.0", "php8.1", "php8.2", "php8.3",
    "php7.4", "php7.3",
    "php-fpm8.0", "php-fpm8.1", "php-fpm8.2", "php-fpm8.3",
    "php-fpm7.4"
]);
let SuspiciousChildren = dynamic([
    "bash", "sh", "dash", "zsh", "ksh",
    "python", "python3", "perl", "ruby",
    "nc", "ncat", "curl", "wget"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (WebServerParents)
| where FileName in~ (SuspiciousChildren)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    ParentProcess = InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ChildProcess = FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- WordPress CLI (wp-cli) commands executed via PHP-FPM for plugin updates, cache clearing, or database maintenance.
- Legitimate curl or wget invocations by PHP-FPM for outbound API calls or health checks configured in WordPress.
- Monitoring agents or backup scripts running under the web server account that invoke shell interpreters.

**Tuning notes:**
- After initial deployment, collect ProcessCommandLine values for php-fpm child processes to identify wp-cli patterns and add exclusions such as: → where not(ProcessCommandLine has 'wp-cli') or → where not(ProcessCommandLine has '/usr/local/bin/wp').
- If curl or wget generate excessive noise from legitimate PHP outbound calls, consider removing them from SuspiciousChildren and creating a separate hunting query focused on curl/wget with suspicious argument patterns (e.g., pipe to bash, -O to /tmp).
- Consider adding a FolderPath filter to flag child processes executing from /tmp, /dev/shm, or other world-writable directories as a higher-confidence indicator.

**Risks / caveats:**
- DeviceProcessEvents Linux process telemetry requires the Defender for Endpoint Linux agent to be deployed and onboarded on WordPress hosting servers. If the agent is absent, the query returns no results.
- PHP-FPM process names are version-suffixed in many distributions (e.g., php-fpm8.2, php-fpm7.4). The query covers common variants but non-standard build names will not match without extension.
- PHP-FPM version-suffixed process names beyond those listed (e.g., php-fpm8.4 or distribution-specific variants) will not match; extend the WebServerParents list as new PHP versions are deployed.
- The query does not distinguish between WordPress hosts and other PHP-based web applications; scoping DeviceName to a WordPress host list after initial baselining is recommended.

### Triage Runbook

**First 15 minutes:**
- Verify the host is a WordPress server and identify the parent process type, such as apache2, httpd, nginx, or php-fpm.
- Review the child process and command line for shells, interpreters, reverse shell tools, or download utilities such as bash, sh, python, perl, curl, wget, nc, or ncat.
- Check the initiating account and folder path to see whether the child binary was launched from a suspicious writable location like /tmp or /dev/shm.
- Look for repeated child process creation from the same web server parent, which may indicate interactive attacker activity.
- If the command line or process path is suspicious, treat the host as compromised and begin containment.

**Evidence to collect:**
- DeviceName, Timestamp, AccountName, InitiatingProcessAccountName, ParentProcess, InitiatingProcessCommandLine, ChildProcess, ProcessCommandLine, FolderPath, and SHA256.
- Any related DeviceProcessEvents on the same host showing follow-on shell activity or additional spawned interpreters.
- Web server logs or application logs around the event time to identify the request that triggered execution.
- Any outbound network connections from the child process or its descendants.
- Any dropped files, scripts, or artifacts in world-writable directories.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and parent process names to find all suspicious child processes.
- DeviceNetworkEvents for the same host and child process to identify command-and-control or download activity.
- DeviceFileEvents for the same host to find dropped payloads or modified web content.
- Linux web server logs or WordPress application logs to correlate the triggering request.
- SHA256 pivots across DeviceProcessEvents to find reuse on other hosts.

**Benign explanations:**
- WordPress CLI maintenance tasks may legitimately spawn shells or interpreters through PHP-FPM.
- Cron jobs or backup scripts running under the web server account can create shell activity that resembles exploitation.
- Legitimate outbound API calls from PHP applications may use curl or wget.

**Escalation criteria:**
- The child process is a shell, interpreter, or network utility with suspicious arguments or execution from a writable directory.
- The same host shows repeated web-server-originated process creation or outbound connections consistent with attacker control.
- The process tree includes reverse shell behavior, payload download, or post-exploitation tooling.
- The host is a production WordPress server and the activity cannot be explained by a known maintenance window or approved job.

**Containment actions:**
- Isolate the Linux host if malicious execution is confirmed or strongly suspected.
- Preserve process, network, and web log evidence before remediation.
- Disable the affected WordPress site or virtual host if needed to stop active exploitation.
- Block malicious binaries or hashes identified during triage.

**Closure criteria:**
- The process is confirmed to be a scheduled WordPress maintenance or backup task with matching change records.
- The parent and child process relationship matches a known benign automation pattern on that host.
- No additional suspicious process, network, or file activity is found after review.
- The event is documented and any recurring benign pattern is added to tuning guidance.

<br/>
---
<br/>

## Detection 4: ACR Stealer - ClickFix Lure Execution via Script Host Spawned from Browser Process

### Detection Opportunity

ClickFix lure execution leading to ACR Stealer deployment, observed as mshta.exe, wscript.exe, or encoded PowerShell spawned from a browser process following user interaction with a malicious lure page.

### Intelligence Context

- Microsoft Security Blog: ACR Stealer: Two observed intrusion chains amid increased threat activity — [https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)
  - Context: Microsoft observed ACR Stealer campaigns using ClickFix lures to trick users into executing malicious scripts. The intrusion chains produce distinctive process trees where script hosts or encoded PowerShell are launched from browser parent processes, followed by credential theft from browser stores.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1056, T1555, T1528, T1005, T1555.003
- Products: Microsoft Defender
- Platforms: Windows
- Malware: ACR Stealer
- Tools: Not specified
- Search tags: T1056, T1555, T1528, T1005, Microsoft Defender, Windows, ACR Stealer, T1555.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores/ T1555.003 Credentials from Web Browsers (high); Credential Access: T1005 Data from Local System (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let BrowserParents = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe"]);
let ScriptHosts = dynamic(["powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "cmd.exe"]);
let ClickFixProcs =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ (BrowserParents)
    | where FileName in~ (ScriptHosts)
    | where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64", "iex", "Invoke-Expression", "DownloadString", "WebClient")
    | project
        SpawnTime = Timestamp,
        DeviceName,
        AccountName,
        BrowserParent = InitiatingProcessFileName,
        ScriptHostName = FileName,
        ScriptCommandLine = ProcessCommandLine,
        SHA256;
let CredAccess =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("Login Data", "Cookies", "Web Data", "logins.json", "key4.db", "cert9.db")
    | where FolderPath has_any ("\\Chrome\\", "\\Edge\\", "\\Firefox\\", "\\Brave\\", "\\Opera\\", "\\Chromium\\")
    | where not(InitiatingProcessFileName in~ (BrowserParents))
    | where ActionType in~ ("FileRead", "FileAccessed", "FileCopied")
    | project
        AccessTime = Timestamp,
        DeviceName,
        AccountName,
        CredFileName = FileName,
        CredPath = FolderPath,
        AccessingProcess = InitiatingProcessFileName,
        ActionType;
ClickFixProcs
| join kind=inner CredAccess on DeviceName, AccountName
| extend MinutesDelta = datetime_diff('minute', AccessTime, SpawnTime)
| where MinutesDelta >= 0 and MinutesDelta <= 30
| project
    SpawnTime,
    AccessTime,
    MinutesDelta,
    DeviceName,
    AccountName,
    BrowserParent,
    ScriptHostName,
    ScriptCommandLine,
    SHA256,
    CredFileName,
    CredPath,
    AccessingProcess,
    ActionType
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise IT automation tools that use browser-based management consoles and spawn PowerShell with encoded commands for legitimate configuration tasks.
- Password manager or credential sync utilities that access browser Login Data files using non-browser processes.
- Security scanning or endpoint management agents that enumerate browser credential store paths during inventory or compliance checks.

**Tuning notes:**
- Validate ActionType values in DeviceFileEvents by running: DeviceFileEvents → where FileName =~ 'Login Data' → summarize by ActionType — and adjust the ActionType filter to match observed values.
- If password manager utilities (e.g., 1Password, Bitwarden desktop) access browser credential files, add their process names to the exclusion list in the CredAccess subquery.
- Reduce MinutesDelta threshold from 30 to 10 minutes if the join produces unrelated pairings on endpoints with frequent background credential access activity.
- Consider adding a second detection variant without the ProcessCommandLine encoded command filter to catch ClickFix chains that use plaintext script invocations.

**Risks / caveats:**
- DeviceFileEvents ActionType values for file read operations vary by Defender for Endpoint version and OS configuration. 'FileRead' and 'FileAccessed' may not be present; 'FileCopied' is the most consistently available ActionType for credential store access. Validate ActionType values in the environment before relying on this filter.
- DeviceFileEvents may not capture all file read events for browser credential stores depending on Defender for Endpoint sensor configuration and file access auditing settings on the endpoint.
- DeviceFileEvents ActionType coverage for file read operations is not guaranteed across all Defender for Endpoint sensor versions; if FileRead and FileAccessed are absent, the CredAccess subquery may return no results even when credential access occurs.
- The join on DeviceName and AccountName may produce false pairings on shared workstations or terminal servers where multiple users are active; consider adding a ProcessId or InitiatingProcessId correlation if available.

### Triage Runbook

**First 15 minutes:**
- Confirm the browser parent, script host, and command line; treat browser-spawned mshta.exe, wscript.exe, cscript.exe, or encoded PowerShell as highly suspicious.
- Check whether the command line contains encoded commands, Invoke-Expression, DownloadString, WebClient, or other lure-execution indicators.
- Review the correlated credential-access event to see whether browser store files were accessed shortly after script execution.
- Identify the user who interacted with the browser and determine whether they reported a prompt, fake verification page, or copy-paste instruction consistent with ClickFix.
- If the script execution and credential access are both present, escalate immediately as likely compromise.

**Evidence to collect:**
- SpawnTime, AccessTime, MinutesDelta, DeviceName, AccountName, BrowserParent, ScriptHostName, ScriptCommandLine, SHA256, CredFileName, CredPath, AccessingProcess, and ActionType.
- Browser history, download history, and any visible lure page URL if available from endpoint or proxy logs.
- Any additional DeviceProcessEvents showing child processes spawned by the script host.
- Any DeviceFileEvents or browser profile access events that show credential store reads or copies.
- User-reported symptoms, screenshots, or helpdesk notes describing the lure interaction.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName to find the full process tree from the browser parent.
- DeviceFileEvents for browser credential store paths on the same host and account.
- DeviceNetworkEvents for outbound connections from the script host or its descendants.
- Browser or proxy logs to identify the lure page and any downloaded payloads.
- AlertInfo and AlertEvidence for any related Defender detections on the same device.

**Benign explanations:**
- Some enterprise management portals legitimately launch PowerShell from a browser for administrative tasks.
- A browser-based support workflow may use script hosts for automation, though encoded commands are still unusual.
- Password manager or security tooling may access browser data after a browser-triggered workflow, but this should be rare and documented.

**Escalation criteria:**
- The browser-spawned script host uses encoded commands or download-and-execute behavior.
- A correlated credential access event occurs shortly after script execution on the same device and account.
- The user did not expect the browser action or reports a suspicious prompt, fake verification, or copy-paste instruction.
- There is evidence of additional payload execution, persistence, or outbound connections after the initial lure.

**Containment actions:**
- Isolate the endpoint if malicious script execution and credential access are confirmed.
- Reset or revoke browser-based session tokens and passwords for the affected user if credential theft is suspected.
- Preserve browser artifacts, script command lines, and any downloaded files before cleanup.
- Block malicious hashes, URLs, or domains if identified during investigation.

**Closure criteria:**
- The browser-to-script chain is confirmed to be a legitimate administrative workflow with documented approval.
- The correlated credential access is attributed to a known benign tool such as a password manager or backup agent.
- No additional suspicious process, file, or network activity is found on the host.
- The event is documented with a clear benign explanation and tuning action if needed.

<br/>
---
<br/>

## Detection 5: ACR Stealer - Non-Browser Process Accessing Browser Credential Stores

### Detection Opportunity

Non-browser process accessing browser Login Data or cookie files, consistent with ACR Stealer harvesting browser credentials and authentication tokens from enterprise endpoints.

### Intelligence Context

- Microsoft Security Blog: ACR Stealer: Two observed intrusion chains amid increased threat activity — [https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/07/16/acr-stealer-two-observed-intrusion-chains-amid-increased-threat-activity/)
  - Context: Microsoft confirmed ACR Stealer steals browser credentials and authentication tokens from enterprise environments. The stealer accesses browser credential store files (Login Data, cookies) using non-browser processes, a high-fidelity behavioral indicator with well-known file paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1056, T1555, T1528, T1005, T1555.003
- Products: Microsoft Defender
- Platforms: Windows
- Malware: ACR Stealer
- Tools: Not specified
- Search tags: T1056, T1555, T1528, T1005, Microsoft Defender, Windows, ACR Stealer, T1555.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores/ T1555.003 Credentials from Web Browsers (high); Credential Access: T1005 Data from Local System (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let KnownBrowsers = dynamic([
    "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "chromium.exe", "iexplore.exe"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("Login Data", "Cookies", "Web Data", "logins.json", "key4.db", "cert9.db")
| where FolderPath has_any ("\\Chrome\\", "\\Edge\\", "\\Firefox\\", "\\Brave\\", "\\Opera\\", "\\Chromium\\")
| where not(InitiatingProcessFileName in~ (KnownBrowsers))
| where ActionType in~ ("FileRead", "FileAccessed", "FileCopied")
| summarize
    AccessCount = count(),
    Files = make_set(FileName),
    Processes = make_set(InitiatingProcessFileName),
    ActionTypes = make_set(ActionType),
    SuspiciousPaths = make_set(FolderPath),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, AccountName
| where AccessCount >= 2
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project
    DeviceName,
    AccountName,
    AccessCount,
    DurationMinutes,
    Files,
    Processes,
    ActionTypes,
    SuspiciousPaths,
    FirstSeen,
    LastSeen
| order by AccessCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise backup agents (e.g., Veeam, Acronis) that back up user profile directories including browser credential stores.
- Password manager desktop applications (e.g., 1Password, Bitwarden, LastPass) that read browser credential files for import or sync.
- Endpoint security or DLP tools that scan browser credential store paths for sensitive data classification.
- IT management or inventory agents that enumerate user profile directories.

**Tuning notes:**
- Before scheduling as a recurring hunt, validate ActionType values: DeviceFileEvents → where FileName =~ 'Login Data' → summarize by ActionType — and update the ActionType filter to match observed values in the environment.
- Review the Processes column in hunt results to identify legitimate tools; add confirmed-benign process names to the KnownBrowsers exclusion list or a separate exclusion dynamic array.
- Increase AccessCount threshold to 5 or higher if backup or DLP agents generate multi-file access events across browser directories on every scan cycle.
- Add → where InitiatingProcessFolderPath has_any ('%TEMP%', '%APPDATA%\\Roaming', 'C:\\Users\\Public') as an optional high-confidence filter to surface processes running from suspicious locations.

**Risks / caveats:**
- DeviceFileEvents ActionType values for file read operations (FileRead, FileAccessed) are not guaranteed to be present across all Defender for Endpoint sensor versions and OS configurations. If these ActionType values are absent, the query returns no results despite credential access occurring.
- DeviceFileEvents may not capture passive file read events for browser credential stores depending on endpoint sensor configuration; only file write, copy, or rename events may be reliably captured in some configurations.
- ActionType coverage for file read events is the primary reliability risk; validate by running DeviceFileEvents → where FileName =~ 'Login Data' → summarize by ActionType before relying on this query for hunting.
- The AccessCount >= 2 threshold is a starting point; environments with backup agents or DLP tools will require a higher threshold or process-name exclusions to avoid analyst fatigue.

### Triage Runbook

**First 15 minutes:**
- Identify the accessing process and confirm it is not a browser or an approved password manager, backup agent, or security tool.
- Review the file names and paths accessed, especially Login Data, Cookies, Web Data, logins.json, key4.db, and cert9.db.
- Check whether the process is running from a suspicious location such as temp, user profile, or public writable directories.
- Assess whether the access count and timing suggest bulk harvesting rather than a one-off legitimate read.
- If the process is unknown or clearly malicious, escalate and begin containment.

**Evidence to collect:**
- DeviceName, AccountName, AccessCount, Files, Processes, ActionTypes, SuspiciousPaths, FirstSeen, and LastSeen.
- The full process path and command line for each accessing process in the Processes set.
- Any related DeviceProcessEvents showing how the accessing process was launched.
- Any DeviceNetworkEvents from the same process or host that indicate exfiltration or command-and-control.
- Any user or admin change records that explain why browser credential stores were accessed.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and accessing process names to reconstruct the process tree.
- DeviceFileEvents for the same host and account to see whether other sensitive files were accessed.
- DeviceNetworkEvents for the same host and process to identify outbound transfer activity.
- AlertInfo and AlertEvidence for any related Defender detections on the same endpoint.
- SHA256 pivots if the accessing process hash is available from other telemetry.

**Benign explanations:**
- Password manager applications may read browser credential stores during import, sync, or migration.
- Backup agents may access browser profile directories as part of full-user-profile backups.
- Security or DLP tools may enumerate browser data for inspection or classification.
- IT inventory or migration tools may touch browser profile files during endpoint management tasks.

**Escalation criteria:**
- The accessing process is unknown, unsigned, or running from a suspicious path.
- The process accesses multiple browser credential files or does so repeatedly in a short period.
- There is evidence of credential theft follow-on activity such as browser token use, exfiltration, or additional suspicious processes.
- The process is associated with a recent ClickFix or other suspicious execution chain on the same host.

**Containment actions:**
- Isolate the endpoint if the process is confirmed or strongly suspected to be credential theft malware.
- Terminate the malicious process only after preserving evidence if possible.
- Reset affected browser passwords and revoke active sessions if credential theft is likely.
- Block the process hash or path if it is clearly malicious.

**Closure criteria:**
- The accessing process is identified as a known approved tool with a documented business purpose.
- The access pattern matches expected backup, migration, or password manager behavior.
- No additional suspicious activity is found on the host or account.
- The event is documented and any benign process names are added to tuning guidance.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- CVE-2026-58644 SharePoint RCE - Defender Alert Correlated with w3wp.exe Process Execution: AlertInfo and AlertEvidence are only populated when Defender for Endpoint or AMSI detections fire on the host. If no relevant alerts have been generated, the SharePointAlerts subquery returns empty and the join produces no results.
- ACR Stealer - Non-Browser Process Accessing Browser Credential Stores: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by CVE-2026-58644 SharePoint RCE - Suspicious Child Process from w3wp.exe; CVE-2026-58644 SharePoint RCE - Defender Alert Correlated with w3wp.exe Process Execution; CVE-2026-63030 WordPress RCE - Shell Spawned from Web Server Process on Linux Host; ACR Stealer - ClickFix Lure Execution via Script Host Spawned from Browser Process
- DeviceFileEvents: shared by ACR Stealer - ClickFix Lure Execution via Script Host Spawned from Browser Process; ACR Stealer - Non-Browser Process Accessing Browser Credential Stores

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: CVE-2026-58644 SharePoint RCE - Suspicious Child Process from w3wp.exe; CVE-2026-58644 SharePoint RCE - Defender Alert Correlated with w3wp.exe Process Execution; CVE-2026-63030 WordPress RCE - Shell Spawned from Web Server Process on Linux Host; ACR Stealer - ClickFix Lure Execution via Script Host Spawned from Browser Process.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ACR Stealer - Non-Browser Process Accessing Browser Credential Stores.

### Hunting Agenda and Promotion Criteria

- ACR Stealer - Non-Browser Process Accessing Browser Credential Stores: Do not schedule yet; validate as an analyst-led hunt first.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
