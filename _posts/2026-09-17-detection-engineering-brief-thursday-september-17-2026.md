---
layout: post
title: "Detection Engineering Brief - Thursday, September 17, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-17
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-85706
  - T1190
  - GitLab CE
  - GitLab EE
  - CVE-2026-76461
  - T1059
  - Cisco Secure Email Gateway
  - Cisco AsyncOS
  - macOS
  - AMOS
  - NightEagle
  - GhostContainer
  - Active Directory
  - RDP
  - GitHub
  - T1555
  - T1213
  - T1105
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 2 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-85706, T1190, GitLab CE, GitLab EE, CVE-2026-76461, T1059, Cisco Secure Email Gateway, Cisco AsyncOS, macOS, AMOS, NightEagle, GhostContainer, Active Directory, RDP, GitHub, T1555, T1213, T1105.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-85706 GitLab Path Traversal Attempt via Commits API; CVE-2026-76461 Cisco Secure Email Gateway SQL Injection via Syslog Anomaly; CVE-2026-76461 Cisco SEG Post-Exploitation Root Command Execution via Syslog; AMOS Stealer macOS Credential Store Access by Non-Browser Process; NightEagle APT GitHub Payload Retrieval by Non-Browser Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-85706 GitLab Path Traversal Attempt via Commits API

### Detection Opportunity

Unauthenticated path traversal against GitLab repository commits API containing directory traversal sequences.

### Intelligence Context

- Rapid7: CVE-2026-85706: Critical GitLab Path Traversal Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild)
  - Context: Rapid7 reported active exploitation of a critical path traversal vulnerability in the GitLab repository commits API, allowing unauthenticated users to read arbitrary files from affected servers. The vulnerability was added to CISA's KEV catalog based on evidence of in-the-wild exploitation.

### Search Metadata

- CVEs: CVE-2026-85706
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: GitLab CE, GitLab EE
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-85706, T1190, GitLab CE, GitLab EE

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog RequestURL field is not populated by all GitLab syslog/CEF forwarder configurations; if the field is empty the query returns no results.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor has_any ("GitLab", "gitlab")
    or DeviceProduct has_any ("GitLab", "gitlab")
| where RequestURL has "/api/v4/projects"
| where RequestURL has "/commits"
| let NormURL = tolower(RequestURL)
| where NormURL has_any ("../", "..%2f", "%2e%2e", "%2e%2e%2f", ".%2e/", "%2e./")
| where RequestMethod in ("GET", "POST")
| where EventOutcome in ("200", "206")
| where SourceIP !startswith "10."
    and SourceIP !startswith "192.168."
    and not (SourceIP startswith "172." and split(SourceIP, ".")[1] between ("16" .. "31"))
| project TimeGenerated, SourceIP, RequestURL, RequestMethod, EventOutcome, DeviceVendor, DeviceProduct, Message
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate security scanners or penetration testing tools targeting GitLab from external IPs may match traversal patterns.
- URL-encoded characters used in legitimate commit SHAs or branch names that coincidentally match encoded traversal sequences.

**Tuning notes:**
- If GitLab logs appear under a different DeviceVendor or DeviceProduct string in your environment, update those filter values accordingly.
- If internal red team or scanner IPs generate noise, add them to the SourceIP exclusion list.
- Consider extending EventOutcome to include 301 and 302 if the GitLab instance redirects traversal attempts before serving content.

**Risks / caveats:**
- CommonSecurityLog RequestURL field is not populated by all GitLab syslog/CEF forwarder configurations; if the field is empty the query returns no results.
- No standard Microsoft Sentinel data connector exists for GitLab CE/EE; log ingestion depends on a custom syslog or CEF forwarder being deployed and operational.
- The 7-day lookback window may miss earlier exploitation if log ingestion latency is high or the connector was recently deployed.
- RFC-1918 172.16-31 exclusion uses string comparison on split segments which may behave unexpectedly for non-standard IP formatting; validate against your log format.

### Triage Runbook

**First 15 minutes:**
- Confirm the request came from an external SourceIP and was not a sanctioned scanner or internal test host.
- Review the full RequestURL and Message to verify the traversal sequence and the targeted commits API path are present in the same event.
- Check whether EventOutcome 200 or 206 corresponds to a likely successful read and whether the response size or follow-on requests suggest file access.
- Identify the affected GitLab host or appliance and determine whether it is internet-facing and currently patched for CVE-2026-85706.

**Evidence to collect:**
- TimeGenerated, SourceIP, RequestMethod, RequestURL, EventOutcome, DeviceVendor, DeviceProduct, and Message for the triggering event.
- Any adjacent GitLab access log entries from the same SourceIP before and after the alert to identify enumeration or repeated traversal attempts.
- GitLab version/build information and patch status for the affected instance.
- Whether the same SourceIP targeted other GitLab endpoints or other public-facing applications in the same time window.

**Pivot points:**
- CommonSecurityLog for the same SourceIP over the prior and subsequent 24 hours to find repeated requests, alternate traversal encodings, or other GitLab API activity.
- CommonSecurityLog filtered to the same DeviceProduct to identify whether other GitLab hosts were targeted.
- GitLab application or reverse-proxy logs, if available, to confirm response codes, response sizes, and any file paths disclosed.
- Threat intelligence or firewall logs for the SourceIP to determine whether it is associated with scanning or exploitation activity.

**Benign explanations:**
- An external vulnerability scanner or penetration test may intentionally probe the commits API with traversal strings.
- A malformed request from a security tool or browser plugin could accidentally resemble traversal syntax.
- Encoded characters in a legitimate GitLab URL may coincidentally match traversal patterns, though this is less likely when the commits API path is present.

**Escalation criteria:**
- Escalate immediately if the event is from an external IP and shows HTTP 200 or 206 with a traversal sequence against the commits API.
- Escalate if multiple traversal attempts occur from the same SourceIP or across multiple GitLab hosts.
- Escalate if the targeted GitLab instance is unpatched, internet-facing, or contains sensitive repositories or secrets.
- Escalate if follow-on activity suggests file disclosure, credential exposure, or secondary exploitation.

**Containment actions:**
- Block the SourceIP at the perimeter or reverse proxy if the activity is confirmed malicious and ongoing.
- Temporarily restrict external access to the GitLab instance or the commits API if exploitation is active and patching cannot be immediate.
- Accelerate patching or mitigation for CVE-2026-85706 on all exposed GitLab CE/EE instances.
- Preserve relevant logs and snapshots before making disruptive changes.

**Closure criteria:**
- The request is confirmed to be a sanctioned scan or test and no successful file-read indicators are present.
- The GitLab instance is patched, the request was blocked or returned an error, and no follow-on suspicious activity is observed.
- No sensitive file access, repository exposure, or additional exploitation indicators are found after reviewing adjacent logs.
- The alert is attributable to a known benign source and documented in the case notes.

<br/>
---
<br/>

## Detection 2: CVE-2026-76461 Cisco Secure Email Gateway SQL Injection via Syslog Anomaly

### Detection Opportunity

Unauthenticated remote SQL injection against Cisco Secure Email Gateway producing anomalous error messages or SQL keywords in appliance logs.

### Intelligence Context

- Rapid7: CVE-2026-76461: Critical Cisco Secure Email Gateway Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild)
  - Context: Rapid7 reported active exploitation of a critical SQL injection vulnerability in Cisco Secure Email Gateway that allows unauthenticated remote attackers to execute arbitrary commands with root privileges. Exploitation occurs through the appliance's normal inbound email processing path.

### Search Metadata

- CVEs: CVE-2026-76461
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Cisco Secure Email Gateway, Cisco AsyncOS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-76461, T1190, T1059, Cisco Secure Email Gateway, Cisco AsyncOS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No standard Microsoft Sentinel data connector exists for Cisco Secure Email Gateway; CEF forwarding must be configured manually via a syslog forwarder.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor has "Cisco"
| where DeviceProduct has_any ("Email Gateway", "AsyncOS", "IronPort")
| where LogSeverity >= 5
| where Message has_any ("syntax error", "ORA-", "mysql_fetch", "UNION SELECT", "database error", "unhandled exception")
    or Activity has_any ("syntax error", "database error", "UNION SELECT")
| where SourceIP !startswith "10."
    and SourceIP !startswith "192.168."
    and not (SourceIP startswith "172." and split(SourceIP, ".")[1] between ("16" .. "31"))
| project TimeGenerated, SourceIP, DeviceVendor, DeviceProduct, Activity, Message, LogSeverity
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate email content containing SQL-like strings (e.g., newsletters with code samples) may trigger Message field matches if the appliance logs message content.
- Appliance self-diagnostic or health-check messages containing 'database error' strings unrelated to exploitation.

**Tuning notes:**
- Adjust LogSeverity threshold based on observed severity values in your Cisco SEG CEF output.
- If internal mail relay IPs generate noise, add them explicitly to the SourceIP exclusion.
- Review a sample of Message field values from your appliance before scheduling to confirm SQL error strings are present and the keyword list is appropriately scoped.

**Risks / caveats:**
- Cisco AsyncOS syslog verbosity must be configured at a level that surfaces SQL error strings or application exceptions in the Message field; default log levels may suppress these strings entirely.
- No standard Microsoft Sentinel data connector exists for Cisco Secure Email Gateway; CEF forwarding must be configured manually via a syslog forwarder.
- SQL error strings may not appear in AsyncOS syslog output at default log verbosity; the query may return no results without appliance log level adjustment.
- The RFC-1918 172.16-31 exclusion uses string comparison on split segments; validate against your log format for correctness.

### Triage Runbook

**First 15 minutes:**
- Confirm the triggering SourceIP is external and not an internal mail relay, monitoring system, or approved security test source.
- Review Message, Activity, and LogSeverity for SQL error strings, UNION SELECT indicators, or other injection artifacts.
- Check whether the appliance is internet-facing and whether CVE-2026-76461 mitigation or patching has been applied.
- Look for repeated errors from the same SourceIP that suggest active probing or exploitation attempts.

**Evidence to collect:**
- TimeGenerated, SourceIP, DeviceVendor, DeviceProduct, Activity, Message, and LogSeverity from the triggering event.
- Any adjacent Cisco SEG syslog entries showing database errors, application exceptions, or unusual inbound mail-processing behavior.
- Appliance version, patch level, and current log verbosity settings.
- Inbound mail headers or SMTP logs around the same time to determine whether the request arrived through normal email processing.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DeviceProduct over a 24-hour window to identify repeated SQL injection indicators or other suspicious requests.
- Syslog for the Cisco SEG host to look for application crashes, unexpected restarts, or root-level command execution indicators.
- Mail gateway or SMTP logs to correlate the alert with specific inbound messages or sender patterns.
- Firewall or proxy logs to determine whether the SourceIP is associated with broader exploitation activity.

**Benign explanations:**
- Legitimate email content or attachments containing SQL-like strings may surface in appliance logs.
- Appliance self-diagnostics or transient database issues can generate similar error messages without exploitation.
- A security scanner or test harness may intentionally trigger SQL error conditions on the gateway.

**Escalation criteria:**
- Escalate if the SourceIP is external and the logs show strong SQL injection indicators such as UNION SELECT or repeated syntax errors.
- Escalate if the appliance is unpatched, internet-facing, or handling sensitive mail flows.
- Escalate if there are signs of command execution, unexpected restarts, or outbound connections from the appliance.
- Escalate if multiple mail gateway nodes show similar indicators in the same time window.

**Containment actions:**
- Block the offending SourceIP if exploitation is active and not attributable to a sanctioned test.
- Isolate the appliance from external exposure if compromise is suspected and business impact can be managed.
- Apply vendor guidance, patches, or mitigations for CVE-2026-76461 as soon as feasible.
- Preserve syslog and mail-processing logs before restarting or reconfiguring the appliance.

**Closure criteria:**
- The event is confirmed to be benign mail content, a health-check, or a sanctioned test with no other compromise indicators.
- No additional SQL injection attempts, crashes, or command execution indicators are found in adjacent logs.
- The appliance is patched or mitigated and the alert source is documented as benign.
- The SourceIP is tied to a known internal relay or monitoring system and the activity matches expected behavior.

<br/>
---
<br/>

## Detection 3: CVE-2026-76461 Cisco SEG Post-Exploitation Root Command Execution via Syslog

### Detection Opportunity

Arbitrary command execution with root privileges on Cisco Secure Email Gateway following SQL injection exploitation, surfaced as unexpected process spawning or outbound connections in appliance syslog.

### Intelligence Context

- Rapid7: CVE-2026-76461: Critical Cisco Secure Email Gateway Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild)
  - Context: Rapid7 confirmed that successful exploitation of CVE-2026-76461 allows an attacker to execute arbitrary commands with root privileges on the Cisco Secure Email Gateway appliance. Post-exploitation activity may manifest as unexpected shell invocations or anomalous outbound network connections from the appliance.

### Search Metadata

- CVEs: CVE-2026-76461
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Cisco Secure Email Gateway, Cisco AsyncOS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-76461, T1190, T1059, Cisco Secure Email Gateway, Cisco AsyncOS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let SQLInjectionEvents = CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor has "Cisco"
| where DeviceProduct has_any ("Email Gateway", "AsyncOS", "IronPort")
| where LogSeverity >= 5
| where Message has_any ("syntax error", "ORA-", "mysql_fetch", "UNION SELECT", "database error", "unhandled exception")
| project SQLTime = TimeGenerated, SourceIP, DeviceProduct;
let ShellEvents = Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has_any ("/bin/sh", "/bin/bash", "cmd.exe", "wget ", "curl ", "chmod ", "nc ", "ncat ", "python -c", "perl -e", "base64 -d")
| project ShellTime = TimeGenerated, HostName, SyslogMessage, ProcessName;
SQLInjectionEvents
| join kind=inner ShellEvents on $left.SourceIP == $right.HostName
| where ShellTime between (SQLTime .. (SQLTime + 1h))
| project SQLTime, ShellTime, SourceIP, HostName, SyslogMessage, ProcessName, DeviceProduct
| order by SQLTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative shell access to the appliance CLI may produce syslog entries matching shell binary strings.
- Automated health-check or monitoring scripts running on the appliance host may match wget or curl patterns.

**Tuning notes:**
- If the appliance HostName in Syslog differs from its SourceIP in CommonSecurityLog, replace the join key with the correct field mapping for your environment.
- Extend or reduce the 1-hour correlation window based on observed log latency between the CEF and syslog forwarding paths.
- Add a HostName filter to the ShellEvents leg to scope Syslog results to the specific appliance hostname if other Linux hosts forward to the same Syslog table.

**Risks / caveats:**
- The join key between CommonSecurityLog SourceIP and Syslog HostName will not resolve unless the appliance forwards CEF logs with SourceIP matching the HostName used in syslog output; this is appliance-configuration-dependent.
- AsyncOS may not log shell process invocations to syslog at any verbosity level; the Syslog leg of the query may return no results regardless of exploitation.
- Syslog table must be receiving forwarded logs from the Cisco SEG host; if only CEF forwarding is configured, the Syslog table will not contain appliance entries.
- The SourceIP-to-HostName join key will fail to match unless the appliance IP in CommonSecurityLog exactly matches the HostName string in Syslog; validate this mapping before relying on results.

### Triage Runbook

**First 15 minutes:**
- Treat the alert as potential compromise until proven otherwise because it correlates SQL injection indicators with shell or tool execution.
- Verify the SourceIP-to-HostName mapping is valid in your environment so the correlation is not a false join.
- Review the ShellEvents content for explicit shell binaries, download tools, or command execution strings such as wget, curl, sh, or bash.
- Check whether the appliance generated any outbound connections, process anomalies, or service restarts around the same time.

**Evidence to collect:**
- SQLTime, ShellTime, SourceIP, HostName, SyslogMessage, ProcessName, and DeviceProduct from the correlated event.
- All Syslog entries from the appliance for at least 1 hour before and after the alert.
- Any CommonSecurityLog entries showing the original SQL injection indicators or repeated exploitation attempts.
- Appliance version, patch status, and whether administrative shell access is normally permitted on the device.

**Pivot points:**
- Syslog for the appliance HostName to identify additional shell commands, file writes, or service changes.
- CommonSecurityLog for the same SourceIP to confirm the initial exploitation chain.
- Firewall or proxy logs for outbound connections from the appliance to unknown destinations.
- Authentication or admin access logs to determine whether a legitimate administrator was active at the same time.

**Benign explanations:**
- A legitimate administrator may have used the appliance CLI or maintenance shell during the same time window.
- Monitoring or backup scripts may produce wget, curl, or shell-like strings in syslog.
- The SourceIP-to-HostName join may be incorrect if the environment maps appliance identifiers differently.

**Escalation criteria:**
- Escalate immediately if shell execution indicators are confirmed on an internet-facing or unpatched Cisco SEG appliance.
- Escalate if outbound connections, file downloads, or service tampering are observed after the SQL injection indicators.
- Escalate if the appliance is handling production mail and the activity is not attributable to approved administration.
- Escalate if multiple logs show root-level command execution or persistence-like behavior.

**Containment actions:**
- Isolate the appliance from external traffic if post-exploitation is confirmed and business continuity allows.
- Block the attacking SourceIP and any related destinations observed in outbound traffic.
- Disable nonessential administrative access paths and preserve forensic logs before rebooting or reimaging.
- Coordinate emergency patching or vendor-supported recovery steps for CVE-2026-76461.

**Closure criteria:**
- The shell-like activity is verified as legitimate administration or maintenance and no other compromise indicators exist.
- The join is determined to be invalid in this environment and no corroborating evidence of exploitation is found.
- No outbound connections, file changes, or service tampering are present in adjacent logs.
- The appliance is patched and monitored, and the case is documented with the benign explanation.

<br/>
---
<br/>

## Detection 4: AMOS Stealer macOS Credential Store Access by Non-Browser Process

### Detection Opportunity

macOS stealer accessing keychain files or browser credential directories via non-browser, non-system processes consistent with AMOS stealer data theft behavior.

### Intelligence Context

- Unit 42: Atomic macOS (AMOS) Stealer Activity — [https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/](https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/)
  - Context: Unit 42 reported that AMOS stealer uses deceptive setup guides to compromise macOS users and then steals credentials and sensitive user data. The stealer consistently targets macOS keychain files and browser credential stores as part of its data collection routine.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1555, T1213
- Products: Not specified
- Platforms: macOS
- Malware: AMOS
- Tools: Not specified
- Search tags: macOS, AMOS, T1555, T1213

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores (high); Collection: T1213 Data from Information Repositories (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let CredentialAccess = DeviceFileEvents
| where TimeGenerated > ago(7d)
| where OSPlatform =~ "macOS"
| where FilePath has_any (
    "Library/Keychains",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Firefox/Profiles",
    "Library/Application Support/Microsoft Edge",
    ".ssh/",
    "Library/Cookies"
  )
| where ActionType in ("FileRead", "FileAccessed", "FileCreated", "FileModified")
| where InitiatingProcessName !in~ (
    "Google Chrome", "Brave Browser", "firefox", "Microsoft Edge",
    "Safari", "Keychain Access", "security", "securityd",
    "com.apple.security", "loginwindow", "SystemUIServer",
    "cfprefsd", "trustd", "syspolicyd"
  )
| project AccessTime = TimeGenerated, DeviceName, AccountName, FilePath, FileName, InitiatingProcessName, ActionType;
let NetworkActivity = DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where isnotempty(RemoteIP)
| project NetTime = TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessName;
CredentialAccess
| join kind=inner NetworkActivity on DeviceName
| where NetTime between (AccessTime .. (AccessTime + 30m))
| project AccessTime, NetTime, DeviceName, AccountName, FilePath, FileName, ActionType, InitiatingProcessName, RemoteIP, RemotePort
| order by AccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate backup agents or endpoint management tools accessing browser profile directories for backup purposes.
- Developer tools or test frameworks accessing credential paths during automated testing.
- Security products performing file scanning that access keychain or browser profile paths.

**Tuning notes:**
- Validate OSPlatform string value against your Defender for Endpoint macOS sensor output before scheduling.
- Confirm which ActionType values are emitted for keychain path access by sampling DeviceFileEvents for macOS devices in your environment.
- Expand the InitiatingProcessName exclusion list with any additional legitimate macOS management or backup agents observed in your fleet.
- Consider adding a SHA256 hash lookup against known AMOS samples if hash IOCs become available from threat intelligence.

**Risks / caveats:**
- DeviceFileEvents on macOS via Defender for Endpoint does not reliably emit FileRead or FileAccessed ActionType events for keychain paths; the macOS sensor primarily captures file creation, modification, rename, and deletion events, meaning the credential access leg may return no results.
- OSPlatform field availability and exact string value ('macOS' vs 'Mac' vs 'Darwin') should be validated against your Defender for Endpoint macOS sensor version.
- FileRead and FileAccessed ActionType values may not be emitted by the Defender for Endpoint macOS sensor; if only FileCreated and FileModified are available, the detection shifts to stealer file staging behaviour rather than direct read behaviour.
- The InitiatingProcessName exclusion list requires ongoing maintenance as legitimate macOS applications are updated or new management tools are deployed.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process and confirm whether it is a known browser, system service, backup agent, or an unexpected binary.
- Review the FilePath and FileName to see whether the access targets keychains, browser profiles, cookies, or SSH material.
- Check whether the same DeviceName made outbound network connections shortly after the file activity.
- Determine whether the affected user account recently installed software, opened a suspicious lure, or approved a new profile or helper tool.

**Evidence to collect:**
- AccessTime, NetTime, DeviceName, AccountName, FilePath, FileName, InitiatingProcessName, ActionType, RemoteIP, and RemotePort.
- The full process tree for the initiating process and any child processes on the same endpoint.
- Recent DeviceNetworkEvents from the same DeviceName to identify exfiltration destinations.
- Any user-reported activity, recent downloads, or software installation events on the endpoint.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and AccountName to find additional access to keychains, browser profiles, or SSH directories.
- DeviceNetworkEvents for the same DeviceName to identify outbound connections to non-private IPs after the file access.
- DeviceProcessEvents to reconstruct the parent-child process chain and identify launchers, droppers, or script interpreters.
- Defender XDR alerts or incident history for the same host to see whether this endpoint has prior suspicious activity.

**Benign explanations:**
- A legitimate browser, keychain utility, or system security daemon may access these paths during normal operation.
- Backup, migration, or endpoint management tools may read browser profiles or keychain-related files.
- Developer or test tooling may touch credential repositories during automation or troubleshooting.

**Escalation criteria:**
- Escalate if the initiating process is unknown, unsigned, recently downloaded, or launched from a user-writable path.
- Escalate if file access is followed by outbound connections to unfamiliar external IPs.
- Escalate if multiple credential repositories are accessed across browsers or the keychain in a short period.
- Escalate if the user reports suspicious prompts, fake installers, or unexpected login issues.

**Containment actions:**
- Isolate the endpoint if the process is unrecognized and exfiltration is suspected.
- Terminate the suspicious process only after preserving volatile evidence if your response process allows it.
- Reset affected credentials and session tokens if credential theft is likely.
- Block known malicious destinations if outbound connections are confirmed.

**Closure criteria:**
- The process is confirmed as a legitimate browser, system daemon, or approved management tool.
- No outbound connections or additional suspicious file access are found after review.
- The activity matches a documented backup, migration, or security workflow.
- The endpoint is clean after process-tree review and there is no user impact or credential exposure.

<br/>
---
<br/>

## Detection 5: NightEagle APT GitHub Payload Retrieval by Non-Browser Process

### Detection Opportunity

Non-browser, non-development processes on endpoints making outbound connections to GitHub raw content URLs, consistent with NightEagle APT tooling hosted on GitHub being fetched as part of attack infrastructure.

### Intelligence Context

- Securelist: NightEagle targets Russian companies — [https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
  - Context: Securelist reported that the NightEagle APT hosts attack tools on GitHub as part of their campaign infrastructure, using them alongside the GhostContainer backdoor. Fetching attacker-controlled payloads from GitHub via non-browser processes is a detectable pattern associated with this campaign.

### Search Metadata

- CVEs: Not specified
- Threat actors: NightEagle
- ATT&CK tags: T1105
- Products: Not specified
- Platforms: Active Directory, RDP
- Malware: GhostContainer
- Tools: GitHub
- Search tags: NightEagle, GhostContainer, Active Directory, RDP, GitHub, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- RemoteUrl field in DeviceNetworkEvents is not populated for all HTTP/HTTPS connections depending on Defender for Endpoint sensor version and network inspection configuration; queries relying on RemoteUrl may return incomplete results.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let GitHubFetch = DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemoteUrl has_any ("raw.githubusercontent.com", "github.com")
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "git.exe", "gh.exe", "code.exe", "devenv.exe", "rider64.exe",
    "Google Chrome", "Microsoft Edge", "firefox", "Safari",
    "node.exe", "npm.exe", "yarn.exe", "pip.exe", "python.exe"
  )
| project FetchTime = TimeGenerated, DeviceName, RemoteUrl, RemoteIP, FetchingProcess = InitiatingProcessName;
let PostFetchExec = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| project ExecTime = TimeGenerated, DeviceName, ProcessCommandLine, SpawnedBy = InitiatingProcessName, ParentProcessName;
GitHubFetch
| join kind=inner PostFetchExec on DeviceName
| where ExecTime between (FetchTime .. (FetchTime + 10m))
| where SpawnedBy =~ FetchingProcess or ParentProcessName =~ FetchingProcess
| project FetchTime, ExecTime, DeviceName, RemoteUrl, RemoteIP, FetchingProcess, ProcessCommandLine, ParentProcessName
| order by FetchTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CI/CD pipeline agents, build servers, or package managers fetching dependencies from GitHub via non-browser processes.
- Endpoint management or configuration management tools pulling scripts from GitHub repositories.
- Developer workstations running scripts that fetch GitHub content outside of a browser or IDE.

**Tuning notes:**
- Expand the InitiatingProcessName exclusion list with CI/CD agent process names observed in your environment such as jenkins-agent.exe, runner.exe, or similar.
- If RemoteUrl is not populated in your environment, consider pivoting to RemoteIP matching against GitHub IP ranges as a fallback, though this significantly increases false positive volume.
- Consider adding a ProcessCommandLine filter on the PostFetchExec leg to require suspicious execution patterns such as encoded commands, script interpreters, or known post-exploitation tool names.
- Scope DeviceName to non-developer workstations or server assets if your environment has a reliable asset classification to reduce developer noise.

**Risks / caveats:**
- RemoteUrl field in DeviceNetworkEvents is not populated for all HTTP/HTTPS connections depending on Defender for Endpoint sensor version and network inspection configuration; queries relying on RemoteUrl may return incomplete results.
- RemoteUrl may not be populated for all GitHub connections in DeviceNetworkEvents; connections where RemoteUrl is empty will not be matched even if the destination is GitHub.
- Process name matching for the post-fetch execution correlation is weak and will miss cases where the payload is executed by a renamed binary, injected thread, or a different process than the one that performed the fetch.
- The exclusion list for legitimate development tools requires ongoing maintenance and will generate false positives in developer-heavy environments.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process and confirm whether the device is a developer workstation, build server, or a normal user endpoint.
- Review the RemoteUrl and RemoteIP to confirm the connection was to GitHub or raw.githubusercontent.com.
- Check the follow-on process execution on the same DeviceName within the 10-minute window for script interpreters, encoded commands, or unusual binaries.
- Look for user context, recent downloads, or scheduled tasks that explain why the process contacted GitHub.

**Evidence to collect:**
- FetchTime, ExecTime, DeviceName, RemoteUrl, RemoteIP, FetchingProcess, ProcessCommandLine, and ParentProcessName.
- The full DeviceProcessEvents tree around the fetch and any child process execution.
- Any DeviceNetworkEvents showing repeated GitHub access or additional external destinations from the same host.
- Asset classification for the endpoint to determine whether GitHub access is expected.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName to identify other GitHub or raw content requests and any non-GitHub destinations.
- DeviceProcessEvents to inspect the command line of the post-fetch process and its parent chain.
- Defender XDR alerts for the same host to see whether this is part of a broader intrusion sequence.
- If available, proxy or DNS logs to validate the destination and identify any additional infrastructure.

**Benign explanations:**
- Developer activity, CI/CD agents, package managers, or automation tools may legitimately fetch content from GitHub.
- Endpoint management or scripting tools may download scripts or configuration from GitHub repositories.
- A user may have run a legitimate script or installer that retrieves dependencies from GitHub outside a browser.

**Escalation criteria:**
- Escalate if the device is not a developer or build asset and the fetch is followed by suspicious process execution.
- Escalate if the command line shows encoded commands, script interpreters, or known post-exploitation tooling.
- Escalate if the same host also shows lateral movement, credential access, or persistence indicators.
- Escalate if the GitHub access is repeated, automated, and not tied to an approved software workflow.

**Containment actions:**
- Isolate the host if the fetched content appears to be malicious and is being executed.
- Block the destination or related GitHub content only if your environment policy allows and the activity is confirmed malicious.
- Suspend the suspicious process or scheduled task after preserving evidence.
- Coordinate with endpoint owners to disable the workflow if it is an unauthorized downloader.

**Closure criteria:**
- The activity is confirmed as legitimate development, CI/CD, or approved automation.
- No suspicious follow-on execution or additional external destinations are found.
- The host is classified as a developer or build system and the behavior matches its normal baseline.
- The alert is explained by a known script, package manager, or management tool and documented accordingly.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- CVE-2026-85706 GitLab Path Traversal Attempt via Commits API: CommonSecurityLog RequestURL field is not populated by all GitLab syslog/CEF forwarder configurations; if the field is empty the query returns no results.
- AMOS Stealer macOS Credential Store Access by Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.
- NightEagle APT GitHub Payload Retrieval by Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.
- NightEagle APT GitHub Payload Retrieval by Non-Browser Process: RemoteUrl field in DeviceNetworkEvents is not populated for all HTTP/HTTPS connections depending on Defender for Endpoint sensor version and network inspection configuration; queries relying on RemoteUrl may return incomplete results.

**Telemetry availability:**
- CVE-2026-76461 Cisco Secure Email Gateway SQL Injection via Syslog Anomaly: No standard Microsoft Sentinel data connector exists for Cisco Secure Email Gateway; CEF forwarding must be configured manually via a syslog forwarder.
- CVE-2026-76461 Cisco SEG Post-Exploitation Root Command Execution via Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Shared-table notes:**
- CommonSecurityLog: shared by CVE-2026-85706 GitLab Path Traversal Attempt via Commits API; CVE-2026-76461 Cisco Secure Email Gateway SQL Injection via Syslog Anomaly; CVE-2026-76461 Cisco SEG Post-Exploitation Root Command Execution via Syslog
- DeviceNetworkEvents: shared by AMOS Stealer macOS Credential Store Access by Non-Browser Process; NightEagle APT GitHub Payload Retrieval by Non-Browser Process

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: CVE-2026-85706 GitLab Path Traversal Attempt via Commits API; CVE-2026-76461 Cisco Secure Email Gateway SQL Injection via Syslog Anomaly; CVE-2026-76461 Cisco SEG Post-Exploitation Root Command Execution via Syslog.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: AMOS Stealer macOS Credential Store Access by Non-Browser Process; NightEagle APT GitHub Payload Retrieval by Non-Browser Process.

### Hunting Agenda and Promotion Criteria

- AMOS Stealer macOS Credential Store Access by Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.
- NightEagle APT GitHub Payload Retrieval by Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-85706 GitLab Path Traversal Attempt via Commits API: CommonSecurityLog RequestURL field is not populated by all GitLab syslog/CEF forwarder configurations; if the field is empty the query returns no results..
- CVE-2026-76461 Cisco Secure Email Gateway SQL Injection via Syslog Anomaly: No standard Microsoft Sentinel data connector exists for Cisco Secure Email Gateway; CEF forwarding must be configured manually via a syslog forwarder.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-76461 Cisco SEG Post-Exploitation Root Command Execution via Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
