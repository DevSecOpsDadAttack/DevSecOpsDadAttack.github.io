---
layout: post
title: "Detection Engineering Brief - Friday, October 23, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-23
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-109618
  - CVE-2026-109619
  - T1190
  - PHP
  - PHP-FPM
  - Apache mod_php
  - php-cgi
  - FrankenPHP
  - LiteSpeed
  - web servers
  - CMS
  - Storm-0940
  - ARTEX
  - ConnectWise
  - Microsoft 365
  - CVE-2022-21894
  - APT41
  - Windows
  - UEFI
  - firmware
  - BlackX
  - BlackLotus
  - T1059
  - T1059.004
  - T1059.006
  - T1059.001
  - T1078
  - T1078.004
  - T1550
  - T1550.001
  - T1098
  - T1098.003
  - T1542
  - T1542.003
  - T1070
  - T1070.006
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 2 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-109618, CVE-2026-109619, T1190, PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed, web servers, CMS, Storm-0940, ARTEX, ConnectWise, Microsoft 365, CVE-2022-21894, APT41, Windows, UEFI, firmware, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: PHP Web Worker Spawning Unexpected Child Process - CVE-2026-109618/109619; PHP Worker Spawning Shell Correlated with HTTP 200 Response - CVE-2026-109618/109619 PoC Exploitation; EFI System Partition File Write by Non-Bootloader Process - BlackX UEFI Bootkit Installation.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: PHP Web Worker Spawning Unexpected Child Process - CVE-2026-109618/109619

### Detection Opportunity

Unauthenticated remote code execution via PHP flaws causing web worker processes to spawn unexpected child shells or interpreters.

### Intelligence Context

- Rapid7: CVE-2026-109618 and CVE-2026-109619: Critical Unauthenticated Remote Code Execution in PHP — [https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php)
  - Context: Both CVE-2026-109618 and CVE-2026-109619 allow unauthenticated RCE with web worker privileges. Exploitation produces child process spawning from PHP worker processes such as php-fpm, php-cgi, and web server workers running mod_php or LiteSpeed.

### Search Metadata

- CVEs: CVE-2026-109618, CVE-2026-109619
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1059.004, T1059.006, T1059.001
- Products: PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-109618, CVE-2026-109619, T1190, PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed, T1059, T1059.004, T1059.006, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (medium); execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let WebWorkers = dynamic(["php-fpm", "php-cgi", "apache2", "httpd", "litespeed", "lshttpd", "frankenphp"]);
let SuspiciousChildren = dynamic(["sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "python", "python3", "perl", "ruby", "curl", "wget"]);
let LookbackWindow = 5m;
let SuspiciousProcs = DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (WebWorkers)
| where FileName in~ (SuspiciousChildren)
| project SpawnTime = Timestamp, DeviceId, DeviceName, AccountName,
    ParentProcess = InitiatingProcessFileName,
    ChildProcess = FileName,
    ChildProcessId = ProcessId,
    ProcessCommandLine;
let NetworkCorrelation = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (dynamic(["sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "python", "python3", "perl", "ruby", "curl", "wget"]))
| where not(ipv4_is_private(RemoteIP)) and RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| project NetTime = Timestamp, DeviceId, RemoteIP, RemotePort,
    NetProcessName = InitiatingProcessFileName,
    NetProcessId = InitiatingProcessId;
SuspiciousProcs
| join kind=inner (
    NetworkCorrelation
) on DeviceId
| where NetProcessId == ChildProcessId
| where NetTime between (SpawnTime .. (SpawnTime + LookbackWindow))
| project SpawnTime, NetTime, DeviceId, DeviceName, AccountName, ParentProcess,
    ChildProcess, ProcessCommandLine, RemoteIP, RemotePort
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate PHP-based deployment scripts that invoke curl or wget to fetch configuration or assets after a web request.
- Monitoring agents or health-check scripts that run under web worker accounts and make outbound connections.
- CI/CD pipeline hooks that trigger shell commands via PHP worker processes during deployment.
- Python or perl scripts invoked by PHP for legitimate application functionality.

**Tuning notes:**
- Extend LookbackWindow beyond 5 minutes if observed exploitation in your environment shows a delay between shell spawn and outbound callback.
- Add known-good ProcessCommandLine patterns (e.g., curl to internal package mirrors) to an exclusion filter after baselining.
- Consider adding InitiatingProcessParentFileName not in ("systemd", "supervisord", "s6-svscan") to suppress operator-initiated shell sessions via process managers.

**Risks / caveats:**
- DeviceProcessEvents.InitiatingProcessFileName is populated only when Defender for Endpoint has process lineage telemetry enabled on the host; Linux hosts require MDE Linux agent with process events enabled.
- DeviceNetworkEvents.InitiatingProcessId linkage to DeviceProcessEvents.ProcessId requires both tables to capture the same process instance; if the child process exits before the network event is recorded, the join may miss the correlation.
- Process ID reuse on high-throughput servers may cause the ProcessId/InitiatingProcessId join to occasionally correlate unrelated processes if PIDs are recycled within the 5-minute window.
- The 1-day lookback window may be expensive on environments with high process event volume; consider reducing to 4-6 hours for scheduled execution.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent/child process chain on the affected host and verify the parent is a PHP worker process such as php-fpm, php-cgi, apache2, httpd, litespeed, lshttpd, or frankenphp.
- Review the child process command line for obvious attacker tradecraft such as sh, bash, python, perl, curl, wget, powershell.exe, or encoded/obfuscated arguments.
- Check whether the child process made any outbound network connections shortly after spawn, especially to non-private IPs or unusual ports.
- Identify the account context and whether the activity occurred on a public-facing web server or CMS host that should not normally spawn shells.
- Look for nearby process, file, and network activity on the same device within the same time window to determine if this is isolated or part of a broader intrusion.

**Evidence to collect:**
- DeviceName, DeviceId, AccountName, ParentProcess, ChildProcess, ProcessCommandLine, SpawnTime, NetTime, RemoteIP, and RemotePort from the alert.
- Full process tree for the parent PHP worker and the spawned child process, including any grandchild processes.
- Any DeviceNetworkEvents for the child process and any subsequent connections from the same host within 15 minutes.
- Any DeviceFileEvents showing webroot changes, dropped scripts, temporary files, or new executables around the alert time.
- Web server access logs or application logs for the request that preceded the spawn, including source IP and requested URL if available.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and a wider time range to reconstruct the process tree and identify repeated child spawns.
- DeviceNetworkEvents filtered on the same DeviceId and InitiatingProcessId to find outbound callbacks from the spawned child process.
- DeviceFileEvents on the same DeviceId for recent writes to webroot, temp directories, or script locations.
- Web server or application logs for requests to the affected endpoint around the spawn time.
- If available, sign-in or admin activity logs for the same host to determine whether an operator was present.

**Benign explanations:**
- A legitimate PHP application may invoke curl, wget, python, or perl for deployment, maintenance, or API integration.
- Monitoring, health-check, or backup scripts may run under web worker context and create short-lived child processes.
- CI/CD or operator-driven deployment activity may temporarily cause PHP workers to spawn shells or interpreters.
- Known-good application behavior may include PHP calling helper scripts during scheduled jobs or plugin updates.

**Escalation criteria:**
- The child process is an interactive shell or scripting interpreter with suspicious arguments and no known business justification.
- The spawned process makes an external network connection to an unfamiliar IP, especially immediately after spawn.
- There are signs of post-exploitation activity such as webshell creation, credential dumping, or additional process spawning.
- The affected host is internet-facing and the activity is not attributable to a known deployment or maintenance window.

**Containment actions:**
- Isolate the host if the child process is confirmed suspicious or if there is evidence of outbound callback or follow-on execution.
- Disable or restrict the affected web application or virtual host until the exploit path is understood.
- Preserve volatile evidence before rebooting or restarting PHP/web services, including process listings and network connections.
- Block the source IP only if it is clearly malicious and not a shared proxy or legitimate client.

**Closure criteria:**
- The child process is confirmed to be part of approved application behavior or a documented maintenance task.
- No suspicious network, file, or follow-on process activity is found on the host.
- The process tree and command line match a known-good baseline for the application or server role.
- The alert can be tied to a validated deployment, health check, or operator action with supporting logs.

<br/>
---
<br/>

## Detection 2: PHP Worker Spawning Shell Correlated with HTTP 200 Response - CVE-2026-109618/109619 PoC Exploitation

### Detection Opportunity

Rapid exploitation of critical PHP flaws using publicly available PoC exploits, evidenced by PHP worker child process spawning correlated with successful inbound HTTP responses.

### Intelligence Context

- SANS ISC: Critical PHP Vulnerability (CVE-2026-109618, CVE-2026-109619) [infocon yellow], (Wed, Oct 21st) — [https://isc.sans.edu/diary/rss/33440](https://isc.sans.edu/diary/rss/33440)
  - Context: SANS ISC reported that PoC exploits for CVE-2026-109618 and CVE-2026-109619 were available before patches, with CVSS 9.4 severity and rapid exploitation expected. Detection focus is on PHP worker child process spawning correlated with successful HTTP responses indicating exploit delivery.

### Search Metadata

- CVEs: CVE-2026-109618, CVE-2026-109619
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1059.004, T1059.006, T1059.001
- Products: PHP
- Platforms: web servers, CMS
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-109618, CVE-2026-109619, T1190, PHP, web servers, CMS, T1059, T1059.004, T1059.006, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (medium); execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (medium)

### Deployment Gates

- DeviceVendor values 'Apache', 'nginx', 'LiteSpeed' must exactly match the strings emitted by the log forwarder configured in the environment; these are not standardized across connectors.

**Required telemetry:**
- Syslog, CommonSecurityLog

### KQL

```kql
let PhpWorkerSpawns = Syslog
| where TimeGenerated > ago(1d)
| where ProcessName in ("php-fpm", "php-cgi", "php")
| where SyslogMessage has_any ("NOTICE: child", "WARNING: [pool", "exec", "sh", "bash", "python", "perl", "curl", "wget", "spawn")
| project SpawnTime = TimeGenerated, Computer = tolower(Computer), SyslogMessage, ProcessName;
let SuccessfulRequests = CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor has_any ("Apache", "nginx", "LiteSpeed", "apache", "NGINX")
| extend ResponseCode = coalesce(
    toint(FieldDeviceCustomNumber1),
    toint(extract(@"responseCode=(\d+)", 1, AdditionalExtensions))
  )
| where ResponseCode == 200
| project ReqTime = TimeGenerated, Computer = tolower(DeviceName), SourceIP, RequestURL;
PhpWorkerSpawns
| join kind=inner (
    SuccessfulRequests
) on Computer
| where SpawnTime between ((ReqTime - 30s) .. (ReqTime + 2m))
| project ReqTime, SpawnTime, Computer, SourceIP, RequestURL, ProcessName, SyslogMessage
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- PHP-FPM pool management log entries (child process recycling, pool scaling) that coincide with legitimate HTTP 200 responses.
- Routine PHP application log entries containing the word 'child' or 'spawn' in application-level messages forwarded through syslog.
- Any HTTP 200 response to a PHP endpoint that occurs within 2 minutes of a PHP-FPM pool management event.

**Tuning notes:**
- Validate DeviceVendor values by running: CommonSecurityLog → where TimeGenerated > ago(1d) → summarize count() by DeviceVendor → sort by count_ desc
- Validate Syslog ProcessName values by running: Syslog → where TimeGenerated > ago(1d) → where ProcessName has 'php' → summarize count() by ProcessName
- Adjust the time window in the join predicate based on observed latency between HTTP request receipt and PHP-FPM log emission in your environment.
- If FieldDeviceCustomNumber1 is consistently null, confirm the CEF field mapping with the log forwarder vendor documentation.

**Risks / caveats:**
- CommonSecurityLog HTTP response code field mapping (AdditionalExtensions 'responseCode=200' vs FieldDeviceCustomNumber1) is vendor-specific and will not match without knowing the exact CEF connector and field mapping used in the tenant.
- DeviceVendor values 'Apache', 'nginx', 'LiteSpeed' must exactly match the strings emitted by the log forwarder configured in the environment; these are not standardized across connectors.
- PHP-FPM standard log output does not contain the keywords 'exec', 'fork', or 'spawn'; the Syslog keyword filter will return no results unless the PHP-FPM log verbosity is set to DEBUG and the log format has been customized.
- The Computer field in Syslog and DeviceName in CommonSecurityLog must resolve to the same hostname string for the join to succeed; FQDN vs short hostname mismatches will silently drop all correlations.

### Triage Runbook

**First 15 minutes:**
- Validate the correlated HTTP 200 response and identify the source IP, request URL, and timestamp of the triggering request.
- Check whether the PHP worker spawned a shell or interpreter within the expected correlation window and whether the command line is malicious.
- Review the web server or PHP-FPM logs for the exact request pattern, payload indicators, and any repeated attempts from the same source.
- Determine whether the affected endpoint is internet-facing and whether the request targeted a vulnerable application or CMS component.
- Look for immediate post-exploitation behavior such as outbound connections, file writes, or additional child processes from the same host.

**Evidence to collect:**
- RequestURL, SourceIP, ReqTime, SpawnTime, ProcessName, and SyslogMessage from the alert.
- Web server access logs and PHP-FPM or application logs around the request time.
- Process tree and command line for the spawned child process and any descendants.
- DeviceNetworkEvents for the child process and any other processes on the same host shortly after the request.
- Any file changes in the webroot, temporary directories, or application plugin/theme paths.

**Pivot points:**
- CommonSecurityLog or web access logs for the same SourceIP and RequestURL to identify repeated exploit attempts.
- Syslog for PHP-FPM notices or warnings around the same time to confirm worker behavior.
- DeviceProcessEvents on the same host to identify shell, Python, Perl, or PowerShell execution after the request.
- DeviceNetworkEvents on the same host to identify outbound callbacks or staging activity.
- If available, WAF or reverse proxy logs to determine whether the request was blocked, allowed, or modified.

**Benign explanations:**
- A legitimate request to a PHP endpoint may coincide with normal PHP-FPM child recycling or pool management logs.
- Application-level logging may include words like child or spawn without indicating exploitation.
- A deployment or maintenance action may trigger a successful request and a short-lived helper process.
- High-traffic PHP applications may generate noisy correlations when normal HTTP 200 responses overlap with routine worker activity.

**Escalation criteria:**
- The request is clearly malicious, includes exploit-like parameters, or is followed by suspicious shell execution.
- The same source IP repeatedly targets the host or multiple hosts with similar requests.
- The spawned process performs outbound communication, drops files, or spawns additional interpreters.
- The host is internet-facing and the activity aligns with known exploitation of the referenced CVEs.

**Containment actions:**
- Isolate the host if exploitation is confirmed or strongly suspected.
- Block the source IP or upstream request pattern at the WAF, reverse proxy, or firewall if safe to do so.
- Disable the vulnerable application or affected endpoint until patching and validation are complete.
- Preserve logs and memory/process evidence before service restart or remediation.

**Closure criteria:**
- The correlated request is verified as benign application traffic or an approved test.
- No suspicious child process behavior or post-request activity is found.
- The request and process chain match known-good operational behavior for the application.
- The source and payload are explained by a documented maintenance, monitoring, or deployment action.

<br/>
---
<br/>

## Detection 3: Anomalous Service Principal Credential Use with Unusual Resource Access - Storm-0940 M365 Abuse

### Detection Opportunity

Application credential abuse across Microsoft 365 environments by service principals authenticating from anomalous sources and accessing unexpected resources, consistent with Storm-0940 post-compromise activity.

### Intelligence Context

- Microsoft Security Blog: AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise — [https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
  - Context: Storm-0940 abused application credentials across Microsoft 365 environments as part of a supply chain compromise enabled by the ARTEX agentic AI tool. The abuse involved service principal authentication activity that is detectable via Entra ID sign-in and audit logs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-0940
- ATT&CK tags: T1078, T1078.004, T1550, T1550.001, T1098, T1098.003
- Products: ARTEX, ConnectWise, Microsoft 365
- Platforms: Not specified
- Malware: Not specified
- Tools: ARTEX
- Search tags: Storm-0940, ARTEX, ConnectWise, Microsoft 365, T1078, T1078.004, T1550, T1550.001, T1098, T1098.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: initial access: T1078 Valid Accounts/ T1078.004 Cloud Accounts (high); credential access: T1550 Use Alternate Authentication Material/ T1550.001 Application Access Token (medium); persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Credentials (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let SuspiciousSPSignins = SigninLogs
| where TimeGenerated > ago(1d)
| where isnotempty(ServicePrincipalName)
| where ResultType == 0
| where ConditionalAccessStatus in ("notApplied", "unknownFutureValue") or RiskLevelDuringSignIn in ("medium", "high")
| project SigninTime = TimeGenerated, AppId, ServicePrincipalName, IPAddress,
    ConditionalAccessStatus, RiskLevelDuringSignIn;
let SensitiveOps = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has_any (
    "Add service principal credentials",
    "Update application",
    "Consent to application",
    "Add app role assignment",
    "Add delegated permission grant"
  )
| extend ActorAppId = tostring(InitiatedBy.app.appId)
| extend ActorSPId = tostring(InitiatedBy.app.servicePrincipalId)
| where isnotempty(ActorAppId) or isnotempty(ActorSPId)
| extend TargetResourcesRendered = tostring(TargetResources)
| project AuditTime = TimeGenerated, ActorAppId, ActorSPId, OperationName,
    TargetResourcesRendered;
SuspiciousSPSignins
| join kind=inner (
    SensitiveOps
) on $left.AppId == $right.ActorAppId
| where AuditTime between (SigninTime .. (SigninTime + 30m))
| project SigninTime, AuditTime, ServicePrincipalName, AppId, IPAddress,
    ConditionalAccessStatus, RiskLevelDuringSignIn, OperationName, TargetResourcesRendered
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate DevOps pipelines that authenticate as a service principal and then immediately update application registrations or add credentials as part of automated deployment.
- Managed identity or service principal rotation processes that add new credentials immediately after authenticating.
- Third-party SaaS connectors that authenticate and then request delegated permission grants during initial setup or re-authorization.

**Tuning notes:**
- Develop an allowlist of AppIds for known-legitimate service principals that operate without CA enforcement and add a → where AppId !in (allowlist) filter.
- Extend the join window to 60 minutes if audit log ingestion latency in the tenant regularly exceeds 15 minutes.
- If P2 licensing is unavailable, remove the RiskLevelDuringSignIn branch and focus exclusively on ConditionalAccessStatus == 'notApplied' with additional OperationName specificity.

**Risks / caveats:**
- RiskLevelDuringSignIn is only populated in SigninLogs when the tenant has Entra ID P2 (or Microsoft Entra ID Protection) licensing; without P2, this field will be empty and the risk-based filter branch will never match.
- InitiatedBy.app.appId in AuditLogs is populated for service-principal-initiated actions but may be null for delegated or user-initiated operations; the ActorAppId != '' filter handles this but reduces coverage for mixed-initiation scenarios.
- Without Entra ID P2 licensing, RiskLevelDuringSignIn will always be empty, meaning only the ConditionalAccessStatus branch will fire; this reduces detection coverage to sign-ins where CA policy was not applied.
- The 30-minute correlation window may miss slow-moving post-compromise activity where the actor waits before performing sensitive operations.

### Triage Runbook

**First 15 minutes:**
- Identify the service principal, AppId, source IP, and sign-in risk or Conditional Access status associated with the alert.
- Review the correlated AuditLogs operation to determine what sensitive action occurred, such as credential addition, permission grant, or role assignment.
- Check whether the source IP, tenant, and time of activity match known automation, CI/CD, or managed identity behavior.
- Look for additional sign-ins or audit events from the same AppId before and after the alert to assess scope and persistence.
- Verify whether the service principal recently changed ownership, credentials, permissions, or conditional access posture.

**Evidence to collect:**
- ServicePrincipalName, AppId, IPAddress, ConditionalAccessStatus, RiskLevelDuringSignIn, SigninTime, AuditTime, OperationName, and TargetResourcesRendered.
- Full sign-in history for the AppId, including prior source IPs and geographies.
- Audit log history for the same application or service principal, especially credential and permission changes.
- Any related Entra ID role assignments, consent grants, or application updates.
- Tenant change records or change-management tickets that explain the service principal activity.

**Pivot points:**
- SigninLogs for the same AppId over a wider time range to identify unusual source IPs or repeated sign-ins.
- AuditLogs for the same AppId or TargetResources to enumerate all recent application changes.
- Entra ID role assignment and consent logs to check for privilege escalation or new delegated permissions.
- Conditional Access and identity protection logs to determine whether the sign-in was expected or risky.
- If available, Microsoft 365 unified audit logs for downstream mailbox, SharePoint, or Teams access by the same principal.

**Benign explanations:**
- A legitimate DevOps or automation account may authenticate and then update application registrations or credentials as part of deployment.
- Managed identity rotation or certificate renewal can look like credential addition or application update activity.
- A third-party SaaS integration may perform consent or permission changes during initial setup or reauthorization.
- A service principal may legitimately operate from a new IP after infrastructure changes, failover, or vendor migration.

**Escalation criteria:**
- The service principal authenticates from an unfamiliar IP and performs sensitive changes without a change ticket or owner confirmation.
- The audit event shows new credentials, permission grants, or role assignments that were not approved.
- The principal is associated with high-value applications, admin roles, or broad tenant access.
- There are signs of follow-on abuse such as mailbox access, mass data collection, or additional privilege changes.

**Containment actions:**
- Disable or rotate the service principal credentials if unauthorized use is confirmed or strongly suspected.
- Revoke active sessions, refresh tokens, and any newly issued credentials or certificates tied to the principal.
- Remove unauthorized permissions, role assignments, or consent grants immediately.
- Coordinate with identity administrators to preserve audit evidence before making destructive changes where possible.

**Closure criteria:**
- The activity is confirmed as approved automation, rotation, or vendor-managed setup with supporting change records.
- The source IP and audit action match a known-good baseline for the service principal.
- No unauthorized permissions, credentials, or downstream resource access are identified.
- The principal owner validates the activity and no additional suspicious sign-ins or audit events are present.

<br/>
---
<br/>

## Detection 4: EFI System Partition File Write by Non-Bootloader Process - BlackX UEFI Bootkit Installation

### Detection Opportunity

Exploitation of CVE-2022-21894 (Baton Drop) by APT41 to write malicious files to the EFI system partition as part of BlackX UEFI bootkit installation.

### Intelligence Context

- Securelist: How APT41 revived the BlackLotus bootkit to attack diplomatic organizations in Central Asia — [https://securelist.com/uefi-bootkit-blackx/121539/](https://securelist.com/uefi-bootkit-blackx/121539/)
  - Context: APT41 deployed the BlackX UEFI bootkit by exploiting CVE-2022-21894 (Baton Drop). Exploitation leaves file-system artifacts on the EFI system partition. Kaspersky GReAT identified this as a revival of the BlackLotus bootkit technique targeting diplomatic organizations.

### Search Metadata

- CVEs: CVE-2022-21894
- Threat actors: APT41
- ATT&CK tags: T1542, T1542.003, T1070, T1070.006
- Products: BlackLotus
- Platforms: Windows, UEFI, firmware
- Malware: BlackX, BlackLotus
- Tools: Not specified
- Search tags: CVE-2022-21894, APT41, Windows, UEFI, firmware, BlackX, BlackLotus, T1542, T1542.003, T1070, T1070.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: persistence: T1542 Pre-OS Boot/ T1542.003 Bootkit (high); defense evasion: T1070 Indicator Removal on Host/ T1070.006 Timestomp (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let LegitBootTools = dynamic(["bcdedit.exe", "mountvol.exe", "diskpart.exe", "bcdboot.exe", "reagentc.exe", "TrustedInstaller.exe", "svchost.exe", "wuauclt.exe", "UsoClient.exe", "MoUsoCoreWorker.exe"]);
let EfiWrites = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\EFI\\", "\\Boot\\", "bootmgr", "bootmgfw.efi", "\\grub")
| where ActionType in ("FileCreated", "FileRenamed", "FileCopied")
| where not(InitiatingProcessFileName in~ (LegitBootTools))
| where not(InitiatingProcessFileName startswith "TiWorker")
| project EfiWriteTime = Timestamp, DeviceId, DeviceName,
    FolderPath, FileName, InitiatingProcessFileName, SHA256;
let SuspiciousPrecursor = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "SeLoadDriverPrivilege",
    "bootmgr",
    "\\EFI\\",
    "-exec bypass",
    "shimx64",
    "grubx64",
    "bootx64"
  )
| where not(InitiatingProcessFileName in~ (LegitBootTools))
| project ProcTime = Timestamp, DeviceId, AccountName, ProcessCommandLine,
    PrecursorProcess = InitiatingProcessFileName;
EfiWrites
| join kind=innerunique (
    SuspiciousPrecursor
) on DeviceId
| where ProcTime < EfiWriteTime and EfiWriteTime <= (ProcTime + 1h)
| project EfiWriteTime, ProcTime, DeviceId, DeviceName, FolderPath, FileName,
    SHA256, InitiatingProcessFileName, AccountName, ProcessCommandLine, PrecursorProcess
| sort by EfiWriteTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- OEM firmware update utilities (e.g., Dell Command Update, HP BIOS Update, Lenovo System Update) that write to EFI paths and are not in the LegitBootTools exclusion list.
- Third-party disk management or partition tools that mount and write to the ESP.
- Linux dual-boot environments where GRUB or systemd-boot updates are performed from within Windows using WSL or cross-OS tools.
- Windows Feature Updates that use non-standard update agent process names not covered by the exclusion list.

**Tuning notes:**
- Enumerate OEM firmware update process names in your environment by running: DeviceFileEvents → where FolderPath has '\\EFI\\' → summarize count() by InitiatingProcessFileName → sort by count_ desc, then add confirmed legitimate processes to LegitBootTools.
- Reduce the lookback from 7d to 2d for scheduled execution to control query cost; use 7d only for manual threat hunting.
- If SHA256 values for known BlackX or BlackLotus components become available, add a SHA256 in (known_hashes) branch as a high-confidence parallel detection path.

**Risks / caveats:**
- DeviceFileEvents may not capture writes to the EFI system partition if the partition is not mounted as a drive letter accessible to the Windows OS at the time of the write; UEFI bootkit installers often mount the ESP temporarily and MDE may not observe the file operation if it occurs at a layer below the Windows I/O stack.
- The ActionType values 'FileCreated', 'FileModified', 'FileRenamed' must be confirmed as valid ActionType strings in DeviceFileEvents; 'FileModified' is not a standard ActionType in MDE DeviceFileEvents (standard values are FileCreated, FileRenamed, FileDeleted, FileCopied).
- MDE may not observe EFI partition file writes if the bootkit installer operates below the Windows I/O stack (e.g., via direct UEFI runtime services or a vulnerable signed bootloader that bypasses OS-level file event hooks).
- The 7-day lookback window is expensive for DeviceFileEvents and DeviceProcessEvents at scale; consider reducing to 2 days for scheduled execution and using 7 days only for ad-hoc hunting.

### Triage Runbook

**First 15 minutes:**
- Confirm the EFI write path, file name, SHA256, and initiating process to determine whether the write targets boot-related files or directories.
- Review the precursor process command line and account context to see whether the activity aligns with boot manipulation or privilege escalation.
- Check whether the initiating process is a known-good boot or update utility such as bcdboot, bcdedit, mountvol, diskpart, or a vendor firmware tool.
- Determine whether the host recently underwent a firmware update, OS upgrade, recovery operation, or dual-boot maintenance task.
- Look for additional signs of tampering such as Secure Boot changes, boot configuration edits, or unexpected reboots.

**Evidence to collect:**
- EfiWriteTime, ProcTime, DeviceName, DeviceId, FolderPath, FileName, SHA256, InitiatingProcessFileName, AccountName, and ProcessCommandLine.
- Full DeviceFileEvents history for the same host around the EFI write time.
- DeviceProcessEvents showing the precursor process tree and any related boot configuration commands.
- Any reboot, firmware update, or OS servicing logs around the same time.
- If available, Secure Boot, BitLocker, and boot configuration state from endpoint management or system logs.

**Pivot points:**
- DeviceFileEvents on the same DeviceId for other writes to EFI, Boot, or GRUB-related paths.
- DeviceProcessEvents for boot-related commands, privilege escalation, or firmware update utilities.
- Windows event logs or endpoint management logs for reboot, update, or recovery activity.
- Inventory or software deployment records to identify OEM firmware tools present on the host.
- If available, MDE alerts or tamper events related to boot configuration or Secure Boot changes.

**Benign explanations:**
- A legitimate Windows update, recovery, or boot repair operation may write to EFI paths.
- OEM firmware update utilities can legitimately modify boot files or EFI partition contents.
- Disk management or dual-boot maintenance tools may mount and update the EFI system partition.
- TrustedInstaller or system maintenance processes may touch boot-related files during servicing.

**Escalation criteria:**
- The EFI write is performed by an unexpected process or user and is not tied to a documented maintenance activity.
- The file path or hash suggests a bootkit component, loader replacement, or unauthorized boot configuration change.
- There are additional indicators of persistence or defense evasion, such as Secure Boot tampering or repeated EFI writes.
- The host is a high-value endpoint and the activity cannot be explained by approved firmware or OS servicing.

**Containment actions:**
- Isolate the host if unauthorized EFI modification is confirmed or strongly suspected.
- Preserve disk and memory evidence before rebooting, repairing, or reimaging the system.
- Coordinate with endpoint and firmware administrators before making boot configuration changes.
- If safe and approved, disable network access to prevent further attacker activity while preserving evidence.

**Closure criteria:**
- The EFI write is attributed to a known-good boot management or firmware update process.
- The file path, hash, and command line match approved maintenance activity.
- No additional suspicious boot, persistence, or tampering indicators are found.
- The activity is validated by change records, OEM tooling logs, or endpoint management evidence.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- PHP Web Worker Spawning Unexpected Child Process - CVE-2026-109618/109619: Do not schedule yet; validate as an analyst-led hunt first.
- EFI System Partition File Write by Non-Bootloader Process - BlackX UEFI Bootkit Installation: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- PHP Worker Spawning Shell Correlated with HTTP 200 Response - CVE-2026-109618/109619 PoC Exploitation: DeviceVendor values 'Apache', 'nginx', 'LiteSpeed' must exactly match the strings emitted by the log forwarder configured in the environment; these are not standardized across connectors.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Shared-table notes:**
- DeviceProcessEvents: shared by PHP Web Worker Spawning Unexpected Child Process - CVE-2026-109618/109619; EFI System Partition File Write by Non-Bootloader Process - BlackX UEFI Bootkit Installation

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Anomalous Service Principal Credential Use with Unusual Resource Access - Storm-0940 M365 Abuse.
2. Resolve environment-mapping detections next: PHP Worker Spawning Shell Correlated with HTTP 200 Response - CVE-2026-109618/109619 PoC Exploitation.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: PHP Web Worker Spawning Unexpected Child Process - CVE-2026-109618/109619; EFI System Partition File Write by Non-Bootloader Process - BlackX UEFI Bootkit Installation.

### Hunting Agenda and Promotion Criteria

- PHP Web Worker Spawning Unexpected Child Process - CVE-2026-109618/109619: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- EFI System Partition File Write by Non-Bootloader Process - BlackX UEFI Bootkit Installation: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- PHP Worker Spawning Shell Correlated with HTTP 200 Response - CVE-2026-109618/109619 PoC Exploitation: DeviceVendor values 'Apache', 'nginx', 'LiteSpeed' must exactly match the strings emitted by the log forwarder configured in the environment; these are not standardized across connectors.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
