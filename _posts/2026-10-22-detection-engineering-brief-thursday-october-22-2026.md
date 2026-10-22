---
layout: post
title: "Detection Engineering Brief - Thursday, October 22, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-22
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
  - Storm-0940
  - ConnectWise
  - Microsoft 365
  - ARTEX
  - Lazarus
  - CrossWeb EX
  - Windows
  - T1505
  - T1505.003
  - T1059
  - T1218
  - T1218.005
  - T1071
  - T1071.001
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-109618, CVE-2026-109619, T1190, PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed, Storm-0940, ConnectWise, Microsoft 365, ARTEX, Lazarus, CrossWeb EX, Windows, T1505, T1505.003, T1059, T1218, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: ConnectWise Agent Spawning Unexpected Child Process Post Supply Chain Compromise; Lazarus CrossWeb EX Financial Software Spawning Unexpected Child Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: PHP Worker Process Spawning Unexpected Shell or Interpreter

### Detection Opportunity

Unauthenticated remote code execution against PHP web services resulting in web worker processes spawning child shells or interpreters.

### Intelligence Context

- Rapid7: CVE-2026-109618 and CVE-2026-109619: Critical Unauthenticated Remote Code Execution in PHP — [https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php)
  - Context: Both CVE-2026-109618 and CVE-2026-109619 allow unauthenticated RCE with web worker privileges. Rapid7 explicitly identifies PHP-FPM, php-cgi, Apache mod_php, FrankenPHP, and LiteSpeed as affected deployment modes. Post-exploitation activity is expected to manifest as web worker processes spawning shells.

### Search Metadata

- CVEs: CVE-2026-109618, CVE-2026-109619
- Threat actors: Not specified
- ATT&CK tags: T1190, T1505, T1505.003
- Products: PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-109618, CVE-2026-109619, T1190, PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed, T1505, T1505.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (high); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let PhpWorkerParents = dynamic(["php-fpm", "php-cgi", "apache2", "httpd", "litespeed", "frankenphp"]);
let SuspiciousChildren = dynamic(["sh", "bash", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "nc", "ncat", "curl", "wget", "cmd.exe", "powershell.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where InitiatingProcessFileName in~ (PhpWorkerParents)
| where FileName in~ (SuspiciousChildren)
| where FileName !~ InitiatingProcessFileName
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessId,
    FileName,
    ProcessCommandLine,
    ProcessId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- PHP CLI scripts invoked by cron or deployment pipelines that legitimately call bash or python as subprocesses.
- Apache spawning logrotate, sendmail, or rotatelogs as part of normal log management.
- Development environments where php-cgi or apache2 are used interactively and spawn shells for legitimate purposes.

**Tuning notes:**
- Confirm exact PHP worker binary names on target hosts by querying distinct InitiatingProcessFileName values from web server devices before scheduling.
- Add AccountName exclusions for known service accounts used by CI/CD pipelines that legitimately invoke interpreters under web worker context.
- If php CLI is heavily used on web servers for non-web purposes, add a filter on InitiatingProcessCommandLine to restrict to FPM or CGI invocation patterns.

**Risks / caveats:**
- DeviceProcessEvents is only populated when MDE agent is deployed and onboarded on the web server hosts; Linux web servers without MDE coverage will produce no results.
- FrankenPHP and LiteSpeed may run under binary names not matching the filter list; coverage depends on the actual executable name on disk.
- Short child process names such as 'sh', 'nc', and 'perl' matched via in~ are exact-match safe, but legitimate PHP-spawned helper scripts using these interpreters will generate FPs until a baseline exclusion list is built.
- The 7-day lookback window may produce high result volumes in active environments; consider reducing to 1 day for scheduled rule deployment.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a public-facing PHP server and identify the exact worker process involved (php-fpm, php-cgi, apache2/httpd, FrankenPHP, LiteSpeed).
- Review the child process command line and parent/child process tree for signs of attacker activity such as sh/bash/python/perl/curl/wget or encoded/obfuscated arguments.
- Check whether the same host shows nearby web exploitation indicators: repeated web requests, new PHP files, unusual outbound connections, or additional suspicious child processes.
- Determine whether the spawning account and process context match normal web service behavior or an application deployment task.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessId, FileName, ProcessCommandLine, ProcessId.
- Full process tree around the alert window, including grandparent process and any sibling processes spawned by the same PHP worker.
- Recent web server logs or reverse proxy logs for the same host and time window to identify the triggering request path, source IP, and HTTP method.
- Any outbound network connections from the child process or the PHP worker immediately after process creation.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and a 24-hour window to find additional child processes from the same InitiatingProcessId or InitiatingProcessFileName.
- DeviceNetworkEvents for the same DeviceName and time window to identify outbound connections from the PHP worker or child shell.
- DeviceFileEvents for the same host to look for new or modified .php files in web roots.
- If available, web server access logs or WAF logs to correlate the process start time with suspicious requests.

**Benign explanations:**
- Legitimate PHP CLI or application maintenance jobs that invoke bash, python, or perl as subprocesses.
- Developer or admin activity on a test or staging web server where interactive shell spawning is expected.
- Automated deployment or backup scripts that run under the web service context and call helper interpreters.

**Escalation criteria:**
- The child process is an interactive shell, downloader, or scripting interpreter with suspicious arguments and no approved maintenance explanation.
- The alert coincides with suspicious web requests, new web shell files, or outbound connections to untrusted destinations.
- Multiple PHP worker hosts show the same pattern within a short time window, suggesting active exploitation at scale.
- The host is internet-facing and the process tree indicates post-exploitation activity beyond normal web service behavior.

**Containment actions:**
- Isolate the affected web server from the network if the child process indicates active exploitation or command execution.
- Terminate the suspicious child process and, if necessary, the parent PHP worker after preserving volatile evidence.
- Block the source IPs or request patterns at the WAF or reverse proxy if they are clearly associated with exploitation.
- Preserve process, network, and web logs before rebooting or rebuilding the server.

**Closure criteria:**
- Confirmed legitimate maintenance or application behavior with matching change record and no other compromise indicators.
- No suspicious follow-on activity in process, file, or network telemetry after review of the alert window.
- The parent-child chain matches a known benign baseline for that specific server role and application.
- Any suspicious request source or payload was ruled out as a false positive by web log correlation and local process review.

<br/>
---
<br/>

## Detection 2: PHP Web Shell Drop by Web Worker Process

### Detection Opportunity

Web shell deployment to web-accessible directories following PHP RCE exploitation, where a PHP worker process creates a new .php file in a web root path.

### Intelligence Context

- Rapid7: CVE-2026-109618 and CVE-2026-109619: Critical Unauthenticated Remote Code Execution in PHP — [https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php)
  - Context: Rapid7 identifies web shell drops and follow-on command execution as expected post-exploitation activity after successful exploitation of CVE-2026-109618 or CVE-2026-109619. File creation events in web-accessible directories initiated by PHP worker processes are a high-fidelity indicator.

### Search Metadata

- CVEs: CVE-2026-109618, CVE-2026-109619
- Threat actors: Not specified
- ATT&CK tags: T1190, T1505, T1505.003
- Products: PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-109618, CVE-2026-109619, T1190, PHP, PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed, T1505, T1505.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (high); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let PhpWorkerParents = dynamic(["php-fpm", "php-cgi", "apache2", "httpd", "litespeed", "frankenphp"]);
let WebRoots = dynamic(["/var/www", "/srv/www", "/usr/share/nginx", "/opt/lampp/htdocs", "/var/www/html", "htdocs", "public_html", "webroot"]);
DeviceFileEvents
| where Timestamp >= ago(1d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".php"
| where InitiatingProcessFileName in~ (PhpWorkerParents)
| where FolderPath has_any (WebRoots)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CMS platforms such as WordPress, Drupal, or Joomla that write PHP plugin or theme files to web root directories under the web worker process context during legitimate updates.
- Automated deployment pipelines that run under the web worker user and write PHP files as part of application deployment.
- PHP-based file managers or admin panels that legitimately create PHP files in web-accessible directories.

**Tuning notes:**
- Add organization-specific web root paths to the WebRoots list to improve coverage for non-standard deployment paths.
- Consider restricting ActionType to 'FileCreated' only when scheduling as a high-fidelity rule, and running the FileModified variant separately as a lower-priority hunt.
- Add AccountName exclusions for known deployment service accounts to suppress CI/CD-driven PHP file writes.
- Submit SHA256 values from matches to threat intelligence platforms to distinguish web shells from legitimate PHP files.

**Risks / caveats:**
- DeviceFileEvents is only populated when MDE agent is deployed on Linux web server hosts; environments without MDE Linux coverage will produce no results.
- nginx is not a PHP execution engine and its presence as InitiatingProcessFileName for PHP file writes is unusual; including it may produce misleading results if nginx is used as a reverse proxy and writes config or cache files with .php extensions.
- Web root paths in the FolderPath filter are common defaults; environments using non-standard web root locations will have missed detections until those paths are added.
- FileModified events will fire for legitimate CMS plugin updates and may generate significant FP volume in environments with active CMS deployments.

### Triage Runbook

**First 15 minutes:**
- Validate that the file path is a real web root or application directory and that the file creation was initiated by a PHP worker process.
- Open the file metadata and content safely to determine whether it contains web shell behavior, obfuscation, command execution, or one-line stagers.
- Check whether the file creation aligns with a known deployment, CMS update, or admin action from an approved account.
- Look for nearby process or network activity from the same host that suggests post-exploitation follow-on actions.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId.
- The file contents or a secure copy of the dropped PHP file for offline review and hash reputation checks.
- Process tree and any sibling file writes from the same InitiatingProcessId or same worker process.
- Web server access logs around the file creation time to identify the request that likely triggered the write.

**Pivot points:**
- DeviceFileEvents for the same DeviceName to find other PHP file creations or modifications in web roots.
- DeviceProcessEvents for the same host and time window to identify shells, interpreters, or downloaders spawned by the same worker.
- DeviceNetworkEvents for the same host to identify outbound connections after the file was created.
- Threat intelligence or file reputation lookups using SHA256 for the dropped file.

**Benign explanations:**
- Legitimate CMS/plugin/theme updates that write PHP files into web roots under a web worker context.
- Automated deployment pipelines or release tooling that update application code in place.
- Admin tools or file managers embedded in the application that legitimately create PHP files.
- A modified file rather than a malicious drop, if the content matches a known application release artifact.

**Escalation criteria:**
- The file contains command execution, obfuscation, or web shell patterns, or its hash is unknown/suspicious.
- The file was created in a web root by a worker process and there is no approved change record.
- Additional suspicious processes, outbound connections, or repeated file writes occur on the same host.
- The file appears designed for persistence, remote command execution, or credential theft.

**Containment actions:**
- Quarantine or remove the dropped file only after preserving a copy for evidence.
- Isolate the host if the file is confirmed malicious or if additional compromise indicators are present.
- Block the triggering source IP or request pattern if identified from web logs.
- Rotate credentials or secrets exposed on the server if the web shell had access to them.

**Closure criteria:**
- The file is verified as a legitimate deployment artifact or CMS update and matches an approved change.
- Hash and content review show no malicious functionality or obfuscation.
- No additional suspicious process, file, or network activity is found on the host.
- The file path and initiating process are consistent with documented application behavior for that server.

<br/>
---
<br/>

## Detection 3: Storm-0940 M365 Application Credential Abuse via OAuth Service Principal

### Detection Opportunity

Application credential abuse across Microsoft 365 environments, including new OAuth credential additions or anomalous service principal sign-ins consistent with Storm-0940 supply chain compromise activity.

### Intelligence Context

- Microsoft Security Blog: AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise — [https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
  - Context: Storm-0940 used ARTEX agentic AI to accelerate a ConnectWise supply chain compromise enabling application credential abuse across Microsoft 365 environments. The campaign involves adding credentials to existing OAuth applications or service principals to enable persistent access without user interaction.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-0940
- ATT&CK tags: T1059, T1218, T1218.005, T1071, T1071.001
- Products: ConnectWise, Microsoft 365
- Platforms: Not specified
- Malware: Not specified
- Tools: ARTEX
- Search tags: Storm-0940, ConnectWise, Microsoft 365, ARTEX, T1059, T1218, T1218.005, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Execution: T1218 System Binary Proxy Execution/ T1218.005 Mshta (low); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AuditLogs, SigninLogs

### KQL

```kql
let CredentialAdditions = AuditLogs
| where TimeGenerated >= ago(1d)
| where OperationName in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Add application"
    )
| where Result == "success"
| extend
    AppId = tostring(TargetResources[0].id),
    AppName = tostring(TargetResources[0].displayName),
    InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    InitiatedByApp = tostring(InitiatedBy.app.displayName)
| where isnotempty(AppId)
| project CredentialAddTime = TimeGenerated, AppId, AppName, InitiatedByUPN, InitiatedByIP, InitiatedByApp;
let AppSignins = SigninLogs
| where TimeGenerated >= ago(1d)
| where TokenIssuerType == "AzureAD"
| where isnotempty(AppId)
| where ResultType == 0
| project
    SigninTime = TimeGenerated,
    AppId,
    AppDisplayName,
    UserPrincipalName,
    IPAddress,
    ResultType,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    UserAgent;
CredentialAdditions
| join kind=inner AppSignins on AppId
| where SigninTime between (CredentialAddTime .. (CredentialAddTime + 2h))
| project
    CredentialAddTime,
    SigninTime,
    AppName,
    AppDisplayName,
    InitiatedByUPN,
    InitiatedByApp,
    InitiatedByIP,
    UserPrincipalName,
    IPAddress,
    ResultType,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    UserAgent
| order by CredentialAddTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate application credential rotations performed by administrators followed immediately by automated service sign-ins as part of normal operations.
- CI/CD pipelines that add application secrets and immediately authenticate to validate the new credential.
- Managed identity or workload identity federation scenarios where credential additions and sign-ins are tightly coupled by design.

**Tuning notes:**
- Validate that OperationName values in your AuditLogs match the strings used in the filter by querying distinct OperationName values for service principal operations before scheduling.
- If AppId join misses are observed, consider joining on AppName or AppDisplayName as a fallback, accepting higher FP risk.
- Add InitiatedByUPN exclusions for known PIM or credential rotation service accounts to reduce FP volume.
- Consider a parallel detection using AADServicePrincipalSignInLogs joined on ServicePrincipalId to cover non-interactive service principal sign-ins not present in SigninLogs.

**Risks / caveats:**
- Service principal sign-ins may appear in AADServicePrincipalSignInLogs rather than SigninLogs depending on tenant configuration and Sentinel connector version; if AppId-keyed sign-ins are absent from SigninLogs the join will produce no results.
- TargetResources[0].id in AuditLogs returns the object ID of the target resource, not the application client ID; the AppId join key may not match SigninLogs AppId (client ID) in all cases, potentially causing join misses for multi-tenant or delegated scenarios.
- If service principal sign-ins are routed to AADServicePrincipalSignInLogs instead of SigninLogs, the join will miss those events; a parallel query against AADServicePrincipalSignInLogs should be considered.
- TargetResources[0].id returns the Entra object ID of the target application or service principal, which may differ from the AppId (client ID) field in SigninLogs; join misses are possible for some application types.

### Triage Runbook

**First 15 minutes:**
- Confirm the credential addition event, the target application/service principal, and who initiated the change.
- Review the first successful sign-in after the credential change, including IP address, user agent, risk level, and conditional access result.
- Check whether the initiating account or app is a known admin, automation account, or credential rotation workflow.
- Assess whether the sign-in source, timing, and geography are consistent with normal tenant operations.

**Evidence to collect:**
- CredentialAddTime, SigninTime, AppName, AppDisplayName, InitiatedByUPN, InitiatedByApp, InitiatedByIP, UserPrincipalName, IPAddress, ResultType, RiskLevelDuringSignIn, ConditionalAccessStatus, UserAgent.
- AuditLogs details for the credential addition operation, including TargetResources and InitiatedBy context.
- SigninLogs or service principal sign-in logs for the same AppId and a wider time window to identify additional access attempts.
- Any related admin activity, consent grants, or application permission changes around the same time.

**Pivot points:**
- AuditLogs for the same AppId or AppDisplayName to find other credential or permission changes.
- SigninLogs and, if available, AADServicePrincipalSignInLogs for the same application to identify broader use patterns.
- Entra ID directory audit activity for consent grants, role assignments, or app permission changes.
- Microsoft 365 unified audit logs for mailbox, SharePoint, or Teams access by the same application or related account.

**Benign explanations:**
- Legitimate secret rotation or certificate renewal performed by an administrator or automation pipeline.
- A managed application or workload identity that is expected to add credentials and immediately authenticate.
- A planned application registration or migration activity documented by the identity team.
- A service principal used by a vendor integration that signs in shortly after a routine credential update.

**Escalation criteria:**
- The credential addition was not performed by an approved administrator, automation account, or change ticket.
- The first sign-in originates from an unusual IP, geography, or user agent, or is associated with elevated risk.
- The application accesses sensitive Microsoft 365 resources or shows repeated sign-ins after the credential change.
- There are additional signs of tenant abuse such as consent grants, mailbox access, or privilege changes.

**Containment actions:**
- Disable or remove the suspicious application credential or temporarily disable the service principal if abuse is confirmed.
- Revoke active sessions and tokens associated with the application or initiating account where possible.
- Reset or rotate any related secrets and review application permissions for over-privilege.
- Block or investigate the source IPs and preserve audit evidence before making changes.

**Closure criteria:**
- The credential change is verified as approved and the subsequent sign-in matches expected automation behavior.
- No unauthorized access, risky sign-in, or suspicious downstream activity is found.
- The application and initiating account are confirmed to be part of a documented rotation or deployment process.
- Any anomalous sign-in was explained by a known service principal workflow and no further abuse indicators exist.

<br/>
---
<br/>

## Detection 4: ConnectWise Agent Spawning Unexpected Child Process Post Supply Chain Compromise

### Detection Opportunity

ConnectWise remote management agent processes spawning unexpected shells or making outbound connections to non-standard destinations, consistent with Storm-0940 supply chain abuse of the ConnectWise platform.

### Intelligence Context

- Microsoft Security Blog: AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise — [https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
  - Context: Storm-0940 abused the ConnectWise platform as part of a supply chain compromise. RMM tool abuse produces anomalous child process and network events on managed endpoints where the ConnectWise agent is the initiating process for unexpected execution chains.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-0940
- ATT&CK tags: T1059, T1218, T1218.005, T1071, T1071.001
- Products: ConnectWise, Microsoft 365
- Platforms: Not specified
- Malware: Not specified
- Tools: ARTEX
- Search tags: Storm-0940, ConnectWise, Microsoft 365, ARTEX, T1059, T1218, T1218.005, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Execution: T1218 System Binary Proxy Execution/ T1218.005 Mshta (low); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ConnectWiseParents = dynamic([
    "ScreenConnect.ClientService.exe",
    "ScreenConnect.WindowsClient.exe",
    "ConnectWiseControl.ClientService.exe",
    "cwagent.exe"
]);
let SuspiciousChildren = dynamic([
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "net.exe", "whoami.exe", "nltest.exe"
]);
let LookbackWindow = ago(7d);
let ProcessEvents = DeviceProcessEvents
| where Timestamp >= LookbackWindow
| where InitiatingProcessFileName in~ (ConnectWiseParents)
| where FileName in~ (SuspiciousChildren)
| project
    Timestamp,
    EventType = "ChildProcess",
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    RemoteIP = "",
    RemotePort = int(null),
    RemoteUrl = "",
    RemoteIPType = "";
let NetworkEvents = DeviceNetworkEvents
| where Timestamp >= LookbackWindow
| where InitiatingProcessFileName in~ (ConnectWiseParents)
| where RemotePort !in (443, 8041, 8040, 80)
| project
    Timestamp,
    EventType = "NetworkAnomaly",
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName = "",
    ProcessCommandLine = "",
    RemoteIP,
    RemotePort,
    RemoteUrl,
    RemoteIPType;
union ProcessEvents, NetworkEvents
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote support sessions where ConnectWise agents spawn cmd.exe or powershell.exe at the direction of IT administrators.
- Automated scripts executed via ConnectWise for patch management or configuration management that invoke net.exe, schtasks.exe, or similar utilities.
- ConnectWise agent updates or self-maintenance routines that spawn child processes or make outbound connections on non-standard ports.

**Tuning notes:**
- Query DeviceProcessEvents for distinct InitiatingProcessFileName values containing 'ScreenConnect' or 'ConnectWise' in your environment to confirm actual binary names before relying on this detection.
- Validate the RemotePort exclusion list against your ConnectWise server configuration; add any additional legitimate ports used by your deployment.
- After confirming binary names, consider splitting the process and network branches into separate scheduled rules with independent tuning rather than running as a union hunt.
- Add InitiatingProcessAccountName exclusions for known IT administrator accounts that routinely use ConnectWise for legitimate remote support.

**Risks / caveats:**
- Custom-branded ConnectWise deployments use partner-specific executable names that will not match the ConnectWiseParents list; coverage is zero for those deployments without inventory-confirmed binary names.
- DeviceNetworkEvents RemotePort filtering assumes ConnectWise uses ports 443, 8040, and 8041; environments with non-default ConnectWise server port configurations will generate FPs or miss legitimate traffic.
- Custom-branded ConnectWise agent binary names are not covered by the ConnectWiseParents list; environments with partner-branded agents will have zero coverage from the process and network branches.
- The RemotePort exclusion list is based on ConnectWise default ports; non-default server configurations will produce FPs or miss legitimate traffic until the exclusion list is validated against the actual deployment.

### Triage Runbook

**First 15 minutes:**
- Confirm the endpoint has a legitimate ConnectWise agent and identify the exact parent process and child process or network event that triggered the alert.
- Review the child process command line for remote administration, script execution, or living-off-the-land binaries such as cmd.exe, powershell.exe, mshta.exe, or rundll32.exe.
- Check whether the network event is to an approved ConnectWise server and expected port, or to an unusual public destination.
- Determine whether the activity aligns with a known remote support session, patch job, or admin action.

**Evidence to collect:**
- Timestamp, EventType, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, RemoteIPType.
- Full process tree for the ConnectWise agent and any spawned child processes.
- Network connection details including destination IP, port, URL, and whether the destination is internal, vendor-owned, or public.
- Remote support session records, admin tickets, or change records for the same time window.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to find other child processes spawned by the ConnectWise agent.
- DeviceNetworkEvents for the same host to identify additional outbound connections from the agent.
- DeviceLogonEvents or related endpoint telemetry to see whether an admin session was active at the time.
- If available, ConnectWise server logs or RMM audit logs for the same session or device.

**Benign explanations:**
- Legitimate remote support activity where an administrator intentionally runs commands through ConnectWise.
- Patch management, inventory, or configuration scripts executed by the RMM platform.
- Agent update, self-healing, or maintenance routines that spawn helper processes.
- Non-default ConnectWise server ports or custom deployment behavior that differs from the baseline.

**Escalation criteria:**
- The child process is a shell, script interpreter, or system binary used in a way not tied to an approved support session.
- The network destination is not an approved ConnectWise server or is an unexpected public IP/URL.
- Multiple endpoints show the same suspicious agent behavior, suggesting broader abuse.
- There is no valid support ticket, admin action, or maintenance window to explain the activity.

**Containment actions:**
- Suspend or isolate the affected endpoint if the agent is executing suspicious commands or contacting unapproved destinations.
- Disable or restrict the ConnectWise agent temporarily if abuse is confirmed and business impact is acceptable.
- Block suspicious outbound destinations at the proxy or firewall while preserving evidence.
- Coordinate with the RMM owner before making changes to avoid disrupting legitimate fleet management.

**Closure criteria:**
- The activity is matched to a documented remote support or maintenance session.
- The child process and network destination are confirmed as expected for the environment and agent configuration.
- No additional suspicious execution or lateral activity is observed on the endpoint.
- The ConnectWise binary name and port usage are validated against the organization’s approved baseline.

<br/>
---
<br/>

## Detection 5: Lazarus CrossWeb EX Financial Software Spawning Unexpected Child Process

### Detection Opportunity

Abuse of CrossWeb EX financial security software by Lazarus Group, where the CrossWeb EX process spawns unexpected child processes as part of watering-hole delivered malware execution.

### Intelligence Context

- Securelist: Operation FlashHole: Lazarus breaks security, defies control — [https://securelist.com/lazarus-operation-flashhole/121541/](https://securelist.com/lazarus-operation-flashhole/121541/)
  - Context: Lazarus Group abused CrossWeb EX financial security software as part of Operation FlashHole, which combined a watering-hole technique with a sophisticated malware set. CrossWeb EX is a financial sector security product whose abuse by Lazarus produces anomalous child process chains that are detectable via parent-child process relationship monitoring on Windows endpoints.

### Search Metadata

- CVEs: Not specified
- Threat actors: Lazarus
- ATT&CK tags: T1059, T1218, T1218.005
- Products: CrossWeb EX
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Lazarus, CrossWeb EX, Windows, T1059, T1218, T1218.005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Execution: T1218 System Binary Proxy Execution/ T1218.005 Mshta (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let SuspiciousChildren = dynamic([
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "net.exe",
    "whoami.exe", "nltest.exe", "schtasks.exe", "at.exe"
]);
DeviceProcessEvents
| where Timestamp >= ago(14d)
| where (
    InitiatingProcessFileName contains "CrossWeb"
    or InitiatingProcessFileName contains "crossweb"
    or InitiatingProcessFileName contains "CrossWebEx"
    )
    or (
    InitiatingProcessParentFileName contains "CrossWeb"
    or InitiatingProcessParentFileName contains "crossweb"
    or InitiatingProcessParentFileName contains "CrossWebEx"
    )
| where FileName in~ (SuspiciousChildren)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessId,
    FileName,
    ProcessCommandLine,
    ProcessId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate CrossWeb EX operations that spawn child processes as part of normal security software functionality, such as update handlers or certificate validation utilities.
- Other software with 'CrossWeb' in the binary name that is unrelated to CrossWeb EX financial security software.

**Tuning notes:**
- Query DeviceProcessEvents for all distinct InitiatingProcessFileName values containing 'CrossWeb' on financial sector endpoints to confirm the exact binary name before scheduling.
- Once the confirmed binary name is known, replace the contains filters with an exact in~ match for higher precision.
- Extend the lookback window beyond 14 days for initial threat hunting to surface historical Operation FlashHole indicators.
- Consult CrossWeb EX vendor documentation for the expected child process list to build an exclusion baseline before scheduling as an alert rule.

**Risks / caveats:**
- CrossWeb EX executable name is not confirmed in the source article; the filter strings 'CrossWebEx', 'crosswebex', and 'CrossWeb' are inferred approximations. If the actual binary name does not contain these substrings, the query will return zero results.
- CrossWeb EX is a Korean financial sector security product with limited deployment outside South Korean financial institutions; MDE telemetry from hosts running this software may not be available in most environments.
- The CrossWeb EX binary name is unconfirmed; the substring filters 'CrossWeb' and 'CrossWebEx' are approximations that must be validated against actual endpoint inventory before this query can be trusted to produce accurate results.
- If CrossWeb EX is not deployed in the environment, this query will return zero results regardless of query correctness.

### Triage Runbook

**First 15 minutes:**
- Confirm the endpoint actually runs CrossWeb EX and identify the exact executable name from the alert context.
- Review the child process name and command line to see whether it is a shell, script interpreter, downloader, or system binary proxy execution tool.
- Check whether the activity occurred during a known CrossWeb EX update, login, certificate validation, or vendor maintenance window.
- Assess whether the host is in a financial environment where CrossWeb EX is expected and whether the process tree matches normal behavior.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessId, FileName, ProcessCommandLine, ProcessId.
- The full process tree around the alert, including grandparent process context and any sibling processes.
- Any vendor documentation or local baseline of expected CrossWeb EX child processes for the environment.
- Recent user activity and network connections from the same host around the alert time.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to find repeated CrossWeb-related child process activity.
- DeviceNetworkEvents for the same host to identify outbound connections that coincide with the process spawn.
- DeviceFileEvents for the same host to look for dropped files, scripts, or executables near the alert time.
- Endpoint inventory or software deployment records to confirm the CrossWeb EX installation and version.

**Benign explanations:**
- Legitimate CrossWeb EX update, certificate, or helper utility execution.
- Other software with a similar name substring that is not the targeted CrossWeb EX product.
- Administrative or support activity on a financial workstation that legitimately launches helper binaries.
- Vendor-specific behavior that is normal for the installed CrossWeb EX version but not yet baselined.

**Escalation criteria:**
- The child process is clearly malicious or is a known LOLBin used for execution, persistence, or download.
- The host shows additional indicators such as suspicious network traffic, dropped files, or repeated child process spawning.
- The CrossWeb EX executable name is confirmed and the behavior is outside the vendor baseline.
- The endpoint is in a high-value financial environment and the activity cannot be explained by approved maintenance.

**Containment actions:**
- Isolate the endpoint if the child process is malicious or if additional compromise indicators are present.
- Terminate the suspicious child process after preserving process evidence.
- Block known malicious outbound destinations if identified during triage.
- Coordinate with the application owner before disabling CrossWeb EX to avoid unnecessary business disruption.

**Closure criteria:**
- The process spawn is confirmed as legitimate CrossWeb EX behavior and matches vendor or internal baseline.
- The executable name and parent-child chain are validated against endpoint inventory and software documentation.
- No additional suspicious processes, files, or network activity are found on the host.
- The alert is attributable to a known update, maintenance, or support workflow with supporting evidence.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- ConnectWise Agent Spawning Unexpected Child Process Post Supply Chain Compromise: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Lazarus CrossWeb EX Financial Software Spawning Unexpected Child Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by PHP Worker Process Spawning Unexpected Shell or Interpreter; ConnectWise Agent Spawning Unexpected Child Process Post Supply Chain Compromise; Lazarus CrossWeb EX Financial Software Spawning Unexpected Child Process

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: PHP Worker Process Spawning Unexpected Shell or Interpreter; PHP Web Shell Drop by Web Worker Process; Storm-0940 M365 Application Credential Abuse via OAuth Service Principal.
2. Resolve environment-mapping detections next: Lazarus CrossWeb EX Financial Software Spawning Unexpected Child Process.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ConnectWise Agent Spawning Unexpected Child Process Post Supply Chain Compromise.

### Hunting Agenda and Promotion Criteria

- ConnectWise Agent Spawning Unexpected Child Process Post Supply Chain Compromise: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Lazarus CrossWeb EX Financial Software Spawning Unexpected Child Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
