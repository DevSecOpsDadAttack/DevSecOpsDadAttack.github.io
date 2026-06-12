---
layout: post
title: "Detection Engineering Brief - Friday, June 12, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-12
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-35273
  - T1190
  - Oracle PeopleSoft Enterprise PeopleTools
  - CVE-2026-10520
  - CVE-2026-10523
  - T1059
  - Ivanti Sentry
---

## Executive Signal

This brief produced 3 detection candidates.

0 production candidates, 0 hunting-only, 3 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-35273, T1190, Oracle PeopleSoft Enterprise PeopleTools, CVE-2026-10520, CVE-2026-10523, T1059, Ivanti Sentry.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: PeopleSoft RCE - Anomalous Child Process Spawned by PeopleSoft Application Process; Ivanti Sentry RCE - Shell Interpreter Invocation from Sentry Web Service Process; Ivanti Sentry Auth Bypass - Unauthenticated Admin Account Creation from External Source.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: PeopleSoft RCE - Anomalous Child Process Spawned by PeopleSoft Application Process

### Detection Opportunity

Unauthenticated remote exploitation of Oracle PeopleSoft leading to unexpected child process execution, indicative of RCE via CVE-2026-35273

### Intelligence Context

- Rapid7: Active Exploitation of Oracle PeopleSoft Zero-Day (CVE-2026-35273) — [https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273](https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273)
  - Context: Mandiant reported active in-the-wild exploitation of CVE-2026-35273, a remotely exploitable unauthenticated RCE vulnerability affecting PeopleTools 8.61 and 8.62. Exploitation may result in arbitrary command execution on the PeopleSoft host, detectable via anomalous child processes spawned from the PeopleSoft application process.

### Search Metadata

- CVEs: CVE-2026-35273
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Oracle PeopleSoft Enterprise PeopleTools
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-35273, T1190, Oracle PeopleSoft Enterprise PeopleTools, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("psadmin.exe", "psadmin", "java.exe", "java", "psappsrv.exe", "psappsrv", "pswatchsrv.exe", "pswatchsrv")
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "sh", "bash", "dash", "zsh",
    "python.exe", "python", "python3",
    "perl.exe", "perl",
    "wget", "curl", "curl.exe",
    "whoami.exe", "whoami",
    "id",
    "net.exe", "net1.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Java-based application servers (Tomcat, JBoss, WebLogic) on the same host or other hosts will match if DeviceName is not scoped.
- Legitimate PeopleSoft administrative scripts that invoke cmd.exe or shell utilities during maintenance windows.
- Monitoring or backup agents that run under the same service account as PeopleSoft processes.

Tuning notes:
- Add a DeviceName filter against a watchlist or dynamic_list of known PeopleSoft server hostnames before promoting to a scheduled rule.
- Consider adding a FolderPath contains filter for the PeopleSoft installation directory (e.g., PT_HOME or PSHOME paths) when java is the initiating process to reduce false positives.
- On Linux MDE agents, process names will not have .exe extensions; the in~ operator handles case but not extension variants, so both forms are included.

Risks / caveats:
- DeviceProcessEvents requires Microsoft Defender for Endpoint (MDE) onboarding on the PeopleSoft host. If MDE is not deployed on the PeopleSoft server, this query will return no results for that host.
- PeopleSoft typically runs on Windows or Linux. On Linux hosts onboarded via MDE, process telemetry field fidelity (especially InitiatingProcessFileName) should be validated as Linux process names may appear without extensions.
- Without DeviceName scoping to PeopleSoft hosts, the query will match any Java or psadmin process on any onboarded device, producing significant noise in environments with many Java-based servers.
- The 7-day lookback window may need adjustment based on hunting cadence; shorter windows reduce noise during active incident response.

### Triage Runbook

First 15 minutes:
- Confirm the alert is on a known PeopleSoft server by checking DeviceName against your approved PeopleSoft host inventory.
- Review the parent and child process chain: identify the initiating PeopleSoft process, the spawned child process, and the full command line for both.
- Check whether the child process is a known maintenance action on that host and whether the timing aligns with a change window or scheduled job.
- Look for immediate follow-on activity from the same account or host, especially whoami/id, net, curl/wget, powershell, cmd, python, perl, or shell activity.
- If the child process is clearly unexpected and not tied to maintenance, treat as likely exploitation and escalate immediately.

Evidence to collect:
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, and FolderPath from the alert.
- The full process tree around the event, including the grandparent process if available.
- Any additional DeviceProcessEvents on the same host within the prior and subsequent 1-2 hours showing command execution, discovery, or download activity.
- PeopleSoft application logs and web access logs for the same time window to identify the inbound request that preceded the process spawn.
- Host patch level and whether CVE-2026-35273 mitigation or vendor guidance has already been applied.

Pivot points:
- DeviceProcessEvents for the same DeviceName and AccountName around the alert time to reconstruct the process tree.
- DeviceNetworkEvents for outbound connections from the host after the alert to identify command-and-control or download activity.
- DeviceFileEvents for new or modified files created by the spawned process.
- PeopleSoft web/application logs and reverse proxy or load balancer logs for the corresponding request source and URI.
- Asset inventory or CMDB to validate whether the host is a production PeopleSoft server and whether maintenance was expected.

Benign explanations:
- Legitimate PeopleSoft administrative scripts or scheduled maintenance may spawn cmd.exe, powershell.exe, sh, bash, python, perl, curl, or wget.
- Backup, monitoring, or patching agents running under the PeopleSoft service account can create similar child processes.
- Non-PeopleSoft Java applications on the same host can resemble this pattern if the host inventory is incomplete or the alert is not scoped correctly.

Escalation criteria:
- The child process is a shell or interpreter with an attacker-like command line, especially if it includes download, execution, or discovery commands.
- The event occurs on a production PeopleSoft host with no approved maintenance activity or change ticket.
- You find evidence of outbound connections, file drops, credential discovery, or additional suspicious child processes after the initial spawn.
- The host shows multiple process spawns from the PeopleSoft parent process or repeated alerts from the same server.

Containment actions:
- If exploitation is strongly suspected, isolate the PeopleSoft host from the network using your endpoint containment process.
- Preserve volatile evidence before rebooting or stopping services, including running processes, network connections, and relevant logs.
- Block or restrict external access to the PeopleSoft application until the vulnerability status is confirmed and the host is assessed.
- Coordinate with application owners before taking service-impacting actions, but do not delay containment if active compromise is evident.

Closure criteria:
- The host is confirmed to be a known PeopleSoft server and the process spawn is validated as an approved maintenance or administrative action.
- No suspicious follow-on activity is found in process, network, or file telemetry.
- Application and web logs show the event was tied to a legitimate request or internal admin workflow, not an external exploit attempt.
- The alert is documented with the approved maintenance context or tuning rationale and no further suspicious events occur.

---

## Detection 2: Ivanti Sentry RCE - Shell Interpreter Invocation from Sentry Web Service Process

### Detection Opportunity

Remote unauthenticated OS command injection on Ivanti Sentry resulting in root-level shell execution, indicative of exploitation of CVE-2026-10520

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: CVE-2026-10520 is an OS command injection vulnerability in Ivanti Sentry that allows a remote unauthenticated attacker to achieve RCE with root privileges. Exploitation is detectable via anomalous shell or interpreter invocations originating from the Sentry web service process in appliance syslog.

### Search Metadata

- CVEs: CVE-2026-10520, CVE-2026-10523
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Ivanti Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10520, CVE-2026-10523, T1190, T1059, Ivanti Sentry

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

Required telemetry:
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(7d)
| where ProcessName in ("sh", "bash", "dash", "zsh", "python", "python3", "perl", "wget", "curl")
| where SyslogMessage has_any (
    ";", "|", "`", "$(", "&&", "||", ">/",
    "chmod", "wget", "curl", "nc ", "ncat",
    "/bin/sh", "/bin/bash", "base64", "/dev/tcp"
)
| where Facility in ("daemon", "kern", "user", "syslog")
| project
    TimeGenerated,
    HostName,
    ProcessName,
    SyslogMessage,
    Facility,
    SeverityLevel
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Any Linux host forwarding syslog that legitimately invokes shell interpreters (cron jobs, monitoring agents, backup scripts) will match if HostName is not scoped.
- Sentry appliance health-check or update scripts that invoke wget or curl for legitimate software update operations.
- Security scanning tools running on or against the appliance that generate shell-like syslog entries.

Tuning notes:
- Add a HostName filter against a known list of Ivanti Sentry appliance hostnames before promoting to a scheduled rule.
- Consider removing single-character injection indicators (semicolons, pipes) from the has_any list and relying on multi-character patterns to reduce noise.
- Adjust Facility filter based on actual syslog facility values observed from the Sentry appliance in the environment.
- If the Sentry appliance emits structured audit log entries, consider parsing SyslogMessage with extract() or parse_json() for higher-fidelity field extraction.

Risks / caveats:
- The Syslog table in Sentinel is only populated if the Ivanti Sentry appliance is configured to forward syslog to the Log Analytics workspace via the Syslog connector or Azure Monitor Agent. If syslog forwarding is not configured, this query returns no results.
- Ivanti Sentry is a Linux-based appliance. Syslog verbosity must be set to capture process execution events (typically daemon or kern facility at info or debug level). Default appliance syslog configurations may not emit process-level execution events.
- Without HostName scoping to Ivanti Sentry appliances, this query will produce high false-positive volume from any Linux host forwarding syslog to Sentinel.
- Syslog-based process detection is inherently lower fidelity than endpoint telemetry; the ProcessName field reflects the syslog tag set by the process, which may not always match the actual binary name.

### Triage Runbook

First 15 minutes:
- Confirm the HostName is a known Ivanti Sentry appliance and not another Linux host forwarding syslog.
- Review the SyslogMessage for command-injection indicators such as /bin/sh, /bin/bash, base64, /dev/tcp, semicolons, pipes, backticks, or command chaining.
- Check whether the process invocation aligns with a known appliance update, health check, or maintenance task.
- Look for repeated shell launches, downloader activity, or suspicious commands in adjacent syslog entries from the same host.
- If the message suggests attacker-controlled shell execution, escalate as probable appliance compromise.

Evidence to collect:
- TimeGenerated, HostName, ProcessName, SyslogMessage, Facility, and SeverityLevel from the alert.
- Adjacent syslog entries from the same host before and after the alert to reconstruct the execution sequence.
- Any appliance audit or admin logs showing login, configuration changes, or service restarts around the same time.
- Network telemetry from the appliance, if available, showing outbound connections or downloads after the event.
- Firmware version, patch status, and whether the appliance is exposed to the internet.

Pivot points:
- Syslog for the same HostName and a wider time window to identify repeated shell or interpreter invocations.
- CommonSecurityLog or firewall logs for outbound connections from the appliance after the alert.
- Azure Monitor or network device logs for connections to suspicious external IPs or download destinations.
- Change management records for Ivanti Sentry maintenance, upgrades, or scripted operations.
- Asset inventory to confirm the appliance role, version, and exposure.

Benign explanations:
- Legitimate appliance maintenance or update scripts may invoke shell utilities or download tools.
- Health-check or backup jobs on the appliance can generate shell-like syslog entries.
- If HostName scoping is missing, the alert may reflect unrelated Linux hosts forwarding syslog.

Escalation criteria:
- The syslog shows clear command injection patterns or attacker-style shell execution on a production Sentry appliance.
- There is evidence of outbound connections, downloads, or repeated shell launches from the appliance.
- The appliance is internet-facing and no approved maintenance activity explains the event.
- Multiple alerts or correlated authentication anomalies occur on the same appliance.

Containment actions:
- If compromise is likely, isolate the Ivanti Sentry appliance from external access or place it behind emergency access controls.
- Preserve syslog and appliance logs before making disruptive changes.
- Disable or restrict administrative access paths until the appliance is assessed and patched.
- Coordinate with infrastructure owners to maintain service continuity while containing the threat.

Closure criteria:
- The HostName is confirmed as the correct appliance and the shell invocation is validated as a known-good maintenance action.
- No suspicious follow-on commands, downloads, or outbound connections are found.
- The appliance firmware and logging configuration are reviewed and documented.
- The alert is tuned or suppressed only after the benign pattern is verified on the specific appliance version.

---

## Detection 3: Ivanti Sentry Auth Bypass - Unauthenticated Admin Account Creation from External Source

### Detection Opportunity

Authentication bypass on Ivanti Sentry enabling unauthenticated creation of arbitrary administrative accounts from external IP addresses, indicative of exploitation of CVE-2026-10523

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: CVE-2026-10523 is an authentication bypass in Ivanti Sentry that allows a remote unauthenticated attacker to create arbitrary administrative accounts. This is a high-fidelity post-exploitation signal detectable in appliance audit logs forwarded to Sentinel, particularly when the source IP has no prior authenticated session.

### Search Metadata

- CVEs: CVE-2026-10520, CVE-2026-10523
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Ivanti Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10520, CVE-2026-10523, T1190, T1059, Ivanti Sentry

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog, CommonSecurityLog before scheduling.

Required telemetry:
- Syslog, CommonSecurityLog

### KQL

```kql
let lookback = 2h;
let authLookback = 2h;
let accountCreations = Syslog
| where TimeGenerated > ago(lookback)
| where SyslogMessage has_any (
    "account created", "admin account", "user added",
    "adduser", "useradd", "new administrator"
)
| extend SourceIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| where isnotempty(SourceIP)
| project CreationTime = TimeGenerated, HostName, SourceIP, SyslogMessage;
let priorAuths = CommonSecurityLog
| where TimeGenerated > ago(authLookback)
| where DeviceVendor has_any ("Ivanti", "MobileIron")
| where Activity has_any ("login", "authenticated", "auth success", "logon success")
| where isnotempty(SourceIP)
| project AuthTime = TimeGenerated, DeviceName, SourceIP;
accountCreations
| join kind=leftanti priorAuths on SourceIP
| project
    CreationTime,
    HostName,
    SourceIP,
    SyslogMessage
| order by CreationTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- If CEF forwarding is misconfigured or delayed, legitimate authenticated admin account creations will appear as unauthenticated, generating false positives.
- Administrative account creation performed via the Sentry management console from an IP that has not previously authenticated via the monitored interface will be flagged.
- Automated provisioning systems that create accounts without a preceding interactive authentication event visible in CommonSecurityLog.

Tuning notes:
- Validate the exact SyslogMessage strings emitted by the deployed Ivanti Sentry firmware version for account creation events and update the has_any keyword list accordingly.
- Confirm DeviceVendor values in CommonSecurityLog from the Sentry appliance and update the has_any filter to match observed values exactly.
- Add a HostName filter in the accountCreations subquery scoped to known Ivanti Sentry appliance hostnames to prevent false matches from other Linux hosts.
- If authentication events are not available in CommonSecurityLog, consider using Syslog authentication success messages as the priorAuths source, adjusting the table and field references accordingly.

Risks / caveats:
- CommonSecurityLog is only populated if the Ivanti Sentry appliance is configured to forward CEF-formatted logs to Sentinel. If CEF forwarding is not configured, the priorAuths dataset will be empty and the leftanti join will flag all account creation events as unauthenticated, producing 100% false positives.
- The DeviceVendor field value for Ivanti Sentry in CommonSecurityLog depends on the CEF header configured on the appliance. Values other than Ivanti or MobileIron will cause the authentication event lookup to return no results.
- Syslog account creation keyword matching (account created, admin account, user added, adduser, useradd, new administrator) is not based on documented Ivanti Sentry log format strings and may not match actual appliance log output for any given firmware version.
- The leftanti join on SourceIP alone may miss cases where NAT or proxy infrastructure causes the source IP in Syslog to differ from the source IP in CommonSecurityLog authentication events.

### Triage Runbook

First 15 minutes:
- Confirm the HostName is a known Ivanti Sentry appliance and verify the SourceIP is external and not a trusted admin network.
- Inspect the SyslogMessage to confirm it is an account creation event and identify the username, role, or privilege level if present.
- Check CommonSecurityLog or other authentication logs for any prior successful login from the same SourceIP or device.
- Determine whether the account was created during an approved provisioning or support activity.
- If the account is administrative and no prior authenticated session exists, escalate immediately as likely compromise.

Evidence to collect:
- CreationTime, HostName, SourceIP, and SyslogMessage from the alert.
- Any matching authentication or session logs from CommonSecurityLog or appliance logs for the same SourceIP and time window.
- The created account name, assigned role, and whether MFA or other controls were bypassed.
- Appliance firmware version, patch level, and exposure status.
- Any subsequent logins, configuration changes, or privilege changes made by the new account.

Pivot points:
- CommonSecurityLog for the SourceIP and HostName to identify prior or subsequent authentication activity.
- Syslog for the same HostName to find additional account creation, privilege change, or admin activity.
- Firewall or proxy logs to validate whether the SourceIP is external, internal, or NATed.
- Change management or IAM records to verify whether the account creation was authorized.
- Appliance audit logs to identify actions performed by the new account after creation.

Benign explanations:
- A legitimate administrator may have created an account from a network path that does not generate a prior authentication event in the monitored logs.
- CEF or syslog forwarding gaps can make a valid authenticated session appear unauthenticated.
- Automated provisioning or support workflows may create accounts without a visible interactive login in the expected log source.

Escalation criteria:
- The created account has administrative privileges and there is no approved change or support ticket.
- The SourceIP is external, unfamiliar, or associated with other suspicious activity.
- You find evidence of subsequent logins, configuration changes, or additional privilege escalation by the new account.
- Authentication logs are absent or inconsistent in a way that suggests logging gaps during a real attack.

Containment actions:
- Disable or remove the newly created account if it is not immediately validated as legitimate.
- Restrict external access to the Ivanti Sentry management interface while investigating.
- Preserve appliance logs and authentication telemetry before making changes.
- If active misuse is suspected, isolate the appliance or place it into emergency maintenance mode with owner approval.

Closure criteria:
- The account creation is matched to an approved administrative or provisioning activity with supporting records.
- Authentication and audit logs show a legitimate source and no unauthorized follow-on actions.
- The created account is validated as expected, or it has been removed if unauthorized.
- Logging gaps are understood and documented, and the detection is tuned only after validation on the deployed firmware.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- PeopleSoft RCE - Anomalous Child Process Spawned by PeopleSoft Application Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.
- Ivanti Sentry RCE - Shell Interpreter Invocation from Sentry Web Service Process: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.
- Ivanti Sentry Auth Bypass - Unauthenticated Admin Account Creation from External Source: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog, CommonSecurityLog before scheduling.

Shared-table notes:
- Syslog: shared by Ivanti Sentry RCE - Shell Interpreter Invocation from Sentry Web Service Process; Ivanti Sentry Auth Bypass - Unauthenticated Admin Account Creation from External Source

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: PeopleSoft RCE - Anomalous Child Process Spawned by PeopleSoft Application Process; Ivanti Sentry RCE - Shell Interpreter Invocation from Sentry Web Service Process; Ivanti Sentry Auth Bypass - Unauthenticated Admin Account Creation from External Source.

### Hunting Agenda and Promotion Criteria

- PeopleSoft RCE - Anomalous Child Process Spawned by PeopleSoft Application Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Ivanti Sentry RCE - Shell Interpreter Invocation from Sentry Web Service Process: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling..
- Ivanti Sentry Auth Bypass - Unauthenticated Admin Account Creation from External Source: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog, CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
