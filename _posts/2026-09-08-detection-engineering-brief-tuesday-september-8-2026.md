---
layout: post
title: "Detection Engineering Brief - Tuesday, September 8, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-08
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1059
  - Linux
  - crond
  - agetty
  - atd
  - sshd
  - polkitd
  - ted backdoor
  - curlRAT
  - HAProxy
  - T1190
  - MikroTik
  - email
  - T1003.008
  - T1003
  - T1136.001
  - T1136
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 0 hunting-only, 4 require environment mapping, and 1 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: T1059, Linux, crond, agetty, atd, sshd, polkitd, ted backdoor, curlRAT, HAProxy, T1190, MikroTik, email, T1003.008, T1003, T1136.001, T1136.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: DPRK Trojanized System Daemon Spawning Unexpected Child Process; HAProxy Process Spawning Shell Interpreter on Linux Host; Unexpected Access to Linux Credential Files by Non-Standard Process; MikroTik Device New Account Creation Following SSH Session.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: DPRK Trojanized System Daemon Spawning Unexpected Child Process

### Detection Opportunity

Trojanized versions of crond, agetty, atd, sshd, or polkitd spawning unexpected child processes, consistent with ted backdoor or curlRAT persistence implants replacing legitimate Linux service binaries.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: DPRK-linked actors replaced legitimate Linux service binaries (crond, agetty, atd, sshd, polkitd) with trojanized versions to achieve persistence and surveillance. These daemons spawning shells or unexpected child processes is the primary behavioral signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1003.008, T1003
- Products: crond, agetty, atd, sshd, polkitd
- Platforms: Linux
- Malware: ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, Linux, crond, agetty, atd, sshd, polkitd, ted backdoor, curlRAT, T1003.008, T1003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: credential access: T1003 OS Credential Dumping/ T1003.008 /etc/passwd and /etc/shadow (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(1d)
| where Facility in ("kern", "daemon", "auth", "cron")
| where SyslogMessage has_any ("sshd", "crond", "atd", "agetty", "polkitd")
| where SyslogMessage has_any ("bash", "/bin/sh", "/bin/dash", "/bin/zsh", "curl", "wget", "ncat", "python", "perl")
| extend SuspectDaemon = extract(@"comm=\"?(sshd|crond|atd|agetty|polkitd)\"?", 1, SyslogMessage)
| extend SuspectChild = extract(@"(?:exe|comm)=\"?([^\s\"]*(?:bash|/sh|/dash|/zsh|curl|wget|ncat|python|perl)[^\s\"]*)\"?", 1, SyslogMessage)
| extend ChildPath = extract(@"exe=\"([^\"]+)\"", 1, SyslogMessage)
| where isnotempty(SuspectDaemon) and isnotempty(SuspectChild)
| where SuspectChild !has "sshd"
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleMessage = any(SyslogMessage)
    by HostName, Facility, SuspectDaemon, SuspectChild, ChildPath
| project FirstSeen, LastSeen, HostName, Facility, SuspectDaemon, SuspectChild, ChildPath, EventCount, SampleMessage
| sort by LastSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate cron jobs that invoke bash or sh as part of scheduled automation.
- SSH multiplexing or ProxyCommand configurations that cause sshd to spawn shell-like processes.
- System management tools (Ansible, Puppet) that use sshd as a transport and spawn Python or Perl interpreters.

**Tuning notes:**
- After initial deployment, run the summarize output for 7 days and identify recurring SuspectDaemon/SuspectChild pairs that are legitimate; add them as exclusion conditions.
- If HostName values for Linux servers are known, add a filter such as 'HostName in (known_linux_servers)' to reduce scope.
- Consider promoting to a watchlist-driven exclusion model for SuspectChild values that are confirmed benign in the environment.

**Risks / caveats:**
- Parent-child process relationship data in SyslogMessage is only available if auditd is configured with EXECVE/SYSCALL rules and audispd or equivalent forwards structured audit records to syslog. Standard rsyslog/syslog-ng daemon logs do not contain this information.
- The Syslog table in Sentinel does not have a native ProcessName field populated from auditd records; ProcessName reflects the syslog tag, not the audited process.
- Lookback window set to 1d for scheduled rule cadence; adjust to match rule run frequency to avoid gaps or duplicate alerts.
- Regex extraction depends on auditd log format (comm= and exe= fields); if a different audit framework or log format is used, extractions will return empty and the where isnotempty filter will suppress all results.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a Linux server expected to run the flagged daemon and note whether the child process is a shell, downloader, or interpreter.
- Check whether the child process path and parent daemon path are consistent with a legitimate service workflow or look like a replaced binary in an unusual location.
- Review the surrounding SyslogMessage entries for repeated spawns, command-line fragments, or auditd evidence of execve from the same parent process.
- Identify whether the host is internet-facing, a jump host, or a high-value server, and whether any other alerts fired on the same host around the same time.

**Evidence to collect:**
- HostName, FirstSeen, LastSeen, SuspectDaemon, SuspectChild, ChildPath, EventCount, and SampleMessage from the alert.
- The full SyslogMessage for the matching event and several minutes of logs before and after the alert.
- File integrity or package verification evidence for the daemon binary path, including hash, package owner, and last modification time if available.
- Any recent authentication, privilege escalation, or outbound connection logs from the same host.

**Pivot points:**
- Syslog for the same HostName and SuspectDaemon over the last 24 hours to find repeated child spawns.
- Syslog for the same HostName with child process names such as bash, sh, curl, wget, python, perl, or ncat.
- Any endpoint or host inventory table available in the tenant to confirm the expected daemon version and package source.
- If available, process or audit telemetry for the same host to validate whether the daemon binary path changed recently.

**Benign explanations:**
- Cron or at jobs may legitimately spawn shells or scripts on hosts that use those services heavily.
- sshd can spawn helper processes for legitimate administration, multiplexing, or automation tools.
- System management tools such as Ansible, Puppet, or backup scripts may create shell-like child processes through service accounts.

**Escalation criteria:**
- The daemon binary path is unexpected, unsigned, or differs from the package-managed version.
- The child process is a shell, downloader, or interpreter and is not explained by a known maintenance task.
- Multiple hosts show the same daemon-to-child pattern, or the host also shows credential access, persistence, or outbound beaconing.
- The host is a critical server and the event cannot be tied to a documented change or approved automation.

**Containment actions:**
- If the child process is clearly malicious or the daemon binary appears trojanized, isolate the host from the network using your standard endpoint containment process.
- Disable or stop the affected service only if doing so will not cause unacceptable business impact and after coordinating with the system owner.
- Preserve volatile evidence and collect the suspicious binary for forensic analysis before remediation.
- Block any confirmed malicious outbound destinations if they are identified during triage.

**Closure criteria:**
- The child process is explained by approved automation or a documented service workflow.
- Binary/package verification confirms the daemon is legitimate and unchanged.
- No additional suspicious child processes, credential access, or persistence indicators are found on the host.
- A change ticket or maintenance record explains the activity and matches the alert timing.

<br/>
---
<br/>

## Detection 2: HAProxy Process Spawning Shell Interpreter on Linux Host

### Detection Opportunity

HAProxy process spawning a shell interpreter, indicating remote command execution through a compromised HAProxy instance as reported in DPRK-linked intrusions targeting South Korean infrastructure.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: Compromised HAProxy instances were used by DPRK-linked actors to execute remote commands on servers. HAProxy spawning shell processes is anomalous and directly observed in this campaign.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1003.008, T1003
- Products: HAProxy
- Platforms: Linux
- Malware: ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, HAProxy, Linux, ted backdoor, curlRAT, T1003.008, T1003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: credential access: T1003 OS Credential Dumping/ T1003.008 /etc/passwd and /etc/shadow (high)

### Deployment Gates

- Without auditd EXECVE telemetry forwarded to Syslog, this query will only match if HAProxy itself logs shell invocation strings in its own log output, which is not standard behavior.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(14d)
| where ProcessName has "haproxy"
    or SyslogMessage has "haproxy"
| where SyslogMessage matches regex @"exe=\"/bin/(bash|sh|dash|zsh)\""
    or SyslogMessage has "/bin/bash"
    or SyslogMessage has "/bin/sh"
    or SyslogMessage has "/bin/dash"
    or SyslogMessage has "/bin/zsh"
| extend ChildExePath = extract(@"exe=\"([^\"]+)\"", 1, SyslogMessage)
| project TimeGenerated, HostName, ProcessName, SeverityLevel, ChildExePath, SyslogMessage
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- HAProxy managed via shell-based init systems (SysV init scripts) may generate shell-adjacent log messages during service start/stop.
- Log aggregation from hosts where haproxy and shell processes run concurrently may produce coincidental message proximity without a true parent-child relationship.

**Tuning notes:**
- Scope HostName to known HAProxy servers using a filter such as 'HostName in (haproxy_host_list)' once host inventory is available.
- If auditd is deployed, add a filter for 'SyslogMessage has "ppid"' and extract the parent PID to correlate with haproxy process PID for stronger parent-child validation.
- Review matches for HAProxy health-check scripts that may legitimately invoke shell commands and add exclusions based on argument patterns.

**Risks / caveats:**
- HAProxy does not natively log child process spawning to syslog; this telemetry requires auditd EXECVE rules with parent process tracking (ppid) forwarded to Syslog.
- ProcessName in the Syslog table reflects the syslog program tag, not the audited parent process; relying on ProcessName to identify haproxy as a parent is unreliable without auditd.
- Without auditd EXECVE telemetry forwarded to Syslog, this query will only match if HAProxy itself logs shell invocation strings in its own log output, which is not standard behavior.
- The 14-day lookback is appropriate for hunting but should be reduced to 1d if promoted to a scheduled rule.

### Triage Runbook

**First 15 minutes:**
- Confirm the host actually runs HAProxy and whether the alert references a real process lineage or only a log message containing haproxy and a shell path.
- Check whether the shell spawn occurred during service start, restart, health-check execution, or a deployment window.
- Review nearby logs for command execution, unusual child processes, or signs that HAProxy was modified or replaced.
- Determine whether the host is a load balancer, reverse proxy, or internet-facing edge system with elevated exposure.

**Evidence to collect:**
- HostName, ProcessName, ChildExePath, TimeGenerated, and the full SyslogMessage from the alert.
- HAProxy service status, version, package ownership, and recent configuration changes if available.
- Any auditd or process execution telemetry showing parent PID, child PID, and command line for the suspected spawn.
- Recent authentication events, config file edits, and outbound connections from the same host.

**Pivot points:**
- Syslog for the same HostName and ProcessName or SyslogMessage containing haproxy over the last 24 hours.
- Syslog for shell interpreters and common downloaders on the same host, especially bash, sh, dash, zsh, curl, wget, python, and perl.
- Any available process execution or audit table to validate parent-child lineage and command line arguments.
- Configuration or change-management data for HAProxy deployments and restarts around the alert time.

**Benign explanations:**
- Service start/stop scripts may invoke shell commands during deployment or restart.
- Health-check wrappers or orchestration tooling may generate shell-related log entries on HAProxy hosts.
- The alert may be triggered by log text proximity rather than a true parent-child process relationship.

**Escalation criteria:**
- There is confirmed process lineage showing HAProxy spawning a shell or downloader outside an approved maintenance window.
- The HAProxy binary, config, or service unit has been altered unexpectedly.
- The host also shows credential access, persistence, or suspicious outbound traffic.
- Multiple HAProxy hosts show the same behavior, suggesting a broader compromise.

**Containment actions:**
- If confirmed malicious, isolate the host or remove it from load-balancing rotation to prevent further abuse.
- Disable the affected HAProxy instance only after coordinating with operations to avoid service outage.
- Preserve logs, configs, and binaries for forensic review before remediation.
- Block any confirmed malicious outbound destinations identified during investigation.

**Closure criteria:**
- The shell activity is tied to a documented deployment, restart, or approved automation.
- No evidence of unauthorized command execution, config tampering, or persistence is found.
- Process lineage cannot be confirmed and the alert is determined to be a weak log-text match only.
- The host is verified clean after review of adjacent logs and change records.

<br/>
---
<br/>

## Detection 3: Unexpected Access to Linux Credential Files by Non-Standard Process

### Detection Opportunity

Processes accessing /etc/shadow, /etc/passwd, or SSH private key directories on Linux hosts, consistent with credential harvesting activity observed in DPRK-linked intrusions.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: DPRK-linked actors performed credential harvesting on compromised Linux systems. Access to /etc/shadow, /etc/passwd, or SSH key material by unexpected processes is the detectable artifact of this activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1003.008, T1003
- Products: Not specified
- Platforms: Linux
- Malware: ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, Linux, ted backdoor, curlRAT, T1003.008, T1003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: credential access: T1003 OS Credential Dumping/ T1003.008 /etc/passwd and /etc/shadow (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(14d)
| where SyslogMessage matches regex @"(?:name|path)=\"?(?:/etc/shadow|/etc/passwd|/root/\.ssh/[^\s\"]*|/home/[^/]+/\.ssh/[^\s\"]*)\"?"
| where not(SyslogMessage matches regex @"\b(?:sshd|passwd|useradd|usermod|chage|pam_unix|nscd|sudo|cron|systemd|login|gdm|sssd|nsswitch)\b")
| extend AccessingProcess = extract(@"comm=\"?([^\s\"]+)\"?", 1, SyslogMessage)
| extend AccessedFile = extract(@"(?:name|path)=\"?(/etc/shadow|/etc/passwd|/root/\.ssh/[^\s\"]*|/home/[^/]+/\.ssh/[^\s\"]*)\"?", 1, SyslogMessage)
| where isnotempty(AccessedFile)
| summarize
    AccessCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleMessage = any(SyslogMessage)
    by HostName, AccessingProcess, AccessedFile
| where isnotempty(AccessingProcess)
| project FirstSeen, LastSeen, HostName, AccessingProcess, AccessedFile, AccessCount, SampleMessage
| sort by LastSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- System backup agents (Bacula, Amanda, rsync) that read /etc/passwd for UID mapping.
- Configuration management tools (Ansible, Chef, Puppet) that read credential files during system audits.
- LDAP/SSSD daemons that access /etc/passwd as part of name service switching.
- Security scanning tools (Lynis, OpenSCAP) that read these files during compliance checks.

**Tuning notes:**
- Run the query without the exclusion filter first to enumerate all processes accessing credential files in the environment, then build the exclusion list from that baseline.
- Add 'HostName in (high_value_server_list)' to scope the query to authentication servers, jump hosts, or servers known to be targeted.
- Consider splitting into two separate queries: one for /etc/shadow and /etc/passwd (higher severity) and one for .ssh directories (medium severity) to allow independent tuning.

**Risks / caveats:**
- File access events for /etc/shadow, /etc/passwd, and .ssh directories are only present in Syslog if auditd is configured with explicit watch rules (-w /etc/shadow -p rwa, -w /etc/passwd -p rwa, -w /root/.ssh -p rwa) and audit records are forwarded to syslog via audispd or equivalent.
- Without auditd file watch rules, this query will return zero results regardless of actual credential file access activity.
- The exclusion regex must be expanded to cover all legitimate credential-accessing processes in the target environment before this query produces actionable results without excessive false positives.
- auditd must be configured with file watch rules for /etc/shadow, /etc/passwd, /root/.ssh, and /home/*/.ssh before this query will return any results.

### Triage Runbook

**First 15 minutes:**
- Identify the accessing process and compare it to the expected allowlist for the host role, such as sshd, passwd, useradd, sudo, or backup tooling.
- Check whether the accessed file is /etc/shadow, /etc/passwd, or an SSH private key path and whether the access pattern is repeated or broad.
- Review whether the access occurred during a known maintenance, backup, or compliance scan window.
- Look for companion activity such as shell spawning, privilege escalation, or outbound connections from the same host.

**Evidence to collect:**
- HostName, AccessingProcess, AccessedFile, AccessCount, FirstSeen, LastSeen, and SampleMessage from the alert.
- The full auditd or SyslogMessage records showing the file path and process identity.
- Recent authentication, sudo, user management, and package installation logs from the same host.
- Any file integrity or package verification evidence for the accessing process binary.

**Pivot points:**
- Syslog for the same HostName and AccessingProcess to see whether the process also spawned shells or downloaders.
- Syslog for the same host and file paths to determine whether access is isolated or repeated across multiple files.
- Any available endpoint process or audit table to validate command line, parent process, and user context.
- Change-management or backup job records for the host during the alert window.

**Benign explanations:**
- Backup agents, configuration management tools, and compliance scanners may read credential files for legitimate reasons.
- LDAP, SSSD, or NSS-related services may access /etc/passwd as part of normal identity resolution.
- Administrative workflows such as user creation or password changes can legitimately touch these files.

**Escalation criteria:**
- The accessing process is not approved for credential file access on this host.
- The process is running from an unusual path, temporary directory, or user-writable location.
- The access is followed by shell execution, privilege escalation, or outbound network activity.
- The host is a high-value system and the access cannot be tied to a documented maintenance or backup task.

**Containment actions:**
- If unauthorized credential harvesting is likely, isolate the host using standard containment procedures.
- Disable the suspicious process or service only if necessary and coordinated with the system owner.
- Preserve the accessed files, process binary, and relevant logs for forensic analysis.
- Reset exposed credentials if there is evidence that secrets or SSH keys were accessed.

**Closure criteria:**
- The process is a known and approved credential-accessing tool for that host role.
- The access aligns with a documented backup, audit, or administration activity.
- No additional suspicious process behavior or lateral movement indicators are found.
- The event is attributable to expected system behavior after validation with the host owner.

<br/>
---
<br/>

## Detection 4: MikroTik Device New Account Creation Following SSH Session

### Detection Opportunity

New user accounts created on MikroTik network devices following SSH sessions, consistent with post-exploitation persistence after SSH authentication bypass exploitation.

### Intelligence Context

- SANS ISC: Critical MikroTik Vulnerability - Patch Now, (Sun, Sep 6th) — [https://isc.sans.edu/diary/rss/33314](https://isc.sans.edu/diary/rss/33314)
  - Context: Attackers exploiting an SSH authentication bypass on MikroTik devices were observed adding new accounts to maintain persistent access. The compound behavior of SSH access followed by account creation is the high-fidelity persistence signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1136.001, T1136
- Products: MikroTik
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, MikroTik, T1136.001, T1136

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: initial access: T1190 Exploit Public-Facing Application (medium); persistence: T1136 Create Account/ T1136.001 Local Account (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
let SSHSessions = Syslog
| where TimeGenerated > ago(1d)
| where SyslogMessage has_any ("logged in", "login from", "ssh login")
| where SyslogMessage has_any ("mikrotik", "RouterOS")
    or ProcessName has_any ("sshd", "ssh")
| extend SSHSourceIP = extract(@"(?:from|login from)\s+([\d\.]+|[\da-fA-F:]+)", 1, SyslogMessage)
| project SSHTime = TimeGenerated, HostName, SSHSourceIP, SSHMessage = SyslogMessage;
let AccountCreation = Syslog
| where TimeGenerated > ago(1d)
| where SyslogMessage matches regex @"(?i)(user add|added user|account created|/ip/user/add|user.*added by|new user)"
| extend CreatedUser = extract(@"(?i)user[:\s]+([\w\-\.]+)", 1, SyslogMessage)
| project AccountTime = TimeGenerated, HostName, CreatedUser, AccountMessage = SyslogMessage;
SSHSessions
| join kind=inner AccountCreation on HostName
| where AccountTime >= SSHTime and AccountTime <= SSHTime + 30m
| project SSHTime, AccountTime, HostName, SSHSourceIP, CreatedUser, SSHMessage, AccountMessage
| sort by SSHTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative SSH sessions followed by planned account provisioning during maintenance windows.
- Automated configuration management systems that SSH to MikroTik devices and create service accounts as part of standard provisioning.

**Tuning notes:**
- Add a filter on SSHSourceIP to exclude known management IP ranges to reduce false positives from legitimate administrative access.
- Reduce the correlation window from 30m to 5m if automated exploitation is suspected, as human operators are unlikely to create accounts within seconds.
- Validate MikroTik syslog presence with: Syslog → where SyslogMessage has_any ('mikrotik', 'RouterOS') → summarize count() by HostName, bin(TimeGenerated, 1h) before deploying as a scheduled rule.

**Risks / caveats:**
- MikroTik syslog forwarding must be explicitly configured on each device with the appropriate log topics (system, info, account, ssh) enabled; without this, neither SSH session nor account creation events will appear in Syslog.
- MikroTik RouterOS syslog messages do not follow a standardized format; the regex patterns for SSH session detection and account creation must be validated against actual MikroTik log output from the specific RouterOS version in use.
- HostName in the Syslog table reflects the syslog source address or configured hostname; if MikroTik devices do not set a system identity, HostName may be an IP address, which must be accounted for in the join.
- MikroTik RouterOS syslog message format varies by firmware version; the regex patterns for SSH login and account creation must be tested against actual log samples from the deployed RouterOS version.

### Triage Runbook

**First 15 minutes:**
- Verify the device identity, firmware version, and whether the SSH source IP is a known management address.
- Check whether the account creation happened shortly after the SSH session and whether the new account name is expected.
- Review the device’s recent configuration and account logs for additional changes such as firewall edits, scripts, or scheduled tasks.
- Determine whether the device is internet-facing or part of a critical network path.

**Evidence to collect:**
- SSHTime, AccountTime, HostName, SSHSourceIP, CreatedUser, SSHMessage, and AccountMessage from the alert.
- The device’s current user list, privilege levels, and any recent configuration export if available.
- RouterOS version, system identity, and management access configuration.
- Any logs showing login failures, successful logins, or other administrative changes around the same time.

**Pivot points:**
- Syslog for the same HostName over the last 24 hours to find additional login, account, or configuration events.
- Syslog for the SSHSourceIP across other network devices to see whether the source is targeting multiple assets.
- Any network or firewall logs showing management access to the MikroTik device before and after the alert.
- If available, configuration management or backup records to compare the current device state with a known-good baseline.

**Benign explanations:**
- A legitimate administrator may SSH in and create an account during planned provisioning or maintenance.
- Automated configuration management may create service accounts as part of device onboarding.
- The SSH source may be a trusted jump host or management subnet if the environment uses centralized administration.

**Escalation criteria:**
- The SSH source IP is unknown, external, or not part of an approved management range.
- The created account is unexpected, has elevated privileges, or persists after review.
- Additional unauthorized configuration changes are present on the device.
- Multiple MikroTik devices show the same pattern, suggesting a broader campaign.

**Containment actions:**
- If compromise is likely, remove the device from remote management exposure or restrict management access to trusted sources.
- Disable the unauthorized account and rotate any credentials that may have been exposed.
- Preserve a configuration export and logs before making changes if operationally safe.
- Coordinate with network operations before rebooting or resetting the device.

**Closure criteria:**
- The SSH session and account creation are tied to a documented change or approved provisioning activity.
- The created account is verified as legitimate and expected.
- No other unauthorized configuration changes are found on the device.
- The source IP is confirmed to be a trusted management system or jump host.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- DPRK Trojanized System Daemon Spawning Unexpected Child Process: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.
- HAProxy Process Spawning Shell Interpreter on Linux Host: Without auditd EXECVE telemetry forwarded to Syslog, this query will only match if HAProxy itself logs shell invocation strings in its own log output, which is not standard behavior.
- Unexpected Access to Linux Credential Files by Non-Standard Process: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.
- MikroTik Device New Account Creation Following SSH Session: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Shared-table notes:**
- Syslog: shared by DPRK Trojanized System Daemon Spawning Unexpected Child Process; HAProxy Process Spawning Shell Interpreter on Linux Host; Unexpected Access to Linux Credential Files by Non-Standard Process; MikroTik Device New Account Creation Following SSH Session

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: DPRK Trojanized System Daemon Spawning Unexpected Child Process; HAProxy Process Spawning Shell Interpreter on Linux Host; Unexpected Access to Linux Credential Files by Non-Standard Process; MikroTik Device New Account Creation Following SSH Session.

### Hunting Agenda and Promotion Criteria

- DPRK Trojanized System Daemon Spawning Unexpected Child Process: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- HAProxy Process Spawning Shell Interpreter on Linux Host: Without auditd EXECVE telemetry forwarded to Syslog, this query will only match if HAProxy itself logs shell invocation strings in its own log output, which is not standard behavior..
- Unexpected Access to Linux Credential Files by Non-Standard Process: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- MikroTik Device New Account Creation Following SSH Session: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
