---
layout: post
title: "Detection Engineering Brief - Monday, September 7, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-07
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1059
  - Linux
  - Ted backdoor
  - curlRAT
  - crond
  - agetty
  - atd
  - sshd
  - polkitd
  - HAProxy
  - T1078
  - MikroTik
  - email
  - T1071
  - T1136
  - T1027
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 1 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: T1059, Linux, Ted backdoor, curlRAT, crond, agetty, atd, sshd, polkitd, HAProxy, T1078, MikroTik, email, T1071, T1136, T1027.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Shell Spawned by Trojanized Linux Daemon with Outbound Network Connection; Unauthorized Account Creation on MikroTik Device Post-Exploitation; Invisible Unicode Tag Characters Embedded in Email Subject or Metadata.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Trojanized Linux System Daemon Binary Modification Detected

### Detection Opportunity

Trojanized versions of crond, agetty, atd, sshd, and polkitd replaced legitimate system binaries on compromised Linux servers as part of DPRK-linked backdoor deployment.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: DPRK-linked actors replaced legitimate Linux system daemons (crond, agetty, atd, sshd, polkitd) with trojanized binaries to establish persistent backdoor access on compromised servers in South Korean media and automotive sectors.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1071
- Products: crond, agetty, atd, sshd, polkitd
- Platforms: Linux
- Malware: Ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, Linux, Ted backdoor, curlRAT, crond, agetty, atd, sshd, polkitd, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let TargetDaemons = dynamic(["crond", "agetty", "atd", "sshd", "polkitd"]);
let PackageManagers = dynamic(["apt", "apt-get", "yum", "rpm", "dpkg", "dnf", "zypper", "snap", "flatpak"]);
let FileModEvents = DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| where FileName in~ (TargetDaemons)
| where FolderPath startswith_any ("/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/")
| where not(InitiatingProcessFileName has_any (PackageManagers))
| project
    DeviceId,
    DeviceName,
    ModifyTime = Timestamp,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ActionType;
let PostExecEvents = DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (TargetDaemons)
| project
    DeviceId,
    ExecTime = Timestamp,
    ExecFileName = FileName,
    ProcessCommandLine,
    AccountName;
FileModEvents
| join kind=inner PostExecEvents on DeviceId
| where ExecFileName =~ FileName
| where ExecTime between (ModifyTime .. (ModifyTime + 1h))
| project
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ActionType,
    ModifyTime,
    ExecTime,
    ProcessCommandLine,
    AccountName
| sort by ModifyTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Manual sysadmin binary replacements performed outside a package manager (e.g., copying a patched sshd binary directly) will trigger the rule.
- Configuration management tools such as Ansible, Chef, or Puppet that write binaries directly without invoking a package manager will generate alerts.
- Systemd service restarts of sshd or crond shortly after any legitimate binary update will satisfy the post-execution correlation.

**Tuning notes:**
- Add snap and flatpak to PackageManagers if those package systems are in use.
- If configuration management tools (Ansible, Puppet, Chef) write binaries directly, add their agent process names to the PackageManagers exclusion list.
- Consider adding a SHA256 allowlist join against known-good binary hashes from a trusted baseline to reduce FP volume.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileCreated' and 'FileModified' are supported on MDE for Linux but require MDE Linux agent version 101.45.00 or later with file monitoring enabled; confirm agent version and auditd/fanotify configuration on enrolled hosts.
- SHA256 field in DeviceFileEvents may be empty for file modification events on Linux depending on agent configuration; hash-based downstream triage may be incomplete.
- The 24-hour lookback window means detections are delayed up to 24 hours from the modification event; reduce to 1-4 hours for near-real-time alerting.
- The 1-hour post-modification execution window may miss cases where the trojanized daemon is not restarted immediately; extend if daemon restart is deferred.

### Triage Runbook

**First 15 minutes:**
- Verify the host, daemon name, file path, timestamp, and initiating process to confirm the write was not performed by a known package manager or approved configuration tool.
- Check whether the modified binary was subsequently executed and whether the execution account or service context is expected for that host.
- Review recent authentication, privilege escalation, and process activity on the host for signs of backdoor deployment, shell spawning, or lateral movement.
- If the binary hash is available, compare it to a trusted baseline or package source to determine whether the file is trojanized.

**Evidence to collect:**
- DeviceName, FileName, FolderPath, SHA256, ActionType, ModifyTime, ExecTime, ProcessCommandLine, AccountName.
- InitiatingProcessFileName and InitiatingProcessCommandLine for the writer process, including parent process context if available.
- Recent DeviceProcessEvents for the same host covering daemon restarts, shell launches, and suspicious child processes.
- Recent DeviceNetworkEvents for the host to identify outbound connections after the binary modification.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and FileName to find prior or repeated modifications.
- DeviceProcessEvents for the same DeviceId to identify the first execution of the modified daemon and any spawned shells.
- DeviceNetworkEvents for the same DeviceId to look for outbound connections after the modification window.
- If available, compare the SHA256 against a known-good software inventory or package baseline.

**Benign explanations:**
- A sysadmin may have manually replaced a daemon binary during emergency patching or troubleshooting.
- Configuration management tools such as Ansible, Chef, or Puppet may write binaries directly without invoking a package manager.
- A legitimate package update or rollback may have touched the same file path, especially if the package manager exclusion list is incomplete.

**Escalation criteria:**
- The writer process is unknown, interactive, or not tied to an approved change window.
- The modified daemon is executed shortly after the write and spawns a shell or makes outbound connections.
- The file hash does not match the trusted baseline or the binary is located in a canonical system path but differs from the expected package version.
- Multiple core daemons on the same host are modified, or the host shows additional persistence or lateral movement activity.

**Containment actions:**
- Isolate the host from the network if the modified daemon is confirmed malicious or if the host is actively beaconing.
- Preserve the modified binary and relevant logs before rebooting or replacing files.
- Disable or rotate credentials used on the host if compromise is confirmed, especially privileged accounts.
- Coordinate with Linux operations before restoring binaries to avoid overwriting forensic evidence.

**Closure criteria:**
- The file modification is attributed to a verified change ticket or approved automation job.
- The binary hash matches the trusted baseline and the execution context is consistent with normal administration.
- No additional suspicious process, network, or authentication activity is found on the host during the relevant window.
- Any malicious binary has been removed or restored from a trusted source and the host is either reimaged or validated clean.

<br/>
---
<br/>

## Detection 2: Shell Spawned by Trojanized Linux Daemon with Outbound Network Connection

### Detection Opportunity

Backdoor-spawned shell processes initiated from trojanized Linux system daemons (crond, sshd) with concurrent outbound network connections, indicating remote command execution capability.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: Trojanized Linux daemons enabled threat actors to execute remote commands on compromised servers. Detection targets the parent-child process chain where a system daemon spawns an interactive shell, correlated with an outbound network connection from the same device.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1071
- Products: crond, sshd, HAProxy
- Platforms: Linux
- Malware: Ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, HAProxy, Linux, Ted backdoor, curlRAT, crond, sshd, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let TrojanizedDaemons = dynamic(["crond", "agetty", "atd", "sshd", "polkitd"]);
let ShellBinaries = dynamic(["bash", "sh", "dash", "zsh", "python", "python3", "perl"]);
let SuspectShells = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (TrojanizedDaemons)
| where FileName in~ (ShellBinaries)
| project
    DeviceId,
    DeviceName,
    ShellSpawnTime = Timestamp,
    ParentDaemon = InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ShellProcess = FileName,
    ProcessCommandLine,
    AccountName;
let OutboundConns = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where isnotempty(RemoteIP)
| project
    DeviceId,
    ConnTime = Timestamp,
    RemoteIP,
    RemotePort,
    RemoteUrl;
SuspectShells
| join kind=inner OutboundConns on DeviceId
| where ConnTime between (ShellSpawnTime .. (ShellSpawnTime + 5m))
| project
    DeviceName,
    ParentDaemon,
    InitiatingProcessCommandLine,
    ShellProcess,
    ProcessCommandLine,
    AccountName,
    ShellSpawnTime,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    ConnTime
| sort by ShellSpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Every interactive SSH login where the user runs any command that initiates an outbound connection will match when sshd is in the daemon list.
- Cron jobs that invoke shell scripts with outbound curl or wget calls will match for crond.
- Automated monitoring agents or backup scripts launched by atd or crond that make outbound connections will match.

**Tuning notes:**
- To reduce sshd noise, remove sshd from TrojanizedDaemons and run a separate lower-priority query focused on crond, atd, agetty, and polkitd.
- Add a lookup against known administrative account names to suppress authorized SSH sessions.
- Consider adding a count threshold: only alert if the same device spawns more than N shells from a daemon within the correlation window.

**Risks / caveats:**
- DeviceNetworkEvents on Linux via MDE requires the network monitoring component to be active; outbound connection telemetry may be incomplete if the agent is not configured with full network visibility.
- InitiatingProcessFileName in DeviceProcessEvents reflects the immediate parent process name only; multi-hop process chains (daemon -> intermediate process -> shell) will not be captured by this single-level parent check.
- ipv4_is_private() does not handle IPv6 private ranges; if the environment uses IPv6 internally, add an explicit IPv6 private range filter.
- The 7-day lookback is appropriate for hunting but will produce a large result set in active environments; reduce to 24-48 hours for iterative review.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent daemon, shell process, account, and remote IP/URL to determine whether the connection is expected administrative activity or malicious remote execution.
- Check whether the parent daemon is one of the known trojanized binaries on the host and whether it was recently modified.
- Review the shell command line for download, execution, privilege escalation, or discovery commands.
- Assess whether the remote destination is external, newly seen, or associated with suspicious infrastructure.

**Evidence to collect:**
- DeviceName, ParentDaemon, ShellProcess, ProcessCommandLine, InitiatingProcessCommandLine, AccountName, ShellSpawnTime, RemoteIP, RemotePort, RemoteUrl, ConnTime.
- DeviceProcessEvents showing the full parent-child chain around the shell spawn.
- DeviceNetworkEvents for the same DeviceId to identify additional outbound connections before and after the shell event.
- Any recent DeviceFileEvents for daemon binary replacement on the same host.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId to find other shells, downloaders, or privilege escalation tools spawned by the daemon.
- DeviceNetworkEvents for the same DeviceId and RemoteIP to identify repeated connections or other affected hosts.
- DeviceFileEvents for the same DeviceName to confirm whether the daemon binary was modified before the shell spawn.
- If available, authentication logs or SSH logs to determine whether the shell was triggered by a legitimate login or by malware.

**Benign explanations:**
- An authorized SSH session can legitimately cause sshd to spawn a shell, especially when the user runs commands that make outbound connections.
- Cron jobs or automation scripts may spawn shells and contact external services for updates, backups, or monitoring.
- Administrative scripts launched by atd or crond may use bash, python, or perl and connect to the internet for legitimate reasons.

**Escalation criteria:**
- The shell is spawned by a daemon that was previously identified as trojanized or recently modified.
- The command line shows suspicious download, execution, or discovery behavior, or the remote IP is untrusted.
- The same host shows repeated shell spawns, multiple outbound connections, or evidence of persistence.
- The activity occurs under an unexpected account or outside an approved maintenance window.

**Containment actions:**
- Isolate the host if the shell is confirmed malicious or if active outbound C2 is observed.
- Terminate the suspicious shell and associated daemon only after preserving evidence and coordinating with system owners.
- Block the remote IP or domain if it is confirmed malicious and not shared with legitimate services.
- Reset credentials used on the host if the shell activity indicates account compromise.

**Closure criteria:**
- The shell activity is tied to a known-good administrative session, automation job, or approved maintenance task.
- The remote connection is explained by legitimate business activity and no other suspicious host behavior is present.
- No evidence of trojanized daemon modification, persistence, or additional malicious process activity is found.
- Any confirmed malicious shell and related network activity have been contained and documented.

<br/>
---
<br/>

## Detection 3: Unauthorized Account Creation on MikroTik Device Post-Exploitation

### Detection Opportunity

New accounts created on MikroTik network devices following SSH authentication bypass exploitation, used to maintain persistent access after patching.

### Intelligence Context

- SANS ISC: Critical MikroTik Vulnerability - Patch Now, (Sun, Sep 6th) — [https://isc.sans.edu/diary/rss/33314](https://isc.sans.edu/diary/rss/33314)
  - Context: Attackers exploiting a MikroTik SSH authentication bypass were observed adding new accounts to compromised devices to maintain persistent access even after the vulnerability is patched.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078, T1136
- Products: MikroTik
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1078, MikroTik, T1136

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1136 Create Account (high); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- MikroTik RouterOS does not have a native Microsoft Sentinel data connector; syslog forwarding must be manually configured via a Linux syslog forwarder with the Syslog or CEF connector. If this is not configured, both Syslog and CommonSecurityLog will contain no MikroTik events.
- CommonSecurityLog DeviceVendor and DeviceProduct values depend on the CEF header configured in the syslog forwarder; these values are not standardized across MikroTik firmware versions and must be confirmed against the actual log output.

**Required telemetry:**
- Syslog, CommonSecurityLog

### KQL

```kql
let AccountCreationKeywords = dynamic(["user add", "added user", "account created", "new user", "useradd"]);
let SyslogHits = Syslog
| where TimeGenerated > ago(24h)
| where Computer has_any ("mikrotik", "routeros")
| where SyslogMessage has_any (AccountCreationKeywords)
| extend SourceIP = extract(@"(?:from|src)[\s:]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})", 1, SyslogMessage)
| project
    TimeGenerated,
    Source = "Syslog",
    HostName = Computer,
    Message = SyslogMessage,
    SourceIP;
let CSLHits = CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor =~ "MikroTik" or DeviceProduct =~ "RouterOS"
| where Activity has_any (AccountCreationKeywords) or Message has_any (AccountCreationKeywords)
| project
    TimeGenerated,
    Source = "CommonSecurityLog",
    HostName = DeviceName,
    Message,
    SourceIP;
union SyslogHits, CSLHits
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized provisioning of new accounts by network administrators will trigger the rule if performed outside a recognized management IP range.
- Automated network management platforms (e.g., The Dude, Ansible network modules) that create accounts programmatically will match.

**Tuning notes:**
- After confirming actual RouterOS account creation log message format, replace the broad keyword list with the exact log string pattern to reduce FP volume.
- Add a where SourceIP !in (known_admin_ips) filter once administrative management IP ranges are identified.
- If MikroTik devices forward syslog with IP addresses as the Computer field rather than hostnames, replace the Computer has_any filter with a lookup against a watchlist of MikroTik device IPs.

**Risks / caveats:**
- MikroTik RouterOS does not have a native Microsoft Sentinel data connector; syslog forwarding must be manually configured via a Linux syslog forwarder with the Syslog or CEF connector. If this is not configured, both Syslog and CommonSecurityLog will contain no MikroTik events.
- The Computer hostname filter uses substring matching on 'mikrotik' and 'routeros'; if MikroTik devices are forwarded with IP addresses or non-descriptive hostnames, the Syslog branch will return no results.
- CommonSecurityLog DeviceVendor and DeviceProduct values depend on the CEF header configured in the syslog forwarder; these values are not standardized across MikroTik firmware versions and must be confirmed against the actual log output.
- The AccountCreationKeywords list may not match the exact log message format produced by the RouterOS version in use; validate against actual MikroTik syslog output before relying on this detection.

### Triage Runbook

**First 15 minutes:**
- Verify the account creation message, source IP, and device identity to confirm the event is from a real MikroTik device and not a logging artifact.
- Check whether the source IP belongs to an approved network management range or a known administrator.
- Review nearby logs for SSH login attempts, successful logins, privilege changes, and configuration edits on the device.
- Determine whether the new account has administrative privileges or remote management access enabled.

**Evidence to collect:**
- TimeGenerated, HostName, Message, SourceIP, and the raw syslog or CEF event that recorded the account creation.
- Any preceding authentication logs showing the source IP, username, and success/failure pattern.
- Current account list and privilege assignments on the MikroTik device, if accessible.
- Recent configuration change logs, especially SSH, user, and management service settings.

**Pivot points:**
- Syslog and CommonSecurityLog for the same HostName to find related login, privilege, and configuration events.
- Network device management logs or NMS logs to identify who last administered the device.
- Firewall or VPN logs for the SourceIP to determine whether it is internal, external, or associated with a jump host.
- If available, compare the account name against known administrator naming conventions and change records.

**Benign explanations:**
- A network administrator may have legitimately created a new account during provisioning or recovery.
- Automated network management tools such as The Dude or Ansible may create accounts programmatically.
- A syslog parsing issue may misclassify another RouterOS message as account creation.

**Escalation criteria:**
- The SourceIP is external, unknown, or not in an approved management range.
- The new account has elevated privileges, remote access, or was created shortly after suspicious SSH activity.
- There are additional signs of compromise such as configuration tampering, disabled logging, or repeated login attempts.
- The device is internet-facing and the account creation followed an SSH authentication bypass or other exploitation indicator.

**Containment actions:**
- Disable or remove the unauthorized account if the device owner confirms it is not legitimate.
- Restrict management access to known admin IPs and rotate device credentials.
- If compromise is confirmed, isolate the device from management and production networks as operationally feasible.
- Preserve configuration and logs before making destructive changes.

**Closure criteria:**
- The account creation is validated as authorized and matches a change record or approved automation.
- The source IP and account owner are identified and confirmed legitimate.
- No additional suspicious logins, configuration changes, or persistence mechanisms are found.
- Unauthorized accounts are removed and device access is restored to a known-good state.

<br/>
---
<br/>

## Detection 4: Invisible Unicode Tag Characters Embedded in Email Subject or Metadata

### Detection Opportunity

Invisible Unicode tag block characters (U+E0000–U+E007F) embedded in email content to obfuscate phishing payloads and bypass content filtering.

### Intelligence Context

- Microsoft Security Blog: ASCII smuggling crosses over from AI prompt injection to phishing evasion — [https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/)
  - Context: Threat actors embedded invisible Unicode tag block characters in email bodies and subjects to hide phishing instructions from content filters, a technique originally used for AI prompt injection now adapted for email-based evasion.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1027
- Products: Not specified
- Platforms: email
- Malware: Not specified
- Tools: Not specified
- Search tags: email, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Defense Evasion: T1027 Obfuscated Files or Information (high)

### Deployment Gates

- OfficeActivity Subject field is only populated for certain Operation types; MessageBind and Create operations may not include Subject depending on the Exchange Online audit configuration and license tier (E3 vs E5 audit logging).

**Required telemetry:**
- OfficeActivity

### KQL

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("Send", "SendAs", "SendOnBehalf")
| where isnotempty(Subject)
| where Subject matches regex @"[\x{E0000}-\x{E007F}]"
| project
    TimeGenerated,
    Operation,
    UserId,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ClientIP,
    OperationProperties
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated email systems or marketing platforms that use non-standard Unicode encoding in subject lines may produce matches if their encoding artifacts fall in the tag block range.
- Email forwarding or re-encoding by intermediate mail transfer agents may introduce or strip tag block characters unpredictably.

**Tuning notes:**
- If the regex syntax is unsupported, consider implementing this detection in Defender for Office 365 using a mail flow rule or custom detection policy that inspects raw MIME content.
- For environments with high email volume, add a summarize count() by SenderFromAddress step before the final project to identify bulk senders before reviewing individual messages.
- Extend the lookback to 30 days for the initial hunting run to establish whether any historical matches exist in the environment.

**Risks / caveats:**
- The Office 365 Management API that populates OfficeActivity may normalize, strip, or encode Unicode supplementary plane characters (U+E0000–U+E007F) before ingestion into Log Analytics, making the Subject field unsuitable for this regex match. This must be validated with a synthetic test email before deployment.
- KQL regex syntax \x{E0000} for Unicode supplementary plane code points is not supported in all Kusto engine versions. The standard KQL regex engine uses RE2 syntax, which does not support \x{XXXXXX} for code points above U+FFFF. An alternative detection approach using has_any with pre-encoded byte sequences or a custom function may be required.
- OfficeActivity Subject field is only populated for certain Operation types; MessageBind and Create operations may not include Subject depending on the Exchange Online audit configuration and license tier (E3 vs E5 audit logging).
- The regex \x{E0000}-\x{E007F} must be validated in the target Kusto workspace before scheduling; if the RE2 engine does not support this syntax, the query will return a parse error rather than results.

### Triage Runbook

**First 15 minutes:**
- Inspect the message subject and metadata in a raw or decoded view to confirm the presence of invisible Unicode tag characters.
- Identify whether the sender is external, newly seen, or spoofing a trusted domain.
- Check whether the message was delivered to multiple recipients or targeted a high-value user.
- Review whether any links, attachments, or instructions in the message align with phishing or social engineering.

**Evidence to collect:**
- TimeGenerated, Operation, SenderFromAddress, RecipientEmailAddress, Subject, ClientIP, UserId, and OperationProperties.
- A raw MIME or message trace view if available to confirm whether the Unicode characters are preserved in transit.
- Delivery and click telemetry for the recipient(s), including whether the message was opened or interacted with.
- Any related mail flow, quarantine, or Defender for Office 365 verdicts for the same message.

**Pivot points:**
- OfficeActivity for the same SenderFromAddress and RecipientEmailAddress to find related sends or replies.
- Message trace or Defender for Office 365 investigation data to determine delivery path and user interaction.
- Mail flow rules or transport logs to see whether the message was modified, forwarded, or re-encoded.
- If available, search for the same Subject pattern across recent email activity to identify campaign scope.

**Benign explanations:**
- A legitimate system or marketing platform may introduce unusual Unicode encoding artifacts in subject lines.
- Mail forwarding or re-encoding by intermediate systems may alter the subject unexpectedly.
- A test message from an internal security or email team may intentionally include unusual characters.

**Escalation criteria:**
- The sender is external or spoofed and the message contains phishing language, credential prompts, or malicious links.
- Multiple recipients received the same message, especially if they are executives, finance, or help desk users.
- Any recipient clicked a link, opened an attachment, or submitted credentials after receiving the message.
- The Unicode characters appear intentionally placed to hide instructions or bypass filtering rather than as an encoding artifact.

**Containment actions:**
- Quarantine or purge the message if it is confirmed malicious and the platform supports removal.
- Block the sender, domain, or related URLs if they are confirmed malicious.
- Warn recipients who received the message and reset credentials if any user interaction occurred.
- Escalate to email security operations to add detection or filtering for the campaign pattern.

**Closure criteria:**
- The message is confirmed benign, such as a known internal test or encoding artifact from a trusted system.
- No user interaction, credential submission, or malicious content is identified.
- The sender and delivery path are explained by normal business or mail transport behavior.
- If malicious, the message has been contained and affected users have been notified and remediated.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Shell Spawned by Trojanized Linux Daemon with Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Unauthorized Account Creation on MikroTik Device Post-Exploitation: MikroTik RouterOS does not have a native Microsoft Sentinel data connector; syslog forwarding must be manually configured via a Linux syslog forwarder with the Syslog or CEF connector. If this is not configured, both Syslog and CommonSecurityLog will contain no MikroTik events.

**Other deployment dependency:**
- Unauthorized Account Creation on MikroTik Device Post-Exploitation: CommonSecurityLog DeviceVendor and DeviceProduct values depend on the CEF header configured in the syslog forwarder; these values are not standardized across MikroTik firmware versions and must be confirmed against the actual log output.

**Licensing / identity risk fields:**
- Invisible Unicode Tag Characters Embedded in Email Subject or Metadata: OfficeActivity Subject field is only populated for certain Operation types; MessageBind and Create operations may not include Subject depending on the Exchange Online audit configuration and license tier (E3 vs E5 audit logging).

**Shared-table notes:**
- DeviceProcessEvents: shared by Trojanized Linux System Daemon Binary Modification Detected; Shell Spawned by Trojanized Linux Daemon with Outbound Network Connection

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Trojanized Linux System Daemon Binary Modification Detected.
2. Resolve environment-mapping detections next: Unauthorized Account Creation on MikroTik Device Post-Exploitation; Invisible Unicode Tag Characters Embedded in Email Subject or Metadata.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Shell Spawned by Trojanized Linux Daemon with Outbound Network Connection.

### Hunting Agenda and Promotion Criteria

- Shell Spawned by Trojanized Linux Daemon with Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Unauthorized Account Creation on MikroTik Device Post-Exploitation: MikroTik RouterOS does not have a native Microsoft Sentinel data connector; syslog forwarding must be manually configured via a Linux syslog forwarder with the Syslog or CEF connector. If this is not configured, both Syslog and CommonSecurityLog will contain no MikroTik events..
- Invisible Unicode Tag Characters Embedded in Email Subject or Metadata: OfficeActivity Subject field is only populated for certain Operation types; MessageBind and Create operations may not include Subject depending on the Exchange Online audit configuration and license tier (E3 vs E5 audit logging)..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
