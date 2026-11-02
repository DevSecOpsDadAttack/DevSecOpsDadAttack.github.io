---
layout: post
title: "Detection Engineering Brief - Monday, November 2, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-02
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Cursor
  - SSH
  - Active Directory Certificate Services
  - Kerberos
  - CVE-2026-102764
  - BeyondTrust Remote Support
  - T1071.004
  - T1095
  - T1071
  - T1649
  - T1203
  - T1190
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 0 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Cursor, SSH, Active Directory Certificate Services, Kerberos, CVE-2026-102764, BeyondTrust Remote Support, T1071.004, T1095, T1071, T1649, T1203, T1190.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source; AD CS ESC1 Abuse - Low-Privileged Account Certificate Enrollment with Anomalous Template; BeyondTrust CVE-2026-102764 - Unexpected Process Execution Following Inbound Customer Session.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Malicious IDE Extension SSH Backdoor - authorized_keys Modified by Extension Process

### Detection Opportunity

Malicious Claude Code-branded Cursor extension modified SSH authorized_keys file to establish persistent SSH backdoor access.

### Intelligence Context

- Microsoft Security Blog: Inside a malicious Claude Code-branded extension and its persistent SSH backdoor — [https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
  - Context: A malicious extension branded as Claude Code was installed in the Cursor IDE and established SSH persistence by modifying the authorized_keys file or sshd_config, enabling persistent remote access to the compromised host.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071.004, T1095, T1071
- Products: Cursor
- Platforms: SSH
- Malware: Not specified
- Tools: Not specified
- Search tags: Cursor, SSH, T1071.004, T1095, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (low); Command and Control: T1095 Non-Application Layer Protocol (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where (
    FileName in~ ("authorized_keys", "sshd_config")
    or FolderPath has ".ssh"
    or FolderPath has "/etc/ssh"
)
| where (
    InitiatingProcessFileName has_any ("cursor", "node", "electron", "code")
    or InitiatingProcessParentFileName has_any ("cursor", "node", "electron", "code")
)
| project
    TimeGenerated,
    DeviceName,
    FolderPath,
    FileName,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer tooling that uses node.js or electron for legitimate file operations in .ssh directories (e.g., SSH config management extensions that are not malicious).
- VS Code Remote SSH extension (process name 'code') legitimately interacts with SSH configuration; the 'code' filter arm may generate false positives in environments using VS Code Remote.
- Automated dotfile management scripts invoked from within an IDE terminal session may appear as node or electron child processes.

**Tuning notes:**
- After baselining, add known-legitimate node or electron processes that write to .ssh directories to an exclusion filter on InitiatingProcessCommandLine.
- If Cursor's exact process binary name differs in your environment (e.g., 'Cursor.exe' on Windows), verify via DeviceProcessEvents before relying on the has_any filter.
- Consider scoping DeviceName to a device group tag for developer workstations to reduce noise from servers where Cursor would never legitimately run.

**Risks / caveats:**
- DeviceFileEvents telemetry requires Defender for Endpoint Plan 2 with file activity monitoring enabled on the target hosts. If DfE is not deployed on developer workstations running Cursor, this query will return no results.
- The 'code' process name filter will match VS Code (code.exe / code) in addition to Cursor; environments running VS Code Remote SSH should add 'code' to an exclusion allowlist or remove it from the filter after baselining.
- The 7-day lookback window may miss historical compromise; consider extending to 30 days for initial hunting runs.
- node.exe is a generic runtime used by many applications beyond IDE extensions; baselining node-initiated SSH file writes in the environment is recommended before scheduling at high-severity alert frequency.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a developer workstation where Cursor is expected; if not, treat as highly suspicious immediately.
- Review the exact file path and change time for authorized_keys or sshd_config and verify whether the write came from a Cursor, node, electron, or code process.
- Identify the initiating user account and determine whether the change occurred during an active IDE session or from an unexpected background process.
- Check for any recent outbound SSH activity from the same host and user to see whether the persistence was used immediately after modification.

**Evidence to collect:**
- DeviceFileEvents for the affected host covering at least 24 hours before and after the alert time.
- DeviceProcessEvents for the initiating process tree, including parent, child, command line, and any extension-related binaries.
- Recent DeviceNetworkEvents showing SSH connections, destination IPs, ports, and timestamps from the same host.
- The exact contents or diff of the modified authorized_keys or sshd_config file if available from endpoint response or backup tooling.

**Pivot points:**
- DeviceFileEvents filtered to the same DeviceName and InitiatingProcessAccountName to find other writes to .ssh or /etc/ssh.
- DeviceProcessEvents for the initiating process name and parent process to identify the IDE, extension host, or shell chain.
- DeviceNetworkEvents for RemotePort 22 from the same host to identify possible remote access destinations.
- DeviceLogonEvents or identity logs to determine whether the user account had unusual sign-in activity around the same time.

**Benign explanations:**
- A legitimate SSH configuration management or dotfile automation tool launched from within an IDE terminal.
- VS Code Remote SSH activity if the environment uses code.exe for approved remote development workflows.
- A developer manually editing SSH keys or config files from within Cursor or another IDE extension.
- A legitimate node or electron-based extension that manages SSH settings for approved development tooling.

**Escalation criteria:**
- The modified file is authorized_keys on a user profile or sshd_config on a workstation or server where no approved change was expected.
- The same host shows outbound SSH connections to unknown or unapproved destinations after the file modification.
- The initiating process tree includes suspicious command lines, downloaded extension artifacts, or evidence of unauthorized extension installation.
- Multiple developer workstations show the same pattern, suggesting a broader malicious extension campaign.

**Containment actions:**
- Isolate the affected host from the network if the change is unauthorized or if outbound SSH activity is confirmed.
- Disable or reset the affected user account if there is evidence of active misuse or credential compromise.
- Remove the suspicious IDE extension and preserve the extension package, logs, and process artifacts for analysis.
- Revoke any SSH keys added or modified by the suspicious process and rotate credentials used on the host.

**Closure criteria:**
- The file change is confirmed as an approved administrative or developer action with supporting change evidence.
- No suspicious outbound SSH activity, no malicious extension artifacts, and no additional persistence indicators are found.
- The host is cleaned or rebuilt as needed and the suspicious extension is removed from the environment.
- The user account and SSH keys have been reviewed and no unauthorized access paths remain.

<br/>
---
<br/>

## Detection 2: Malicious IDE Extension SSH Backdoor - Outbound SSH Connection from IDE Process

### Detection Opportunity

Cursor IDE extension process initiated an outbound SSH connection, consistent with a persistent SSH backdoor established by a malicious Claude Code-branded extension.

### Intelligence Context

- Microsoft Security Blog: Inside a malicious Claude Code-branded extension and its persistent SSH backdoor — [https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
  - Context: The malicious extension established a persistent SSH backdoor. Outbound SSH connections (port 22) originating from IDE or extension host processes are a direct indicator of this backdoor behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071.004, T1095, T1071
- Products: Cursor
- Platforms: SSH
- Malware: Not specified
- Tools: Not specified
- Search tags: Cursor, SSH, T1071.004, T1095, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (low); Command and Control: T1095 Non-Application Layer Protocol (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemotePort == 22
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt", "ConnectionFound")
| where (
    InitiatingProcessFileName has_any ("cursor", "node", "electron", "code")
    or InitiatingProcessParentFileName has_any ("cursor", "node", "electron", "code")
)
| project
    TimeGenerated,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- VS Code Remote SSH extension uses the 'code' process and legitimately initiates SSH connections on port 22; environments using VS Code Remote should remove 'code' from the filter or add known Remote SSH destination IPs to an exclusion.
- Developer tools that use node.js to proxy or tunnel SSH connections for legitimate purposes (e.g., SSH tunneling libraries in dev toolchains) may trigger this rule.
- Cursor's built-in remote development features, if any, may legitimately connect over SSH.

**Tuning notes:**
- Add known legitimate SSH destination IPs (jump hosts, build servers) to an exclusion filter on RemoteIP after baselining.
- Consider restricting DeviceName to a developer workstation device group tag to reduce noise from servers.
- If Cursor's process binary name is confirmed in your environment via DeviceProcessEvents, replace the has_any filter with an exact in~ match for higher precision.

**Risks / caveats:**
- DeviceNetworkEvents telemetry requires Defender for Endpoint Plan 2 with network monitoring enabled. Port 22 outbound connections may not be captured if network inspection is disabled or if the host uses a VPN that bypasses DfE network monitoring.
- The 'code' process name filter matches VS Code in addition to Cursor; VS Code Remote SSH users will generate false positives. Baseline port-22 connections from 'code' processes in the environment before scheduling.
- node.exe is a generic runtime; any node-based application that connects to port 22 (e.g., deployment scripts, CI tooling run from an IDE terminal) will match.
- If the malicious extension uses a non-standard port for its SSH backdoor, this rule will not fire. Consider adding additional high-numbered ports if threat intelligence indicates non-standard SSH ports.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination IP, port, and timestamp of the SSH connection and determine whether it is an approved jump host or developer target.
- Validate the initiating process and parent process to confirm the connection came from Cursor, node, electron, or code rather than a normal SSH client.
- Check whether the same host recently modified authorized_keys or sshd_config, which would strengthen the backdoor hypothesis.
- Review whether the user was actively using the IDE at the time or whether the connection occurred from a background process without user interaction.

**Evidence to collect:**
- DeviceNetworkEvents for the affected host around the alert time, including RemoteIP, RemotePort, RemoteUrl, and process context.
- DeviceProcessEvents for the initiating process tree and any spawned shells or helper processes.
- DeviceFileEvents for .ssh and /etc/ssh changes on the same host before and after the network event.
- Identity and sign-in logs for the initiating user account to identify unusual access patterns or concurrent sessions.

**Pivot points:**
- DeviceNetworkEvents filtered to the same DeviceName and RemotePort 22 to find repeated SSH sessions.
- DeviceProcessEvents for the initiating process name and command line to identify the exact IDE or extension behavior.
- DeviceFileEvents for the same host to look for persistence changes in authorized_keys or sshd_config.
- DeviceLogonEvents or Entra ID sign-in logs to correlate the user session with the network activity.

**Benign explanations:**
- Approved VS Code Remote SSH usage in environments where code.exe is expected to connect to port 22.
- Legitimate developer tooling or automation that tunnels or proxies SSH from within an IDE.
- A sanctioned remote development workflow using Cursor or a related extension.
- A build, deployment, or admin script launched from an IDE terminal that uses SSH for legitimate access.

**Escalation criteria:**
- The destination is not an approved host and the connection was initiated by an IDE or extension process.
- The same host also shows SSH persistence changes or other suspicious file modifications.
- The user denies initiating the connection or the connection occurred outside normal working hours without explanation.
- Multiple SSH sessions or repeated attempts are observed from the same workstation.

**Containment actions:**
- Isolate the host if the SSH destination is unapproved or if there is evidence of active backdoor use.
- Disable the user account or revoke active sessions if the account appears compromised.
- Block the destination IP temporarily if it is confirmed malicious and not business-critical.
- Remove the suspicious extension and preserve endpoint artifacts for forensic review.

**Closure criteria:**
- The SSH destination is confirmed as an approved internal host and the process behavior matches expected tooling.
- No persistence changes, suspicious child processes, or additional unauthorized connections are found.
- The user and workstation are validated against known-good remote development workflows.
- Any suspicious extension or process is removed and the environment is baselined for future detections.

<br/>
---
<br/>

## Detection 3: AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source

### Detection Opportunity

Low-privileged or unexpected account requested a certificate via AD CS enrollment following an NTLM authentication event, consistent with ESC8 authentication relay abuse.

### Intelligence Context

- Microsoft Security Blog: From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths — [https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/)
  - Context: Attackers abused AD CS via authentication relay (ESC8) to obtain certificates. The intrusion path involved NTLM relay to the AD CS web enrollment endpoint, generating certificate request events (EventID 4886/4887) that can be correlated with NTLM logon events from unexpected source addresses.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1649
- Products: Active Directory Certificate Services
- Platforms: Kerberos
- Malware: Not specified
- Tools: Not specified
- Search tags: Active Directory Certificate Services, Kerberos, T1649

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1649 Steal or Forge Authentication Certificates (high)

### Deployment Gates

- EventID 4886 and 4887 are generated on the CA server only when AD CS certificate request auditing is explicitly enabled via 'Audit Certification Services' policy. These events are not collected by default and will be absent if this audit category is not configured.
- The IpAddress field in EventID 4886/4887 is frequently empty or populated as '-' in default AD CS audit configurations. If IpAddress is not populated in certificate request events, the inner join on SourceIP == LogonIP will return zero results.
- If IpAddress is not populated in EventID 4886/4887 in the target environment, this query will return no results. Validate IpAddress population before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let CertRequests = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4886, 4887)
| where SubjectUserName !endswith "$"
| extend SourceIP = tostring(IpAddress)
| where isnotempty(SourceIP) and SourceIP != "-"
| extend TemplateName = extract(@"Certificate Template:\s*([^\r\n]+)", 1, tostring(EventData))
| project CertTime = TimeGenerated, RequesterName = SubjectUserName, SourceIP, EventID, CertComputer = Computer, TemplateName;
let NTLMLogons = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName =~ "NTLM"
| extend LogonIP = tostring(IpAddress)
| where isnotempty(LogonIP) and LogonIP != "-"
| project LogonTime = TimeGenerated, LogonUser = TargetUserName, LogonIP;
CertRequests
| join kind=inner NTLMLogons on $left.SourceIP == $right.LogonIP
| where CertTime between (LogonTime .. (LogonTime + 5m))
| project
    CertTime,
    LogonTime,
    RequesterName,
    LogonUser,
    SourceIP,
    EventID,
    CertComputer,
    TemplateName
| order by CertTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate certificate enrollment by users who authenticate via NTLM to the CA web enrollment page from their workstation IP will match this rule; this is expected behavior for environments that have not disabled NTLM on the enrollment endpoint.
- Helpdesk or IT staff who enroll certificates on behalf of users via the web enrollment interface using NTLM authentication will trigger this rule.
- Automated certificate management tools that use NTLM authentication to the enrollment endpoint will generate matches.

**Tuning notes:**
- Add known CA service accounts and certificate management service accounts to an exclusion filter on RequesterName to suppress legitimate enrollment activity.
- After confirming IpAddress population, add known legitimate enrollment source IPs (e.g., helpdesk workstations, PKI management servers) to an exclusion filter on SourceIP.
- Cross-reference TemplateName values against ESC1/ESC8-vulnerable templates identified in your environment to prioritize alerts.

**Risks / caveats:**
- EventID 4886 and 4887 are generated on the CA server only when AD CS certificate request auditing is explicitly enabled via 'Audit Certification Services' policy. These events are not collected by default and will be absent if this audit category is not configured.
- The IpAddress field in EventID 4886/4887 is frequently empty or populated as '-' in default AD CS audit configurations. If IpAddress is not populated in certificate request events, the inner join on SourceIP == LogonIP will return zero results.
- EventID 4624 NTLM logon events must be collected from the CA server or the enrollment endpoint host specifically, not just from domain controllers, for the IP correlation to be meaningful.
- If IpAddress is not populated in EventID 4886/4887 in the target environment, this query will return no results. Validate IpAddress population before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the certificate request event and the correlated NTLM logon came from the same source IP within the expected time window.
- Identify the requester account, target account, and certificate template involved, then determine whether the requester is a machine account, helpdesk account, or low-privileged user.
- Verify whether the source IP belongs to a known enrollment workstation, helpdesk system, or PKI management host.
- Check whether the CA server and enrollment endpoint show any other suspicious authentication or certificate activity around the same time.

**Evidence to collect:**
- SecurityEvent records for EventID 4886, 4887, and 4624 on the CA server and any enrollment endpoints.
- The certificate template name, requester name, source IP, and any available EventData from the certificate request event.
- Network and authentication logs from the source host to determine whether NTLM relay tooling or proxy behavior was present.
- Any certificate issuance details, including whether the certificate was successfully issued and whether it was later used for logon.

**Pivot points:**
- SecurityEvent for EventID 4886, 4887, and 4624 on the CA server and related hosts.
- SecurityEvent or domain controller logs for additional NTLM logons from the same source IP or account.
- Certificate Services logs or CA operational logs to confirm issuance and template details.
- Identity logs to look for subsequent Kerberos or certificate-based authentication by the requester account.

**Benign explanations:**
- Legitimate certificate enrollment from a workstation that authenticates to the web enrollment page using NTLM.
- Helpdesk or PKI staff performing approved certificate enrollment on behalf of a user.
- Automated certificate management or renewal tooling that uses NTLM on the enrollment endpoint.
- A known internal enrollment host that legitimately accesses the CA web interface.

**Escalation criteria:**
- The source IP is not a known enrollment or helpdesk system and the requester is a low-privileged or unexpected account.
- The certificate template is sensitive, vulnerable, or not normally used by the requester.
- The certificate was issued successfully and there is evidence it was used for subsequent authentication.
- Multiple certificate requests or NTLM logons from the same unexpected source are observed.

**Containment actions:**
- Block or isolate the source host if relay activity is suspected and the host is not trusted.
- Disable or reset the requester account if compromise is likely.
- Revoke any suspiciously issued certificates and remove them from affected stores if feasible.
- Increase monitoring on the CA and enrollment endpoint for additional relay attempts.

**Closure criteria:**
- The request is confirmed as legitimate enrollment from an approved source and account.
- No evidence of relay tooling, certificate misuse, or follow-on authentication abuse is found.
- Any issued certificate is validated as expected and not used for unauthorized access.
- The source IP and requester are added to an allowlist only after validation and documentation.

<br/>
---
<br/>

## Detection 4: AD CS ESC1 Abuse - Low-Privileged Account Certificate Enrollment with Anomalous Template

### Detection Opportunity

A low-privileged user account enrolled a certificate using an AD CS template that permits Subject Alternative Name specification, consistent with ESC1 privilege escalation via certificate abuse.

### Intelligence Context

- Microsoft Security Blog: From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths — [https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/)
  - Context: ESC1 abuse allows a low-privileged user to enroll a certificate with an elevated Subject Alternative Name, enabling impersonation of privileged accounts. The intrusion path described in the reporting used this technique as part of a chained attack following help desk impersonation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1649
- Products: Active Directory Certificate Services
- Platforms: Kerberos
- Malware: Not specified
- Tools: Not specified
- Search tags: Active Directory Certificate Services, Kerberos, T1649

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1649 Steal or Forge Authentication Certificates (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4886
| where SubjectUserName !endswith "$"
| extend RequesterName = tostring(SubjectUserName)
| extend TemplateName = extract(@"Certificate Template:\s*([^\r\n]+)", 1, tostring(EventData))
| where isnotempty(TemplateName)
| summarize
    EnrollmentCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RequesterName, TemplateName, Computer
| order by EnrollmentCount asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate user certificate enrollment for any template will appear in results until a known-safe template exclusion list is applied.
- Helpdesk staff enrolling certificates on behalf of users will appear as human account enrollments.
- Any user who has ever enrolled a certificate via the web enrollment interface or certmgr will appear in results.

**Tuning notes:**
- After identifying ESC1-vulnerable templates using Certify or Certipy, add a filter such as '| where TemplateName in~ ("VulnerableTemplate1", "VulnerableTemplate2")' to scope the rule to high-risk templates only. This is required before promoting to a scheduled alert.
- Add known-safe template names to an exclusion filter on TemplateName to suppress routine enrollment noise once the vulnerable template list is established.
- Consider adding a threshold filter such as '| where EnrollmentCount == 1' to surface only first-time enrollments per user-template pair for initial alerting.

**Risks / caveats:**
- EventID 4886 is generated on the CA server only when AD CS certificate request auditing is explicitly enabled via 'Audit Certification Services' policy. These events will be absent if this audit category is not configured.
- The TemplateName extraction relies on a regex pattern against the EventData string field. If the EventData format differs between Windows Server versions or AD CS configurations, the extract may return empty values, causing the isnotempty(TemplateName) filter to drop all results.
- Without filtering TemplateName against a known list of ESC1-vulnerable templates in the environment, this query will surface all human account certificate enrollments and require analyst triage to identify anomalous templates. Identifying ESC1-vulnerable templates requires running Certify or Certipy against the AD CS environment.
- The 7-day lookback may miss historical ESC1 abuse; consider extending to 30 days for initial hunting runs.

### Triage Runbook

**First 15 minutes:**
- Identify the requester account, template name, CA server, and first/last seen times for the enrollment.
- Confirm whether the template is known to allow SAN specification or other ESC1-like abuse in your environment.
- Check whether the requester is a normal certificate consumer or an account that should never enroll from this template.
- Look for immediate follow-on activity such as privileged logons, new service tickets, or certificate-based authentication.

**Evidence to collect:**
- SecurityEvent EventID 4886 details including requester, template name, and CA computer.
- Any available certificate issuance metadata or CA operational logs for the same request.
- Identity logs showing subsequent logons, group changes, or privilege use by the requester account.
- Historical certificate enrollment activity for the same user-template pair to determine whether this is new or rare.

**Pivot points:**
- SecurityEvent for EventID 4886 on the CA server to review other enrollments by the same account.
- SecurityEvent or identity logs for subsequent authentication by the requester account after enrollment.
- Directory or PKI inventory data to compare the template against known vulnerable or approved templates.
- SecurityEvent for privileged logons or account changes around the enrollment time.

**Benign explanations:**
- A legitimate user enrolling a certificate from an approved template that happens to be uncommon.
- Helpdesk or PKI staff performing an authorized enrollment on behalf of a user.
- A first-time enrollment by a new employee or newly provisioned device.
- A certificate renewal or reissue that appears anomalous only because the user rarely enrolls certificates.

**Escalation criteria:**
- The template is confirmed vulnerable or not intended for low-privileged users.
- The requester account is unexpected, newly created, or associated with suspicious activity.
- The certificate is followed by privileged access, lateral movement, or unusual authentication patterns.
- The same account enrolls multiple certificates from risky templates in a short period.

**Containment actions:**
- Disable or suspend the requester account if abuse is likely and business impact is acceptable.
- Revoke the suspicious certificate and any related certificates if they were issued in error or abuse is confirmed.
- Restrict or disable the vulnerable template until the PKI team validates its configuration.
- Monitor for certificate-based logons from the requester account and related hosts.

**Closure criteria:**
- The template is confirmed safe and the enrollment is documented as legitimate.
- No follow-on privileged activity or certificate misuse is observed.
- The requester account and CA activity are consistent with approved PKI operations.
- Any risky template exposure has been remediated or formally accepted with compensating controls.

<br/>
---
<br/>

## Detection 5: BeyondTrust CVE-2026-102764 - Unexpected Process Execution Following Inbound Customer Session

### Detection Opportunity

An unexpected OS-level process was spawned under the BeyondTrust service account context following an inbound customer support session, consistent with unauthenticated file upload leading to remote code execution.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Unauthenticated File Upload to RCE in BeyondTrust Remote Support (CVE-2026-102764) — [https://www.rapid7.com/blog/post/ra-rapid7-analysis-unauthenticated-file-upload-to-rce-in-beyondtrust-remote-support-cve-2026-102764](https://www.rapid7.com/blog/post/ra-rapid7-analysis-unauthenticated-file-upload-to-rce-in-beyondtrust-remote-support-cve-2026-102764)
  - Context: CVE-2026-102764 allows an unauthenticated attacker to upload files via the public customer connection endpoint and execute code as the site's OS user. The attack abuses internal message routing to reach the file transfer service. RCE as the OS service account following an unauthenticated upload is the primary post-exploitation indicator.

### Search Metadata

- CVEs: CVE-2026-102764
- Threat actors: Not specified
- ATT&CK tags: T1203, T1190
- Products: BeyondTrust Remote Support
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-102764, BeyondTrust Remote Support, T1203, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1203 Exploitation for Client Execution (medium); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(7d)
| where HostName has_any ("beyondtrust", "bomgar")
| where ProcessName has_any ("bomgar", "btrs", "support", "www", "apache", "nginx")
| where Message has_any (
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/python",
    "/usr/bin/python3",
    "/usr/bin/perl",
    "curl ",
    "wget ",
    " nc ",
    "ncat",
    "bash -",
    "sh -c"
)
| project
    TimeGenerated,
    HostName,
    ProcessName,
    SeverityLevel,
    Facility,
    Message
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative shell sessions on the BeyondTrust appliance by system administrators will generate syslog entries matching the shell keyword list.
- Automated maintenance scripts (curl, wget for updates; bash for cron jobs) running under service account context will match.
- Log rotation, health check scripts, and monitoring agents that invoke shell utilities will generate matches.

**Tuning notes:**
- Replace the HostName has_any filter with the exact hostnames of BeyondTrust appliances in the environment, confirmed by querying 'Syslog → distinct HostName' filtered to known appliance IP ranges.
- Validate ProcessName values by querying 'Syslog → where HostName == "<confirmed-appliance-hostname>" → distinct ProcessName' to identify the actual BeyondTrust service process names in syslog.
- If auditd is available on the appliance, consider using AuditLog or auditd-forwarded syslog entries for more reliable process execution visibility than application-level syslog.
- After baselining, add known-legitimate administrative processes and cron job patterns to an exclusion filter on Message to reduce noise.

**Risks / caveats:**
- Syslog ingestion from BeyondTrust appliances requires a configured syslog forwarder (rsyslog/syslog-ng) or the Azure Monitor Agent on the appliance, or a syslog collector forwarding to the Sentinel workspace. If BeyondTrust appliance syslog is not forwarded to Sentinel, this query will return no results.
- The Syslog table HostName field reflects the hostname as reported by the syslog sender. If the BeyondTrust appliance uses a different hostname than expected (e.g., FQDN vs short name), the HostName filter will not match.
- BeyondTrust appliances may not generate OS-level process execution syslog entries for child processes spawned by the service; process execution visibility depends on whether auditd or equivalent process accounting is configured on the appliance OS.
- The HostName filter uses has_any with generic substrings ('beyondtrust', 'bomgar'). If the appliance hostname does not contain these substrings, the query will return no results. The exact appliance hostnames must be confirmed from the Syslog table before this query is useful.

### Triage Runbook

**First 15 minutes:**
- Confirm the appliance hostname, time of the event, and the exact process or command indicators in the syslog message.
- Determine whether the process execution occurred immediately after an inbound customer support session or file transfer activity.
- Check whether the process is expected for appliance maintenance or whether it is a shell, interpreter, or downloader that should not run under the service account.
- Review whether the appliance has any concurrent signs of compromise such as unusual outbound connections, new files, or repeated suspicious syslog entries.

**Evidence to collect:**
- Syslog entries from the appliance for at least 24 hours before and after the alert time.
- Any appliance audit or process accounting logs that show the parent process, child process, and command line.
- Inbound session logs and file transfer logs from BeyondTrust to identify the customer session associated with the event.
- Network telemetry from the appliance showing outbound connections, especially to unusual external IPs or ports.

**Pivot points:**
- Syslog filtered to the appliance hostname and related process names to find repeated shell or downloader activity.
- Syslog or appliance logs for inbound customer session identifiers around the same time.
- Network logs for the appliance to identify outbound connections after the suspicious execution.
- Any available file integrity or endpoint telemetry from the appliance host to identify dropped files or modified binaries.

**Benign explanations:**
- A legitimate administrative shell session on the appliance by a trusted administrator.
- Maintenance scripts, log rotation, or monitoring agents that invoke shell utilities.
- Approved update or support activity that spawns expected helper processes.
- A false positive from generic syslog keyword matching where the message references a shell utility without actual compromise.

**Escalation criteria:**
- The process is an unexpected shell, interpreter, or downloader running under the BeyondTrust service account.
- There is evidence of outbound connections, file drops, or repeated suspicious process creation after the inbound session.
- The event aligns with an unauthenticated or untrusted customer session rather than an approved admin action.
- Multiple appliances or repeated sessions show the same pattern, suggesting active exploitation.

**Containment actions:**
- Isolate the BeyondTrust appliance from external access if exploitation is suspected and business continuity allows.
- Disable or restrict the affected customer-facing service until the vendor guidance and patch status are confirmed.
- Preserve syslog, session logs, and any available forensic artifacts before rebooting or patching.
- Block suspicious outbound destinations if the appliance is attempting external callback or staging activity.

**Closure criteria:**
- The process execution is confirmed as expected maintenance or approved administrative activity.
- No additional suspicious syslog, network, or file activity is found on the appliance.
- The appliance is patched or otherwise remediated according to vendor guidance if exposure exists.
- The incident is documented with the exact process, session context, and validation of benign behavior.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source: EventID 4886 and 4887 are generated on the CA server only when AD CS certificate request auditing is explicitly enabled via 'Audit Certification Services' policy. These events are not collected by default and will be absent if this audit category is not configured.
- AD CS ESC1 Abuse - Low-Privileged Account Certificate Enrollment with Anomalous Template: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.
- BeyondTrust CVE-2026-102764 - Unexpected Process Execution Following Inbound Customer Session: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Schema / correlation keys:**
- AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source: The IpAddress field in EventID 4886/4887 is frequently empty or populated as '-' in default AD CS audit configurations. If IpAddress is not populated in certificate request events, the inner join on SourceIP == LogonIP will return zero results.
- AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source: If IpAddress is not populated in EventID 4886/4887 in the target environment, this query will return no results. Validate IpAddress population before scheduling.

**Shared-table notes:**
- SecurityEvent: shared by AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source; AD CS ESC1 Abuse - Low-Privileged Account Certificate Enrollment with Anomalous Template

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Malicious IDE Extension SSH Backdoor - authorized_keys Modified by Extension Process; Malicious IDE Extension SSH Backdoor - Outbound SSH Connection from IDE Process.
2. Resolve environment-mapping detections next: AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source; AD CS ESC1 Abuse - Low-Privileged Account Certificate Enrollment with Anomalous Template; BeyondTrust CVE-2026-102764 - Unexpected Process Execution Following Inbound Customer Session.

### Hunting Agenda and Promotion Criteria

- AD CS ESC8 Abuse - Certificate Enrollment Following NTLM Logon from Unexpected Source: EventID 4886 and 4887 are generated on the CA server only when AD CS certificate request auditing is explicitly enabled via 'Audit Certification Services' policy. These events are not collected by default and will be absent if this audit category is not configured.; prove correlation keys join correctly on real tenant telemetry.
- AD CS ESC1 Abuse - Low-Privileged Account Certificate Enrollment with Anomalous Template: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- BeyondTrust CVE-2026-102764 - Unexpected Process Execution Following Inbound Customer Session: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
