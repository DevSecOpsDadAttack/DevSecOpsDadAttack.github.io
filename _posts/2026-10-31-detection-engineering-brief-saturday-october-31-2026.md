---
layout: post
title: "Detection Engineering Brief - Saturday, October 31, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-31
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1557
  - T1550
  - Active Directory Certificate Services
  - Kerberos
  - Windows
  - CVE-2026-102764
  - T1190
  - T1059
  - BeyondTrust Remote Support
  - T1547
  - T1053
  - Claude Code
  - Cursor
  - SSH
  - CVE-2026-109618
  - CVE-2026-109619
  - PHP
  - T1547.001
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 0 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1557, T1550, Active Directory Certificate Services, Kerberos, Windows, CVE-2026-102764, T1190, T1059, BeyondTrust Remote Support, T1547, T1053, Claude Code, Cursor, SSH, CVE-2026-109618, CVE-2026-109619, PHP, T1547.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: AD CS Certificate Issuance from Anomalous Requester (ESC1/ESC8); Kerberos PKINIT Authentication Following AD CS Certificate Issuance; BeyondTrust Web Service Spawning Shell Process (CVE-2026-102764 RCE).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: AD CS Certificate Issuance from Anomalous Requester (ESC1/ESC8)

### Detection Opportunity

AD CS certificate requested via NTLM relay or Kerberos abuse using sensitive certificate templates by unexpected requester accounts, consistent with ESC1/ESC8 exploitation following help desk impersonation.

### Intelligence Context

- Microsoft Security Blog: From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths — [https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/)
  - Context: Attackers relayed authentication to AD CS after gaining remote access via Teams impersonation, requesting certificates using sensitive templates under unexpected requester identities to achieve privilege escalation via ESC1/ESC8 paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1557, T1550
- Products: Active Directory Certificate Services, Kerberos
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1557, T1550, Active Directory Certificate Services, Kerberos, Windows

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1550 Use Alternate Authentication Material (high); Initial Access: T1557 Adversary-in-the-Middle (medium)

### Deployment Gates

- EventData regex extraction of 'Requester' and 'Certificate Template Name' fields depends on the raw XML structure of CA audit events; if EventData is not ingested in raw XML form, all extractions will return empty strings and the query will produce no meaningful results.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let LookbackWindow = 2d;
let CorrelationWindow = 10m;
let SensitiveTemplates = dynamic(["SubCA", "DomainController", "DomainControllerAuthentication", "KerberosAuthentication", "SmartCardLogon", "Administrator"]);
let CertRequests = SecurityEvent
| where TimeGenerated >= ago(LookbackWindow)
| where EventID in (4886, 4887)
| extend RequesterName = tostring(extract(@"(?i)Requester:\s*([^\r\n]+)", 1, EventData))
| extend TemplateName = tostring(extract(@"(?i)Certificate Template Name:\s*([^\r\n]+)", 1, EventData))
| where isnotempty(RequesterName)
| where TemplateName in~ (SensitiveTemplates) or (isnotempty(SubjectUserName) and RequesterName !~ SubjectUserName)
| project CertTime = TimeGenerated, RequesterName = trim(" ", RequesterName), TemplateName = trim(" ", TemplateName), SubjectUserName, IpAddress, WorkstationName, CertEventID = EventID;
let KerbTGTs = SecurityEvent
| where TimeGenerated >= ago(LookbackWindow)
| where EventID == 4768
| project KerbTime = TimeGenerated, KerbUser = tostring(TargetUserName), KerbIP = tostring(IpAddress);
CertRequests
| join kind=inner (
    KerbTGTs
) on $left.RequesterName == $right.KerbUser
| where CertTime between (KerbTime .. (KerbTime + CorrelationWindow))
| project CertTime, KerbTime, RequesterName, TemplateName, SubjectUserName, IpAddress, WorkstationName, CertEventID, KerbIP
| extend TimeDeltaSeconds = datetime_diff('second', CertTime, KerbTime)
| order by CertTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate smart card enrollment stations where an enrollment agent account requests certificates on behalf of users will trigger the requester mismatch condition.
- Automated certificate lifecycle management tools that request certificates using service accounts will match the template filter.
- Domain controller auto-enrollment for DomainController template will generate matching events.

**Tuning notes:**
- Expand SensitiveTemplates to include any environment-specific templates that grant client authentication, domain controller impersonation, or smart card logon EKUs.
- Add '| where not(RequesterName endswith "$")' to exclude computer account auto-enrollment if needed.
- Adjust LookbackWindow based on scheduled rule frequency to avoid duplicate alerts.

**Risks / caveats:**
- EventID 4886 and 4887 are only generated on CA servers with 'Issue and manage certificate requests' audit policy enabled; these events are absent from most Sentinel SecurityEvent ingestion pipelines unless the CA server is explicitly onboarded.
- EventData regex extraction of 'Requester' and 'Certificate Template Name' fields depends on the raw XML structure of CA audit events; if EventData is not ingested in raw XML form, all extractions will return empty strings and the query will produce no meaningful results.
- EventID 4768 Pre-Authentication Type field extraction via regex on EventData requires the domain controller Security Event log to be forwarded with full EventData XML; structured field parsing may differ by connector configuration.
- The 10-minute correlation window between Kerberos TGT and certificate request may need adjustment based on observed attack dwell time in the environment.

### Triage Runbook

**First 15 minutes:**
- Identify the requester, template, subject, and source IP/workstation from the alert and confirm whether the requester is expected to use that template.
- Check whether the requester account is a machine account, enrollment agent, PKI admin, or a help desk/service account that legitimately requests certificates on behalf of others.
- Validate whether the certificate subject or template indicates privileged use such as DomainController, SmartCardLogon, KerberosAuthentication, or Administrator.
- Correlate the certificate issuance time with nearby Kerberos TGT activity and look for immediate PKINIT use from the same or a different IP.

**Evidence to collect:**
- CA audit event details for the issuance request, including requester, template name, subject, serial number, and source IP.
- Domain controller 4768 events around the same time, especially pre-authentication type 16 and the target account.
- Account history for the requester and target account, including group membership, recent password resets, and recent privilege changes.
- Any related help desk, remote access, or identity verification activity that could explain the request.

**Pivot points:**
- SecurityEvent for EventID 4886 and 4887 on the CA server to enumerate related certificate requests and issuances.
- SecurityEvent for EventID 4768 on domain controllers to find PKINIT logons for the same account shortly after issuance.
- SecurityEvent for EventID 4769 and 4771 to identify follow-on Kerberos activity or failures from the same account or IP.
- If available, correlate with sign-in or endpoint telemetry for the requester workstation to identify the originating host and user session.

**Benign explanations:**
- Legitimate smart card enrollment or renewal by a user who recently received a new certificate.
- Enrollment agent or PKI administrator activity performed as part of normal certificate operations.
- Domain controller or computer auto-enrollment for approved templates in environments that use automated PKI workflows.

**Escalation criteria:**
- The requester is not authorized to use the template or is requesting a certificate for a different subject than expected.
- The issued certificate is for a sensitive template and is followed by PKINIT from a different IP, host, or unusual location.
- The requester account is newly created, recently privileged, or associated with help desk impersonation or relay activity.
- Multiple anomalous certificate requests occur in a short period or involve privileged templates.

**Containment actions:**
- Disable or reset the requester account if it is confirmed compromised and not a service or admin account.
- Revoke the suspicious certificate and any related certificates issued in the same abuse chain.
- Block or isolate the source host if it is confirmed to be the attacker foothold or relay point.
- Escalate to PKI and identity teams to review template permissions and enrollment agent trust relationships.

**Closure criteria:**
- The requester and template are confirmed legitimate and the issuance aligns with approved PKI workflow.
- No suspicious PKINIT, privilege escalation, or follow-on authentication activity is found.
- The certificate was revoked or otherwise accounted for and the alert is explained by documented administrative activity.

<br/>
---
<br/>

## Detection 2: Kerberos PKINIT Authentication Following AD CS Certificate Issuance

### Detection Opportunity

Kerberos TGT requested using certificate-based pre-authentication (PKINIT) shortly after an AD CS certificate was issued, indicating pass-the-certificate abuse following ESC1/ESC8 exploitation.

### Intelligence Context

- Microsoft Security Blog: From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths — [https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/)
  - Context: After obtaining a certificate via relay abuse, attackers used PKINIT Kerberos pre-authentication to request TGTs for privileged accounts, completing the pass-the-certificate chain described in the ESC1/ESC8 intrusion path.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1550, T1557
- Products: Active Directory Certificate Services, Kerberos
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1550, T1557, Active Directory Certificate Services, Kerberos, Windows

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1550 Use Alternate Authentication Material (high); Initial Access: T1557 Adversary-in-the-Middle (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let LookbackWindow = 2d;
let CorrelationWindow = 15m;
let CertIssued = SecurityEvent
| where TimeGenerated >= ago(LookbackWindow)
| where EventID == 4887
| extend IssuedTo = trim(" ", tostring(extract(@"(?i)Subject:\s*([^\r\n]+)", 1, EventData)))
| where isnotempty(IssuedTo)
| project IssueTime = TimeGenerated, IssuedTo, CertIP = tostring(IpAddress);
let PKINITLogons = SecurityEvent
| where TimeGenerated >= ago(LookbackWindow)
| where EventID == 4768
| extend PreAuthType = trim(" ", tostring(extract(@"(?i)Pre-Authentication Type:\s*(\d+)", 1, EventData)))
| where PreAuthType == "16"
| project LogonTime = TimeGenerated, TargetUserName = tostring(TargetUserName), LogonIP = tostring(IpAddress), TicketEncryptionType = tostring(TicketEncryptionType);
PKINITLogons
| join kind=inner (
    CertIssued
) on $left.TargetUserName == $right.IssuedTo
| where LogonTime between (IssueTime .. (IssueTime + CorrelationWindow))
| extend SuspiciousIPMismatch = (LogonIP != CertIP)
| extend TimeDeltaSeconds = datetime_diff('second', LogonTime, IssueTime)
| project LogonTime, IssueTime, TargetUserName, LogonIP, CertIP, TicketEncryptionType, SuspiciousIPMismatch, TimeDeltaSeconds
| order by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate smart card logons by users who recently enrolled a new certificate will match the PKINIT + recent issuance pattern.
- Certificate auto-renewal followed by immediate smart card logon will trigger this detection.
- VPN or remote access scenarios where the logon IP differs from the enrollment IP will set SuspiciousIPMismatch = true legitimately.

**Tuning notes:**
- Restrict TargetUserName to a watchlist of privileged or sensitive accounts to reduce smart card logon noise.
- If the CA Subject field contains a DN (e.g., 'CN=user,DC=domain,DC=com'), update the IssuedTo extraction to parse only the CN component: extract(@'CN=([^,]+)', 1, IssuedTo).
- Consider adding TicketEncryptionType == '0x17' (RC4) as an additional risk indicator for pass-the-ticket downgrade.

**Risks / caveats:**
- EventID 4887 is only generated on CA servers with certificate issuance auditing enabled; absent from standard Sentinel SecurityEvent ingestion unless the CA server is explicitly onboarded.
- Pre-Authentication Type field in EventID 4768 EventData is only populated when Kerberos pre-authentication auditing is enabled at the domain controller level; value '16' for PKINIT must be confirmed present in the environment.
- The 'Subject' field extraction from EventID 4887 EventData to derive IssuedTo may not match TargetUserName format in EventID 4768 (e.g., UPN vs. SAMAccountName), causing the join to return no results.
- The join key matching TargetUserName (SAMAccountName from EventID 4768) to IssuedTo (Subject DN from EventID 4887) may fail if the Subject field contains a full Distinguished Name rather than a plain account name; the extraction regex may need adjustment based on actual CA Subject field format.

### Triage Runbook

**First 15 minutes:**
- Identify the target account, logon IP, certificate issuance time, and whether the certificate subject matches the account expected to authenticate.
- Check whether the account is privileged or sensitive and whether the logon originated from an unusual IP, host, or geographic location.
- Review the certificate issuance event that preceded the logon and confirm the template and requester were legitimate.
- Look for immediate follow-on activity such as privileged group access, directory changes, or lateral movement from the same account.

**Evidence to collect:**
- EventID 4768 details including pre-authentication type, target user, IP address, and ticket encryption type.
- The corresponding certificate issuance event with subject, requester, template, and CA host details.
- Account context for the target user, including privilege level, recent password changes, and smart card enrollment history.
- Any related 4769, 4771, or sign-in telemetry showing subsequent service ticket requests or failed authentication attempts.

**Pivot points:**
- SecurityEvent EventID 4768 to find other PKINIT logons by the same account or from the same IP.
- SecurityEvent EventID 4887 to validate the certificate issuance chain and identify the requester.
- SecurityEvent EventID 4769 and 4771 to identify service ticket requests or authentication failures after the PKINIT event.
- If available, endpoint or identity logs for the source host to determine whether the logon was interactive, remote, or automated.

**Benign explanations:**
- A user legitimately logging on with a newly issued smart card or certificate.
- Certificate auto-renewal followed by immediate use for normal authentication.
- Remote access or VPN scenarios where the logon IP differs from the certificate enrollment IP.

**Escalation criteria:**
- The account is privileged and the certificate issuance was anomalous or mismatched to the user.
- The PKINIT logon occurs from an unexpected IP or host shortly after suspicious certificate issuance.
- The account shows signs of abuse such as unusual ticket encryption, rapid privilege use, or concurrent suspicious activity.
- The certificate subject or requester does not align with the target account.

**Containment actions:**
- Disable or reset the affected account if abuse is confirmed and the account is not a service account.
- Revoke the suspicious certificate and coordinate with PKI administrators to invalidate related issuance if needed.
- Isolate the source host if it is a suspected attacker system or relay point.
- Force credential hygiene actions for the affected account, including password reset and smart card/certificate review.

**Closure criteria:**
- The PKINIT event is matched to a legitimate certificate issuance and approved user activity.
- No suspicious follow-on authentication, privilege use, or lateral movement is observed.
- Any mismatched IP or host is explained by known remote access, VPN, or smart card workflow.

<br/>
---
<br/>

## Detection 3: BeyondTrust Web Service Spawning Shell Process (CVE-2026-102764 RCE)

### Detection Opportunity

BeyondTrust Remote Support web service process spawning an OS-level shell or interpreter as a child process, indicating successful remote code execution following unauthenticated file upload via CVE-2026-102764.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Unauthenticated File Upload to RCE in BeyondTrust Remote Support (CVE-2026-102764) — [https://www.rapid7.com/blog/post/ra-rapid7-analysis-unauthenticated-file-upload-to-rce-in-beyondtrust-remote-support-cve-2026-102764](https://www.rapid7.com/blog/post/ra-rapid7-analysis-unauthenticated-file-upload-to-rce-in-beyondtrust-remote-support-cve-2026-102764)
  - Context: An unauthenticated attacker exploited the public customer connection endpoint to write files to the BeyondTrust appliance and execute code as the OS user, with the web service process acting as the parent of spawned shell commands.

### Search Metadata

- CVEs: CVE-2026-102764
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: BeyondTrust Remote Support
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-102764, T1190, T1059, BeyondTrust Remote Support

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let BeyondTrustParents = dynamic(["bomgar-scc", "bomgar-rep", "btapp"]);
let BeyondTrustParentsExtended = dynamic(["bomgar-scc", "bomgar-rep", "btapp", "php", "php-fpm"]);
let ShellProcesses = dynamic(["bash", "sh", "dash", "cmd.exe", "powershell.exe", "python", "python3", "perl", "ruby"]);
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where (
    InitiatingProcessFileName has_any (BeyondTrustParents)
    or InitiatingProcessParentFileName has_any (BeyondTrustParents)
    or InitiatingProcessFileName has_any (BeyondTrustParentsExtended)
  )
| where FileName has_any (ShellProcesses)
| extend RiskIndicator = case(
    ProcessCommandLine has "-c" or ProcessCommandLine has "-e" or ProcessCommandLine has "exec" or ProcessCommandLine has "eval", "CommandExecution",
    ProcessCommandLine has "wget" or ProcessCommandLine has "curl" or ProcessCommandLine has "nc" or ProcessCommandLine has "ncat", "NetworkTool",
    "ShellSpawn"
  )
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName, ProcessCommandLine, ActionType, RiskIndicator,
    InitiatingProcessSHA1, SHA1
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative scripts executed by BeyondTrust service accounts that invoke shell interpreters for maintenance tasks.
- Monitoring or health-check agents running under the BeyondTrust service user that spawn shell commands.

**Tuning notes:**
- Add '| where DeviceName has "beyondtrust"' or a specific hostname filter to scope the query to the BeyondTrust appliance.
- Validate actual BeyondTrust service process names by running: DeviceProcessEvents → where DeviceName contains "<appliance-hostname>" → summarize count() by InitiatingProcessFileName → top 20 by count_
- Consider adding a DeviceNetworkEvents correlation for inbound connections on ports 80/443 to the appliance within 5 minutes before the shell spawn as a higher-confidence signal.

**Risks / caveats:**
- MDE agent must be deployed and operational on the BeyondTrust appliance; if the appliance runs as a hardened virtual appliance or unsupported OS, DeviceProcessEvents will be absent for this host.
- InitiatingProcessParentFileName is a valid DeviceProcessEvents field but may not be populated for all process creation events depending on MDE sensor version and OS.
- Without a DeviceName filter scoped to the BeyondTrust appliance, this query will match any PHP or shell process on any MDE-enrolled host; adding a DeviceName filter is strongly recommended before scheduling.
- BeyondTrust process names vary by product version and installation type; the BeyondTrustParents list should be validated against the installed version's process listing.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process, child shell/interpreter, command line, and device name match the BeyondTrust appliance.
- Check whether the shell spawn occurred immediately after inbound web traffic or an unusual request to the public customer connection endpoint.
- Identify the account context and whether the spawned process launched network tools, downloaders, or privilege-changing commands.
- Assess whether the appliance is still reachable and whether there are signs of additional spawned processes or persistence.

**Evidence to collect:**
- DeviceProcessEvents for the parent and child process chain, including command lines and hashes.
- Any available web access logs or reverse proxy logs showing inbound requests to the appliance around the alert time.
- Process ancestry and any subsequent child processes, especially curl, wget, nc, bash, sh, python, or powershell.
- Host inventory details confirming the appliance version, exposure, and whether MDE coverage is complete.

**Pivot points:**
- DeviceProcessEvents on the appliance host to enumerate all child processes from the same parent around the alert time.
- DeviceNetworkEvents to identify outbound connections from the appliance after the shell spawn.
- DeviceFileEvents to look for new or modified files on the appliance, especially web roots, temp directories, or startup locations.
- If available, web server or appliance logs to correlate the inbound request that preceded execution.

**Benign explanations:**
- Legitimate vendor maintenance or administrative scripts executed by a known service account.
- Health-check or monitoring tooling that spawns shell commands on the appliance.
- A non-malicious administrative action on a test or staging appliance that resembles shell execution.

**Escalation criteria:**
- The child process is an interactive shell or interpreter with suspicious command-line arguments or download behavior.
- There are outbound connections, file writes, or additional child processes consistent with post-exploitation activity.
- The appliance is internet-facing and the process chain aligns with the known CVE exploitation pattern.
- No approved maintenance activity explains the process creation.

**Containment actions:**
- Isolate the BeyondTrust appliance from the network if exploitation is strongly suspected and business impact is acceptable.
- Preserve volatile and process evidence before rebooting or patching the appliance.
- Block inbound access to the exposed service until the appliance is patched or remediated.
- Coordinate with the vendor and platform owners to rotate any credentials or secrets stored on the appliance.

**Closure criteria:**
- The process creation is confirmed as legitimate maintenance or monitoring activity.
- No suspicious follow-on processes, network activity, or file changes are found.
- The appliance is patched or otherwise protected and the alert is attributable to approved administration.

<br/>
---
<br/>

## Detection 4: IDE Extension Writing to SSH Authorized Keys or Spawning SSH Daemon

### Detection Opportunity

Malicious Cursor or VS Code extension process writing to SSH authorized_keys files or spawning SSH-related processes to establish a persistent backdoor on a developer host.

### Intelligence Context

- Microsoft Security Blog: Inside a malicious Claude Code-branded extension and its persistent SSH backdoor — [https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
  - Context: A malicious extension disguised as Claude Code branding was installed in the Cursor IDE and established persistence by writing to SSH authorized_keys and launching SSH daemon processes, enabling persistent remote backdoor access to developer workstations.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1547, T1053, T1547.001
- Products: Claude Code, Cursor
- Platforms: SSH
- Malware: Not specified
- Tools: Not specified
- Search tags: T1547, T1053, Claude Code, Cursor, SSH, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (low); Persistence: T1053 Scheduled Task/Job (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let IDEParents = dynamic(["cursor", "code", "node", "extensionHost", "Cursor.exe", "Code.exe"]);
let SSHKeyWrites = DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where (FolderPath has ".ssh/" or FolderPath endswith ".ssh")
    and FileName =~ "authorized_keys"
    and InitiatingProcessFileName has_any (IDEParents)
| project TimeGenerated, DeviceName, AccountName,
    FolderPath, FileName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    ActionType, InitiatingProcessSHA1,
    ProcessCommandLine = "",
    SHA1 = ""
| extend SignalType = "SSHKeyWrite";
let SSHProcessSpawn = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName has_any (IDEParents)
    and FileName in~ ("sshd", "ssh-keygen", "ssh")
| project TimeGenerated, DeviceName, AccountName,
    FolderPath = "",
    FileName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    ActionType, InitiatingProcessSHA1,
    ProcessCommandLine, SHA1
| extend SignalType = "SSHProcessSpawn";
union SSHKeyWrites, SSHProcessSpawn
| project TimeGenerated, DeviceName, AccountName, FolderPath, FileName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    ProcessCommandLine, ActionType, SignalType,
    InitiatingProcessSHA1, SHA1
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer tooling that legitimately manages SSH keys (e.g., GitHub CLI, SSH key rotation scripts) running under a Node.js or IDE process.
- VS Code Remote SSH extension operations that invoke ssh-keygen or write to authorized_keys as part of legitimate remote development setup.
- Infrastructure-as-code tools running inside an IDE terminal that manage SSH keys.

**Tuning notes:**
- Add '| where AccountName !in ("<automation-account-1>", "<automation-account-2>")' to exclude known SSH key management service accounts.
- Consider adding InitiatingProcessCommandLine has 'extensions' as an additional filter to narrow to extension host contexts specifically.
- For macOS environments, validate that FolderPath patterns capture /Users/ home directory paths correctly.

**Risks / caveats:**
- DeviceFileEvents coverage of writes to user home directory .ssh paths on Linux requires MDE Linux agent deployment on developer workstations; macOS home directory paths differ from Linux and may require separate FolderPath patterns.
- The IDEParents list uses partial name matching via has_any(); 'node' and 'code' are short strings that may match unintended process names (e.g., 'nodemon', 'vscode-server'); consider using more specific matching if noise is observed.
- On macOS, the authorized_keys path is typically under /Users/<username>/.ssh/ and FolderPath patterns should be validated for the OS in use.
- VS Code Remote SSH extension legitimately invokes ssh-keygen during setup; AccountName allowlisting may be needed for developer accounts using this feature.

### Triage Runbook

**First 15 minutes:**
- Identify the host, user, initiating process, and whether the activity came from Cursor, VS Code, or a related extension host.
- Inspect the file path and confirm whether authorized_keys was created or modified in a user home .ssh directory.
- Review the process command line for sshd, ssh-keygen, or ssh usage and determine whether it was expected for the user.
- Check for concurrent signs of compromise such as new autoruns, suspicious downloads, or unusual remote connections.

**Evidence to collect:**
- DeviceFileEvents showing the exact file path, timestamp, and initiating process for authorized_keys changes.
- DeviceProcessEvents for sshd, ssh-keygen, or ssh process creation and their parent/ancestor chain.
- User context for the affected account, including whether the user is a developer, automation account, or CI/CD agent.
- Any recent extension installs, IDE plugin changes, or remote development sessions on the host.

**Pivot points:**
- DeviceFileEvents to find other .ssh file modifications on the same host or by the same process.
- DeviceProcessEvents to enumerate related shell, scripting, or network processes spawned by the IDE or extension host.
- DeviceNetworkEvents to identify inbound or outbound SSH connections around the alert time.
- DeviceLogonEvents or identity telemetry to determine whether the user had a remote session or unusual logon pattern.

**Benign explanations:**
- Legitimate VS Code Remote SSH setup or developer onboarding activity.
- Infrastructure automation or configuration management tools that manage SSH keys on developer or build hosts.
- A developer intentionally rotating SSH keys or configuring remote access for a sanctioned project.

**Escalation criteria:**
- authorized_keys was modified by an IDE or extension process without a clear business justification.
- sshd or related SSH processes were spawned unexpectedly on a developer workstation.
- The host shows additional persistence, suspicious network activity, or evidence of unauthorized remote access.
- The user denies the activity or the account is not expected to manage SSH access.

**Containment actions:**
- Isolate the host if unauthorized persistence or remote access is confirmed.
- Remove unauthorized SSH keys and disable any suspicious SSH service or listener.
- Reset the affected user credentials and revoke any exposed access tokens or keys.
- Preserve the host for forensic review if the activity appears malicious.

**Closure criteria:**
- The file or process activity is confirmed as legitimate developer or automation workflow.
- No unauthorized SSH access, persistence, or additional compromise indicators are found.
- Any modified keys or services are documented and approved by the host owner.

<br/>
---
<br/>

## Detection 5: PHP or Web Server Process Spawning Interactive Shell (CVE-2026-109618/CVE-2026-109619)

### Detection Opportunity

PHP-FPM, Apache, or Nginx worker process spawning an interactive shell or interpreter as a child process following inbound web requests, indicating successful exploitation of critical PHP vulnerabilities CVE-2026-109618 or CVE-2026-109619.

### Intelligence Context

- Unit 42: Threat Brief: Critical Vulnerabilities in PHP: CVE-2026-109618, CVE-2026-109619 (Updated October 29) — [https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/)
  - Context: Critical PHP vulnerabilities allow remote attackers to achieve code execution through exposed PHP applications; post-exploitation is observable as web server or PHP-FPM processes spawning OS-level shell commands, which Unit 42 identified as the primary monitoring focus for these CVEs.

### Search Metadata

- CVEs: CVE-2026-109618, CVE-2026-109619
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: PHP
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-109618, CVE-2026-109619, T1190, PHP

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let WebParents = dynamic(["php", "php-fpm", "php8", "php7", "apache2", "httpd", "nginx", "lighttpd"]);
let ShellChildren = dynamic(["bash", "sh", "dash", "zsh", "cmd.exe", "powershell.exe", "python", "python3", "perl", "ruby", "wget", "curl"]);
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName has_any (WebParents)
    and FileName has_any (ShellChildren)
| extend RiskIndicator = case(
    ProcessCommandLine has "-c" or ProcessCommandLine has "-e" or ProcessCommandLine has "exec" or ProcessCommandLine has "eval", "CommandExecution",
    ProcessCommandLine has "wget" or ProcessCommandLine has "curl" or ProcessCommandLine has "nc" or ProcessCommandLine has "ncat", "NetworkTool",
    ProcessCommandLine has "chmod" or ProcessCommandLine has "chown", "PermissionChange",
    "ShellSpawn"
  )
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName, ProcessCommandLine, ActionType, RiskIndicator,
    InitiatingProcessSHA1, SHA1
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- PHP-based deployment or configuration management tools that invoke shell commands as part of legitimate application lifecycle operations.
- Web application frameworks that use shell_exec() or similar PHP functions for legitimate administrative tasks.
- Monitoring agents running under the web server user that spawn shell commands for health checks.

**Tuning notes:**
- Add versioned PHP binary names to WebParents: extend WebParents with dynamic(["php8.1", "php8.2", "php7.4", "php-fpm8.1", "php-fpm8.2"]) or update the let statement directly.
- Add '| where DeviceName in ("webserver1", "webserver2")' or use a device group tag filter to scope to PHP web servers.
- Consider adding a DeviceNetworkEvents correlation for inbound connections on ports 80/443 within 2 minutes before the shell spawn to increase confidence.

**Risks / caveats:**
- MDE Linux agent must be deployed on PHP web servers for DeviceProcessEvents telemetry to be available; Linux web servers without MDE will produce no results.
- On some Linux distributions, PHP-FPM worker processes may appear with versioned binary names (php8.1-fpm, php7.4) not covered by the base WebParents list; these must be added via tuning.
- Versioned PHP binary names (php8.1, php8.2, php7.4, php-fpm8.2) are not in the base WebParents list and must be added to match the specific PHP versions deployed in the environment.
- The query will match any host with MDE deployed running PHP; scoping to specific web server hostnames or device groups is recommended in environments with mixed workloads.

### Triage Runbook

**First 15 minutes:**
- Identify the server, parent web process, child shell/interpreter, and command line from the alert.
- Check whether the process spawn followed an inbound web request or unusual traffic to the application.
- Determine whether the child process performed command execution, downloaded payloads, changed permissions, or created new files.
- Assess whether the affected host is internet-facing and whether additional suspicious processes are present.

**Evidence to collect:**
- DeviceProcessEvents showing the full parent-child process chain and command lines.
- DeviceNetworkEvents for inbound and outbound connections around the alert time.
- DeviceFileEvents for new or modified files, especially web roots, temp directories, or executable locations.
- Web server or application logs that show the request path, source IP, and HTTP method preceding the process spawn.

**Pivot points:**
- DeviceProcessEvents to find all child processes from the same web server parent on the host.
- DeviceNetworkEvents to identify outbound connections, especially to unusual IPs or ports after the spawn.
- DeviceFileEvents to look for dropped web shells, scripts, or modified application files.
- Web or reverse proxy logs to correlate the inbound request and identify the source IP and URI.

**Benign explanations:**
- Legitimate application behavior where PHP or web tooling invokes shell commands for maintenance or administration.
- Development or staging environments where shell execution from web processes is expected.
- Monitoring or backup scripts running under the web server context for approved operational tasks.

**Escalation criteria:**
- The child process is an interactive shell or interpreter with suspicious arguments or payload staging behavior.
- There is evidence of outbound connections, file drops, permission changes, or additional process spawning.
- The host is internet-facing and the timing aligns with a suspicious inbound request.
- No approved application or administrative workflow explains the process creation.

**Containment actions:**
- Isolate the web server if exploitation is strongly suspected and business impact is acceptable.
- Block or restrict inbound access to the affected application until it is patched or remediated.
- Preserve logs and process evidence before restarting services or applying fixes.
- Coordinate with application owners to rotate secrets and review exposed credentials if compromise is confirmed.

**Closure criteria:**
- The process spawn is explained by approved application behavior or known maintenance activity.
- No suspicious follow-on activity, file changes, or outbound connections are observed.
- The vulnerable application is patched or otherwise mitigated and the alert is attributable to benign activity.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- AD CS Certificate Issuance from Anomalous Requester (ESC1/ESC8): EventData regex extraction of 'Requester' and 'Certificate Template Name' fields depends on the raw XML structure of CA audit events; if EventData is not ingested in raw XML form, all extractions will return empty strings and the query will produce no meaningful results.

**Telemetry availability:**
- Kerberos PKINIT Authentication Following AD CS Certificate Issuance: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Other deployment dependency:**
- BeyondTrust Web Service Spawning Shell Process (CVE-2026-102764 RCE): Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- SecurityEvent: shared by AD CS Certificate Issuance from Anomalous Requester (ESC1/ESC8); Kerberos PKINIT Authentication Following AD CS Certificate Issuance
- DeviceProcessEvents: shared by BeyondTrust Web Service Spawning Shell Process (CVE-2026-102764 RCE); IDE Extension Writing to SSH Authorized Keys or Spawning SSH Daemon; PHP or Web Server Process Spawning Interactive Shell (CVE-2026-109618/CVE-2026-109619)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: IDE Extension Writing to SSH Authorized Keys or Spawning SSH Daemon; PHP or Web Server Process Spawning Interactive Shell (CVE-2026-109618/CVE-2026-109619).
2. Resolve environment-mapping detections next: AD CS Certificate Issuance from Anomalous Requester (ESC1/ESC8); Kerberos PKINIT Authentication Following AD CS Certificate Issuance; BeyondTrust Web Service Spawning Shell Process (CVE-2026-102764 RCE).

### Hunting Agenda and Promotion Criteria

- AD CS Certificate Issuance from Anomalous Requester (ESC1/ESC8): EventData regex extraction of 'Requester' and 'Certificate Template Name' fields depends on the raw XML structure of CA audit events; if EventData is not ingested in raw XML form, all extractions will return empty strings and the query will produce no meaningful results.; prove correlation keys join correctly on real tenant telemetry.
- Kerberos PKINIT Authentication Following AD CS Certificate Issuance: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; prove correlation keys join correctly on real tenant telemetry.
- BeyondTrust Web Service Spawning Shell Process (CVE-2026-102764 RCE): Defender for Endpoint file-event coverage must be confirmed on the target host population..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
