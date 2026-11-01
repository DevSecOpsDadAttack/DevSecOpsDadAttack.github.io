---
layout: post
title: "Detection Engineering Brief - Sunday, November 1, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-01
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Claude Code
  - Cursor
  - Windows
  - macOS
  - Linux
  - T1053
  - Active Directory Certificate Services
  - AD CS
  - Kerberos
  - Active Directory
  - T1134
  - T1550
  - T1558
  - CVE-2026-102764
  - BeyondTrust Remote Support
  - T1190
  - T1059
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Claude Code, Cursor, Windows, macOS, Linux, T1053, Active Directory Certificate Services, AD CS, Kerberos, Active Directory, T1134, T1550, T1558, CVE-2026-102764, BeyondTrust Remote Support, T1190, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Malicious IDE Extension Installation Masquerading as Claude Code; AD CS Certificate Issued with Mismatched Requester and Subject Indicating ESC8 Relay Abuse; Kerberos Ticket Request Anomaly Following AD CS Certificate Issuance for Lateral Movement; Shell Process Spawned by BeyondTrust Web Service Indicating RCE via CVE-2026-102764.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SSH Backdoor Persistence via Scheduled Task from IDE Extension Process

### Detection Opportunity

Scheduled task or cron job created referencing SSH or authorized_keys by a process descended from an IDE extension host, consistent with a malicious Claude Code-branded Cursor extension establishing persistent SSH backdoor access.

### Intelligence Context

- Microsoft Security Blog: Inside a malicious Claude Code-branded extension and its persistent SSH backdoor — [https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
  - Context: A malicious extension masquerading as Claude Code in the Cursor IDE was reported to establish a persistent SSH backdoor using a scheduled task or equivalent persistence mechanism. The detection targets scheduled task creation events where the command line references SSH-related artifacts and the initiating process is an IDE or extension host.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1053
- Products: Claude Code, Cursor
- Platforms: Windows, macOS, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: Claude Code, Cursor, Windows, macOS, Linux, T1053

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1053 Scheduled Task/Job (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceEvents, DeviceNetworkEvents

### KQL

```kql
let SSHScheduledTasks = DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where ProcessCommandLine has_any ("ssh", "authorized_keys", ".ssh/", "sshd")
| where InitiatingProcessFileName has_any ("cursor", "code", "node", "electron")
| project DeviceId, DeviceName, AccountName, Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType;
let SSHOutbound = DeviceNetworkEvents
| where RemotePort == 22
| where RemoteIP !in ("127.0.0.1", "::1")
| where not(ipv4_is_private(RemoteIP))
| where InitiatingProcessFileName has_any ("cursor", "code", "node", "electron")
| project DeviceId, NetworkTimestamp = Timestamp, RemoteIP, InitiatingProcessFileName;
SSHScheduledTasks
| join kind=inner SSHOutbound on DeviceId
| where NetworkTimestamp between (Timestamp .. datetime_add('minute', 10, Timestamp))
| project DeviceName, AccountName, Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, NetworkTimestamp
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developers who legitimately configure SSH keys or scheduled tasks from within Cursor or VS Code and then connect to remote hosts via SSH within the correlation window.
- CI/CD automation running inside Electron-based IDEs that schedules SSH-based deployment tasks.
- Remote development extensions that legitimately manage SSH configuration files.

**Tuning notes:**
- Expand InitiatingProcessFileName to include additional IDE binary names present in the environment such as windsurf, zed, or jetbrains-specific process names.
- If RFC1918 SSH connections are legitimate in the environment (e.g., connecting to local VMs), remove the ipv4_is_private filter and replace with a specific allowlist of known internal SSH targets.
- Consider adding a DeviceProcessEvents lookup to confirm the initiating process parent chain traces back to the Cursor extension host for higher-confidence alerts.

**Risks / caveats:**
- ScheduledTaskCreated ActionType in DeviceEvents requires Defender for Endpoint with Windows audit policy enabling scheduled task creation events; this ActionType is not generated on macOS or Linux hosts via the same mechanism and may be absent if the DfE sensor version does not surface it.
- DeviceProcessEvents was listed as a required table in the original detection but is not used in the query; removed to avoid confusion. No functional impact.
- The 10-minute correlation window between task creation and outbound SSH may miss slow-moving attackers who delay their first connection; consider extending to 30 minutes if dwell-time analysis supports it.
- ipv4_is_private() does not filter IPv6 private ranges; if the environment uses IPv6 for SSH, additional filtering may be needed.

### Triage Runbook

**First 15 minutes:**
- Confirm the scheduled task or cron-like artifact was created by a process descended from Cursor, VS Code, node, or electron rather than a known updater.
- Review the task command line for SSH-related artifacts such as ssh, sshd, authorized_keys, .ssh paths, or scripts that modify SSH configuration.
- Check whether the same host made an outbound connection on port 22 within the alert window and identify the destination IP and account used.
- Validate whether the initiating user is a developer or automation account expected to manage SSH keys or remote development tooling.
- If the task and SSH connection are both unexpected, treat the host as potentially compromised and preserve volatile evidence before making changes.

**Evidence to collect:**
- DeviceName, AccountName, Timestamp, ProcessCommandLine, InitiatingProcessFileName, and InitiatingProcessCommandLine from the alert.
- RemoteIP and NetworkTimestamp for the correlated SSH connection.
- The full scheduled task definition or cron entry, including the exact action and trigger.
- Parent/child process chain for the initiating process to confirm whether it originated from an IDE extension host.
- Recent changes to SSH configuration files, authorized_keys, and any newly created user accounts or keys.

**Pivot points:**
- DeviceEvents for additional ScheduledTaskCreated events from the same DeviceId or AccountName.
- DeviceNetworkEvents for other outbound connections on port 22 or to the same RemoteIP from the same host or user.
- DeviceFileEvents for writes to .ssh, authorized_keys, sshd_config, or extension directories around the same time.
- DeviceProcessEvents to reconstruct the parent chain of the initiating process and identify any follow-on shell activity.

**Benign explanations:**
- A developer legitimately used Cursor or VS Code to configure SSH access for a remote lab, VM, or build host.
- An automation script or CI/CD workflow created a scheduled task to manage deployment over SSH.
- A remote development extension legitimately updated SSH keys or related configuration during setup.

**Escalation criteria:**
- The scheduled task modifies SSH persistence artifacts and the outbound SSH destination is not a known internal development target.
- The initiating process chain shows an unexpected extension host, script interpreter, or downloaded payload rather than a trusted updater.
- There is evidence of additional suspicious activity such as new user creation, credential access, or lateral movement from the same host.
- The user denies performing the action or the activity occurs on a non-developer endpoint.

**Containment actions:**
- Isolate the host from the network if the SSH persistence is unauthorized or the destination is unknown.
- Disable or remove the suspicious scheduled task or cron entry only after preserving evidence and confirming it is malicious.
- Revoke or rotate any SSH keys, tokens, or credentials that may have been exposed on the host.
- Block the suspicious RemoteIP if it is confirmed malicious and not required for business operations.

**Closure criteria:**
- The task was created by an approved developer workflow and the SSH destination is a known, authorized target.
- No unauthorized SSH persistence artifacts remain on the host after validation.
- The initiating process chain and user activity are consistent with documented administration or automation.
- No additional suspicious network, file, or process activity is found during the investigation window.

<br/>
---
<br/>

## Detection 2: Malicious IDE Extension Installation Masquerading as Claude Code

### Detection Opportunity

File write activity into IDE extension directories by a process other than the IDE updater, where the file path or name contains Claude Code branding, indicating potential installation of a trojanized extension.

### Intelligence Context

- Microsoft Security Blog: Inside a malicious Claude Code-branded extension and its persistent SSH backdoor — [https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
  - Context: The malicious extension was branded as Claude Code and installed into the Cursor IDE extension directory. Detection targets file creation events in IDE extension paths where the initiating process is not the expected IDE updater or marketplace installer, and the path or file name references Claude Code.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1053
- Products: Claude Code, Cursor
- Platforms: Windows, macOS, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: Claude Code, Cursor, Windows, macOS, Linux, T1053

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Persistence: T1053 Scheduled Task/Job (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (
    ".cursor/extensions",
    ".vscode/extensions",
    "cursor/extensions",
    ".cursor\\extensions",
    ".vscode\\extensions",
    "cursor\\extensions",
    "AppData\\Roaming\\Cursor\\User\\extensions",
    "AppData\\Roaming\\Code\\User\\extensions"
)
| where FolderPath has_any ("claude", "claudecode", "claude-code")
    or FileName has_any ("claude", "claudecode", "claude-code")
| where InitiatingProcessFileName !in~ (
    "cursor",
    "cursor-update",
    "code",
    "code-update",
    "cursor_installer",
    "code_installer",
    "cursor.exe",
    "code.exe"
)
| where InitiatingProcessFileName has_any (
    "python",
    "python3",
    "bash",
    "sh",
    "powershell",
    "pwsh",
    "cmd",
    "curl",
    "wget",
    "npm",
    "7z",
    "unzip",
    "tar",
    "chrome",
    "msedge",
    "firefox"
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developers who manually install or update the legitimate Claude Code extension using npm, a package manager, or a script will trigger this detection.
- Automated developer environment setup scripts that install extensions via CLI will match the initiating process filter.
- Extension development workflows where developers build and install their own extensions locally using node or npm.

**Tuning notes:**
- Add environment-specific IDE installer and updater process names to the exclusion list before scheduling.
- Consider adding a watchlist of known-good SHA256 hashes for the legitimate Claude Code extension to suppress known-good file writes.
- If node-initiated writes need to be included, add a secondary filter on InitiatingProcessCommandLine to distinguish npm install from arbitrary script execution.

**Risks / caveats:**
- FolderPath values for IDE extension directories differ between Windows (AppData\Roaming), macOS (~/.cursor/extensions), and Linux (~/.cursor/extensions or /home/*/.cursor/extensions); the query uses forward-slash paths which will not match Windows FolderPath values stored with backslashes in DeviceFileEvents.
- node is excluded from the initiating process positive list in the improved query because it is also a common legitimate extension installer; analysts should manually review node-initiated writes separately.
- The exclusion list for IDE updater processes is not exhaustive; environments with custom Cursor or VS Code deployment wrappers will need additional entries.
- SHA256 may be empty for some FileModified events depending on sensor configuration, limiting hash-based triage.

### Triage Runbook

**First 15 minutes:**
- Review the file path, file name, and SHA256 to confirm the write occurred in an IDE extension directory and references Claude Code branding.
- Identify the initiating process and determine whether it is a known installer, package manager, script interpreter, or an unexpected process.
- Check whether the account is a developer or automation account that commonly installs extensions manually or via CLI.
- Look for adjacent file writes in the same extension directory that indicate a full extension package rather than a single benign file update.
- If the write is unexpected, preserve the file hash and copy the artifact for analysis before the user can modify or remove it.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, and SHA256.
- The full directory listing of the affected extension folder, including package metadata and manifest files.
- Any recent downloads or archive extraction activity that could have staged the extension package.
- The parent process chain for the writer process to determine whether it originated from a browser, shell, or package manager.
- User confirmation of whether the extension was intentionally installed and from what source.

**Pivot points:**
- DeviceFileEvents for other writes to Cursor or VS Code extension directories by the same account or host.
- DeviceProcessEvents for package manager, shell, browser, or script activity preceding the file write.
- DeviceNetworkEvents for downloads from package registries, GitHub, or other extension distribution sources around the same time.
- DeviceFileEvents for the same SHA256 on other hosts to determine spread or reuse.

**Benign explanations:**
- A developer manually installed or updated the legitimate Claude Code extension using npm, a script, or a local package.
- An automated workstation setup script deployed extensions as part of a standard developer image build.
- A local extension development workflow wrote files into the extension directory during testing.

**Escalation criteria:**
- The file write came from an unexpected process and the extension package is unsigned, unfamiliar, or not sourced from an approved repository.
- The extension directory contains additional suspicious files such as post-install scripts, obfuscated code, or persistence logic.
- The same artifact appears on multiple hosts or is followed by suspicious SSH, credential, or shell activity.
- The user denies installing the extension or the endpoint is not a developer workstation.

**Containment actions:**
- Quarantine the suspicious extension package or remove it from the IDE extension directory after preserving evidence.
- Disable the affected IDE extension if it is installed and appears malicious.
- Block execution of the initiating process if it is clearly malicious or part of an unauthorized installer chain.
- Reset credentials or tokens used on the workstation if the extension had access to secrets or developer tooling.

**Closure criteria:**
- The file write is confirmed to be a legitimate extension installation or update from an approved source.
- The SHA256 matches a known-good package or approved internal artifact.
- No additional suspicious writes, downloads, or process activity are associated with the event.
- The user and workstation role align with expected extension management behavior.

<br/>
---
<br/>

## Detection 3: AD CS Certificate Issued with Mismatched Requester and Subject Indicating ESC8 Relay Abuse

### Detection Opportunity

AD CS certificate issuance events where the requester account differs from the certificate subject account, consistent with ESC8 authentication relay abuse used to obtain certificates for privilege escalation following help desk impersonation.

### Intelligence Context

- Microsoft Security Blog: From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths — [https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/)
  - Context: Attackers impersonated help desk personnel via Teams to gain remote access, then abused AD CS through authentication relay (ESC8) to obtain certificates for privilege escalation. EventID 4886 and 4887 with a requester account that differs from the certificate subject is the primary detectable signal for relay-based certificate abuse.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1134, T1550, T1558
- Products: Active Directory Certificate Services, AD CS, Kerberos
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Not specified
- Search tags: Active Directory Certificate Services, AD CS, Kerberos, Windows, Active Directory, T1134, T1550, T1558

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1134 Access Token Manipulation (low); Defense Evasion: T1550 Use Alternate Authentication Material (medium); Credential Access: T1558 Steal or Forge Kerberos Tickets (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let CertEvents = SecurityEvent
| where EventID in (4886, 4887)
| extend RequesterName = tostring(EventData.RequesterName)
| extend CertSubject = tostring(EventData.SubjectUserName)
| where isnotempty(RequesterName) and isnotempty(CertSubject)
| where RequesterName !endswith "$"
| where RequesterName !in~ ("ANONYMOUS LOGON", "SYSTEM")
| where tolower(RequesterName) != tolower(CertSubject)
| extend RequesterNameNorm = tolower(split(RequesterName, "\\")[-1])
| project CertTimestamp = TimeGenerated, Computer, RequesterName, RequesterNameNorm, CertSubject, EventID;
let RemoteLogons = SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where TargetUserName !endswith "$"
| where TargetUserName !in~ ("ANONYMOUS LOGON", "SYSTEM")
| extend LogonAccount = tolower(TargetUserName)
| project LogonTimestamp = TimeGenerated, LogonAccount, IpAddress, LogonComputer = Computer;
CertEvents
| join kind=inner RemoteLogons on $left.RequesterNameNorm == $right.LogonAccount
| where LogonTimestamp < CertTimestamp
| where CertTimestamp <= LogonTimestamp + 1h
| project CertTimestamp, LogonTimestamp, Computer, RequesterName, CertSubject, EventID, IpAddress, LogonComputer
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- PKI administrators or enrollment agents who are authorized to request certificates on behalf of other users will trigger this detection.
- Automated certificate lifecycle management tools that use a service account to enroll certificates for other principals.
- Web enrollment scenarios where a proxy account requests certificates on behalf of end users.

**Tuning notes:**
- Validate EventData.RequesterName and EventData.SubjectUserName field names by running: SecurityEvent → where EventID == 4887 → take 5 → project EventData before deploying.
- Add known PKI enrollment agent service account names to an exclusion filter on RequesterName to suppress authorized certificate-on-behalf-of workflows.
- If UPN-format account names appear in RequesterName, extend the normalization to extract the local part before the @ symbol.

**Risks / caveats:**
- EventID 4886 and 4887 are only generated on hosts running AD CS (Certificate Authority role) with the 'Audit Certification Services' policy enabled; if this audit category is not configured, the query returns no results.
- EventData.RequesterName and EventData.SubjectUserName are XML-parsed fields whose availability and exact names depend on the MMA/AMA agent version and the workspace's SecurityEvent table schema; these fields may be null or named differently (e.g., as parsed columns or within the raw EventData string) and must be validated before deployment.
- LogonType 10 (RemoteInteractive/RDP) events are generated on the target host, not the domain controller; the join between CA server events and logon events may span different Computer values, requiring the join to be on account name rather than Computer.
- The 1-hour correlation window between remote logon and certificate issuance may produce false positives in environments where help desk staff routinely log in remotely and later request certificates for users as part of normal operations.

### Triage Runbook

**First 15 minutes:**
- Validate the certificate event details: requester, subject, certificate template, and issuing CA.
- Check whether the requester is a known enrollment agent, PKI admin, or service account authorized to request certificates for others.
- Review the preceding remote interactive logon and identify the source host, IP address, and user context.
- Determine whether the subject account is privileged, a help desk account, or otherwise high value.
- If the requester and subject mismatch is not expected, treat the certificate as potentially abused and begin containment planning.

**Evidence to collect:**
- CertTimestamp, LogonTimestamp, Computer, RequesterName, CertSubject, EventID, IpAddress, and LogonComputer.
- The certificate template name, serial number, and any EKUs or authentication usages associated with the issued certificate.
- The source IP and host for the remote interactive logon that preceded issuance.
- Any related 4624, 4768, 4769, 4771, 4776, or 4672 events for the requester or subject account.
- PKI policy or enrollment agent documentation showing whether the requester is authorized.

**Pivot points:**
- SecurityEvent for additional 4886, 4887, 4624, 4768, 4769, and 4672 events tied to the requester or subject.
- SecurityEvent on the CA server for other certificate issuance events from the same requester or template.
- SecurityEvent on domain controllers for subsequent authentication activity by the subject account.
- If available, certificate services logs or CA management records for template and serial number validation.

**Benign explanations:**
- A PKI administrator or enrollment agent legitimately requested a certificate on behalf of another user.
- An automated certificate lifecycle tool used a service account to enroll or renew certificates.
- A web enrollment or proxy workflow intentionally separates requester and subject identities.

**Escalation criteria:**
- The requester is not an approved enrollment agent or PKI service account.
- The subject account is privileged, and the certificate was issued after an unusual remote logon or help desk impersonation scenario.
- The certificate is followed by suspicious Kerberos activity, lateral movement, or privileged logon attempts.
- The requester or source host is associated with phishing, relay, or unauthorized remote access.

**Containment actions:**
- Revoke the suspicious certificate if abuse is confirmed or strongly suspected.
- Disable or reset the requester and subject accounts if compromise is likely.
- Isolate the source host used for the remote logon if it appears malicious.
- Notify PKI administrators to review CA templates, enrollment agent permissions, and relay exposure.

**Closure criteria:**
- The requester is confirmed as an authorized PKI or enrollment agent account.
- The certificate issuance is documented and expected for the subject account.
- No suspicious follow-on authentication or privilege escalation activity is observed.
- The CA and logon evidence align with a legitimate administrative workflow.

<br/>
---
<br/>

## Detection 4: Kerberos Ticket Request Anomaly Following AD CS Certificate Issuance for Lateral Movement

### Detection Opportunity

Kerberos TGT or service ticket requests using unusual encryption types or targeting sensitive service accounts, occurring shortly after AD CS certificate issuance events, consistent with Pass-the-Ticket or Kerberos abuse following ESC1/ESC8 certificate-based authentication.

### Intelligence Context

- Microsoft Security Blog: From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths — [https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/)
  - Context: Following certificate-based privilege escalation via ESC1 or ESC8, attackers used Kerberos for lateral movement. EventID 4768 and 4769 with anomalous encryption types or service account targeting, correlated with a preceding certificate issuance event, provides a compound detection for this intrusion path.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1134, T1550, T1558
- Products: Active Directory Certificate Services, AD CS, Kerberos
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Not specified
- Search tags: Active Directory Certificate Services, AD CS, Kerberos, Windows, Active Directory, T1134, T1550, T1558

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1134 Access Token Manipulation (low); Defense Evasion: T1550 Use Alternate Authentication Material (medium); Credential Access: T1558 Steal or Forge Kerberos Tickets (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let CertIssued = SecurityEvent
| where EventID == 4887
| extend RawRequester = tostring(EventData.RequesterName)
| where isnotempty(RawRequester)
| where RawRequester !endswith "$"
| extend CertRequester = tolower(split(RawRequester, "\\")[-1])
| project CertTime = TimeGenerated, CertRequester, Computer;
let KerbRequests = SecurityEvent
| where EventID in (4768, 4769)
| extend EncType = tostring(EventData.TicketEncryptionType)
| extend KerbUser = tolower(tostring(TargetUserName))
| extend SvcName = tostring(EventData.ServiceName)
| where EncType in ("0x17", "0x3", "0x1", "0x18")
    or SvcName =~ "krbtgt"
| project KerbTime = TimeGenerated, KerbUser, SvcName, EncType, IpAddress;
CertIssued
| join kind=inner KerbRequests on $left.CertRequester == $right.KerbUser
| where KerbTime > CertTime
| where KerbTime <= CertTime + 2h
| project CertTime, KerbTime, CertRequester, SvcName, EncType, IpAddress, Computer
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Environments that have not enforced AES-only Kerberos will generate high volumes of RC4 ticket requests unrelated to certificate abuse.
- Legacy applications that require RC4 Kerberos will match the encryption type filter regardless of certificate issuance.
- PKI enrollment agents who request certificates and then authenticate via Kerberos in normal operations.

**Tuning notes:**
- Validate EventData.TicketEncryptionType field availability by running: SecurityEvent → where EventID == 4768 → take 5 → project EventData before deploying.
- Replace the krbtgt-only SvcName filter with a list of high-value service accounts specific to the environment (e.g., domain admin service accounts, privileged application accounts) to broaden coverage.
- If the environment enforces AES-only Kerberos via GPO, the EncType filter alone becomes a high-fidelity signal and the SvcName filter can be relaxed.
- Consider adding a filter to exclude known PKI enrollment agent accounts from CertRequester to suppress authorized certificate-on-behalf-of workflows.

**Risks / caveats:**
- EventID 4887 requires AD CS audit logging enabled on the CA server; EventID 4768/4769 requires Kerberos authentication auditing enabled on domain controllers. Both must forward to the same Log Analytics workspace for the join to function.
- EventData.TicketEncryptionType and EventData.RequesterName are XML-parsed fields that may not be available as structured columns depending on the agent and workspace configuration; validate field availability before deployment.
- EventID 4887 is generated on the CA server while 4768/4769 are generated on domain controllers; these are different Computer values and the join must be on account name, not on Computer.
- In environments where RC4 Kerberos is still widely used, the encryption type filter alone will produce high false positive volumes; the certificate issuance correlation is the primary noise suppressor.

### Triage Runbook

**First 15 minutes:**
- Confirm the certificate issuance event and the Kerberos request are tied to the same account and fall within the expected time window.
- Review the encryption type and service name to determine whether the request is unusual for the environment, especially RC4 or krbtgt activity.
- Check whether the account is a known PKI enrollment agent, service account, or legacy application identity.
- Identify the source IP and host making the Kerberos request and compare it to the certificate issuance source.
- If the account is privileged or the service target is sensitive, escalate immediately and begin containment planning.

**Evidence to collect:**
- CertTime, KerbTime, CertRequester, SvcName, EncType, IpAddress, and Computer.
- The certificate template, serial number, and any associated CA logs for the issuance event.
- Related 4768, 4769, 4770, 4771, 4624, and 4672 events for the same account and source IP.
- Whether the service name is krbtgt or another high-value service account.
- Any evidence of ticket reuse, unusual logon locations, or multiple hosts using the same identity.

**Pivot points:**
- SecurityEvent for 4887, 4768, 4769, 4624, 4672, and 4771 around the same account and time window.
- SecurityEvent for other Kerberos requests from the same IpAddress or Computer.
- SecurityEvent for privileged group membership changes or admin logons involving the same account.
- If available, endpoint telemetry for the source host to identify the process initiating the Kerberos activity.

**Benign explanations:**
- A legacy application or domain environment still uses RC4 or other older Kerberos encryption types.
- A PKI enrollment agent or service account legitimately requested a certificate and then authenticated normally.
- The service account is a known high-value identity that routinely requests tickets as part of normal operations.

**Escalation criteria:**
- The Kerberos request targets krbtgt or another sensitive service account and follows an unexpected certificate issuance.
- The encryption type is weak or unusual for the environment and the account is not a known legacy exception.
- The same account or source host shows additional suspicious authentication, privilege escalation, or lateral movement.
- The requester is not authorized to obtain certificates on behalf of the subject or the source host is untrusted.

**Containment actions:**
- Disable or reset the affected account if abuse is confirmed or strongly suspected.
- Revoke the certificate associated with the suspicious authentication chain.
- Isolate the source host if it is acting as the origin of malicious Kerberos activity.
- Increase monitoring for the affected account, source IP, and any hosts that accepted the ticket.

**Closure criteria:**
- The Kerberos activity is explained by a documented and approved PKI or service workflow.
- The encryption type and service target are normal for the environment or a known exception.
- No additional suspicious ticket requests, logons, or lateral movement are observed.
- The certificate issuance and Kerberos events are consistent with legitimate administrative activity.

<br/>
---
<br/>

## Detection 5: Shell Process Spawned by BeyondTrust Web Service Indicating RCE via CVE-2026-102764

### Detection Opportunity

A shell interpreter process spawned as a child of the BeyondTrust Remote Support web service process on a Linux host, consistent with remote code execution achieved through unauthenticated file upload exploitation of CVE-2026-102764.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Unauthenticated File Upload to RCE in BeyondTrust Remote Support (CVE-2026-102764) — [https://www.rapid7.com/blog/post/ra-rapid7-analysis-unauthenticated-file-upload-to-rce-in-beyondtrust-remote-support-cve-2026-102764](https://www.rapid7.com/blog/post/ra-rapid7-analysis-unauthenticated-file-upload-to-rce-in-beyondtrust-remote-support-cve-2026-102764)
  - Context: CVE-2026-102764 allows an unauthenticated attacker to write files to the BeyondTrust Remote Support appliance via the public customer connection endpoint and then execute code as the appliance OS user. The most detectable post-exploitation signal is a shell process spawned by the BeyondTrust web service process, which is anomalous in normal operation.

### Search Metadata

- CVEs: CVE-2026-102764
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: BeyondTrust Remote Support
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-102764, BeyondTrust Remote Support, Linux, T1190, T1059

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
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let ShellSpawn = DeviceProcessEvents
| where InitiatingProcessFileName has_any ("bomgar", "beyondtrust", "btremotesupport", "supportapp")
| where FileName in~ ("bash", "sh", "dash", "python", "python3", "perl", "ruby")
| project DeviceId, DeviceName, AccountName, ShellTime = Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let FileWrites = DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any ("/var/www", "/opt/bomgar", "/opt/beyondtrust", "/tmp", "/srv")
| project DeviceId, WriteTime = Timestamp, WrittenFile = FileName, FolderPath, WrittenFileSHA256 = SHA256;
ShellSpawn
| join kind=inner FileWrites on DeviceId
| where WriteTime between ((ShellTime - 5m) .. ShellTime)
| project ShellTime, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, WrittenFile, FolderPath, WriteTime, WrittenFileSHA256
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- BeyondTrust administrative scripts or health checks that legitimately invoke shell interpreters as part of appliance maintenance.
- Legitimate file operations in /tmp or /opt/bomgar by the BeyondTrust service during normal operation.
- If apache2 or nginx is added back to the initiating process list, any web application on those servers that spawns a shell will match.

**Tuning notes:**
- Before deploying, run: DeviceProcessEvents → where DeviceName == "<beyondtrust-appliance-hostname>" → summarize by InitiatingProcessFileName to identify the exact BeyondTrust service process names in the environment.
- If BeyondTrust runs behind apache2 or nginx as a reverse proxy and those processes are the direct parent of shell spawns, add them back to the InitiatingProcessFileName list and scope the query to the BeyondTrust appliance DeviceName to avoid cross-host false positives.
- For a broader hunting variant that does not require the file write correlation, change the join to leftouter and remove the WriteTime filter to surface all shell spawns from BeyondTrust processes regardless of file evidence.
- Add known-benign ProcessCommandLine patterns (e.g., health check script paths) to a not has_any exclusion on ProcessCommandLine to suppress recurring false positives from legitimate BeyondTrust maintenance operations.

**Risks / caveats:**
- Defender for Endpoint agent must be deployed on the BeyondTrust Remote Support Linux appliance; if the appliance is not onboarded to MDE, DeviceProcessEvents will contain no entries for it and the query returns no results.
- The BeyondTrust appliance may run as a hardened or containerized environment where MDE sensor deployment is not supported, making this telemetry unavailable.
- If the BeyondTrust service process name does not match any of the four names in the filter, the query returns no results; the exact process name must be confirmed from baseline DeviceProcessEvents telemetry on the appliance.
- The inner join on file write evidence means that RCE exploits that do not leave a file artifact in the monitored paths (e.g., in-memory execution or writes to unlisted directories) will not be detected.

### Triage Runbook

**First 15 minutes:**
- Confirm the shell process was spawned by a BeyondTrust-specific service process on the appliance host and not by a maintenance script or admin action.
- Review the correlated file write to identify the uploaded or dropped file, its path, and its hash.
- Check for recent inbound web activity, unusual customer connection requests, or suspicious source IPs around the time of the event.
- Determine whether the shell command line indicates interactive use, payload execution, or post-exploitation staging.
- If the shell spawn is unexpected, treat the appliance as compromised and preserve logs and volatile evidence immediately.

**Evidence to collect:**
- ShellTime, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, WrittenFile, FolderPath, WriteTime, and WrittenFileSHA256.
- The exact BeyondTrust service process name and its parent/child process chain.
- Web access logs or appliance logs showing the request that preceded the file write or shell spawn.
- Any additional files created in /var/www, /opt/bomgar, /opt/beyondtrust, /tmp, or /srv around the same time.
- Network connections from the appliance after the shell spawn, including outbound destinations and ports.

**Pivot points:**
- DeviceProcessEvents for all child processes of the BeyondTrust service on the appliance host.
- DeviceFileEvents for other file creations or modifications on the appliance host in the same time window.
- DeviceNetworkEvents for outbound connections from the appliance after the shell spawn.
- Appliance or web server logs to identify the source IP and request path that triggered the activity.

**Benign explanations:**
- A legitimate BeyondTrust maintenance or health-check script invoked a shell interpreter.
- An administrator performed a documented support action that spawned a shell on the appliance.
- A benign file operation in a monitored directory coincided with normal service behavior.

**Escalation criteria:**
- The shell command line is not associated with a known maintenance or support workflow.
- The correlated file write is an uploaded payload, web shell, or script in a web-accessible or temporary directory.
- The appliance shows outbound connections, credential access, or additional child processes after the shell spawn.
- The event occurs on a production appliance with no approved administrative activity at that time.

**Containment actions:**
- Isolate the BeyondTrust appliance from the network if exploitation is confirmed or strongly suspected.
- Preserve relevant logs, uploaded files, and process artifacts before remediation.
- Disable public access to the affected service or endpoint until patched and validated.
- Rotate credentials and secrets that may have been accessible from the appliance.

**Closure criteria:**
- The shell spawn is confirmed to be part of an approved maintenance or support procedure.
- The correlated file write is benign and matches a documented appliance workflow.
- No additional suspicious processes, files, or network connections are observed.
- The appliance is patched or otherwise confirmed not vulnerable, and the activity is explained.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Malicious IDE Extension Installation Masquerading as Claude Code: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- AD CS Certificate Issued with Mismatched Requester and Subject Indicating ESC8 Relay Abuse: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.
- Kerberos Ticket Request Anomaly Following AD CS Certificate Issuance for Lateral Movement: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Other deployment dependency:**
- Shell Process Spawned by BeyondTrust Web Service Indicating RCE via CVE-2026-102764: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceFileEvents: shared by Malicious IDE Extension Installation Masquerading as Claude Code; Shell Process Spawned by BeyondTrust Web Service Indicating RCE via CVE-2026-102764
- SecurityEvent: shared by AD CS Certificate Issued with Mismatched Requester and Subject Indicating ESC8 Relay Abuse; Kerberos Ticket Request Anomaly Following AD CS Certificate Issuance for Lateral Movement

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SSH Backdoor Persistence via Scheduled Task from IDE Extension Process.
2. Resolve environment-mapping detections next: AD CS Certificate Issued with Mismatched Requester and Subject Indicating ESC8 Relay Abuse; Kerberos Ticket Request Anomaly Following AD CS Certificate Issuance for Lateral Movement; Shell Process Spawned by BeyondTrust Web Service Indicating RCE via CVE-2026-102764.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Malicious IDE Extension Installation Masquerading as Claude Code.

### Hunting Agenda and Promotion Criteria

- Malicious IDE Extension Installation Masquerading as Claude Code: Do not schedule yet; validate as an analyst-led hunt first..
- AD CS Certificate Issued with Mismatched Requester and Subject Indicating ESC8 Relay Abuse: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Kerberos Ticket Request Anomaly Following AD CS Certificate Issuance for Lateral Movement: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Shell Process Spawned by BeyondTrust Web Service Indicating RCE via CVE-2026-102764: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
