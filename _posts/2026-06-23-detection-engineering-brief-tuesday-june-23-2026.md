---
layout: post
title: "Detection Engineering Brief - Tuesday, June 23, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-23
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1557.001
  - T1098
  - T1558.003
  - Active Directory
  - Kerberos
  - LDAP
  - Metasploit
  - Windows
  - T1068
  - WebDAV
  - T1021.002
  - PsExec
  - T1059.005
  - T1105
  - WhatsApp
  - UEMS
  - RMM
  - messaging apps
  - T1021
  - T1059
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1557.001, T1098, T1558.003, Active Directory, Kerberos, LDAP, Metasploit, Windows, T1068, WebDAV, T1021.002, PsExec, T1059.005, T1105, WhatsApp, UEMS, RMM, messaging apps, T1021, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: NTLM Network Logon to Domain Controller LDAP Port from Machine Account; PsExec Service Creation Targeting Local Host Following NTLM Relay Chain; Script Interpreter Outbound Download Followed by New Executable Drop in User-Writable Path.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Shadow Credentials Write Followed by Privileged Kerberos TGS Request

### Detection Opportunity

Attacker writes msDS-KeyCredentialLink attribute to a computer or user object via LDAP relay, then immediately requests a Kerberos service ticket as Administrator.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: Metasploit module relays NTLM authentication to a domain controller LDAP service, uses the resulting session to write Shadow Credentials (msDS-KeyCredentialLink) to an AD object, then obtains a Kerberos TGS as Administrator to achieve privilege escalation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1557.001, T1098, T1558.003, T1021, T1021.002, T1068
- Products: Active Directory, Kerberos, LDAP
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1557.001, T1098, T1558.003, Active Directory, Kerberos, LDAP, Metasploit, Windows, T1021, T1021.002, T1068

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium); Privilege Escalation: T1068 Exploitation for Privilege Escalation (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- SecurityEvent

### KQL

```kql
let ShadowCredWrite = SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName =~ "msDS-KeyCredentialLink"
| where OperationType == "%%14674"
| project WriteTime = TimeGenerated, SubjectUserName, ObjectDN, IpAddress, Computer;
let KerbPrivRequest = SecurityEvent
| where EventID == 4769
| where TargetUserName has_any ("Administrator", "admin", "krbtgt")
| project KerbTime = TimeGenerated, TargetUserName, ServiceName, IpAddress, TicketEncryptionType, Computer;
ShadowCredWrite
| join kind=inner KerbPrivRequest on IpAddress
| where KerbTime between (WriteTime .. (WriteTime + 10m))
| project
    WriteTime,
    KerbTime,
    SubjectUserName,
    ObjectDN,
    TargetUserName,
    ServiceName,
    TicketEncryptionType,
    IpAddress,
    DomainController = Computer
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Windows Hello for Business provisioning writes msDS-KeyCredentialLink legitimately; these will appear as EventID 5136 matches and may correlate with subsequent Kerberos activity from the same host.
- Privileged account Kerberos requests are common in large environments; the 10-minute window may produce coincidental joins if the IpAddress is a shared NAT or jump host.

Tuning notes:
- Expand TargetUserName to include all privileged account names relevant to your AD naming conventions.
- Add an exclusion for known Windows Hello for Business provisioning service accounts that legitimately write msDS-KeyCredentialLink.
- Consider adding a Computer allowlist to restrict matches to domain controller hostnames only.

Risks / caveats:
- EventID 5136 requires 'Audit Directory Service Changes' to be enabled in AD DS audit policy and the domain controller Security log forwarded to the Log Analytics workspace via the Windows Security Events connector or AMA. If this subcategory is not enabled, the ShadowCredWrite subquery returns no results.
- EventID 4769 requires 'Audit Kerberos Service Ticket Operations' to be enabled. If absent, the KerbPrivRequest subquery returns no results.
- AttributeLDAPDisplayName is parsed from the EventData XML of EventID 5136. If the Sentinel connector ingests raw XML without parsing this field, the filter will not match and the query will return no results.
- The 10-minute correlation window is a starting point; environments with slower relay chains or high DC load may need a wider window.

### Triage Runbook

First 15 minutes:
- Verify the writer account in SubjectUserName and determine whether it is a known provisioning, PAM, or directory management account.
- Inspect ObjectDN to identify the target object and confirm whether it is a user, computer, or high-value account such as Administrator or krbtgt.
- Check the timing between WriteTime and KerbTime; a tight sequence from the same IpAddress strongly supports relay-based abuse.
- Review the domain controller Computer and surrounding SecurityEvent records for related 5136, 4769, 4624, and 4672 activity from the same source.
- If the target is a privileged account or the writer is unknown, treat as active compromise and begin incident handling immediately.

Evidence to collect:
- Full 5136 event data including ObjectDN, AttributeLDAPDisplayName, OperationType, SubjectUserName, and IpAddress.
- Full 4769 event data including TargetUserName, ServiceName, TicketEncryptionType, and Computer.
- Any preceding 4624/4776/4771 events from the same IpAddress or writer account.
- Directory context for the target object: group membership, admin rights, recent password or attribute changes, and whether the object is a computer or user account.
- Whether the source IP maps to a domain controller, jump host, NAT device, or known management system.

Pivot points:
- SecurityEvent for EventID 5136, 4769, 4624, 4672, 4776, and 4771 around the same WriteTime and IpAddress.
- Active Directory admin and group membership records for ObjectDN and TargetUserName.
- Domain controller logs for additional LDAP writes from the same SubjectUserName or source IP.
- If available, endpoint telemetry for the source host to identify the process or tool that initiated the LDAP relay.

Benign explanations:
- Windows Hello for Business or device registration workflows can legitimately write msDS-KeyCredentialLink.
- A privileged Kerberos request may be normal if it is part of an admin login or service activity immediately after a legitimate directory change.
- Shared jump hosts or NAT can create coincidental joins between unrelated LDAP writes and Kerberos requests.
- A management or PAM solution may write key credential attributes as part of approved provisioning.

Escalation criteria:
- Escalate immediately if the target is Administrator, krbtgt, or another Tier 0 account.
- Escalate if SubjectUserName is not a known directory/provisioning account or if the source IP is not a trusted management host.
- Escalate if TicketEncryptionType or the ticket pattern suggests a PKINIT-style flow following the attribute write.
- Escalate if there are multiple 5136 writes or additional privileged logons from the same source within the same window.

Containment actions:
- Disable or isolate the suspected writer account if it is not an approved admin or service account.
- Reset credentials or revoke access for the targeted privileged account if compromise is confirmed or strongly suspected.
- Block the source host or IP at the network layer if it is a workstation or untrusted system and not a domain controller or management server.
- Preserve domain controller logs and directory state before making changes to the affected object.

Closure criteria:
- Confirmed legitimate provisioning or admin activity with a known account, approved change record, and expected target object.
- No evidence of unauthorized privilege escalation after reviewing related 4624/4769/4672 activity and directory changes.
- Source IP and writer account are validated as trusted management infrastructure and the object change is expected.
- False positive is documented and the relevant allowlist or tuning exception is approved.

---

## Detection 2: NTLM Network Logon to Domain Controller LDAP Port from Machine Account

### Detection Opportunity

Machine account authenticates via NTLM to a domain controller on LDAP port 389 or 636, consistent with an NTLM relay attack coerced via WebDAV OpenEncryptedFileRaw.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: Metasploit coerces the local machine account to authenticate via OpenEncryptedFileRaw over WebDAV, then relays that NTLM authentication to the domain controller LDAP service on port 389 or 636 to establish an authenticated LDAP session for further exploitation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1557.001, T1068, T1021, T1021.002
- Products: Active Directory, LDAP, WebDAV
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1557.001, T1068, Active Directory, LDAP, WebDAV, Metasploit, Windows, T1021, T1021.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium); Privilege Escalation: T1068 Exploitation for Privilege Escalation (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents, DeviceLogonEvents before scheduling.

Required telemetry:
- DeviceNetworkEvents, DeviceLogonEvents

### KQL

```kql
let NTLMLdapConnections = DeviceNetworkEvents
| where RemotePort in (389, 636)
| where ActionType == "ConnectionSuccess"
| project NetTime = Timestamp, DeviceId, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName;
let MachineNTLMLogons = DeviceLogonEvents
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where AccountName endswith "$"
| project LogonTime = Timestamp, DeviceId, AccountName;
NTLMLdapConnections
| join kind=inner MachineNTLMLogons on DeviceId
| where LogonTime between (NetTime .. (NetTime + 30s))
| project
    NetTime,
    LogonTime,
    DeviceName,
    AccountName,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate LDAP clients using NTLM for directory queries on port 389 will match if not scoped to DC IPs.
- Domain-joined devices performing NTLM fallback during Kerberos failures will produce machine-account NTLM logons that match this pattern.

Tuning notes:
- Add a filter on RemoteIP matching your domain controller IP ranges to scope the detection to DC-targeted LDAP relay activity.
- Consider correlating with DeviceNetworkEvents on the DC side (if DCs are MDE-onboarded) for the inbound connection to increase fidelity.
- Adjust the 30-second join window based on observed relay timing in your environment.

Risks / caveats:
- DeviceLogonEvents does not expose a RemoteIP field that reliably matches the RemoteIP in DeviceNetworkEvents for the same NTLM session. The original query joins on DeviceId only and uses a time window, which is a weak correlation that may miss or misattribute events.
- NTLM logon events in DeviceLogonEvents may not be generated for all NTLM relay scenarios depending on whether the relay target is the local device or a remote DC; relay-to-DC events may only appear on the DC side, which requires the DC to be onboarded to Defender for Endpoint.
- Without a DC IP list, the RemotePort 389/636 filter matches any LDAP-capable host, not just domain controllers.
- The query must be scoped to domain controller RemoteIP values before scheduling to avoid high false-positive volume; this requires an environment-specific IP list or a watchlist.

### Triage Runbook

First 15 minutes:
- Confirm the destination RemoteIP is a domain controller and not a generic LDAP-capable server.
- Check whether AccountName is a machine account that normally talks to LDAP and whether the initiating device is expected to contact the DC.
- Review InitiatingProcessFileName on the source device to see whether a coercion or relay tool is present.
- Look for nearby NTLM-related logons, LDAP binds, or other suspicious authentication failures from the same DeviceId and time window.
- If the source is a workstation or server that should not be performing LDAP NTLM to a DC, treat as suspicious and continue investigation.

Evidence to collect:
- DeviceNetworkEvents details for the LDAP connection: Timestamp, DeviceName, RemoteIP, RemotePort, and InitiatingProcessFileName.
- DeviceLogonEvents details for the NTLM logon: LogonTime, AccountName, LogonType, and DeviceName.
- Whether the RemoteIP belongs to a domain controller IP range and whether the source device is a known management host.
- Any related authentication failures, coercion indicators, or repeated LDAP connections from the same device.
- Endpoint context for the source device, including recent process launches and any WebDAV or script activity.

Pivot points:
- DeviceNetworkEvents filtered to the same DeviceId, RemoteIP, and a wider time window for repeated LDAP connections.
- DeviceLogonEvents for the same AccountName and DeviceId to identify other NTLM logons or fallback authentication.
- Domain controller telemetry for inbound LDAP binds, 4624/4776 events, and any subsequent directory writes.
- If available, endpoint process telemetry on the source device for WebDAV, script, or relay tooling.

Benign explanations:
- Some domain-joined devices fall back to NTLM when Kerberos fails, producing machine-account LDAP authentication.
- Administrative tools and directory inventory systems may use NTLM for LDAP queries to domain controllers.
- A misconfigured application or service account may generate LDAP traffic that looks unusual but is operationally expected.
- Shared infrastructure or jump hosts can make the source device appear suspicious when the activity is actually centralized management.

Escalation criteria:
- Escalate if the destination is a domain controller and the source device is not a known management or directory service host.
- Escalate if the machine account activity is paired with other relay indicators such as WebDAV, coercion, or rapid follow-on directory changes.
- Escalate if the same source device shows repeated NTLM LDAP attempts or multiple accounts involved in a short period.
- Escalate if the activity is observed on a workstation with no business reason to query LDAP over NTLM.

Containment actions:
- Isolate the source device if relay tooling or coercion activity is confirmed and the host is not a critical server.
- Block or restrict the source host from reaching domain controller LDAP ports if it is untrusted and the activity is malicious.
- Disable or investigate the machine account only if there is evidence it has been abused or its trust relationship is compromised.
- Preserve endpoint and DC logs before remediation to support root-cause analysis.

Closure criteria:
- Destination confirmed as a domain controller but the source device and account are validated as expected management or service activity.
- No corroborating evidence of relay, coercion, or unauthorized directory modification is found.
- The NTLM LDAP use is explained by a documented application, fallback condition, or approved admin workflow.
- A tuning exception is created for the validated source, account, or DC scope if appropriate.

---

## Detection 3: PsExec Service Creation Targeting Local Host Following NTLM Relay Chain

### Detection Opportunity

PsExec service (PSEXESVC) is created on a host where the source and destination of the SMB connection are the same machine, used to obtain SYSTEM-level access after an NTLM relay privilege escalation.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: After obtaining a Kerberos ticket as Administrator via Shadow Credentials, the Metasploit module uses PsExec back to the same host it originated from to achieve SYSTEM-level code execution, creating the PSEXESVC service on the local machine.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002, T1068, T1021
- Products: Active Directory
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Metasploit, PsExec
- Search tags: T1021.002, T1068, Active Directory, Metasploit, PsExec, Windows, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium); Privilege Escalation: T1068 Exploitation for Privilege Escalation (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- SecurityEvent

### KQL

```kql
let PsExecService = SecurityEvent
| where EventID == 7045
| where ServiceName =~ "PSEXESVC"
| project ServiceTime = TimeGenerated, Computer, AccountName;
let SelfLogon = SecurityEvent
| where EventID == 4624
| where LogonType == 3
| project LogonTime = TimeGenerated, Computer, IpAddress, SubjectUserName;
PsExecService
| join kind=inner SelfLogon on Computer
| where LogonTime between ((ServiceTime - 2m) .. (ServiceTime + 2m))
| where IpAddress in ("127.0.0.1", "::1") or IpAddress == Computer
| project
    ServiceTime,
    LogonTime,
    Computer,
    AccountName,
    IpAddress,
    SubjectUserName
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Administrators using PsExec for legitimate local automation or testing will produce PSEXESVC service creation events.
- Monitoring or deployment tools that use PsExec internally may generate matching type-3 logons from loopback addresses.

Tuning notes:
- If EventID 7045 is available in the WindowsEvent table instead of SecurityEvent, rewrite the PsExecService subquery to use WindowsEvent with EventID == 7045 and parse ServiceName from EventData.
- Add a preceding EventID 5136 (msDS-KeyCredentialLink) correlation within 30 minutes on the same Computer to increase specificity and reduce false positives from legitimate PsExec use.
- Extend the join window beyond 2 minutes if relay chain timing in your environment is slower.

Risks / caveats:
- EventID 7045 (service installation) requires the System event log to be forwarded to Sentinel. If only the Security log is collected, this event will not appear in SecurityEvent.
- EventID 7045 is in the System log, not the Security log. SecurityEvent in Sentinel typically contains Security log events. EventID 7045 may need to be collected via a custom Windows Event log data connector targeting the System log, or via the WindowsEvent table.
- EventID 7045 is a System log event. If the Sentinel workspace collects only Security log events via the Windows Security Events connector, this query will return no results for the PsExecService subquery. Validate that System log events are forwarded, or migrate the 7045 filter to the WindowsEvent table.
- The IpAddress == Computer comparison will fail when Computer contains a FQDN and IpAddress contains a short hostname or IP; this match is unreliable without normalization.

### Triage Runbook

First 15 minutes:
- Verify that EventID 7045 is present and that ServiceName is PSEXESVC on the affected Computer.
- Check whether the matching 4624 type 3 logon came from loopback or the same host and whether SubjectUserName/AccountName are expected for local administration.
- Look for preceding Shadow Credentials or LDAP relay activity on the same host within the prior 30 minutes.
- Identify the account that installed the service and whether it is a known admin, deployment, or automation account.
- If the service creation is unexpected or follows relay indicators, treat the host as compromised and move to containment.

Evidence to collect:
- Service installation details: ServiceTime, Computer, AccountName, and any available service binary path or command line from the event source.
- Logon details: LogonTime, IpAddress, LogonType, and SubjectUserName for the correlated 4624 event.
- Any preceding 5136, 4769, or LDAP relay-related events on the same Computer or from the same source IP.
- Endpoint process history around the service creation time to identify PsExec, cmd.exe, powershell.exe, or related tooling.
- Whether the host is a workstation, server, or management system and whether local PsExec use is approved.

Pivot points:
- SecurityEvent for EventID 7045, 4624, 4688, 4697, 5136, and 4769 around the same Computer and time window.
- If 7045 is not present in SecurityEvent, check the WindowsEvent table or other forwarded System log sources.
- Endpoint telemetry for the same Computer to identify the parent process and any spawned SYSTEM processes.
- Directory and authentication logs for the same source account to confirm whether the PsExec activity followed a relay chain.

Benign explanations:
- Administrators may legitimately use PsExec for local automation, troubleshooting, or software deployment.
- Monitoring or deployment tools can create PSEXESVC as part of approved remote administration.
- A lab or test environment may intentionally use loopback PsExec for validation.
- Some security tools and remote support workflows can resemble PsExec service creation.

Escalation criteria:
- Escalate if PSEXESVC appears on a workstation or server with no approved local PsExec use.
- Escalate if the event is preceded by Shadow Credentials, LDAP relay, or privileged Kerberos activity on the same host.
- Escalate if the installing account is not a known admin or automation account.
- Escalate if the host begins spawning additional SYSTEM-level processes or shows lateral movement after the service creation.

Containment actions:
- Isolate the host if the PsExec service creation is unexpected and tied to relay or privilege escalation activity.
- Disable the suspicious account if it is not a trusted admin or deployment identity.
- Terminate malicious remote administration sessions and remove the PSEXESVC service if confirmed unauthorized.
- Preserve service creation and logon evidence before rebooting or cleaning the host.

Closure criteria:
- PsExec use is confirmed as approved administrative activity with a known account and change record.
- No preceding relay or Shadow Credentials indicators are found on the host or source IP.
- The service creation is explained by a documented deployment, support, or automation workflow.
- Any necessary allowlist for the approved admin host or account is documented and approved.

---

## Detection 4: VBScript Execution Spawned from WhatsApp Desktop Process

### Detection Opportunity

wscript.exe or cscript.exe is launched as a child of the WhatsApp desktop application, executing a VBS file from a user download or temp directory as part of a multi-stage RMM agent delivery chain.

### Intelligence Context

- Securelist: A VBScript campaign distributed through WhatsApp deploying RMM software — [https://securelist.com/whatsapp-vbs-rmm-campaign/120290/](https://securelist.com/whatsapp-vbs-rmm-campaign/120290/)
  - Context: Attackers distribute VBS scripts via WhatsApp messages. When opened, the WhatsApp desktop process spawns wscript.exe or cscript.exe to execute the VBS payload from the user's download directory, initiating a multi-stage chain that ultimately installs a UEMS RMM agent for persistent remote access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059.005, T1105, T1059
- Products: WhatsApp, UEMS, RMM
- Platforms: Windows, messaging apps
- Malware: Not specified
- Tools: Not specified
- Search tags: T1059.005, T1105, WhatsApp, UEMS, RMM, Windows, messaging apps, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1105 Ingress Tool Transfer (high); Execution: T1059 Command and Scripting Interpreter/ T1059.005 Visual Basic (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ScriptFromWhatsApp = DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
| where InitiatingProcessFileName has_any ("WhatsApp.exe", "WhatsApp")
| where ProcessCommandLine has_any (".vbs", ".vbe")
| where FolderPath has_any ("Downloads", "Temp", "AppData")
    or ProcessCommandLine has_any ("Downloads", "Temp", "AppData")
| project
    ProcTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FolderPath;
let ScriptNetworkActivity = DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where ActionType == "ConnectionSuccess"
| project NetTime = Timestamp, DeviceId, RemoteUrl, RemoteIP;
ScriptFromWhatsApp
| join kind=leftouter ScriptNetworkActivity on DeviceId
| where isnull(NetTime) or NetTime between (ProcTime .. (ProcTime + 5m))
| project
    ProcTime,
    NetTime,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FolderPath,
    RemoteUrl,
    RemoteIP
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Users who legitimately open VBS attachments received via WhatsApp for business automation purposes will match.
- Security awareness training platforms that deliver simulated phishing via messaging apps may trigger this detection.

Tuning notes:
- Add additional messaging app process names to the InitiatingProcessFileName filter if scope expansion to other platforms is desired.
- Narrow FolderPath to paths beginning with 'C:\\Users' to reduce matches from system-level Temp directories.
- Consider promoting to a higher-confidence alert when both the process execution and outbound network connection are present in the same row.

Risks / caveats:
- RemoteUrl is not always populated in DeviceNetworkEvents; for many connections only RemoteIP is available. The query projects RemoteUrl but analysts should also review RemoteIP for triage.
- The WhatsApp process name may differ across installation types (Store app vs. standalone installer) or future versions; validate InitiatingProcessFileName values in your environment.
- The 5-minute network correlation window is a heuristic; multi-stage chains with delayed downloads may fall outside this window.
- leftouter join will retain all script execution events even without a network match, which may increase alert volume; analysts should triage both matched and unmatched rows.

### Triage Runbook

First 15 minutes:
- Confirm the parent process is WhatsApp and the child is wscript.exe or cscript.exe executing a .vbs or .vbe file.
- Review the script path and folder location to see whether it came from Downloads, Temp, or AppData.
- Check whether the user recently received a file or message in WhatsApp that could explain the script execution.
- Inspect any immediate outbound connections from the script interpreter and note the RemoteUrl or RemoteIP.
- If the script came from a user profile and is not tied to a known business process, treat it as suspicious and continue triage.

Evidence to collect:
- Process tree details: Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, and FolderPath.
- Network details from DeviceNetworkEvents for the same script interpreter, including RemoteUrl and RemoteIP.
- The exact file path and filename of the VBS/VBE script and any dropped files that follow.
- User context: whether the user is expected to receive scripts or installers through WhatsApp for business purposes.
- Any subsequent child processes, downloads, or persistence actions launched by the script.

Pivot points:
- DeviceProcessEvents for the same DeviceId and AccountName to identify the full parent-child chain before and after the script launch.
- DeviceNetworkEvents for wscript.exe/cscript.exe to identify outbound connections and downloaded content.
- DeviceFileEvents for files created by the same process or user around the same time.
- If available, email, chat, or collaboration telemetry to confirm whether the file was delivered through WhatsApp or another messaging channel.

Benign explanations:
- Some users may legitimately receive business automation scripts or installers through messaging apps.
- Security awareness simulations can intentionally deliver VBS files via messaging platforms.
- Internal support teams may use scripts for troubleshooting in controlled environments.
- A user may have manually opened a script from a trusted source, though this should still be validated.

Escalation criteria:
- Escalate if the script is followed by outbound network activity to an unknown or suspicious destination.
- Escalate if the script drops additional executables, creates persistence, or launches RMM tooling.
- Escalate if the user does not recognize the file or if the WhatsApp conversation is unrelated to business operations.
- Escalate if multiple endpoints show the same pattern, indicating a broader campaign.

Containment actions:
- Isolate the endpoint if the script is confirmed malicious or is dropping additional payloads.
- Block the observed RemoteUrl or RemoteIP if it is clearly malicious and not business-critical.
- Quarantine the script and any dropped files through endpoint response actions.
- Reset the user session or credentials if the script execution led to credential theft or suspicious follow-on activity.

Closure criteria:
- The script is verified as benign, expected, and tied to a documented business process or approved test.
- No suspicious outbound connections, dropped executables, or persistence are observed.
- The user confirms the file source and the content matches an authorized workflow.
- Any allowlist for the script path, sender, or business application is approved and documented.

---

## Detection 5: Script Interpreter Outbound Download Followed by New Executable Drop in User-Writable Path

### Detection Opportunity

A script interpreter (wscript, cscript, or powershell) makes an outbound network connection to download a file, followed by creation of a new executable in a user-writable directory, consistent with the multi-stage RMM agent delivery chain observed in this campaign.

### Intelligence Context

- Securelist: A VBScript campaign distributed through WhatsApp deploying RMM software — [https://securelist.com/whatsapp-vbs-rmm-campaign/120290/](https://securelist.com/whatsapp-vbs-rmm-campaign/120290/)
  - Context: The multi-stage infection chain uses script interpreters to download and execute subsequent payloads, ultimately dropping a UEMS RMM agent binary into a user-writable path. The script interpreter initiates outbound connections and the resulting file creation of an executable is the key observable.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1105, T1059.005, T1059
- Products: WhatsApp, UEMS, RMM
- Platforms: Windows, messaging apps
- Malware: Not specified
- Tools: Not specified
- Search tags: T1105, T1059.005, WhatsApp, UEMS, RMM, Windows, messaging apps, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1105 Ingress Tool Transfer (high); Execution: T1059 Command and Scripting Interpreter/ T1059.005 Visual Basic (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceNetworkEvents, DeviceFileEvents

### KQL

```kql
let ScriptDownload = DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe", "powershell.exe")
| where ActionType == "ConnectionSuccess"
| project
    DownloadTime = Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    RemoteUrl,
    InitiatingProcessId;
let ExeDrop = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".msi"
| where FolderPath has_any ("Downloads", "Temp", "AppData", "ProgramData")
| where FolderPath has "Users" or FolderPath has "ProgramData"
| project
    DropTime = Timestamp,
    DeviceId,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessId;
ScriptDownload
| join kind=inner ExeDrop on DeviceId, InitiatingProcessId
| where DropTime between (DownloadTime .. (DownloadTime + 5m))
| project
    DownloadTime,
    DropTime,
    DeviceName,
    InitiatingProcessFileName,
    RemoteUrl,
    FileName,
    FolderPath,
    SHA256
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate PowerShell-based software deployment scripts that download and install executables will match.
- IT automation tools that use wscript or cscript to invoke installers will produce matching file creation events.
- Software update mechanisms that use PowerShell to download and stage executables in AppData or ProgramData will match.

Tuning notes:
- Add a RemoteUrl allowlist for known software distribution CDNs and update services used in your environment.
- Narrow FolderPath to specific user-profile subdirectories by replacing the has_any with a startswith check on 'C:\\Users' to exclude system-level paths.
- Correlate results with the companion WhatsApp parent-process detection to prioritize high-confidence alerts from the same device within a short time window.

Risks / caveats:
- InitiatingProcessId may be reused by the OS within the correlation window if the script interpreter process exits and a new process is assigned the same PID; this can cause false joins between unrelated events.
- DeviceFileEvents ActionType 'FileCreated' may not be generated for all file write methods depending on the Defender for Endpoint sensor version and OS configuration.
- InitiatingProcessId reuse within the 5-minute window can cause false joins; this is an inherent limitation of PID-based correlation without a process GUID.
- The FolderPath filter 'has Users' combined with 'has ProgramData' uses an or-style logic via two separate has clauses; verify the combined filter behaves as intended for paths that contain neither substring.

### Triage Runbook

First 15 minutes:
- Validate the process chain: wscript.exe, cscript.exe, or powershell.exe making the network connection and then creating the executable.
- Review the RemoteUrl and SHA256 to determine whether the download or dropped file is known, signed, or suspicious.
- Check the FolderPath to confirm the executable landed in Downloads, Temp, AppData, or ProgramData under a user profile.
- Look for immediate follow-on execution of the dropped file or additional child processes from the same interpreter.
- If the download and drop are not part of a known software deployment workflow, treat as likely malicious and escalate.

Evidence to collect:
- Network event details: DownloadTime, DeviceName, InitiatingProcessFileName, RemoteUrl, and InitiatingProcessId.
- File creation details: DropTime, FileName, FolderPath, SHA256, and InitiatingProcessId.
- Process tree and command line for the script interpreter, including any encoded commands or URLs.
- Any subsequent execution of the dropped executable or related persistence artifacts.
- User and host context to determine whether the activity aligns with approved software installation or support tooling.

Pivot points:
- DeviceNetworkEvents for the same DeviceId and InitiatingProcessId to identify all downloads by the script interpreter.
- DeviceFileEvents for the same DeviceId and SHA256 to find other hosts that received the same file.
- DeviceProcessEvents for the dropped FileName or SHA256 to see whether it executed after creation.
- If available, reputation or threat intel lookups for the RemoteUrl and SHA256.

Benign explanations:
- Legitimate software deployment scripts may download and stage executables in user-writable paths.
- IT automation or support tools may use PowerShell or script interpreters to install software.
- Some update mechanisms temporarily place installers in AppData or ProgramData before execution.
- A sanctioned RMM rollout can look similar if it is not yet allowlisted.

Escalation criteria:
- Escalate if the dropped executable is unsigned, unknown, or immediately executed after download.
- Escalate if the RemoteUrl is unrecognized or associated with a suspicious domain or IP.
- Escalate if the same pattern appears on multiple hosts or user accounts.
- Escalate if the script interpreter uses obfuscation, encoded commands, or persistence actions.

Containment actions:
- Isolate the host if the dropped executable is suspicious or has already executed.
- Quarantine the downloaded file and any related artifacts through endpoint response actions.
- Block the RemoteUrl or RemoteIP if it is malicious and not required for business operations.
- Disable the user session or reset credentials if the activity suggests credential theft or unauthorized access.

Closure criteria:
- The download and file drop are confirmed as part of an approved software deployment or support process.
- The dropped executable is validated as signed, expected, and benign.
- No follow-on execution, persistence, or suspicious network activity is observed.
- Allowlist or tuning is documented for the approved script, URL, or deployment mechanism.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- NTLM Network Logon to Domain Controller LDAP Port from Machine Account: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents, DeviceLogonEvents before scheduling.

Schema / correlation keys:
- PsExec Service Creation Targeting Local Host Following NTLM Relay Chain: Do not schedule yet; validate as an analyst-led hunt first.
- Script Interpreter Outbound Download Followed by New Executable Drop in User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- SecurityEvent: shared by Shadow Credentials Write Followed by Privileged Kerberos TGS Request; PsExec Service Creation Targeting Local Host Following NTLM Relay Chain
- DeviceNetworkEvents: shared by NTLM Network Logon to Domain Controller LDAP Port from Machine Account; VBScript Execution Spawned from WhatsApp Desktop Process; Script Interpreter Outbound Download Followed by New Executable Drop in User-Writable Path

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Shadow Credentials Write Followed by Privileged Kerberos TGS Request; VBScript Execution Spawned from WhatsApp Desktop Process.
2. Resolve environment-mapping detections next: NTLM Network Logon to Domain Controller LDAP Port from Machine Account.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: PsExec Service Creation Targeting Local Host Following NTLM Relay Chain; Script Interpreter Outbound Download Followed by New Executable Drop in User-Writable Path.

### Hunting Agenda and Promotion Criteria

- PsExec Service Creation Targeting Local Host Following NTLM Relay Chain: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Script Interpreter Outbound Download Followed by New Executable Drop in User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- NTLM Network Logon to Domain Controller LDAP Port from Machine Account: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents, DeviceLogonEvents before scheduling.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
