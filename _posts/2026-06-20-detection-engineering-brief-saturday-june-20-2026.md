---
layout: post
title: "Detection Engineering Brief - Saturday, June 20, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-20
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1098
  - T1557.001
  - Metasploit
  - PsExec
  - Windows
  - Domain Controller
  - LDAP
  - T1021.002
  - WebDAV
  - T1558.003
  - T1115
  - T1090.003
  - Tor
  - T1190
  - T1059
  - AutoGen Studio
  - MCP WebSocket
  - AI agent host
  - T1021
  - T1558
  - T1090
---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1098, T1557.001, Metasploit, PsExec, Windows, Domain Controller, LDAP, T1021.002, WebDAV, T1558.003, T1115, T1090.003, Tor, T1190, T1059, AutoGen Studio, MCP WebSocket, AI agent host, T1021, T1558, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Machine Account NTLM Authentication to Domain Controller LDAP from Non-DC Host; PsExec Self-Targeting Execution Following S4U2Proxy Kerberos Ticket Acquisition; Clipboard Hijacking Process with Concurrent Tor Network Communication; Shell or Interpreter Spawned by AutoGen Studio or AI Agent WebSocket Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Shadow Credentials Written via msDS-KeyCredentialLink Modification

### Detection Opportunity

Adversary writes Shadow Credentials to a computer account by modifying the msDS-KeyCredentialLink attribute through an abused LDAP session obtained via NTLM relay.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: Metasploit module coerces local machine account authentication via WebDAV, relays NTLM to DC LDAP, then uses the resulting session to write Shadow Credentials to msDS-KeyCredentialLink, enabling subsequent S4U2Proxy Kerberos ticket acquisition as Administrator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1557.001, T1021.002, T1558.003, T1021, T1558
- Products: Metasploit
- Platforms: Windows, Domain Controller, LDAP
- Malware: Not specified
- Tools: PsExec
- Search tags: T1098, T1557.001, Metasploit, PsExec, Windows, Domain Controller, LDAP, T1021.002, T1558.003, T1021, T1558

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Defense Evasion: T1558 Steal or Forge Kerberos Tickets/ T1558.003 Kerberoasting (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- SecurityEvent

### KQL

```kql
SecurityEvent
| where TimeGenerated >= ago(1d)
| where EventID == 5136
| where ObjectServer == "DS"
| extend AttributeName = trim(@"\s", extract(@"AttributeLDAPDisplayName:\s+([^\r\n]+)", 1, EventData))
| where AttributeName =~ "msDS-KeyCredentialLink"
| extend
    ObjectDN = trim(@"\s", extract(@"ObjectDN:\s+([^\r\n]+)", 1, EventData)),
    SubjectAccount = trim(@"\s", extract(@"SubjectUserName:\s+([^\r\n]+)", 1, EventData)),
    SubjectDomain = trim(@"\s", extract(@"SubjectDomainName:\s+([^\r\n]+)", 1, EventData)),
    OperationType = trim(@"\s", extract(@"OperationType:\s+([^\r\n]+)", 1, EventData))
| where OperationType in~ ("%%14674", "%%14675", "Value Added", "Value Deleted")
| project
    TimeGenerated,
    Computer,
    SubjectAccount,
    SubjectDomain,
    ObjectDN,
    AttributeName,
    OperationType,
    EventData
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Windows Hello for Business enrollment processes legitimately write msDS-KeyCredentialLink for user and device objects.
- Third-party PAM or MFA solutions that implement FIDO2 or certificate-based authentication may write this attribute during enrollment.
- Azure AD Connect or hybrid identity synchronization agents may touch this attribute in hybrid environments.

Tuning notes:
- To reduce noise in environments with Windows Hello for Business, add '| where SubjectAccount !in~ ("<enrollment_service_account>")' after the OperationType filter once enrollment accounts are identified.
- If DC naming is consistent (e.g., all DCs contain '-DC-' in hostname), add '| where Computer contains "-DC-"' to scope the query and reduce processing cost.
- Consider splitting into two rules: one alerting on Value Added (new credential written) at High severity, and one on Value Deleted at Medium severity for completeness.

Risks / caveats:
- EventID 5136 is only generated when the Advanced Audit Policy subcategory 'Audit Directory Service Changes' is enabled on Domain Controllers. If this policy is not configured, the table will contain no matching events and the rule will produce zero results.
- The EventData field in SecurityEvent is a raw XML/text blob; regex extraction of AttributeLDAPDisplayName, ObjectDN, SubjectUserName, and OperationType depends on the exact formatting of the 5136 event as forwarded by the agent. AMA and legacy MMA may produce slightly different EventData representations.
- Windows Hello for Business and FIDO2 enrollment will generate true-positive-looking events; an allowlist of known enrollment service accounts should be maintained.
- The regex patterns assume standard Windows Security event formatting. Custom event collection pipelines that pre-parse or truncate EventData may break extraction.

### Triage Runbook

First 15 minutes:
- Confirm the target object in ObjectDN is a computer account and identify the affected host and owning business unit.
- Review SubjectAccount and SubjectDomain to determine whether the writer is a known enrollment, sync, or PAM service account.
- Check whether OperationType is Value Added versus Value Deleted; treat Value Added as the higher-risk event.
- Look for nearby 5136 events on the same object for other sensitive attribute changes, especially delegation, SPN, or group membership changes.
- If the writer is not an approved service account, treat this as likely malicious and begin incident escalation.

Evidence to collect:
- Full 5136 event record including EventData, SubjectAccount, SubjectDomain, ObjectDN, AttributeName, and OperationType.
- The affected computer account name and whether it maps to a production server, workstation, or domain controller.
- Any preceding NTLM relay or LDAP authentication events from the same source host or account.
- Directory change history for the same ObjectDN over the prior 24 to 72 hours.
- Identity context for SubjectAccount, including whether it is a known Windows Hello, FIDO2, AAD Connect, or PAM enrollment account.

Pivot points:
- SecurityEvent for EventID 5136 on the same ObjectDN and SubjectAccount over the last 72 hours.
- SecurityEvent for EventID 4624 and 4776 involving the SubjectAccount or source host around the alert time.
- DeviceNetworkEvents or SecurityEvent network-related logs to identify LDAP, SMB, or WebDAV activity from the source host.
- Directory service logs for other changes to the affected computer account or related privileged groups.

Benign explanations:
- Windows Hello for Business or FIDO2 enrollment legitimately writes msDS-KeyCredentialLink.
- Hybrid identity or Azure AD Connect synchronization may touch this attribute in managed environments.
- Third-party PAM or MFA products may update the attribute during device or credential enrollment.

Escalation criteria:
- SubjectAccount is not a known enrollment or sync service account.
- The affected object is a privileged server, domain controller, or other high-value asset.
- There are signs of NTLM relay, suspicious LDAP activity, or other directory tampering around the same time.
- Multiple computer accounts or repeated msDS-KeyCredentialLink writes occur in a short window.

Containment actions:
- Disable or isolate the source account if it is confirmed unauthorized and still active.
- Reset credentials or disable the affected computer account only after confirming business impact and change ownership.
- Block the source host from further LDAP/SMB access if it is clearly malicious and not a managed enrollment system.
- Engage directory services administrators to remove unauthorized Shadow Credentials and validate Kerberos trust state.

Closure criteria:
- The change is validated as a documented enrollment or synchronization action by an approved service account.
- No additional suspicious directory changes, relay activity, or privilege escalation indicators are found.
- The affected object and writer account are confirmed to be expected for the environment and the event is documented as benign.

---

## Detection 2: Machine Account NTLM Authentication to Domain Controller LDAP from Non-DC Host

### Detection Opportunity

A machine account authenticates to a Domain Controller's LDAP service using NTLM from a non-Domain Controller source, consistent with NTLM relay attack coerced via WebDAV OpenEncryptedFileRaw.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: The Metasploit module coerces the local machine account to authenticate via OpenEncryptedFileRaw over WebDAV, then relays that NTLM authentication to a Domain Controller's LDAP service on port 389 to obtain a privileged LDAP session.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1557.001, T1021.002, T1558.003, T1021, T1558
- Products: Metasploit
- Platforms: Windows, Domain Controller, LDAP, WebDAV
- Malware: Not specified
- Tools: PsExec
- Search tags: T1557.001, T1021.002, Metasploit, PsExec, Windows, Domain Controller, LDAP, WebDAV, T1558.003, T1021, T1558

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Defense Evasion: T1558 Steal or Forge Kerberos Tickets/ T1558.003 Kerberoasting (medium)

### Deployment Gates

- The cross-product join between SecurityEvent and DeviceNetworkEvents requires the Microsoft Defender for Endpoint data connector to be active in the Sentinel workspace, or the query must be run in the unified Defender XDR advanced hunting portal.

Required telemetry:
- SecurityEvent, DeviceNetworkEvents

### KQL

```kql
let DCWatchlist = dynamic(["dc01", "dc02", "dc03"]);  // Replace with actual DC hostnames or load from a watchlist
let NTLMMachineLogons = SecurityEvent
| where TimeGenerated >= ago(1d)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName =~ "NTLM"
| where TargetUserName endswith "$"
| where tolower(Computer) has_any (DCWatchlist)
| where isnotempty(IpAddress) and IpAddress != "-" and IpAddress != "::1" and IpAddress != "127.0.0.1"
| where not (tolower(IpAddress) has_any (DCWatchlist))
| project LogonTime = TimeGenerated, DCName = Computer, MachineAccount = TargetUserName, TargetDomain = TargetDomainName, SourceIP = IpAddress;
let LDAPConnections = DeviceNetworkEvents
| where Timestamp >= ago(1d)
| where RemotePort == 389
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("lsass.exe", "svchost.exe")
| project ConnTime = Timestamp, SourceDevice = DeviceName, SourceDeviceIP = LocalIP, DestIP = RemoteIP, InitiatingProcessFileName;
NTLMMachineLogons
| join kind=inner (
    LDAPConnections
) on $left.SourceIP == $right.DestIP
| where abs(datetime_diff('second', LogonTime, ConnTime)) < 30
| project
    LogonTime,
    ConnTime,
    DCName,
    MachineAccount,
    TargetDomain,
    SourceIP,
    SourceDevice,
    InitiatingProcessFileName
| sort by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legacy applications that use NTLM for LDAP authentication from application servers will generate matches.
- Directory synchronization tools such as Azure AD Connect may generate machine account NTLM LDAP authentications.
- Backup agents and monitoring tools that query LDAP using machine account credentials.

Tuning notes:
- Replace the DCWatchlist dynamic array with a Sentinel watchlist lookup using '_GetWatchlist()' once a DC inventory watchlist is created.
- Consider adding a second join leg against DeviceNetworkEvents filtered for port 445 (SMB/WebDAV) from the same source device within a broader time window to correlate the coercion step.
- If the environment uses LDAPS (port 636) exclusively, add port 636 to the RemotePort filter.

Risks / caveats:
- The IpAddress field in SecurityEvent EventID 4624 is only populated when the logon originates from a network source; it may be empty or '-' for local logons, which would cause the join to fail silently.
- DeviceNetworkEvents is a Defender for Endpoint table and requires MDE onboarding on the source endpoints. Endpoints without MDE will not appear in this table, creating blind spots.
- Cross-workspace or cross-product joins between SecurityEvent (Sentinel workspace) and DeviceNetworkEvents (Defender XDR / MDE) require either the Sentinel-Defender connector or execution in the unified Defender XDR advanced hunting portal. This join will fail if run in a standalone Sentinel workspace without the MDE data connector.
- The has_any filter on Computer for 'DC' and 'DOMAINCONTROLLER' substrings is not a reliable DC identification method and must be replaced with environment-specific DC hostname values or a watchlist before the query produces meaningful results.

### Triage Runbook

First 15 minutes:
- Validate the source IP and SourceDevice are not domain controllers or approved directory infrastructure.
- Identify the MachineAccount and confirm whether it belongs to a server, workstation, or application host that should ever talk to LDAP via NTLM.
- Check the timing between the NTLM logon and the LDAP connection; close correlation strongly supports relay behavior.
- Review InitiatingProcessFileName on the source device for WebDAV, script, or exploit tooling indicators.
- If the source is a workstation or non-management server with no clear business reason, escalate immediately.

Evidence to collect:
- SecurityEvent 4624 details for the NTLM logon, including LogonType, TargetUserName, TargetDomainName, IpAddress, and Computer.
- DeviceNetworkEvents showing LDAP connections from the same source device and any related SMB/WebDAV traffic.
- The source device hostname, logged-on user, and initiating process lineage on the source host.
- Any directory changes on the DC immediately after the authentication event, especially msDS-KeyCredentialLink or privileged object modifications.
- Whether the machine account is associated with a known application server, sync tool, or monitoring platform.

Pivot points:
- SecurityEvent for EventID 4624, 4776, and 5136 around the same source IP and DC.
- DeviceNetworkEvents for the source device on ports 80, 443, 445, 389, and 636 to identify coercion and relay steps.
- DeviceProcessEvents on the source device for WebDAV clients, script hosts, or exploit frameworks.
- Directory service logs on the DC for attribute changes following the NTLM authentication.

Benign explanations:
- Legacy application servers may still use NTLM for LDAP authentication.
- Directory synchronization, backup, or monitoring tools may authenticate with machine accounts.
- Some management workflows can generate machine-account LDAP traffic from non-DC hosts in tightly controlled environments.

Escalation criteria:
- The source device is not a known management or application server.
- The machine account is a workstation or unexpected server account.
- There is evidence of WebDAV coercion, relay tooling, or immediate privileged LDAP modification.
- The same source IP is associated with multiple machine-account NTLM LDAP authentications.

Containment actions:
- Isolate the source device if relay activity is confirmed or strongly suspected.
- Disable or reset the compromised machine account only after confirming operational impact.
- Block the source host from LDAP and SMB access to domain controllers if malicious activity is ongoing.
- Coordinate with AD administrators to review and revert unauthorized directory changes.

Closure criteria:
- The source device is confirmed as an approved management or sync system with documented NTLM LDAP use.
- No suspicious process lineage, coercion traffic, or directory tampering is found.
- The machine account and DC interaction are validated against a known-good change or service workflow.

---

## Detection 3: PsExec Self-Targeting Execution Following S4U2Proxy Kerberos Ticket Acquisition

### Detection Opportunity

PsExec is executed targeting the local host under an Administrator or SYSTEM context, consistent with the final stage of the NTLM relay privilege escalation chain where S4U2Proxy yields a Kerberos ticket enabling self-lateral movement.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: After obtaining a Kerberos service ticket as Administrator via S4U2Proxy, the Metasploit module executes PsExec back to the same host it originated from to achieve SYSTEM access, making self-targeting PsExec a terminal indicator of this attack chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002, T1558.003, T1021, T1558
- Products: Metasploit
- Platforms: Windows
- Malware: Not specified
- Tools: PsExec
- Search tags: T1021.002, T1558.003, Metasploit, PsExec, Windows, T1021, T1558

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Defense Evasion: T1558 Steal or Forge Kerberos Tickets/ T1558.003 Kerberoasting (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("PsExec.exe", "PsExec64.exe")
| where InitiatingProcessFileName in~ ("autogenstudio.exe", "node.exe", "python.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "msfconsole", "ruby.exe", "wscript.exe", "cscript.exe")
    or isnotempty(InitiatingProcessFileName)
| where ProcessCommandLine has "127.0.0.1"
    or ProcessCommandLine has "localhost"
    or ProcessCommandLine has DeviceName
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ChildProcess = FileName,
    ProcessCommandLine,
    SHA1,
    MD5,
    AccountName,
    InitiatingProcessId,
    ProcessId
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- IT administrators running PsExec against localhost for testing or troubleshooting.
- Automated deployment scripts that use PsExec to execute local tasks under elevated context.
- Software packaging tools that invoke PsExec for local installation steps.

Tuning notes:
- To reduce noise, add a filter on InitiatingProcessAccountName to exclude known IT admin accounts or service accounts that legitimately use PsExec.
- Consider adding a SHA256 allowlist of known-legitimate PsExec binaries to distinguish Sysinternals-signed PsExec from attacker-supplied copies.
- Extend the lookback window beyond 7 days for threat hunting purposes; reduce to 1 day if converted to a scheduled rule after baselining.

Risks / caveats:
- The original KQL used 'has_any ("127.0.0.1", "localhost", DeviceName)' where DeviceName is a column reference, which is not valid KQL syntax inside has_any with a mix of string literals and column references. This would cause a query error at runtime.
- DeviceLogonEvents LogonType 3 for SYSTEM account is a very common event on Windows endpoints and joining solely on DeviceName without process ID linkage will produce a high volume of coincidental matches.
- The ProcessCommandLine has DeviceName check performs a per-row string search against the device's own hostname, which is valid KQL but may miss cases where the attacker uses the FQDN or an IP alias not matching the DeviceName value.
- The InitiatingProcessFileName filter was broadened to avoid missing cases where PsExec is launched from an unexpected parent; analysts should review the parent process context during triage.

### Triage Runbook

First 15 minutes:
- Confirm the parent process and initiating account for the PsExec execution.
- Check whether the command line explicitly targets localhost, 127.0.0.1, or the device's own hostname.
- Determine whether the initiating account is an IT admin, deployment service, or an unexpected user context.
- Review nearby process activity for evidence of ticket abuse, credential theft, or prior relay activity on the same host.
- If the host is a production endpoint and the account is not clearly authorized, escalate as likely compromise.

Evidence to collect:
- DeviceProcessEvents for the PsExec process, including command line, parent process, and account context.
- Any child processes spawned by PsExec and whether they ran under SYSTEM or an elevated administrator context.
- SHA1, MD5, and SHA256 of the PsExec binary if available for reputation and provenance checks.
- Recent logon and privilege events on the same host, especially unusual admin logons or service creation.
- Any preceding directory or Kerberos-related activity that suggests S4U2Proxy abuse.

Pivot points:
- DeviceProcessEvents for PsExec.exe, PsExec64.exe, cmd.exe, powershell.exe, and related child processes on the same host.
- DeviceLogonEvents for recent admin, SYSTEM, or unusual logons on the device.
- DeviceNetworkEvents for SMB connections and remote execution activity from the same account or host.
- SecurityEvent or Defender XDR identity logs for correlated privilege escalation or ticket-related events.

Benign explanations:
- IT administrators may use PsExec for local troubleshooting or software deployment.
- Automation or packaging tools may invoke PsExec during installation workflows.
- Lab, test, or build systems may legitimately self-target for validation or scripting.

Escalation criteria:
- The initiating account is not a known admin or automation account.
- The PsExec command line indicates self-targeting in a production environment without a change record.
- There are signs of prior NTLM relay, suspicious LDAP activity, or unexpected privilege escalation.
- The spawned process runs as SYSTEM and performs follow-on actions such as persistence, credential access, or lateral movement.

Containment actions:
- Disable the initiating account if unauthorized use is confirmed.
- Isolate the host if PsExec is being used as part of active compromise or post-exploitation.
- Terminate malicious child processes only after capturing volatile evidence where possible.
- Coordinate with endpoint and identity teams to review for persistence and credential exposure.

Closure criteria:
- The activity is tied to a documented admin or automation workflow.
- No suspicious parent process, account misuse, or follow-on malicious behavior is identified.
- The PsExec execution is confirmed to be a benign local management action and is documented.

---

## Detection 4: Clipboard Hijacking Process with Concurrent Tor Network Communication

### Detection Opportunity

A process accesses clipboard APIs and simultaneously establishes network connections to Tor infrastructure ports, consistent with a crypto clipper malware replacing cryptocurrency wallet addresses and communicating through Tor for command and control.

### Intelligence Context

- Microsoft Security Blog: Crypto Clipper uses Tor and worm-like propagation for persistence and control — [https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
  - Context: The malware combines clipboard theft and wallet address replacement with Tor-based C2 communications. Detecting clipboard API access co-occurring with Tor port connections from the same non-browser process provides a compound, high-confidence signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1115, T1090.003, T1090
- Products: Tor
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1115, T1090.003, Tor, Windows, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1115 Clipboard Data (high); Command and Control: T1090 Proxy/ T1090.003 Multi-hop Proxy (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents, DeviceNetworkEvents before scheduling.

Required telemetry:
- DeviceEvents, DeviceNetworkEvents

### KQL

```kql
let ClipboardAccessors = DeviceEvents
| where Timestamp >= ago(1d)
| where ActionType in~ ("ClipboardRead", "SetClipboard", "GetClipboardData")
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "brave.exe", "opera.exe", "vivaldi.exe", "tor.exe"
)
| project
    ClipTime = Timestamp,
    DeviceName,
    AccountName,
    ClipProcess = InitiatingProcessFileName,
    InitiatingProcessId,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName;
let TorConnections = DeviceNetworkEvents
| where Timestamp >= ago(1d)
| where RemotePort in (9001, 9050, 9150)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "brave.exe", "opera.exe", "vivaldi.exe", "tor.exe"
)
| project
    TorTime = Timestamp,
    DeviceName,
    TorProcess = InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    InitiatingProcessId,
    ProcessSHA1 = InitiatingProcessSHA1,
    ProcessMD5 = InitiatingProcessMD5;
ClipboardAccessors
| join kind=inner (
    TorConnections
) on DeviceName, InitiatingProcessId
| where abs(datetime_diff('minute', ClipTime, TorTime)) <= 10
| project
    ClipTime,
    TorTime,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessParentFileName,
    ClipProcess,
    TorProcess,
    RemoteIP,
    RemotePort,
    ProcessSHA1,
    ProcessMD5
| sort by ClipTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Security researchers or malware analysts running samples in non-isolated environments.
- Password managers or clipboard utility tools that access clipboard APIs may coincidentally run on systems where Tor Browser is also installed.
- Automated testing frameworks that interact with clipboard APIs.

Tuning notes:
- Before scheduling, run the ClipboardAccessors subquery standalone over 14 days to confirm ActionType availability: DeviceEvents | where ActionType in~ ('ClipboardRead', 'SetClipboard', 'GetClipboardData') | summarize count() by ActionType.
- If clipboard ActionTypes are unavailable, consider an alternative detection pivot using DeviceEvents for process injection or API hooking ActionTypes combined with the Tor port filter.
- Add additional Tor-associated ports (9040, 9051, 9053) if the environment's threat intel indicates Tor relay or control port usage.

Risks / caveats:
- The ActionType values 'ClipboardRead', 'SetClipboard', and 'GetClipboardData' in DeviceEvents are not guaranteed to be present in all MDE deployments. These ActionTypes depend on specific sensor capabilities and may not be collected on all Windows versions or MDE license tiers. If absent, the detection produces zero results without any error.
- Port 9150 is the Tor Browser's SOCKS proxy port and is typically only present when Tor Browser is installed; including it without excluding the Tor Browser executable may generate false positives from legitimate Tor Browser usage.
- If ClipboardRead, SetClipboard, or GetClipboardData ActionTypes are not present in the environment's DeviceEvents, this detection will silently produce zero results. Validate ActionType availability before scheduling.
- Tor bridges and non-standard Tor ports will not be detected by port-based filtering alone.

### Triage Runbook

First 15 minutes:
- Identify the process name, parent process, and account associated with the clipboard access and Tor connection.
- Check whether the process is a browser, Tor Browser, password manager, or another known legitimate clipboard consumer.
- Review the RemoteIP and RemotePort to determine whether the connection is to Tor infrastructure or a known benign service.
- Look for recent clipboard-related user complaints, wallet address changes, or suspicious copy/paste behavior on the host.
- If the process is not a known legitimate application, treat the alert as likely malware and escalate.

Evidence to collect:
- DeviceEvents records showing clipboard-related ActionType values and the initiating process details.
- DeviceNetworkEvents for the same process and device, including RemoteIP, RemotePort, and process hashes.
- Process lineage for the clipboard-accessing process, including parent and grandparent processes.
- Any user-reported wallet address changes, clipboard anomalies, or suspicious browser activity.
- File hashes and reputation results for the process binary and any dropped artifacts.

Pivot points:
- DeviceEvents for additional clipboard access by the same process or account.
- DeviceNetworkEvents for repeated Tor-port connections, especially to the same RemoteIP.
- DeviceProcessEvents for the same process tree to identify persistence, injection, or payload staging.
- Defender XDR or threat intel lookups for the process hashes and RemoteIP.

Benign explanations:
- Tor Browser can legitimately connect to Tor ports and should be excluded if it is the initiating process.
- Password managers or clipboard utilities may access clipboard APIs during normal use.
- Security research or malware analysis environments may intentionally trigger both behaviors.

Escalation criteria:
- The process is not a known browser, Tor Browser, or approved clipboard utility.
- Tor connections occur from a non-browser process with no business justification.
- There is evidence of wallet address replacement, persistence, or additional malicious behavior.
- Multiple hosts show the same process pattern or the same RemoteIP is reused across endpoints.

Containment actions:
- Isolate the host if the process is confirmed or strongly suspected to be malicious.
- Terminate the suspicious process and any related child processes after preserving evidence.
- Block the RemoteIP or Tor-related egress path if it is clearly malicious and not required for business use.
- Reset credentials or secure wallets if the user reports clipboard tampering involving sensitive financial addresses.

Closure criteria:
- The process is identified as a legitimate browser, Tor Browser, or approved utility.
- No malicious clipboard replacement, persistence, or suspicious network behavior is found.
- The event is explained by a known test, research, or administrative workflow and documented.

---

## Detection 5: Shell or Interpreter Spawned by AutoGen Studio or AI Agent WebSocket Process

### Detection Opportunity

A shell interpreter or scripting engine is spawned as a child of an AutoGen Studio or Node.js process listening on a localhost WebSocket port, consistent with arbitrary code execution triggered through an unauthenticated MCP WebSocket interface by a malicious webpage.

### Intelligence Context

- Microsoft Security Blog: AutoJack: How a single page can RCE the host running your AI agent — [https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/](https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/)
  - Context: A malicious webpage abuses the unauthenticated AutoGen Studio MCP WebSocket interface on localhost to trigger arbitrary process execution on the host. The attack manifests as shell or interpreter processes spawned from the AutoGen Studio or node.exe parent process, which is highly anomalous for an AI agent framework.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: AutoGen Studio, MCP WebSocket
- Platforms: AI agent host
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, T1059, AutoGen Studio, MCP WebSocket, AI agent host

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp >= ago(1d)
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "bash.exe",
    "sh.exe", "mshta.exe"
)
| where InitiatingProcessFileName in~ (
    "autogenstudio.exe", "node.exe", "python.exe", "python3.exe"
)
| project
    SpawnTime = Timestamp,
    DeviceName,
    AccountName,
    ParentProcess = InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessParentFileName,
    ChildProcess = FileName,
    ProcessCommandLine,
    ProcessId,
    SHA256,
    SHA1,
    MD5
| sort by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Development environments where node.exe or python.exe legitimately spawn shell processes as part of build scripts, test runners, or package installation.
- CI/CD pipeline agents running on developer workstations where node.exe invokes shell commands.
- Python-based automation frameworks that intentionally spawn cmd.exe or powershell.exe as subprocess calls.

Tuning notes:
- To reduce false positives in development environments, add a filter on DeviceName or DeviceCategory to scope the rule to production or server-class hosts where AI agent frameworks are deployed.
- Consider adding a secondary filter on InitiatingProcessCommandLine to look for WebSocket-related arguments such as '--port', 'ws://', or 'websocket' to increase specificity.
- If the AutoGen Studio WebSocket port is known and consistent, a corroborating lookup against DeviceNetworkEvents for recent outbound connections from the same InitiatingProcessId to that port can be added as an enrichment step after the main query.

Risks / caveats:
- DeviceNetworkEvents records outbound network connections from the perspective of the initiating process. Localhost loopback listener activity (a process accepting connections on 127.0.0.1) is not reliably captured as a ConnectionSuccess event in this table, meaning the AIAgentParents subquery may return zero results and cause the join to produce no output.
- The LocalPort field in DeviceNetworkEvents refers to the local source port of an outbound connection, not a listening port. Filtering on LocalPort to identify a WebSocket listener is semantically incorrect for this table and will not reliably identify processes listening on those ports.
- The detection relies on the AutoGen Studio process running as autogenstudio.exe, node.exe, or python.exe. If the framework is installed under a different executable name or wrapped in a service host, it will not be detected.
- Development environments where node.exe or python.exe legitimately spawn shells will generate false positives; an allowlist of known-good parent command lines or host scoping is required to operationalize this as a scheduled rule.

### Triage Runbook

First 15 minutes:
- Confirm the parent process is autogenstudio.exe, node.exe, python.exe, or python3.exe and identify the exact command line.
- Check whether the child process is a shell or scripting interpreter that is unusual for the host's normal AI agent workflow.
- Determine whether the host is expected to run AutoGen Studio or other AI agent tooling in production.
- Review the account context and recent user activity to see whether a browser session or external page load preceded the spawn.
- If the host is not a known AI agent system or the shell spawn is unexpected, escalate immediately.

Evidence to collect:
- DeviceProcessEvents showing the parent-child process chain, command lines, and account context.
- Any related DeviceNetworkEvents for the same parent process to identify recent localhost or external connections.
- Process hashes for the parent and child processes for reputation and provenance checks.
- Host inventory data showing whether the device is a sanctioned AI agent or development system.
- Any browser history, user activity, or application logs indicating a webpage or external trigger.

Pivot points:
- DeviceProcessEvents for additional shell, script, or download activity from the same parent process.
- DeviceNetworkEvents for the parent process and related outbound connections around the alert time.
- DeviceFileEvents for dropped files, scripts, or payloads created by the child process.
- Defender XDR or endpoint telemetry for persistence, scheduled tasks, or service creation on the same host.

Benign explanations:
- Development, test, or CI/CD environments may legitimately have node.exe or python.exe spawn shells.
- Automation frameworks may intentionally launch cmd.exe, powershell.exe, or script hosts as part of workflows.
- Known AI agent hosts may execute local scripts during normal operation if properly controlled.

Escalation criteria:
- The host is not an approved AI agent or development system.
- The shell spawn occurs without a documented automation workflow or change record.
- There is evidence of browser-driven exploitation, unexpected external access, or follow-on malicious activity.
- The spawned shell performs persistence, credential access, or additional code execution.

Containment actions:
- Isolate the host if unauthorized code execution is suspected or confirmed.
- Terminate the suspicious shell and related child processes after preserving evidence.
- Disable the affected user account if the activity is tied to malicious interaction or abuse.
- Remove or restrict exposure of the AI agent service until the interface is secured and validated.

Closure criteria:
- The process tree is tied to a documented and expected automation or development workflow.
- The host is confirmed as an approved AI agent system and the shell spawn is normal for that workflow.
- No evidence of exploitation, persistence, or malicious follow-on activity is found.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Machine Account NTLM Authentication to Domain Controller LDAP from Non-DC Host: The cross-product join between SecurityEvent and DeviceNetworkEvents requires the Microsoft Defender for Endpoint data connector to be active in the Sentinel workspace, or the query must be run in the unified Defender XDR advanced hunting portal.
- Clipboard Hijacking Process with Concurrent Tor Network Communication: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents, DeviceNetworkEvents before scheduling.
- Shell or Interpreter Spawned by AutoGen Studio or AI Agent WebSocket Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

Schema / correlation keys:
- PsExec Self-Targeting Execution Following S4U2Proxy Kerberos Ticket Acquisition: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- SecurityEvent: shared by Shadow Credentials Written via msDS-KeyCredentialLink Modification; Machine Account NTLM Authentication to Domain Controller LDAP from Non-DC Host
- DeviceNetworkEvents: shared by Machine Account NTLM Authentication to Domain Controller LDAP from Non-DC Host; Clipboard Hijacking Process with Concurrent Tor Network Communication; Shell or Interpreter Spawned by AutoGen Studio or AI Agent WebSocket Process
- DeviceProcessEvents: shared by PsExec Self-Targeting Execution Following S4U2Proxy Kerberos Ticket Acquisition; Shell or Interpreter Spawned by AutoGen Studio or AI Agent WebSocket Process

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Shadow Credentials Written via msDS-KeyCredentialLink Modification.
2. Resolve environment-mapping detections next: Machine Account NTLM Authentication to Domain Controller LDAP from Non-DC Host; Clipboard Hijacking Process with Concurrent Tor Network Communication; Shell or Interpreter Spawned by AutoGen Studio or AI Agent WebSocket Process.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: PsExec Self-Targeting Execution Following S4U2Proxy Kerberos Ticket Acquisition.

### Hunting Agenda and Promotion Criteria

- PsExec Self-Targeting Execution Following S4U2Proxy Kerberos Ticket Acquisition: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Machine Account NTLM Authentication to Domain Controller LDAP from Non-DC Host: The cross-product join between SecurityEvent and DeviceNetworkEvents requires the Microsoft Defender for Endpoint data connector to be active in the Sentinel workspace, or the query must be run in the unified Defender XDR advanced hunting portal.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Clipboard Hijacking Process with Concurrent Tor Network Communication: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents, DeviceNetworkEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Shell or Interpreter Spawned by AutoGen Studio or AI Agent WebSocket Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
