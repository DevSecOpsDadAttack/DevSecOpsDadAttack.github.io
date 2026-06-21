---
layout: post
title: "Detection Engineering Brief - Sunday, June 21, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-21
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Metasploit
  - PsExec
  - Windows
  - Active Directory
  - LDAP
  - T1557.001
  - T1098
  - T1558.003
  - T1021.002
  - Tor
  - T1090.003
  - T1547
  - Sapphire Sleet
  - npm
  - Node.js
  - T1195.001
  - T1059
  - software development environments
  - AutoGen Studio
  - MCP WebSocket
  - AI agent
  - T1190
  - T1021
  - T1557
  - T1090
  - T1195
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Metasploit, PsExec, Windows, Active Directory, LDAP, T1557.001, T1098, T1558.003, T1021.002, Tor, T1090.003, T1547, Sapphire Sleet, npm, Node.js, T1195.001, T1059, software development environments, AutoGen Studio, MCP WebSocket, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: NTLM Relay to LDAP with Shadow Credential Write on Domain Controller; npm Postinstall Script Spawning Shell Interpreter During Package Installation; AI Agent Process Spawning System Shell via AutoGen Studio MCP WebSocket.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: NTLM Relay to LDAP with Shadow Credential Write on Domain Controller

### Detection Opportunity

Machine account NTLM authentication relayed to domain controller LDAP service, followed by msDS-KeyCredentialLink attribute modification to write Shadow Credentials for privilege escalation.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: Metasploit module coerces local machine account authentication via OpenEncryptedFileRaw over WebDAV, relays NTLM to the domain controller LDAP service, then writes Shadow Credentials via msDS-KeyCredentialLink to obtain a Kerberos ticket as Administrator, enabling PsExec SYSTEM access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1557.001, T1098, T1558.003, T1021, T1021.002, T1557
- Products: Metasploit
- Platforms: Windows, Active Directory, LDAP
- Malware: Not specified
- Tools: PsExec
- Search tags: Metasploit, PsExec, Windows, Active Directory, LDAP, T1557.001, T1098, T1558.003, T1021, T1021.002, T1557

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Credential Access: T1557 Adversary-in-the-Middle/ T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents, SecurityEvent before scheduling.

Required telemetry:
- DeviceNetworkEvents, SecurityEvent

### KQL

```kql
let LDAPMachineConnections = DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemotePort in (389, 636)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessAccountName endswith "$"
| project LDAPTime = TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName;
let ShadowCredWrites = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 5136
| where OperationType == "%%14674"
| where AttributeLDAPDisplayName =~ "msDS-KeyCredentialLink"
| where SubjectUserName endswith "$"
| extend SourceHost = tostring(split(SubjectUserName, "$")[0])
| project WriteTime = TimeGenerated, SourceHost, SubjectUserName, TargetUserName, AttributeLDAPDisplayName, Computer;
LDAPMachineConnections
| join kind=inner ShadowCredWrites on $left.DeviceName == $right.SourceHost
| where WriteTime between (LDAPTime .. (LDAPTime + 30m))
| project
    LDAPTime,
    WriteTime,
    DeviceName,
    RemoteIP,
    RemotePort,
    InitiatingProcessAccountName,
    SubjectUserName,
    TargetUserName,
    AttributeLDAPDisplayName,
    SourceHost
| extend AlertDetail = strcat("Machine account LDAP relay from ", DeviceName, " to ", RemoteIP, " followed by Shadow Credential write targeting ", TargetUserName)
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Windows Hello for Business enrollment writes msDS-KeyCredentialLink legitimately; these will appear if the enrolling device also has LDAP connections to DCs.
- Identity management products (e.g., Azure AD Connect, CyberArk) may write msDS-KeyCredentialLink during provisioning workflows.
- Legitimate LDAP-connected admin tools running as machine accounts on management hosts may trigger the network connection side.

Tuning notes:
- Scope RemoteIP to a watchlist or explicit list of domain controller IPs to significantly reduce noise from non-DC LDAP services.
- Reduce the correlation window from 30 minutes to 5-10 minutes if relay-to-write dwell time in the environment is consistently short.
- Add an exclusion for known Windows Hello for Business enrollment servers or identity management hosts by DeviceName.

Risks / caveats:
- SecurityEvent EventID 5136 is only generated when Advanced Audit Policy > DS Access > Audit Directory Service Changes is enabled on domain controllers; this is not enabled by default and must be confirmed.
- SecurityEvent must be forwarded from domain controllers to the Sentinel workspace via the Windows Security Events connector or AMA; absence of this connector means the ShadowCredWrites subquery returns no rows.
- AttributeLDAPDisplayName and OperationType are fields parsed from the EventData XML of Event 5136; their availability depends on the connector parsing the raw event correctly — verify these fields are populated in the SecurityEvent table in the target workspace.
- The join key equating DeviceName (from DeviceNetworkEvents, a Defender for Endpoint field) to a hostname extracted from SubjectUserName (a Security Event field containing SAM account or UPN) is not guaranteed to match; SubjectUserName in 5136 reflects the account performing the write, not necessarily the relay source host.

### Triage Runbook

First 15 minutes:
- Validate the source host and domain controller IP in the alert against your known DC inventory and management hosts.
- Check whether the SubjectUserName is a machine account ending in '$' and whether the TargetUserName is a privileged or sensitive account.
- Review the 5136 directory change details to confirm the attribute modified was msDS-KeyCredentialLink and that the operation was an addition, not a removal.
- Look for nearby signs of relay tooling or follow-on access from the same host, including PsExec service creation, SMB admin share access, or unusual LDAP activity.
- If the write targeted a high-value account or the source host is not a known admin/provisioning system, treat as active compromise.

Evidence to collect:
- DeviceNetworkEvents for the source host showing LDAP connections to the DC IP and the initiating process/account used.
- SecurityEvent 5136 details including Computer, SubjectUserName, TargetUserName, AttributeLDAPDisplayName, and OperationType.
- Any correlated process telemetry on the source host around the same time, especially OpenEncryptedFileRaw/WebDAV, relay tooling, or PsExec.
- Directory context for the target account: group membership, recent password resets, and whether Windows Hello for Business or identity tooling is expected.
- DC-side logs showing additional directory changes or Kerberos ticket activity tied to the same source host or account.

Pivot points:
- SecurityEvent on EventID 5136 filtered to TargetUserName and AttributeLDAPDisplayName = msDS-KeyCredentialLink.
- DeviceNetworkEvents filtered to the source DeviceName and RemoteIP in the DC range, with RemotePort 389 or 636.
- DeviceProcessEvents on the source host for relay-related or admin tooling processes around the alert window.
- SecurityEvent and DeviceLogonEvents for the target account to identify subsequent logons or ticket use.

Benign explanations:
- Windows Hello for Business enrollment or re-enrollment can legitimately write msDS-KeyCredentialLink.
- Identity management or privileged access tooling may write the attribute during provisioning workflows.
- A known admin workstation or automation host may generate LDAP traffic to DCs as part of normal operations.

Escalation criteria:
- Escalate immediately if the target is a domain admin, service account with broad privileges, or a Tier 0 identity.
- Escalate if the source host is not a known provisioning, identity, or admin system.
- Escalate if there is evidence of subsequent PsExec, remote service creation, or other lateral movement from the same host.
- Escalate if multiple accounts or multiple DCs show similar Shadow Credential writes in a short time window.

Containment actions:
- Isolate the source host if it is not a trusted identity/provisioning system and the activity is confirmed malicious.
- Disable or reset the affected account if it is privileged and you confirm unauthorized Shadow Credential modification.
- Remove the malicious msDS-KeyCredentialLink entry and review for additional unauthorized directory changes.
- Block the source host from DC access while preserving evidence if the environment allows safe containment.

Closure criteria:
- Confirmed as a legitimate Windows Hello for Business or identity-management workflow with matching change records.
- The source host is a known approved provisioning/admin system and the target account is expected.
- No additional suspicious LDAP, PsExec, or directory modification activity is found after review.
- Any unauthorized attribute change has been remediated and the account/host has been validated by the identity team.

---

## Detection 2: PsExec SYSTEM Execution Following Machine Account NTLM Logon

### Detection Opportunity

PsExec used to spawn a SYSTEM-level process on a host immediately after an NTLM network logon from a machine account, consistent with post-relay lateral movement for privilege escalation.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: After relaying NTLM credentials and obtaining a Kerberos ticket as Administrator, the Metasploit module uses PsExec to execute back to the originating host for SYSTEM-level access, completing the privilege escalation chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002, T1557.001, T1021, T1557
- Products: Metasploit
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: PsExec
- Search tags: Metasploit, PsExec, Windows, Active Directory, T1021.002, T1557.001, T1021, T1557

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Credential Access: T1557 Adversary-in-the-Middle/ T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
let PsExecActivity = DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where FileName =~ "PSEXESVC.exe"
    or ProcessCommandLine has_cs "PSEXESVC"
    or InitiatingProcessFileName in~ ("psexec.exe", "psexec64.exe")
| project PsExecTime = TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName;
let MachineAccountLogons = DeviceLogonEvents
| where TimeGenerated > ago(1d)
| where LogonType == "Network"
| where AccountName endswith "$"
| project LogonTime = TimeGenerated, DeviceName, AccountName, AccountDomain, LogonId;
MachineAccountLogons
| join kind=inner PsExecActivity on DeviceName
| where PsExecTime between (LogonTime .. (LogonTime + 15m))
| project
    LogonTime,
    PsExecTime,
    DeviceName,
    AccountName,
    AccountDomain,
    LogonId,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| extend AlertDetail = strcat("Machine account ", AccountName, " network logon followed by PsExec execution on ", DeviceName)
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate IT administration using PsExec from management servers that authenticate as machine accounts.
- Automated patch management or software deployment tools that use PsExec and authenticate via machine account credentials.
- Security scanning tools that perform network logons and spawn service processes on target hosts.

Tuning notes:
- Build a DeviceName exclusion list for known administrative hosts, jump servers, and patch management systems that legitimately use PsExec.
- Reduce the correlation window from 15 minutes to 2-5 minutes if relay-to-execution dwell time in the environment is consistently shorter.
- Consider adding an AccountName exclusion for specific service machine accounts known to perform legitimate network logons.

Risks / caveats:
- DeviceLogonEvents is only populated for devices onboarded to Microsoft Defender for Endpoint; endpoints not onboarded will produce no results for the logon side of the correlation.
- The 15-minute correlation window may produce false positives in environments where machine account network logons and PsExec activity coincidentally overlap on the same host.
- PSEXESVC.exe may not appear in DeviceProcessEvents if PsExec is blocked at the network layer or if the service binary is renamed; the InitiatingProcessFileName check partially mitigates this.
- Machine accounts performing legitimate scheduled tasks with network logons on hosts that also run PsExec-based admin tooling will generate false positives until exclusions are tuned.

### Triage Runbook

First 15 minutes:
- Confirm the target host and the machine account that performed the network logon in DeviceLogonEvents.
- Check whether the PsExec activity occurred within minutes of the logon and whether the process was PSEXESVC.exe or a renamed equivalent.
- Review the initiating process command line and parent process to see whether the execution came from a known admin tool, patch system, or suspicious source.
- Validate whether the target host is a server or workstation that should ever receive PsExec from that machine account.
- If the machine account is unexpected or the host is not a known admin endpoint, treat the alert as likely malicious lateral movement.

Evidence to collect:
- DeviceLogonEvents for the target host, including AccountName, AccountDomain, LogonType, and LogonId.
- DeviceProcessEvents for PSEXESVC.exe, psexec.exe, psexec64.exe, or renamed service binaries on the target host.
- Process command line and parent process details to identify the source of the PsExec execution.
- Any related SMB, admin share, or service creation telemetry around the same time.
- Host inventory or change records showing whether the target is managed by a legitimate remote administration workflow.

Pivot points:
- DeviceProcessEvents on the target host for service creation, cmd.exe, powershell.exe, or other child processes spawned by PSEXESVC.
- DeviceLogonEvents filtered to the same AccountName and DeviceName to identify repeated network logons.
- DeviceNetworkEvents for SMB connections to the target host from the same source host or machine account.
- SecurityEvent or endpoint telemetry for service installation events around the PsExec time window.

Benign explanations:
- Legitimate IT administration from a jump host or management server using PsExec.
- Automated patching, software deployment, or remote support tooling that uses PsExec under the hood.
- Security scanning or validation tools that intentionally create remote service executions.

Escalation criteria:
- Escalate if the machine account is not associated with a known management system or service.
- Escalate if the target host is a domain controller, server with sensitive data, or a Tier 0 asset.
- Escalate if PsExec is followed by credential dumping, new local admin creation, or additional lateral movement.
- Escalate if the same source account or host appears across multiple targets in a short period.

Containment actions:
- Isolate the target host if the PsExec execution is unauthorized and active compromise is suspected.
- Disable or restrict the machine account if it is being abused and not required for business operations.
- Block the source management path temporarily if the activity is clearly malicious and not a sanctioned admin workflow.
- Preserve service creation and process evidence before remediation.

Closure criteria:
- Confirmed as a sanctioned administration or patch-management action with matching change ticket.
- The machine account and source host are known and approved for remote administration.
- No additional suspicious child processes, service creations, or lateral movement are observed.
- Any unauthorized execution has been contained and the target host is clean after follow-up review.

---

## Detection 3: Tor C2 Communication from Non-Browser Process with Startup Persistence

### Detection Opportunity

A non-browser process establishes connections to Tor network ports (9001, 9050) for C2 communication, correlated with a registry Run key or startup folder write by the same process, consistent with the crypto clipper malware's persistence and Tor-based C2 pattern.

### Intelligence Context

- Microsoft Security Blog: Crypto Clipper uses Tor and worm-like propagation for persistence and control — [https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
  - Context: The crypto clipper malware uses Tor-based C2 communications and establishes persistence via startup mechanisms. Combining Tor port connectivity with registry Run key writes from the same initiating process provides a compound high-fidelity signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090.003, T1547, T1090
- Products: Not specified
- Platforms: Windows, Tor
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, Tor, T1090.003, T1547, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.003 Multi-hop Proxy (high); Persistence: T1547 Boot or Logon Autostart Execution (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceNetworkEvents, DeviceRegistryEvents

### KQL

```kql
let TorConnections = DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemotePort in (9001, 9050)
    or InitiatingProcessFileName =~ "tor.exe"
| where not(
    InitiatingProcessFileName =~ "firefox.exe"
    or (InitiatingProcessFileName =~ "tor.exe" and InitiatingProcessFolderPath has "Tor Browser")
  )
| project
    TorTime = TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    RemotePort,
    RemoteIP;
let RunKeyWrites = DeviceRegistryEvents
| where TimeGenerated > ago(1d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
  )
| project
    RegTime = TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    RegistryKey,
    RegistryValueName,
    RegistryValueData;
TorConnections
| join kind=inner RunKeyWrites on DeviceName, InitiatingProcessFileName
| where RegTime between ((TorTime - 60m) .. (TorTime + 60m))
| project
    TorTime,
    RegTime,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine = InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    RemotePort,
    RemoteIP,
    RegistryKey,
    RegistryValueName,
    RegistryValueData
| extend AlertDetail = strcat(
    InitiatingProcessFileName,
    " connected to Tor port ",
    RemotePort,
    " (",
    RemoteIP,
    ") and wrote Run key ",
    RegistryValueName,
    " = ",
    RegistryValueData
  )
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Tor Browser installed outside its default bundle path may trigger if the process name matches and it writes a Run key during installation.
- Privacy-focused applications that use Tor as a transport layer and also write startup persistence entries.
- Security research tools or sandboxes running on monitored endpoints that test Tor connectivity.

Tuning notes:
- Add InitiatingProcessFolderPath exclusions for any internally approved tools that legitimately write Run keys and happen to use Tor.
- Consider joining on InitiatingProcessId in addition to DeviceName and InitiatingProcessFileName to reduce cross-instance false positives.
- Extend port coverage to 9150 (Tor Browser SOCKS port) if the environment has observed malware using that port.

Risks / caveats:
- DeviceNetworkEvents only captures connections for devices onboarded to Defender for Endpoint; endpoints not onboarded will not generate Tor connection telemetry.
- The 60-minute bidirectional correlation window is wide; a malware sample that writes persistence long before or after Tor connectivity may be missed, while coincidental matches on shared process names writing Run keys near Tor connections may produce false positives.
- Joining on InitiatingProcessFileName alone (without process ID) may match different instances of the same process name on the same device; adding InitiatingProcessId to the join would improve precision but requires confirming the field is consistently populated.
- Malware that uses a Tor proxy on a non-standard port (not 9001 or 9050) will not be detected by the port-based filter.

### Triage Runbook

First 15 minutes:
- Confirm the initiating process is not Tor Browser or another approved privacy tool by checking the folder path and command line.
- Validate the remote port and IP to see whether the connection is consistent with Tor-related traffic and whether the process is a non-browser executable.
- Review the registry write details to confirm a Run or RunOnce persistence entry and capture the value data.
- Check whether the same process created additional suspicious child processes, dropped files, or made outbound connections to other unusual destinations.
- If the process is not an approved application and persistence is present, treat the host as compromised.

Evidence to collect:
- DeviceNetworkEvents showing the Tor-port connection, remote IP, and initiating process details.
- DeviceRegistryEvents showing the Run/RunOnce key write, value name, and value data.
- Process tree for the initiating process, including parent process and any child processes.
- File creation or modification telemetry for payloads written near the same time.
- Host inventory or software list to confirm whether Tor Browser or another approved Tor-using application is installed.

Pivot points:
- DeviceProcessEvents for the initiating process and its children around the alert time.
- DeviceRegistryEvents for additional autostart locations such as Startup folder, RunOnce, Services, or Scheduled Tasks.
- DeviceNetworkEvents for repeated Tor-port connections or other suspicious outbound traffic from the same host.
- DeviceFileEvents for dropped executables, scripts, or configuration files associated with the process.

Benign explanations:
- Tor Browser or a sanctioned privacy application using Tor-related ports.
- A security research or lab system intentionally testing Tor connectivity.
- A legitimate installer or updater that writes a Run key and happens to use a process name similar to the alerting process.

Escalation criteria:
- Escalate if the process is not Tor Browser and the host is not a known research or privacy-testing system.
- Escalate if the Run key points to an unknown executable, script, or user-writable path.
- Escalate if there are repeated Tor connections, additional persistence mechanisms, or evidence of credential theft.
- Escalate if the host is a server or endpoint that should not have Tor-related software installed.

Containment actions:
- Isolate the host if unauthorized Tor C2 and persistence are confirmed.
- Disable the persistence entry and quarantine the payload after evidence capture.
- Block the malicious executable hash or path if available in your environment.
- Reset credentials if the host shows signs of follow-on credential access or lateral movement.

Closure criteria:
- The process is confirmed as approved Tor Browser or another sanctioned application.
- The registry write is tied to a legitimate installer, updater, or approved software deployment.
- No additional suspicious network activity, persistence, or payload artifacts are found.
- Any unauthorized persistence has been removed and the host has been validated by follow-up review.

---

## Detection 4: npm Postinstall Script Spawning Shell Interpreter During Package Installation

### Detection Opportunity

npm or node.exe spawns a shell interpreter (cmd, powershell, sh, bash) as a child process during package installation, consistent with a malicious postinstall script executing a hidden payload as observed in the Sapphire Sleet supply chain compromise of the Mastra npm package.

### Intelligence Context

- Microsoft Security Blog: From package to postinstall payload: Inside the Mastra npm supply chain compromise by Sapphire Sleet — [https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/)
  - Context: Sapphire Sleet poisoned an npm package to deliver a hidden payload via a postinstall script, infecting 140+ downstream projects. The postinstall hook causes npm or node.exe to spawn shell interpreters during package installation, which is the primary detectable signal of this supply chain attack.

### Search Metadata

- CVEs: Not specified
- Threat actors: Sapphire Sleet
- ATT&CK tags: T1195.001, T1059, T1195
- Products: npm, Node.js
- Platforms: software development environments
- Malware: Not specified
- Tools: Not specified
- Search tags: Sapphire Sleet, npm, Node.js, T1195.001, T1059, software development environments, T1195

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1195 Supply Chain Compromise/ T1195.001 Compromise Software Dependencies and Development Tools (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SuspectShellSpawns = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("npm.exe", "node.exe", "npm", "node")
| where InitiatingProcessCommandLine has_any ("install", "ci", "postinstall")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "wscript.exe", "cscript.exe")
| project
    SpawnTime = TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    FileName,
    ProcessCommandLine,
    FolderPath,
    ProcessId;
let ChildNetworkActivity = DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash")
| where ActionType == "ConnectionSuccess"
| where RemoteIP !startswith "10."
    and RemoteIP !startswith "192.168."
    and RemoteIP !startswith "172."
    and RemoteIP != "127.0.0.1"
| project
    NetTime = TimeGenerated,
    DeviceName,
    NetProcessFileName = InitiatingProcessFileName,
    NetProcessId = InitiatingProcessId,
    RemoteIP,
    RemotePort,
    RemoteUrl;
SuspectShellSpawns
| join kind=leftouter (
    ChildNetworkActivity
  ) on DeviceName, $left.FileName == $right.NetProcessFileName
| where isempty(NetTime) or NetTime between (SpawnTime .. (SpawnTime + 10m))
| project
    SpawnTime,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    FileName,
    ProcessCommandLine,
    FolderPath,
    ProcessId,
    NetTime,
    RemoteIP,
    RemotePort,
    RemoteUrl
| extend HasOutboundNetwork = isnotempty(NetTime)
| extend AlertDetail = strcat(
    InitiatingProcessFileName,
    " spawned ",
    FileName,
    " during npm install",
    iff(HasOutboundNetwork, strcat("; child connected to ", RemoteIP, ":", tostring(RemotePort)), "")
  )
| sort by HasOutboundNetwork desc, SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate npm packages with postinstall scripts that compile native modules (e.g., node-gyp) spawn cmd.exe or sh during installation.
- Build tools such as webpack, rollup, and esbuild may invoke shell interpreters as part of their build pipeline.
- CI/CD pipeline steps that run npm install as part of automated builds will generate high volume on build agent hosts.
- Developer workstations running npm install for any package with a postinstall hook will trigger the base shell spawn signal.

Tuning notes:
- Restrict DeviceName to a device group tag for developer workstations and CI/CD agents to reduce query scope and cost.
- Add FolderPath exclusions for node_modules/.bin and known build tool paths to reduce noise from legitimate postinstall scripts.
- Prioritize results where HasOutboundNetwork is true for initial triage, as external network connections from spawned shells are the highest-fidelity signal.

Risks / caveats:
- Defender for Endpoint must be deployed on developer workstations and CI/CD build agents for this query to return results; these endpoint types are frequently excluded from EDR coverage.
- On Linux-based CI/CD agents, process names 'npm', 'node', 'sh', and 'bash' without the .exe extension must be present in DeviceProcessEvents; confirm the Linux MDE agent version supports process telemetry for these process names.
- The private IP exclusion for network activity uses prefix matching which may not cover all RFC1918 ranges correctly for 172.16.0.0/12; analysts should validate the exclusion covers the full 172.16-172.31 range if needed.
- The leftouter join on filename without process ID may still match network activity from a different instance of cmd.exe or powershell.exe running concurrently on the same device.

### Triage Runbook

First 15 minutes:
- Identify the host type: developer workstation, build agent, or non-development endpoint.
- Review the npm/node command line and the child shell command line to determine which package or script triggered the execution.
- Check whether the shell process made outbound connections or downloaded additional content during the install window.
- Validate whether the package being installed is approved and whether the command line matches a known-good build or dependency workflow.
- If the host is not a developer or CI/CD system, or the command line is unfamiliar, treat the event as suspicious supply-chain activity.

Evidence to collect:
- DeviceProcessEvents for the npm/node parent and the spawned shell process, including full command lines and folder paths.
- DeviceNetworkEvents for any outbound connections from the child shell process, especially to non-corporate IPs or URLs.
- Package manager logs, lockfiles, and build logs showing the package name and install step that triggered the alert.
- File creation telemetry for scripts, binaries, or modified package contents under the workspace.
- DeviceName context to determine whether the endpoint belongs to a developer, build, or production group.

Pivot points:
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName to map the full process tree.
- DeviceNetworkEvents for the child shell process to identify external destinations and download behavior.
- DeviceFileEvents for recent changes under node_modules, package cache, or workspace directories.
- DeviceRegistryEvents only if the install step also created persistence or modified startup locations.

Benign explanations:
- Legitimate npm postinstall hooks used by packages that compile native modules or set up dependencies.
- CI/CD pipelines that run npm install as part of automated builds.
- Developer workstations installing approved packages that invoke cmd.exe, powershell.exe, sh, or bash during setup.

Escalation criteria:
- Escalate if the package is unapproved, recently published, or inconsistent with the project’s dependency list.
- Escalate if the spawned shell contacts external infrastructure or downloads a second-stage payload.
- Escalate if the host is not a developer or build system.
- Escalate if multiple endpoints show the same package or script behavior in a short time window.

Containment actions:
- Pause the build or isolate the developer host if malicious package execution is confirmed.
- Remove the suspicious package from the workspace and invalidate affected build artifacts.
- Block the package version or registry source if your environment supports software supply-chain controls.
- Reset credentials if the install step led to token theft, secret exposure, or lateral movement.

Closure criteria:
- The package and postinstall behavior are confirmed as expected for the project or build pipeline.
- No external network activity, payload drop, or persistence is observed.
- The host is a known developer or CI/CD system and the command line matches approved workflows.
- Any malicious package or artifact has been removed and affected builds have been remediated.

---

## Detection 5: AI Agent Process Spawning System Shell via AutoGen Studio MCP WebSocket

### Detection Opportunity

AutoGen Studio or a Python-based AI agent process spawns cmd.exe, powershell.exe, or other system utilities as unexpected child processes, consistent with arbitrary process execution triggered through the unauthenticated MCP WebSocket endpoint by a malicious webpage.

### Intelligence Context

- Microsoft Security Blog: AutoJack: How a single page can RCE the host running your AI agent — [https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/](https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/)
  - Context: A malicious webpage exploits the unauthenticated AutoGen Studio MCP WebSocket endpoint to trigger arbitrary process execution on the host. The attack abuses localhost trust and missing authentication to coerce the AI agent runtime into spawning system-level processes, resulting in RCE on the host machine.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: AutoGen Studio, MCP WebSocket
- Platforms: Windows, AI agent
- Malware: Not specified
- Tools: Not specified
- Search tags: AutoGen Studio, MCP WebSocket, Windows, AI agent, T1190, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let AgentShellSpawns = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "python", "python3")
| where InitiatingProcessCommandLine has_any ("autogen", "autogenstudio", "mcp", "agent")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project
    SpawnTime = TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    FileName,
    ProcessCommandLine,
    ProcessId;
let LocalhostConnections = DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemoteIP in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1")
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "python", "python3")
| where ActionType == "ConnectionSuccess"
| project
    ConnTime = TimeGenerated,
    DeviceName,
    ConnProcessFileName = InitiatingProcessFileName,
    RemotePort,
    LocalPort;
AgentShellSpawns
| join kind=leftouter (
    LocalhostConnections
  ) on DeviceName, $left.InitiatingProcessFileName == $right.ConnProcessFileName
| where isempty(ConnTime) or ConnTime between ((SpawnTime - 5m) .. SpawnTime)
| project
    SpawnTime,
    ConnTime,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    FileName,
    ProcessCommandLine,
    ProcessId,
    RemotePort,
    HasLocalhostConn = isnotempty(ConnTime)
| extend AlertDetail = strcat(
    "AI agent process ",
    InitiatingProcessFileName,
    " spawned ",
    FileName,
    iff(isnotempty(ConnTime), strcat(" after localhost WebSocket on port ", tostring(RemotePort)), " (no localhost conn captured)"),
    ": ",
    ProcessCommandLine
  )
| sort by HasLocalhostConn desc, SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Python-based automation scripts with 'agent' or 'mcp' in their command line that legitimately spawn cmd.exe or powershell.exe for subprocess tasks.
- Data science notebooks or ML training scripts that invoke shell commands via subprocess.
- Python package installation or environment setup scripts that spawn shells during dependency resolution.
- Other MCP server implementations unrelated to AutoGen Studio that use the same keyword patterns.

Tuning notes:
- Review actual AutoGen Studio process command lines in the environment and replace the broad keyword list with the specific module or script name used to invoke AutoGen Studio.
- Consider adding InitiatingProcessFolderPath contains a specific virtual environment or installation path for AutoGen Studio to narrow the Python process match.
- Prioritize results where HasLocalhostConn is true for initial triage as these represent the highest-confidence WebSocket-triggered execution signal.

Risks / caveats:
- DeviceNetworkEvents may not capture loopback (127.0.0.1 / ::1) connections on all MDE sensor versions and OS configurations; validate that localhost connections appear in DeviceNetworkEvents for the target endpoints before relying on the network correlation side of this query.
- Defender for Endpoint must be deployed on the workstations running AutoGen Studio for this query to return results.
- Keyword matching on 'agent' and 'mcp' in InitiatingProcessCommandLine is broad and will match Python processes unrelated to AutoGen Studio; the keyword list should be refined to match the specific AutoGen Studio invocation pattern observed in the environment.
- Loopback connection telemetry availability in DeviceNetworkEvents is uncertain; the leftouter join ensures shell spawns are still surfaced, but the WebSocket correlation signal may be absent for many results.

### Triage Runbook

First 15 minutes:
- Confirm the host is running AutoGen Studio or another AI agent runtime and that the alerting process matches the expected installation path.
- Review the child process command line to see what cmd.exe, powershell.exe, or other utility was launched and whether it is consistent with normal agent behavior.
- Check whether the host had a localhost WebSocket connection around the same time and whether the port matches the agent’s MCP service.
- Determine whether the activity originated during normal user interaction or while a browser was open to an untrusted page.
- If the shell command is unexpected or the host is exposed to untrusted browsing, treat as likely exploitation.

Evidence to collect:
- DeviceProcessEvents for the agent process and its child shell processes, including full command lines and parent/child relationships.
- DeviceNetworkEvents for localhost connections to the agent process, including RemoteIP, RemotePort, and LocalPort.
- Installation path and version of AutoGen Studio or the AI agent runtime on the host.
- Browser history or user activity context if available, to determine whether a webpage may have triggered the action.
- Any files created, scripts executed, or follow-on network connections from the spawned shell.

Pivot points:
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName to map all child processes spawned by the agent.
- DeviceNetworkEvents for localhost and loopback traffic from the agent process around the alert time.
- DeviceFileEvents for dropped scripts, downloaded payloads, or modified configuration files.
- DeviceLogonEvents if you need to determine whether the activity occurred during an interactive user session.

Benign explanations:
- A legitimate AutoGen Studio workflow that intentionally launches shell utilities for local automation.
- A developer testing an AI agent or MCP integration in a lab environment.
- Other Python automation or MCP server implementations that use similar keywords and spawn shells for normal subprocess tasks.

Escalation criteria:
- Escalate if the shell command is not expected for the agent workflow or includes download, execution, or credential access behavior.
- Escalate if the host is a production workstation or server rather than a lab or development system.
- Escalate if the localhost connection aligns with a suspicious browser session or untrusted webpage.
- Escalate if the agent process spawns additional tools such as mshta, wscript, or cscript after the initial shell.

Containment actions:
- Terminate the agent runtime and isolate the host if unauthorized shell execution is confirmed.
- Disable or restrict the exposed MCP/WebSocket service until authentication and access controls are validated.
- Block the suspicious browser session or network path if a webpage-triggered exploit is suspected.
- Preserve process and network evidence before restarting or reimaging the host.

Closure criteria:
- The shell execution is confirmed as an expected and documented AutoGen Studio workflow.
- The localhost connection and command line match a known-good agent configuration.
- No suspicious follow-on processes, downloads, or persistence are observed.
- Any exposed service weakness has been remediated or the host has been removed from exposure.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- NTLM Relay to LDAP with Shadow Credential Write on Domain Controller: Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents, SecurityEvent before scheduling.

Schema / correlation keys:
- npm Postinstall Script Spawning Shell Interpreter During Package Installation: Do not schedule yet; validate as an analyst-led hunt first.
- AI Agent Process Spawning System Shell via AutoGen Studio MCP WebSocket: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceNetworkEvents: shared by NTLM Relay to LDAP with Shadow Credential Write on Domain Controller; Tor C2 Communication from Non-Browser Process with Startup Persistence; npm Postinstall Script Spawning Shell Interpreter During Package Installation; AI Agent Process Spawning System Shell via AutoGen Studio MCP WebSocket
- DeviceProcessEvents: shared by PsExec SYSTEM Execution Following Machine Account NTLM Logon; npm Postinstall Script Spawning Shell Interpreter During Package Installation; AI Agent Process Spawning System Shell via AutoGen Studio MCP WebSocket

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: PsExec SYSTEM Execution Following Machine Account NTLM Logon; Tor C2 Communication from Non-Browser Process with Startup Persistence.
2. Resolve environment-mapping detections next: NTLM Relay to LDAP with Shadow Credential Write on Domain Controller.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: npm Postinstall Script Spawning Shell Interpreter During Package Installation; AI Agent Process Spawning System Shell via AutoGen Studio MCP WebSocket.

### Hunting Agenda and Promotion Criteria

- npm Postinstall Script Spawning Shell Interpreter During Package Installation: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- AI Agent Process Spawning System Shell via AutoGen Studio MCP WebSocket: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- NTLM Relay to LDAP with Shadow Credential Write on Domain Controller: Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents, SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
