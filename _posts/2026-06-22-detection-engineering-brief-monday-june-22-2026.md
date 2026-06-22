---
layout: post
title: "Detection Engineering Brief - Monday, June 22, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-22
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Metasploit
  - PsExec
  - Windows
  - Active Directory
  - T1187
  - T1557.001
  - T1098
  - T1558.003
  - T1068
  - T1021.002
  - LDAP
  - WebDAV
  - Sapphire Sleet
  - T1195.001
  - T1059
  - npm
  - Node.js
  - Microsoft Defender
  - developer workstations
  - CI/CD
  - T1190
  - AutoGen Studio
  - MCP WebSocket
  - AI agents
  - local web services
  - T1059.005
  - T1204.002
  - T1105
  - WhatsApp
  - UEMS
  - T1557
  - T1098.005
  - T1195
  - T1204
---

## Executive Signal

This brief produced 5 detection candidates.

3 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Metasploit, PsExec, Windows, Active Directory, T1187, T1557.001, T1098, T1558.003, T1068, T1021.002, LDAP, WebDAV, Sapphire Sleet, T1195.001, T1059, npm, Node.js, Microsoft Defender, developer workstations, CI/CD, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Shadow Credentials Write Followed by Administrator Kerberos Ticket Request; AI Agent Process Spawning Shell Following Browser-Initiated Localhost WebSocket Activity.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Shadow Credentials Write Followed by Administrator Kerberos Ticket Request

### Detection Opportunity

msDS-KeyCredentialLink attribute written to an AD object followed by a Kerberos service ticket requested for the Administrator account, indicating Shadow Credentials abuse via NTLM relay.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: Metasploit module relays NTLM authentication from a coerced machine account to DC LDAP, writes Shadow Credentials via msDS-KeyCredentialLink, then obtains a Kerberos service ticket as Administrator using S4U2Proxy to enable PsExec SYSTEM access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1187, T1557.001, T1098, T1558.003, T1068, T1021.002, T1557, T1098.005
- Products: Metasploit, LDAP, WebDAV, PsExec
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Metasploit, PsExec
- Search tags: Metasploit, PsExec, Windows, Active Directory, T1187, T1557.001, T1098, T1558.003, T1068, T1021.002, LDAP, WebDAV, T1557, T1098.005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1557 Adversary-in-the-Middle/ T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay (medium); Persistence: T1098 Account Manipulation/ T1098.005 Device Registration (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

Required telemetry:
- SecurityEvent

### KQL

```kql
let ShadowCredWrite = SecurityEvent
| where EventID == 4662
| where Properties has "msDS-KeyCredentialLink"
| where SubjectUserName !in~ ("ANONYMOUS LOGON", "SYSTEM", "-")
| project WriteTime = TimeGenerated, WriterAccount = SubjectUserName, TargetObject = ObjectName, SourceIP = IpAddress, DCComputer = Computer;
let KerbAdminTicket = SecurityEvent
| where EventID == 4769
| where ServiceName =~ "Administrator"
| where TicketEncryptionType !in ("0x12", "0x11")
| where SubjectUserName !in~ ("ANONYMOUS LOGON", "-")
| project TicketTime = TimeGenerated, RequesterAccount = SubjectUserName, ServiceName, TicketSourceIP = IpAddress, TicketDCComputer = Computer;
ShadowCredWrite
| join kind=inner KerbAdminTicket on $left.WriterAccount == $right.RequesterAccount
| where TicketTime between (WriteTime .. (WriteTime + 30m))
| project WriteTime, TicketTime, WriterAccount, RequesterAccount, TargetObject, ServiceName, SourceIP, TicketSourceIP, DCComputer, TicketDCComputer
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Privileged Access Workstation or PAM solutions that legitimately write msDS-KeyCredentialLink for Windows Hello for Business key provisioning.
- Azure AD Connect or hybrid identity tools that manage key credentials on AD objects.
- Administrator Kerberos tickets requested by legitimate admin tooling within 30 minutes of any msDS-KeyCredentialLink write, even unrelated ones, if the join falls back to SubjectUserName.

Tuning notes:
- Add WriterAccount exclusions for known PAM or hybrid identity service accounts that legitimately manage msDS-KeyCredentialLink.
- Narrow the correlation window from 30 minutes to 5-10 minutes if the attack chain in your environment is expected to complete faster.
- Add a Computer filter to restrict both subqueries to known domain controller hostnames to eliminate noise from non-DC SecurityEvent sources.
- Validate TicketEncryptionType values in your environment; add '0x17' (RC4-HMAC) to the exclusion list if AES128 (0x11) is also used legitimately.

Risks / caveats:
- EventID 4662 with msDS-KeyCredentialLink in Properties requires per-attribute SACL auditing on AD objects, which is not enabled by default. If this audit policy is absent, the ShadowCredWrite subquery returns zero rows and the correlation never fires.
- IpAddress in SecurityEvent for EventID 4662 is frequently null or '-' for LDAP-originated events on domain controllers, which would cause the inner join on SourceIP to produce no results. The fallback join on SubjectUserName is used in the improved query to mitigate this.
- EventID 4769 TicketEncryptionType is a hex string in SecurityEvent; the filter value must match the exact string format logged by Windows (e.g., '0x12' vs '18'). Verify the format in your environment.
- If IpAddress is consistently null in 4662 events in the target environment, the SourceIP field will not be useful for triage; the join on WriterAccount/RequesterAccount is the primary correlation key.

### Triage Runbook

First 15 minutes:
- Confirm the two correlated events are on the same domain controller and within the expected 30-minute window.
- Identify the WriterAccount and RequesterAccount; if they are a machine account or unexpected service account, treat as suspicious.
- Review the TargetObject to determine whether it is a privileged user, admin group member, or a computer account used for lateral movement.
- Check whether the Administrator ticket request used weak encryption or an unusual source host/IP, and whether the source aligns with the write event.
- Look for immediate follow-on activity from the same account or host, especially PsExec, remote service creation, or additional Kerberos ticket requests.

Evidence to collect:
- SecurityEvent 4662 details for the msDS-KeyCredentialLink write, including SubjectUserName, ObjectName, Properties, IpAddress, and Computer.
- SecurityEvent 4769 details for the Administrator ticket request, including SubjectUserName, ServiceName, TicketEncryptionType, IpAddress, and Computer.
- Any additional 4662, 4769, 4624, 4672, 4688, or 7045 events involving the same WriterAccount, RequesterAccount, or TargetObject.
- Domain controller hostname and whether the source IP is empty, loopback, or a non-DC host.
- Account context for the target object to determine whether the object is privileged or a high-value asset.

Pivot points:
- SecurityEvent for 4662, 4769, 4624, 4672, 4688, and 7045 around the same time window.
- Active Directory object history or admin audit logs for the TargetObject and any recent key credential changes.
- Endpoint or server telemetry for the source host associated with the WriterAccount if available.
- Authentication logs for the RequesterAccount to identify other unusual Kerberos or NTLM activity.

Benign explanations:
- Legitimate Windows Hello for Business or PAM tooling may write msDS-KeyCredentialLink for approved provisioning.
- Azure AD Connect or hybrid identity tooling may manage key credentials on some objects.
- A legitimate admin action may request an Administrator ticket near a benign key credential write, especially if the join falls back on SubjectUserName.

Escalation criteria:
- The TargetObject is a privileged account, domain admin, or a computer account used for privileged access.
- The WriterAccount is unexpected, a machine account, or a non-admin user account.
- The Administrator ticket request is followed by remote execution, service creation, or other signs of lateral movement.
- The source host or IP is not a known identity management system or approved admin workstation.

Containment actions:
- Disable or reset the suspected WriterAccount if it is not an approved identity management account.
- Remove unauthorized key credential entries from the affected AD object after confirming with directory services owners.
- Isolate the source host if it is a workstation or server used in the relay chain.
- Force password reset or credential rotation for the affected privileged account if compromise is confirmed.

Closure criteria:
- The write is confirmed as approved identity management activity and the ticket request is attributable to a known administrative workflow.
- No unauthorized key credential changes are present on the target object.
- No follow-on lateral movement, service creation, or additional suspicious Kerberos activity is observed.
- The source host and accounts are validated as belonging to a documented, approved process.

---

## Detection 2: Machine Account NTLM Authentication to Domain Controller LDAP Port from Non-DC Host

### Detection Opportunity

A machine account authenticates to a domain controller over LDAP port 389 using NTLM from a non-domain-controller host, consistent with NTLM relay attack coerced via WebDAV OpenEncryptedFileRaw.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: NTLM Relay Priv Esc, MCP Server Integration, Paperclip AI RCE Chain, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-19-06-2026)
  - Context: The Metasploit module coerces the local machine account to authenticate via OpenEncryptedFileRaw over WebDAV, then relays that NTLM credential to the domain controller LDAP service on port 389 to write Shadow Credentials.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1187, T1557.001, T1098, T1558.003, T1068, T1021.002, T1557, T1098.005
- Products: Metasploit, LDAP, WebDAV, PsExec
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Metasploit, PsExec
- Search tags: Metasploit, PsExec, Windows, Active Directory, T1187, T1557.001, T1098, T1558.003, T1068, T1021.002, LDAP, WebDAV, T1557, T1098.005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1557 Adversary-in-the-Middle/ T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay (medium); Persistence: T1098 Account Manipulation/ T1098.005 Device Registration (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemotePort == 389
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| where InitiatingProcessAccountName endswith "$"
| where InitiatingProcessFileName !in~ (
    "lsass.exe",
    "svchost.exe",
    "mmc.exe",
    "ldp.exe",
    "wmiprvse.exe",
    "adexplorer.exe",
    "adexplorer64.exe",
    "dsquery.exe",
    "dsget.exe"
)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Management or monitoring agents running as machine accounts that perform LDAP queries to domain controllers, such as SCCM client, antivirus management agents, or backup agents.
- Custom enterprise applications running as machine accounts that query LDAP for directory lookups.
- Domain-joined workstations running Group Policy processing via lsass.exe or svchost.exe are excluded, but edge cases with other host processes may appear.

Tuning notes:
- Add a RemoteIP filter scoped to domain controller IP addresses or subnets to significantly reduce false positive volume.
- Build an allowlist of known management agent process names in your environment and add them to the InitiatingProcessFileName exclusion list.
- Consider correlating with DeviceLogonEvents for NTLM logon type to confirm the authentication protocol if higher fidelity is needed.

Risks / caveats:
- DeviceNetworkEvents ActionType value 'ConnectionSuccess' must be confirmed as available in the tenant's Defender for Endpoint schema; some environments may only have 'NetworkConnectionEvents' action types depending on sensor version.
- Without scoping RemoteIP to known domain controller IP ranges, this query will fire on any LDAP port 389 connection to any host, including non-DC LDAP servers such as third-party directory services.
- Environments with many management agents running as machine accounts will generate significant volume; baselining is required before scheduling at high frequency.
- The query does not distinguish NTLM from Kerberos authentication at the network layer; DeviceNetworkEvents does not expose authentication protocol, so some legitimate Kerberos-authenticated LDAP connections from machine accounts will be included.

### Triage Runbook

First 15 minutes:
- Identify the initiating device, machine account, and remote IP; confirm the remote IP is a domain controller or directory service host.
- Review the initiating process name and command line to see whether the connection came from a known management agent or an unusual process.
- Check whether the same machine account has repeated LDAP 389 connections to the same or multiple domain controllers.
- Look for nearby WebDAV, SMB, or coercion-related activity on the source host, especially from user-facing processes or scripts.
- Determine whether the source host is a workstation, server, or management system and whether the behavior matches its normal role.

Evidence to collect:
- DeviceNetworkEvents for the LDAP connection, including DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, and RemoteIP.
- Any DeviceLogonEvents or DeviceProcessEvents on the source host around the same time for coercion, script execution, or relay tooling.
- Domain controller logs showing whether the LDAP connection was followed by directory writes or authentication anomalies.
- A list of known management agents or directory tools that legitimately use machine accounts in your environment.
- Network context for the RemoteIP to confirm whether it is a DC subnet or a third-party LDAP service.

Pivot points:
- DeviceNetworkEvents for repeated LDAP 389 connections from the same machine account or host.
- DeviceProcessEvents on the source host for WebDAV, script interpreters, or relay-related tooling.
- SecurityEvent on domain controllers for 4662, 4768, 4769, 4624, and 7045 around the same time.
- DeviceLogonEvents to determine whether the machine account activity aligns with normal authentication patterns.

Benign explanations:
- SCCM, antivirus, backup, or other management agents may use machine accounts to query LDAP.
- Custom enterprise applications may perform directory lookups from machine accounts.
- Some domain-joined systems generate LDAP traffic during normal policy or inventory operations.

Escalation criteria:
- The source host is a user workstation or non-management server and the LDAP activity is not expected.
- The machine account activity is paired with WebDAV, script execution, or other coercion indicators.
- The same host or account shows directory writes, ticket requests, or remote execution shortly after the LDAP connection.
- The remote IP is a domain controller and the process/account combination is not on an approved allowlist.

Containment actions:
- Isolate the source host if coercion or relay is suspected and the host is not a critical production system.
- Block or disable the suspicious machine account only if it is confirmed to be abused and not required for immediate operations.
- Coordinate with AD owners to inspect for unauthorized directory changes on the targeted domain controller.
- Preserve the source host for forensic review before remediation if compromise is likely.

Closure criteria:
- The activity is attributed to a known, approved management or directory service process.
- The remote IP is confirmed to be a legitimate directory service endpoint and no suspicious follow-on activity exists.
- No related directory writes, ticket anomalies, or remote execution are found.
- The process and account are added to an environment-specific allowlist if validated.

---

## Detection 3: npm Postinstall Script Spawning Shell or Network Utility from Node.exe

### Detection Opportunity

node.exe or npm spawns a shell interpreter or network utility during package installation, consistent with a poisoned npm package executing a malicious postinstall script as observed in the Sapphire Sleet Mastra supply chain compromise.

### Intelligence Context

- Microsoft Security Blog: From package to postinstall payload: Inside the Mastra npm supply chain compromise by Sapphire Sleet — [https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/)
  - Context: Sapphire Sleet poisoned the Mastra npm package to execute a hidden payload during the postinstall lifecycle hook, infecting 140+ projects. The payload ran at install time via node.exe executing the postinstall script.

### Search Metadata

- CVEs: Not specified
- Threat actors: Sapphire Sleet
- ATT&CK tags: T1195.001, T1059, T1195
- Products: npm, Node.js, Microsoft Defender
- Platforms: developer workstations, CI/CD
- Malware: Not specified
- Tools: Not specified
- Search tags: Sapphire Sleet, T1195.001, T1059, npm, Node.js, Microsoft Defender, developer workstations, CI/CD, T1195

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1195 Supply Chain Compromise/ T1195.001 Compromise Software Dependencies and Development Tools (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "npm")
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "sh",
    "bash",
    "curl.exe",
    "wget.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
)
| where InitiatingProcessCommandLine has "install"
    or InitiatingProcessCommandLine has "postinstall"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FileName, ProcessCommandLine, FolderPath, SHA256
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate postinstall scripts in enterprise npm packages that invoke shell commands for build steps, such as node-gyp compilation invoking cmd.exe or sh.
- CI/CD pipelines with custom npm lifecycle hooks that intentionally run shell commands during install.
- Developer workstations running npm install for packages with legitimate postinstall shell invocations such as Husky git hooks.

Tuning notes:
- Add FolderPath exclusions for known legitimate build tool directories such as node_modules/.bin paths associated with trusted internal packages.
- Add ProcessCommandLine exclusions for known-good postinstall patterns such as node-gyp rebuild or husky install after baselining.
- Consider restricting AccountName to service accounts used by CI/CD agents if developer workstation noise is high.

Risks / caveats:
- On Linux CI/CD agents onboarded to Defender for Endpoint, process names such as 'sh', 'bash', and 'node' without the .exe extension must be present in DeviceProcessEvents. Confirm that Linux MDE sensor telemetry is available if CI/CD agents run on Linux.
- Legitimate npm packages with postinstall shell invocations will generate false positives in developer-heavy environments; a baselining period is required to build an allowlist of known-good package postinstall patterns.
- The query does not validate that the spawned process performs malicious network activity; a follow-on correlation with DeviceNetworkEvents would increase fidelity.
- On Linux endpoints, FileName values for sh and bash do not include .exe; the in~ operator handles case but not extension differences, so Linux telemetry may require a separate query variant.

### Triage Runbook

First 15 minutes:
- Identify the parent package, repository, and user or CI account that ran npm install.
- Review the child process command line to see whether it is a normal build action or a downloader, shell, or script launcher.
- Check whether the process occurred on a developer workstation or CI/CD agent and whether that host normally performs package installs.
- Inspect the InitiatingProcessCommandLine for the package name, install target, and any suspicious lifecycle hook indicators.
- Look for immediate network activity, file writes, or additional child processes from the same node.exe or npm process.

Evidence to collect:
- DeviceProcessEvents for the parent node.exe or npm process and its child process tree.
- SHA256 of the child process and any dropped files for reputation or internal hash lookup.
- ProcessCommandLine and InitiatingProcessCommandLine to identify the package and install context.
- DeviceNetworkEvents from the same host and time window for outbound connections to package registries or suspicious destinations.
- FolderPath and AccountName to determine whether the activity occurred in a developer profile, build agent, or shared system.

Pivot points:
- DeviceProcessEvents for the full process tree around the npm install event.
- DeviceNetworkEvents for outbound connections from the same host during the install window.
- DeviceFileEvents for dropped or modified files in node_modules, temp, or user profile directories.
- Defender file reputation or internal threat intel lookups using SHA256.

Benign explanations:
- Legitimate npm packages often use postinstall scripts for compilation, dependency setup, or hook installation.
- CI/CD pipelines may intentionally run shell commands during install as part of build automation.
- Developer workstations may show shell or network utility execution during package installation for trusted internal packages.

Escalation criteria:
- The package is untrusted, newly introduced, or not expected in the repository.
- The child process downloads payloads, reaches out to unusual domains, or writes executables outside normal build paths.
- The same package or hash appears across multiple developer or CI hosts.
- The install occurred outside normal build windows or from an account that should not be performing package installs.

Containment actions:
- Pause the affected build job or isolate the developer workstation if malicious package execution is likely.
- Quarantine or block the suspicious child binary or dropped artifact if confirmed malicious.
- Remove the compromised package version from internal registries or lockfiles if the source is controlled internally.
- Rotate any credentials exposed on the affected host if the payload had network or credential access.

Closure criteria:
- The package and postinstall behavior are confirmed as legitimate and match known build patterns.
- The child process hash and command line are approved or already allowlisted.
- No suspicious network activity, file drops, or persistence is observed.
- The event is documented as an expected build or developer workflow.

---

## Detection 4: AI Agent Process Spawning Shell Following Browser-Initiated Localhost WebSocket Activity

### Detection Opportunity

A Python-based AI agent process such as AutoGen Studio spawns a shell interpreter after a browser process connects to a localhost WebSocket port, consistent with AutoJack RCE via malicious webpage abusing MCP WebSocket unsafe parameter handling.

### Intelligence Context

- Microsoft Security Blog: AutoJack: How a single page can RCE the host running your AI agent — [https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/](https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/)
  - Context: A malicious webpage abuses AutoGen Studio's MCP WebSocket by exploiting localhost trust and missing authentication. Unsafe parameter handling allows the webpage to trigger arbitrary process execution on the host running the AI agent, producing shell spawning from the AI framework parent process.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: AutoGen Studio, MCP WebSocket
- Platforms: Windows, AI agents, local web services
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, T1059, AutoGen Studio, MCP WebSocket, Windows, AI agents, local web services

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Exploit Public-Facing Application: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let BrowserLocalhost = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe")
| where RemoteIP in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1")
| where RemotePort >= 8000
| project BrowserTime = TimeGenerated, DeviceName, BrowserProcess = InitiatingProcessFileName, LocalWSPort = RemotePort;
let AIAgentShell = DeviceProcessEvents
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "autogenstudio.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project ShellTime = TimeGenerated, DeviceName, AIParent = InitiatingProcessFileName, AIParentCommandLine = InitiatingProcessCommandLine, ShellChild = FileName, ProcessCommandLine, SHA256;
BrowserLocalhost
| join kind=inner AIAgentShell on DeviceName
| where ShellTime between (BrowserTime .. (BrowserTime + 5m))
| project BrowserTime, ShellTime, DeviceName, BrowserProcess, LocalWSPort, AIParent, AIParentCommandLine, ShellChild, ProcessCommandLine, SHA256
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer environments where Python processes legitimately spawn shells for build, test, or scripting tasks within 5 minutes of any browser localhost activity.
- Jupyter notebooks or other Python-based local web services that serve browser UIs and also invoke shell commands as part of normal operation.
- VS Code or other IDEs that use Python language servers and browser-based UIs simultaneously with shell invocations.

Tuning notes:
- Narrow RemotePort to the specific AutoGen Studio MCP WebSocket port if it is known and consistent in the environment.
- Add AIParentCommandLine exclusions for known legitimate Python automation patterns that spawn shells in your environment.
- Extend the correlation window to 10 minutes if AI agent processing latency causes genuine attack events to fall outside the 5-minute window.
- Consider adding a DeviceNetworkEvents follow-on check for outbound connections from the spawned shell process to increase confidence before scheduling as an alert.

Risks / caveats:
- DeviceNetworkEvents may not capture all localhost loopback connections depending on Defender for Endpoint sensor configuration; loopback traffic is filtered by some OS network stacks before the sensor can observe it. Validate that browser-to-localhost connections appear in DeviceNetworkEvents in the target environment before relying on this signal.
- Loopback network connections may not be reliably captured in DeviceNetworkEvents; if the browser localhost signal is absent, the correlation will not fire even during a genuine attack.
- The 5-minute correlation window may miss attacks where the AI agent processes the WebSocket payload with significant latency before spawning a shell.
- The query does not confirm that the Python process is specifically AutoGen Studio; any Python process spawning a shell within 5 minutes of browser localhost activity will match.

### Triage Runbook

First 15 minutes:
- Confirm the browser process, localhost port, and AI agent process occurred on the same device within the 5-minute window.
- Review the shell child process command line to determine whether it is a normal automation step or an unexpected command execution.
- Identify the user session and whether the browser activity was tied to a known AI agent UI or local development tool.
- Check whether the AI parent command line references AutoGen Studio, MCP, or another local web service.
- Look for any outbound network activity or file writes from the spawned shell process.

Evidence to collect:
- DeviceNetworkEvents showing the browser connection to localhost, including browser process name and remote port.
- DeviceProcessEvents for the AI parent and shell child, including command lines and SHA256.
- User session context and device ownership to determine whether the host is a developer workstation or shared system.
- Any local service logs for the AI agent or MCP WebSocket service if available.
- Follow-on process and network activity from the shell child to identify payload execution or staging.

Pivot points:
- DeviceProcessEvents for the AI parent process tree and any child shells or script interpreters.
- DeviceNetworkEvents for localhost and immediate post-execution outbound connections.
- DeviceFileEvents for files created or modified by the shell process.
- Application or service logs for the AI agent or local web service if accessible.

Benign explanations:
- Developer environments often use Python-based tools that legitimately spawn shells after browser interaction.
- Local AI agent UIs may invoke shell commands as part of normal automation or tool execution.
- Jupyter, IDE integrations, or local web dashboards can produce similar browser and shell patterns.

Escalation criteria:
- The shell command is unexpected, downloads content, or launches additional suspicious tooling.
- The browser connection is to an unfamiliar localhost port or the AI agent is not a known approved tool.
- The host shows follow-on persistence, credential access, or outbound connections after the shell spawn.
- The activity occurs on a non-developer endpoint or a system that should not run local AI services.

Containment actions:
- Stop the local AI agent service and isolate the host if the shell execution is not expected.
- Terminate the suspicious shell process and preserve its command line and parent-child chain.
- Block the local service or browser session if the exploit is actively recurring.
- Collect the AI agent logs and browser history before remediation if compromise is suspected.

Closure criteria:
- The browser-to-localhost interaction is confirmed as a known, approved AI tool workflow.
- The shell command is expected and matches documented automation behavior.
- No suspicious outbound connections, file changes, or persistence are observed.
- The local service and user activity are validated by the system owner.

---

## Detection 5: VBScript Executed from Messaging App Download Path Spawning RMM Installer

### Detection Opportunity

wscript.exe or cscript.exe executes a VBS file from a WhatsApp download or user temp directory and subsequently spawns a child process consistent with RMM agent installation, indicating the multi-stage VBScript infection chain delivering UEMS.

### Intelligence Context

- Securelist: A VBScript campaign distributed through WhatsApp deploying RMM software — [https://securelist.com/whatsapp-vbs-rmm-campaign/120290/](https://securelist.com/whatsapp-vbs-rmm-campaign/120290/)
  - Context: Attackers distribute VBS scripts via WhatsApp. When a user executes the script, wscript.exe or cscript.exe runs the VBS from the WhatsApp download directory, initiating a multi-stage chain that downloads and installs a UEMS RMM agent for persistent remote access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059.005, T1204.002, T1105, T1059, T1204
- Products: WhatsApp, UEMS
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1059.005, T1204.002, T1105, WhatsApp, UEMS, Windows, T1059, T1204

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.005 Visual Basic (high); User Execution: T1204 User Execution/ T1204.002 Malicious File (high); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let VBSExecution = DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has ".vbs"
| where ProcessCommandLine has_any (
    "WhatsApp",
    "\\Downloads\\",
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\"
)
| project VBSTime = TimeGenerated, DeviceName, AccountName, ScriptProcess = FileName, ProcessCommandLine, InitiatingProcessSHA256;
let ChildActivity = DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where FileName !in~ ("wscript.exe", "cscript.exe", "conhost.exe")
| project ChildTime = TimeGenerated, DeviceName, ChildAccountName = AccountName, ChildProcess = FileName, ChildCommandLine = ProcessCommandLine, ChildFolderPath = FolderPath, ChildSHA256 = SHA256;
VBSExecution
| join kind=inner ChildActivity on DeviceName
| where ChildTime between (VBSTime .. (VBSTime + 10m))
| project VBSTime, ChildTime, DeviceName, AccountName, ScriptProcess, ProcessCommandLine, ChildProcess, ChildCommandLine, ChildFolderPath, ChildSHA256, InitiatingProcessSHA256
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Enterprise VBScript automation deployed via user profile directories that legitimately spawns installer processes.
- IT support scripts delivered via messaging apps that perform legitimate software installation.
- Software deployment tools that use wscript.exe to invoke installers from user temp directories.

Tuning notes:
- Once the UEMS RMM installer binary name is confirmed from threat intelligence, add a ChildProcess filter to narrow results to that specific binary.
- Add AccountName exclusions for known IT automation service accounts that legitimately run VBS installers from user directories.
- Reduce the correlation window from 10 minutes to 2-3 minutes if the infection chain completes faster in observed cases to reduce coincidental matches.
- Add ChildFolderPath filters to focus on non-standard install paths such as AppData or Temp directories where RMM agents are dropped.

Risks / caveats:
- FolderPath in DeviceProcessEvents reflects the folder of the spawned process binary, not the script file being executed. The VBS script path appears in ProcessCommandLine, not FolderPath. The improved query moves the path filter to ProcessCommandLine to correctly target the script file location.
- The join on DeviceName only may produce multiple child process matches per VBS execution event if wscript.exe spawns several processes within the 10-minute window; analysts should review all ChildProcess values per VBSTime event.
- The WhatsApp path filter relies on the string 'WhatsApp' appearing in the command line; if WhatsApp Desktop changes its download directory structure, the filter may miss new paths.
- The RMM installer binary name (UEMS) is not confirmed in the query; ChildProcess will match any non-excluded child, requiring analyst review to identify the RMM component.

### Triage Runbook

First 15 minutes:
- Identify the user account, device, and exact script path from the command line to confirm the file originated from WhatsApp, Downloads, or Temp.
- Review the child process tree to see whether the script launched an installer, downloader, or RMM-related binary.
- Check whether the same account or device shows additional script execution, file drops, or network connections shortly after the VBS launch.
- Determine whether the script was opened from a messaging app attachment or a user download and whether the user reports interacting with it.
- Look for persistence indicators such as scheduled tasks, services, Run keys, or new remote access software.

Evidence to collect:
- DeviceProcessEvents for the VBS execution and all child processes, including command lines, folder paths, and SHA256 values.
- Any DeviceNetworkEvents from the same host during and after execution to identify downloads or remote access traffic.
- File creation events for dropped installers or RMM components in user profile, Temp, or ProgramData paths.
- User context and device ownership to determine whether the execution was user-initiated or automated.
- Any persistence artifacts such as services, scheduled tasks, or startup entries created by the child process.

Pivot points:
- DeviceProcessEvents for the full process tree from wscript.exe or cscript.exe.
- DeviceFileEvents for dropped files and installer artifacts in user-writable directories.
- DeviceNetworkEvents for outbound connections to download or command-and-control infrastructure.
- DeviceRegistryEvents and scheduled task/service telemetry for persistence created after script execution.

Benign explanations:
- Some IT automation or software deployment scripts use VBScript from user profile directories.
- Legitimate support workflows may distribute scripts through messaging apps in small environments, though this should be rare.
- A user may have opened a benign VBS file from Downloads or Temp that launches a standard installer.

Escalation criteria:
- The child process installs or launches remote management software not approved for the device.
- The script came from a messaging app attachment or unsolicited download and the user did not expect it.
- Persistence, outbound beaconing, or additional payloads are observed after the script runs.
- The same script hash or behavior appears on multiple endpoints.

Containment actions:
- Isolate the endpoint if the RMM installer or follow-on payload is unauthorized.
- Terminate the script interpreter and any spawned installer or remote access process.
- Quarantine the script and any dropped binaries, and block the hash if confirmed malicious.
- Disable the user account temporarily if the execution appears to be part of a broader compromise.

Closure criteria:
- The script is confirmed as a sanctioned IT automation or software deployment artifact.
- The child process is a known approved installer and no persistence or suspicious network activity is present.
- The file path, hash, and user context are documented and validated by the system owner.
- No additional endpoints show the same script or installer behavior.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Shadow Credentials Write Followed by Administrator Kerberos Ticket Request: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

Schema / correlation keys:
- AI Agent Process Spawning Shell Following Browser-Initiated Localhost WebSocket Activity: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceNetworkEvents: shared by Machine Account NTLM Authentication to Domain Controller LDAP Port from Non-DC Host; AI Agent Process Spawning Shell Following Browser-Initiated Localhost WebSocket Activity
- DeviceProcessEvents: shared by npm Postinstall Script Spawning Shell or Network Utility from Node.exe; AI Agent Process Spawning Shell Following Browser-Initiated Localhost WebSocket Activity; VBScript Executed from Messaging App Download Path Spawning RMM Installer

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Machine Account NTLM Authentication to Domain Controller LDAP Port from Non-DC Host; npm Postinstall Script Spawning Shell or Network Utility from Node.exe; VBScript Executed from Messaging App Download Path Spawning RMM Installer.
2. Resolve environment-mapping detections next: Shadow Credentials Write Followed by Administrator Kerberos Ticket Request.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: AI Agent Process Spawning Shell Following Browser-Initiated Localhost WebSocket Activity.

### Hunting Agenda and Promotion Criteria

- AI Agent Process Spawning Shell Following Browser-Initiated Localhost WebSocket Activity: Do not schedule yet; validate as an analyst-led hunt first..
- Shadow Credentials Write Followed by Administrator Kerberos Ticket Request: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
