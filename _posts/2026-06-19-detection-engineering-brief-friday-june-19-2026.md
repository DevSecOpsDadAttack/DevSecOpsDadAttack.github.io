---
layout: post
title: "Detection Engineering Brief - Friday, June 19, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-19
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - SSH
  - Linux
  - Network
  - Windows
  - Endpoint
  - npm
  - Developer endpoints
  - CI/CD
  - AutoGen Studio
  - MCP WebSocket
  - AI agent hosts
  - Web
  - T1110
  - T1110.001
  - T1078
  - T1021
  - T1021.002
  - T1105
  - T1547
  - T1059
  - T1059.004
  - T1059.001
  - T1203
---

## Executive Signal

This brief produced 5 detection candidates.

3 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: SSH, Linux, Network, Windows, Endpoint, npm, Developer endpoints, CI/CD, AutoGen Studio, MCP WebSocket, AI agent hosts, Web, T1110, T1110.001, T1078, T1021, T1021.002, T1105, T1547, T1059, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Crypto Clipper Clipboard Hijacking via Repeated Clipboard API Access with Wallet Address Pattern; AutoGen Studio Spawning Unexpected Shell or System Utility Indicating AI Agent RCE.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: SSH Brute Force Followed by Successful Login from Same Source IP

### Detection Opportunity

Successful SSH login from a source IP that previously generated multiple failed authentication attempts, indicating likely credential compromise following coordinated brute force activity

### Intelligence Context

- SANS ISC: The Behavior of Coordinated SSH Brute Force Attacks over the last three months [Guest Diary], (Wed, Jun 17th) — [https://isc.sans.edu/diary/rss/33086](https://isc.sans.edu/diary/rss/33086)
  - Context: Reporting documents coordinated SSH brute force campaigns from distributed sources, with observed follow-on successful logins after brute force activity indicating credential compromise.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1110, T1110.001, T1078
- Products: SSH
- Platforms: Linux, Network
- Malware: Not specified
- Tools: Not specified
- Search tags: SSH, Linux, Network, T1110, T1110.001, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1110 Brute Force/ T1110.001 Password Guessing (high); Initial Access: T1078 Valid Accounts (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- Syslog

### KQL

```kql
let lookback = 1h;
let failThreshold = 10;
let failedSSH =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility in ("auth", "authpriv") and SyslogMessage has "Failed password"
    | extend SourceIP = extract(@"from ([\d\.]+)", 1, SyslogMessage)
    | where isnotempty(SourceIP)
    | summarize
        FailCount = count(),
        FirstFail = min(TimeGenerated),
        LastFail = max(TimeGenerated)
        by SourceIP, Computer;
let successSSH =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility in ("auth", "authpriv") and SyslogMessage has "Accepted password"
    | extend SourceIP = extract(@"from ([\d\.]+)", 1, SyslogMessage)
    | extend User = extract(@"for (\S+) from", 1, SyslogMessage)
    | extend SSHPort = extract(@"port (\d+)", 1, SyslogMessage)
    | where isnotempty(SourceIP);
successSSH
| join kind=inner failedSSH on SourceIP, Computer
| where FailCount >= failThreshold
| where TimeGenerated > LastFail
| project
    TimeGenerated,
    Computer,
    SourceIP,
    User,
    SSHPort,
    FailCount,
    FirstFail,
    LastFail,
    AlertDetail = strcat("SSH success after ", tostring(FailCount), " failures from ", SourceIP)
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate users with misconfigured SSH keys who exhaust retries before falling back to password authentication.
- Automated configuration management tools (Ansible, Chef) that attempt multiple credential sets before succeeding.
- NAT or proxy environments where multiple users share a single source IP, causing unrelated failures and successes to correlate.

Tuning notes:
- Lower failThreshold to 5 for sensitive or internal-only SSH hosts; raise to 20-50 for internet-facing jump hosts with high background noise.
- Add a Computer allowlist exclusion for honeypot hosts if they are intentionally exposed and generate high volumes of expected brute force.
- Extend lookback to 4h or 24h to catch slow distributed brute force campaigns that stay below per-hour thresholds.

Risks / caveats:
- Syslog table will be empty or missing auth facility entries if Linux hosts are not onboarded via Log Analytics Agent or AMA with the auth/authpriv facility explicitly configured in the data collection rule.
- OpenSSH variants that log to a non-standard facility (e.g., local0-local7) or use PAM-rewritten message strings will not match 'Failed password' or 'Accepted password' patterns.
- A 1-hour lookback window may miss slow brute force campaigns that spread failures over longer periods; consider extending to 4h or 24h for internet-facing hosts.
- Ingestion delay in Syslog can cause the success event to arrive before all failure events are indexed, potentially suppressing alerts for fast attacks.

### Triage Runbook

First 15 minutes:
- Confirm the alert details: target host, source IP, username, fail count, first/last failure time, and the successful login timestamp.
- Check whether the source IP is external, newly seen, or associated with VPN/NAT/shared egress; treat shared IPs carefully but do not dismiss them without validation.
- Review SSH/auth logs on the target host for the login session, command history, sudo use, new keys, and any immediate post-login activity.
- Determine whether the account is privileged, service-related, or a human user; privileged or service account success should be escalated immediately.
- Look for concurrent alerts on the same host or source IP, including other logins, privilege escalation, or lateral movement attempts.

Evidence to collect:
- Syslog entries for the failed and successful SSH events, including exact timestamps and source IP.
- User account details: privilege level, last password change, MFA/SSH key usage, and whether the account is expected to log in from that source.
- Host context: internet exposure, SSH port in use, recent admin changes, and whether the host is a jump box or bastion.
- Session evidence after login: commands run, sudo/su usage, new processes, new users, new keys in authorized_keys, and file changes.
- Any related network telemetry from the source IP to the host around the login window.

Pivot points:
- Syslog for the same Computer, SourceIP, or User over the last 24 hours.
- Authentication logs on the Linux host if available locally or via centralized logging.
- Process and command execution telemetry on the host after the successful login, if endpoint telemetry exists.
- Other hosts contacted by the same SourceIP or the same User within the same time window.
- Change-management or admin activity records to validate whether the login was expected.

Benign explanations:
- A legitimate user mistyped a password several times before successfully authenticating.
- An automation or configuration tool retried multiple credentials before succeeding.
- A shared NAT or proxy IP caused unrelated users to generate the failures and the success.
- A recently rotated password or SSH key caused temporary authentication failures before the correct credential was used.

Escalation criteria:
- The successful login is for a privileged, service, or break-glass account.
- The source IP is untrusted, foreign, or not associated with approved admin access.
- There is evidence of post-login reconnaissance, privilege escalation, persistence, or lateral movement.
- The host is internet-facing and the login was not expected or approved.
- Multiple hosts show the same source IP pattern or the account is used successfully on additional systems.

Containment actions:
- Disable or reset the affected account if the login is confirmed unauthorized or highly suspicious.
- Block the source IP at the relevant perimeter controls if it is not a legitimate admin or automation source.
- Terminate active SSH sessions and isolate the host if post-login activity suggests compromise.
- Rotate any credentials that may have been exposed, including passwords and SSH keys.
- Preserve logs and volatile evidence before making disruptive changes when feasible.

Closure criteria:
- The login is verified as authorized by the account owner or change record.
- The source IP is confirmed as a trusted admin, automation, or shared egress source and no suspicious post-login activity exists.
- No additional suspicious logins, commands, or lateral movement are observed after review.
- Any false-positive cause is documented and an allowlist or tuning action is approved.
- Evidence collected is sufficient to explain the failed-then-successful pattern without indicating compromise.

---

## Detection 2: Crypto Clipper Clipboard Hijacking via Repeated Clipboard API Access with Wallet Address Pattern

### Detection Opportunity

A process repeatedly accessing clipboard contents and writing back modified data consistent with cryptocurrency wallet address replacement, as observed in crypto clipper malware using worm-like propagation

### Intelligence Context

- Microsoft Security Blog: Crypto Clipper uses Tor and worm-like propagation for persistence and control — [https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
  - Context: Reporting describes a crypto clipper malware that steals cryptocurrency by replacing clipboard wallet addresses, uses Tor for C2, and propagates in a worm-like manner across endpoints.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021, T1021.002, T1105, T1547
- Products: Not specified
- Platforms: Windows, Endpoint, Network
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, Endpoint, Network, T1021, T1021.002, T1105, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium); Lateral Movement: T1105 Ingress Tool Transfer (medium); Persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- Clipboard telemetry collection requires Microsoft Defender for Endpoint with advanced telemetry features enabled; tenants on basic licensing tiers may not generate these events at all.

Required telemetry:
- DeviceEvents, DeviceNetworkEvents

### KQL

```kql
let torPorts = dynamic([9001, 9050, 9150]);
let clipboardActionTypes = dynamic(["SetClipboardText", "GetClipboardText", "ClipboardDataRead", "ClipboardDataWrite"]);
let excludedProcs = dynamic(["explorer.exe", "svchost.exe", "SearchHost.exe", "TextInputHost.exe"]);
let clipboardEvents =
    DeviceEvents
    | where Timestamp > ago(1h)
    | where ActionType in (clipboardActionTypes)
    | where InitiatingProcessFileName !in~ (excludedProcs)
    | summarize
        ClipCount = count(),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp)
        by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
    | where ClipCount >= 5;
let torConnections =
    DeviceNetworkEvents
    | where Timestamp > ago(1h)
    | where RemotePort in (torPorts)
    | summarize TorConnCount = count(), TorFirstSeen = min(Timestamp) by DeviceId, InitiatingProcessFileName;
clipboardEvents
| join kind=inner torConnections on DeviceId, InitiatingProcessFileName
| project
    FirstSeen,
    LastSeen,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ClipCount,
    TorConnCount,
    RiskDetail = strcat("Clipboard accesses: ", tostring(ClipCount), " | Tor port connections: ", tostring(TorConnCount))
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Password managers or clipboard utility software that legitimately access clipboard at high frequency.
- Legitimate Tor Browser usage on endpoints where Tor is permitted, combined with any clipboard-active application.
- Security research or red team tooling running on analyst workstations.

Tuning notes:
- Run 'DeviceEvents | where ActionType contains_cs "Clipboard" | summarize count() by ActionType' to confirm which clipboard ActionType values exist before deploying.
- Adjust ClipCount threshold based on observed baseline for non-excluded processes in the environment.
- Expand excluded process list to include any legitimate clipboard-intensive applications specific to the environment (e.g., RDP clipboard sync processes).

Risks / caveats:
- Clipboard-specific ActionType values ('SetClipboardText', 'GetClipboardText', 'ClipboardDataRead', 'ClipboardDataWrite') must be verified to exist in the tenant's DeviceEvents table. These are not universally documented as standard MDE ActionType values and may not be collected depending on sensor version or advanced feature configuration.
- Clipboard telemetry collection requires Microsoft Defender for Endpoint with advanced telemetry features enabled; tenants on basic licensing tiers may not generate these events at all.
- If clipboard ActionType values are not present in the tenant, the query returns no results; run the validation step before scheduling.
- Tor traffic over non-standard ports or wrapped in HTTPS tunnels will not be detected by port-based filtering.

### Triage Runbook

First 15 minutes:
- Validate the process name, command line, parent process, and device name to determine whether the activity is tied to a known application or an unknown binary.
- Check whether the process is repeatedly reading and writing clipboard data and whether the timing aligns with user copy/paste activity.
- Inspect recent network connections from the same process for Tor ports or other suspicious outbound traffic, and note any repeated connections.
- Look for persistence indicators on the host, including autoruns, scheduled tasks, startup items, or newly installed software.
- If the host is a workstation used for crypto transactions, prioritize immediate user notification and account review.

Evidence to collect:
- DeviceEvents entries showing clipboard-related activity, including timestamps, process name, command line, and parent process.
- DeviceNetworkEvents for the same process and device, especially Tor-related or unusual outbound connections.
- File and process metadata for the suspected binary, including hash, signer, install path, and first-seen time.
- Persistence artifacts such as Run keys, scheduled tasks, services, startup folders, browser extensions, or WMI subscriptions.
- User activity context: whether the user was actively copying wallet addresses, using a password manager, or running legitimate clipboard tools.

Pivot points:
- DeviceEvents filtered to the same DeviceId, InitiatingProcessFileName, or SHA256.
- DeviceNetworkEvents for the same process, device, or remote ports associated with Tor or proxying.
- DeviceFileEvents for recent drops, downloads, or modifications related to the suspected process.
- DeviceRegistryEvents and scheduled task telemetry for persistence checks.
- Email, browser, or download telemetry if available to identify the initial delivery vector.

Benign explanations:
- A legitimate clipboard manager, password manager, or remote support tool is accessing the clipboard frequently.
- Tor Browser or a privacy tool is installed and used intentionally on the endpoint.
- A developer or tester is running security research or malware analysis tooling in a lab environment.
- Accessibility software or remote desktop clipboard synchronization is generating repeated clipboard events.

Escalation criteria:
- The process is unsigned, newly installed, or has a suspicious parent-child chain and repeated clipboard modification behavior.
- Tor or other anonymized outbound traffic is present from the same process and device.
- The host is used for cryptocurrency transactions or contains wallet software and the clipboard tampering is confirmed.
- Persistence artifacts or additional malware behavior are found on the endpoint.
- Multiple endpoints show the same process or hash, suggesting spread or a broader campaign.

Containment actions:
- Isolate the endpoint from the network if malicious clipboard hijacking is confirmed or strongly suspected.
- Terminate the suspicious process and remove the associated binary after preserving evidence.
- Block the file hash, parent process, and any confirmed outbound indicators at endpoint and network controls.
- Reset credentials and review wallet-related accounts or browser sessions if the host was used for crypto activity.
- Collect a forensic image or targeted triage package before remediation if the environment allows.

Closure criteria:
- The clipboard activity is attributed to a known, approved application or user workflow.
- No malicious process, persistence, or suspicious network activity is found after review.
- The binary hash, signer, and install source are validated as benign.
- Any required allowlist or tuning is documented for the approved clipboard tool.
- The user confirms no wallet replacement or unauthorized transaction occurred.

---

## Detection 3: Malicious npm Postinstall Script Spawning Shell or Network Tool

### Detection Opportunity

npm or node process spawning a shell interpreter or network utility as a child process during package installation, consistent with postinstall script abuse observed in the Mastra npm supply chain compromise

### Intelligence Context

- Microsoft Security Blog: From package to postinstall payload: Inside the Mastra npm supply chain compromise — [https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/)
  - Context: A poisoned npm package infected 140+ projects by executing a hidden payload via the postinstall lifecycle hook, causing npm or node to spawn unexpected child processes during package installation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1059.001, T1105
- Products: npm
- Platforms: Developer endpoints, CI/CD
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, Developer endpoints, CI/CD, T1059, T1059.004, T1059.001, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let npmParents = dynamic(["npm", "npm.cmd", "node.exe", "node", "npx", "npx.cmd"]);
let suspiciousChildren = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash", "sh", "zsh", "dash",
    "curl", "wget", "certutil.exe", "bitsadmin.exe",
    "ncat", "ncat.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (npmParents)
| where FileName in~ (suspiciousChildren)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessParentFileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    SHA256,
    AlertDetail = strcat("npm/node spawned ", FileName, " via: ", InitiatingProcessCommandLine)
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate postinstall scripts that invoke bash or sh for build steps (e.g., node-gyp, native module compilation).
- CI/CD pipelines that use npm to orchestrate shell-based build steps as part of normal workflow.
- Developer tools that wrap npm and legitimately spawn curl or wget to download build dependencies.

Tuning notes:
- Scope DeviceId or DeviceName to device groups representing developer endpoints or CI/CD agents using a watchlist or dynamic group filter to reduce noise from production servers running node services.
- Add AccountName exclusions for known CI/CD service accounts if their postinstall behavior is validated as benign.
- Extend suspiciousChildren list to include python.exe, ruby, perl if those runtimes are used in postinstall hooks in the environment.
- Reduce lookback to 1h when promoting to a scheduled rule.

Risks / caveats:
- Microsoft Defender for Endpoint must be deployed on developer workstations and CI/CD build agents; endpoints without MDE sensor will not generate DeviceProcessEvents.
- Legitimate postinstall scripts invoking bash or sh for native module compilation (node-gyp) will generate false positives; analyst review of ProcessCommandLine content is required to distinguish.
- Custom node wrapper scripts with non-standard filenames will not be caught by the parent process filter.
- 7-day lookback is appropriate for hunting but should be reduced to 1h-24h if promoted to a scheduled rule to avoid duplicate alerting.

### Triage Runbook

First 15 minutes:
- Confirm the parent npm/node process, child process name, command line, account, and device to determine whether this was an expected build step or an unexpected payload execution.
- Review the package name, repository, and install source from the command line or surrounding telemetry to identify the package that triggered the event.
- Check whether the child process is a shell, PowerShell, or network utility used to download additional content or execute scripts.
- Determine whether the host is a developer workstation or CI/CD agent and whether the activity aligns with a known build pipeline.
- Look for immediate follow-on activity such as additional downloads, credential access, archive creation, or outbound connections.

Evidence to collect:
- DeviceProcessEvents for the npm/node parent and spawned child process, including full command lines and hashes.
- Package manager logs, lockfiles, and repository metadata showing the package version and install source.
- DeviceNetworkEvents for outbound connections made by the child process or related processes.
- File creation/modification events for downloaded payloads, scripts, or altered project files.
- Account and host context: user identity, CI/CD service account, and whether the install was interactive or automated.

Pivot points:
- DeviceProcessEvents for the same DeviceId, AccountName, or SHA256 over the last 24 hours.
- DeviceNetworkEvents for the same process tree to identify downloads or command-and-control traffic.
- DeviceFileEvents for new scripts, binaries, or modified package artifacts in the project directory.
- Source control or build pipeline logs to confirm whether the install was expected.
- Threat intelligence or reputation checks on the package name, hash, or download domain if available.

Benign explanations:
- A legitimate postinstall script is invoking a shell for native module compilation or environment setup.
- A CI/CD pipeline uses npm to orchestrate build steps that legitimately call curl, wget, or PowerShell.
- A developer is testing a package locally and the child process is part of normal build behavior.
- A wrapper tool around npm is spawning helper utilities as part of a documented workflow.

Escalation criteria:
- The spawned child process downloads or executes additional payloads from an untrusted source.
- The package is not approved, is newly published, or matches a known malicious or typosquatted package.
- The host is a CI/CD runner or developer workstation with access to secrets, signing keys, or production repositories.
- Additional suspicious process creation, credential access, or persistence is observed after the install.
- Multiple endpoints or build agents show the same package or hash executing similar behavior.

Containment actions:
- Stop the build or terminate the install process if it is still running and the behavior is not expected.
- Quarantine the affected endpoint or CI/CD agent if malicious execution is confirmed or strongly suspected.
- Remove the suspicious package and any dropped artifacts, then rotate any secrets exposed on the host.
- Block the package source, hash, or download domain if a malicious dependency is confirmed.
- Preserve logs, lockfiles, and build artifacts before cleanup when possible.

Closure criteria:
- The package and child process behavior are validated as expected for the build or development workflow.
- No suspicious downloads, credential access, or persistence are found on the host.
- The package source, version, and hash are confirmed benign or approved.
- Any required allowlist for the package or build tool is documented.
- The event is explained by a known CI/CD or developer workflow and no broader spread is observed.

---

## Detection 4: AutoGen Studio Spawning Unexpected Shell or System Utility Indicating AI Agent RCE

### Detection Opportunity

AutoGen Studio or its underlying Python process spawning a shell interpreter or system utility as a child process, consistent with arbitrary code execution triggered through the MCP WebSocket interface by a malicious webpage

### Intelligence Context

- Microsoft Security Blog: AutoJack: How a single page can RCE the host running your AI agent — [https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/](https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/)
  - Context: A malicious webpage can trigger arbitrary process execution on the host running AutoGen Studio by abusing the unauthenticated MCP WebSocket interface, turning the AI browsing agent into a remote code execution vector.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001, T1059.004, T1203
- Products: AutoGen Studio, MCP WebSocket
- Platforms: AI agent hosts, Web
- Malware: Not specified
- Tools: Not specified
- Search tags: AutoGen Studio, MCP WebSocket, AI agent hosts, Web, T1059, T1059.001, T1059.004, T1203

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Execution: T1203 Exploitation for Client Execution (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let autogenProcesses = dynamic(["autogenstudio", "autogen_studio", "python.exe", "python", "python3"]);
let autogenCmdlineTerms = dynamic(["autogen", "autogenstudio", "mcp", "websocket"]);
let suspawnedProcs = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash", "sh", "zsh",
    "curl", "wget", "certutil.exe", "bitsadmin.exe",
    "whoami.exe", "whoami", "net.exe", "net1.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (autogenProcesses)
| where InitiatingProcessCommandLine has_any (autogenCmdlineTerms)
| where FileName in~ (suspawnedProcs)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessParentFileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    SHA256,
    AlertDetail = strcat("AutoGen process spawned ", FileName, " | Parent cmdline: ", InitiatingProcessCommandLine)
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate AutoGen agent tasks that intentionally invoke shell commands as part of coded agent workflows.
- Python development environments where developers test AutoGen locally and run shell commands interactively.
- Other Python applications whose command lines happen to contain 'mcp' or 'websocket' as argument strings.

Tuning notes:
- Run 'DeviceProcessEvents | where InitiatingProcessCommandLine has_any ("autogen", "autogenstudio") | summarize count() by InitiatingProcessFileName, InitiatingProcessCommandLine | top 20 by count_' to baseline actual AutoGen launch patterns before scheduling.
- Scope DeviceId or DeviceName to device groups representing known AI agent hosts to reduce noise from general Python development machines.
- Add AccountName exclusions for service accounts running AutoGen in automated pipelines if their child process behavior is validated as benign.
- Refine command-line filter strings to match the exact entry point script or module name used in the environment.

Risks / caveats:
- Microsoft Defender for Endpoint must be deployed on AI agent host machines; endpoints without MDE sensor will not generate DeviceProcessEvents.
- If AutoGen Studio is launched via a wrapper script or virtual environment activator that does not pass 'autogen', 'autogenstudio', 'mcp', or 'websocket' in the command line, the InitiatingProcessCommandLine filter will produce zero results for legitimate AutoGen processes.
- The command-line filter ('autogen', 'autogenstudio', 'mcp', 'websocket') must be validated against the actual AutoGen Studio launch method in the environment before scheduling; incorrect strings will cause missed detections.
- Legitimate AutoGen agent tasks that invoke shell commands as part of designed agent workflows will generate false positives; a baseline of expected child processes from AutoGen is required.

### Triage Runbook

First 15 minutes:
- Validate the AutoGen-related parent process and command line to confirm the host is actually running AutoGen Studio or a related MCP/WebSocket service.
- Review the spawned child process name, command line, and account to determine whether it is an expected agent action or an unexpected shell/system utility.
- Check whether the host is reachable from a browser, local network, or exposed service that could have triggered the execution.
- Look for immediate follow-on activity such as downloads, credential access, discovery commands, or additional child processes.
- If the host is a shared AI agent server, identify whether other sessions or users may have been affected.

Evidence to collect:
- DeviceProcessEvents for the AutoGen-related parent and all child processes, including hashes and full command lines.
- Network telemetry showing inbound or outbound connections to the AI agent host around the alert time.
- Service, container, or application logs for AutoGen Studio, MCP WebSocket, or any browser-facing component.
- File and registry changes indicating persistence, configuration tampering, or dropped payloads.
- User and host context: who launched the service, whether it is a lab or production AI agent host, and whether remote access is expected.

Pivot points:
- DeviceProcessEvents for the same DeviceId, AccountName, or parent process tree over the last 24 hours.
- DeviceNetworkEvents for the host to identify suspicious inbound access or outbound downloads.
- DeviceFileEvents and DeviceRegistryEvents for persistence or payload staging.
- Application logs for AutoGen Studio, Python, or the MCP service if centralized logging exists.
- Browser or web proxy logs to identify a triggering webpage or remote session if available.

Benign explanations:
- The AI agent is designed to run shell commands as part of normal workflows and the child process is expected.
- A developer is testing AutoGen locally and intentionally invoking system utilities.
- A wrapper script or virtual environment launch path differs from the expected command line but still represents approved usage.
- A lab or red-team environment is intentionally exercising the RCE path for validation.

Escalation criteria:
- The child process is an unexpected shell, LOLBin, or downloader and cannot be explained by the approved agent workflow.
- The host is internet-facing or reachable from untrusted browsers and the execution appears externally triggered.
- There is evidence of payload download, credential theft, persistence, or lateral movement after the spawn.
- The AutoGen service is running on a production AI agent host with access to sensitive data or credentials.
- Multiple suspicious child processes or repeated triggers occur from the same host or service instance.

Containment actions:
- Disable or isolate the AI agent service or host if arbitrary code execution is confirmed or strongly suspected.
- Terminate the suspicious child process and preserve the parent process and service logs for investigation.
- Block external access to the exposed MCP/WebSocket interface until the exposure is understood and secured.
- Rotate any secrets, API keys, or tokens accessible to the AI agent host.
- Collect forensic evidence before rebuilding or patching the host when feasible.

Closure criteria:
- The spawned process is verified as an approved AutoGen workflow action.
- No evidence of external triggering, payload download, persistence, or lateral movement is found.
- The exposed service is confirmed to be inaccessible to untrusted users or remediated.
- Any required hardening or allowlist changes for the AI agent workflow are documented.
- The host is returned to service only after the launch path and child process behavior are validated.

---

## Detection 5: Worm-Like Self-Propagation via Process Copying to Network Shares with Outbound SMB Activity

### Detection Opportunity

A process writing copies of itself or dropping executables to network share paths combined with outbound SMB connections, consistent with the worm-like propagation mechanism described in the crypto clipper campaign

### Intelligence Context

- Microsoft Security Blog: Crypto Clipper uses Tor and worm-like propagation for persistence and control — [https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
  - Context: The crypto clipper malware propagates in a worm-like manner across endpoints, leaving detectable traces in process creation and file write events consistent with self-copying to network-accessible locations.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021, T1021.002, T1105, T1547
- Products: Not specified
- Platforms: Windows, Endpoint, Network
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, Endpoint, Network, T1021, T1021.002, T1105, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium); Lateral Movement: T1105 Ingress Tool Transfer (medium); Persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let correlationWindowMinutes = 30;
let excludedSystemProcs = dynamic(["System", "svchost.exe", "msiexec.exe", "TrustedInstaller.exe"]);
let executableExtensions = dynamic([".exe", ".dll", ".bat", ".ps1"]);
let fileDrops =
    DeviceFileEvents
    | where Timestamp > ago(1h)
    | where ActionType == "FileCreated"
    | where FolderPath startswith @"\\\\"
        or FolderPath matches regex @"(?i)[A-Za-z]:\\(Removable|USB|RECYCLER)"
    | where FileName has_any (executableExtensions)
    | where InitiatingProcessFileName !in~ (excludedSystemProcs)
    | project
        DropTime = Timestamp,
        DeviceId,
        DeviceName,
        AccountName,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        FileName,
        SHA256,
        FolderPath;
let smbConns =
    DeviceNetworkEvents
    | where Timestamp > ago(1h)
    | where RemotePort == 445
    | where InitiatingProcessFileName !in~ (excludedSystemProcs)
    | project
        ConnTime = Timestamp,
        DeviceId,
        InitiatingProcessFileName,
        RemoteIP;
fileDrops
| join kind=inner smbConns on DeviceId, InitiatingProcessFileName
| where abs(datetime_diff('minute', DropTime, ConnTime)) <= correlationWindowMinutes
| project
    DropTime,
    ConnTime,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    SHA256,
    FolderPath,
    RemoteIP,
    AlertDetail = strcat(InitiatingProcessFileName, " dropped ", FileName, " to ", FolderPath, " and connected to ", RemoteIP, " via SMB")
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate software deployment tools (SCCM, PDQ Deploy, custom deployment scripts) that copy executables to network shares and initiate SMB connections.
- Backup agents that write executable files to network share destinations.
- IT administrators manually copying tools to network shares via Explorer or robocopy while SMB connections are active.

Tuning notes:
- Add known-good deployment process names (e.g., PDQDeployRunner.exe, ccmexec.exe, robocopy.exe) to the excludedSystemProcs list to reduce false positives from legitimate admin tooling.
- Extend FolderPath patterns to include mapped drive letters used for network shares in the environment if UNC paths are not consistently used.
- Adjust correlationWindowMinutes from 30 to a tighter window (5-10 minutes) if the environment has low baseline SMB activity to reduce coincidental correlations.
- Scope to specific device groups if worm propagation risk is concentrated in particular network segments.

Risks / caveats:
- DeviceFileEvents may not capture file writes to network shares if the write is performed by the System process or a kernel-mode driver rather than a user-mode process, as MDE telemetry is process-bound.
- SMB connections initiated by the Windows kernel (System process) for share enumeration may not appear in DeviceNetworkEvents with a meaningful InitiatingProcessFileName, causing the join on InitiatingProcessFileName to miss kernel-driven propagation.
- Legitimate deployment tools writing executables to network shares will generate false positives; a process exclusion allowlist based on environment-specific deployment tooling is recommended before scheduling.
- Mapped drive paths (e.g., Z:\share\) used instead of UNC paths will not be matched by the startswith @'\\\\' filter; additional path patterns may be needed.

### Triage Runbook

First 15 minutes:
- Confirm the file drop path, file name, hash, initiating process, and SMB connection details to determine whether the activity is self-copying or legitimate deployment.
- Identify whether the destination is a network share, administrative share, or removable path and whether the target is internal or external to the environment.
- Review the process tree and command line to see whether the activity resembles a worm, deployment tool, or manual admin copy.
- Check for additional file writes, SMB connections, or process launches from the same host within the same time window.
- If the host is a server or file share, prioritize scoping for other endpoints that may have accessed the dropped file.

Evidence to collect:
- DeviceFileEvents showing the file creation or copy event, including FolderPath, FileName, SHA256, and initiating process.
- DeviceNetworkEvents showing SMB connections, remote IPs, and the same initiating process.
- Process tree and command line for the initiating process, including parent and grandparent context.
- Share access logs or file server logs for the destination path if available.
- Host context: whether the device is a workstation, server, deployment system, or admin machine.

Pivot points:
- DeviceFileEvents for the same DeviceId, SHA256, or FolderPath over the last 24 hours.
- DeviceNetworkEvents for SMB connections from the same host or process to identify other shares contacted.
- DeviceProcessEvents for the same initiating process to see whether it spawned additional tools or scripts.
- File server or SMB share logs to identify other hosts accessing the same dropped file.
- Endpoint telemetry on neighboring hosts for the same hash or file name to detect spread.

Benign explanations:
- A legitimate software deployment or admin tool is copying executables to a network share.
- Backup, synchronization, or imaging software is writing files to shared storage.
- An administrator manually copied tools to a share while SMB traffic was active.
- A scripted maintenance task uses SMB and file copy operations as part of normal operations.

Escalation criteria:
- The dropped file is unsigned, newly seen, or matches a suspicious hash and the process is not an approved deployment tool.
- The same file or hash appears on multiple hosts or shares in a short period.
- The host shows additional malicious behavior such as persistence, credential theft, or lateral movement.
- The destination share contains executable payloads not expected in normal operations.
- The activity originates from a server or workstation that should not be performing software distribution.

Containment actions:
- Isolate the source host if self-propagation or malicious copying is confirmed or strongly suspected.
- Remove or quarantine the dropped file from affected shares after preserving evidence.
- Block the file hash and any confirmed malicious process names across the environment.
- Disable the account used for the copy if it is compromised or unauthorized.
- Notify file share owners and review adjacent hosts for execution of the dropped payload.

Closure criteria:
- The file copy is verified as an approved deployment, backup, or admin action.
- No malicious hash, persistence, or spread is found on the source host or destination shares.
- The SMB activity is explained by documented operational use and matches expected tooling.
- Any required allowlist for the copying process or share path is documented.
- No additional hosts or shares show the same suspicious file or process pattern.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Licensing / identity risk fields:
- Crypto Clipper Clipboard Hijacking via Repeated Clipboard API Access with Wallet Address Pattern: Clipboard telemetry collection requires Microsoft Defender for Endpoint with advanced telemetry features enabled; tenants on basic licensing tiers may not generate these events at all.

Schema / correlation keys:
- AutoGen Studio Spawning Unexpected Shell or System Utility Indicating AI Agent RCE: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceNetworkEvents: shared by Crypto Clipper Clipboard Hijacking via Repeated Clipboard API Access with Wallet Address Pattern; Worm-Like Self-Propagation via Process Copying to Network Shares with Outbound SMB Activity
- DeviceProcessEvents: shared by Malicious npm Postinstall Script Spawning Shell or Network Tool; AutoGen Studio Spawning Unexpected Shell or System Utility Indicating AI Agent RCE

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SSH Brute Force Followed by Successful Login from Same Source IP; Malicious npm Postinstall Script Spawning Shell or Network Tool; Worm-Like Self-Propagation via Process Copying to Network Shares with Outbound SMB Activity.
2. Resolve environment-mapping detections next: Crypto Clipper Clipboard Hijacking via Repeated Clipboard API Access with Wallet Address Pattern.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: AutoGen Studio Spawning Unexpected Shell or System Utility Indicating AI Agent RCE.

### Hunting Agenda and Promotion Criteria

- AutoGen Studio Spawning Unexpected Shell or System Utility Indicating AI Agent RCE: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Crypto Clipper Clipboard Hijacking via Repeated Clipboard API Access with Wallet Address Pattern: Clipboard telemetry collection requires Microsoft Defender for Endpoint with advanced telemetry features enabled; tenants on basic licensing tiers may not generate these events at all.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
