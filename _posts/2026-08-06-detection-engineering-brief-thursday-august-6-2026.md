---
layout: post
title: "Detection Engineering Brief - Thursday, August 6, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-06
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - SSH
  - Linux
  - npm
  - ChainDrop
  - build systems
  - GitHub
  - build hosts
  - cloud services
  - ClickFix
  - macOS
  - web browsers
  - T1098
  - T1053
  - T1053.003
  - T1543
  - T1543.002
  - T1078
  - T1195
  - T1195.002
  - T1059
  - T1059.007
  - T1059.004
  - T1105
  - T1059.002
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 3 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: SSH, Linux, npm, ChainDrop, build systems, GitHub, build hosts, cloud services, ClickFix, macOS, web browsers, T1098, T1053, T1053.003, T1543, T1543.002, T1078, T1195, T1195.002, T1059, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Rapid Post-SSH-Login Persistence Activity Within 30 Seconds; ChainDrop: Node Process Accessing Credential Stores on Build Hosts; ChainDrop: npm Publish Command Executed Outside Expected CI Service Accounts; npm Supply Chain Worm: Node Spawning Unexpected Child Processes on Build Hosts; macOS ClickFix: Browser-Spawned Shell or Script Execution Indicating Infostealer Delivery.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Rapid Post-SSH-Login Persistence Activity Within 30 Seconds

### Detection Opportunity

Automated SSH actors establishing persistence mechanisms within seconds of initial login on Linux hosts.

### Intelligence Context

- SANS ISC: 22 Seconds to Compromise: How Automated SSH Actors Move From Login to Persistence Before You Can Blink [Guest Diary] — [https://isc.sans.edu/diary/rss/33220](https://isc.sans.edu/diary/rss/33220)
  - Context: Reporting documents automated SSH threat actors completing the full login-to-persistence chain in approximately 22 seconds, indicating scripted post-exploitation tooling executing persistence commands immediately after authentication.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1053, T1053.003, T1543, T1543.002
- Products: SSH
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: SSH, Linux, T1098, T1053, T1053.003, T1543, T1543.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation (medium); Persistence: T1053 Scheduled Task/Job/ T1053.003 Cron (high); Persistence: T1543 Create or Modify System Process/ T1543.002 Systemd Service (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- Syslog, DeviceFileEvents

### KQL

```kql
let SSHLogins = Syslog
| where Facility == "auth" and SyslogMessage has "Accepted"
| extend SSHUser = extract(@"for (\S+) from", 1, SyslogMessage)
| extend RemoteIP = extract(@"from ([\d\.]+)", 1, SyslogMessage)
| where isnotempty(SSHUser) and isnotempty(RemoteIP)
| project LoginTime = TimeGenerated, Computer = tolower(Computer), SSHUser, RemoteIP;
let PersistenceWrites = DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (".ssh/authorized_keys", "/etc/cron", "/var/spool/cron", "/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly")
| where InitiatingProcessFileName in~ ("bash", "sh", "dash", "zsh", "python", "python3", "perl", "node", "ruby")
| project WriteTime = Timestamp, DeviceName = tolower(DeviceName), FileName, FolderPath, InitiatingProcessFileName, ActionType, MdeAccountName = AccountName;
SSHLogins
| join kind=inner PersistenceWrites on $left.Computer == $right.DeviceName
| where WriteTime between (LoginTime .. (LoginTime + 30s))
| extend TimeDeltaSeconds = datetime_diff('second', WriteTime, LoginTime)
| project LoginTime, WriteTime, TimeDeltaSeconds, DeviceName, SSHUser, MdeAccountName, RemoteIP, FolderPath, FileName, InitiatingProcessFileName, ActionType
| order by TimeDeltaSeconds asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Configuration management tools (Ansible, Puppet, Chef) that SSH in and immediately write cron or systemd unit files as part of legitimate provisioning.
- Automated deployment pipelines that SSH to hosts and deploy service unit files within seconds of login.
- Developer workstations where users SSH locally and modify dotfiles including authorized_keys.

**Tuning notes:**
- After baselining, add InitiatingProcessFileName exclusions for known legitimate automation processes in your environment.
- Consider adding a watchlist of sensitive Linux hosts and filtering Computer to that watchlist to reduce volume.
- If MDE Linux agent is not deployed on all Syslog-forwarding hosts, the join will silently drop those hosts; audit coverage before relying on this detection.

**Risks / caveats:**
- Syslog.Computer and DeviceFileEvents.DeviceName are populated by different agents and may not share a consistent hostname format (FQDN vs. short name), causing the join to produce zero results without normalization.
- DeviceFileEvents.AccountName on Linux reflects the OS process owner recorded by MDE, which may not match the SSH-authenticated username parsed from Syslog, making the account correlation unreliable without environment validation.
- DeviceFileEvents uses Timestamp (Defender XDR schema) not TimeGenerated; the original query correctly uses Timestamp for the MDE table but the join window arithmetic must reference the correct field.
- The 30-second window may need tightening to 22 seconds for higher-fidelity detection aligned with the reported attacker timeline, or widening if ingestion latency causes events to arrive out of order.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is tied to a real SSH login followed by a file write within the same host and 30-second window.
- Identify the SSH user and remote IP from the alert details and verify whether the account is expected to administer that host.
- Inspect the target path to determine whether the write was to authorized_keys, cron, or a systemd unit file.
- Check whether the initiating process was a shell or scripting interpreter and whether the action was a create or modify event.
- Look for additional activity from the same SSH session such as new users, sudo use, service enablement, or outbound connections.

**Evidence to collect:**
- SSH login timestamp, username, source IP, and authentication method from Syslog.
- File path, filename, action type, and initiating process name from DeviceFileEvents.
- Any nearby process creation or service-management activity on the same host within 5 minutes before and after the alert.
- Host identity details to confirm whether the device name maps to the expected Linux asset.
- If available, the exact command history or shell audit trail for the SSH session.

**Pivot points:**
- Syslog for other Accepted SSH logins from the same RemoteIP or SSHUser in the last 24 hours.
- DeviceFileEvents for the same DeviceName and SSHUser around the alert time to find other persistence-related writes.
- DeviceProcessEvents on the same host for service creation, cron edits, user creation, sudo, or shell activity near the alert.
- Authentication and asset inventory tables to determine whether the account and host are privileged or internet-facing.

**Benign explanations:**
- Planned configuration management activity from Ansible, Puppet, or Chef using SSH to deploy cron or systemd files.
- Legitimate administrative maintenance by a Linux operator immediately after login.
- Automated patching or provisioning workflows that write service files as part of normal host setup.

**Escalation criteria:**
- The SSH user or source IP is unknown, external, or not associated with approved administration.
- The write targets authorized_keys, cron, or systemd paths on a sensitive or internet-facing host without a change ticket.
- You find follow-on actions such as new user creation, privilege escalation, or suspicious outbound connections.
- The same source IP or account appears across multiple hosts in a short period.

**Containment actions:**
- Disable or reset the affected account if the login is unauthorized or suspicious.
- Block the source IP at the perimeter or SSH access layer if it is clearly malicious.
- Isolate the Linux host if you see additional signs of active compromise beyond a single persistence write.
- Remove unauthorized persistence artifacts only after preserving evidence and confirming scope.

**Closure criteria:**
- The SSH login is confirmed as approved maintenance or automation and the file write matches the change record.
- No additional suspicious activity is found on the host or from the source IP.
- The persistence artifact is verified as benign and documented in the ticket.
- Any tuning needed for known automation accounts or host groups is recorded for follow-up.

<br/>
---
<br/>

## Detection 2: ChainDrop: Node Process Accessing Credential Stores on Build Hosts

### Detection Opportunity

ChainDrop worm accessing credential files (.npmrc, .gitconfig) via node processes on build systems as part of credential theft and propagation.

### Intelligence Context

- Microsoft Security Blog: ChainDrop supply chain compromise: Anatomy of a self-propagating worm — [https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/)
  - Context: ChainDrop is a credential-stealing worm embedded in over 400 compromised npm packages. It accesses credential stores such as .npmrc and .gitconfig from within npm lifecycle scripts executed by node on build systems, then uses stolen tokens to republish malicious package updates.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078, T1195, T1195.002
- Products: npm
- Platforms: build systems
- Malware: ChainDrop
- Tools: Not specified
- Search tags: npm, ChainDrop, build systems, T1078, T1195, T1195.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1078 Valid Accounts (medium); Impact: T1195 Supply Chain Compromise/ T1195.002 Compromise Software Supply Chain (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let CredentialAccess = DeviceFileEvents
| where InitiatingProcessFileName in~ ("node", "npm", "npm.cmd")
| where ActionType in ("FileCreated", "FileModified", "FileRead")
| where FileName in~ (".npmrc", ".gitconfig", ".git-credentials") or FolderPath has_any (".npmrc", ".gitconfig", ".git-credentials", "npm/token", "npm-token")
| where isnotempty(DeviceName)
| project CredAccessTime = Timestamp, DeviceName, AccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName;
let NpmRegistryOutbound = DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("node", "npm", "npm.cmd")
| where RemoteUrl has_any ("registry.npmjs.org", "registry.npmjs.com") or RemotePort == 443
| where isnotempty(DeviceName)
| project NetTime = Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName;
CredentialAccess
| join kind=inner NpmRegistryOutbound on DeviceName
| where NetTime between (CredAccessTime .. (CredAccessTime + 5m))
| project CredAccessTime, NetTime, DeviceName, AccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by CredAccessTime desc
| take 500
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate npm install or npm ci operations on developer workstations that read .npmrc for registry authentication and then connect to registry.npmjs.org.
- CI pipeline agents running npm publish or npm install as part of normal build steps.
- IDE extensions or tooling that reads .gitconfig during project initialization.

**Tuning notes:**
- Validate that DeviceFileEvents captures FileRead events for .npmrc on your specific OS platforms and MDE sensor versions before relying on this detection.
- Remove the RemotePort == 443 fallback once you confirm RemoteUrl is consistently populated for npm registry connections in your environment.
- Add a DeviceName filter against a watchlist of CI/CD build hosts to reduce false positive volume significantly.

**Risks / caveats:**
- DeviceFileEvents does not reliably capture read-only file access (FileRead) for .npmrc and .gitconfig on all OS platforms in Defender for Endpoint; if only FileCreated/FileModified are present, the credential access signal will be absent.
- DeviceNetworkEvents.RemoteUrl may not be populated for all npm registry connections depending on the Defender for Endpoint version and OS; RemoteIP/RemotePort may need to be used as a fallback, requiring knowledge of npm registry IP ranges.
- FileRead ActionType availability in DeviceFileEvents varies by OS and MDE sensor version; if absent, the query will only fire on file creation/modification events, missing pure read-based credential access.
- The RemotePort == 443 fallback in NpmRegistryOutbound will match all HTTPS outbound traffic from node/npm, significantly broadening the network signal when RemoteUrl is unpopulated.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a build system or CI runner and not a developer workstation.
- Verify whether the file access involved .npmrc, .gitconfig, or .git-credentials and whether the initiating process was node or npm.
- Check whether the access was followed by outbound connections to npm registry endpoints or other package infrastructure.
- Identify the account running the process and determine whether it is a known CI service account.
- Look for signs of package republishing, token use, or unusual child processes spawned by the same node/npm activity.

**Evidence to collect:**
- DeviceFileEvents showing the credential file name, folder path, action type, and initiating process.
- DeviceNetworkEvents showing registry connections, remote URL/IP, and timing relative to the file access.
- DeviceName and AccountName to determine whether the activity came from an approved build host and service account.
- Any related DeviceProcessEvents for node, npm, or child processes spawned during the same time window.
- If available, package registry audit logs or CI job logs for the same time period.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and AccountName to find other reads or modifications of credential stores.
- DeviceNetworkEvents for outbound connections from node/npm on the same host to registry.npmjs.org or registry.npmjs.com.
- DeviceProcessEvents for npm, node, or npm.cmd on the host to identify package install, publish, or script execution activity.
- CI/CD platform logs to correlate the alert time with a pipeline run or package publish job.

**Benign explanations:**
- Normal npm install or npm ci activity on a developer workstation or build host reading .npmrc for registry authentication.
- CI pipeline execution that legitimately accesses .gitconfig or npm token files during package build or publish steps.
- IDE or developer tooling that reads .gitconfig during workspace initialization.

**Escalation criteria:**
- The host is a build system and the account is not an expected CI service account.
- Credential file access is followed by package publish activity or unusual outbound registry traffic.
- You find evidence of token theft, republishing, or multiple hosts showing the same pattern.
- The activity occurs outside normal build windows or from an unexpected source account.

**Containment actions:**
- Revoke or rotate npm, Git, and related registry tokens if theft is suspected.
- Disable the affected CI or build account until the scope is understood.
- Isolate the build host if there is evidence of active worm propagation or unauthorized package publishing.
- Coordinate with DevOps before removing files or stopping pipelines to avoid breaking legitimate builds unnecessarily.

**Closure criteria:**
- The activity is matched to a known build job, approved service account, and expected package workflow.
- No evidence of token theft, republishing, or malicious outbound activity is found.
- The accessed files and registry connections are consistent with documented pipeline behavior.
- Any required host scoping or account exclusions are documented for tuning.

<br/>
---
<br/>

## Detection 3: ChainDrop: npm Publish Command Executed Outside Expected CI Service Accounts

### Detection Opportunity

Malicious npm publish commands executed by unexpected processes or accounts on build hosts as part of ChainDrop worm propagation.

### Intelligence Context

- Microsoft Security Blog: ChainDrop supply chain compromise: Anatomy of a self-propagating worm — [https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/)
  - Context: ChainDrop automatically republishes malicious package updates to the npm registry using stolen credentials. This propagation step involves npm publish commands executed programmatically from within compromised package lifecycle scripts, not from expected CI pipeline service accounts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078, T1195, T1195.002
- Products: npm
- Platforms: build systems
- Malware: ChainDrop
- Tools: Not specified
- Search tags: npm, ChainDrop, build systems, T1078, T1195, T1195.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1078 Valid Accounts (medium); Impact: T1195 Supply Chain Compromise/ T1195.002 Compromise Software Supply Chain (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ciServiceAccounts = dynamic([]);
let NpmPublishProcs = DeviceProcessEvents
| where ProcessCommandLine has_any ("npm publish", "npm.cmd publish")
| where InitiatingProcessFileName in~ ("node", "sh", "bash", "dash", "zsh")
| where isnotempty(DeviceName)
| where AccountName !in~ (ciServiceAccounts)
| project PublishTime = Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName;
let RegistryConnections = DeviceNetworkEvents
| where RemoteUrl has_any ("registry.npmjs.org", "registry.npmjs.com") or RemotePort == 443
| where InitiatingProcessFileName in~ ("node", "npm", "npm.cmd")
| where isnotempty(DeviceName)
| project NetTime = Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort;
NpmPublishProcs
| join kind=inner RegistryConnections on DeviceName
| where NetTime between (PublishTime .. (PublishTime + 2m))
| project PublishTime, NetTime, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by PublishTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CI pipeline agents that invoke npm publish via shell wrappers (sh -c 'npm publish') where the shell is the initiating process rather than the CI runner binary directly.
- Developer workstations where developers manually run npm publish from a terminal spawned by a shell.

**Tuning notes:**
- Populate ciServiceAccounts with all AccountName values used by your CI/CD pipeline agents (e.g., github-actions, jenkins, azuredevops) before enabling as a scheduled rule.
- After populating the exclusion list, promote to production_candidate.
- Scope DeviceName to a build host watchlist to reduce volume from developer machines.

**Risks / caveats:**
- ProcessCommandLine may be truncated for long npm publish invocations on some OS platforms in Defender for Endpoint, potentially missing the 'publish' argument.
- DeviceNetworkEvents.RemoteUrl population for npm registry connections is not guaranteed on all OS and MDE sensor versions; the network correlation may silently fail if RemoteUrl is empty.
- The ciServiceAccounts dynamic list is empty and must be populated with environment-specific CI account names before this query will suppress legitimate pipeline activity.
- The RemotePort == 443 fallback broadens the network correlation to all HTTPS traffic from node/npm; remove once RemoteUrl population is confirmed.

### Triage Runbook

**First 15 minutes:**
- Confirm the publish command was executed on a build host and not by an approved CI service account.
- Review the full command line to verify it was an actual publish action and not a benign version check or wrapper command.
- Check whether the process was launched by node, sh, bash, or another shell consistent with lifecycle-script abuse.
- Look for a matching outbound connection to the npm registry around the same time.
- Determine whether the same account or host has performed other publish actions recently.

**Evidence to collect:**
- DeviceProcessEvents showing the publish command line, initiating process, account name, and device name.
- DeviceNetworkEvents showing registry connections, remote URL/IP, and timing relative to the publish event.
- Any CI job metadata or build logs that explain why the publish occurred.
- Account inventory or allowlist data for expected CI service accounts.
- If available, package registry audit logs showing the package name, version, and publish source.

**Pivot points:**
- DeviceProcessEvents for npm publish, npm.cmd publish, or npx publish on the same host and account.
- DeviceNetworkEvents for registry.npmjs.org or registry.npmjs.com traffic from the same device.
- CI/CD logs to confirm whether the publish was initiated by an approved pipeline.
- Identity logs to determine whether the account has recent sign-in anomalies or token misuse indicators.

**Benign explanations:**
- A legitimate CI pipeline publishing a package from an approved service account.
- A developer manually publishing a package from a controlled build environment during a planned release.
- A shell wrapper around npm publish used by a standard release script.

**Escalation criteria:**
- The account is not in the approved CI allowlist and the publish was not expected.
- The publish is associated with suspicious shell execution, token theft, or other ChainDrop indicators.
- The same host or account shows repeated publish attempts or multiple package updates in a short period.
- Registry audit logs show an unexpected package version or maintainer change.

**Containment actions:**
- Disable or rotate the affected npm and related registry credentials immediately if unauthorized publishing is confirmed or strongly suspected.
- Suspend the CI/build account and stop the pipeline that is performing the publish.
- Coordinate with the package registry owner to unpublish or quarantine malicious package versions if applicable.
- Isolate the host if there are signs of broader compromise beyond the publish action.

**Closure criteria:**
- The publish is confirmed as an approved CI or release activity and the account is on the allowlist.
- Registry and CI logs match the alert time and explain the action.
- No suspicious follow-on activity or unauthorized package changes are found.
- The allowlist or host scoping is updated if needed to prevent repeat noise.

<br/>
---
<br/>

## Detection 4: npm Supply Chain Worm: Node Spawning Unexpected Child Processes on Build Hosts

### Detection Opportunity

Compromised npm packages executing unexpected child processes (shells, downloaders) via postinstall lifecycle scripts on build hosts.

### Intelligence Context

- SANS ISC: Don't Revoke That Token Yet: Inside the keyv/cacheable npm Worm, (Wed, Aug 5th) — [https://isc.sans.edu/diary/rss/33218](https://isc.sans.edu/diary/rss/33218)
  - Context: A compromised npm package executed on a build host as part of a supply-chain worm. The worm abuses tokens and propagates through the ecosystem. Execution of unexpected binaries from within npm lifecycle scripts is the primary host-level indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.007, T1059.004, T1105
- Products: npm, GitHub
- Platforms: build hosts, cloud services
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, GitHub, build hosts, cloud services, T1059, T1059.007, T1059.004, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (medium); Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("node", "npm", "npm.cmd", "npx", "npx.cmd")
| where FileName in~ ("bash", "sh", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh", "curl", "wget", "certutil", "python", "python3", "perl")
| where ProcessCommandLine !has "--version"
    and ProcessCommandLine !has " -v "
    and ProcessCommandLine !has "--help"
    and ProcessCommandLine !has "-version"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
| take 1000
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- npm postinstall scripts that invoke bash or sh for platform-specific binary selection or compilation (node-gyp, native addons).
- npm scripts that invoke curl or wget to download platform-specific prebuilt binaries during package installation.
- npx invocations that spawn python or perl as part of legitimate toolchain scripts.
- CI pipeline steps where npm test or npm run scripts invoke shells as part of test harness execution.

**Tuning notes:**
- Run this query over 7-14 days of historical data to baseline expected child process patterns from node/npm in your environment before adding exclusions.
- After baselining, promote to scheduled_rule with AccountName and FileName exclusions for confirmed legitimate patterns.
- Consider adding a DeviceNetworkEvents correlation to identify spawned processes that also make outbound connections, which would significantly increase fidelity.

**Risks / caveats:**
- DeviceProcessEvents.FileName reflects the process image name without path on some platforms; FolderPath provides the directory but the combination may differ from full executable path depending on OS and MDE sensor version.
- Without DeviceName scoping to build hosts, this query will return high volume from developer workstations where npm scripts routinely spawn shells.
- The exclusion list for benign ProcessCommandLine patterns is minimal; significant analyst review is required to establish a baseline before this can be converted to a scheduled rule.
- SHA256 field availability depends on MDE sensor version and OS platform; it may be null for some process events.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a build system or CI runner and identify the package or script that triggered the child process.
- Review the child process name and command line to see whether it is a shell, downloader, scripting interpreter, or known build tool.
- Check whether the initiating process was node, npm, or npx and whether the command line includes postinstall or other lifecycle script context.
- Look for outbound network activity from the spawned process, especially downloads or connections to unfamiliar domains.
- Determine whether the same package or process pattern appears repeatedly across multiple hosts.

**Evidence to collect:**
- DeviceProcessEvents for the parent node/npm process and the spawned child process command line.
- Process tree details including initiating process command line and account name.
- DeviceNetworkEvents for any outbound connections made by the child process.
- DeviceName and FolderPath to identify whether the activity occurred in a build workspace or system path.
- If available, package name, install job, or CI pipeline metadata associated with the process.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName to find other shell, curl, wget, python, or perl spawns.
- DeviceNetworkEvents for the child process to identify downloads or command-and-control style traffic.
- CI logs or build orchestration logs to map the process to a specific job or package install.
- File events in the workspace to see whether the package dropped or modified additional files.

**Benign explanations:**
- Legitimate npm postinstall scripts that invoke bash, sh, python, or curl for platform-specific setup.
- Native module compilation or dependency installation that uses shell scripts or download tools.
- CI test or build steps that intentionally spawn shells as part of the build pipeline.

**Escalation criteria:**
- The child process is a downloader, encoded command runner, or unexpected scripting interpreter with no clear build justification.
- The same pattern appears on multiple build hosts or is tied to a specific package version.
- The child process makes suspicious outbound connections or writes to unusual locations.
- The activity occurs outside normal build windows or under an unexpected account.

**Containment actions:**
- Pause the affected build job or pipeline if the process is still active and suspicious.
- Quarantine the package or dependency version in the build system until validated.
- Isolate the host if the child process is clearly malicious or is downloading payloads.
- Block known malicious outbound destinations if they are identified during triage.

**Closure criteria:**
- The child process is explained by a documented build step or known benign package behavior.
- No suspicious network activity, file writes, or repeated anomalous spawns are found.
- The package or script is validated as expected by the build owner.
- Any needed exclusions for known benign child processes are recorded.

<br/>
---
<br/>

## Detection 5: macOS ClickFix: Browser-Spawned Shell or Script Execution Indicating Infostealer Delivery

### Detection Opportunity

ClickFix-style lure pages tricking macOS users into pasting and executing malicious commands, resulting in browser processes spawning osascript, bash, or curl as infostealer delivery.

### Intelligence Context

- Microsoft Security Blog: From open lures to cloaked gates: How a macOS ClickFix campaign learned to hide — [https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/](https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/)
  - Context: A macOS ClickFix campaign served infostealer lures behind a browser fingerprinting gate. Users were prompted to paste clipboard-injected commands into Terminal, resulting in shell or osascript execution spawned in the context of browser activity. The campaign shifted from open lure delivery to fingerprinting-gated infrastructure to evade detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1059.002, T1105
- Products: ClickFix
- Platforms: macOS, web browsers
- Malware: Not specified
- Tools: Not specified
- Search tags: ClickFix, macOS, web browsers, T1059, T1059.004, T1059.002, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.002 AppleScript (high); Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let SuspiciousShellIndicators = dynamic(["curl ", "wget ", "base64", "eval ", "http://", "https://", "/tmp/", "/var/folders/", "osascript", "| bash", "| sh", "python -c", "python3 -c"]);
let BrowserProcessNames = dynamic(["Safari", "Google Chrome", "firefox", "Chromium", "Microsoft Edge", "msedge", "com.apple.WebKit.WebContent", "com.apple.WebKit.Networking"]);
DeviceProcessEvents
| where FileName in~ ("osascript", "bash", "sh", "zsh", "curl", "python3", "python", "Terminal")
| where ProcessCommandLine has_any (SuspiciousShellIndicators)
| where InitiatingProcessFileName in~ (BrowserProcessNames)
    or InitiatingProcessParentFileName in~ (BrowserProcessNames)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
| take 500
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Browser extensions or helper applications that legitimately invoke osascript for macOS integration (e.g., 1Password, Keychain access helpers).
- Developer tools that browsers invoke for debugging or extension development.
- Legitimate curl invocations from browser-spawned processes for update checks or telemetry.

**Tuning notes:**
- Validate that macOS browser processes appear as InitiatingProcessFileName or InitiatingProcessParentFileName in DeviceProcessEvents when Terminal spawns a shell after a browser session.
- Consider adding a time-proximity correlation between browser network activity and the shell spawn using a join with DeviceNetworkEvents to increase fidelity.
- Add FolderPath exclusions for signed application bundles under /Applications/ to reduce false positives from legitimate browser helper scripts.

**Risks / caveats:**
- On macOS, the ClickFix execution chain involves the user pasting into Terminal, meaning the browser is a grandparent or higher ancestor rather than the direct InitiatingProcessFileName. DeviceProcessEvents only exposes one level of parent process (InitiatingProcessFileName), so the browser-to-shell relationship may not be directly observable without process tree reconstruction.
- InitiatingProcessParentFileName availability on macOS in Defender for Endpoint should be validated; it may not be populated consistently across all macOS sensor versions.
- The ClickFix paste-into-Terminal pattern places Terminal as the direct parent of the shell command, not the browser. If InitiatingProcessFileName is Terminal and InitiatingProcessParentFileName is the browser, this query will catch it; if the ancestry chain is deeper, it will be missed.
- InitiatingProcessParentFileName may not be consistently populated on macOS in all MDE sensor versions; validate field availability before relying on the grandparent ancestry check.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is macOS and identify the user account involved.
- Review the command line for signs of pasted payloads, download commands, base64 decoding, temp-path execution, or osascript use.
- Check the process ancestry to see whether Terminal or a browser-related process is in the chain.
- Look for immediate outbound connections or file downloads following the shell or script execution.
- Determine whether the user recently visited a suspicious website, support page, or CAPTCHA-style lure.

**Evidence to collect:**
- DeviceProcessEvents showing the process tree, command line, parent process, and account name.
- Any available browser history, download history, or web proxy logs around the alert time.
- DeviceNetworkEvents for outbound connections from the same host and user session.
- SHA256 of the spawned binary or script if present.
- User-reported context such as a recent website visit, prompt, or pasted command.

**Pivot points:**
- DeviceProcessEvents for the same host to find other osascript, bash, sh, zsh, curl, python, or Terminal activity.
- DeviceNetworkEvents for the same DeviceName to identify downloads or connections to suspicious infrastructure.
- Browser telemetry or proxy logs to identify the page visited immediately before the execution.
- File events for temp directories and Downloads to see whether payloads were written locally.

**Benign explanations:**
- Legitimate use of osascript or shell commands by developers or IT staff on macOS.
- Browser helper or update processes that invoke curl for normal application behavior.
- Signed application scripts under /Applications that use shell or AppleScript for integration tasks.

**Escalation criteria:**
- The command line shows a pasted payload, encoded content, or direct download-and-execute behavior.
- The user reports being prompted by a website to paste commands into Terminal.
- The host shows follow-on credential theft, persistence, or additional suspicious downloads.
- The same lure or destination appears across multiple macOS endpoints.

**Containment actions:**
- Isolate the macOS host if the command appears malicious or if follow-on activity is present.
- Reset affected user credentials if there is evidence of infostealer behavior or token theft.
- Block the suspicious domain or URL at web and DNS controls if identified.
- Collect volatile evidence before remediation if the host is still active and compromise is suspected.

**Closure criteria:**
- The execution is explained by a known legitimate admin or developer action.
- No suspicious downloads, credential theft, or persistence are found after review.
- The browser ancestry and command line are consistent with benign software behavior.
- Any confirmed malicious URL, domain, or script is documented for blocking and hunting.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- Rapid Post-SSH-Login Persistence Activity Within 30 Seconds: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- ChainDrop: Node Process Accessing Credential Stores on Build Hosts: Do not schedule yet; validate as an analyst-led hunt first.
- npm Supply Chain Worm: Node Spawning Unexpected Child Processes on Build Hosts: Do not schedule yet; validate as an analyst-led hunt first.
- macOS ClickFix: Browser-Spawned Shell or Script Execution Indicating Infostealer Delivery: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- ChainDrop: npm Publish Command Executed Outside Expected CI Service Accounts: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Shared-table notes:**
- DeviceFileEvents: shared by Rapid Post-SSH-Login Persistence Activity Within 30 Seconds; ChainDrop: Node Process Accessing Credential Stores on Build Hosts
- DeviceNetworkEvents: shared by ChainDrop: Node Process Accessing Credential Stores on Build Hosts; ChainDrop: npm Publish Command Executed Outside Expected CI Service Accounts
- DeviceProcessEvents: shared by ChainDrop: npm Publish Command Executed Outside Expected CI Service Accounts; npm Supply Chain Worm: Node Spawning Unexpected Child Processes on Build Hosts; macOS ClickFix: Browser-Spawned Shell or Script Execution Indicating Infostealer Delivery

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Rapid Post-SSH-Login Persistence Activity Within 30 Seconds; ChainDrop: npm Publish Command Executed Outside Expected CI Service Accounts.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ChainDrop: Node Process Accessing Credential Stores on Build Hosts; npm Supply Chain Worm: Node Spawning Unexpected Child Processes on Build Hosts; macOS ClickFix: Browser-Spawned Shell or Script Execution Indicating Infostealer Delivery.

### Hunting Agenda and Promotion Criteria

- ChainDrop: Node Process Accessing Credential Stores on Build Hosts: Do not schedule yet; validate as an analyst-led hunt first.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.
- npm Supply Chain Worm: Node Spawning Unexpected Child Processes on Build Hosts: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- macOS ClickFix: Browser-Spawned Shell or Script Execution Indicating Infostealer Delivery: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Rapid Post-SSH-Login Persistence Activity Within 30 Seconds: Defender for Endpoint file-event coverage must be confirmed on the target host population.; prove correlation keys join correctly on real tenant telemetry.
- ChainDrop: npm Publish Command Executed Outside Expected CI Service Accounts: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling..

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
