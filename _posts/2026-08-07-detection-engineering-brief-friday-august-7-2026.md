---
layout: post
title: "Detection Engineering Brief - Friday, August 7, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-07
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - GitHub Actions
  - npm
  - Ethereum
  - ChainDrop
  - keyv
  - cacheable
  - GitHub
  - build hosts
  - Linux
  - Unix
  - SSH
  - T1071
  - T1071.001
  - T1090
  - T1090.001
  - T1041
  - T1053
  - T1053.003
  - T1098
  - T1098.004
  - T1543
  - T1543.002
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: GitHub Actions, npm, Ethereum, ChainDrop, keyv, cacheable, GitHub, build hosts, Linux, Unix, SSH, T1071, T1071.001, T1090, T1090.001, T1041, T1053, T1053.003, T1098, T1098.004, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: ChainDrop - GitHub Actions Runner Secret Extraction via Process Activity; keyv/cacheable npm Worm - Anomalous Network Activity on Build Host Following Token Revocation.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: ChainDrop - GitHub Actions Runner Secret Extraction via Process Activity

### Detection Opportunity

Processes on CI/CD runner hosts reading or exfiltrating GitHub Actions secrets via environment variable access or file writes.

### Intelligence Context

- Unit 42: ChainDrop: Inside a Self-Propagating npm Worm — [https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/)
  - Context: ChainDrop was observed extracting GitHub Actions runner secrets by accessing environment variables containing CI/CD credentials during npm package installation on runner hosts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1090, T1090.001
- Products: GitHub Actions
- Platforms: npm, Ethereum
- Malware: ChainDrop
- Tools: Not specified
- Search tags: GitHub Actions, npm, Ethereum, ChainDrop, T1071, T1071.001, T1090, T1090.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookback = 1h;
let secretKeywords = dynamic(["GITHUB_TOKEN", "ACTIONS_", "SECRET", "printenv"]);
let networkTools = dynamic(["curl", "wget", "base64", "nc", "ncat"]);
let npmInstallEvents = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node", "npm", "npm.cmd")
| where ProcessCommandLine has_any ("install", "postinstall", "ci")
| project DeviceName, AccountName, npmTime = Timestamp, npmProcId = ProcessId, npmCommandLine = ProcessCommandLine;
let suspChildProcs = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node", "npm", "sh", "bash")
| where ProcessCommandLine has_any (secretKeywords)
    or FileName in~ (networkTools)
| extend SecretKeywordMatched = iff(ProcessCommandLine has_any (secretKeywords), true, false)
| project DeviceName, AccountName, childTime = Timestamp, ParentProcId = InitiatingProcessId,
    ChildProcessFileName = FileName, ChildProcessCommandLine = ProcessCommandLine,
    ChildFolderPath = FolderPath, SecretKeywordMatched;
npmInstallEvents
| join kind=inner suspChildProcs on DeviceName, AccountName, $left.npmProcId == $right.ParentProcId
| where (childTime - npmTime) between (0s .. 120s)
| project DeviceName, AccountName, npmTime, childTime, npmCommandLine,
    ChildProcessFileName, ChildProcessCommandLine, ChildFolderPath, SecretKeywordMatched
| order by npmTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate postinstall scripts in popular npm packages that invoke curl or wget for asset downloads.
- Developer workstations running npm install where env or printenv is called by build tooling.
- CI pipelines that legitimately call base64 for encoding build artifacts.

**Tuning notes:**
- Add a device name prefix filter or device group tag to restrict results to known runner hosts once runner naming conventions are established.
- Extend secretKeywords with additional CI/CD secret variable name prefixes specific to the organization's pipeline configuration.
- Baseline the query over 7 days before scheduling to identify recurring legitimate postinstall patterns for exclusion.

**Risks / caveats:**
- MDE agent must be deployed on GitHub Actions runner hosts for DeviceProcessEvents to contain runner telemetry. If runners are ephemeral cloud-hosted GitHub-managed runners, MDE onboarding may not be present and the query will return no results for those hosts.
- The 120-second join window may need adjustment depending on CI pipeline step durations in the target environment.
- Ephemeral GitHub-managed runners that are not MDE-onboarded will not appear in results.
- The secretKeywords and networkTools lists should be extended with environment-specific CI/CD variable names during tuning.

### Triage Runbook

**First 15 minutes:**
- Confirm the alerting host is a known GitHub Actions runner or build host and identify the triggering account and pipeline job.
- Review the child process command line and file name for direct secret access indicators such as GITHUB_TOKEN, ACTIONS_, SECRET, printenv, curl, wget, base64, or shell wrappers.
- Check whether the child process folder path is under node_modules or a legitimate package install path to distinguish package postinstall behavior from unexpected execution.
- Look for additional process activity on the same host within the same 2-minute window, especially archive creation, outbound network tools, or repeated environment enumeration.

**Evidence to collect:**
- DeviceName, AccountName, npmTime, childTime, npmCommandLine, ChildProcessFileName, ChildProcessCommandLine, ChildFolderPath, SecretKeywordMatched.
- Parent and child process tree details from DeviceProcessEvents for the npm install process and any spawned shell or utility.
- Any recent CI job metadata or runner name mapping that shows which repository, workflow, or build step was running.
- Whether the host is ephemeral, shared, or a persistent runner, and whether MDE telemetry is expected on that asset.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName around the alert time to reconstruct the full process tree.
- DeviceProcessEvents filtered to the same DeviceName for other child processes spawned by node, npm, sh, or bash in the preceding and following 10 minutes.
- If available, CI/CD or runner inventory to map DeviceName to repository, workflow, and runner group.
- Search for repeated use of the same AccountName across other runner hosts to identify broader compromise.

**Benign explanations:**
- Legitimate npm postinstall scripts that call curl, wget, or base64 to download build assets or encode artifacts.
- Developer or CI tooling that prints environment variables during troubleshooting or package installation.
- Known package build steps that access environment variables as part of normal dependency compilation or test execution.

**Escalation criteria:**
- The child process explicitly references GitHub secrets, environment variable dumping, or credential material.
- The process tree shows unexpected network tooling or shell execution not associated with a known package baseline.
- The same runner account or host shows repeated secret-access behavior across multiple jobs or repositories.
- Evidence suggests the activity occurred outside an approved build window or on a host not in the runner inventory.

**Containment actions:**
- Pause or disable the affected runner host or runner group if it is persistent and under your control.
- Revoke or rotate any GitHub Actions secrets or tokens that may have been exposed.
- Invalidate the current workflow run and block the repository/package version if malicious postinstall behavior is confirmed.
- Preserve the host state and process telemetry before reimaging or terminating the runner.

**Closure criteria:**
- The process activity is matched to a documented, approved build step and no secret access or exfiltration indicators are present.
- The child process path and command line align with a known benign package baseline or approved tooling.
- No additional suspicious process or network activity is found on the runner host during the alert window.
- Any exposed credentials have been rotated and the workflow or package has been validated as benign.

<br/>
---
<br/>

## Detection 2: ChainDrop - Build Host Outbound Connection to Ethereum RPC Endpoints

### Detection Opportunity

Build host processes making outbound connections to Ethereum JSON-RPC ports or blockchain API domains, consistent with ChainDrop's smart contract C2 routing.

### Intelligence Context

- Unit 42: ChainDrop: Inside a Self-Propagating npm Worm — [https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/)
  - Context: ChainDrop used Ethereum smart contracts for C2 routing, meaning infected build hosts would make outbound connections to Ethereum JSON-RPC endpoints or public blockchain API services as part of command-and-control communication.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1090, T1090.001
- Products: GitHub Actions
- Platforms: npm, Ethereum
- Malware: ChainDrop
- Tools: Not specified
- Search tags: GitHub Actions, npm, Ethereum, ChainDrop, T1071, T1071.001, T1090, T1090.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let ethRpcPorts = dynamic([8545, 8546]);
let ethApiDomains = dynamic(["infura.io", "alchemy.com", "etherscan.io", "cloudflare-eth.com", "ankr.com", "quicknode.pro"]);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node", "npm", "npm.cmd", "sh", "bash", "python", "python3")
| where RemotePort in (ethRpcPorts)
    or RemoteUrl has_any (ethApiDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    RemoteIP, RemoteUrl, RemotePort, ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workstations running Web3 or DeFi development tooling that legitimately contacts Infura, Alchemy, or Etherscan.
- Internal blockchain development environments that use standard Ethereum RPC ports.

**Tuning notes:**
- Add a device name prefix or device group filter to restrict results to known CI/CD runner hosts once naming conventions are confirmed.
- Extend ethApiDomains with additional public Ethereum RPC providers identified through threat intelligence.
- Consider adding a RemotePort filter for HTTPS (443) connections to ethApiDomains to catch TLS-wrapped RPC calls that would not use port 8545/8546.

**Risks / caveats:**
- MDE agent must be deployed on build hosts for DeviceNetworkEvents to contain runner network telemetry. Ephemeral GitHub-managed runners without MDE onboarding will not appear.
- DeviceNetworkEvents may not capture outbound connections on non-standard ports (8545, 8546) in all MDE configurations. Verify port-level telemetry coverage before relying on the RemotePort filter.
- Without device-group scoping, developer workstations running Web3 tooling will generate false positives.
- The ethApiDomains list covers major public providers but does not include all possible Ethereum RPC providers. Extend during threat intelligence review.

### Triage Runbook

**First 15 minutes:**
- Confirm the source host is a build runner or developer workstation and identify the initiating process and command line.
- Review the remote URL, IP, and port to determine whether the destination is a known public provider such as Infura, Alchemy, Etherscan, or a private Ethereum node.
- Check whether the initiating process is node, npm, sh, bash, python, or another script interpreter that would be consistent with package execution.
- Look for nearby process activity indicating npm install, postinstall scripts, or other suspicious child processes on the same host.

**Evidence to collect:**
- Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, and ActionType from the alert.
- Any repeated connections to the same domain or IP from the same host over the last 24 hours.
- Process tree context showing whether the connection originated from a package install, script, or interactive developer session.
- Host classification evidence showing whether the device is a known CI/CD runner, a developer workstation, or a blockchain development system.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName to identify all blockchain-related destinations and repeated connection attempts.
- DeviceProcessEvents on the same host to find npm install, postinstall, curl, wget, or script execution around the network event time.
- If available, device inventory or group membership to confirm whether the host is a sanctioned build runner.
- Search for the same RemoteUrl or RemoteIP across other build hosts to determine whether the behavior is isolated or widespread.

**Benign explanations:**
- Developer workstations or build hosts used for Web3, DeFi, or blockchain application development.
- Internal Ethereum testnets or private blockchain infrastructure used by engineering teams.
- Package installation or build tooling that legitimately contacts public APIs for dependency checks, downloads, or telemetry.

**Escalation criteria:**
- The connection originates from a CI/CD runner that should not access blockchain services.
- The initiating process is an unexpected shell or script launched during npm install and not tied to a known package baseline.
- Multiple build hosts show the same Ethereum RPC destinations in a short period without an approved development reason.
- The host also shows secret extraction, unusual child processes, or other postinstall abuse indicators.

**Containment actions:**
- Block or restrict the suspicious outbound destination if it is not required for business operations.
- Isolate the build host if the connection is paired with other suspicious process activity or secret access.
- Rotate any credentials used by the affected build pipeline if compromise is suspected.
- Preserve network and process telemetry before remediation if the host appears to be actively compromised.

**Closure criteria:**
- The destination is confirmed as an approved blockchain service or internal node used by a sanctioned workflow.
- The initiating process and command line match a documented development or build activity.
- No additional suspicious process behavior or credential access is found on the host.
- Any required allowlist or device-group scoping has been documented for future tuning.

<br/>
---
<br/>

## Detection 3: keyv/cacheable npm Worm - Node Process Spawning Shell or Network Tool During npm Install

### Detection Opportunity

Compromised npm package postinstall scripts spawning shells or network utilities on build hosts during package installation.

### Intelligence Context

- SANS ISC: Don't Revoke That Token Yet: Inside the keyv/cacheable npm Worm — [https://isc.sans.edu/diary/rss/33218](https://isc.sans.edu/diary/rss/33218)
  - Context: The keyv and cacheable npm packages were compromised and executed malicious postinstall scripts on build hosts. The malicious code ran when developers or CI pipelines installed the packages, spawning unexpected processes as a child of node.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1041
- Products: keyv, cacheable, GitHub, npm
- Platforms: build hosts
- Malware: Not specified
- Tools: Not specified
- Search tags: keyv, cacheable, GitHub, npm, build hosts, T1071, T1071.001, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Exfiltration: T1041 Exfiltration Over C2 Channel (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookback = 1h;
let suspiciousChildren = dynamic(["sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh", "curl", "wget", "certutil", "nc", "ncat", "python", "python3", "perl", "ruby"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node", "node.exe")
| where FileName in~ (suspiciousChildren)
| where InitiatingProcessCommandLine has_any ("install", "postinstall", "/node_modules/")
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId,
    FileName, ProcessCommandLine, ProcessId, FolderPath
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- npm packages with legitimate postinstall scripts that invoke python or perl for build steps (e.g., node-gyp invoking python for native module compilation).
- Developer workstations where npm install is run interactively and legitimate tooling invokes bash or sh.
- CI pipelines using packages like node-pre-gyp that spawn sh or bash during native dependency compilation.

**Tuning notes:**
- Run the query in hunting mode for 7 days to identify recurring legitimate postinstall patterns (e.g., node-gyp invoking python) and add FileName exclusions for confirmed benign cases.
- Add a device name prefix or device group filter to restrict to known build host populations once naming conventions are confirmed.
- Consider adding a FolderPath contains '/node_modules/.bin/' filter to further tighten scope to postinstall execution contexts.

**Risks / caveats:**
- MDE agent must be deployed on build hosts for DeviceProcessEvents to capture node child process creation. Hosts without MDE onboarding will not appear in results.
- InitiatingProcessCommandLine population for node child processes depends on MDE telemetry depth configuration. Verify this field is non-null for node-spawned processes in the target environment before scheduling.
- node-gyp and similar native module build tools legitimately spawn python and sh as children of node during npm install, which will generate false positives until those paths are baselined and excluded.
- The 1-hour lookback is appropriate for a scheduled rule running on a short cadence; adjust the lookback to match the rule execution frequency to avoid gaps or duplicate alerts.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a build system or developer workstation and identify the exact npm install command and package context.
- Review the spawned FileName and ProcessCommandLine for shells, download tools, or interpreters such as sh, bash, curl, wget, certutil, python, perl, or powershell.
- Check the FolderPath to see whether the child process originated from node_modules or a package-specific path that would indicate postinstall execution.
- Look for repeated child process creation from node within the same install window and any signs of outbound network activity or file writes.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, FileName, ProcessCommandLine, ProcessId, and FolderPath.
- The full process tree for the node process and any children spawned during the install window.
- Package name, version, and source repository if available from the build logs or package manager output.
- Any related network events or file creation activity on the same host during the same time period.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName to reconstruct all node child processes around the alert time.
- DeviceNetworkEvents for the same host to identify outbound connections made by the spawned shell or utility.
- If available, build logs or package manager logs to identify the package being installed when the process spawned.
- Search for the same FileName or command line across other build hosts to determine whether this is a broader package issue.

**Benign explanations:**
- Legitimate native module builds such as node-gyp that spawn python or sh during npm install.
- Approved postinstall scripts that download assets or compile dependencies for a known package.
- Interactive developer installs where local tooling invokes shells or interpreters as part of normal build steps.

**Escalation criteria:**
- The spawned process is a network utility or shell not expected for the package baseline and is accompanied by outbound connections.
- The process command line references credential material, environment dumping, or suspicious download behavior.
- The same package or command pattern appears on multiple hosts or repositories unexpectedly.
- The host shows additional signs of compromise such as persistence, credential access, or unauthorized file modification.

**Containment actions:**
- Stop the affected build job or disable the runner if it is persistent and under your control.
- Quarantine the host if the spawned process is clearly malicious or if additional compromise indicators are present.
- Block the suspicious package version or source in the build pipeline until validated.
- Rotate any secrets that may have been exposed during the install window if secret access is suspected.

**Closure criteria:**
- The process is matched to a known benign package build step or approved automation pattern.
- No suspicious network activity, secret access, or persistence behavior is observed on the host.
- The package version and source are validated as safe or removed from the build path.
- Any required exclusions or allowlist entries are documented for future tuning.

<br/>
---
<br/>

## Detection 4: keyv/cacheable npm Worm - Anomalous Network Activity on Build Host Following Token Revocation

### Detection Opportunity

Build host initiating anomalous outbound network connections shortly after a GitHub token revocation event, consistent with the worm's armed payload trigger behavior.

### Intelligence Context

- SANS ISC: Don't Revoke That Token Yet: Inside the keyv/cacheable npm Worm — [https://isc.sans.edu/diary/rss/33218](https://isc.sans.edu/diary/rss/33218)
  - Context: The worm's payload was designed to arm itself upon detection of token revocation. Revoking the stolen GitHub token triggered the payload, causing the compromised build host to initiate new malicious network activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1041
- Products: keyv, cacheable, GitHub, npm
- Platforms: build hosts
- Malware: Not specified
- Tools: Not specified
- Search tags: keyv, cacheable, GitHub, npm, build hosts, T1071, T1071.001, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Exfiltration: T1041 Exfiltration Over C2 Channel (low)

### Deployment Gates

- GitHub audit logs must be ingested into Microsoft Sentinel's AuditLogs table. This requires the GitHub connector for Sentinel or a custom Log Analytics ingestion pipeline. If GitHub audit logs are not ingested, the tokenRevocations subquery returns no results and the correlation produces nothing.
- The OperationName values for GitHub token revocation events vary by ingestion method. The filter 'has_any ("revoke", "token", "credential", "secret")' must be validated against the actual OperationName values present in the AuditLogs table for the specific GitHub connector in use.

**Required telemetry:**
- AuditLogs, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let triggerWindow = 10m;
let tokenRevocations = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any ("revoke", "token", "credential", "secret")
| extend ActorAccount = tostring(InitiatedBy.user.userPrincipalName)
| project RevocationTime = TimeGenerated, ActorAccount, OperationName;
let buildHostNetworkEvents = DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where InitiatingProcessFileName in~ ("node", "npm", "sh", "bash", "curl", "wget")
| project NetTime = TimeGenerated, DeviceName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType;
tokenRevocations
| join kind=inner buildHostNetworkEvents on 1 == 1
| where NetTime >= RevocationTime and NetTime <= RevocationTime + triggerWindow
| project RevocationTime, NetTime, ActorAccount, OperationName, DeviceName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by RevocationTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Any outbound network connection from any build host within 10 minutes of any token revocation event will match, regardless of causal relationship, due to the absence of a shared join key.
- Routine CI/CD pipeline network activity that coincidentally occurs within the trigger window after an unrelated token revocation.

**Tuning notes:**
- Validate GitHub audit log OperationName values by running: AuditLogs → where TimeGenerated > ago(7d) → where OperationName has 'token' → summarize count() by OperationName before deploying.
- If a host-to-identity mapping table exists (e.g., from Azure AD sign-in logs or a custom watchlist), add a join on ActorAccount to DeviceName to eliminate the cartesian product.
- Restrict buildHostNetworkEvents to known build host device names using a device name prefix filter or a watchlist of runner hostnames to reduce result volume.

**Risks / caveats:**
- GitHub audit logs must be ingested into Microsoft Sentinel's AuditLogs table. This requires the GitHub connector for Sentinel or a custom Log Analytics ingestion pipeline. If GitHub audit logs are not ingested, the tokenRevocations subquery returns no results and the correlation produces nothing.
- The OperationName values for GitHub token revocation events vary by ingestion method. The filter 'has_any ("revoke", "token", "credential", "secret")' must be validated against the actual OperationName values present in the AuditLogs table for the specific GitHub connector in use.
- AuditLogs contains user identity context (ActorAccount) but no device name. DeviceNetworkEvents contains device context but no user identity. There is no shared join key between these tables without an intermediate identity-to-host mapping, making the time-window-only join a cartesian product across all build host network events.
- The join produces a cartesian product between revocation events and build host network events because there is no shared identity-to-host key. Each result row must be manually assessed for causal relationship.

### Triage Runbook

**First 15 minutes:**
- Validate that the revocation event is real and identify the actor account, token type, and affected GitHub repository or organization.
- Confirm whether the network event came from a known build host and identify the initiating process and destination.
- Review whether the network activity began immediately after revocation and whether it includes shells, download tools, or repeated outbound connections.
- Check for concurrent signs of malicious behavior on the host such as unexpected process spawning, file writes, or additional outbound destinations.

**Evidence to collect:**
- RevocationTime, NetTime, ActorAccount, OperationName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, and ActionType.
- GitHub audit log details for the revocation event, including the exact token or credential type if available.
- Process tree and network timeline for the affected build host around the revocation window.
- Any repository, workflow, or runner metadata that links the host to the revoked credential.

**Pivot points:**
- AuditLogs to enumerate all token, credential, or secret revocation events in the relevant time window.
- DeviceNetworkEvents for the same DeviceName to identify all outbound connections before and after the revocation event.
- DeviceProcessEvents for the same host to find node, npm, shell, curl, or wget activity around the trigger window.
- If available, runner inventory or CI logs to map the host to the repository or workflow that used the revoked token.

**Benign explanations:**
- A legitimate CI/CD job that happened to run network activity shortly after an unrelated token revocation.
- Routine build or deployment traffic that coincided with the revocation window by chance.
- Developer or automation activity that uses network tools as part of normal package installation or artifact retrieval.

**Escalation criteria:**
- The host shows new outbound connections, especially to unfamiliar domains, immediately after revocation and the process tree is suspicious.
- The same build host or account shows repeated network activity tied to multiple revocation events.
- The revoked token was high privilege or had access to repositories, secrets, or deployment systems.
- There is supporting evidence of secret extraction, package compromise, or persistence on the host.

**Containment actions:**
- Revoke or rotate the affected GitHub token, related secrets, and any downstream credentials used by the pipeline.
- Isolate the build host if the network activity is suspicious and not attributable to approved automation.
- Pause the affected workflow or disable the runner group until the source of the activity is understood.
- Preserve audit logs and host telemetry before remediation if compromise is likely.

**Closure criteria:**
- The revocation and network activity are shown to be unrelated or part of an approved workflow.
- The host and process are matched to a documented benign build or deployment action.
- No additional suspicious network or process behavior is found in the trigger window.
- Any exposed credentials have been rotated and the correlation has been tuned or scoped appropriately.

<br/>
---
<br/>

## Detection 5: Automated SSH Actor - Rapid Persistence Mechanism Creation Within Seconds of Login

### Detection Opportunity

Automated SSH actor achieving persistence on Linux hosts within seconds of initial login by creating cron jobs, modifying authorized_keys, or writing systemd units.

### Intelligence Context

- SANS ISC: 22 Seconds to Compromise: How Automated SSH Actors Move From Login to Persistence Before You Can Blink [Guest Diary] — [https://isc.sans.edu/diary/rss/33220](https://isc.sans.edu/diary/rss/33220)
  - Context: Automated SSH threat actors were observed achieving full persistence on Linux hosts within 22 seconds of initial login, indicating scripted post-exploitation tooling executing persistence mechanisms immediately after authentication.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1053, T1053.003, T1098, T1098.004, T1543, T1543.002
- Products: Not specified
- Platforms: Linux, Unix, SSH
- Malware: Not specified
- Tools: Not specified
- Search tags: Linux, Unix, SSH, T1053, T1053.003, T1098, T1098.004, T1543, T1543.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Both
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1053 Scheduled Task/Job/ T1053.003 Cron (high); Persistence: T1098 Account Manipulation/ T1098.004 SSH Authorized Keys (high); Persistence: T1543 Create or Modify System Process/ T1543.002 Systemd Service (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceLogonEvents, DeviceProcessEvents

### KQL

```kql
let lookback = 24h;
let persistenceWindow = 30s;
let sshLogons = DeviceLogonEvents
| where Timestamp > ago(lookback)
| where LogonType in ("RemoteInteractive", "Network")
| where InitiatingProcessFileName in~ ("sshd", "ssh")
| project DeviceName, AccountName, LogonTime = Timestamp, RemoteIP;
let persistenceProcs = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any (
    "crontab", "/etc/cron", "authorized_keys", "systemctl enable",
    "systemctl start", ".bashrc", ".bash_profile", ".profile",
    "useradd", "usermod", "passwd", "chpasswd", "visudo"
  )
| project DeviceName, AccountName, PersistTime = Timestamp,
    ProcessCommandLine, PersistFileName = FileName, InitiatingProcessFileName;
sshLogons
| join kind=inner persistenceProcs on DeviceName, AccountName
| where PersistTime >= LogonTime and PersistTime <= LogonTime + persistenceWindow
| extend TimeDeltaSeconds = datetime_diff('second', PersistTime, LogonTime)
| project LogonTime, PersistTime, TimeDeltaSeconds, DeviceName, AccountName,
    RemoteIP, PersistFileName, ProcessCommandLine, InitiatingProcessFileName
| order by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Configuration management automation (Ansible, Chef, Puppet) that SSHes into hosts and immediately runs crontab or systemctl commands as part of legitimate provisioning.
- Monitoring agents that SSH into hosts and modify .bashrc or .profile as part of deployment.
- Legitimate admin sessions where an administrator immediately runs passwd or useradd after SSH login for routine account management.

**Tuning notes:**
- Validate SSH logon representation by running: DeviceLogonEvents → where InitiatingProcessFileName in~ ('sshd', 'ssh') → summarize count() by LogonType, InitiatingProcessFileName before scheduling.
- Add AccountName exclusions for known automation service accounts (e.g., ansible, puppet, chef) that legitimately perform configuration tasks immediately after SSH login.
- Consider extending persistenceWindow to 60 seconds if legitimate automation in the environment takes longer than 30 seconds to execute its first configuration command after SSH login.
- The TimeDeltaSeconds field in the projection enables rapid analyst triage to distinguish sub-5-second automated activity from slower human-initiated sessions.

**Risks / caveats:**
- MDE Linux agent must be deployed on target hosts for DeviceLogonEvents and DeviceProcessEvents to contain SSH session and child process telemetry. Hosts without MDE onboarding will not appear.
- SSH logon events in DeviceLogonEvents may surface with LogonType 'Network' rather than 'RemoteInteractive' depending on the MDE Linux agent version and host configuration. Validate the LogonType values for SSH sessions in the target environment before scheduling.
- InitiatingProcessFileName for SSH-sourced logons may be 'sshd' or absent depending on how the MDE Linux agent records the logon initiator. Verify this field is populated for SSH logons in the target environment.
- The LogonType filter includes both 'RemoteInteractive' and 'Network' to account for variation in how MDE Linux agent records SSH logons. This may include non-SSH network logons if InitiatingProcessFileName is not reliably populated.

### Triage Runbook

**First 15 minutes:**
- Confirm the logon was an SSH session and identify the source IP, account, and target host.
- Review the persistence command line to determine whether it modified crontab, authorized_keys, systemd units, shell profiles, or account settings.
- Check the time delta between login and persistence action; sub-30-second activity is especially suspicious unless tied to approved automation.
- Look for additional commands from the same account on the host that indicate privilege escalation, lateral movement, or further persistence.

**Evidence to collect:**
- LogonTime, PersistTime, TimeDeltaSeconds, DeviceName, AccountName, RemoteIP, InitiatingProcessFileName, PersistFileName, ProcessCommandLine, and InitiatingProcessFileName.
- SSH session details from DeviceLogonEvents and the corresponding process tree from DeviceProcessEvents.
- Any change artifacts such as modified crontab entries, authorized_keys content, or systemd unit files if accessible.
- Host role and account ownership information to determine whether the account is a service account, admin account, or interactive user.

**Pivot points:**
- DeviceLogonEvents for the same DeviceName and AccountName to review all SSH logons and source IPs.
- DeviceProcessEvents on the same host to find follow-on commands after the persistence action.
- If available, Linux audit or configuration management logs to confirm whether the change was approved.
- Search for the same RemoteIP or AccountName across other Linux hosts to identify broader compromise or automation patterns.

**Benign explanations:**
- Configuration management tools such as Ansible, Chef, or Puppet that SSH in and immediately apply cron or systemd changes.
- Legitimate administrative maintenance where an operator updates authorized_keys, cron jobs, or account settings after login.
- Deployment scripts that modify shell profiles or service units as part of a standard provisioning workflow.

**Escalation criteria:**
- The account or source IP is not recognized and the persistence action is not tied to an approved automation system.
- The command line shows unauthorized modification of authorized_keys, cron, systemd, or account settings.
- The same source IP or account appears across multiple hosts in a short period.
- There are signs of privilege escalation, additional backdoors, or post-login reconnaissance on the host.

**Containment actions:**
- Disable or lock the affected account if it is not a known automation identity.
- Remove unauthorized persistence artifacts such as rogue cron entries, systemd units, or SSH keys after preserving evidence.
- Isolate the host if the attacker may still have active access or if multiple persistence mechanisms are present.
- Block the source IP at the network edge if it is clearly malicious and not part of approved administration.

**Closure criteria:**
- The SSH session is confirmed as approved automation or a legitimate administrative action.
- The persistence change is validated against change records or configuration management history.
- No additional suspicious commands, accounts, or hosts are associated with the session.
- Any unauthorized persistence artifacts have been removed and access has been remediated.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- ChainDrop - GitHub Actions Runner Secret Extraction via Process Activity: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- keyv/cacheable npm Worm - Anomalous Network Activity on Build Host Following Token Revocation: GitHub audit logs must be ingested into Microsoft Sentinel's AuditLogs table. This requires the GitHub connector for Sentinel or a custom Log Analytics ingestion pipeline. If GitHub audit logs are not ingested, the tokenRevocations subquery returns no results and the correlation produces nothing.
- keyv/cacheable npm Worm - Anomalous Network Activity on Build Host Following Token Revocation: The OperationName values for GitHub token revocation events vary by ingestion method. The filter 'has_any ("revoke", "token", "credential", "secret")' must be validated against the actual OperationName values present in the AuditLogs table for the specific GitHub connector in use.

**Shared-table notes:**
- DeviceProcessEvents: shared by ChainDrop - GitHub Actions Runner Secret Extraction via Process Activity; keyv/cacheable npm Worm - Node Process Spawning Shell or Network Tool During npm Install; Automated SSH Actor - Rapid Persistence Mechanism Creation Within Seconds of Login
- DeviceNetworkEvents: shared by ChainDrop - Build Host Outbound Connection to Ethereum RPC Endpoints; keyv/cacheable npm Worm - Anomalous Network Activity on Build Host Following Token Revocation

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: ChainDrop - Build Host Outbound Connection to Ethereum RPC Endpoints; keyv/cacheable npm Worm - Node Process Spawning Shell or Network Tool During npm Install; Automated SSH Actor - Rapid Persistence Mechanism Creation Within Seconds of Login.
2. Resolve environment-mapping detections next: keyv/cacheable npm Worm - Anomalous Network Activity on Build Host Following Token Revocation.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ChainDrop - GitHub Actions Runner Secret Extraction via Process Activity.

### Hunting Agenda and Promotion Criteria

- ChainDrop - GitHub Actions Runner Secret Extraction via Process Activity: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- keyv/cacheable npm Worm - Anomalous Network Activity on Build Host Following Token Revocation: GitHub audit logs must be ingested into Microsoft Sentinel's AuditLogs table. This requires the GitHub connector for Sentinel or a custom Log Analytics ingestion pipeline. If GitHub audit logs are not ingested, the tokenRevocations subquery returns no results and the correlation produces nothing.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
