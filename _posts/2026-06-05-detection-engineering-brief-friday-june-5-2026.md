---
layout: post
title: "Detection Engineering Brief - Friday, June 5, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-05
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - npm
  - GitHub
  - CI/CD
  - developer systems
  - cloud platforms
  - Windows
  - Linux
  - macOS
  - MSI
  - swagger.json
  - Web applications
  - APIs
  - T1537
  - T1098
  - T1105
  - T1566
  - T1566.002
  - T1204
  - T1204.002
  - T1027
  - T1595
  - T1595.002
  - T1590
  - T1590.005
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: npm, GitHub, CI/CD, developer systems, cloud platforms, Windows, Linux, macOS, MSI, swagger.json, Web applications, APIs, T1537, T1098, T1105, T1566, T1566.002, T1204, T1204.002, T1027, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: npm-Spawned Process Accessing Credential Files - Miasma Credential Theft; Automated npm Publish Outside Expected CI/CD Context - Miasma Worm Propagation; External Reconnaissance Scanning for swagger.json and API Documentation Endpoints.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: npm Preinstall Hook Spawning Shell or Network Tool - Miasma Campaign

### Detection Opportunity

npm preinstall lifecycle script spawning a shell or network utility during package installation, consistent with the Miasma supply chain campaign targeting @redhat-cloud-services packages

### Intelligence Context

- Microsoft Security Blog: Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — [https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
  - Context: The Miasma campaign embedded malicious code in npm preinstall hooks within compromised @redhat-cloud-services packages. During installation, the hook spawned shells or network tools to steal credentials and establish persistence on developer machines and CI/CD systems.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1537, T1098, T1105
- Products: npm, GitHub
- Platforms: CI/CD, developer systems, cloud platforms, Windows, Linux, macOS
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, GitHub, CI/CD, developer systems, cloud platforms, Windows, Linux, macOS, T1537, T1098, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1537 Transfer Data to Cloud Account (medium); Persistence: T1098 Account Manipulation (low); Command and Control: T1105 Ingress Tool Transfer (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "npm", "npm.cmd")
| where FileName in~ ("cmd.exe", "powershell.exe", "sh", "bash", "curl", "wget", "certutil.exe", "wscript.exe", "cscript.exe")
| where InitiatingProcessCommandLine has "npm"
    and InitiatingProcessCommandLine has_any ("install", "ci", "preinstall", "postinstall", "lifecycle")
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    FolderPath,
    ReportId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate npm postinstall scripts that invoke shell commands for build steps (e.g., node-gyp, esbuild native compilation).
- Developer tools that use node.exe to spawn curl or wget for asset downloads during package setup.
- CI/CD pipeline agents running npm ci as part of normal build workflows.

Tuning notes:
- Add AccountName exclusions for known CI/CD service accounts to reduce pipeline noise.
- If network utility spawning (curl, wget, certutil) generates excessive FPs, restrict FileName to shell binaries only (cmd.exe, powershell.exe, sh, bash) as a first tuning step.
- Consider adding a FolderPath has_any ('node_modules', 'AppData\\Local\\Temp', '/tmp') filter to focus on lifecycle-context spawning.

Risks / caveats:
- InitiatingProcessCommandLine may not be populated for all npm process invocations depending on endpoint agent version and configuration; if unpopulated the command-line filter will silently drop events.
- Legitimate npm lifecycle scripts that invoke shells for native compilation (node-gyp) will generate false positives; baseline the environment before alerting.
- On Linux/macOS endpoints, 'npm' and 'sh'/'bash' as process names depend on agent telemetry fidelity for non-Windows platforms.
- The 7-day lookback is appropriate for scheduled rules but may miss slow-burn installations; adjust to 1d for high-volume environments.

### Triage Runbook

First 15 minutes:
- Confirm the initiating process and command line are consistent with npm install/ci activity and not a known build job.
- Check whether the parent process chain shows node.exe/npm spawning cmd, powershell, sh, bash, curl, wget, certutil, wscript, or cscript from a package install path or temp/node_modules directory.
- Identify the user account and device owner; determine whether this is a developer workstation, build agent, or service account.
- Look for immediate follow-on activity from the same host such as credential file access, outbound connections to package registries, or creation of persistence artifacts.
- If the process chain is unexpected or the host is not a known build system, treat as likely compromise and escalate immediately.

Evidence to collect:
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, ReportId, DeviceId.
- Full process tree for the alerting event and any child processes spawned within the next 15 minutes.
- Recent npm activity on the host, including package names installed and whether the package source was a trusted internal registry or public npm.
- Any related file, network, or credential access events from the same account and device around the alert time.
- Whether the account is a known CI/CD service account or a developer identity with expected npm usage.

Pivot points:
- DeviceProcessEvents for the same DeviceName and AccountName over the prior 24 hours to find other shell or network tool launches.
- DeviceFileEvents for the same host and account to look for reads of .npmrc, .gitconfig, cloud credential stores, or package files.
- DeviceNetworkEvents for outbound connections to registry.npmjs.org, registry.npmjs.com, paste sites, or unusual external IPs after the install event.
- DeviceLogonEvents and DeviceInfo to determine whether the account and device are expected to run npm installs.
- If available, GitHub or source control audit logs for recent dependency changes or package publication activity.

Benign explanations:
- Legitimate npm postinstall or preinstall scripts used for native compilation or build setup, such as node-gyp or esbuild.
- Developer tooling that uses curl, wget, or shell commands to fetch dependencies or assets during package installation.
- CI/CD pipeline jobs that run npm ci as part of normal build and test workflows.

Escalation criteria:
- The host is a developer workstation or non-build system and the process chain shows unexpected shell or network tool execution during npm install.
- The same account or host also accessed credential files, cloud tokens, or registry secrets near the alert time.
- Outbound connections or file activity indicate credential theft, package tampering, or persistence behavior.
- The package source or install path is untrusted, recently modified, or associated with a compromised repository.

Containment actions:
- Isolate the endpoint if the process chain is clearly malicious or if credential theft is confirmed.
- Disable or reset the affected user or service account credentials if they may have been exposed.
- Block the suspicious package source or repository in the organization’s software allowlist or package proxy.
- Preserve volatile evidence and process tree before remediation if the host is a developer workstation or build agent.

Closure criteria:
- Confirmed as a known and approved build/install workflow with matching package provenance and no suspicious follow-on activity.
- No credential access, no unexpected outbound connections, and no persistence indicators were found after review.
- The alert maps to an approved CI/CD service account or build host and matches documented baseline behavior.
- Any suspicious package or repository has been validated as benign by the owning engineering team and security has recorded the exception.

---

## Detection 2: npm-Spawned Process Accessing Credential Files - Miasma Credential Theft

### Detection Opportunity

A node.exe or npm-spawned process accessing known credential file paths such as .npmrc, .gitconfig, or cloud provider credential stores, consistent with the Miasma campaign's credential-stealing behavior targeting developer machines

### Intelligence Context

- Microsoft Security Blog: Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — [https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
  - Context: The Miasma campaign's malicious npm packages read credential files including .npmrc, .gitconfig, and cloud platform credential stores from developer machines and CI/CD environments to exfiltrate tokens and secrets.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1537, T1098, T1105
- Products: npm, GitHub
- Platforms: CI/CD, developer systems, cloud platforms, Windows, Linux, macOS
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, GitHub, CI/CD, developer systems, cloud platforms, Windows, Linux, macOS, T1537, T1098, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1537 Transfer Data to Cloud Account (medium); Persistence: T1098 Account Manipulation (low); Command and Control: T1105 Ingress Tool Transfer (low)

### Deployment Gates

- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

Required telemetry:
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let CredentialFileAccess = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileRead", "FileAccessed", "FileCreated", "FileModified")
| where FileName in~ (".npmrc", ".gitconfig", "credentials")
    or FolderPath has_any (".aws", ".azure", ".config/gcloud", ".npmrc", ".gitconfig")
| where InitiatingProcessFileName in~ ("node.exe", "npm", "npm.cmd", "sh", "bash", "cmd.exe", "powershell.exe")
| project
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccessTime = Timestamp;
let OutboundAfterAccess = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "npm", "npm.cmd", "sh", "bash")
| where RemotePort in (80, 443)
| project
    DeviceName,
    AccountName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    NetworkTimestamp = Timestamp;
CredentialFileAccess
| join kind=inner OutboundAfterAccess on DeviceName, AccountName
| where NetworkTimestamp >= AccessTime and datetime_diff('minute', NetworkTimestamp, AccessTime) <= 5
| project
    AccessTime,
    NetworkTimestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteUrl,
    RemoteIP,
    RemotePort
| order by AccessTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate npm tooling that reads .npmrc for registry authentication during normal package installation.
- Git clients reading .gitconfig during repository operations initiated by node.exe-based tools.
- Cloud CLI tools (AWS CLI, Azure CLI, gcloud) reading their own credential files during normal operation when invoked from npm scripts.

Tuning notes:
- Run the CredentialFileAccess subquery alone first to confirm FileRead/FileAccessed ActionTypes are present in your environment before deploying the full join.
- Narrow FolderPath filters to include the user home directory prefix (e.g., 'C:\\Users\\' on Windows, '/home/' on Linux) to reduce system-level FPs.
- Exclude known CI/CD service accounts from AccountName to reduce pipeline noise.
- Extend the correlation window beyond 5 minutes if legitimate npm operations in your environment have longer delays between credential file reads and registry connections.

Risks / caveats:
- DeviceFileEvents ActionType values 'FileRead' and 'FileAccessed' are not available in all Defender for Endpoint deployments; availability depends on agent version, OS, and audit policy configuration. If absent, the detection produces no results.
- RemoteUrl field in DeviceNetworkEvents may not be populated for all HTTPS connections depending on TLS inspection configuration; if empty, the network correlation leg will not match.
- If FileRead and FileAccessed ActionTypes are unavailable and only FileCreated/FileModified are present, the detection shifts from read-time detection to write-time detection, which may miss read-only credential theft.
- The 5-minute correlation window between file access and outbound network activity may miss cases where exfiltration is delayed or batched.

### Triage Runbook

First 15 minutes:
- Verify the file paths accessed and confirm they are real credential locations such as .npmrc, .gitconfig, .aws, .azure, or .config/gcloud.
- Check whether the initiating process is node.exe, npm, or a shell launched by npm, and whether the access occurred during a legitimate install or script run.
- Look for outbound network activity from the same host within minutes of the file access, especially to npm registries or unknown external destinations.
- Identify whether the account is a developer identity or CI/CD service account and whether the device is a workstation or build agent.
- If credential files were accessed by an unexpected process or on a non-build host, escalate as likely credential theft.

Evidence to collect:
- AccessTime, NetworkTimestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort.
- Full file access sequence for the host and account around the alert time, including any reads of .npmrc, .gitconfig, cloud credential stores, or token caches.
- Process tree showing the npm or node parent-child relationship and any child processes spawned after the file access.
- Network connections from the host in the 5 to 30 minutes after access, including destination IPs, URLs, and ports.
- Any evidence of package publish, token use, or authentication failures from the same account in source control, cloud, or npm audit logs.

Pivot points:
- DeviceFileEvents for the same DeviceName and AccountName to find other credential or secret file access.
- DeviceNetworkEvents to identify outbound connections after the file access and to correlate with registry or exfiltration destinations.
- DeviceProcessEvents to find shell, curl, wget, powershell, or node child processes launched by npm.
- Identity and cloud audit logs for token use, password resets, or unusual sign-ins tied to the same account.
- GitHub or package registry audit logs for publish, login, or token creation events associated with the account.

Benign explanations:
- npm legitimately reads .npmrc for registry authentication during package installation.
- Git clients or developer tools may read .gitconfig as part of normal repository operations.
- Cloud CLI tools invoked from npm scripts may read their own credential stores during authorized automation.

Escalation criteria:
- Credential files were accessed by an unexpected npm-spawned process on a developer workstation or non-build host.
- The same host made outbound connections shortly after access, especially to registry.npmjs.org, registry.npmjs.com, or unknown external IPs.
- There is evidence of token use, package publish, or account abuse after the file access.
- The accessed files include cloud provider credentials or long-lived tokens with broad access.

Containment actions:
- Isolate the endpoint if unauthorized credential access is confirmed or strongly suspected.
- Revoke or rotate any exposed npm, GitHub, cloud, or source control tokens immediately.
- Disable the affected account until the scope of secret exposure is understood.
- Invalidate active sessions and review package publishing permissions for the account.

Closure criteria:
- The accessed files were expected for a documented build or developer workflow and no suspicious network or publish activity followed.
- The account and device are approved CI/CD assets with matching baseline behavior.
- No secrets were exfiltrated or reused, and any observed access was limited to normal authentication reads.
- Security has validated the file paths and process chain as benign and documented the exception.

---

## Detection 3: Automated npm Publish Outside Expected CI/CD Context - Miasma Worm Propagation

### Detection Opportunity

npm publish command executed from a developer workstation or non-pipeline process, consistent with the Miasma campaign's worm-like self-propagation by republishing compromised packages to the npm registry

### Intelligence Context

- Microsoft Security Blog: Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — [https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
  - Context: The Miasma campaign spread worm-like by using stolen npm credentials to republish trojanized versions of trusted @redhat-cloud-services packages. The npm publish command was executed programmatically as part of the malicious payload, not through normal developer or CI/CD workflows.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1537, T1098, T1105
- Products: npm, GitHub
- Platforms: CI/CD, developer systems, cloud platforms, Windows, Linux, macOS
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, GitHub, CI/CD, developer systems, cloud platforms, Windows, Linux, macOS, T1537, T1098, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1537 Transfer Data to Cloud Account (medium); Persistence: T1098 Account Manipulation (low); Command and Control: T1105 Ingress Tool Transfer (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let NpmPublish = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "npm" and ProcessCommandLine has "publish"
| where InitiatingProcessFileName in~ ("node.exe", "npm", "npm.cmd", "sh", "bash", "cmd.exe", "powershell.exe")
| project
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    PublishTime = Timestamp;
let RegistryConnection = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "registry.npmjs.org" or RemoteUrl has "registry.npmjs.com"
| where RemotePort in (80, 443)
| project
    DeviceName,
    AccountName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    NetTime = Timestamp;
NpmPublish
| join kind=inner RegistryConnection on DeviceName, AccountName
| where NetTime >= PublishTime and datetime_diff('minute', NetTime, PublishTime) <= 3
| project
    PublishTime,
    NetTime,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    RemoteUrl,
    RemoteIP,
    RemotePort
| order by PublishTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate developer-initiated npm publish from a workstation during normal package release workflows.
- CI/CD pipeline agents running npm publish as part of authorized release automation.
- Automated release bots or semantic-release tooling that programmatically publishes packages.

Tuning notes:
- Before scheduling, add AccountName exclusions for all known CI/CD service accounts and DeviceName exclusions for build agent pools.
- If RemoteUrl is not populated, consider correlating on RemoteIP resolved to registry.npmjs.org IP ranges as an alternative.
- Add 'not (ProcessCommandLine has "unpublish")' to avoid matching npm unpublish commands if they appear in the environment.

Risks / caveats:
- RemoteUrl field in DeviceNetworkEvents may not be populated for HTTPS connections to registry.npmjs.org if TLS inspection is not enabled; the network correlation leg may return no results.
- Without CI/CD account and device exclusions applied by the deploying analyst, this query will alert on every legitimate automated publish, making it unsuitable for scheduled alerting without tuning.
- RemoteUrl may be empty for HTTPS connections without TLS inspection, causing the registry correlation to fail silently.
- The 3-minute correlation window may be too short for environments where npm publish takes longer to initiate the registry connection; adjust based on observed timing.

### Triage Runbook

First 15 minutes:
- Confirm whether the publish came from a known release pipeline, automation bot, or developer workstation.
- Review the full command line to verify it is a real npm publish and not a related release command or wrapper script.
- Check the initiating process and device name for signs of a build agent versus a user endpoint.
- Look for recent credential theft indicators on the same host, including credential file access or unusual outbound connections.
- If the publish is from an unexpected host or account, escalate as possible package compromise and account abuse.

Evidence to collect:
- PublishTime, NetTime, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort.
- Package name, version, and registry target from the publish command line or npm logs.
- Process tree and parent process context to determine whether the publish was user-driven, script-driven, or automated.
- Recent sign-in and token activity for the account, including any password resets, MFA prompts, or new token creation.
- Any related source control commits, release pipeline runs, or package metadata changes around the publish time.

Pivot points:
- DeviceProcessEvents for npm, node, shell, or release tooling activity on the same host and account.
- DeviceNetworkEvents for connections to registry.npmjs.org or registry.npmjs.com before and after the publish.
- Identity logs and GitHub audit logs for token use, package publish, or repository changes tied to the account.
- DeviceFileEvents for credential file access or package manifest changes on the host.
- Package registry or internal artifact repository logs to confirm whether the publish was authorized.

Benign explanations:
- A developer may legitimately run npm publish from a workstation during a planned release.
- An approved CI/CD pipeline or release bot may publish packages automatically.
- Semantic-release or similar automation may invoke npm publish as part of normal release workflows.

Escalation criteria:
- The publish originated from a non-build workstation, unexpected account, or unapproved automation context.
- The package name, version, or registry target is not consistent with the owning team’s release process.
- There are signs of credential theft, token abuse, or unauthorized source control changes on the same host or account.
- The publish appears to be republishing a trusted package name with unexpected content or versioning.

Containment actions:
- Suspend the affected npm or source control credentials if unauthorized publishing is confirmed.
- Coordinate with the package owner to halt further publishes and assess whether a malicious version was released.
- Block or quarantine the affected endpoint if it also shows credential theft or other compromise indicators.
- Notify the package registry or internal artifact team to review and, if needed, yank the malicious package version.

Closure criteria:
- The publish is verified as an approved release from a known CI/CD pipeline or authorized developer workflow.
- The package version, registry, and host match documented release procedures and no suspicious follow-on activity exists.
- No credential theft, unauthorized token use, or unexpected source control changes were found.
- The owning team confirms the publish and security records the approved exception or baseline.

---

## Detection 4: Executable Process Spawned from JPEG-Associated Path After WeTransfer Download

### Detection Opportunity

A file downloaded from WeTransfer followed by process execution associated with a JPEG file path, consistent with the Evil MSI campaign delivering a payload embedded in a JPEG image delivered via email link

### Intelligence Context

- SANS ISC: The Evil MSI Background is Back!, (Fri, Jun 5th) — [https://isc.sans.edu/diary/rss/33054](https://isc.sans.edu/diary/rss/33054)
  - Context: The campaign delivered a malicious payload embedded inside a JPEG image file, distributed via a WeTransfer link in a phishing email. The JPEG contained an executable payload that was extracted and run on the victim Windows machine.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1566.002, T1204, T1204.002, T1027
- Products: MSI
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: MSI, Windows, T1566, T1566.002, T1204, T1204.002, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.002 Spearphishing Link (medium); Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Defense Evasion: T1027 Obfuscated Files or Information (low)

### Deployment Gates

- FileOriginUrl is not populated for non-browser download methods; phishing campaigns that use download managers or scripted fetchers will evade this detection.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let WeTransferDownload = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileOriginUrl has "wetransfer.com"
| where FileName has_any (".jpg", ".jpeg", ".zip", ".exe", ".msi")
| project
    DeviceName,
    AccountName,
    DownloadedFile = FileName,
    DownloadPath = FolderPath,
    FileOriginUrl,
    SHA256,
    DownloadTime = Timestamp;
let JpegExecution = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (".jpg", ".jpeg")
    or ProcessCommandLine has_any (".jpg", ".jpeg")
| project
    DeviceName,
    AccountName,
    ExecutedFile = FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ExecTime = Timestamp;
WeTransferDownload
| join kind=inner JpegExecution on DeviceName, AccountName
| where ExecTime >= DownloadTime and datetime_diff('minute', ExecTime, DownloadTime) <= 15
| project
    DownloadTime,
    ExecTime,
    DeviceName,
    AccountName,
    DownloadedFile,
    DownloadPath,
    FileOriginUrl,
    SHA256,
    ExecutedFile,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by DownloadTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Image editing or viewing software that opens JPEG files and spawns helper processes with the JPEG path in the command line.
- Legitimate WeTransfer downloads of JPEG files by designers or content creators followed by normal image processing.
- Software installers that embed JPEG assets and reference them during installation.

Tuning notes:
- Extend the correlation window from 15 to 60 minutes if you want to capture user-initiated execution after download rather than only automated execution.
- Add FolderPath exclusions for known software distribution directories that legitimately reference JPEG files.
- If FPs emerge from image editing software, add InitiatingProcessFileName exclusions for known image viewer or editor binaries.

Risks / caveats:
- FileOriginUrl is only populated for browser-initiated downloads via Edge, Chrome, or Firefox with the Defender for Endpoint browser extension or native integration; downloads via curl, wget, or direct HTTP clients will not populate this field, causing the WeTransfer download leg to return no results for those delivery vectors.
- FileOriginUrl is not populated for non-browser download methods; phishing campaigns that use download managers or scripted fetchers will evade this detection.
- The 15-minute correlation window may miss cases where a user manually opens the downloaded file hours later; extend to 60 minutes if broader coverage is needed at the cost of increased FP rate.
- JPEG-path process execution matching is inherently broad; legitimate image processing workflows may trigger this detection.

### Triage Runbook

First 15 minutes:
- Confirm the download source is actually WeTransfer and identify the downloaded filename, path, and hash if available.
- Review the process command line to see whether execution came from a .jpg or .jpeg path or from an extracted payload near the image file.
- Check whether the user recently received a phishing email or opened a link that led to the download.
- Look for immediate child processes, script execution, or persistence actions after the JPEG-associated execution.
- If the file was executed from a suspicious path or the user did not expect the download, escalate as likely malware execution.

Evidence to collect:
- DownloadTime, ExecTime, DeviceName, AccountName, DownloadedFile, DownloadPath, FileOriginUrl, SHA256, ExecutedFile, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine.
- Email or browser history showing the WeTransfer link source and the user interaction that led to the download.
- Process tree for the executed file and any child processes spawned within 30 minutes.
- Any file writes, registry changes, scheduled tasks, or startup modifications after execution.
- Network connections from the host after the download, including external IPs, URLs, and ports.

Pivot points:
- DeviceFileEvents for the same host to identify additional downloads, extracted files, or renamed payloads.
- DeviceProcessEvents to find child processes, script interpreters, or persistence mechanisms launched after execution.
- DeviceNetworkEvents to identify outbound connections to command-and-control or staging infrastructure.
- Email and browser telemetry, if available, to confirm the phishing delivery path.
- Defender for Endpoint file hash reputation or sandbox results for the downloaded file.

Benign explanations:
- Legitimate WeTransfer downloads of image files by designers, marketers, or content creators.
- Image editing or viewing software may reference JPEG paths while launching helper processes.
- Software installers may embed JPEG assets and reference them during normal installation.

Escalation criteria:
- The downloaded file was executed from a suspicious or hidden path and the user did not expect the file.
- The process tree shows script execution, credential theft, or persistence behavior after the JPEG-associated launch.
- The file hash is unknown, malicious, or associated with phishing campaigns.
- There are outbound connections or additional payloads consistent with malware execution.

Containment actions:
- Isolate the endpoint if the file execution is confirmed malicious or if follow-on compromise is observed.
- Quarantine the downloaded file and any extracted payloads.
- Reset credentials for the affected user if the host may have been used to steal tokens or sessions.
- Block the source URL or related domain if the phishing source is confirmed and still active.

Closure criteria:
- The download and execution are verified as part of a legitimate business workflow with matching file provenance.
- The file hash is benign, no suspicious child processes or persistence were observed, and the user expected the activity.
- The WeTransfer link and resulting file are confirmed by the user or business owner as authorized.
- Security has documented the benign explanation and no further action is required.

---

## Detection 5: External Reconnaissance Scanning for swagger.json and API Documentation Endpoints

### Detection Opportunity

External IP addresses sending HTTP GET requests to swagger.json or common API documentation paths, consistent with ongoing automated reconnaissance scanning observed against web-exposed APIs

### Intelligence Context

- SANS ISC: Continuing Scans for swagger.json, (Wed, Jun 3rd) — [https://isc.sans.edu/diary/rss/33044](https://isc.sans.edu/diary/rss/33044)
  - Context: Ongoing external scanning campaigns are targeting web-exposed APIs by requesting swagger.json and related API documentation endpoints to enumerate API structure, endpoints, and parameters for follow-on exploitation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1595, T1595.002, T1590, T1590.005
- Products: swagger.json
- Platforms: Web applications, APIs
- Malware: Not specified
- Tools: Not specified
- Search tags: swagger.json, Web applications, APIs, T1595, T1595.002, T1590, T1590.005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Reconnaissance: T1595 Active Scanning/ T1595.002 Vulnerability Scanning (medium); Reconnaissance: T1590 Gather Victim Network Information/ T1590.005 IP Addresses (low)

### Deployment Gates

- Field availability in CommonSecurityLog is connector-dependent; RequestURL and RequestMethod must be confirmed as populated for the specific web log source before this query is meaningful.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where isnotempty(SourceIP) and isnotempty(RequestURL)
| where RequestMethod == "GET"
| where RequestURL has_any ("swagger.json", "/api-docs", "/openapi.json", "/swagger-ui", "/swagger/", "/v2/api-docs", "/v3/api-docs")
| where ipv4_is_private(SourceIP) == false
| summarize
    RequestCount = count(),
    DistinctPaths = dcount(RequestURL),
    Paths = make_set(RequestURL, 20),
    UserAgents = make_set(UserAgent, 5),
    DestinationPorts = make_set(DestinationPort, 5),
    Outcomes = make_set(EventOutcome, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, bin(TimeGenerated, 10m)
| extend IsAutomatedScanner = DistinctPaths >= 3
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    RequestCount,
    DistinctPaths,
    IsAutomatedScanner,
    Paths,
    UserAgents,
    DestinationPorts,
    Outcomes
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate API monitoring and uptime checking services that periodically request swagger.json for schema validation.
- Internal security teams running authorized vulnerability scans against web-exposed APIs.
- API client code generators that fetch swagger.json to generate client libraries.

Tuning notes:
- Run a baseline count of CommonSecurityLog with RequestURL and RequestMethod filters before deploying to confirm field population from your specific connector.
- Add SourceIP exclusions for known internal security scanners, API gateway health check IPs, and authorized monitoring services.
- Increase the DistinctPaths threshold from 3 to 5 or higher if legitimate API clients generate FPs by requesting multiple documentation paths.
- If the environment uses non-RFC1918 internal IP ranges, add explicit exclusions for those ranges in addition to the ipv4_is_private() filter.

Risks / caveats:
- CommonSecurityLog field availability (RequestURL, RequestMethod, SourceIP, UserAgent) depends entirely on the specific data connector and log source configured in the Sentinel workspace; these fields may be empty or mapped differently for different appliance vendors.
- ipv4_is_private() does not handle IPv6 addresses or non-RFC1918 internal ranges; if the environment uses IPv6 or non-standard internal subnets, external IP filtering will be incomplete.
- RequestURL may contain only the path component without the hostname depending on the log source, which affects has_any matching for full URL patterns.
- Field availability in CommonSecurityLog is connector-dependent; RequestURL and RequestMethod must be confirmed as populated for the specific web log source before this query is meaningful.

### Triage Runbook

First 15 minutes:
- Confirm the source IP is external and not a known internal scanner, monitoring service, or partner network.
- Review the requested paths and user agent to determine whether the activity is a browser, scanner, or scripted probe.
- Check whether the requests were blocked or successful and whether they targeted multiple documentation endpoints across the same host or site.
- Identify the destination application or API and determine whether it is internet-facing and expected to expose documentation.
- If the source is unknown and the requests are broad or repeated, escalate to the web/app owner for review.

Evidence to collect:
- FirstSeen, LastSeen, SourceIP, RequestCount, DistinctPaths, IsAutomatedScanner, Paths, UserAgents, DestinationPorts, Outcomes.
- RequestURL, RequestMethod, EventOutcome, and any response codes or WAF actions available from the same log source.
- Destination host, application, or API name and whether swagger/openapi documentation is intended to be public.
- Any correlated spikes in 404, 401, 403, or blocked requests from the same source IP.
- Whether the source IP belongs to a known security scanner, uptime monitor, or authorized assessment vendor.

Pivot points:
- CommonSecurityLog for the same SourceIP to find additional paths, ports, or targets probed in the same time window.
- Web server, WAF, or reverse proxy logs to confirm whether requests were blocked, allowed, or rate-limited.
- Threat intelligence or reputation sources for the SourceIP and UserAgent.
- Asset inventory or application owner records to determine whether the target API should expose documentation endpoints.
- If available, firewall or IDS logs to see whether the source IP probed other services beyond the documented API.

Benign explanations:
- Authorized vulnerability scanning by internal security teams or external assessment vendors.
- Legitimate API monitoring or uptime services that request swagger.json for schema validation.
- Developer tools or client generators that fetch openapi/swagger documents during normal use.

Escalation criteria:
- The source IP is unknown, external, and repeatedly probes multiple documentation endpoints or hosts.
- The requests are successful and expose sensitive API structure on an internet-facing service.
- The same source IP is associated with broader scanning or exploitation attempts against other assets.
- The target application owner confirms the activity is not authorized.

Containment actions:
- If the source is malicious and the environment supports it, block the source IP at the WAF, firewall, or reverse proxy.
- Rate-limit or temporarily restrict access to exposed documentation endpoints if they are not required publicly.
- Notify the application owner to review exposure of swagger/openapi documents and remove public access if unnecessary.
- Escalate to threat hunting if the source IP is part of a wider scan campaign against multiple assets.

Closure criteria:
- The source IP is confirmed as an authorized scanner, monitor, or internal tool.
- The target application owner confirms the requests were expected and no sensitive exposure occurred.
- The activity was blocked or rate-limited and no follow-on exploitation was observed.
- Security has documented the benign source and the alert is closed with an approved exception.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.
- External Reconnaissance Scanning for swagger.json and API Documentation Endpoints: Field availability in CommonSecurityLog is connector-dependent; RequestURL and RequestMethod must be confirmed as populated for the specific web log source before this query is meaningful.

Schema / correlation keys:
- Automated npm Publish Outside Expected CI/CD Context - Miasma Worm Propagation: Do not schedule yet; validate as an analyst-led hunt first.

Environment scope / baselines:
- Executable Process Spawned from JPEG-Associated Path After WeTransfer Download: FileOriginUrl is not populated for non-browser download methods; phishing campaigns that use download managers or scripted fetchers will evade this detection.

Shared-table notes:
- DeviceProcessEvents: shared by npm Preinstall Hook Spawning Shell or Network Tool - Miasma Campaign; Automated npm Publish Outside Expected CI/CD Context - Miasma Worm Propagation; Executable Process Spawned from JPEG-Associated Path After WeTransfer Download
- DeviceFileEvents: shared by npm-Spawned Process Accessing Credential Files - Miasma Credential Theft; Executable Process Spawned from JPEG-Associated Path After WeTransfer Download
- DeviceNetworkEvents: shared by npm-Spawned Process Accessing Credential Files - Miasma Credential Theft; Automated npm Publish Outside Expected CI/CD Context - Miasma Worm Propagation

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: npm Preinstall Hook Spawning Shell or Network Tool - Miasma Campaign; Executable Process Spawned from JPEG-Associated Path After WeTransfer Download.
2. Resolve environment-mapping detections next: npm-Spawned Process Accessing Credential Files - Miasma Credential Theft; External Reconnaissance Scanning for swagger.json and API Documentation Endpoints.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Automated npm Publish Outside Expected CI/CD Context - Miasma Worm Propagation.

### Hunting Agenda and Promotion Criteria

- Automated npm Publish Outside Expected CI/CD Context - Miasma Worm Propagation: Do not schedule yet; validate as an analyst-led hunt first..
- npm-Spawned Process Accessing Credential Files - Miasma Credential Theft: File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.; confirm required file-access telemetry exists and produces representative events; prove correlation keys join correctly on real tenant telemetry.
- External Reconnaissance Scanning for swagger.json and API Documentation Endpoints: Field availability in CommonSecurityLog is connector-dependent; RequestURL and RequestMethod must be confirmed as populated for the specific web log source before this query is meaningful.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
