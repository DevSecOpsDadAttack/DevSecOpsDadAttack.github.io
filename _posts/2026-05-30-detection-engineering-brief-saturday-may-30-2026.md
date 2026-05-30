---
layout: post
title: "Detection Engineering Brief - Saturday, May 30, 2026"
subtitle: "Machine-speed threat intelligence translated into detection engineering action."
date: 2026-05-30
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - npm
  - developer environments
  - build environments
  - Storm-2697
  - Windows
  - The Gentlemen
  - CVE-2026-0257
  - T1190
  - PAN-OS
  - GlobalProtect
  - Prisma Access
  - T1071
  - T1071.001
  - T1021
  - T1021.002
  - T1021.001
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: npm, developer environments, build environments, Storm-2697, Windows, The Gentlemen, CVE-2026-0257, T1190, PAN-OS, GlobalProtect, Prisma Access, T1071, T1071.001, T1021, T1021.002, T1021.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: NPM Post-Install Script Spawning System Enumeration Commands; Node.js Outbound Network Connection Following NPM Install in Build Environment; PAN-OS GlobalProtect VPN Session Established Without Prior Authentication Event.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: NPM Post-Install Script Spawning System Enumeration Commands

### Detection Opportunity

Malicious npm packages executing post-install scripts that spawn system enumeration commands to profile developer and build environments

### Intelligence Context

- Microsoft Security Blog: Malicious npm packages abuse dependency confusion to profile developer environments — [https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)
  - Context: A dependency confusion campaign using 33 malicious npm packages executed post-install scripts to collect reconnaissance data including host profiling from developer and build environments.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001
- Products: npm
- Platforms: developer environments, build environments
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, developer environments, build environments, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let EnumerationBinaries = dynamic(["whoami", "whoami.exe", "hostname", "hostname.exe", "printenv", "ifconfig", "ipconfig.exe", "uname", "id", "net.exe"]);
let NpmParents = dynamic(["node.exe", "node", "npm", "npm.cmd"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (NpmParents)
    or InitiatingProcessCommandLine has_any ("npm install", "npm ci", "npm i ")
| where FileName in~ (EnumerationBinaries)
| where not (
    InitiatingProcessCommandLine has_any ("mocha", "jest", "eslint", "node-gyp", "webpack")
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessParentFileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate npm packages with post-install scripts that invoke hostname or env for configuration detection (e.g., cross-env, node-gyp environment checks).
- CI/CD pipeline steps that run npm install followed by environment validation scripts in the same node process tree.
- Developer workstations running npm scripts that include shell commands for local environment setup.

Tuning notes:
- Scope DeviceName to known build agent hostnames or a Defender device group tag to reduce noise from developer workstations.
- Add Yarn (yarn.js, yarn.cmd), pnpm, and Bun process names to NpmParents if those package managers are used in the environment.
- After baselining, consider adding a summarize step to group by DeviceName and FileName to identify repeated patterns before scheduling.

Risks / caveats:
- The 7-day lookback window may produce high result volumes on active developer fleets; consider scoping to known build agent device groups first.
- The npm parent process filter does not distinguish between npm install and npm run, so post-install hooks from npm run scripts will also be captured.
- Environments using Yarn, pnpm, or Bun as package managers will not be covered by this query without adding their process names to NpmParents.
- No threshold or aggregation is applied; this is a raw event hunt requiring analyst review of each result.

### Triage Runbook

First 15 minutes:
- Confirm the host role: developer workstation, CI/build agent, or shared server; if it is a build agent, identify the pipeline/job that was running at the alert time.
- Review the parent and grandparent process chain for node/npm, shell, CI runner, or package manager context and note whether the command line shows an expected install or a suspicious dependency source.
- Inspect the child enumeration command and its command line to see whether it is a normal environment check (for example hostname/env checks) or a broader reconnaissance pattern.
- Check whether the same account or device has repeated npm install activity followed by multiple enumeration commands in a short period.
- If the process tree or package source is unfamiliar, preserve the package name/version and any related build logs before making changes.

Evidence to collect:
- DeviceProcessEvents rows for the alert window showing InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, and ProcessCommandLine.
- The npm package name, version, and install source from build logs, lockfiles, or package manifests if available.
- DeviceName, AccountName, and whether the account is a developer, service account, or CI runner identity.
- Any nearby process events showing archive extraction, script execution, or additional child processes spawned by node/npm.
- FolderPath of the child process to determine whether the binary came from a system path, temp path, or node_modules/.bin.

Pivot points:
- DeviceProcessEvents filtered to the same DeviceName and AccountName for 1 hour before and after the alert to identify the full process tree.
- DeviceProcessEvents for the same package manager parent process to look for repeated enumeration binaries or follow-on scripting.
- CI/CD job logs or build orchestration records for the same timestamp and account.
- Endpoint file inventory or package manager cache locations to identify the installed package and its lifecycle scripts.

Benign explanations:
- Legitimate npm packages may run post-install checks that call hostname, env, whoami, or similar commands to tailor installation behavior.
- CI pipelines often run npm install followed by environment validation or build scripts that invoke the same binaries.
- Developer workstations may execute local setup scripts that enumerate the host as part of configuration or troubleshooting.

Escalation criteria:
- The package source is untrusted, unexpected, or tied to a dependency confusion pattern.
- Enumeration occurs from a package or script that is not part of the approved build process or known tooling baseline.
- The same host shows additional suspicious behavior such as outbound connections, credential access, or file staging shortly after the install.
- The account is a service account or build identity and the activity is not explained by a documented pipeline job.

Containment actions:
- If the package or script is suspicious, stop the build/job and isolate the host from the network if it is a developer workstation or build agent with no active production role.
- Remove or quarantine the malicious package artifact and block the package source or version in the internal registry or dependency controls.
- Reset credentials for any service account or pipeline identity used on the host if there is evidence the environment was exposed beyond simple enumeration.

Closure criteria:
- The activity is matched to a documented build or developer workflow and the package source is trusted.
- No additional suspicious child processes, outbound connections, or file staging are observed around the alert time.
- The package and command line are confirmed to be benign environment checks already present in the approved software baseline.
- Any required allowlist or tuning action is documented for the specific package manager, pipeline, or host group.

---

## Detection 2: Node.js Outbound Network Connection Following NPM Install in Build Environment

### Detection Opportunity

Malicious npm packages exfiltrating collected reconnaissance data via outbound network connections from node.js processes shortly after package installation

### Intelligence Context

- Microsoft Security Blog: Malicious npm packages abuse dependency confusion to profile developer environments — [https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)
  - Context: Malicious npm packages in the dependency confusion campaign collected host reconnaissance data and exfiltrated it over the network from build environments, with node.js processes making outbound connections to external hosts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001
- Products: npm
- Platforms: developer environments, build environments
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, developer environments, build environments, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let NpmInstallEvents = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("npm install", "npm ci", "npm i ")
| project DeviceName, NpmInstallTime = Timestamp, AccountName;
let NodeNetworkEvents = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where RemotePort in (80, 443, 8080, 8443)
| where not (RemoteIP matches regex @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)")
| where not (RemoteUrl has_any ("registry.npmjs.org", "registry.yarnpkg.com", "npmjs.com", "yarnpkg.com", "nodejs.org"))
| project
    DeviceName,
    NetworkTime = Timestamp,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine;
NpmInstallEvents
| join kind=inner NodeNetworkEvents on DeviceName
| where NetworkTime between (NpmInstallTime .. (NpmInstallTime + 5m))
| project
    DeviceName,
    AccountName,
    NpmInstallTime,
    NetworkTime,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by NpmInstallTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Node.js packages that legitimately phone home to telemetry or analytics endpoints during post-install (e.g., Sentry, Datadog, Segment SDKs).
- npm install triggering automatic update checks or license validation against external APIs.
- CI/CD pipelines that run npm install and then immediately execute integration tests that make outbound HTTP calls.
- Package managers fetching assets from CDN endpoints not covered by the registry exclusion list.

Tuning notes:
- Add organization-specific private registry and artifact repository domains to the RemoteUrl exclusion list.
- Scope DeviceName to known build agent device groups to reduce developer workstation noise.
- Consider extending the time window from 5m to 10m if post-install scripts in the environment have observed execution latency beyond 5 minutes.
- After baselining, aggregate by RemoteIP to identify repeated external destinations across multiple devices as a higher-confidence signal.

Risks / caveats:
- RemoteUrl is not always populated in DeviceNetworkEvents; DNS-based exfiltration or connections to bare IPs will only appear in RemoteIP. Detections relying solely on RemoteUrl exclusions may miss connections where RemoteUrl is empty.
- The 5-minute correlation window may miss post-install scripts that execute asynchronously or after a delay longer than 5 minutes.
- RemoteUrl may be empty for connections to bare IP addresses, causing the registry exclusion to be ineffective for those rows.
- Organization-specific internal package registries, artifact repositories (e.g., Artifactory, Nexus, Azure Artifacts), and CDN endpoints used for asset delivery are not excluded and will generate false positives until added.

### Triage Runbook

First 15 minutes:
- Confirm whether the destination is a known registry, CDN, telemetry endpoint, artifact repository, or an unknown external host.
- Correlate the network event to the preceding npm install on the same device and account; verify the timing and whether the node process is the expected child of the install.
- Review the remote IP, URL, and port to determine whether the traffic is normal HTTPS package retrieval or an unusual outbound connection to a non-business destination.
- Check whether the host is a build agent or developer workstation and whether the same pipeline/job normally makes outbound web requests at this stage.
- If the destination is unfamiliar, capture the process command line and any nearby file or script activity before the process exits.

Evidence to collect:
- DeviceNetworkEvents rows for the alert window including RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, and InitiatingProcessCommandLine.
- DeviceProcessEvents rows showing the npm install event, the node process start, and any child processes spawned after install.
- DeviceName, AccountName, and whether the account maps to a CI runner, service account, or interactive user.
- Any proxy, firewall, or DNS logs that show the full destination and whether the connection was allowed, blocked, or retried.
- Build logs or package manager logs that identify the package being installed and any post-install scripts executed.

Pivot points:
- DeviceNetworkEvents for the same DeviceName and AccountName within 30 minutes to identify other external destinations or repeated connections.
- DeviceProcessEvents for node.exe and npm on the same host to reconstruct the process tree around the install.
- Proxy or secure web gateway logs to determine whether the destination is a known business service or a suspicious external endpoint.
- DNS logs for the same host to see whether the RemoteUrl was resolved from a domain not visible in the alert.

Benign explanations:
- Legitimate packages may phone home for telemetry, license validation, update checks, or asset retrieval during install.
- CI/CD jobs often make outbound HTTP/HTTPS calls during dependency installation, integration tests, or artifact downloads.
- Package managers may contact CDNs or private artifact repositories that are not fully covered by the exclusion list.

Escalation criteria:
- The destination is not a known registry, artifact repository, CDN, or approved telemetry endpoint.
- The connection occurs immediately after a suspicious package install and is paired with prior host enumeration or file staging.
- Multiple hosts or multiple accounts show the same destination, suggesting a common malicious package or infrastructure.
- The host is a production-adjacent build system and the traffic cannot be explained by the documented pipeline.

Containment actions:
- If the destination is suspicious and the host is a build agent or developer workstation, isolate the host from the network pending validation.
- Block the remote IP/domain at proxy or firewall controls if it is confirmed malicious or clearly unauthorized.
- Quarantine the package artifact and halt the pipeline or deployment job until the package source is verified.

Closure criteria:
- The destination is confirmed as an approved registry, CDN, artifact repository, or telemetry service used by the environment.
- The network activity is tied to a documented build step or package post-install behavior with no other suspicious indicators.
- No evidence of data staging, unusual child processes, or repeated external connections is found.
- Any missing allowlist entries are added to reduce future noise.

---

## Detection 3: Mass File Rename or Overwrite Activity Consistent with Gentlemen Ransomware Encryption

### Detection Opportunity

Go-based ransomware performing high-volume file encryption by creating or modifying large numbers of files with changed extensions across multiple directories in rapid succession

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware, attributed to Storm-2697, is a Go-compiled encryptor that uses per-file ephemeral key encryption and performs high-volume file modification across directories as part of its encryption routine on Windows hosts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1021, T1021.002, T1021.001
- Products: Not specified
- Platforms: Windows
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, Windows, The Gentlemen, T1021, T1021.002, T1021.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
let ExcludedProcesses = dynamic(["MsMpEng.exe", "svchost.exe", "TiWorker.exe", "SearchIndexer.exe", "OneDrive.exe", "Dropbox.exe", "veeam", "BackupExec.exe", "robocopy.exe", "xcopy.exe"]);
let ExcludedFolderPrefixes = dynamic(["C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Windows\\WinSxS", "C:\\Windows\\servicing"]);
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed", "FileCreated", "FileModified")
| where not (InitiatingProcessFileName in~ (ExcludedProcesses))
| where not (FolderPath has_any (ExcludedFolderPrefixes))
| summarize
    FileCount = count(),
    UniqueFolders = dcount(FolderPath),
    SampleFiles = make_set(FileName, 10),
    InitiatingProcess = any(InitiatingProcessFileName),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath),
    InitiatingCmdLine = any(InitiatingProcessCommandLine),
    AccountName = any(AccountName)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 2m)
| where FileCount >= 100 and UniqueFolders >= 5
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcess,
    InitiatingProcessFolderPath,
    InitiatingCmdLine,
    FileCount,
    UniqueFolders,
    SampleFiles
| order by FileCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Backup agents (Veeam, Acronis, BackupExec) performing scheduled backup jobs that touch many files across directories.
- File synchronization tools (OneDrive, Dropbox, SharePoint sync) performing initial sync or large batch uploads.
- Antivirus or EDR remediation tools performing bulk file quarantine or restoration.
- Software deployment tools (SCCM, Intune) performing mass file extraction during application installation.

Tuning notes:
- Add environment-specific backup agent process names to ExcludedProcesses after baselining.
- Reduce the bin window from 2m to 1m for higher-sensitivity detection at the cost of increased alert volume.
- Consider adding a secondary condition filtering on InitiatingProcessFolderPath containing Temp, AppData, or ProgramData to increase precision for malware dropped to staging directories.
- Correlate alerts with DeviceNetworkEvents on the same host within the same time window to identify concurrent lateral movement as a high-confidence ransomware indicator.

Risks / caveats:
- ActionType value 'FileModified' may not be consistently populated in all Defender for Endpoint sensor configurations or OS versions; 'FileRenamed' and 'FileCreated' are more reliably captured. Validate ActionType coverage in the environment before relying on FileModified counts.
- The 1-day lookback window is appropriate for a scheduled rule but may miss slow-burn encryption that stays below the per-2-minute threshold by spreading activity over longer periods.
- The FileCount threshold of 100 and UniqueFolders threshold of 5 are baseline values; environments with active backup or sync agents not covered by the exclusion list will require threshold increases.
- FileModified ActionType availability varies by sensor configuration; if not collected, the FileCount will be lower than actual encryption activity, potentially causing misses at the threshold boundary.

### Triage Runbook

First 15 minutes:
- Treat the alert as a potential active ransomware event and immediately verify whether the initiating process is known and expected on this host.
- Check the initiating process path and command line for unusual locations such as temp, AppData, or ProgramData, and look for signs of a dropped or renamed binary.
- Review the sample files and affected folders to see whether user data, shared drives, or business-critical directories are being modified.
- Identify whether the account is a normal user, service account, backup account, or deployment account and whether it should be performing bulk file changes.
- Look for concurrent signs of ransomware such as shadow copy deletion, service stoppage, or rapid file extension changes on the same device.

Evidence to collect:
- DeviceFileEvents rows for the alert window including ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, and InitiatingProcessFolderPath.
- The list of sample files and affected directories to determine whether the activity spans user data, network shares, or system paths.
- DeviceName and AccountName, plus whether the process is running from a temporary or unusual folder.
- Any nearby events showing deletion of backups, creation of ransom-note-like files, or disabling of security tools.
- If available, related DeviceNetworkEvents or DeviceProcessEvents showing lateral movement or command-and-control activity from the same host.

Pivot points:
- DeviceFileEvents on the same host for 24 hours to identify the start of the file modification pattern and any preceding dropper activity.
- DeviceProcessEvents for the initiating process to identify parent process, command line, and any child processes.
- DeviceNetworkEvents for the same host and time window to look for outbound connections or lateral movement.
- Security/backup platform logs to confirm whether a scheduled backup, sync, or deployment job was running.

Benign explanations:
- Backup agents, file sync tools, or deployment systems can legitimately touch many files across multiple directories.
- Antivirus or EDR remediation can generate bulk file modifications when quarantining or restoring files.
- Large software installs or patching jobs may create or overwrite many files in a short period.

Escalation criteria:
- The initiating process is unknown, unsigned, or running from an unusual directory.
- File changes span many user or shared data directories and are accompanied by extension changes or ransom-note artifacts.
- There are additional indicators of ransomware such as shadow copy deletion, service tampering, or lateral movement.
- The host is a server or critical workstation and the activity is not clearly attributable to a scheduled backup or deployment job.

Containment actions:
- Immediately isolate the host from the network if encryption appears active or the process is still running.
- Terminate the suspicious process only if doing so will not destroy evidence needed for response and after isolation is in place.
- Disable or reset the affected account if it is a user or service account being abused, and coordinate with incident response for broader containment.
- Preserve volatile evidence and notify backup owners to protect recovery points.

Closure criteria:
- The activity is confirmed as a legitimate backup, sync, remediation, or deployment process with matching change records.
- No evidence of malicious process origin, ransom artifacts, shadow copy deletion, or lateral movement is found.
- The file modification pattern is consistent with the approved baseline for that host role.
- Any required allowlist or threshold tuning is documented for the specific backup or deployment tooling.

---

## Detection 4: Simultaneous Lateral Movement to Multiple Internal Hosts Consistent with Gentlemen Ransomware Self-Propagation

### Detection Opportunity

Self-propagating Go-compiled ransomware initiating simultaneous SMB or RPC connections to multiple internal hosts from a single source within a short time window as part of its network propagation module

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware includes an aggressive self-propagation module that deploys itself across an entire network using simultaneous lateral movement techniques per target, making rapid multi-host SMB or RPC fan-out a key behavioral indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1021, T1021.002, T1021.001
- Products: Not specified
- Platforms: Windows
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, Windows, The Gentlemen, T1021, T1021.002, T1021.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (low)

### Deployment Gates

- ActionType 'ConnectionSuccess' availability depends on Defender for Endpoint sensor version and network event collection configuration; if not available, remove the ActionType filter and accept increased noise from failed connection attempts.

Required telemetry:
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (445, 135, 139)
| where ActionType == "ConnectionSuccess"
| where RemoteIP matches regex @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
| summarize
    UniqueTargets = dcount(RemoteIP),
    TargetIPs = make_set(RemoteIP, 20),
    InitiatingProcess = any(InitiatingProcessFileName),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath),
    InitiatingCmdLine = any(InitiatingProcessCommandLine),
    AccountName = any(AccountName)
    by DeviceName, bin(Timestamp, 5m)
| where UniqueTargets >= 15
| project
    Timestamp,
    DeviceName,
    AccountName,
    UniqueTargets,
    TargetIPs,
    InitiatingProcess,
    InitiatingProcessFolderPath,
    InitiatingCmdLine
| order by UniqueTargets desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Domain controllers performing Kerberos ticket validation or replication to multiple DCs simultaneously.
- SCCM or Intune management servers pushing software deployments to many endpoints concurrently.
- Vulnerability scanners (Nessus, Qualys, Rapid7) performing authenticated SMB scans.
- Network monitoring tools performing SMB availability checks across the environment.

Tuning notes:
- Raise the UniqueTargets threshold to 25 or 30 if domain controllers or SCCM servers cannot be excluded by device group and generate false positives.
- Add a DeviceName exclusion list for known network scanners, domain controllers, and patch management servers after baselining.
- Correlate alerts with the mass file encryption detection on the same DeviceName within the same time window to create a high-confidence ransomware composite alert.
- If ActionType is not populated in the environment, remove the ActionType filter and compensate by raising the UniqueTargets threshold.

Risks / caveats:
- ActionType 'ConnectionSuccess' availability depends on Defender for Endpoint sensor version and network event collection configuration; if not available, remove the ActionType filter and accept increased noise from failed connection attempts.
- Domain controllers, SCCM servers, and vulnerability scanners will generate false positives at this threshold and should be excluded by DeviceName or device group after baselining.
- The 5-minute bin window may split a rapid fan-out event across two bins if it straddles a bin boundary, potentially causing a miss if the per-bin count falls below 15.
- The regex does not cover IPv6 private ranges (fc00::/7); environments with IPv6 lateral movement will not be detected.

### Triage Runbook

First 15 minutes:
- Assume possible active lateral movement and identify the source host, initiating process, and account immediately.
- Check whether the source host is a domain controller, management server, scanner, or patching system that would normally contact many hosts.
- Review the target IP set to see whether the connections are broad across the environment or limited to a known management segment.
- Correlate the timing with any file encryption, service creation, or suspicious process execution on the same source host.
- If the source is not a known admin or scanner system, escalate as a likely propagation event and begin containment.

Evidence to collect:
- DeviceNetworkEvents rows for the alert window including RemoteIP, RemotePort, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, and InitiatingProcessFolderPath.
- The set of target IPs and whether they are workstations, servers, or domain controllers.
- DeviceName and AccountName for the source host and whether the account is privileged or service-based.
- Any related DeviceProcessEvents showing the initiating process start, parent process, and command line.
- Any concurrent file encryption or service creation events on the source host.

Pivot points:
- DeviceNetworkEvents for the source host over 24 hours to identify additional internal targets and repeated SMB/RPC fan-out.
- DeviceProcessEvents for the source host to identify the binary path and any suspicious parent process.
- DeviceFileEvents on the same host to check for mass file changes that would support ransomware activity.
- Directory service, SCCM, vulnerability scanner, or patch management logs to validate whether the source is an approved management system.

Benign explanations:
- Domain controllers, SCCM servers, and patch management systems can legitimately contact many internal hosts in a short period.
- Vulnerability scanners and monitoring tools may generate broad SMB/RPC traffic during authenticated scans or availability checks.
- Administrative scripts can fan out to multiple hosts for software deployment or inventory collection.

Escalation criteria:
- The source host is not a known management, scanning, or administrative system.
- The fan-out is accompanied by file encryption, service tampering, or suspicious process execution on the same host.
- The initiating process is running from an unusual path or under a non-administrative account.
- Multiple hosts show the same pattern from the same source or account, indicating active propagation.

Containment actions:
- Isolate the source host from the network immediately if the activity is not clearly benign.
- Disable the source account or revoke its credentials if it is being used for unauthorized propagation.
- Block SMB/RPC traffic from the source host at network controls if isolation is delayed or not possible.
- Coordinate with incident response to check for additional compromised hosts and preserve evidence.

Closure criteria:
- The source is confirmed as an approved scanner, patching server, or management system with matching change records.
- The initiating process and account align with documented administrative activity and no encryption or tampering is present.
- The target set is consistent with the expected scope of the tool or job.
- Any necessary device-group exclusions or threshold tuning are documented.

---

## Detection 5: PAN-OS GlobalProtect VPN Session Established Without Prior Authentication Event

### Detection Opportunity

Unauthenticated VPN connection established through a GlobalProtect gateway by exploiting CVE-2026-0257, resulting in a VPN session without a corresponding successful credential validation log entry

### Intelligence Context

- Rapid7: Rapid7 Observed Exploitation of PAN-OS GlobalProtect Authentication Bypass Vulnerability (CVE-2026-0257) — [https://www.rapid7.com/blog/post/etr-rapid7-observed-exploitation-of-pan-os-globalprotect-authentication-bypass-vulnerability-cve-2026-0257](https://www.rapid7.com/blog/post/etr-rapid7-observed-exploitation-of-pan-os-globalprotect-authentication-bypass-vulnerability-cve-2026-0257)
  - Context: CVE-2026-0257 allows a remote unauthenticated attacker to establish a VPN connection through the GlobalProtect gateway of an affected PAN-OS appliance without valid credentials, bypassing the authentication step entirely.

### Search Metadata

- CVEs: CVE-2026-0257
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: PAN-OS, GlobalProtect, Prisma Access
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-0257, T1190, PAN-OS, GlobalProtect, Prisma Access

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let LookbackWindow = 7d;
let AuthWindowMinutes = 5m;
let AuthEvents = CommonSecurityLog
| where TimeGenerated > ago(LookbackWindow)
| where DeviceVendor == "Palo Alto Networks"
| where DeviceProduct has "GlobalProtect"
| where Activity has_any ("login", "auth-success", "authenticated", "prelogin")
| where DeviceAction !in~ ("failure", "failed", "denied")
| summarize LastAuthTime = max(TimeGenerated) by SourceIP;
let SessionEvents = CommonSecurityLog
| where TimeGenerated > ago(LookbackWindow)
| where DeviceVendor == "Palo Alto Networks"
| where DeviceProduct has "GlobalProtect"
| where Activity has_any ("connected", "tunnel-established", "gateway-connected", "session-start")
| project
    SessionTime = TimeGenerated,
    SourceIP,
    DestinationIP,
    Activity,
    DeviceAction,
    Message,
    LogSeverity;
SessionEvents
| join kind=leftouter AuthEvents on SourceIP
| where isnull(LastAuthTime) or LastAuthTime < (SessionTime - AuthWindowMinutes)
| project
    SessionTime,
    SourceIP,
    DestinationIP,
    Activity,
    DeviceAction,
    Message,
    LogSeverity,
    LastAuthTime
| order by SessionTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- VPN reconnections where the authentication event was logged more than 5 minutes before the session-established event due to session resumption or token-based re-authentication.
- Certificate-based or SAML-based authentication flows where the authentication event may be logged under a different Activity string not covered by the current filter.
- Log ingestion delays causing authentication events to arrive in Sentinel after the session events, making the time-bounded anti-join incorrectly flag legitimate sessions.

Tuning notes:
- Run each subquery independently against recent CommonSecurityLog data to confirm Activity field values match the strings used in the query before deploying.
- Extend AuthWindowMinutes from 5m to 15m or 30m if session resumption or token-based re-authentication in the environment causes legitimate sessions to appear without a recent auth event.
- Add additional Activity strings observed in the environment's PAN-OS logs to both the AuthEvents and SessionEvents filters after validating log field values.
- For Prisma Access environments, validate the DeviceProduct string value and update the filter accordingly.

Risks / caveats:
- The Activity field values for GlobalProtect authentication and session events vary across PAN-OS firmware versions and log profile configurations. The strings used in this query ('login', 'auth-success', 'authenticated', 'prelogin', 'connected', 'tunnel-established', 'gateway-connected', 'session-start') must be validated against actual ingested log data before this query will produce meaningful results.
- CommonSecurityLog ingestion of PAN-OS GlobalProtect logs requires a configured CEF/Syslog connector with the GlobalProtect log type enabled in the PAN-OS log forwarding profile. If GlobalProtect logs are not forwarded as a distinct log type, both AuthEvents and SessionEvents subqueries will return empty results.
- The leftanti join on SourceIP alone without a time window in the original query would exclude any SourceIP that had ever authenticated in the 7-day window, not just within 5 minutes before the session event. The improved query implements a time-bounded approach using a summarize-based anti-join to correctly scope the 5-minute window.
- Activity field string values must be validated against actual PAN-OS GlobalProtect logs ingested into CommonSecurityLog for the specific firmware version deployed before this query will produce accurate results.

### Triage Runbook

First 15 minutes:
- Validate that the source IP, destination IP, and session time correspond to a real GlobalProtect session and not a duplicate or delayed log entry.
- Check whether the same source IP has any authentication, prelogin, or failed login events in the preceding minutes and whether log ingestion delay could explain the gap.
- Confirm the PAN-OS and GlobalProtect log format in CommonSecurityLog for this device to ensure the Activity values used by the detection are present and accurate.
- Review the session details for unusual geography, source network, or user context if any is present in the message field.
- If the session is truly unauthenticated and the device is internet-facing, escalate immediately as a likely exploitation event.

Evidence to collect:
- CommonSecurityLog rows for the source IP and destination IP covering at least 30 minutes before and after the session event, including Activity, DeviceAction, Message, and LogSeverity.
- Any authentication, prelogin, or failed login events from the same source IP in the same time window.
- PAN-OS or GlobalProtect logs outside Sentinel, if available, to validate whether the session was established without a corresponding auth event.
- Firewall or VPN access logs showing whether the session was allowed, denied, or reconnected.
- If available, user or certificate context from the message field to determine whether the session was tied to a known identity.

Pivot points:
- CommonSecurityLog for the same source IP across the last 24 hours to identify repeated unauthenticated sessions or other suspicious activity.
- Firewall logs or PAN-OS management logs to confirm the exact session and authentication sequence.
- Identity logs for the same user or certificate if the environment uses SAML, MFA, or certificate-based VPN authentication.
- Threat intelligence or perimeter logs to see whether the source IP is associated with scanning or exploitation activity.

Benign explanations:
- Log ingestion delays can cause the authentication event to arrive after the session event in Sentinel.
- Some certificate-based, SAML, or token-based flows may log authentication under different Activity strings than the detection expects.
- Session resumption or reconnect behavior can produce a session event without a fresh authentication event within the 5-minute window.

Escalation criteria:
- The session is confirmed in native PAN-OS logs with no corresponding authentication event and the source is external or untrusted.
- Multiple unauthenticated sessions are observed from the same source IP or across multiple source IPs.
- There are signs of follow-on activity from the VPN session such as internal scanning, new logins, or lateral movement.
- The device is internet-facing and the PAN-OS version is known or suspected to be affected by CVE-2026-0257.

Containment actions:
- Block the source IP at the perimeter if it is clearly malicious and the session is active or repeatable.
- Disable or restrict the affected GlobalProtect gateway or vulnerable interface if exploitation is confirmed and emergency change procedures allow it.
- Apply vendor guidance for CVE-2026-0257 mitigation and coordinate immediate patching or configuration changes.
- Preserve logs and session evidence for incident response and legal/forensic review.

Closure criteria:
- Native PAN-OS logs confirm the session was preceded by a valid authentication event or a documented alternate auth flow.
- The alert is explained by log delay, session resumption, or a validated Activity mapping issue in the environment.
- No additional suspicious activity follows the session and the source IP is tied to a legitimate user or test system.
- The detection is tuned with validated Activity strings and any environment-specific exclusions needed to reduce false positives.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- NPM Post-Install Script Spawning System Enumeration Commands: Do not schedule yet; validate as an analyst-led hunt first.
- Node.js Outbound Network Connection Following NPM Install in Build Environment: Do not schedule yet; validate as an analyst-led hunt first.

Other deployment dependency:
- Simultaneous Lateral Movement to Multiple Internal Hosts Consistent with Gentlemen Ransomware Self-Propagation: ActionType 'ConnectionSuccess' availability depends on Defender for Endpoint sensor version and network event collection configuration; if not available, remove the ActionType filter and accept increased noise from failed connection attempts.

Telemetry availability:
- PAN-OS GlobalProtect VPN Session Established Without Prior Authentication Event: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

Shared-table notes:
- DeviceProcessEvents: shared by NPM Post-Install Script Spawning System Enumeration Commands; Node.js Outbound Network Connection Following NPM Install in Build Environment
- DeviceNetworkEvents: shared by Node.js Outbound Network Connection Following NPM Install in Build Environment; Simultaneous Lateral Movement to Multiple Internal Hosts Consistent with Gentlemen Ransomware Self-Propagation

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Mass File Rename or Overwrite Activity Consistent with Gentlemen Ransomware Encryption; Simultaneous Lateral Movement to Multiple Internal Hosts Consistent with Gentlemen Ransomware Self-Propagation.
2. Resolve environment-mapping detections next: PAN-OS GlobalProtect VPN Session Established Without Prior Authentication Event.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: NPM Post-Install Script Spawning System Enumeration Commands; Node.js Outbound Network Connection Following NPM Install in Build Environment.

### Hunting Agenda and Promotion Criteria

- NPM Post-Install Script Spawning System Enumeration Commands: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Node.js Outbound Network Connection Following NPM Install in Build Environment: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- PAN-OS GlobalProtect VPN Session Established Without Prior Authentication Event: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
