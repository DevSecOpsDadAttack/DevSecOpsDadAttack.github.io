---
layout: post
title: "Detection Engineering Brief - Wednesday, June 3, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-03
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - npm
  - CI/CD environments
  - developer systems
  - cloud platforms
  - GitHub
  - macOS
  - FlutterShell
  - T1552
  - T1552.001
  - T1053
  - T1053.003
  - T1547
  - T1547.001
  - T1543
  - T1543.001
  - T1547.013
---

## Executive Signal

This brief produced 5 detection candidates.

3 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: npm, CI/CD environments, developer systems, cloud platforms, GitHub, macOS, FlutterShell, T1552, T1552.001, T1053, T1053.003, T1547, T1547.001, T1543, T1543.001, T1547.013.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: npm-Spawned Process Accessing Credential Files; Flutter-Built Binary Executing from Non-Standard Path with Outbound Network Connection on macOS.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: npm Preinstall Hook Spawning Shell Interpreter

### Detection Opportunity

Malicious npm preinstall lifecycle hook spawning a shell interpreter during package installation as part of the Red Hat npm Miasma supply chain attack

### Intelligence Context

- Microsoft Security Blog: Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — [https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
  - Context: Over 90 versions of @redhat-cloud-services npm packages were compromised. Malicious code was injected into preinstall lifecycle hooks, causing shell interpreters to execute during npm install operations on developer and CI/CD systems.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001
- Products: npm
- Platforms: CI/CD environments, developer systems, cloud platforms
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, CI/CD environments, developer systems, cloud platforms, GitHub, T1552, T1552.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("node", "npm", "npm.cmd", "node.exe")
| where FileName in~ ("sh", "bash", "zsh", "dash", "cmd.exe", "powershell.exe", "pwsh", "python", "python3", "perl", "ruby")
| where InitiatingProcessCommandLine has_any ("install", "ci", "preinstall", "postinstall", "prepare")
| where ProcessCommandLine has_any ("base64", "curl", "wget", "/tmp/", "/var/tmp/")
    or (ProcessCommandLine has "-c " and ProcessCommandLine has_any ("eval", "exec", "chmod"))
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessParentFileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Build scripts that legitimately invoke curl or wget inside npm lifecycle hooks to download build dependencies.
- Developer environments where npm postinstall scripts run shell commands with base64-encoded arguments for legitimate configuration.
- CI/CD pipelines that use /tmp/ as a scratch space during npm install steps.

Tuning notes:
- After initial deployment, collect a 7-day baseline of legitimate npm lifecycle child process patterns and add AccountName or DeviceName exclusions for known CI service accounts.
- If python/python3 spawning is common in your build environment, remove them from the FileName list and create a separate, more targeted rule for Python-specific indicators.
- Consider adding InitiatingProcessParentFileName not in~ ("jenkins", "gitlab-runner", "buildkite-agent") only after confirming those orchestrators do not themselves spawn npm in a way that masks malicious activity.

Risks / caveats:
- On Linux CI/CD agents, Defender for Endpoint must be deployed and the process telemetry sensor must be active; without it DeviceProcessEvents will have no Linux rows and the rule will produce no results for that OS.
- Legitimate npm postinstall scripts that download build artifacts via curl will generate FPs; allowlisting by AccountName or DeviceName for known CI service accounts is recommended after baselining.
- The 1-day lookback window may miss slow-burn supply chain compromises; consider extending to 7 days for periodic hunting runs.
- python and python3 as child processes may generate FPs in environments where npm scripts invoke Python build tools; consider removing them from FileName filter if noise is high.

### Triage Runbook

First 15 minutes:
- Confirm the parent/child process chain: npm or node spawning sh, bash, zsh, cmd.exe, powershell.exe, python, perl, or ruby during install/preinstall/postinstall/prepare.
- Review the full command line for high-risk indicators such as base64, curl, wget, /tmp/, /var/tmp/, -c, eval, exec, or chmod combined with lifecycle keywords.
- Identify the affected device and account, then determine whether it is a developer workstation, CI/CD agent, or cloud build host and whether the activity aligns with an expected build job.
- Check whether the package name/version in the install context matches the Red Hat npm Miasma campaign or any recently introduced dependency change.
- Look for immediate follow-on activity from the same process tree, especially credential file access, outbound connections, or persistence writes.

Evidence to collect:
- DeviceProcessEvents for the full process tree, including InitiatingProcessParentFileName, InitiatingProcessCommandLine, SHA256, and InitiatingProcessSHA256.
- The exact npm package name, version, and install command used on the host.
- AccountName, DeviceName, timestamp, and whether the process ran under a CI service account or a human developer account.
- Any related DeviceFileEvents showing access to .npmrc, .gitconfig, cloud CLI token stores, or SSH keys.
- Any DeviceNetworkEvents from the same process tree showing outbound connections immediately after the shell spawn.

Pivot points:
- DeviceProcessEvents for the same DeviceName and AccountName within the last 24 hours to find other npm lifecycle executions.
- DeviceFileEvents for the same host/account to look for credential file access or persistence writes.
- DeviceNetworkEvents filtered to the same initiating process family and time window to identify exfiltration or C2-like traffic.
- If available, pivot on SHA256 and InitiatingProcessSHA256 to determine whether the binary or script has appeared elsewhere in the tenant.

Benign explanations:
- A legitimate build script uses npm lifecycle hooks to run shell commands for dependency installation or environment setup.
- A CI pipeline downloads build artifacts with curl or wget during npm install steps.
- A developer package uses base64-encoded arguments or temporary directories as part of a normal postinstall routine.

Escalation criteria:
- The shell command accesses credential files, token stores, or SSH keys.
- The process makes outbound connections to non-registry destinations or unusual ports immediately after install.
- The same host shows persistence writes, additional suspicious child processes, or evidence of credential theft.
- The package/version is unexpected, newly introduced, or matches known compromised package names from the campaign.

Containment actions:
- Disable or quarantine the affected package version in the package manager or internal registry if the package is confirmed malicious.
- Isolate the affected developer or CI host if credential theft or additional malicious activity is observed.
- Revoke and rotate any credentials that may have been exposed on the host, including npm, GitHub, cloud CLI, and SSH credentials.

Closure criteria:
- The package/version is verified as legitimate and the command line matches an approved build script pattern.
- No credential access, outbound exfiltration, or persistence activity is found in the surrounding process tree.
- The event is attributable to a known CI service account or approved automation and is added to the local allowlist or tuning list after review.

---

## Detection 2: npm-Spawned Process Accessing Credential Files

### Detection Opportunity

npm or node child processes accessing known credential store files such as .npmrc, .gitconfig, or cloud CLI token files as part of the Miasma credential-stealing campaign

### Intelligence Context

- Microsoft Security Blog: Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — [https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
  - Context: The malicious npm packages stole credentials from GitHub, cloud platforms, and local machines. The attack targeted credential files accessible during npm install execution, including .npmrc, .gitconfig, and cloud CLI token stores.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001
- Products: npm, GitHub
- Platforms: CI/CD environments, developer systems, cloud platforms
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, GitHub, CI/CD environments, developer systems, cloud platforms, T1552, T1552.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let CredentialFileAccess = DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRead", "FileAccessed", "FileCreated")
| where FileName in~ (".npmrc", ".gitconfig", ".git-credentials", "credentials", "config", "token", "access_token", "id_rsa", "id_ed25519")
    or FolderPath has_any (".aws", ".azure", ".config/gcloud", ".kube", ".ssh", ".npmrc", ".gitconfig", "AppData\\Roaming\\npm")
| where InitiatingProcessFileName in~ ("node", "node.exe", "npm", "npm.cmd", "sh", "bash", "zsh", "python", "python3")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine, FileName, FolderPath;
let OutboundAfterAccess = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("node", "node.exe", "npm", "npm.cmd", "sh", "bash", "zsh", "python", "python3")
| where not (RemoteIP startswith "10."
    or RemoteIP startswith "192.168."
    or (RemoteIP startswith "172." and split(RemoteIP, ".")[1] >= "16" and split(RemoteIP, ".")[1] <= "31")
    or RemoteIP == "127.0.0.1"
    or RemoteIP == "::1")
| where not (RemoteUrl has "registry.npmjs.org" or RemoteUrl has "registry.yarnpkg.com")
| project NetTimestamp = Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort;
CredentialFileAccess
| join kind=inner OutboundAfterAccess on DeviceName, AccountName
| where NetTimestamp between (Timestamp .. (Timestamp + 5m))
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    FileName,
    FolderPath,
    RemoteIP,
    RemoteUrl,
    RemotePort
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- npm install reading .npmrc for registry authentication and then connecting to registry.npmjs.org or a private registry over HTTPS.
- Cloud CLI tools (aws, az, gcloud) invoked by npm scripts reading their own credential files before making API calls.
- Git operations triggered by npm prepare scripts reading .gitconfig before connecting to GitHub or GitLab.

Tuning notes:
- After running as a hunting query, identify the RemoteUrl values that appear most frequently and add legitimate registries and CDNs to the exclusion list.
- If the environment uses a private npm registry, add its hostname to the RemoteUrl exclusion to eliminate the largest FP source.
- Consider promoting to a scheduled rule only after the FP rate from legitimate npm registry calls has been reduced to near zero through RemoteUrl exclusions.

Risks / caveats:
- FileRead and FileAccessed ActionType values in DeviceFileEvents are not guaranteed to be populated on all OS versions or sensor configurations; on some Linux agent versions only FileCreated and FileModified are reliably emitted, which would cause the credential file access leg of the join to return no rows.
- RemoteUrl is not always populated in DeviceNetworkEvents depending on the protocol and sensor version; queries relying on it for exfiltration context may silently miss events.
- FileRead and FileAccessed ActionType availability must be confirmed in the target tenant before relying on this query; if absent, only FileCreated fallback will fire and coverage will be reduced.
- The npm registry exclusion by RemoteUrl may not cover private or enterprise npm registries; add those registry hostnames to the exclusion list after identifying them in the environment.

### Triage Runbook

First 15 minutes:
- Validate that the file access came from npm, node, or a shell child process during an install lifecycle event.
- Inspect the accessed file path and name to determine whether it is a high-value secret source such as .npmrc, .gitconfig, .git-credentials, AWS/Azure/GCP config, .ssh keys, or cloud token files.
- Check the timing of the file access against outbound network activity from the same device and account within the 5-minute correlation window.
- Determine whether the host is a CI/CD agent, developer system, or cloud platform node and whether the access is expected for that workflow.
- Look for evidence that the same process tree also spawned a shell interpreter, wrote persistence files, or accessed multiple credential locations.

Evidence to collect:
- DeviceFileEvents showing the exact FileName, FolderPath, ActionType, and InitiatingProcessFileName/CommandLine for the credential access.
- DeviceNetworkEvents from the same DeviceName and AccountName around the access time, including RemoteIP, RemoteUrl, and RemotePort.
- DeviceProcessEvents for the full process tree, including parent process names and SHA256 values.
- Any additional file reads from adjacent credential stores or secret locations on the same host.
- Package install context: npm package name/version, install command, and whether the activity occurred in a pipeline or interactive session.

Pivot points:
- DeviceFileEvents on the same host/account for other reads of .npmrc, .gitconfig, .aws, .azure, .config/gcloud, .kube, or .ssh paths.
- DeviceNetworkEvents for the same process family to identify registry traffic versus suspicious external destinations.
- DeviceProcessEvents to find whether the same npm/node process spawned shells or utilities such as curl, wget, python, or powershell.
- If available, pivot on RemoteUrl and RemoteIP to identify repeated destinations across other hosts.

Benign explanations:
- npm install legitimately reads .npmrc for registry authentication before connecting to a package registry.
- Build scripts may read cloud CLI credential files to perform sanctioned deployment or artifact publishing steps.
- Git-based workflows may read .gitconfig or .git-credentials during prepare or postinstall hooks.

Escalation criteria:
- Credential access is followed by outbound traffic to non-registry destinations or unusual ports.
- Multiple secret stores are accessed in a short window, especially SSH keys or cloud tokens.
- The same host shows shell spawning, persistence writes, or other post-exploitation behavior.
- The access occurs on a developer workstation or CI agent that should not handle those credentials in that context.

Containment actions:
- Revoke and rotate any credentials that may have been accessed, including npm tokens, GitHub PATs, cloud access keys, and SSH keys.
- Isolate the host if there is evidence of exfiltration or broader malicious activity beyond expected registry access.
- Block or quarantine the suspicious package version or dependency chain if the access is tied to a compromised npm package.

Closure criteria:
- The accessed files are limited to expected registry or build credentials and the outbound traffic is to approved registries or internal services.
- The process tree is consistent with a sanctioned build or deployment workflow and no additional suspicious behavior is present.
- Any sensitive credentials exposed during the event have been rotated and the activity is documented as approved automation.

---

## Detection 3: npm Process Writing to Cron or Shell Profile Persistence Paths

### Detection Opportunity

npm or node spawned processes writing files to cron directories or shell profile paths to establish persistence in CI/CD environments

### Intelligence Context

- Unit 42: The npm Threat Landscape: Attack Surface and Mitigations (Updated June 2) — [https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
  - Context: Unit 42 analysis of npm supply chain attacks identified CI/CD persistence as a key post-install behavior, where malicious packages write to cron directories, shell profile scripts, or startup paths to survive pipeline re-runs and maintain access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1053, T1053.003, T1547, T1547.001
- Products: npm
- Platforms: CI/CD environments, developer systems
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, CI/CD environments, developer systems, T1053, T1053.003, T1547, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: persistence: T1053 Scheduled Task/Job/ T1053.003 Cron (high); persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName in~ ("node", "node.exe", "npm", "npm.cmd", "sh", "bash", "zsh", "dash")
| where (
    FolderPath has_any ("/etc/cron", "/var/spool/cron", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron/crontabs", "/etc/profile.d", "/etc/init.d", "/etc/rc", "/lib/systemd/system", "/usr/lib/systemd")
  ) or (
    FolderPath has_any ("/home/", "/root/")
    and FileName in~ (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_logout")
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessParentFileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate npm postinstall scripts that configure shell environments for developer tooling by writing to ~/.bashrc or ~/.profile.
- Infrastructure-as-code tools invoked via npm scripts that write systemd unit files as part of a sanctioned deployment step.
- CI/CD pipeline steps that use npm to scaffold environment configuration files in home directories.

Tuning notes:
- If the rule is intended only for CI/CD agents, add a DeviceName filter scoped to known agent hostnames or a device group tag to eliminate developer workstation FPs.
- After initial deployment, review any results against the CI/CD pipeline definition to identify sanctioned build steps that write to these paths and add them to an exclusion list by InitiatingProcessCommandLine pattern.

Risks / caveats:
- Defender for Endpoint on Linux must be deployed on CI/CD agents and must have file event collection enabled for /etc and /var paths; without Linux sensor coverage this rule will produce no results for Linux-hosted pipelines.
- Legitimate npm postinstall scripts that write shell configuration files to developer home directories will generate FPs; after baselining, add AccountName exclusions for known developer service accounts or DeviceName exclusions for developer workstations if the rule is scoped to CI/CD agents only.
- The /home/ path filter is broad and will match any user home directory; if the environment has many developer workstations with legitimate tooling that writes to ~/.bashrc, FP volume may be high on those devices.

### Triage Runbook

First 15 minutes:
- Confirm the write target is a persistence path such as cron directories, systemd unit paths, /etc/profile.d, or shell profile files in home/root directories.
- Verify the initiating process is npm, node, or a shell spawned from an npm lifecycle hook and not an unrelated system maintenance task.
- Review the written file type and contents if available to determine whether it is a scheduled job, startup script, or environment modification.
- Check whether the same host/account also shows suspicious credential access, shell spawning, or outbound network activity.
- Determine whether the device is a CI/CD agent or developer workstation and whether the write aligns with an approved installation or configuration step.

Evidence to collect:
- DeviceFileEvents showing the exact FolderPath, FileName, ActionType, and SHA256 for the persistence write.
- DeviceProcessEvents for the initiating process tree, including InitiatingProcessParentFileName, InitiatingProcessCommandLine, and SHA256.
- Any related DeviceNetworkEvents or DeviceFileEvents from the same time window that indicate payload download or follow-on execution.
- The account context and whether the host is a known build agent or developer system.
- If possible, the file contents or a copy of the written cron/profile/systemd artifact for review.

Pivot points:
- DeviceFileEvents on the same host/account for other writes to /etc/cron, /var/spool/cron, /etc/rc, /lib/systemd/system, /usr/lib/systemd, /etc/profile.d, /home/*/.bashrc, or /root/* profile files.
- DeviceProcessEvents to identify whether the same npm/node process spawned shells or download utilities before the write.
- DeviceNetworkEvents to see whether the process downloaded a payload before creating the persistence artifact.
- If available, pivot on SHA256 to determine whether the same script or binary has been seen on other hosts.

Benign explanations:
- A sanctioned installer or configuration script writes shell profile files to set environment variables for developer tooling.
- Infrastructure-as-code or deployment automation invoked through npm writes systemd units or cron entries as part of a legitimate setup.
- A CI pipeline scaffolds temporary shell configuration files in a home directory during a build step.

Escalation criteria:
- The written artifact is not part of an approved deployment or configuration workflow.
- The persistence file launches a shell, downloader, or encoded payload, or references suspicious paths or commands.
- The same host shows credential access, outbound exfiltration, or repeated persistence attempts.
- The activity occurs on a system that should not be modified by npm lifecycle scripts, such as a production build agent without that role.

Containment actions:
- Remove the unauthorized cron, systemd, or shell profile artifact if confirmed malicious.
- Isolate the host if the persistence write is accompanied by payload execution or exfiltration.
- Revoke any credentials used by the account if the persistence attempt appears tied to a compromised package or script.

Closure criteria:
- The persistence write is verified as part of an approved installer or automation workflow and the file contents are benign.
- No additional suspicious process, network, or credential activity is present around the event.
- The host is added to an allowlist only after the legitimate pattern is documented and baselined.

---

## Detection 4: Flutter-Built Binary Executing from Non-Standard Path with Outbound Network Connection on macOS

### Detection Opportunity

Execution of a Flutter-framework backdoor binary from a user-writable or non-standard path on macOS followed by outbound network connections, consistent with FlutterShell backdoor deployment

### Intelligence Context

- Unit 42: Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor — [https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/)
  - Context: Operation FlutterBridge delivered the FlutterShell backdoor to macOS users via malvertising. The backdoor is built using the Flutter framework and executes from non-standard user-writable paths, establishing C2 communication after first execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1543, T1543.001, T1547, T1547.013
- Products: Not specified
- Platforms: macOS
- Malware: FlutterShell
- Tools: Not specified
- Search tags: macOS, FlutterShell, T1543, T1543.001, T1547, T1547.013

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: persistence: T1543 Create or Modify System Process/ T1543.001 Launch Agent (high); persistence: T1547 Boot or Logon Autostart Execution/ T1547.013 XDG Autostart Entries (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SuspiciousExec = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("/Users/", "/tmp/", "/var/tmp/", "/private/tmp/")
| where FolderPath !has "/Applications/"
| where FolderPath !has "/Library/"
| project ExecTimestamp = Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, ProcessId;
let OutboundNet = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where not (RemoteIP startswith "10."
    or RemoteIP startswith "192.168."
    or (RemoteIP startswith "172." and split(RemoteIP, ".")[1] >= "16" and split(RemoteIP, ".")[1] <= "31")
    or RemoteIP == "127.0.0.1"
    or RemoteIP == "::1")
| project NetTimestamp = Timestamp, DeviceName, InitiatingProcessId, RemoteIP, RemoteUrl;
SuspiciousExec
| join kind=inner OutboundNet on DeviceName, $left.ProcessId == $right.InitiatingProcessId
| where NetTimestamp between (ExecTimestamp .. (ExecTimestamp + 10m))
| project
    ExecTimestamp,
    NetTimestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    ProcessId,
    RemoteIP,
    RemoteUrl
| order by ExecTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate user-installed applications that run from ~/Applications or ~/Downloads and make outbound connections (e.g., downloaded DMG installers, developer tools).
- Browser-launched applications or downloaded utilities that connect to update servers or telemetry endpoints.
- Development tools executed from home directories that make outbound API calls.

Tuning notes:
- After running as a hunting query, identify the most common FileName values in results and add exclusions for known legitimate applications (e.g., Electron-based apps, developer tools) that execute from user home directories.
- Consider adding a filter for binaries with no code signature or an invalid signature using DeviceProcessEvents fields if available in the tenant, as FlutterShell binaries are unlikely to be Apple-notarized.
- The 10-minute network correlation window can be narrowed if C2 beaconing timing becomes known from threat intelligence.

Risks / caveats:
- Defender for Endpoint macOS sensor must be deployed and active; FolderPath population for macOS process events should be verified in the tenant as field completeness varies by sensor version.
- RemoteUrl is not consistently populated in DeviceNetworkEvents on macOS; detections relying on it for C2 URL context may silently miss events.
- ProcessId reuse within the 1-day lookback window could cause false join matches if a PID is recycled between the execution and network events; this risk is low within a 10-minute correlation window but non-zero.
- The /Users/ path filter is broad and will match all user home directory executions; legitimate downloaded applications will generate significant FP volume on developer macOS machines.

### Triage Runbook

First 15 minutes:
- Confirm the binary executed from /Users/, /tmp/, /var/tmp/, or /private/tmp/ and not from /Applications/ or /Library/.
- Validate the process-to-network attribution using the ProcessId and InitiatingProcessId linkage and confirm the outbound connection occurred within 10 minutes of execution.
- Review the binary name, SHA256, and command line for signs of a downloaded or unpacked application rather than a known installed app.
- Check whether the remote destination is external, unusual for the user, or associated with recent malicious activity.
- Look for follow-on behavior such as additional child processes, persistence writes, or repeated beaconing from the same host.

Evidence to collect:
- DeviceProcessEvents for the execution event, including FileName, FolderPath, ProcessCommandLine, SHA256, ProcessId, and account context.
- DeviceNetworkEvents tied to the same ProcessId/InitiatingProcessId, including RemoteIP, RemoteUrl, and timestamp.
- Any code-signing or notarization details available in the tenant for the executed binary.
- DeviceFileEvents for nearby writes or drops in the same directory that may indicate unpacking or staging.
- The user context and whether the host is a developer machine, test system, or standard user workstation.

Pivot points:
- DeviceProcessEvents on the same host for other executions from user-writable paths in the last 24 hours.
- DeviceNetworkEvents for the same SHA256 or process family across the tenant to identify repeated C2 destinations.
- DeviceFileEvents for the same folder path to find dropped components, plist files, or supporting scripts.
- If available, pivot on RemoteIP and RemoteUrl to identify other hosts contacting the same destination.

Benign explanations:
- A legitimate user-installed application or updater was launched from Downloads or a temporary directory before being moved to a standard location.
- A developer tool or packaged app runs from a home directory and makes normal outbound API or telemetry connections.
- A downloaded installer or DMG-mounted utility briefly executes from a user-writable path during installation.

Escalation criteria:
- The binary is unsigned, untrusted, or has a suspicious SHA256 match in threat intelligence.
- The outbound destination is not an expected vendor endpoint and the process continues to beacon.
- The host also shows persistence creation, credential access, or additional suspicious child processes.
- The execution occurred on a non-developer macOS endpoint where user-writable execution is unusual.

Containment actions:
- Isolate the macOS host if the binary is confirmed malicious or if beaconing persists.
- Quarantine or remove the suspicious binary and any related dropped files after evidence capture.
- Block the remote destination if it is confirmed malicious and used by multiple affected hosts.

Closure criteria:
- The binary is identified as a legitimate signed application or installer with an expected destination.
- No persistence, credential access, or additional malicious behavior is observed after the initial execution.
- The event is attributable to approved software deployment or user action and is documented for tuning.

---

## Detection 5: macOS Process Establishing Persistence Mechanism After Execution from User-Writable Path

### Detection Opportunity

FlutterShell backdoor establishing persistence on macOS by writing to LaunchAgent or LaunchDaemon paths after executing from a non-standard user-writable location

### Intelligence Context

- Unit 42: Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor — [https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/)
  - Context: The FlutterShell backdoor delivered via Operation FlutterBridge establishes persistence on macOS after initial execution. Persistence mechanisms on macOS commonly involve LaunchAgent or LaunchDaemon plist files written to user or system Library paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1543, T1543.001, T1547, T1547.013
- Products: Not specified
- Platforms: macOS
- Malware: FlutterShell
- Tools: Not specified
- Search tags: macOS, FlutterShell, T1543, T1543.001, T1547, T1547.013

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: persistence: T1543 Create or Modify System Process/ T1543.001 Launch Agent (high); persistence: T1547 Boot or Logon Autostart Execution/ T1547.013 XDG Autostart Entries (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let NonStandardExec = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("/Users/", "/tmp/", "/var/tmp/", "/private/tmp/")
| where FolderPath !has "/Applications/"
| where FolderPath !has "/Library/"
| project ExecTimestamp = Timestamp, DeviceName, AccountName, ExecFileName = FileName, ExecFolderPath = FolderPath, SHA256, ProcessId;
let PersistenceWrite = DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/System/Library/LaunchDaemons"
  )
| where FileName endswith ".plist" or FileName endswith ".sh"
| project PersistTimestamp = Timestamp, DeviceName, AccountName, PersistFileName = FileName, PersistFolderPath = FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId;
NonStandardExec
| join kind=inner PersistenceWrite on DeviceName, AccountName, $left.ProcessId == $right.InitiatingProcessId
| where PersistTimestamp between (ExecTimestamp .. (ExecTimestamp + 15m))
| project
    ExecTimestamp,
    PersistTimestamp,
    DeviceName,
    AccountName,
    ExecFileName,
    ExecFolderPath,
    SHA256,
    ProcessId,
    PersistFileName,
    PersistFolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by ExecTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate software installers that are downloaded to ~/Downloads and write LaunchAgent plists as part of a sanctioned installation flow.
- Developer tools or package managers that install themselves from user home directories and register LaunchAgents for background services.
- macOS application updates that temporarily execute from user-writable paths before moving to /Applications/ and registering a LaunchAgent.

Tuning notes:
- After initial deployment, review ExecFileName values in results and add exclusions for known legitimate installer binaries (e.g., known software update agents) that execute from user home directories.
- If the environment has a software distribution system that deploys applications by executing from /tmp/ before installing to /Applications/, add the known installer binary names to an ExecFileName exclusion list.
- Consider reducing the correlation window from 15 minutes if testing shows legitimate installers complete LaunchAgent registration faster, to reduce the FP window.

Risks / caveats:
- Defender for Endpoint macOS sensor must be deployed and must capture file creation events for /Library/LaunchAgents and /Library/LaunchDaemons paths; this should be verified in the tenant as Library path coverage varies by sensor version and macOS SIP configuration.
- FolderPath population for macOS process events in DeviceProcessEvents should be confirmed in the tenant before relying on the non-standard path filter in the execution leg.
- ProcessId reuse within the 1-day lookback window is a theoretical risk; the 15-minute time-bounded join significantly reduces this risk in practice.
- Legitimate software installers downloaded to ~/Downloads that write LaunchAgent plists will match; after baselining, add FileName exclusions for known legitimate installer binaries by ExecFileName.

### Triage Runbook

First 15 minutes:
- Verify the execution path is user-writable and not under /Applications/ or /Library/.
- Confirm the persistence write is directly tied to the same ProcessId that executed from the non-standard path.
- Inspect the created or modified plist or shell script to determine whether it launches a suspicious binary, downloader, or encoded command.
- Check whether the persistence write occurred within 15 minutes of execution and whether the host also shows outbound network activity.
- Determine whether the account and device are part of a sanctioned software installation or update workflow.

Evidence to collect:
- DeviceProcessEvents for the execution leg, including ExecFileName, ExecFolderPath, SHA256, ProcessId, and command line.
- DeviceFileEvents for the persistence write, including PersistFileName, PersistFolderPath, ActionType, and InitiatingProcessCommandLine.
- Any related DeviceNetworkEvents from the same process or host showing outbound connections after execution.
- A copy of the written plist or shell script content if available.
- AccountName, DeviceName, and whether the host is a developer workstation or standard macOS endpoint.

Pivot points:
- DeviceFileEvents for other LaunchAgent or LaunchDaemon writes on the same host within the last 24 hours.
- DeviceProcessEvents for other executions from /Users/, /tmp/, /var/tmp/, or /private/tmp/ on the same device.
- DeviceNetworkEvents tied to the same SHA256 or process family to identify beaconing or download activity.
- If available, pivot on the persistence file name or path across the tenant to find reuse on other hosts.

Benign explanations:
- A legitimate installer or updater executed from Downloads and registered a LaunchAgent as part of normal installation.
- A developer tool or package manager installed a background service from a user directory before moving the app into place.
- A sanctioned application update temporarily ran from a temporary directory and wrote a LaunchAgent for auto-start behavior.

Escalation criteria:
- The plist or script launches an unknown binary, downloader, or suspicious command.
- The same host shows outbound connections, credential access, or additional persistence artifacts.
- The binary is unsigned, untrusted, or matches known malicious FlutterShell indicators.
- The activity occurs on a non-developer endpoint where user-writable execution and persistence are unexpected.

Containment actions:
- Isolate the host if the persistence artifact is malicious or if the process is still active.
- Remove the unauthorized LaunchAgent or LaunchDaemon artifact after preserving evidence.
- Quarantine the executed binary and any related dropped files, and block the remote destination if identified as malicious.

Closure criteria:
- The persistence artifact is verified as part of an approved installation or update and the content is benign.
- No suspicious network, credential, or additional persistence activity is found.
- The event is documented as a legitimate software deployment and tuned only after baseline confirmation.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- npm-Spawned Process Accessing Credential Files: Do not schedule yet; validate as an analyst-led hunt first.
- Flutter-Built Binary Executing from Non-Standard Path with Outbound Network Connection on macOS: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceProcessEvents: shared by npm Preinstall Hook Spawning Shell Interpreter; Flutter-Built Binary Executing from Non-Standard Path with Outbound Network Connection on macOS; macOS Process Establishing Persistence Mechanism After Execution from User-Writable Path
- DeviceFileEvents: shared by npm-Spawned Process Accessing Credential Files; npm Process Writing to Cron or Shell Profile Persistence Paths; macOS Process Establishing Persistence Mechanism After Execution from User-Writable Path
- DeviceNetworkEvents: shared by npm-Spawned Process Accessing Credential Files; Flutter-Built Binary Executing from Non-Standard Path with Outbound Network Connection on macOS

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: npm Preinstall Hook Spawning Shell Interpreter; npm Process Writing to Cron or Shell Profile Persistence Paths; macOS Process Establishing Persistence Mechanism After Execution from User-Writable Path.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: npm-Spawned Process Accessing Credential Files; Flutter-Built Binary Executing from Non-Standard Path with Outbound Network Connection on macOS.

### Hunting Agenda and Promotion Criteria

- npm-Spawned Process Accessing Credential Files: Do not schedule yet; validate as an analyst-led hunt first.; confirm required file-access telemetry exists and produces representative events; prove correlation keys join correctly on real tenant telemetry.
- Flutter-Built Binary Executing from Non-Standard Path with Outbound Network Connection on macOS: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
