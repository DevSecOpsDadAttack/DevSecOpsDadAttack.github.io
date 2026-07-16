---
layout: post
title: "Detection Engineering Brief - Thursday, July 16, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-16
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-15409
  - CVE-2026-15410
  - T1190
  - T1059
  - SonicWall SMA1000
  - AsyncAPI
  - npm
  - CI/CD
  - developer endpoints
  - AWS
  - T1071
  - T1105
  - T1098
  - T1098.003
  - T1554
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-15409, CVE-2026-15410, T1190, T1059, SonicWall SMA1000, AsyncAPI, npm, CI/CD, developer endpoints, AWS, T1071, T1105, T1098, T1098.003, T1554.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SonicWall SMA1000 - Root Command Execution via Path Traversal in Syslog; npm Supply Chain - CI Runner Unexpected Outbound Network Connection During Build; AWS IAM Persistence - Unexpected Inline or Managed Policy Attachment via CloudTrail in Sentinel.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SonicWall SMA1000 - Root Command Execution via Path Traversal in Syslog

### Detection Opportunity

Local privilege escalation enables root command execution via path traversal on SonicWall SMA1000 appliance.

### Intelligence Context

- Rapid7: Rapid7 MDR Team Discovers New SonicWall SMA1000 Zero Days being Actively Exploited (CVE-2026-15409, CVE-2026-15410) — [https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410](https://www.rapid7.com/blog/post/etr-rapid7-mdr-team-discovers-new-sonicwall-sma1000-zero-days-being-actively-exploited-cve-2026-15409-cve-2026-15410)
  - Context: CVE-2026-15410 permits an attacker with access to the internal service on localhost port 8188 to execute arbitrary OS commands as root via a malicious path traversal. Rapid7 MDR observed active exploitation of this vulnerability chain in the wild.

### Search Metadata

- CVEs: CVE-2026-15409, CVE-2026-15410
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: SonicWall SMA1000
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-15409, CVE-2026-15410, T1190, T1059, SonicWall SMA1000

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
let SonicWallHosts = dynamic([]);
Syslog
| where TimeGenerated > ago(7d)
| where array_length(SonicWallHosts) == 0 or HostName in~ (SonicWallHosts)
| where SyslogMessage has_any ("../", "..%2F", "..%5C", "..%252F")
| where SyslogMessage has_any ("uid=0", "euid=0", "root shell", "execve", "8188")
| project TimeGenerated, HostName, ProcessName, Facility, SeverityLevel, SyslogMessage
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Web access log entries forwarded via syslog that contain path traversal attempts in HTTP request paths without actual execution.
- Routine syslog messages referencing root ownership or root filesystem paths that coincidentally contain directory separator sequences.

**Tuning notes:**
- Populate the SonicWallHosts dynamic list with the actual HostName values of SonicWall SMA1000 appliances in the environment to scope the query and eliminate cross-host noise.
- Review baseline SyslogMessage content from SonicWall appliances to confirm which execution-related strings are emitted and refine the has_any filter accordingly.
- Consider adding a Facility filter (e.g., Facility == 'kern' or 'daemon') if SonicWall routes execution-related messages through a specific syslog facility.

**Risks / caveats:**
- Syslog table will only contain SonicWall SMA1000 entries if the appliance syslog is actively forwarded to the Sentinel workspace via a CEF or syslog connector. Without this connector configured, the query produces no relevant results.
- SonicWall SMA1000 syslog verbosity must be configured at a level that captures process-level command execution messages; default logging levels may not emit these events.
- SonicWallHosts dynamic list is empty by default; the query will scan all syslog sources until populated with known SonicWall SMA1000 hostnames, producing significant noise in environments with many Linux syslog sources.
- A 7-day lookback window is appropriate for hunting but should be reduced to 1d or less for scheduled rule deployment to avoid repeated alerting on the same events.

### Triage Runbook

**First 15 minutes:**
- Validate the alert against the raw SyslogMessage and confirm the same event contains both path traversal indicators and root execution indicators.
- Identify the affected SonicWall SMA1000 hostname and compare the timestamp to any concurrent admin activity, maintenance windows, or firmware changes.
- Check for repeated events from the same source or within a short time window, which may indicate active exploitation rather than a single malformed log entry.
- Notify the network/security operations owner for the appliance and begin evidence preservation if the message strongly suggests successful command execution.

**Evidence to collect:**
- Raw syslog entries around the alert time, including several minutes before and after the event.
- Appliance hostname, firmware version, and syslog forwarding configuration details.
- Any available appliance audit logs, authentication logs, and administrative session records.
- Network telemetry showing inbound requests to the appliance around the alert time, especially repeated or unusual access patterns.

**Pivot points:**
- Syslog for the same HostName over the prior and subsequent 24 hours to find repeated traversal or execution strings.
- Firewall, proxy, or network sensor logs for inbound traffic to the SonicWall SMA1000 around the alert timestamp.
- Authentication or admin activity logs for the appliance to identify whether a legitimate administrator was active.
- Asset inventory or CMDB records to confirm the appliance role, exposure, and owner.

**Benign explanations:**
- A forwarded web access log or error message containing path traversal text without actual exploitation.
- Routine syslog content mentioning root filesystem paths or ownership rather than command execution.
- A legitimate administrative action or troubleshooting event that generated unusual command-related logging.

**Escalation criteria:**
- The syslog message shows clear root command execution, execve-like activity, or repeated exploitation attempts.
- There is evidence of inbound exploitation traffic from external sources or multiple affected appliances.
- The appliance is internet-facing, unpatched, or shows signs of post-exploitation activity such as new sessions, configuration changes, or unexpected reboots.
- Any indication that attacker commands were executed as root should be treated as a confirmed security incident.

**Containment actions:**
- If exploitation appears credible, isolate the appliance from untrusted networks or restrict access to management and VPN services.
- Preserve logs and configuration state before rebooting or applying changes.
- Block observed source IPs at perimeter controls if they are clearly malicious and not shared infrastructure.
- Coordinate emergency patching or vendor guidance before returning the appliance to service.

**Closure criteria:**
- The event is traced to benign logging noise or a known administrative action with supporting evidence.
- No additional suspicious syslog entries, inbound exploitation attempts, or appliance anomalies are found during the review window.
- The appliance is confirmed patched or otherwise protected, and the alerting pattern is understood and documented.
- Any required containment or remediation actions have been completed and validated.

<br/>
---
<br/>

## Detection 2: npm Supply Chain - Node.js Spawning Shell or Downloader at Import Time

### Detection Opportunity

Compromised npm package executes a shell or network downloader as a direct child of the node runtime at import time.

### Intelligence Context

- Microsoft Security Blog: Unpacking the AsyncAPI npm supply chain compromise and import-time payload delivery — [https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)
  - Context: Threat actors compromised AsyncAPI npm packages to deliver malware at import time. The payload executes immediately when the package is imported, spawning shells or downloaders as direct children of the node runtime process.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1105
- Products: AsyncAPI, npm
- Platforms: CI/CD, developer endpoints
- Malware: Not specified
- Tools: Not specified
- Search tags: AsyncAPI, npm, CI/CD, developer endpoints, T1071, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Execution: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where InitiatingProcessFileName in~ ("node", "node.exe", "npm", "npm.cmd", "npx", "npx.cmd")
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash", "sh", "zsh", "dash",
    "curl", "wget",
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe"
)
| where not(InitiatingProcessCommandLine has_any ("--version", "--help", "-v"))
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate postinstall scripts in trusted packages that invoke shell utilities such as bash or sh for platform detection or binary compilation.
- Developer tooling that uses node to spawn shell commands as part of build automation outside of npm install contexts.
- Test frameworks that use node to spawn child processes as part of integration test execution.

**Tuning notes:**
- Scope DeviceName to CI runner and developer endpoint device groups using a dynamic list or watchlist to reduce noise from production node services.
- Build an exclusion list of known-safe InitiatingProcessCommandLine patterns from postinstall scripts of trusted packages observed in the environment.
- Consider adding npx.cmd and yarn as additional initiating process names if those package managers are used in the environment.

**Risks / caveats:**
- Defender for Endpoint must be onboarded on developer endpoints and CI runner machines for DeviceProcessEvents to contain relevant telemetry; Linux CI runners require MDE Linux agent deployment.
- Legitimate postinstall scripts in widely used packages may trigger this rule; an allowlist of trusted InitiatingProcessCommandLine patterns should be built from baseline observations before enabling automated response.
- Linux CI runners require MDE Linux agent to be deployed and enrolled; without this, the query will not surface Linux-side exploitation.
- The 1-day lookback is appropriate for scheduled rules but may miss exploitation that occurred before the rule was deployed; an initial 7-day hunting run is recommended.

### Triage Runbook

**First 15 minutes:**
- Confirm the child process was spawned by node, npm, or npx during package import or install rather than during a known build script.
- Identify the package name, repository, and build job or user session associated with the event.
- Check whether the child process is a shell, downloader, or script host and whether it launched from an unexpected folder path.
- Determine whether the same host has additional suspicious process creation, file writes, or outbound connections around the same time.

**Evidence to collect:**
- Parent and child process command lines, folder paths, and account context.
- Package lockfiles, install logs, and CI job logs for the affected build or developer session.
- DeviceProcessEvents around the alert time to identify follow-on process chains.
- Any downloaded files, hashes, or temporary directories created by the process.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to find other node, shell, or downloader activity.
- DeviceFileEvents for recent file writes in package directories, temp folders, or build output paths.
- DeviceNetworkEvents for outbound connections from the same host during the install window.
- CI/CD logs or source control commit history to identify the exact package version and build trigger.

**Benign explanations:**
- Legitimate postinstall scripts that compile native modules or perform platform checks.
- Developer tooling or test frameworks that intentionally spawn shells during builds.
- Package manager behavior from trusted packages that use helper scripts for setup or binary installation.

**Escalation criteria:**
- The child process is a shell or downloader with no clear business justification and occurs during package import or install.
- The package version is unexpected, newly published, or not pinned to a trusted version.
- The host shows additional signs of compromise such as credential access, persistence, or outbound callback traffic.
- Multiple developer or CI hosts show the same package behavior, suggesting a broader supply chain issue.

**Containment actions:**
- Pause the affected build job or isolate the developer endpoint if malicious execution is credible.
- Remove the suspicious package version from the build pipeline and pin to a known-good version.
- Quarantine any downloaded artifacts or temporary files until they are analyzed.
- Reset credentials used on the affected host if there is evidence of token or secret exposure.

**Closure criteria:**
- The process chain is confirmed as a trusted postinstall or build action with supporting package and pipeline evidence.
- No suspicious follow-on processes, downloads, or outbound connections are found on the host.
- The package version and build context are documented and added to allowlists or tuning notes if appropriate.
- Any malicious package or artifact has been removed from the pipeline and affected systems are remediated.

<br/>
---
<br/>

## Detection 3: npm Supply Chain - CI Runner Unexpected Outbound Network Connection During Build

### Detection Opportunity

Trusted CI/CD workflows abused to deliver payload, resulting in unexpected outbound network connections from CI runner processes during npm install.

### Intelligence Context

- Microsoft Security Blog: Unpacking the AsyncAPI npm supply chain compromise and import-time payload delivery — [https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)
  - Context: Threat actors weaponized trusted CI/CD workflows to distribute malware through npm. Compromised packages initiate outbound network connections from CI runner processes during build execution as part of payload delivery.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1105
- Products: AsyncAPI, npm
- Platforms: CI/CD, developer endpoints
- Malware: Not specified
- Tools: Not specified
- Search tags: AsyncAPI, npm, CI/CD, developer endpoints, T1071, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Execution: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let KnownRegistries = dynamic([
    "registry.npmjs.org",
    "registry.yarnpkg.com"
]);
let BuildEvents =
    DeviceProcessEvents
    | where TimeGenerated > ago(7d)
    | where InitiatingProcessCommandLine has_any ("npm install", "npm ci", "npm run")
    | project DeviceName, BuildTime = TimeGenerated, BuildCommandLine = InitiatingProcessCommandLine;
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("npm", "node", "node.exe", "npm.cmd")
| where not(
    RemoteIP startswith "10."
    or RemoteIP startswith "172."
    or RemoteIP startswith "192.168."
    or RemoteIP startswith "127."
    or RemoteIP startswith "100.64."
)
| where (
    (isnotempty(RemoteUrl) and not(RemoteUrl has_any (KnownRegistries)))
    or isempty(RemoteUrl)
)
| join kind=inner BuildEvents on DeviceName
| where abs(datetime_diff('second', TimeGenerated, BuildTime)) < 120
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    ActionType,
    BuildCommandLine
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- npm packages that legitimately fetch binary assets or telemetry from CDNs or vendor endpoints during postinstall.
- Build tools that check for updates or license validation against external endpoints during npm install.
- CI runners that connect to external artifact stores or container registries during build steps that overlap with the npm install time window.

**Tuning notes:**
- Expand KnownRegistries with any private npm registry, Artifactory, Nexus, or GitHub Packages hostnames used in the environment.
- Scope DeviceName to CI runner machine groups using a watchlist or dynamic list to eliminate developer workstation noise.
- Consider reducing the join window from 120 seconds to match the observed npm install duration in the environment to improve correlation precision.
- If RemoteUrl is consistently empty in the environment, pivot to RemoteIP-based allowlisting using known registry IP ranges.

**Risks / caveats:**
- RemoteUrl is not consistently populated in DeviceNetworkEvents for all outbound connection types in Defender XDR; DNS-resolved connections may only populate RemoteIP, making URL-based registry exclusion incomplete.
- Defender for Endpoint must be enrolled on CI runner machines for DeviceNetworkEvents to contain CI build telemetry; self-hosted runners on unmanaged infrastructure will not appear.
- The 120-second join window between network events and build process events is heuristic; builds that take longer than 2 minutes may miss correlated network events, and short-lived processes may produce spurious correlations.
- RemoteUrl being empty for many connections means the KnownRegistries exclusion will not apply, and those connections will be included in results regardless of destination; RemoteIP-based allowlisting of known registry IPs would improve precision but requires maintaining an IP list.

### Triage Runbook

**First 15 minutes:**
- Confirm the network event occurred on a CI runner or developer endpoint during an npm install or related build step.
- Identify the destination IP, URL, and port, and determine whether it is a known registry, artifact store, or vendor endpoint.
- Correlate the network event to the exact build job, repository, and initiating process command line.
- Check for repeated outbound connections, unusual ports, or connections to non-business destinations.

**Evidence to collect:**
- DeviceNetworkEvents and DeviceProcessEvents for the same host and time window.
- Build logs, job metadata, and package manager output from the affected pipeline.
- Destination reputation details, DNS resolution history, and any proxy logs for the remote endpoint.
- Any files downloaded or written during the build window.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName to identify all outbound destinations during the build.
- DeviceProcessEvents to confirm the build command and any child shell or downloader processes.
- Proxy, firewall, or DNS logs to validate the destination and whether it is expected for the environment.
- CI system logs to identify the exact job, runner, and package version involved.

**Benign explanations:**
- Legitimate package downloads from approved registries or private artifact repositories.
- Build steps that fetch dependencies, binaries, or telemetry from vendor endpoints.
- Overlap between build activity and unrelated outbound traffic from the same runner host.

**Escalation criteria:**
- The destination is not an approved registry, artifact store, or business service.
- The connection occurs alongside shell spawning, downloader activity, or suspicious file writes.
- The runner is internet-facing or handles sensitive build secrets and the connection is to an unknown external endpoint.
- Multiple CI runners show the same unexpected destination, suggesting a compromised package or pipeline.

**Containment actions:**
- Pause the affected CI job and isolate the runner if the destination is suspicious.
- Block the destination at proxy or firewall controls if it is clearly malicious.
- Rotate any secrets exposed to the runner during the build window.
- Remove the suspicious package version or build step from the pipeline until validated.

**Closure criteria:**
- The destination is confirmed as an approved registry or expected service for the build.
- No suspicious child processes, downloads, or file modifications are found on the runner.
- The event is explained by documented pipeline behavior and added to tuning or allowlists if needed.
- Any malicious artifact or package is removed and the runner is returned to service after validation.

<br/>
---
<br/>

## Detection 4: AWS IAM Persistence - Unexpected Inline or Managed Policy Attachment via CloudTrail in Sentinel

### Detection Opportunity

Attackers embed persistence by attaching or creating IAM policies via unexpected principals to maintain long-term access.

### Intelligence Context

- Rapid7: Investigating Persistence Mechanisms in AWS — [https://www.rapid7.com/blog/post/dr-investigating-aws-persistence-mechanisms](https://www.rapid7.com/blog/post/dr-investigating-aws-persistence-mechanisms)
  - Context: Rapid7 observed adversaries embedding persistence directly into IAM policies by attaching managed policies or creating inline policies via unexpected principals, enabling durable access that survives credential rotation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.003
- Products: Not specified
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS, T1098, T1098.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail before scheduling.

**Required telemetry:**
- AWSCloudTrail

### KQL

```kql
AWSCloudTrail
| where TimeGenerated > ago(1d)
| where EventName in (
    "PutUserPolicy",
    "AttachUserPolicy",
    "CreatePolicyVersion",
    "AttachRolePolicy",
    "PutRolePolicy",
    "CreatePolicy"
)
| where isempty(ErrorCode)
| extend TargetResource = tostring(parse_json(RequestParameters).policyArn)
| extend TargetResource = iff(isempty(TargetResource), tostring(parse_json(RequestParameters).roleName), TargetResource)
| extend TargetResource = iff(isempty(TargetResource), tostring(parse_json(RequestParameters).userName), TargetResource)
| project
    TimeGenerated,
    EventName,
    UserIdentityArn,
    UserIdentityType,
    UserIdentityUserName,
    UserIdentityAccountId,
    RecipientAccountId,
    AWSRegion,
    SourceIpAddress,
    TargetResource,
    ErrorCode
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IAM administrator activity during provisioning, onboarding, or infrastructure-as-code deployments.
- Automation service accounts (e.g., Terraform, CloudFormation) that regularly attach policies as part of infrastructure management.
- Break-glass account usage during incident response.

**Tuning notes:**
- Add a where UserIdentityArn !in (dynamic([...])) filter populated with known IAM admin role ARNs and automation service account ARNs to suppress expected activity.
- If multiple AWS accounts are ingested, add a where RecipientAccountId in (dynamic([...])) filter to scope monitoring to production or sensitive accounts.
- Consider adding CreateLoginProfile and UpdateLoginProfile to EventName filter to detect additional IAM persistence techniques documented by Rapid7.

**Risks / caveats:**
- The original query targets AuditLogs with Azure AD schema fields; AWS CloudTrail events in Sentinel are stored in the AWSCloudTrail table with a different schema. The original query will return zero relevant results as written.
- The AWSCloudTrail table is only populated if the AWS CloudTrail connector (S3-based or direct API connector) is configured in the Sentinel workspace for the target AWS accounts.
- RequestParameters is a dynamic JSON field in AWSCloudTrail; parsing the target IAM resource from it requires tostring() and parse_json() extraction which may vary by event type.
- An exclusion list of approved IAM administrator and automation role ARNs must be built from environment baseline data and added as a where UserIdentityArn !in () filter before this rule is suitable for automated alerting without high false-positive volume.

### Triage Runbook

**First 15 minutes:**
- Validate the CloudTrail event name, actor ARN, and target resource to confirm a successful IAM policy change.
- Determine whether the principal is an approved administrator, automation role, or break-glass account.
- Check whether the change occurred outside a change window or from an unusual source IP or region.
- Assess whether the affected user, role, or policy grants elevated or cross-account access.

**Evidence to collect:**
- Full CloudTrail event details, including request parameters and response elements.
- Actor identity, source IP, AWS region, and recipient account ID.
- Recent IAM changes for the same principal, role, or user.
- Change management records or infrastructure-as-code deployment logs for the same time period.

**Pivot points:**
- AWSCloudTrail for related IAM events by the same UserIdentityArn in the prior and subsequent 24 hours.
- AWSCloudTrail for AssumeRole, CreateAccessKey, UpdateLoginProfile, or policy attachment activity around the same time.
- AWS Config or IAM inventory to inspect the current permissions of the affected user or role.
- CloudTrail management events for the same source IP or region to identify broader account activity.

**Benign explanations:**
- Legitimate IAM administration during provisioning, onboarding, or access review.
- Infrastructure-as-code deployments that create or attach policies as part of normal operations.
- Break-glass or emergency access activity that was not pre-notified to the SOC.

**Escalation criteria:**
- The actor is not an approved administrator or automation role.
- The policy change grants privileged, persistent, or cross-account access.
- The activity is accompanied by other suspicious AWS actions such as key creation, role assumption, or log tampering.
- The change cannot be tied to a valid ticket, deployment, or approved maintenance activity.

**Containment actions:**
- Disable or quarantine the suspicious IAM principal if it is confirmed unauthorized.
- Revoke newly created or modified access paths, including attached policies or inline policies.
- Rotate credentials and review trust relationships for the affected role or user.
- Preserve CloudTrail and related logs before making additional changes.

**Closure criteria:**
- The IAM change is confirmed as authorized and matches a documented change request or deployment.
- No additional suspicious IAM or privilege escalation activity is found for the actor.
- The affected policy state is reviewed and documented, including any required rollback.
- Any unauthorized access paths have been removed and validated.

<br/>
---
<br/>

## Detection 5: CI/CD Persistence - Unexpected Process Modifying CI Workflow Configuration Files

### Detection Opportunity

CI/CD workflow configuration files modified by unexpected processes, indicating attacker persistence embedded in the build pipeline.

### Intelligence Context

- Unit 42: The npm Threat Landscape: Attack Surface and Mitigations (Updated July 15) — [https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
  - Context: Unit 42 identified CI/CD persistence as a primary attack theme in the npm threat landscape, where attackers modify CI workflow configuration files to embed malicious steps that execute on every subsequent build.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1554
- Products: npm
- Platforms: CI/CD, developer endpoints
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, CI/CD, developer endpoints, T1098, T1554

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Persistence: T1098 Account Manipulation (medium); Persistence: T1554 Compromise Client Software Binary (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where TimeGenerated > ago(1d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where
    FolderPath has_any (
        ".github/workflows",
        ".gitlab-ci",
        ".circleci",
        ".travis",
        "azure-pipelines"
    )
    or FileName in~ (
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".travis.yml",
        "circle.yml",
        "azure-pipelines.yml",
        ".drone.yml"
    )
| where InitiatingProcessFileName !in~ (
    "git",
    "git.exe",
    "code",
    "code.exe",
    "idea",
    "idea64.exe",
    "vim",
    "nano",
    "emacs",
    "runner",
    "runner.exe",
    "agent",
    "agent.exe"
)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    ActionType,
    FolderPath,
    FileName,
    SHA256
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CI runner agents that write workflow files to disk during repository checkout operations before build execution.
- Automated dependency update tools such as Dependabot or Renovate that modify workflow files as part of PR creation.
- IDE plugins or formatters that rewrite YAML files on save.
- Infrastructure-as-code tools that generate or update workflow files programmatically.

**Tuning notes:**
- Review InitiatingProcessFileName values from baseline DeviceFileEvents data on CI runner machines to identify any additional legitimate processes that write to workflow config paths and add them to the exclusion list.
- Scope DeviceName to CI runner and developer endpoint device groups to reduce noise from unrelated machines.
- Consider adding a SHA256 lookup against threat intelligence or a known-good hash baseline for workflow files to enrich alerts with file integrity context.

**Risks / caveats:**
- Defender for Endpoint must be deployed on CI runner and developer machines for DeviceFileEvents to capture write events to workflow configuration paths; self-hosted CI runners on unmanaged infrastructure will not appear.
- DeviceFileEvents ActionType values FileCreated and FileModified must be confirmed as supported in the enrolled MDE agent version; older agent versions may use different ActionType strings.
- The InitiatingProcessFileName exclusion list is a starting baseline; environments with additional approved IDEs, editors, or CI checkout agents will require expansion of this list to avoid false positives.
- FolderPath matching uses has_any which performs substring matching; deeply nested paths that contain these strings for unrelated reasons could produce false positives.

### Triage Runbook

**First 15 minutes:**
- Open the file event and confirm the exact workflow file path, file name, and initiating process.
- Check whether the process is a known editor, CI agent, dependency updater, or source control client.
- Review the modified content if available to see whether the change adds execution steps, downloads, secrets access, or remote calls.
- Identify the repository owner and whether the change aligns with a recent pull request, merge, or automation run.

**Evidence to collect:**
- DeviceFileEvents details including action type, file path, hash, and initiating process command line.
- The current and previous versions of the workflow file from source control.
- CI job logs and repository commit history around the alert time.
- Any related process, network, or file activity on the same host.

**Pivot points:**
- DeviceFileEvents for the same DeviceName to find other workflow or repository file modifications.
- DeviceProcessEvents to identify whether the modifying process spawned shells, downloaders, or script hosts.
- Source control audit logs to confirm whether the file change was committed through an approved workflow.
- CI system logs to determine whether the change was made by a runner, agent, or human editor.

**Benign explanations:**
- A legitimate CI runner or checkout agent writing workflow files during repository synchronization.
- An approved developer editing workflow YAML as part of a normal change request.
- Automation tools such as dependency updaters or infrastructure-as-code systems generating workflow changes.

**Escalation criteria:**
- The modifying process is not a known editor, CI agent, or approved automation tool.
- The file change adds suspicious execution, download, credential, or persistence logic.
- The change is not represented in source control history or approved change management records.
- The same host or account shows additional suspicious activity such as shell spawning or outbound connections.

**Containment actions:**
- If malicious tampering is likely, pause the affected CI pipeline and prevent the workflow from executing.
- Revert the workflow file to the last known-good version from source control.
- Disable the suspicious account or host access to the repository if unauthorized modification is confirmed.
- Preserve the modified file and related logs for forensic review before further changes.

**Closure criteria:**
- The file modification is matched to a legitimate commit, automation run, or approved editor activity.
- The workflow content is reviewed and found not to introduce malicious execution or persistence.
- No additional suspicious file changes or process activity are present on the host.
- Any unauthorized workflow changes are reverted and the repository is restored to a trusted state.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- SonicWall SMA1000 - Root Command Execution via Path Traversal in Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.
- AWS IAM Persistence - Unexpected Inline or Managed Policy Attachment via CloudTrail in Sentinel: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail before scheduling.

**Schema / correlation keys:**
- npm Supply Chain - CI Runner Unexpected Outbound Network Connection During Build: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by npm Supply Chain - Node.js Spawning Shell or Downloader at Import Time; npm Supply Chain - CI Runner Unexpected Outbound Network Connection During Build

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: npm Supply Chain - Node.js Spawning Shell or Downloader at Import Time; CI/CD Persistence - Unexpected Process Modifying CI Workflow Configuration Files.
2. Resolve environment-mapping detections next: SonicWall SMA1000 - Root Command Execution via Path Traversal in Syslog; AWS IAM Persistence - Unexpected Inline or Managed Policy Attachment via CloudTrail in Sentinel.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: npm Supply Chain - CI Runner Unexpected Outbound Network Connection During Build.

### Hunting Agenda and Promotion Criteria

- npm Supply Chain - CI Runner Unexpected Outbound Network Connection During Build: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- SonicWall SMA1000 - Root Command Execution via Path Traversal in Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- AWS IAM Persistence - Unexpected Inline or Managed Policy Attachment via CloudTrail in Sentinel: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
