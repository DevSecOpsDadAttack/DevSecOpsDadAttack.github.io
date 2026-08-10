---
layout: post
title: "Detection Engineering Brief - Monday, August 10, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-10
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-63077
  - T1190
  - T1059
  - JetBrains TeamCity
  - XStream
  - Windows
  - Linux
  - npm
  - GitHub Actions
  - Ethereum
  - ChainDrop
  - DeadLock
  - Rust
  - T1090
  - T1489
  - T1486
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-63077, T1190, T1059, JetBrains TeamCity, XStream, Windows, Linux, npm, GitHub Actions, Ethereum, ChainDrop, DeadLock, Rust, T1090, T1489, T1486.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Unauthenticated External Requests to TeamCity Agent Polling Endpoints - CVE-2026-63077; CI Runner Process Accessing Secret Environment Variables Followed by Outbound Network Connection - ChainDrop; CI Runner Outbound Connection to Ethereum RPC Endpoints - ChainDrop C2.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: TeamCity Server Spawning Shell or Interpreter Process - CVE-2026-63077

### Detection Opportunity

Child shell or interpreter process spawned by the TeamCity JVM server process, indicating successful unauthenticated RCE via CVE-2026-63077

### Intelligence Context

- Rapid7: Rapid7 Analysis: Unauthenticated Remote Code Execution in JetBrains TeamCity (CVE-2026-63077) — [https://www.rapid7.com/blog/post/ra-unauthenticated-rce-in-jetbrains-teamcity-cve-2026-63077](https://www.rapid7.com/blog/post/ra-unauthenticated-rce-in-jetbrains-teamcity-cve-2026-63077)
  - Context: Rapid7 confirmed that an unauthenticated attacker reaching a TeamCity server over HTTP/HTTPS can exploit the agent polling protocol to execute OS commands with TeamCity process privileges. CISA added CVE-2026-63077 to KEV on August 5, 2026, confirming in-the-wild exploitation.

### Search Metadata

- CVEs: CVE-2026-63077
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: JetBrains TeamCity, XStream
- Platforms: Windows, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63077, T1190, T1059, JetBrains TeamCity, XStream, Windows, Linux

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (
    InitiatingProcessFileName in~ ("java.exe", "TeamCity.exe", "teamcity-server.exe")
    or InitiatingProcessFolderPath has_any ("\\TeamCity\\jre\\", "\\TeamCity\\bin\\", "/opt/teamcity/", "/usr/local/teamcity/")
)
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "sh", "bash", "dash", "ksh", "zsh",
    "python", "python3", "perl", "ruby"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- TeamCity build steps or plugins that legitimately invoke cmd.exe or powershell.exe from the server JVM process rather than from a build agent.
- Other Java applications co-hosted on the same server that spawn shells for legitimate administrative purposes.

**Tuning notes:**
- After initial deployment, review results for legitimate plugin-spawned processes and add them to a FileName or FolderPath exclusion.
- Consider scoping DeviceName to known TeamCity server hostnames using a watchlist or explicit list to reduce noise from other Java application servers in the environment.
- If TeamCity runs under a service account with a predictable AccountName, add that as an additional filter to tighten the detection.

**Risks / caveats:**
- InitiatingProcessFolderPath is available in DeviceProcessEvents on Defender for Endpoint but path-based filtering for TeamCity installation directories requires knowledge of the actual install path on monitored hosts; the query falls back to process name matching which is sufficient for initial detection.
- TeamCity installation path patterns in InitiatingProcessFolderPath must be validated against actual deployment paths in the environment; the query includes common defaults.
- Legitimate TeamCity server plugins that invoke shell interpreters directly from the JVM will generate false positives until a baseline exclusion list is established.
- On Linux hosts, Defender for Endpoint sensor coverage must be confirmed to ensure process parent-child relationships are captured for JVM-spawned processes.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process is the TeamCity JVM/server process and not a known build plugin or maintenance task.
- Review the child process command line, folder path, and account context for signs of command execution, download, or staging activity.
- Check whether the host is an internet-facing TeamCity server and whether the alert time aligns with suspicious inbound requests or other TeamCity alerts.
- Look for immediate follow-on activity from the same child process such as network connections, file writes, credential access, or additional process spawning.

**Evidence to collect:**
- Parent and child process command lines, hashes if available, and full process tree around the alert time.
- TeamCity server version, patch level, and whether CVE-2026-63077 mitigation or upgrade has been applied.
- Recent inbound web requests to the TeamCity host, especially to agent polling or plugin-related endpoints.
- Any files created or modified by the spawned process, plus outbound destinations contacted shortly after execution.

**Pivot points:**
- DeviceProcessEvents for the TeamCity host and parent process over the prior 24 hours.
- DeviceNetworkEvents for the same host to identify outbound connections from the spawned shell or interpreter.
- DeviceFileEvents for new or modified files in TeamCity install, temp, or web-accessible directories.
- Web/proxy/WAF logs for inbound requests to TeamCity around the alert timestamp.

**Benign explanations:**
- Legitimate TeamCity plugins or build steps may spawn cmd.exe, powershell.exe, sh, or bash from the server JVM.
- Administrative scripts launched by a trusted operator during maintenance may look similar if they run under the TeamCity service context.
- Other co-hosted Java applications on the same server may be misidentified if the installation path is nonstandard.

**Escalation criteria:**
- Any evidence of external exploitation, especially if the host is internet-facing and the child process executed commands beyond normal plugin behavior.
- Child process downloads, credential access, persistence changes, or outbound connections to untrusted destinations.
- Multiple TeamCity-related alerts on the same host or signs that the server spawned additional interpreters or service-control commands.
- Uncertainty about whether the child process is legitimate and no approved plugin or maintenance activity can explain it.

**Containment actions:**
- Isolate the TeamCity server from the network if there is evidence of active exploitation or follow-on malicious activity.
- Disable or restrict external access to TeamCity until patch status and exposure are validated.
- Preserve volatile evidence before rebooting or cleaning the host, including process tree, network connections, and relevant logs.
- If compromise is confirmed, rotate credentials and tokens accessible to the TeamCity server and review agent/build secrets.

**Closure criteria:**
- The child process is confirmed as a documented, approved TeamCity plugin or maintenance action and no suspicious follow-on activity is found.
- No external exploitation evidence exists in web logs, and the server is patched or otherwise not exposed to the vulnerable condition.
- Process tree, command line, and file/network activity are consistent with known benign administration.
- Any allowlist or tuning decision is documented with the exact plugin, path, or command pattern.

<br/>
---
<br/>

## Detection 2: Unauthenticated External Requests to TeamCity Agent Polling Endpoints - CVE-2026-63077

### Detection Opportunity

High-volume or anomalous unauthenticated HTTP/HTTPS requests from external IPs targeting TeamCity agent polling protocol endpoints, consistent with CVE-2026-63077 exploitation attempts

### Intelligence Context

- Rapid7: Rapid7 Analysis: Unauthenticated Remote Code Execution in JetBrains TeamCity (CVE-2026-63077) — [https://www.rapid7.com/blog/post/ra-unauthenticated-rce-in-jetbrains-teamcity-cve-2026-63077](https://www.rapid7.com/blog/post/ra-unauthenticated-rce-in-jetbrains-teamcity-cve-2026-63077)
  - Context: Rapid7 reported that exploitation requires only HTTP or HTTPS access to the TeamCity server and abuses the agent polling protocol without credentials. Network-level detection of anomalous inbound requests to TeamCity ports from external sources provides an early exploitation indicator.

### Search Metadata

- CVEs: CVE-2026-63077
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: JetBrains TeamCity, XStream
- Platforms: Windows, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63077, T1190, JetBrains TeamCity, XStream, Windows, Linux

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- RequestURL is not populated by all CEF log sources; many firewall and IDS vendors omit this field or populate it inconsistently, which would cause the RequestURL has_any filter to match nothing.
- If RequestURL is not populated by the upstream log source, the query will return no results; validate field population before relying on this detection.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationPort in (8111, 80, 443)
| where RequestURL has_any ("/app/agents", "/update/", "/plugins/", "/BSPRPCRegistrations.html")
| where SourceIP !startswith "10."
    and not (SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.")
    and SourceIP !startswith "192.168."
    and SourceIP !startswith "127."
    and SourceIP !startswith "169.254."
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    ResponseCodes = make_set(ResponseCode, 20)
    by SourceIP, DestinationPort, DeviceName
| where RequestCount > 5
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external TeamCity build agents polling from cloud provider IP ranges that fall outside RFC1918.
- Security scanners or vulnerability assessment tools targeting the TeamCity server from authorized external IPs.
- CDN or load balancer health checks that originate from non-RFC1918 addresses.

**Tuning notes:**
- Validate that CommonSecurityLog entries for the TeamCity host include non-empty RequestURL values before treating empty-result runs as clean.
- Adjust RequestCount threshold based on observed baseline traffic; environments with many external agents may need a threshold of 50 or higher.
- Consider adding a DestinationIP or DeviceName filter scoped to the TeamCity server to avoid matching unrelated appliances logging to the same CommonSecurityLog workspace.

**Risks / caveats:**
- CommonSecurityLog requires an upstream WAF, reverse proxy, or network security appliance to forward logs to Sentinel via the CEF connector; if no such appliance exists in front of TeamCity, this table will contain no relevant records.
- RequestURL is not populated by all CEF log sources; many firewall and IDS vendors omit this field or populate it inconsistently, which would cause the RequestURL has_any filter to match nothing.
- ResponseCode availability depends on the upstream device type; layer-4 firewalls typically do not log HTTP response codes.
- The RequestCount > 5 threshold is a starting point; baseline analysis of normal external agent polling volume is required before scheduling this as an alert.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is external and not a known build agent, scanner, CDN, or health-check source.
- Review the requested URLs, request rate, and response codes to determine whether the traffic is targeted and repetitive.
- Check whether the TeamCity server shows any concurrent process-spawn or file-write alerts that would indicate successful exploitation.
- Verify whether the TeamCity host is internet-facing and whether the vulnerable version or exposure path is still present.

**Evidence to collect:**
- Source IPs, request URLs, ports, response codes, and request counts for the alert window.
- WAF, reverse proxy, or web server logs showing the full request path and user agent if available.
- TeamCity version, exposure details, and any recent patch or configuration changes.
- Correlated host telemetry from the TeamCity server for process creation, file changes, and outbound connections.

**Pivot points:**
- CommonSecurityLog or equivalent web/proxy logs for the same source IPs and URLs over the prior 24 hours.
- DeviceProcessEvents on the TeamCity host for shell/interpreter spawns near the request times.
- DeviceNetworkEvents for outbound connections from the TeamCity server after the suspicious requests.
- Threat intel or firewall logs to determine whether the source IP belongs to an approved scanner or partner network.

**Benign explanations:**
- Authorized vulnerability scanners or security assessments may generate similar request patterns.
- Legitimate external build agents may poll TeamCity from cloud IP ranges if they are not yet allowlisted.
- Load balancer or CDN health checks can appear as repeated unauthenticated requests from non-RFC1918 addresses.

**Escalation criteria:**
- Requests target TeamCity polling endpoints repeatedly from an unknown external IP and are followed by host-side process execution or file changes.
- The TeamCity server is internet-facing, unpatched, and the request pattern matches known exploitation behavior.
- Multiple external IPs or a burst of requests indicate active exploitation attempts across the environment.
- Any evidence shows the same host also spawned shells, interpreters, or service-control commands after the requests.

**Containment actions:**
- Block the source IPs at the perimeter if they are not approved scanners or agents.
- Restrict or temporarily disable external access to TeamCity while validating exposure and patch status.
- If exploitation is suspected, isolate the TeamCity server and preserve logs before remediation.
- Notify infrastructure owners to verify whether any legitimate external agents need to be re-allowlisted after containment.

**Closure criteria:**
- The source IPs are confirmed as approved scanners, health checks, or legitimate build agents.
- Request patterns are consistent with normal baseline traffic and no host-side compromise indicators are present.
- The TeamCity server is patched or otherwise not vulnerable, and no suspicious follow-on activity is observed.
- Allowlist or threshold tuning is documented for the specific source ranges or request patterns.

<br/>
---
<br/>

## Detection 3: CI Runner Process Accessing Secret Environment Variables Followed by Outbound Network Connection - ChainDrop

### Detection Opportunity

CI runner process reading environment variables containing secret or token patterns and subsequently establishing outbound network connections, consistent with ChainDrop npm worm secret exfiltration behavior

### Intelligence Context

- Unit 42: ChainDrop: Inside a Self-Propagating npm Worm — [https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/)
  - Context: Unit 42 analysis of ChainDrop identified that the npm worm extracts GitHub Actions runner secrets from the CI runner environment and exfiltrates them. Detecting processes that enumerate secret-named environment variables and then make outbound connections provides a behavioral signal for this activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090
- Products: npm, GitHub Actions, Ethereum
- Platforms: Not specified
- Malware: ChainDrop
- Tools: Not specified
- Search tags: npm, GitHub Actions, Ethereum, ChainDrop, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1090 Proxy (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SecretEnum = DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "printenv",
    "$GITHUB_TOKEN",
    "$NPM_TOKEN",
    "$AWS_SECRET_ACCESS_KEY",
    "$AWS_SECRET",
    "$API_KEY",
    "$SECRET_KEY",
    "$TOKEN"
)
| project EnumTime = Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName;
let OutboundConns = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIP !startswith "10."
    and not (RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.")
    and RemoteIP !startswith "192.168."
    and RemoteIP !startswith "127."
    and RemoteIP !startswith "169.254."
| project NetTime = Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, NetInitiatingProcess = InitiatingProcessFileName;
SecretEnum
| join kind=inner OutboundConns on DeviceName
| where NetTime between (EnumTime .. (EnumTime + 5m))
| project
    EnumTime,
    NetTime,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    NetInitiatingProcess,
    RemoteIP,
    RemotePort,
    RemoteUrl
| order by EnumTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate CI pipeline steps that print or reference secret variable names in their command lines followed by outbound calls to package registries or artifact stores.
- Security scanning tools within CI pipelines that enumerate environment variables as part of secret detection checks.

**Tuning notes:**
- Scope DeviceName to a watchlist of known CI runner hostnames before running to reduce noise from developer workstations.
- After initial hunting runs, identify legitimate outbound destinations from CI runners and add them to a RemoteIP or RemoteUrl exclusion list.
- Consider narrowing the ProcessCommandLine filter to only the highest-signal indicators such as $GITHUB_TOKEN and $NPM_TOKEN if broader terms generate excessive noise.

**Risks / caveats:**
- RemoteUrl in DeviceNetworkEvents is frequently empty for HTTPS connections without TLS inspection enabled on the Defender for Endpoint sensor; detections relying on RemoteUrl for HTTPS traffic may miss connections.
- ProcessCommandLine may not capture environment variable expansion in all shell invocation contexts; variables passed via process environment block rather than command-line arguments will not be visible in this field.
- Command-line keyword matching for environment variable names generates significant false positives in active CI environments; analyst review of results is required before any scheduling decision.
- The 5-minute join window may be too narrow or too wide depending on pipeline execution timing; adjust based on observed pipeline behavior.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a known CI runner and identify the pipeline, job, and account associated with the process.
- Review the command line for explicit secret-variable references and whether the process is a shell, node, npm, or script wrapper.
- Check the outbound destination, port, and timing to see whether the connection is to an approved registry, artifact store, or suspicious external IP.
- Look for additional signs of secret theft such as archive creation, clipboard access, token use, or repeated outbound connections.

**Evidence to collect:**
- Process command line, parent process, and account context for the secret-enumerating process.
- Remote IP, port, URL, and any DNS or proxy logs for the outbound connection.
- CI job metadata, repository name, workflow name, and recent changes to pipeline definitions.
- Any evidence of environment variable dumping, log output containing secrets, or subsequent authentication attempts using the same account.

**Pivot points:**
- DeviceProcessEvents on the CI runner for environment-variable enumeration, shell wrappers, and archive or curl/wget activity.
- DeviceNetworkEvents for the same host to identify repeated or unusual outbound destinations.
- CI platform audit logs or job logs to identify the exact workflow step and whether it is expected.
- Proxy or DNS logs to determine whether the destination is a known package registry, artifact service, or untrusted endpoint.

**Benign explanations:**
- Legitimate CI jobs may reference secret variable names in scripts, templates, or debug output.
- Security scanning or secret-detection jobs may intentionally enumerate environment variables.
- Package installation, artifact upload, or dependency resolution can create outbound connections immediately after script execution.

**Escalation criteria:**
- The process is not part of an approved CI workflow or the job owner cannot explain the secret enumeration.
- Outbound traffic goes to an unapproved external destination or is followed by additional suspicious connections.
- Secrets appear in logs, artifacts, or downstream authentication activity is observed from the same runner or account.
- Multiple runners or repositories show the same pattern, suggesting worm-like propagation or shared compromise.

**Containment actions:**
- Pause or disable the affected CI job or runner if secret exposure or active exfiltration is suspected.
- Rotate any secrets that may have been exposed, starting with repository, deployment, and cloud credentials used by the runner.
- Restrict outbound network access from the runner to approved destinations if the environment allows it.
- Preserve job logs and runner state before cleanup if compromise is likely.

**Closure criteria:**
- The activity is confirmed as an approved CI or security-scanning workflow with no evidence of secret exposure.
- Outbound connections are to documented, approved destinations and match normal pipeline behavior.
- No suspicious follow-on authentication, exfiltration, or propagation is observed.
- The pipeline owner confirms the command line and timing are expected and the alert is tuned if needed.

<br/>
---
<br/>

## Detection 4: DeadLock Ransomware - Backup Service Termination Followed by Mass File Encryption

### Detection Opportunity

Process issuing commands to stop or delete backup and VSS services followed by rapid mass file modification events from the same initiating process, consistent with DeadLock ransomware pre-encryption preparation

### Intelligence Context

- Microsoft Security Blog: DeadLock ransomware: Breaking down a Rust-based encryptor with decentralized recovery infrastructure — [https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/)
  - Context: Microsoft Security Blog analysis of DeadLock ransomware identified a Rust-compiled encryptor that performs double extortion. The ransomware terminates backup and recovery services prior to encryption to prevent recovery. Correlating backup service termination commands with subsequent mass file modification events from the same host provides a high-confidence compound detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1489, T1486
- Products: Not specified
- Platforms: Rust
- Malware: DeadLock
- Tools: Not specified
- Search tags: DeadLock, Rust, T1489, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1489 Service Stop (high); Impact: T1486 Data Encrypted for Impact (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let BackupKill = DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wbadmin delete",
    "bcdedit /set recoveryenabled no",
    "bcdedit /set bootstatuspolicy",
    "net stop vss",
    "net stop backup",
    "net stop wbengine",
    "sc delete vss",
    "sc stop vss"
)
| project
    KillTime = Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    KillProcess = InitiatingProcessFileName,
    KillCmd = ProcessCommandLine;
let MassEncrypt = DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed", "FileModified", "FileCreated")
| summarize
    FileCount = count(),
    DistinctFolders = dcount(FolderPath),
    EncryptingProcess = any(InitiatingProcessFileName),
    EncryptingAccount = any(InitiatingProcessAccountName)
    by DeviceName, bin(Timestamp, 1m)
| where FileCount > 100 and DistinctFolders > 5
| project
    EncryptTime = Timestamp,
    DeviceName,
    FileCount,
    DistinctFolders,
    EncryptingProcess,
    EncryptingAccount;
BackupKill
| join kind=inner MassEncrypt on DeviceName
| where EncryptTime between (KillTime .. (KillTime + 10m))
| project
    KillTime,
    EncryptTime,
    DeviceName,
    AccountName,
    AccountDomain,
    KillProcess,
    KillCmd,
    FileCount,
    DistinctFolders,
    EncryptingProcess,
    EncryptingAccount
| order by KillTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents that legitimately stop VSS and then write large numbers of files during backup operations.
- Software deployment or patch management tools that stop services and then write many files during installation.
- Antivirus or EDR updates that generate high file modification rates across multiple directories.

**Tuning notes:**
- Validate ActionType string values 'FileRenamed', 'FileModified', and 'FileCreated' against actual DeviceFileEvents records in the environment before scheduling.
- Test FileCount threshold against backup agent and antivirus scan activity on representative hosts to establish a safe minimum threshold.
- Consider adding a FolderPath exclusion for known backup staging directories if backup agents generate high file write rates in predictable locations.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileRenamed', 'FileModified', and 'FileCreated' must be confirmed as valid ActionType strings in the target Defender for Endpoint deployment; 'FileModified' in particular may not be emitted in all sensor configurations or may appear as a different string.
- FileCount > 100 per minute and DistinctFolders > 5 are starting thresholds; environments with active backup agents or software deployment tools may require higher thresholds to suppress false positives.
- The 10-minute join window between backup termination and encryption onset may need extension if DeadLock variants introduce longer delays between stages.
- DeviceFileEvents volume during active ransomware encryption may cause ingestion delays that affect the time-bounded join accuracy.

### Triage Runbook

**First 15 minutes:**
- Treat the alert as likely ransomware until proven otherwise and identify the affected host, user, and process tree immediately.
- Confirm whether the service-stop commands targeted VSS, backup, or recovery services and whether they were executed by an expected admin tool.
- Check for concurrent mass file modifications, renames, or creations on the same host and whether the same process is responsible.
- Look for lateral movement indicators such as remote admin tools, new service creation, or suspicious authentication activity from the same account.

**Evidence to collect:**
- Process command line, parent process, account, and any related service-control events.
- File activity counts, affected folder paths, and the process responsible for the file changes.
- Recent network connections from the host, especially to command-and-control, file-sharing, or remote administration destinations.
- Backup status, snapshot status, and whether recent backups are intact and isolated.

**Pivot points:**
- DeviceProcessEvents for service-stop, bcdedit, wbadmin, vssadmin, sc.exe, and related commands on the host.
- DeviceFileEvents for rapid file modifications, renames, or creations across multiple directories.
- DeviceNetworkEvents for outbound connections from the encrypting process and any parent process.
- Identity and authentication logs for the same account to identify lateral movement or privilege escalation.

**Benign explanations:**
- Backup software, patching tools, or endpoint management tools may stop services and then write many files during maintenance.
- Some antivirus or EDR updates can generate high file modification rates across many directories.
- Administrative recovery tasks may use vssadmin or wbadmin, but they should be rare and well documented.

**Escalation criteria:**
- The same process or account both stops backup services and drives widespread file modification across multiple folders.
- File activity is still increasing or encryption is ongoing when the alert is reviewed.
- The host is a server or file share with business-critical data, or multiple hosts show similar behavior.
- There is any sign of lateral movement, credential theft, or remote execution associated with the same account.

**Containment actions:**
- Isolate the host from the network immediately if active encryption or propagation is suspected.
- Disable the compromised account or revoke active sessions if the account is not a dedicated service account with a clear benign explanation.
- Preserve volatile evidence and avoid rebooting unless required for containment or directed by incident response.
- Coordinate with backup owners to protect immutable or offline backups and verify restore points are unaffected.

**Closure criteria:**
- The service-stop and file activity are confirmed as a documented backup, patching, or deployment operation.
- No ongoing encryption, lateral movement, or suspicious outbound activity is found.
- The process tree and account context match an approved administrative workflow and the file activity is limited to expected paths.
- The host is restored or remediated and the detection is tuned if a known maintenance tool caused the alert.

<br/>
---
<br/>

## Detection 5: CI Runner Outbound Connection to Ethereum RPC Endpoints - ChainDrop C2

### Detection Opportunity

Outbound network connections from CI runner hosts to Ethereum JSON-RPC ports or known public Ethereum node infrastructure, consistent with ChainDrop npm worm using Ethereum smart contracts for C2 routing

### Intelligence Context

- Unit 42: ChainDrop: Inside a Self-Propagating npm Worm — [https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/)
  - Context: Unit 42 identified that ChainDrop uses Ethereum smart contracts for C2 routing, meaning infected CI runners will make outbound connections to Ethereum JSON-RPC endpoints. Connections to Ethereum RPC ports (8545, 8546) or public Ethereum node domains from CI runner infrastructure are anomalous and indicative of this C2 mechanism.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090
- Products: npm, GitHub Actions, Ethereum
- Platforms: Not specified
- Malware: ChainDrop
- Tools: Not specified
- Search tags: npm, GitHub Actions, Ethereum, ChainDrop, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1090 Proxy (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where (
    RemotePort in (8545, 8546)
    or RemoteUrl has_any (
        "infura.io",
        "alchemy.com",
        "etherscan.io",
        "cloudflare-eth.com",
        "ankr.com",
        "quiknode.pro",
        "blastapi.io"
    )
)
| where InitiatingProcessFileName in~ (
    "node", "node.exe",
    "npm", "npm.exe",
    "sh", "bash",
    "python", "python3",
    "pwsh.exe", "powershell.exe",
    "cmd.exe"
)
| where RemoteIP !startswith "10."
    and not (RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.")
    and RemoteIP !startswith "192.168."
    and RemoteIP !startswith "127."
    and RemoteIP !startswith "169.254."
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Blockchain development CI pipelines that legitimately deploy or test smart contracts using Ethereum RPC providers.
- Developer workstations enrolled in Defender for Endpoint that run Web3 development tooling.

**Tuning notes:**
- Scope DeviceName to a watchlist of known CI runner hostnames before scheduling to avoid false positives from developer workstations.
- Validate RemoteUrl field population for HTTPS connections in the environment; if empty, port-based detection on 8545/8546 is the only reliable signal.
- Add additional Ethereum RPC provider domains as the public node provider landscape evolves.

**Risks / caveats:**
- RemoteUrl in DeviceNetworkEvents is frequently empty for HTTPS connections on port 443 without TLS inspection; Ethereum RPC providers such as Infura and Alchemy serve traffic over HTTPS/443, meaning domain-based matching via RemoteUrl may produce no results for those connections.
- Connections to Ethereum RPC providers over HTTPS/443 will not be caught by the RemotePort in (8545, 8546) filter, creating a coverage gap for the most common production Ethereum RPC transport.
- Ethereum RPC connections over HTTPS/443 to providers such as Infura and Alchemy will only be detected if RemoteUrl is populated by the sensor; validate RemoteUrl field availability for HTTPS traffic in the environment.
- The initiating process filter is broad and includes common shell interpreters; scoping DeviceName to CI runner hosts is strongly recommended to reduce noise.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a CI runner and identify the job or process that initiated the connection.
- Review the destination IP, URL, and port to determine whether it is a known Ethereum RPC provider or an internal service.
- Check whether the repository or pipeline is related to blockchain, Web3, or smart contract testing.
- Look for companion indicators such as secret enumeration, unexpected package installation, or repeated outbound connections to the same RPC infrastructure.

**Evidence to collect:**
- Initiating process name and command line, plus the CI job or workflow that launched it.
- Remote IP, port, URL, and any DNS or proxy logs for the destination.
- Runner hostname, repository, and recent pipeline changes that may explain the connection.
- Any correlated process or file activity suggesting package execution, script download, or secret access.

**Pivot points:**
- DeviceNetworkEvents for the runner host to identify all outbound destinations around the alert time.
- DeviceProcessEvents for node, npm, shell, or script activity on the same host.
- CI platform logs to map the connection to a specific job step or repository.
- Proxy or DNS logs to confirm whether the destination is a known Ethereum RPC provider or an unexpected endpoint.

**Benign explanations:**
- Blockchain development, smart contract testing, or Web3 build pipelines may legitimately contact Ethereum RPC providers.
- Developer workstations or shared runners used for blockchain projects may generate expected RPC traffic.
- Some package or dependency workflows may indirectly contact public node providers during testing.

**Escalation criteria:**
- The runner is not associated with blockchain development and the destination is an Ethereum RPC provider or public node service.
- The connection is accompanied by secret enumeration, suspicious script execution, or other ChainDrop-like behavior.
- Multiple CI runners or repositories show the same outbound pattern without an approved business reason.
- The destination or process is not explainable by the job owner and the traffic is repeated or persistent.

**Containment actions:**
- Pause the affected CI job or runner if the connection is unexplained and appears malicious.
- Block or restrict the specific destination if it is not required for approved business use.
- Rotate any secrets used by the runner if there is evidence of broader compromise or secret access.
- Preserve job logs and network telemetry before making changes if the activity may be part of an active investigation.

**Closure criteria:**
- The connection is confirmed as part of an approved blockchain or Web3 workflow.
- The destination is a documented, approved Ethereum RPC provider and no other suspicious behavior is present.
- No secret enumeration, malicious package execution, or repeated anomalous connections are observed.
- The repository or runner is added to an allowlist or tuning note if the behavior is expected.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Unauthenticated External Requests to TeamCity Agent Polling Endpoints - CVE-2026-63077: RequestURL is not populated by all CEF log sources; many firewall and IDS vendors omit this field or populate it inconsistently, which would cause the RequestURL has_any filter to match nothing.
- Unauthenticated External Requests to TeamCity Agent Polling Endpoints - CVE-2026-63077: If RequestURL is not populated by the upstream log source, the query will return no results; validate field population before relying on this detection.
- CI Runner Process Accessing Secret Environment Variables Followed by Outbound Network Connection - ChainDrop: Do not schedule yet; validate as an analyst-led hunt first.
- CI Runner Outbound Connection to Ethereum RPC Endpoints - ChainDrop C2: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by TeamCity Server Spawning Shell or Interpreter Process - CVE-2026-63077; CI Runner Process Accessing Secret Environment Variables Followed by Outbound Network Connection - ChainDrop; DeadLock Ransomware - Backup Service Termination Followed by Mass File Encryption
- DeviceNetworkEvents: shared by CI Runner Process Accessing Secret Environment Variables Followed by Outbound Network Connection - ChainDrop; CI Runner Outbound Connection to Ethereum RPC Endpoints - ChainDrop C2

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: TeamCity Server Spawning Shell or Interpreter Process - CVE-2026-63077; DeadLock Ransomware - Backup Service Termination Followed by Mass File Encryption.
2. Resolve environment-mapping detections next: Unauthenticated External Requests to TeamCity Agent Polling Endpoints - CVE-2026-63077.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: CI Runner Process Accessing Secret Environment Variables Followed by Outbound Network Connection - ChainDrop; CI Runner Outbound Connection to Ethereum RPC Endpoints - ChainDrop C2.

### Hunting Agenda and Promotion Criteria

- CI Runner Process Accessing Secret Environment Variables Followed by Outbound Network Connection - ChainDrop: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CI Runner Outbound Connection to Ethereum RPC Endpoints - ChainDrop C2: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Unauthenticated External Requests to TeamCity Agent Polling Endpoints - CVE-2026-63077: RequestURL is not populated by all CEF log sources; many firewall and IDS vendors omit this field or populate it inconsistently, which would cause the RequestURL has_any filter to match nothing.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
