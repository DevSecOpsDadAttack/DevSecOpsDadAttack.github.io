---
layout: post
title: "Detection Engineering Brief - Saturday, September 12, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-12
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - SPIFFE
  - SPIRE
  - Kubernetes
  - CVE-2025-66516
  - CVE-2025-54988
  - T1190
  - Apache Tika
  - Metasploit
  - T1552.001
  - T1552
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

0 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: SPIFFE, SPIRE, Kubernetes, CVE-2025-66516, CVE-2025-54988, T1190, Apache Tika, Metasploit, T1552.001, T1552.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SPIRE Agent Socket or SVID File Access by Root Process on Kubernetes Node; Apache Tika XXE Exploitation Attempt via Suspicious XML Parsing Process; Metasploit Scanner Reconnaissance Against Apache Tika Endpoints (CVE-2025-54988 / CVE-2025-66516).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SPIRE Agent Socket or SVID File Access by Root Process on Kubernetes Node

### Detection Opportunity

Root-level process on a Kubernetes node accesses SPIRE agent socket paths or SVID-related files, consistent with post-exploitation harvesting of workload identities.

### Intelligence Context

- Unit 42: The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE — [https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/)
  - Context: Unit 42 reported that root access on a compromised Kubernetes node enables attackers to access SPIFFE/SPIRE metadata, spoof co-located workload identities, and harvest SVIDs for lateral movement.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552.001, T1552
- Products: SPIFFE, SPIRE
- Platforms: Kubernetes
- Malware: Not specified
- Tools: Not specified
- Search tags: SPIFFE, SPIRE, Kubernetes, T1552.001, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let SpirePaths = dynamic(["/run/spire/sockets", "/var/run/spire", "/tmp/spire-agent"]);
let SpireFilePatterns = dynamic([".svid", "spire-agent", "agent.sock"]);
let lookback = 1h;
let timeDeltaMinutes = 10;
let SuspiciousFileAccess = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileAccessed", "FileCreated", "FileModified")
| where InitiatingProcessAccountName == "root" or AccountName == "root"
| where FolderPath has_any (SpirePaths) or FileName has_any (SpireFilePatterns)
| project
    DeviceName,
    FileAccessTime = Timestamp,
    FilePath = FolderPath,
    FileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    FileAccountName = coalesce(InitiatingProcessAccountName, AccountName);
let RootProcesses = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where AccountName == "root"
| where ProcessCommandLine has_any (SpirePaths) or ProcessCommandLine has_any (SpireFilePatterns)
| project
    DeviceName,
    ProcessTime = Timestamp,
    ProcessCommandLine,
    ProcessFileName = FileName,
    ProcessId,
    ProcessAccountName = AccountName;
SuspiciousFileAccess
| join kind=inner RootProcesses on DeviceName, $left.InitiatingProcessId == $right.ProcessId
| where abs(datetime_diff('minute', FileAccessTime, ProcessTime)) <= timeDeltaMinutes
| project
    DeviceName,
    FileAccessTime,
    FilePath,
    FileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    ProcessCommandLine,
    ProcessFileName,
    FileAccountName
| order by FileAccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SPIRE agent self-access during startup, certificate rotation, or health checks running as root.
- Kubernetes node initialization scripts that touch SPIRE directories as part of cluster bootstrap.
- Security scanning tools running as root that enumerate certificate directories.

**Tuning notes:**
- Run in hunting mode against known-good nodes first to identify legitimate SPIRE agent self-access patterns before scheduling.
- If legitimate root processes routinely access SPIRE paths (e.g., during certificate rotation), add an exclusion on InitiatingProcessFileName for the known SPIRE agent binary name.
- Extend SpirePaths with any custom socket paths defined in your SPIRE server configuration (e.g., via agent.conf socket_path).
- Consider reducing lookback to 30 minutes for scheduled rule use to limit result volume.

**Risks / caveats:**
- DeviceFileEvents may not capture access events for Unix domain socket files (/run/spire/sockets/agent.sock) on Linux nodes depending on the Defender for Endpoint sensor configuration and kernel version; validate that socket-path file events appear in telemetry before relying on this query.
- The join on DeviceName without a shared process identifier (InitiatingProcessId) can produce cross-process false matches when multiple root processes run concurrently on the same node.
- SpirePaths and SpireFilePatterns must be updated to reflect the actual SPIRE socket and SVID storage paths used in the target Kubernetes deployment; default paths may not match custom configurations.
- The join on InitiatingProcessId assumes the file access is initiated by the same process captured in DeviceProcessEvents; if the SPIRE access occurs via a subprocess not separately logged, the join will produce no results.

### Triage Runbook

**First 15 minutes:**
- Confirm the node is a Kubernetes worker or control-plane host with SPIRE installed and identify the exact alerting process, command line, and timestamp.
- Check whether the process is the SPIRE agent itself, a known bootstrap/init script, or an unexpected root shell, scanner, or admin utility.
- Review recent privileged access on the node: SSH logins, sudo activity, break-glass use, container escape indicators, or newly started root processes.
- Correlate the file access with nearby process activity to see whether the same root process also enumerated /run/spire, /var/run/spire, or SVID-related files.

**Evidence to collect:**
- Alerting DeviceName, FilePath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, and AccountName.
- Any parent/child process ancestry around the alert time, especially shells, package managers, archive tools, or credential-dumping utilities.
- Kubernetes node access logs, SSH/auth logs, sudo logs, and any EDR telemetry showing root login or privilege escalation.
- SPIRE agent logs and workload registration logs to determine whether the access aligns with certificate rotation, startup, or health checks.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and time window to identify other root processes and suspicious command lines.
- DeviceFileEvents filtered to the same node and paths containing spire, svid, agent.sock, or related certificate files.
- Kubernetes audit logs or node authentication logs to identify who accessed the node before the alert.
- If available, container/runtime logs to determine whether the activity came from a host process or a container breakout.

**Benign explanations:**
- SPIRE agent self-access during startup, rotation, or health-check activity.
- Node bootstrap or cluster initialization scripts that touch SPIRE directories as part of provisioning.
- Legitimate security or inventory scanning tools running as root and enumerating certificate paths.

**Escalation criteria:**
- The process is not the SPIRE agent or a documented bootstrap utility and is reading or copying SVID-related files.
- There is evidence of recent unauthorized root access, suspicious shell activity, or container escape on the node.
- Multiple SPIRE-related files or sockets are accessed in a short period, especially by an interactive shell or unknown binary.
- The node hosts sensitive workloads and the access cannot be explained by a known maintenance window or approved change.

**Containment actions:**
- Isolate the Kubernetes node from the network if the process appears malicious or the node is suspected compromised.
- Revoke or rotate affected SPIRE-issued identities and any downstream credentials that may have been exposed.
- Terminate the suspicious root process and preserve volatile evidence before rebooting or reimaging the node.
- If compromise is confirmed, cordon/drain the node and investigate adjacent nodes for the same access pattern.

**Closure criteria:**
- The process is confirmed as the SPIRE agent or an approved maintenance/bootstrap component.
- SPIRE logs and node access records explain the access as expected operational behavior.
- No additional suspicious root activity, credential access, or lateral movement is found on the node.
- Any necessary exclusions or tuning are documented for the specific SPIRE deployment paths and binaries.

<br/>
---
<br/>

## Detection 2: Apache Tika XXE Exploitation Attempt via Suspicious XML Parsing Process

### Detection Opportunity

A process associated with Apache Tika parses XML content and spawns child processes or makes outbound network calls consistent with XML External Entity exploitation targeting local file read (CVE-2025-54988 / CVE-2025-66516).

### Intelligence Context

- Rapid7: Metasploit Wrap Up: This One Goes to Sixteen! — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen)
  - Context: Rapid7 reported that Metasploit added an auxiliary scanner and exploit module targeting CVE-2025-54988 and CVE-2025-66516, an XXE vulnerability in Apache Tika's XFA parser that allows local file read. The scanner produces recognizable HTTP request patterns against Tika endpoints.

### Search Metadata

- CVEs: CVE-2025-66516, CVE-2025-54988
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Apache Tika
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2025-66516, CVE-2025-54988, T1190, Apache Tika, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Both
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 6h;
let TikaShellSpawn = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has_any ("java") and InitiatingProcessCommandLine has "tika"
| where FileName in~ ("sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh.exe", "curl", "wget", "python", "python3", "perl", "ruby")
| project
    DeviceName,
    EventTime = Timestamp,
    DetectionBranch = "ChildProcessSpawn",
    ParentCmd = InitiatingProcessCommandLine,
    ChildProcess = FileName,
    ChildCmd = ProcessCommandLine,
    RemoteIP = "",
    RemotePort = int(null),
    AccountName;
let TikaAnomalousNetwork = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has_any ("java") and InitiatingProcessCommandLine has "tika"
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 8080, 8443)
| project
    DeviceName,
    EventTime = Timestamp,
    DetectionBranch = "AnomalousOutboundConnection",
    ParentCmd = InitiatingProcessCommandLine,
    ChildProcess = "",
    ChildCmd = "",
    RemoteIP,
    RemotePort,
    AccountName = InitiatingProcessAccountName;
union TikaShellSpawn, TikaAnomalousNetwork
| project
    DeviceName,
    EventTime,
    DetectionBranch,
    ParentCmd,
    ChildProcess,
    ChildCmd,
    RemoteIP,
    RemotePort,
    AccountName
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Tika integrations that spawn shell scripts for post-processing parsed documents.
- Java-based Tika deployments that make outbound connections to internal document storage or metadata services on non-standard ports.
- Development or test environments where Tika is invoked interactively from a shell, causing the shell itself to appear as a child process.

**Tuning notes:**
- Validate that 'tika' appears in InitiatingProcessCommandLine for all Tika service instances in the environment before relying on this filter.
- Add known legitimate child processes or outbound destinations to exclusion filters after baselining normal Tika behavior.
- Consider adding InitiatingProcessParentFileName checks if Tika is always launched from a specific parent (e.g., systemd, supervisord) to further narrow scope.
- For scheduled rule promotion, split into two separate rules (one per DetectionBranch) with independent thresholds and suppression logic.

**Risks / caveats:**
- InitiatingProcessCommandLine may not contain 'tika' if Apache Tika is launched via a wrapper script, systemd unit, or container entrypoint that does not pass the jar name in the command line; this would cause the query to produce no results for those deployments.
- If Apache Tika is launched without 'tika' appearing in the Java process command line (e.g., via a fat-jar with a different main class name or a wrapper), neither branch will fire; validate command line patterns for the specific deployment.
- The network branch port exclusion list (80, 443, 8080, 8443) may need expansion if Tika legitimately connects to internal services on other ports, which would generate false positives.
- The 6-hour lookback window is appropriate for hunting but should be reduced to 1 hour if promoted to a scheduled rule to limit result volume.

### Triage Runbook

**First 15 minutes:**
- Identify the host, parent Java/Tika process, child process name, command line, and whether the alert fired on child spawning or outbound network activity.
- Check whether the Tika instance is internet-facing, recently patched, or running in a test/dev environment where interactive use is expected.
- Review the child process or network destination for signs of exploitation, such as shells, curl/wget, unexpected interpreters, or connections to unusual ports or hosts.
- Look for repeated failures, unusual XML uploads, or a burst of requests around the same time that would support active probing or exploitation.

**Evidence to collect:**
- DeviceName, ParentCmd, ChildProcess, ChildCmd, RemoteIP, RemotePort, AccountName, and the exact EventTime from the alert.
- Process ancestry for the Java/Tika service to determine how it was launched and whether the command line is normal for that deployment.
- Network telemetry showing the destination IPs, ports, and whether the connection was internal service traffic or an external callback.
- Application logs, Tika logs, reverse proxy logs, and any uploaded document metadata around the alert time.

**Pivot points:**
- DeviceProcessEvents on the same host and time window to find additional child processes spawned by the Tika parent.
- DeviceNetworkEvents for the Tika process to identify other outbound connections, especially to unusual ports or non-approved destinations.
- Web server, reverse proxy, or application logs for XML uploads, parsing errors, or repeated requests to Tika endpoints.
- If available, file or container logs to determine whether the Tika service recently handled suspicious XML/XFA content.

**Benign explanations:**
- Legitimate Tika integrations that spawn shell scripts or helper tools for post-processing parsed documents.
- Development, QA, or admin use where Tika is launched interactively and child shells appear as expected.
- Normal outbound connections to internal document repositories, metadata services, or update endpoints on non-standard ports.

**Escalation criteria:**
- A shell, interpreter, or download utility is spawned by the Tika process without a documented business reason.
- Outbound connections go to unusual external IPs or ports that do not match approved Tika dependencies.
- The host is internet-facing and logs show repeated XML parsing attempts or suspicious document submissions.
- There is evidence of file read attempts, command execution, or follow-on activity beyond normal document processing.

**Containment actions:**
- If exploitation is likely, isolate the Tika host or container from the network to stop further probing or callback activity.
- Block the source IPs or suspicious destinations at the proxy/WAF if they are clearly malicious and externally sourced.
- Restart or disable the affected Tika service only after preserving logs and memory if possible, and coordinate with the service owner.
- Patch or upgrade Apache Tika and any exposed front-end components once the incident is contained.

**Closure criteria:**
- The child process or network activity is confirmed as expected Tika behavior or approved integration traffic.
- No evidence of XML XXE exploitation, file read, or malicious callback behavior is found in logs or telemetry.
- The service owner validates the process launch pattern and destination traffic as normal for the deployment.
- Any required tuning is documented, including known child processes or approved outbound destinations.

<br/>
---
<br/>

## Detection 3: Metasploit Scanner Reconnaissance Against Apache Tika Endpoints (CVE-2025-54988 / CVE-2025-66516)

### Detection Opportunity

Repeated HTTP requests with XML content targeting Apache Tika API endpoints from a single external source, consistent with Metasploit auxiliary scanner activity probing for the XFA XXE vulnerability.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: This One Goes to Sixteen! — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen)
  - Context: Rapid7 reported that Metasploit added an auxiliary scanner module for CVE-2025-54988/CVE-2025-66516 that produces recognizable scanning patterns of repeated HTTP requests to Apache Tika endpoints with XML content-type, enabling detection via network and WAF telemetry.

### Search Metadata

- CVEs: CVE-2025-66516, CVE-2025-54988
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Apache Tika
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2025-66516, CVE-2025-54988, T1190, Apache Tika, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let requestThreshold = 10;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestURL has_any ("/tika", "/meta", "/detect", "/unpack")
| where AdditionalExtensions has_any ("xml", "application/xml", "text/xml") or RequestURL has "xml"
| where SourceIP !startswith "10."
    and SourceIP !startswith "172.16."
    and SourceIP !startswith "172.17."
    and SourceIP !startswith "172.18."
    and SourceIP !startswith "172.19."
    and SourceIP !startswith "172.20."
    and SourceIP !startswith "172.21."
    and SourceIP !startswith "172.22."
    and SourceIP !startswith "172.23."
    and SourceIP !startswith "172.24."
    and SourceIP !startswith "172.25."
    and SourceIP !startswith "172.26."
    and SourceIP !startswith "172.27."
    and SourceIP !startswith "172.28."
    and SourceIP !startswith "172.29."
    and SourceIP !startswith "172.30."
    and SourceIP !startswith "172.31."
    and SourceIP !startswith "192.168."
    and SourceIP !startswith "127."
| summarize
    RequestCount = count(),
    TargetedPaths = make_set(RequestURL, 50),
    DestPorts = make_set(DestinationPort),
    Actions = make_set(DeviceAction),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP
| where RequestCount >= requestThreshold
| extend AlertDetail = strcat("Source ", SourceIP, " sent ", RequestCount, " XML requests to Tika endpoints within ", lookback)
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    RequestCount,
    TargetedPaths,
    DestPorts,
    Actions,
    AlertDetail
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized penetration testing or vulnerability scanning from external assessment teams.
- Legitimate API integration clients that batch-submit many XML documents to Tika endpoints in short windows.
- Internal health-check or monitoring systems that probe Tika endpoints repeatedly if RFC1918 exclusion is removed.

**Tuning notes:**
- After identifying the specific WAF or IDS vendor feeding CommonSecurityLog, add a where DeviceVendor == '<vendor>' filter to restrict results to the relevant log source and reduce cross-source noise.
- Baseline normal request rates from known API integration clients and add their source IPs to an exclusion list using a where SourceIP !in (known_clients) clause.
- Validate that AdditionalExtensions contains content-type data by running: CommonSecurityLog → where RequestURL has '/tika' → take 20 → project AdditionalExtensions and inspecting the field format.
- If the WAF logs HTTP request body content-type in a dedicated field (e.g., RequestContext or a custom extension), replace the AdditionalExtensions filter with the appropriate field reference.

**Risks / caveats:**
- CommonSecurityLog requires an active CEF-compatible connector (WAF, IDS, or reverse proxy) forwarding logs to the Sentinel workspace; if no such connector is configured, the table will be empty.
- The AdditionalExtensions field is a vendor-specific free-text blob in CEF format; the has_any filter for 'xml' content-type strings may not match the actual key-value encoding used by the specific WAF or IDS vendor, causing the content-type branch to produce no results.
- RequestURL population in CommonSecurityLog is not guaranteed for all CEF sources; some WAF or IDS vendors log only destination IP and port without HTTP-layer URL data, which would prevent Tika endpoint path matching.
- The AdditionalExtensions content-type filter depends on the specific CEF key name used by the WAF or IDS vendor; validate that content-type data appears in AdditionalExtensions as 'xml', 'application/xml', or 'text/xml' strings in the actual log format before relying on this branch.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, targeted URL paths, destination port, and request volume to determine whether this is a one-off test or sustained scanning.
- Check whether the source is an approved vulnerability scanner, penetration test host, or a known partner network.
- Determine whether the Tika service is internet-facing and whether the requests reached the application or were blocked by a WAF/reverse proxy.
- Look for signs of exploitation beyond reconnaissance, such as repeated XML payloads, error responses, or follow-on requests from the same source.

**Evidence to collect:**
- SourceIP, RequestCount, TargetedPaths, DestPorts, Actions, FirstSeen, and LastSeen from the alert.
- WAF, reverse proxy, or IDS logs showing request headers, response codes, and any XML content-type indicators.
- Application logs from the Tika service to confirm whether the requests were received, blocked, or caused parsing errors.
- Asset context for the destination host, including exposure to the internet, patch level, and service owner.

**Pivot points:**
- CommonSecurityLog for the same SourceIP to see whether the scanner touched other services or ports.
- Web server or reverse proxy logs for the same targeted paths to confirm request content and response behavior.
- Threat intel or internal allowlists to determine whether the source IP belongs to an authorized scanner or assessment team.
- If available, firewall logs to see whether the traffic was blocked before reaching the application.

**Benign explanations:**
- Authorized penetration testing or vulnerability scanning from an approved external assessment source.
- Legitimate API clients or integrations that batch-submit many XML documents to Tika endpoints.
- Security validation activity from a managed scanner that was not properly allowlisted in the detection logic.

**Escalation criteria:**
- The source is external, not approved, and sends repeated XML requests to Tika endpoints in a short window.
- The target is internet-facing and the requests are reaching the application or generating parsing errors.
- There is evidence of follow-on exploitation attempts, unusual response patterns, or multiple targeted paths consistent with active probing.
- The same source IP is observed scanning other public-facing services or returning after blocks.

**Containment actions:**
- Block or rate-limit the source IP at the WAF, reverse proxy, or firewall if the traffic is clearly malicious.
- If the Tika service is exposed and unpatched, prioritize emergency patching or temporary access restriction.
- Notify the service owner and network team to monitor for additional probes or exploitation attempts.
- If exploitation is suspected, preserve logs before making major configuration changes.

**Closure criteria:**
- The source is confirmed as an approved scanner, test host, or benign client and the activity matches expected behavior.
- The target service is not exposed or the requests were blocked before reaching the application.
- No evidence of exploitation, error-based leakage, or follow-on malicious activity is found.
- Any allowlist, threshold, or vendor-specific parsing adjustments are documented for the Sentinel rule.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- SPIRE Agent Socket or SVID File Access by Root Process on Kubernetes Node: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- Apache Tika XXE Exploitation Attempt via Suspicious XML Parsing Process: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Metasploit Scanner Reconnaissance Against Apache Tika Endpoints (CVE-2025-54988 / CVE-2025-66516): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by SPIRE Agent Socket or SVID File Access by Root Process on Kubernetes Node; Apache Tika XXE Exploitation Attempt via Suspicious XML Parsing Process

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: SPIRE Agent Socket or SVID File Access by Root Process on Kubernetes Node; Metasploit Scanner Reconnaissance Against Apache Tika Endpoints (CVE-2025-54988 / CVE-2025-66516).
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Apache Tika XXE Exploitation Attempt via Suspicious XML Parsing Process.

### Hunting Agenda and Promotion Criteria

- Apache Tika XXE Exploitation Attempt via Suspicious XML Parsing Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- SPIRE Agent Socket or SVID File Access by Root Process on Kubernetes Node: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Metasploit Scanner Reconnaissance Against Apache Tika Endpoints (CVE-2025-54988 / CVE-2025-66516): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
