---
layout: post
title: "Detection Engineering Brief - Monday, August 3, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-03
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Xcode
  - macOS
  - XCSSET
  - Kaspersky Anti Targeted Attack
  - KATA
  - network
  - T1059
  - T1059.004
  - T1059.006
  - T1071
  - T1071.004
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 0 hunting-only, 3 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 1 include triage guidance.

Search metadata extracted for this run includes: Xcode, macOS, XCSSET, Kaspersky Anti Targeted Attack, KATA, network, T1059, T1059.004, T1059.006, T1071, T1071.004.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: XCSSET - Suspicious File Write Into Xcode Project Directory by Non-Xcode Process; XCSSET - Shell or Script Interpreter Spawned by Xcode with Suspicious Arguments; DNS Tunneling - High-Frequency Queries with Long Subdomains to a Single Domain.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: XCSSET - Suspicious File Write Into Xcode Project Directory by Non-Xcode Process

### Detection Opportunity

XCSSET malware injects malicious files into Xcode project directories from processes other than Xcode itself on macOS developer endpoints.

### Intelligence Context

- Unit 42: The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version — [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
  - Context: Unit 42 analysis of XCSSET v40 confirmed the malware targets macOS developers by injecting into Xcode projects. File writes into .xcodeproj directories by non-Xcode processes are a primary indicator of this injection behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1059.006
- Products: Xcode
- Platforms: macOS
- Malware: XCSSET
- Tools: Not specified
- Search tags: Xcode, macOS, XCSSET, T1059, T1059.004, T1059.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: Not specified
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let xcode_writers = dynamic(["Xcode", "xcodebuild", "xcrun", "swift", "clang", "ld", "swiftc", "libtool", "ar", "dsymutil", "codesign", "actool", "ibtool", "copypng", "ditto"]);
let suspicious_writes = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (".xcodeproj", ".xcworkspace")
| where ActionType in ("FileCreated", "FileModified")
| where not(InitiatingProcessName has_any (xcode_writers))
| project
    WriteTime = Timestamp,
    DeviceId,
    DeviceName,
    FolderPath,
    FileName,
    InitiatingProcessName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    AccountName;
let follow_on_exec = DeviceProcessEvents
| where Timestamp > ago(7d)
| project
    ExecTime = Timestamp,
    DeviceId,
    ExecProcess = FileName,
    ExecCommandLine = ProcessCommandLine,
    ExecInitiatingProcess = InitiatingProcessName,
    ExecFolderPath = FolderPath,
    ExecSHA256 = SHA256;
suspicious_writes
| join kind=inner follow_on_exec on DeviceId
| where ExecTime between (WriteTime .. (WriteTime + 5m))
| where ExecCommandLine has FolderPath or ExecFolderPath has FolderPath
| project
    WriteTime,
    ExecTime,
    DeviceName,
    AccountName,
    FolderPath,
    FileName,
    SuspiciousWriter = InitiatingProcessName,
    InitiatingProcessCommandLine,
    ExecProcess,
    ExecCommandLine,
    ExecSHA256
| order by WriteTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CI/CD automation tools (e.g., Fastlane, Bazel, Buck) that write into Xcode project directories as part of legitimate build orchestration.
- IDE plugins or extensions (e.g., AppCode, VS Code with Swift extension) that modify project files.
- Source control clients (e.g., git, Sourcetree) writing merge or conflict resolution files into .xcodeproj directories.
- Package managers (e.g., CocoaPods, Swift Package Manager) that modify .xcworkspace files during dependency resolution.

**Tuning notes:**
- Extend xcode_writers with CI/CD and package manager process names observed in the environment (e.g., 'fastlane', 'pod', 'bazel', 'buck', 'ruby', 'python3' if used for build scripting).
- If the FolderPath overlap join filter produces no results due to path format differences, relax it to a broader time-window-only join and add analyst review as a compensating control.
- Consider scoping DeviceName to known developer workstation groups using a watchlist or device tag filter to reduce noise from non-developer endpoints.

**Risks / caveats:**
- DeviceFileEvents macOS coverage requires MDE macOS sensor version that supports file event telemetry; this is not universally available and must be confirmed before the query will return results.
- ActionType values 'FileCreated' and 'FileModified' must be confirmed as populated for macOS endpoints in the target environment's DeviceFileEvents schema; macOS sensor versions vary in supported ActionType values.
- The 5-minute follow-on execution window may miss delayed payload execution; analysts should manually extend the window during active investigations.
- The xcode_writers exclusion list requires baselining against the specific environment's build toolchain to avoid both false positives and false negatives.

### Triage Runbook

**First 15 minutes:**
- Review alert entities and projected fields.
- Confirm whether the account, host, IP, process, file, or URL is expected.
- Check recent activity for the same entity in Sentinel or Defender XDR.

**Evidence to collect:**
- Alert evidence.
- Related sign-in, process, file, network, or audit events.

**Pivot points:**
- Relevant identity, endpoint, file, network, and audit tables.

**Benign explanations:**
- Authorized administrative activity.
- Known automation, deployment, backup, sync, or security tooling.

**Escalation criteria:**
- Unauthorized, repeated, externally sourced, privileged, or critical-asset activity.

**Containment actions:**
- Do not contain automatically. Contain only after analyst validation.

**Closure criteria:**
- Close only when the behavior is confirmed benign and documented.

<br/>
---
<br/>

## Detection 2: XCSSET - Shell or Script Interpreter Spawned by Xcode with Suspicious Arguments

### Detection Opportunity

XCSSET executes malicious shell or Python scripts from within Xcode build phases, causing Xcode to spawn script interpreters with unusual command-line arguments.

### Intelligence Context

- Unit 42: The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version — [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
  - Context: Unit 42 analysis confirmed XCSSET executes malicious scripts embedded in Xcode project build phases. This causes Xcode or xcodebuild to spawn shell or Python interpreters, a behavior distinct from normal compilation activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1059.006
- Products: Xcode
- Platforms: macOS
- Malware: XCSSET
- Tools: Not specified
- Search tags: Xcode, macOS, XCSSET, T1059, T1059.004, T1059.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: Not specified
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessName in~ ("Xcode", "xcodebuild")
| where FileName in~ ("bash", "sh", "zsh", "python", "python3", "perl", "ruby")
| where ProcessCommandLine has_any (
    "curl",
    "wget",
    "base64",
    "/tmp/",
    "/var/tmp/",
    "eval",
    "osascript",
    "launchctl",
    "mktemp",
    "nohup",
    "chmod +x",
    "chown"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    SpawnedInterpreter = FileName,
    ProcessCommandLine,
    SHA256,
    FolderPath,
    ProcessId,
    InitiatingProcessName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessParentName
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate build scripts that use curl to download build dependencies or SDKs (e.g., downloading CocoaPods specs, fetching build artifacts).
- Build phases that use base64 for encoding embedded resources or certificates.
- Scripts that write to /tmp/ as part of legitimate build artifact staging.
- osascript invocations used for legitimate build notifications or UI automation in developer workflows.

**Tuning notes:**
- After baselining, consider requiring two or more suspicious keywords to co-occur in ProcessCommandLine to reduce single-keyword false positives.
- Scope to specific device groups or AccountName patterns corresponding to developer workstations to reduce noise from non-developer endpoints.
- If launchctl appears frequently in legitimate build output, remove it from the keyword list and track it separately as a persistence indicator.

**Risks / caveats:**
- InitiatingProcessName accuracy for Xcode-spawned child processes on macOS depends on MDE sensor version; some macOS sensor versions do not reliably populate parent process fields for GUI application children.
- DeviceProcessEvents macOS coverage requires MDE macOS sensor deployment; absence of macOS-sourced records will cause the query to return no results silently.
- Legitimate build scripts using curl for dependency downloads will generate false positives; an allowlist of known-good command-line patterns should be built from environment baseline before scheduling.
- The keyword list is intentionally broad for hunting; narrowing to combinations (e.g., base64 AND /tmp/) would reduce noise but may miss novel XCSSET variants.

### Triage Runbook

**First 15 minutes:**
- Review alert entities and projected fields.
- Confirm whether the account, host, IP, process, file, or URL is expected.
- Check recent activity for the same entity in Sentinel or Defender XDR.

**Evidence to collect:**
- Alert evidence.
- Related sign-in, process, file, network, or audit events.

**Pivot points:**
- Relevant identity, endpoint, file, network, and audit tables.

**Benign explanations:**
- Authorized administrative activity.
- Known automation, deployment, backup, sync, or security tooling.

**Escalation criteria:**
- Unauthorized, repeated, externally sourced, privileged, or critical-asset activity.

**Containment actions:**
- Do not contain automatically. Contain only after analyst validation.

**Closure criteria:**
- Close only when the behavior is confirmed benign and documented.

<br/>
---
<br/>

## Detection 3: Kerberoasting - High Volume RC4 TGS Requests from Single Account

### Detection Opportunity

Kerberoasting attack generates an anomalous volume of Kerberos TGS service ticket requests using RC4 encryption from a single account, targeting multiple service principals.

### Intelligence Context

- Securelist: Network Anomaly Detection in KATA — [https://securelist.com/tr/network-anomaly-detection-in-kata/120892/](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)
  - Context: The article uses Kerberoasting as a concrete detection example within KATA's network anomaly detection framework, describing how anomalous TGS request patterns with RC4 encryption are used to identify the attack. This maps directly to Windows Security Event 4769 with RC4 ticket encryption type.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.004
- Products: Kaspersky Anti Targeted Attack, KATA
- Platforms: network
- Malware: Not specified
- Tools: Not specified
- Search tags: Kaspersky Anti Targeted Attack, KATA, network, T1071, T1071.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: Not specified
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| where AccountName != "krbtgt"
| where isnotempty(IpAddress) and IpAddress != "::1" and IpAddress != "127.0.0.1"
| summarize
    RequestCount = count(),
    DistinctServices = dcount(ServiceName),
    ServiceList = make_set(ServiceName, 20),
    SourceIPs = make_set(IpAddress, 5),
    DomainControllers = make_set(Computer, 5)
    by AccountName, bin(TimeGenerated, 1h)
| where DistinctServices >= 5
| project
    TimeGenerated,
    AccountName,
    RequestCount,
    DistinctServices,
    ServiceList,
    SourceIPs,
    DomainControllers
| order by DistinctServices desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Vulnerability scanners or security assessment tools that enumerate SPNs as part of authorized penetration testing.
- Service accounts that legitimately authenticate to many services simultaneously (e.g., monitoring agents, backup agents); these should be added to an exclusion list after baselining.
- Automated deployment or provisioning systems that request TGS tickets for multiple services during rollout windows.

**Tuning notes:**
- Increase DistinctServices threshold to 10 or higher in environments where service accounts legitimately authenticate to many services.
- Add an AccountName exclusion list (e.g., via a Sentinel watchlist) for known high-volume service accounts after baselining.
- Consider adding a TicketEncryptionType == '0x12' (AES256) variant with a higher threshold to catch AES-based Kerberoasting against accounts that do not support RC4.
- Schedule the rule to run every 60 minutes with a lookback of 70 minutes to account for ingestion delay and avoid alert gaps.

**Risks / caveats:**
- EventID 4769 requires Advanced Audit Policy 'Audit Kerberos Service Ticket Operations' to be enabled on domain controllers and logs forwarded to Sentinel via the Windows Security Events connector or AMA; if this audit category is not enabled, the query will return no results.
- TicketEncryptionType in the SecurityEvent table is parsed from the raw event XML; the field may be absent or null if the Windows Security Events connector version does not parse this field. Confirm the field is populated before scheduling.
- The DistinctServices threshold of 5 per hour may fire on legitimate service accounts in environments with high service ticket activity; baselining against domain controller logs is recommended before scheduling.
- The 1-hour lookback window in a scheduled rule context means the rule should be scheduled to run every hour with a 1-hour lookback to avoid gaps or duplicate alerts; ingestion delay should be accounted for by adding a small buffer (e.g., ago(70m)).

### Triage Runbook

**First 15 minutes:**
- Review alert entities and projected fields.
- Confirm whether the account, host, IP, process, file, or URL is expected.
- Check recent activity for the same entity in Sentinel or Defender XDR.

**Evidence to collect:**
- Alert evidence.
- Related sign-in, process, file, network, or audit events.

**Pivot points:**
- Relevant identity, endpoint, file, network, and audit tables.

**Benign explanations:**
- Authorized administrative activity.
- Known automation, deployment, backup, sync, or security tooling.

**Escalation criteria:**
- Unauthorized, repeated, externally sourced, privileged, or critical-asset activity.

**Containment actions:**
- Do not contain automatically. Contain only after analyst validation.

**Closure criteria:**
- Close only when the behavior is confirmed benign and documented.

<br/>
---
<br/>

## Detection 4: DNS Tunneling - High-Frequency Queries with Long Subdomains to a Single Domain

### Detection Opportunity

DNS tunneling encodes data within DNS query subdomains, producing unusually long subdomain strings and high query frequency to a single parent domain for C2 or data exfiltration.

### Intelligence Context

- Securelist: Network Anomaly Detection in KATA — [https://securelist.com/tr/network-anomaly-detection-in-kata/120892/](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)
  - Context: The article uses DNS tunneling as a concrete detection example in KATA's network anomaly detection framework, describing how high query rates and long subdomain lengths are reliable behavioral signatures for identifying DNS-based C2 and exfiltration channels.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.004
- Products: Kaspersky Anti Targeted Attack, KATA
- Platforms: network
- Malware: Not specified
- Tools: Not specified
- Search tags: Kaspersky Anti Targeted Attack, KATA, network, T1071, T1071.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (high)

### Deployment Gates

- DnsEvents table requires a DNS data connector to be configured in Sentinel (Windows DNS Debug Logs connector, Syslog-based DNS sensor, or equivalent); this table is not populated by default and its absence will cause the query to return no results.
- DnsEvents table availability must be confirmed before running; the query will silently return no results if the connector is not configured.

**Required telemetry:**
- DnsEvents

### KQL

```kql
let known_cdn_parents = dynamic([
    "akamaiedge.net", "akamaitechnologies.com", "cloudfront.net",
    "amazonaws.com", "azureedge.net", "fastly.net", "edgekey.net"
]);
DnsEvents
| where TimeGenerated > ago(1d)
| where isnotempty(QueryName)
| where not(QueryName has_any (known_cdn_parents))
| extend Labels = split(QueryName, ".")
| extend LabelCount = array_length(Labels)
| where LabelCount >= 3
| mv-apply Label = Labels to typeof(string) on (
    summarize MaxLabelLength = max(strlen(Label))
)
| where MaxLabelLength > 40
| extend ParentDomain = strcat(
    tostring(Labels[LabelCount - 2]),
    ".",
    tostring(Labels[LabelCount - 1])
)
| summarize
    QueryCount = count(),
    DistinctSubdomains = dcount(QueryName),
    MaxLabelLength = max(MaxLabelLength),
    SampleQueries = make_set(QueryName, 5)
    by Computer, ClientIP, ParentDomain, bin(TimeGenerated, 1h)
| where QueryCount >= 20 and DistinctSubdomains >= 10
| project
    TimeGenerated,
    Computer,
    ClientIP,
    ParentDomain,
    QueryCount,
    DistinctSubdomains,
    MaxLabelLength,
    SampleQueries
| order by QueryCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CDN providers (Akamai, CloudFront, Fastly) that use long subdomain labels for routing or token-based URLs.
- Analytics and telemetry platforms that encode session or device identifiers in DNS query subdomains.
- Software update mechanisms that use long subdomain labels for version or device fingerprint encoding.
- Internal applications that use DNS for service discovery with long generated hostnames.

**Tuning notes:**
- Extend known_cdn_parents with any additional CDN, analytics, or telemetry domains observed in the environment's DNS baseline.
- Adjust QueryCount and DistinctSubdomains thresholds based on DNS query volume baselines; consider running the hunting query for 7 days before converting to a scheduled rule.
- Add a QueryType filter (e.g., QueryType in ('A', 'AAAA', 'TXT', 'CNAME')) if the DNS connector populates this field, to focus on query types most commonly used in tunneling.
- Consider adding a Shannon entropy calculation on the longest label as an additional filter for high-confidence scheduling; this requires a custom function or extended KQL logic.

**Risks / caveats:**
- DnsEvents table requires a DNS data connector to be configured in Sentinel (Windows DNS Debug Logs connector, Syslog-based DNS sensor, or equivalent); this table is not populated by default and its absence will cause the query to return no results.
- The DnsEvents schema field names vary by connector source; 'ClientIP' and 'Computer' are standard for the Windows DNS connector but may differ for third-party DNS log sources. The original query referenced 'DeviceName' and 'RemoteIP' which are not standard DnsEvents fields for the Windows DNS connector.
- QueryName field population depends on DNS debug logging being enabled on DNS servers; if only query logging is enabled without full debug mode, QueryName may be empty or inconsistently populated.
- DnsEvents table availability must be confirmed before running; the query will silently return no results if the connector is not configured.

### Triage Runbook

**First 15 minutes:**
- Identify the client IP, host, and parent domain and determine whether the domain is business-related, a CDN, or an external unknown domain.
- Review sample queries to assess whether the subdomains look encoded, randomized, or repetitive in a way that suggests tunneling.
- Check whether the host is a server, workstation, or DNS infrastructure device and whether the volume is abnormal for that role.
- Look for concurrent signs of malware activity on the host, including suspicious processes, persistence, or unusual outbound connections.
- If the domain is unknown and the query pattern is clearly encoded or repetitive, escalate as likely malicious DNS tunneling.

**Evidence to collect:**
- TimeGenerated, Computer, ClientIP, ParentDomain, QueryCount, DistinctSubdomains, MaxLabelLength, and SampleQueries from the alert.
- Full DNS query logs for the same host and time window to confirm frequency, label length, and query types.
- Endpoint process telemetry for the client host to identify the process generating the DNS traffic.
- Any associated network connections to the same parent domain or related infrastructure.
- Whether the domain is owned by the organization, a vendor, or a known CDN/telemetry service.

**Pivot points:**
- DnsEvents for the same ClientIP and ParentDomain over the prior 24 hours to establish baseline and scope.
- DeviceProcessEvents for the same host and time window to identify the process responsible for the DNS lookups.
- DeviceNetworkEvents for the same host to identify outbound connections that may accompany the DNS traffic.
- Threat intelligence or domain reputation lookups for the ParentDomain and any resolved subdomains.
- DnsEvents across the environment for the same ParentDomain to determine whether the behavior is isolated or widespread.

**Benign explanations:**
- CDN, analytics, or telemetry services that legitimately use long subdomains for routing or session identifiers.
- Software update, licensing, or device management systems that encode identifiers in DNS queries.
- Internal service discovery or application frameworks that generate long hostnames as part of normal operation.
- Testing or lab systems intentionally using DNS for controlled data transfer.

**Escalation criteria:**
- The parent domain is unrecognized, newly registered, or has poor reputation and the query pattern is clearly encoded.
- The same host also shows suspicious process execution, persistence, or outbound connections.
- Multiple hosts begin querying the same domain with similar long-label patterns.
- The DNS activity persists after initial review and cannot be tied to a documented business service.

**Containment actions:**
- Isolate the host if the DNS pattern is strongly indicative of malware and there are additional compromise indicators.
- Block the parent domain and related subdomains at DNS or proxy controls if confirmed malicious.
- Quarantine or terminate the responsible process if endpoint telemetry identifies it and policy allows.
- Collect memory or forensic artifacts from the host before remediation if active exfiltration is suspected.

**Closure criteria:**
- The domain is confirmed as a legitimate CDN, telemetry, or business service with matching application ownership.
- The query pattern is explained by a known application or service and no suspicious endpoint activity is present.
- No additional hosts or users exhibit the same encoded high-frequency DNS behavior.
- The alert is attributable to a documented test, lab, or approved security assessment.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- XCSSET - Suspicious File Write Into Xcode Project Directory by Non-Xcode Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- XCSSET - Shell or Script Interpreter Spawned by Xcode with Suspicious Arguments: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.
- DNS Tunneling - High-Frequency Queries with Long Subdomains to a Single Domain: DnsEvents table requires a DNS data connector to be configured in Sentinel (Windows DNS Debug Logs connector, Syslog-based DNS sensor, or equivalent); this table is not populated by default and its absence will cause the query to return no results.
- DNS Tunneling - High-Frequency Queries with Long Subdomains to a Single Domain: DnsEvents table availability must be confirmed before running; the query will silently return no results if the connector is not configured.

**Shared-table notes:**
- DeviceProcessEvents: shared by XCSSET - Suspicious File Write Into Xcode Project Directory by Non-Xcode Process; XCSSET - Shell or Script Interpreter Spawned by Xcode with Suspicious Arguments

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Kerberoasting - High Volume RC4 TGS Requests from Single Account.
2. Resolve environment-mapping detections next: XCSSET - Suspicious File Write Into Xcode Project Directory by Non-Xcode Process; XCSSET - Shell or Script Interpreter Spawned by Xcode with Suspicious Arguments; DNS Tunneling - High-Frequency Queries with Long Subdomains to a Single Domain.

### Hunting Agenda and Promotion Criteria

- XCSSET - Suspicious File Write Into Xcode Project Directory by Non-Xcode Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- XCSSET - Shell or Script Interpreter Spawned by Xcode with Suspicious Arguments: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- DNS Tunneling - High-Frequency Queries with Long Subdomains to a Single Domain: DnsEvents table requires a DNS data connector to be configured in Sentinel (Windows DNS Debug Logs connector, Syslog-based DNS sensor, or equivalent); this table is not populated by default and its absence will cause the query to return no results.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
