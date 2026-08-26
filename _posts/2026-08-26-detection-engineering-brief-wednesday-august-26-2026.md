---
layout: post
title: "Detection Engineering Brief - Wednesday, August 26, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-26
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-63520
  - T1190
  - Microsoft SharePoint
  - Windows
  - cloud metadata services
  - web applications
  - T1059
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 0 hunting-only, 2 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-63520, T1190, Microsoft SharePoint, Windows, cloud metadata services, web applications, T1059.

Relevant IOCs were preserved and rendered inside their associated detection sections.

Deployment blockers or scheduling gates were identified for: SharePoint RCE - Suspicious Child Process Spawned by IIS Worker Process (CVE-2026-63520); SSRF Metadata Probe - Suspicious Outbound Requests to Cloud Metadata Endpoint in Network Logs.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SharePoint RCE - Suspicious Child Process Spawned by IIS Worker Process (CVE-2026-63520)

### Detection Opportunity

Remote code execution against Microsoft SharePoint via CVE-2026-63520 resulting in suspicious child processes spawned by the IIS worker process w3wp.exe.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Microsoft SharePoint Remote Code Execution (CVE-2026-63520) — [https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-remote-code-execution-cve-2026-63520](https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-remote-code-execution-cve-2026-63520)
  - Context: Rapid7 reported active exploitation of CVE-2026-63520 enabling remote code execution against Microsoft SharePoint. SharePoint RCE via IIS typically manifests as unexpected child processes spawned from w3wp.exe on SharePoint servers, providing a reliable post-exploitation signal.

### Search Metadata

- CVEs: CVE-2026-63520
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63520, T1190, Microsoft SharePoint, Windows, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let suspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe"]);
let sharepointHosts = dynamic(["SHAREPOINT-HOST-1", "SHAREPOINT-HOST-2"]);  // Replace with actual SharePoint server hostnames
let lookback = 1d;
let spawnEvents =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where DeviceName in~ (sharepointHosts)
    | where InitiatingProcessFileName =~ "w3wp.exe"
    | where FileName in~ (suspiciousChildren)
    | project
        SpawnTime = Timestamp,
        DeviceName,
        AccountName,
        ChildProcess = FileName,
        ProcessCommandLine,
        InitiatingProcessCommandLine,
        InitiatingProcessFileName;
let netEvents =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where DeviceName in~ (sharepointHosts)
    | where InitiatingProcessFileName in~ (suspiciousChildren)
    | where not(ipv4_is_private(RemoteIP))
    | where RemoteIP != "127.0.0.1"
    | project
        NetTime = Timestamp,
        DeviceName,
        RemoteIP,
        RemotePort,
        NetInitiatingProcess = InitiatingProcessFileName;
spawnEvents
| join kind=leftouter (
    netEvents
) on DeviceName
| extend HasOutboundConnection = isnotnull(NetTime) and (NetTime between (SpawnTime .. (SpawnTime + 5m)))
| where HasOutboundConnection or isnull(NetTime)
| summarize
    SpawnCount = count(),
    RemoteIPs = make_set(RemoteIP, 50),
    RemotePorts = make_set(RemotePort, 50),
    HasOutboundConnection = max(HasOutboundConnection)
    by
    SpawnTime,
    DeviceName,
    AccountName,
    ChildProcess,
    ProcessCommandLine,
    InitiatingProcessCommandLine
| extend ConfidenceLevel = iff(HasOutboundConnection, "High", "Medium")
| project
    SpawnTime,
    DeviceName,
    AccountName,
    ChildProcess,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    HasOutboundConnection,
    ConfidenceLevel,
    RemoteIPs,
    RemotePorts
| sort by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SharePoint administrative scripts that invoke cmd.exe or powershell.exe via IIS application pools.
- Monitoring or backup agents that spawn child processes under w3wp.exe context.
- Automated deployment pipelines running under IIS worker process identity.

**Tuning notes:**
- Populate sharepointHosts with the authoritative list of SharePoint server hostnames from your CMDB or device group.
- Add known SharePoint service account names to an AccountName exclusion filter to suppress legitimate automation.
- Consider promoting to production_candidate after sharepointHosts is populated and a 7-day baseline review confirms acceptable FP rate.
- Adjust lookback window from 1d to match scheduled rule frequency to avoid duplicate alerts.

**Risks / caveats:**
- DeviceProcessEvents and DeviceNetworkEvents are only populated for devices onboarded to Microsoft Defender for Endpoint. SharePoint servers not onboarded will produce no results.
- The join between DeviceProcessEvents and DeviceNetworkEvents on DeviceName with a 5-minute window filter applied after a leftouter join will silently drop the time-window filter rows where NetTime is null; the where clause after a leftouter join must account for null NetTime to avoid discarding spawn-only events.
- The sharepointHosts list must be populated with actual SharePoint server hostnames before the rule produces scoped, actionable results.
- The 5-minute correlation window between spawn and outbound network events may miss slow-moving post-exploitation activity or generate gaps due to ingestion delay between DeviceProcessEvents and DeviceNetworkEvents.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is on a known SharePoint server hostname and not a generic IIS host or lab system.
- Review the child process name and full command line for obvious attacker tradecraft such as cmd.exe, powershell.exe, cscript.exe, wscript.exe, mshta.exe, certutil.exe, or bitsadmin.exe.
- Check whether the child process made an outbound connection and note any remote IPs, ports, and timing relative to the spawn event.
- Inspect the parent/child process tree around the alert time for additional suspicious processes, repeated spawns, or service account abuse.
- If the process command line suggests exploitation or post-exploitation, immediately notify incident response and begin host scoping.

**Evidence to collect:**
- DeviceName, AccountName, SpawnTime, ChildProcess, ProcessCommandLine, InitiatingProcessCommandLine, HasOutboundConnection, RemoteIPs, and RemotePorts from the alert.
- Process tree for w3wp.exe and any descendants on the SharePoint server for at least 30 minutes before and after the alert.
- Recent DeviceNetworkEvents from the same host to identify outbound connections, especially to unusual public IPs or rare ports.
- SharePoint/IIS logs and web request logs around the alert time to identify the triggering request, source IP, URL, and user agent.
- Any recent administrative changes, patching activity, or deployment jobs on the SharePoint server that could explain the process spawn.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and a 24-hour window to find additional child processes spawned by w3wp.exe.
- DeviceNetworkEvents for the same DeviceName and AccountName to identify outbound connections from the suspicious child process.
- IIS/SharePoint access logs to correlate the request that preceded the process spawn.
- Microsoft Defender for Endpoint advanced hunting on the host to enumerate related process and network activity.
- If available, endpoint alert history and recent file creation events on the SharePoint server to look for follow-on payloads.

**Benign explanations:**
- Legitimate SharePoint administrative scripts or maintenance tasks that invoke cmd.exe or powershell.exe through IIS application pools.
- Backup, monitoring, or deployment agents that run under the IIS worker process context on the SharePoint server.
- Known service accounts or automation jobs that are expected to launch child processes during patching or content deployment.
- A false positive caused by non-SharePoint IIS servers if the host scoping is incomplete or misconfigured.

**Escalation criteria:**
- Any child process command line that downloads, decodes, or executes content from the internet.
- Outbound connections from the spawned process to rare public IPs, especially shortly after the spawn event.
- Multiple suspicious child processes from w3wp.exe, repeated alerts on the same host, or evidence of web shell behavior.
- Signs of persistence, credential access, lateral movement, or file modification on the SharePoint server.
- The alert occurs on an internet-facing production SharePoint server with no approved administrative activity to explain it.

**Containment actions:**
- Isolate the SharePoint server from the network if there is evidence of active exploitation or post-exploitation activity.
- Disable or suspend the implicated service or administrative account if it is not required for immediate business operations and appears abused.
- Block suspicious outbound destinations observed in the alert if they are clearly malicious and not business-related.
- Preserve volatile evidence before rebooting or reimaging, including process listings, network connections, and memory if your IR process supports it.
- Coordinate with SharePoint administrators before taking disruptive action if the server hosts critical business services.

**Closure criteria:**
- The child process is confirmed to be a documented administrative or maintenance action with matching change records.
- No additional suspicious processes, outbound connections, or web shell indicators are found on the host.
- The triggering request is explained by approved activity and the account is expected for that workflow.
- The host is patched or otherwise remediated for CVE-2026-63520 and follow-up monitoring shows no recurrence.
- Incident response agrees the event is benign after reviewing process, network, and SharePoint logs.

<br/>
---
<br/>

## Detection 2: SSRF to Cloud Metadata Service - Outbound Connection to 169.254.169.254 from Web Process

### Detection Opportunity

SSRF attempts targeting the cloud metadata service IP 169.254.169.254 via obfuscated hostnames, initiated by web server or application processes.

### Intelligence Context

- SANS ISC: Obfuscating IP Addresses as Hostnames, (Tue, Aug 25th) — [https://isc.sans.edu/diary/rss/33280](https://isc.sans.edu/diary/rss/33280)
  - Context: SANS ISC reported active scanning and SSRF exploitation attempts targeting the cloud metadata service at 169.254.169.254, with attackers using obfuscated hostname representations of the IP to bypass naive input validation. Outbound connections to this link-local address from web-facing processes are a high-confidence indicator of SSRF exploitation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Not specified
- Platforms: cloud metadata services, web applications
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud metadata services, web applications, T1190

### Relevant IOCs

| Type | Indicator |
|---|---|
| IPv4 | `169.254.169.254` |

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let knownCloudAgents = dynamic([
    "WindowsAzureGuestAgent.exe",
    "WaAppAgent.exe",
    "MonitoringAgent.exe",
    "amazon-ssm-agent.exe",
    "aws-cfn-bootstrap.exe",
    "google_guest_agent.exe"
]);
let lookback = 1d;
let netHits =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteIP == "169.254.169.254"
    | where InitiatingProcessFileName !in~ (knownCloudAgents)
    | project
        NetTime = Timestamp,
        DeviceName,
        RemoteIP,
        RemotePort,
        InitiatingProcessFileName,
        InitiatingProcessId,
        InitiatingProcessParentFileName,
        InitiatingProcessAccountName;
let procContext =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName !in~ (knownCloudAgents)
    | project
        ProcTime = Timestamp,
        DeviceName,
        FileName,
        ProcessCommandLine,
        ProcessId,
        AccountName;
netHits
| join kind=leftouter (
    procContext
) on DeviceName, $left.InitiatingProcessId == $right.ProcessId
| where isnull(ProcTime) or abs(datetime_diff('second', NetTime, ProcTime)) <= 30
| summarize
    ConnectionCount = count(),
    FirstSeen = min(NetTime),
    LastSeen = max(NetTime),
    CommandLines = make_set(ProcessCommandLine, 20),
    RemotePorts = make_set(RemotePort, 20)
    by
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName,
    RemoteIP
| extend EventTime = FirstSeen
| project
    EventTime,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName,
    RemoteIP,
    RemotePorts,
    ConnectionCount,
    FirstSeen,
    LastSeen,
    CommandLines
| sort by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Cloud agent binaries not yet enumerated in knownCloudAgents that legitimately query the metadata service.
- Container orchestration agents or sidecar processes on Kubernetes nodes that contact the metadata endpoint.
- Health check scripts run by cloud platform automation under web server process identity.

**Tuning notes:**
- Run the query over 7 days before scheduling to identify any legitimate cloud agents not in knownCloudAgents.
- If InitiatingProcessId join produces excessive null matches, add InitiatingProcessFileName as an additional join key to tighten correlation.
- Adjust lookback to match scheduled rule frequency to avoid duplicate alert rows.

**Risks / caveats:**
- DeviceNetworkEvents may not capture link-local (169.254.x.x) connections on all OS configurations or network drivers; validate that 169.254.169.254 appears in RemoteIP telemetry for the target cloud environment before scheduling.
- DeviceProcessEvents and DeviceNetworkEvents are only available for devices onboarded to Microsoft Defender for Endpoint.
- knownCloudAgents list may be incomplete for the target environment; additional legitimate agent binaries should be added during initial tuning.
- The ProcessId-based join between DeviceNetworkEvents and DeviceProcessEvents relies on InitiatingProcessId being consistently populated; if it is null for some events, the join falls back to DeviceName-only matching which may broaden results.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination is exactly 169.254.169.254 and identify the initiating web or application process from the alert.
- Check whether the initiating process is a known cloud agent or management component that legitimately queries metadata; if not, treat as suspicious.
- Review the process command line and parent process to determine whether the request originated from a web server, application runtime, or scriptable component.
- Look for repeated connections, multiple remote ports, or follow-on outbound activity from the same host within the alert window.
- Determine whether the affected host is internet-facing and whether the application recently changed, was deployed, or received untrusted input.

**Evidence to collect:**
- DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessAccountName, RemoteIP, RemotePort, and ConnectionCount from the alert.
- DeviceNetworkEvents around the same time to identify repeated metadata-service access or additional suspicious destinations.
- DeviceProcessEvents for the initiating process and its parent to capture full command lines and process ancestry.
- Web server, reverse proxy, WAF, or application logs to identify the request path, source IP, and any suspicious parameters or encoded hostnames.
- Cloud control plane or instance metadata access logs, if available, to determine whether credentials or tokens may have been requested or issued.

**Pivot points:**
- DeviceNetworkEvents on the same DeviceName for 24 hours to find all connections to 169.254.169.254 and other link-local destinations.
- DeviceProcessEvents for the same host to identify web processes spawning scripts, shells, or download utilities.
- CommonSecurityLog, WAF, or proxy logs to correlate the inbound request that may have triggered SSRF.
- Cloud provider audit logs or metadata service logs to check for token issuance or unusual metadata access.
- If the host is containerized, pivot to container runtime or orchestration logs to determine whether a sidecar or workload initiated the request.

**Benign explanations:**
- A legitimate cloud management agent or guest agent querying instance metadata as part of normal operation.
- Container orchestration components or sidecars that access metadata endpoints for node or workload identity.
- Health checks or automation scripts run by the cloud platform or internal operations team.
- A security scanner or misconfiguration assessment tool intentionally probing metadata endpoints during authorized testing.

**Escalation criteria:**
- The initiating process is a web server, application runtime, or script with no approved reason to contact metadata services.
- The host shows repeated metadata access, unusual outbound connections, or evidence of token use after the probe.
- The alert is associated with a public-facing application that recently handled untrusted input or has a known SSRF exposure.
- Cloud audit logs show suspicious metadata token retrieval, role assumption, or credential use after the event.
- The destination access is accompanied by other signs of compromise such as web shell activity, process injection, or file changes.

**Containment actions:**
- If exploitation appears active, isolate the host or application server from the network while preserving evidence.
- Disable or restrict the vulnerable application endpoint if it can be safely taken offline without broader impact.
- Rotate or revoke cloud credentials, tokens, or instance roles if metadata access may have exposed them.
- Block the offending source or request pattern at the WAF or reverse proxy if the attack vector is identified.
- Coordinate with cloud operations before making changes that could disrupt legitimate metadata-dependent services.

**Closure criteria:**
- The initiating process is confirmed as a legitimate cloud agent, sidecar, or approved automation component.
- No suspicious follow-on activity, token use, or additional metadata probes are observed on the host.
- Application and proxy logs show the request was part of authorized testing or normal operation.
- Cloud audit review finds no evidence of credential exposure or misuse.
- The alert source is tuned or allowlisted only after the benign behavior is validated and documented.

<br/>
---
<br/>

## Detection 3: SSRF Metadata Probe - Suspicious Outbound Requests to Cloud Metadata Endpoint in Network Logs

### Detection Opportunity

Outbound network scans and SSRF probes targeting the cloud metadata service endpoint at 169.254.169.254, potentially using hostname obfuscation to evade detection.

### Intelligence Context

- SANS ISC: Obfuscating IP Addresses as Hostnames, (Tue, Aug 25th) — [https://isc.sans.edu/diary/rss/33280](https://isc.sans.edu/diary/rss/33280)
  - Context: SANS ISC documented scanning activity where attackers used obfuscated hostname representations of 169.254.169.254 to probe cloud metadata services via SSRF. CommonSecurityLog from WAF or proxy sources can capture destination IP and URL fields that reveal these probes even when hostnames are used.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Not specified
- Platforms: cloud metadata services, web applications
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud metadata services, web applications, T1190

### Relevant IOCs

| Type | Indicator |
|---|---|
| IPv4 | `169.254.169.254` |

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let metadataPaths = dynamic([
    "/latest/meta-data",
    "/metadata/instance",
    "/computeMetadata",
    "/openstack"
]);
let lookback = 7d;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where isnotempty(DestinationIP) or isnotempty(RequestURL)
| where DestinationIP == "169.254.169.254"
    or RequestURL has_any (metadataPaths)
| summarize
    RequestCount = count(),
    DistinctPaths = dcount(RequestURL),
    Methods = make_set(HttpRequestMethod, 10),
    Paths = make_set(RequestURL, 50),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DeviceVendors = make_set(DeviceVendor, 5),
    DeviceProducts = make_set(DeviceProduct, 5)
    by SourceIP, DestinationIP
| extend ScanLikelihood = case(
    DistinctPaths >= 3, "High",
    DistinctPaths >= 2, "Medium",
    "Low"
)
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    DestinationIP,
    RequestCount,
    DistinctPaths,
    Methods,
    Paths,
    ScanLikelihood,
    DeviceVendors,
    DeviceProducts
| sort by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal health check agents that probe metadata-like URL paths on application servers.
- Security scanners or vulnerability assessment tools that probe 169.254.169.254 as part of cloud misconfiguration checks.
- Legitimate cloud SDK calls that appear in proxy logs with metadata service paths.

**Tuning notes:**
- Before running, confirm that CommonSecurityLog contains rows with non-empty DestinationIP or RequestURL by querying: CommonSecurityLog → where TimeGenerated > ago(7d) → where isnotempty(DestinationIP) → take 10.
- Add DeviceVendor filter to restrict results to WAF or proxy log sources if multiple appliance types forward to CommonSecurityLog, as firewall logs may lack RequestURL detail.
- Extend metadataPaths with additional cloud-provider-specific paths such as /metadata/v1/ (DigitalOcean) or /latest/dynamic/ (AWS) if those cloud providers are in scope.
- If promoted to a scheduled rule, add a minimum RequestCount threshold appropriate to baseline traffic volume to reduce single-event noise.

**Risks / caveats:**
- CommonSecurityLog.DestinationIP and CommonSecurityLog.RequestURL are CEF extension fields that are only populated if the upstream appliance maps them in its CEF output. Many firewall and proxy vendors leave one or both fields empty, which would cause the DestinationIP filter to match no rows and the RequestURL path filter to match no rows.
- CommonSecurityLog requires a CEF-compatible data connector (Syslog/CEF forwarder or vendor-specific connector) to be configured and actively ingesting. Without a confirmed connector, the table may be empty or absent.
- The RequestURL path-based match (has_any on metadataPaths) will produce false positives if the WAF or proxy logs internal health check traffic that includes metadata-like URL paths unrelated to SSRF.
- DestinationIP and RequestURL field population depends entirely on the upstream CEF appliance configuration. If these fields are not mapped by the vendor, the query returns no results for the respective filter branch.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, destination IP, request paths, and device vendor/product to understand which appliance generated the log.
- Confirm whether the destination is 169.254.169.254 or whether the request URL contains metadata-service paths such as /latest/meta-data or /metadata/instance.
- Check whether the source is a WAF, proxy, or security scanner and whether the activity matches an approved assessment or internal health check.
- Review the request count and distinct paths to determine whether this is a single probe or a broader scan pattern.
- Determine whether the traffic originated from an internet-facing application or from an internal management network.

**Evidence to collect:**
- FirstSeen, LastSeen, SourceIP, DestinationIP, RequestCount, DistinctPaths, Methods, Paths, ScanLikelihood, DeviceVendor, and DeviceProduct from the alert.
- Raw CommonSecurityLog entries around the alert time to inspect full request URLs, methods, and any vendor-specific fields.
- WAF, proxy, or firewall logs to identify the original client, request headers, and any blocked or allowed actions.
- Application logs for the destination service to determine whether the request reached the app and whether it triggered server-side fetch behavior.
- Cloud provider logs or metadata access telemetry, if available, to see whether the probe resulted in metadata service interaction.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DestinationIP over 7 days to identify repeated metadata probes or broader scanning.
- CommonSecurityLog for the same DeviceVendor and DeviceProduct to validate whether the appliance reliably populates DestinationIP and RequestURL.
- WAF or proxy logs to correlate the source IP with the application endpoint and request path.
- Application server logs to identify SSRF-prone parameters, redirects, or URL fetch functionality.
- Threat intelligence or internal scanner inventories to determine whether the source IP belongs to an authorized assessment tool.

**Benign explanations:**
- An authorized vulnerability scanner or cloud misconfiguration assessment tool probing metadata endpoints.
- Internal health checks or monitoring traffic that uses metadata-like paths as part of application validation.
- Legitimate cloud SDK or platform automation traffic that appears in proxy logs with metadata-related URLs.
- A security appliance or proxy generating logs that resemble metadata probes but are not actually reaching the endpoint.

**Escalation criteria:**
- The source is a public-facing application or web tier with no approved reason to contact metadata services.
- Multiple distinct metadata paths or repeated requests indicate active probing rather than a single benign event.
- The activity is paired with application errors, unusual redirects, or signs that the app fetched attacker-controlled URLs.
- The source IP is external or unrecognized and the request pattern matches SSRF exploitation.
- There is evidence of credential exposure, token retrieval, or subsequent suspicious cloud activity after the probe.

**Containment actions:**
- Block the source IP or request pattern at the WAF or proxy if the traffic is clearly malicious and not business-related.
- Temporarily disable or restrict the vulnerable application feature that performs server-side URL fetching if exploitation is suspected.
- Rotate cloud credentials or instance roles if there is any indication the metadata service was successfully reached.
- Increase logging on the affected application and edge devices to capture the full request chain and headers.
- Coordinate with application owners before disabling functionality that may affect production traffic.

**Closure criteria:**
- The source is confirmed as an authorized scanner, health check, or approved cloud automation.
- The request pattern is explained by known benign traffic and no application-side SSRF behavior is observed.
- No follow-on metadata access, credential use, or suspicious cloud activity is detected.
- The appliance fields are validated and the alert is tuned or allowlisted only after documentation.
- The application owner confirms the traffic is expected and there is no security impact.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- SharePoint RCE - Suspicious Child Process Spawned by IIS Worker Process (CVE-2026-63520): Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.
- SSRF Metadata Probe - Suspicious Outbound Requests to Cloud Metadata Endpoint in Network Logs: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by SharePoint RCE - Suspicious Child Process Spawned by IIS Worker Process (CVE-2026-63520); SSRF to Cloud Metadata Service - Outbound Connection to 169.254.169.254 from Web Process
- DeviceNetworkEvents: shared by SharePoint RCE - Suspicious Child Process Spawned by IIS Worker Process (CVE-2026-63520); SSRF to Cloud Metadata Service - Outbound Connection to 169.254.169.254 from Web Process

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SSRF to Cloud Metadata Service - Outbound Connection to 169.254.169.254 from Web Process.
2. Resolve environment-mapping detections next: SharePoint RCE - Suspicious Child Process Spawned by IIS Worker Process (CVE-2026-63520); SSRF Metadata Probe - Suspicious Outbound Requests to Cloud Metadata Endpoint in Network Logs.

### Hunting Agenda and Promotion Criteria

- SharePoint RCE - Suspicious Child Process Spawned by IIS Worker Process (CVE-2026-63520): Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- SSRF Metadata Probe - Suspicious Outbound Requests to Cloud Metadata Endpoint in Network Logs: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

## Observed IOCs

> Indicators are extracted from source reporting context and should be validated before blocking, alerting, or enrichment.

| Type | Indicator |
|---|---|
| IPv4 | `169.254.169.254` |


<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
