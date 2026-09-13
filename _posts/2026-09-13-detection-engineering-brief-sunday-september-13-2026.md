---
layout: post
title: "Detection Engineering Brief - Sunday, September 13, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-13
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - SPIFFE
  - SPIRE
  - Kubernetes
  - T1190
  - Apache Tika
  - Metasploit
  - CVE-2025-66516
  - CVE-2025-54988
  - Elasticsearch
  - LLM APIs
  - web applications
  - T1552
  - T1552.001
  - T1136
  - T1098
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 1 hunting-only, 4 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: SPIFFE, SPIRE, Kubernetes, T1190, Apache Tika, Metasploit, CVE-2025-66516, CVE-2025-54988, Elasticsearch, LLM APIs, web applications, T1552, T1552.001, T1136, T1098.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SPIRE Agent Socket Access by Root Process on Kubernetes Node; Non-SPIRE Root Process Reading SVID or SPIFFE Identity Files on Kubernetes Node; Apache Tika XXE Exploitation Attempt via XFA Document Upload; Elasticsearch Ingest-Attachment Local File Read Scanning (CVE-2025-54988 / CVE-2025-66516); Bulk Account Creation Followed by Rapid API Key Generation Consistent with LLM Credential Farming.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SPIRE Agent Socket Access by Root Process on Kubernetes Node

### Detection Opportunity

Root-level process execution accessing SPIRE agent socket or /run/spire/ paths on a Kubernetes node, consistent with post-exploitation identity abuse.

### Intelligence Context

- Unit 42: The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE — [https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/)
  - Context: Unit 42 reported that root access on a compromised Kubernetes node enables attackers to access SPIRE agent sockets and metadata paths to spoof and harvest co-located workload identities (SVIDs).

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001
- Products: SPIFFE, SPIRE
- Platforms: Kubernetes
- Malware: Not specified
- Tools: Not specified
- Search tags: SPIFFE, SPIRE, Kubernetes, T1552, T1552.001

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
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 1d;
let correlationWindowMin = 5;
let spireFilePaths = DeviceFileEvents
| where TimeGenerated > ago(lookback)
| where FolderPath has_any ("/run/spire", "/tmp/spire", "/var/lib/spire", "spire-agent.sock")
| where InitiatingProcessAccountName == "root"
| where not (InitiatingProcessCommandLine has_any ("spire-agent", "spire-server"))
| project DeviceName, DeviceId, FileAccessTime = TimeGenerated, FolderPath, AccessedFileName = FileName, InitiatingProcessCommandLine;
let rootProcs = DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where AccountName == "root"
| where ProcessCommandLine has_any ("spire", "svid", "spiffe", "/run/spire")
| where not (ProcessCommandLine has_any ("spire-agent", "spire-server"))
| project DeviceName, DeviceId, ProcTime = TimeGenerated, RootProcessCommandLine = ProcessCommandLine, RootProcessFileName = FileName, AccountName;
spireFilePaths
| join kind=inner rootProcs on DeviceName, DeviceId
| where FileAccessTime between ((ProcTime - totimespan(correlationWindowMin * 1m)) .. (ProcTime + totimespan(correlationWindowMin * 1m)))
| project DeviceName, FileAccessTime, ProcTime, FolderPath, AccessedFileName, InitiatingProcessCommandLine, RootProcessCommandLine, RootProcessFileName, AccountName
| order by FileAccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SPIRE agent or server processes running as root will match file path filters; exclusion of spire-agent and spire-server process names mitigates but does not eliminate this.
- Container runtime processes (containerd, dockerd) running as root may access /run/ paths and generate correlated hits.

**Tuning notes:**
- Extend FolderPath has_any to include any custom SPIRE socket paths used in your deployment (e.g., /var/run/spire/sockets/agent.sock).
- After initial runs, add confirmed legitimate root process names to the exclusion list in both subqueries.
- Consider reducing lookback to 6h for scheduled rule use to manage query cost on high-volume environments.

**Risks / caveats:**
- DeviceFileEvents and DeviceProcessEvents require MDE agent deployment on Kubernetes worker nodes. This is non-standard; most Kubernetes node telemetry is collected via container-level agents, not host-level MDE. If MDE is not deployed on nodes, both tables will return no results for these devices.
- DeviceFileEvents does not reliably capture socket file access events (e.g., Unix domain socket reads via connect() syscall) — only file create/write/rename/delete actions are typically surfaced. Access to spire-agent.sock via socket connection may not appear as a FileEvent at all.
- The 5-minute correlation window is a starting point; environments with high root process activity may require tightening to 1-2 minutes to reduce noise.
- SPIRE deployments using non-default socket paths (e.g., /var/run/spire/sockets/) will not be covered unless FolderPath filters are extended.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is an actual Kubernetes worker node and not a management or build host.
- Identify the root process that triggered the alert and determine whether it is expected on that node.
- Check whether the process name, command line, parent process, and execution time align with SPIRE agent/server activity or with a suspicious post-exploitation tool.
- Look for nearby signs of host compromise such as new root shells, privilege escalation, unusual network connections, or other access to /run/spire or related identity paths.

**Evidence to collect:**
- DeviceName, DeviceId, alert timestamp, and the full root process command line.
- Parent process chain and initiating account for the root process.
- Any file or socket access details for /run/spire, /tmp/spire, /var/lib/spire, or spire-agent.sock.
- Recent process and network activity on the same node, especially other root-owned processes and outbound connections.
- SPIRE deployment details for that node, including expected agent/server process names and custom socket paths.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and DeviceId in the surrounding 1-2 hours.
- DeviceFileEvents for /run/spire, /tmp/spire, /var/lib/spire, and any custom SPIRE socket paths.
- DeviceNetworkEvents for unusual outbound connections from the same host after the alert time.
- If available, Kubernetes node inventory or CMDB to confirm whether the host should run SPIRE components.

**Benign explanations:**
- Legitimate spire-agent or spire-server activity running as root on the node.
- Container runtime or node bootstrap processes that legitimately touch /run paths.
- Authorized administrative troubleshooting on the node by platform engineers.

**Escalation criteria:**
- The process is not a known SPIRE component and is running as root on a production Kubernetes node.
- You find evidence of identity theft behavior, such as access to SPIRE sockets followed by suspicious lateral movement or credential use.
- The node also shows other compromise indicators, including unexpected shells, persistence, or outbound command-and-control traffic.
- The activity occurs on multiple nodes or repeats after the first alert.

**Containment actions:**
- If the process is unauthorized, isolate the node from the network or cordon/drain it according to Kubernetes incident procedures.
- Preserve volatile evidence before rebooting, including process listings, open connections, and relevant logs.
- Disable or rotate any workload identities or credentials suspected to have been exposed through SPIRE access.
- Coordinate with platform owners before taking the node out of service to avoid unnecessary cluster impact.

**Closure criteria:**
- Confirmed legitimate SPIRE or platform maintenance activity with matching change record and expected process lineage.
- No evidence of unauthorized root activity, identity theft, or follow-on compromise on the node.
- Alert maps to a known benign process pattern and the environment-specific SPIRE paths/process names have been validated.
- Any suspicious process was investigated and ruled out after reviewing host, network, and identity evidence.

<br/>
---
<br/>

## Detection 2: Non-SPIRE Root Process Reading SVID or SPIFFE Identity Files on Kubernetes Node

### Detection Opportunity

A process running as root, not associated with the SPIRE agent, reads files with paths or names containing SVID or SPIFFE identity material from co-located workload directories.

### Intelligence Context

- Unit 42: The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE — [https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/)
  - Context: Unit 42 described attackers harvesting co-located workload SVIDs from the node filesystem after gaining root access, enabling identity spoofing against other services.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001
- Products: SPIFFE, SPIRE
- Platforms: Kubernetes
- Malware: Not specified
- Tools: Not specified
- Search tags: SPIFFE, SPIRE, Kubernetes, T1552, T1552.001

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
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where TimeGenerated > ago(1d)
| where ActionType in ("FileRead", "FileCreated", "FileCopied")
| where InitiatingProcessAccountName == "root"
| where (FolderPath has_any ("svid", "spiffe", "spire") or FileName has_any ("svid", "spiffe"))
| where not (InitiatingProcessCommandLine has_any ("spire-agent", "spire-server"))
| project TimeGenerated, DeviceName, DeviceId, FolderPath, FileName, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security scanning tools running as root may read SVID-related paths during filesystem audits.
- Backup agents running as root may access /var/lib/spire/ paths during scheduled backups.
- Container runtimes may access SPIRE-related paths during workload initialization.

**Tuning notes:**
- After initial runs, narrow FolderPath has_any to specific confirmed SVID storage paths from your SPIRE deployment configuration.
- Add confirmed legitimate root process names (backup agents, security scanners) to the exclusion list.
- Run DeviceFileEvents → where TimeGenerated > ago(1h) → summarize count() by ActionType to confirm which ActionType values are present before scheduling.

**Risks / caveats:**
- ActionType value 'FileAccessed' is not a documented standard ActionType in MDE DeviceFileEvents. Including it will not cause query failure but will match zero events, silently reducing detection coverage. Confirm available ActionType values with: DeviceFileEvents → summarize count() by ActionType.
- DeviceFileEvents requires MDE host agent on Kubernetes worker nodes. Without confirmed agent deployment on those nodes, the query returns no relevant results.
- MDE DeviceFileEvents does not reliably capture Unix domain socket access events. SVID material accessed via the SPIRE workload API socket (not filesystem reads) will not appear.
- The FolderPath and FileName keyword filters ('svid', 'spiffe', 'spire') are broad and will match any path containing these strings, including unrelated software with similar naming.

### Triage Runbook

**First 15 minutes:**
- Verify the host is a Kubernetes node and identify the workload or service expected to access the flagged path.
- Review the initiating process name, command line, and parent process to see whether it is a known SPIRE component or an unrelated root process.
- Check whether the access pattern is consistent with backup, security scanning, or container startup activity versus deliberate credential harvesting.
- Look for immediate follow-on actions such as new outbound connections, token use, or access to other workload directories on the same node.

**Evidence to collect:**
- FolderPath, FileName, ActionType, and the full initiating process command line.
- InitiatingProcessFileName and InitiatingProcessParentFileName for process lineage.
- DeviceName, DeviceId, and timestamp of the file access.
- Any nearby reads of other SVID, SPIFFE, or identity-related files on the same host.
- Relevant SPIRE deployment configuration showing expected storage paths for SVID material.

**Pivot points:**
- DeviceFileEvents for the same host and time window to find additional reads of identity-related files.
- DeviceProcessEvents to identify the root process tree and any spawned shells or utilities.
- DeviceNetworkEvents to see whether the same process or host made suspicious outbound connections after the file read.
- If available, host audit or Linux security logs for direct file access context not captured by MDE.

**Benign explanations:**
- Legitimate spire-agent or spire-server file access on the node.
- Backup agents, vulnerability scanners, or security tools running as root and inspecting filesystem contents.
- Container runtime or node initialization activity that touches SPIRE-related directories during workload startup.

**Escalation criteria:**
- The process is not a known SPIRE component and the file path clearly contains SVID or SPIFFE identity material.
- The same host shows multiple reads of identity files followed by suspicious network activity or lateral movement.
- The access is from a root shell, ad hoc admin tool, or unknown binary rather than a managed service.
- You confirm the identity material could be used to impersonate a workload or service in the cluster.

**Containment actions:**
- Isolate the node if the access appears unauthorized and the host is still active in production.
- Rotate or revoke any exposed workload identities, certificates, or related secrets as directed by the SPIRE owners.
- Preserve the process tree and file access evidence before remediation.
- If the access came from a managed tool, temporarily suspend that tool on the node until its behavior is validated.

**Closure criteria:**
- The access is attributable to a known SPIRE component or approved operational tool.
- The file path and process lineage match documented, expected behavior for that node.
- No additional suspicious reads, shell activity, or outbound connections are found.
- Any false positive source has been documented for future tuning, including process exclusions or path scoping.

<br/>
---
<br/>

## Detection 3: Apache Tika XXE Exploitation Attempt via XFA Document Upload

### Detection Opportunity

HTTP POST requests to Apache Tika parsing endpoints containing XFA or DOCTYPE keywords in the request body, consistent with Metasploit XXE exploit module activity.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: This One Goes to Sixteen! — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen)
  - Context: Rapid7 disclosed a new Metasploit module that exploits an XXE vulnerability in Apache Tika's XFA parser by uploading crafted XFA documents to the Tika endpoint, enabling local file read or SSRF.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Apache Tika
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Apache Tika, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where RequestMethod == "POST"
| where RequestURL has_any ("/tika", "/meta", "/unpack", "/detect")
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    UserAgents = make_set(UserAgent, 20),
    SampleURLs = make_set(RequestURL, 5)
    by SourceIP, DestinationPort, bin(TimeGenerated, 5m)
| where RequestCount >= 3
| extend SuspiciousAgent = iff(
    tostring(UserAgents) has_any ("Metasploit", "msf", "python-requests", "Go-http-client", "curl"),
    true, false)
| project TimeGenerated, SourceIP, DestinationPort, RequestCount, DistinctURLs, SuspiciousAgent, UserAgents, SampleURLs
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated document ingestion pipelines that POST multiple documents to Tika in rapid succession.
- Security scanners and vulnerability assessment tools targeting Tika endpoints during authorized testing.
- Load balancer health checks hitting Tika API paths.

**Tuning notes:**
- If your WAF logs request body content into a custom CEF field (e.g., cs6 or RequestContext), add a filter on that field for 'xfa' or 'DOCTYPE' to significantly improve detection fidelity.
- Add known internal document processing IP ranges to a pre-filter exclusion to reduce false positives from legitimate Tika usage.
- Raise RequestCount threshold to 10 or higher if legitimate batch processing generates frequent POST bursts to Tika endpoints.
- Add DestinationPort filter matching your Tika deployment port if it differs from standard HTTP/HTTPS ports.

**Risks / caveats:**
- CommonSecurityLog requires a WAF, reverse proxy, or network appliance forwarding HTTP logs to Sentinel via the CEF connector. If Apache Tika is not fronted by such a device, this table will contain no relevant records.
- XFA and DOCTYPE payload keywords appear in the HTTP request body, not the URL. CommonSecurityLog RequestURL field does not contain request body content. Detection of body-based XXE payloads via RequestURL will produce near-zero true positives unless the WAF is configured to log body content into a mapped CEF field.
- UserAgent-based matching for 'xfa' and 'DOCTYPE' is unreliable as Metasploit modules typically use generic HTTP client user agents, not payload-specific strings.
- Without WAF body inspection logging, XXE payload content (XFA, DOCTYPE) in POST bodies is invisible to this query. The detection relies solely on endpoint targeting patterns and request frequency.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination is an Apache Tika service and identify whether it is internet-facing or internal only.
- Review the source IP, request frequency, and user agent to determine whether the traffic looks like automated exploit tooling.
- Check whether the requests are concentrated on Tika parsing endpoints such as /tika, /meta, /unpack, or /detect.
- Determine whether there are signs of impact, such as application errors, unusual outbound requests from the Tika server, or file access to sensitive local paths.

**Evidence to collect:**
- SourceIP, DestinationPort, RequestURL, RequestMethod, UserAgent, and the request timestamps.
- Any available WAF or reverse proxy logs that may include request body content or blocked request details.
- Tika server logs, application errors, and backend host logs around the same time.
- Whether the source IP is internal, a known scanner, or an external address.
- Any evidence of SSRF, local file read attempts, or unexpected outbound traffic from the Tika host.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and destination over a wider time window to see if the activity is repeated.
- Web or application logs on the Tika server for parsing errors or XXE-related exceptions.
- Network telemetry from the Tika host to identify outbound connections after the request burst.
- If available, WAF logs with body inspection fields to confirm whether XFA or DOCTYPE content was present.

**Benign explanations:**
- Authorized vulnerability scanning or penetration testing against the Tika service.
- Legitimate document ingestion pipelines making repeated POST requests to Tika endpoints.
- Load balancer or monitoring health checks hitting the service endpoints.

**Escalation criteria:**
- The source is external or unknown and the request pattern is consistent with exploit tooling.
- You find application errors, unexpected outbound connections, or evidence of local file access/SSRF on the Tika host.
- The same source continues probing after initial blocking or appears across multiple services.
- The Tika service is internet-facing and not protected by compensating controls.

**Containment actions:**
- Block or rate-limit the source IP at the WAF or reverse proxy if the activity is unauthorized.
- Temporarily restrict access to the Tika endpoint if exploitation is suspected and the service is exposed.
- Preserve relevant logs before making changes to the proxy or application.
- If impact is confirmed, isolate the Tika host or container and begin application-level incident response.

**Closure criteria:**
- The traffic is confirmed as authorized testing or expected document ingestion behavior.
- No application errors, SSRF, or local file read indicators are found on the Tika service.
- The source IP is a known internal system or approved scanner and the pattern matches baseline behavior.
- Any suspicious requests were blocked without evidence of successful exploitation.

<br/>
---
<br/>

## Detection 4: Elasticsearch Ingest-Attachment Local File Read Scanning (CVE-2025-54988 / CVE-2025-66516)

### Detection Opportunity

Repeated API calls to the Elasticsearch ingest-attachment pipeline endpoint from a single source IP, potentially referencing local file paths, consistent with Metasploit auxiliary scanner activity for CVE-2025-54988 and CVE-2025-66516.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: This One Goes to Sixteen! — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen)
  - Context: Rapid7 disclosed a Metasploit auxiliary scanner module targeting CVE-2025-54988 and CVE-2025-66516, which exploits the Elasticsearch ingest-attachment plugin to read local files by submitting crafted pipeline requests.

### Search Metadata

- CVEs: CVE-2025-66516, CVE-2025-54988
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Elasticsearch
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2025-66516, CVE-2025-54988, T1190, Elasticsearch, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where RequestURL has_any ("_ingest", "attachment", "_pipeline")
| where DestinationPort in (9200, 9243)
| where RequestMethod in ("POST", "PUT")
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    UserAgents = make_set(UserAgent, 20),
    SampleURLs = make_set(RequestURL, 5)
    by SourceIP, DestinationPort, bin(TimeGenerated, 10m)
| where RequestCount >= 5
| extend SuspiciousAgent = iff(
    tostring(UserAgents) has_any ("python-requests", "Go-http-client", "Metasploit", "msf", "curl"),
    true, false)
| project TimeGenerated, SourceIP, DestinationPort, RequestCount, DistinctURLs, SuspiciousAgent, UserAgents, SampleURLs
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Elasticsearch pipeline management automation making frequent PUT/POST calls to _ingest endpoints during pipeline updates.
- Monitoring and health-check systems polling Elasticsearch API endpoints.
- Authorized penetration testing activity targeting Elasticsearch.

**Tuning notes:**
- Add known internal Elasticsearch management IP ranges to a pre-filter exclusion to suppress legitimate pipeline management traffic.
- Adjust DestinationPort to match your Elasticsearch deployment port if it differs from 9200 or 9243.
- Raise RequestCount threshold above 5 after baselining normal pipeline management call frequency in your environment.
- If your WAF logs include request body content in a custom field, add a filter for local file path patterns (e.g., '/etc/passwd', 'file://') to significantly improve precision.

**Risks / caveats:**
- CommonSecurityLog requires a WAF, proxy, or network appliance forwarding HTTP logs to Sentinel via the CEF connector. Elasticsearch deployments without a fronting proxy will produce no results from this table.
- RequestMethod field availability in CommonSecurityLog depends on the specific WAF or proxy vendor and its CEF field mapping. Some appliances do not populate RequestMethod in the standard CEF schema.
- The query cannot inspect request body content, so crafted pipeline payloads referencing local file paths are not directly detectable — only the targeting pattern (endpoint + frequency) is observable.
- CVE-2025-54988 and CVE-2025-66516 are referenced from the source article; NVD publication status and affected version ranges should be confirmed before using this detection for prioritization.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination is an Elasticsearch node or front-end proxy and identify whether the service is exposed externally.
- Review the source IP, request count, and user agent for signs of automated scanning or exploit tooling.
- Check whether the requests target ingest-related endpoints repeatedly and whether the timing suggests enumeration rather than normal pipeline use.
- Look for signs of impact on the Elasticsearch host, including unusual errors, file access attempts, or unexpected outbound traffic.

**Evidence to collect:**
- SourceIP, DestinationPort, RequestURL, RequestMethod, UserAgent, and the time window of activity.
- Any proxy or WAF logs that show blocked requests or request body details.
- Elasticsearch logs for ingest pipeline errors, authentication failures, or suspicious pipeline updates.
- Whether the source IP belongs to a known management system, ETL platform, or external scanner.
- Any host or network telemetry showing follow-on activity from the Elasticsearch server.

**Pivot points:**
- CommonSecurityLog for the same SourceIP over a longer period to identify repeated probing or other service targeting.
- Elasticsearch application logs for ingest pipeline changes or errors around the alert time.
- Network telemetry from the Elasticsearch host to identify outbound connections after the requests.
- If available, authentication and admin activity logs to see whether the same source also attempted privileged actions.

**Benign explanations:**
- Legitimate Elasticsearch management, ETL, or pipeline automation traffic.
- Monitoring or health-check systems polling the API.
- Authorized vulnerability assessment or penetration testing.

**Escalation criteria:**
- The source is external or unknown and the request pattern is consistent with exploit scanning.
- You observe errors, unexpected pipeline behavior, or signs of local file access attempts on the Elasticsearch host.
- The same source continues to probe after blocking or appears across multiple nodes.
- The service is internet-facing and lacks compensating controls such as authentication or a WAF.

**Containment actions:**
- Block or rate-limit the source IP if the activity is unauthorized.
- Restrict access to the Elasticsearch API to trusted management networks if feasible.
- Preserve proxy and application logs before changing access controls.
- If impact is suspected, isolate the affected node or cluster segment and rotate any exposed credentials.

**Closure criteria:**
- The activity is attributable to a known management system, ETL job, or approved scanner.
- No evidence of successful exploitation, file read, or suspicious outbound activity is found.
- The source IP is internal and matches documented Elasticsearch administration behavior.
- The alert is explained by normal pipeline maintenance and no further suspicious requests occur.

<br/>
---
<br/>

## Detection 5: Bulk Account Creation Followed by Rapid API Key Generation Consistent with LLM Credential Farming

### Detection Opportunity

Multiple accounts created from the same or closely related IP addresses within a short window, followed by immediate API key issuance events, consistent with automated LLM API credential farming operations.

### Intelligence Context

- SANS ISC: The Self-Expanding Stolen Inference Supply Chain: An AI Agent Harvesting and Re-Serving LLM Access, (Fri, Sep 11th) — [https://isc.sans.edu/diary/rss/33332](https://isc.sans.edu/diary/rss/33332)
  - Context: SANS ISC reported a semi-autonomous attacker operation that farms LLM API credentials at scale by creating accounts through ordinary web flaws and account farming, then aggregating the stolen API access behind an attacker-controlled gateway.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1136, T1098
- Products: Not specified
- Platforms: LLM APIs, web applications
- Malware: Not specified
- Tools: Not specified
- Search tags: LLM APIs, web applications, T1136, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1136 Create Account (high); Credential Access: T1098 Account Manipulation (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- AuditLogs

### KQL

```kql
let lookback = 1d;
let creationWindow = 30m;
let keyIssuanceWindow = 1h;
let bulkThreshold = 3;
let accountCreations = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any ("Add user", "Create user", "Invite external user")
| where Result == "success"
| extend SourceIP = coalesce(
    tostring(InitiatedBy.user.ipAddress),
    tostring(InitiatedBy.app.ipAddress)
  )
| extend CreatedUser = tostring(TargetResources[0].userPrincipalName)
| where isnotempty(SourceIP) and isnotempty(CreatedUser)
| project CreationTime = TimeGenerated, SourceIP, CreatedUser;
let apiKeyEvents = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any (
    "Add service principal credentials",
    "Update application",
    "Add application",
    "Add OAuth2PermissionGrant"
  )
| where Result == "success"
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(ActorUPN)
| project KeyTime = TimeGenerated, ActorUPN, ApiKeyOperationName = OperationName;
let bulkCreatorIPs = accountCreations
| summarize AccountsCreated = dcount(CreatedUser) by SourceIP, bin(CreationTime, creationWindow)
| where AccountsCreated >= bulkThreshold
| project SourceIP, WindowStart = CreationTime, AccountsCreated;
accountCreations
| join kind=inner bulkCreatorIPs on SourceIP
| where CreationTime >= WindowStart and CreationTime < WindowStart + creationWindow
| join kind=inner apiKeyEvents on $left.CreatedUser == $right.ActorUPN
| where KeyTime between (CreationTime .. (CreationTime + keyIssuanceWindow))
| project CreationTime, KeyTime, SourceIP, CreatedUser, ApiKeyOperationName, AccountsCreated
| order by CreationTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- HR or identity governance systems performing bulk user onboarding from a shared egress IP.
- Developer environments where test accounts are created in bulk and immediately assigned API credentials.
- Legitimate multi-tenant provisioning automation creating accounts and credentials in rapid succession.

**Tuning notes:**
- Run AuditLogs → where TimeGenerated > ago(7d) → summarize count() by OperationName → order by count_ desc to confirm which OperationName values are present for user creation and credential operations in your tenant.
- Add known provisioning service principal ObjectIds or IP ranges to a pre-filter exclusion to suppress legitimate bulk onboarding.
- Extend keyIssuanceWindow beyond 1 hour if your onboarding workflow has a longer delay between account creation and credential provisioning.
- Consider adding a UserAgent filter on accountCreations if your WAF or Entra ID logs capture user agent strings for the creation requests, as automated farming tools often use non-browser agents.

**Risks / caveats:**
- SourceIP extraction from AdditionalDetails using parse_json(tostring(AdditionalDetails))[0].value is fragile. The AdditionalDetails field structure varies by OperationName in Entra ID AuditLogs. For user creation events, the initiating IP is typically in InitiatedBy.user.ipAddress or InitiatedBy.app.ipAddress, not AdditionalDetails[0].value. This extraction may return null for most events, causing the bulkCreators join to produce no results.
- The Result field in AuditLogs uses 'success' as a string value, but the actual field name is 'ResultDescription' or the Result field may be an enum. Confirm with: AuditLogs → summarize count() by Result → take 20.
- The join on CreatedUser == ActorUPN assumes the newly created account immediately performs the API key operation under its own UPN. If an admin account creates users and then provisions credentials on their behalf, the UPN join will not match.
- SourceIP may be null for events initiated by service principals without an associated IP in InitiatedBy.app.ipAddress; the isnotempty filter will exclude these events.

### Triage Runbook

**First 15 minutes:**
- Confirm the account creation and API key issuance events are real and not a provisioning workflow or test environment activity.
- Identify the source IP, created accounts, and the actor UPNs involved in the sequence.
- Check whether the accounts are external, newly invited, or tied to a known automation or onboarding system.
- Look for additional suspicious identity activity such as password resets, MFA changes, consent grants, or sign-ins from unusual locations.

**Evidence to collect:**
- CreationTime, KeyTime, SourceIP, CreatedUser, ApiKeyOperationName, and AccountsCreated.
- The full AuditLogs records for the account creation and credential issuance events.
- InitiatedBy details, including user or app identity and any available IP address.
- Any sign-in activity for the newly created accounts after creation.
- Tenant or application context showing whether the affected accounts belong to an LLM API platform, web app, or internal provisioning system.

**Pivot points:**
- AuditLogs for the same SourceIP, CreatedUser, and ActorUPN over a wider time window.
- SigninLogs or equivalent sign-in telemetry for the newly created accounts.
- AuditLogs for related operations such as password resets, MFA changes, app consent, or role assignments.
- If available, application logs from the LLM/API platform to confirm whether the accounts were used to generate credentials.

**Benign explanations:**
- Legitimate bulk onboarding or identity governance workflows.
- Developer or test environments where accounts and API keys are created in batches.
- Multi-tenant provisioning automation that creates accounts and credentials as part of normal operations.

**Escalation criteria:**
- The source IP is unknown or external and the account creation pattern is not tied to an approved workflow.
- The newly created accounts are used to generate credentials and then sign in from suspicious locations or at scale.
- You find additional identity abuse, such as consent grants, MFA tampering, or privilege changes.
- The activity affects production tenants or customer-facing LLM/API services.

**Containment actions:**
- Disable or suspend the newly created accounts if they are unauthorized.
- Revoke newly issued API keys or tokens associated with the suspicious accounts.
- Block the source IP or automation path if it is clearly malicious and not shared with legitimate systems.
- Coordinate with identity and application owners to preserve evidence before mass remediation.

**Closure criteria:**
- The activity is confirmed as approved provisioning, onboarding, or test automation.
- The source IP and actor identity match a documented business process.
- No unauthorized sign-ins, credential use, or additional identity abuse is found.
- Any suspicious accounts or keys have been revoked and the environment shows no further abuse.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- SPIRE Agent Socket Access by Root Process on Kubernetes Node: Defender for Endpoint file-event coverage must be confirmed on the target host population.
- Non-SPIRE Root Process Reading SVID or SPIFFE Identity Files on Kubernetes Node: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- Apache Tika XXE Exploitation Attempt via XFA Document Upload: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Elasticsearch Ingest-Attachment Local File Read Scanning (CVE-2025-54988 / CVE-2025-66516): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Schema / correlation keys:**
- Bulk Account Creation Followed by Rapid API Key Generation Consistent with LLM Credential Farming: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceFileEvents: shared by SPIRE Agent Socket Access by Root Process on Kubernetes Node; Non-SPIRE Root Process Reading SVID or SPIFFE Identity Files on Kubernetes Node
- CommonSecurityLog: shared by Apache Tika XXE Exploitation Attempt via XFA Document Upload; Elasticsearch Ingest-Attachment Local File Read Scanning (CVE-2025-54988 / CVE-2025-66516)

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: SPIRE Agent Socket Access by Root Process on Kubernetes Node; Non-SPIRE Root Process Reading SVID or SPIFFE Identity Files on Kubernetes Node; Apache Tika XXE Exploitation Attempt via XFA Document Upload; Elasticsearch Ingest-Attachment Local File Read Scanning (CVE-2025-54988 / CVE-2025-66516).
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Bulk Account Creation Followed by Rapid API Key Generation Consistent with LLM Credential Farming.

### Hunting Agenda and Promotion Criteria

- Bulk Account Creation Followed by Rapid API Key Generation Consistent with LLM Credential Farming: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- SPIRE Agent Socket Access by Root Process on Kubernetes Node: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold.
- Non-SPIRE Root Process Reading SVID or SPIFFE Identity Files on Kubernetes Node: Defender for Endpoint file-event coverage must be confirmed on the target host population.; confirm required file-access telemetry exists and produces representative events.
- Apache Tika XXE Exploitation Attempt via XFA Document Upload: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Elasticsearch Ingest-Attachment Local File Read Scanning (CVE-2025-54988 / CVE-2025-66516): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
