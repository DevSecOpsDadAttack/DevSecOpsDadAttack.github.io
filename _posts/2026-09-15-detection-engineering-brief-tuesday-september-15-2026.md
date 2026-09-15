---
layout: post
title: "Detection Engineering Brief - Tuesday, September 15, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-15
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-85706
  - T1190
  - GitLab CE
  - GitLab EE
  - CVE-2025-66516
  - CVE-2025-54988
  - Apache Tika
  - Metasploit
  - Cisco
  - PaperCut
  - SonicWall
  - JetBrains
  - Langflow
  - Elasticsearch
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 1 hunting-only, 4 require environment mapping, and 0 rejected.

5 detections include KQL. 3 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-85706, T1190, GitLab CE, GitLab EE, CVE-2025-66516, CVE-2025-54988, Apache Tika, Metasploit, Cisco, PaperCut, SonicWall, JetBrains, Langflow, Elasticsearch.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: GitLab Commits API Path Traversal Attempt - CVE-2026-85706; GitLab Process Reading Sensitive Files Outside Expected Paths - CVE-2026-85706; XXE Payload in POST Request to Apache Tika Endpoint - CVE-2025-54988 / CVE-2025-66516; Metasploit Default User Agent or Staging Pattern Detected Against Network Services; WAF or IDS Alert Referencing CVE-2026-85706 GitLab Path Traversal.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: GitLab Commits API Path Traversal Attempt - CVE-2026-85706

### Detection Opportunity

Unauthenticated path traversal requests to GitLab repository commits API containing directory traversal sequences

### Intelligence Context

- Rapid7: CVE-2026-85706: Critical GitLab Path Traversal Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild)
  - Context: Rapid7 reported active exploitation of CVE-2026-85706, a path traversal vulnerability in the GitLab repository commits API. Unauthenticated attackers can read arbitrary files by embedding traversal sequences in API requests. The vulnerability was added to CISA's KEV catalog confirming in-the-wild exploitation.

### Search Metadata

- CVEs: CVE-2026-85706
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: GitLab CE, GitLab EE
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-85706, T1190, GitLab CE, GitLab EE

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where RequestURL has_any ("/api/v4/projects", "/commits")
| where RequestURL has_any ("../", "..%2f", "..%2F", "%2e%2e", "%2E%2E", "%2e%2e%2f", "%2E%2E%2F", "%2e%2e/", "..%5c", "..%5C")
| extend TraversalType = case(
    RequestURL has "../", "decoded_traversal",
    RequestURL has_any ("..%2f", "..%2F"), "encoded_slash_traversal",
    RequestURL has_any ("%2e%2e%2f", "%2E%2E%2F", "%2e%2e/"), "double_encoded_traversal",
    RequestURL has_any ("%2e%2e", "%2E%2E"), "encoded_dots",
    RequestURL has_any ("..%5c", "..%5C"), "backslash_traversal",
    "other"
  )
| summarize
    AttemptCount = count(),
    DistinctURLs = dcount(RequestURL),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleURLs = make_set(RequestURL, 5),
    TraversalTypes = make_set(TraversalType, 5)
    by SourceIP, RequestMethod, DeviceVendor, DeviceProduct
| extend CVE = "CVE-2026-85706"
| project-reorder SourceIP, RequestMethod, AttemptCount, DistinctURLs, TraversalTypes, FirstSeen, LastSeen, SampleURLs, DeviceVendor, DeviceProduct, CVE
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated vulnerability scanners or penetration testing tools running against GitLab from authorized internal IP ranges.
- Security monitoring tools that replay or log raw request URIs including traversal sequences for audit purposes.
- URL-encoded characters in legitimate repository or branch names that coincidentally match traversal patterns.

**Tuning notes:**
- After confirming GitLab traffic is present in CommonSecurityLog, add a DeviceVendor or DeviceProduct filter to scope results to the specific WAF or proxy protecting GitLab.
- Raise AttemptCount threshold to 3 or 5 after baselining to reduce noise from single-probe scanners if alert volume is high.
- Consider adding a DestinationIP or DestinationHostName filter if multiple applications share the same WAF log source.

**Risks / caveats:**
- CommonSecurityLog is only populated when a CEF-compatible WAF, IDS, or reverse proxy connector is deployed and forwarding GitLab HTTP traffic to the Sentinel workspace. If no such connector exists, the table will be empty for this traffic.
- RequestURL field population depends on the specific WAF or proxy vendor CEF mapping. Some appliances do not populate RequestURL with the full URI or omit query strings and path components containing encoded characters.
- Threshold of one attempt per summarization window may generate alert volume during active scanning campaigns. Consider raising AttemptCount threshold after baselining normal traffic patterns.
- The 24-hour lookback window may miss low-and-slow traversal attempts spread across multiple days. Adjust based on organizational detection latency requirements.

### Triage Runbook

**First 15 minutes:**
- Confirm the GitLab instance is internet-facing and that the source IP is not on an approved scanner, pentest, or red-team allowlist.
- Review the sample RequestURL values for decoded or encoded traversal sequences and verify the request targets the GitLab commits API path.
- Check AttemptCount, DistinctURLs, FirstSeen, and LastSeen to see whether this is a single probe or repeated scanning from the same source.
- Correlate the SourceIP with any WAF, reverse proxy, or IDS alerts for the same time window to determine whether the request was blocked or flagged as malicious.

**Evidence to collect:**
- SourceIP, RequestMethod, SampleURLs, TraversalTypes, AttemptCount, DistinctURLs, FirstSeen, LastSeen, DeviceVendor, and DeviceProduct from the alert.
- Any WAF/IDS event details showing action taken, response code, or rule name for the same source IP and time window.
- GitLab access logs or application logs showing whether the request reached the application and whether any file-read behavior or error responses occurred.
- Asset context for the targeted GitLab host, including exposure to the internet and whether it contains sensitive repositories or secrets.

**Pivot points:**
- CommonSecurityLog for the same SourceIP, DeviceVendor, and DeviceProduct over the prior 24 hours to identify broader scanning or additional GitLab endpoints targeted.
- SecurityAlert for the same SourceIP to find related path traversal, exploit, or web attack alerts.
- GitLab web or reverse proxy logs to confirm whether the request was forwarded, blocked, or returned an error.
- Threat intel or allowlist records for the SourceIP to validate whether it belongs to an authorized scanner.

**Benign explanations:**
- An approved vulnerability scanner or penetration test may intentionally probe GitLab with traversal patterns.
- A security appliance or monitoring tool may log raw encoded URIs that resemble traversal even when the request was normalized or blocked.
- A legitimate request path or repository name may contain URL-encoded characters that coincidentally match traversal signatures.

**Escalation criteria:**
- Escalate immediately if the source is external, not allowlisted, and the request pattern is repeated or targets multiple GitLab URLs.
- Escalate if WAF or proxy logs show the request was allowed through or if GitLab logs indicate unusual file access, errors, or secrets-related activity.
- Escalate if there is any evidence of successful file disclosure, follow-on authentication attempts, or additional exploitation against the same host.

**Containment actions:**
- If the source is confirmed malicious or clearly unauthorized, block the SourceIP at the WAF, reverse proxy, or perimeter firewall.
- If exploitation appears successful or likely, isolate the GitLab host from the network only after preserving logs and coordinating with the platform owner.
- Disable or restrict public access to the affected GitLab endpoint if emergency mitigation is required and business impact is acceptable.

**Closure criteria:**
- The source is confirmed as an authorized scanner or test and the activity matches the approved scope.
- WAF/proxy logs show the request was blocked and no application-side file access or suspicious follow-on activity occurred.
- No additional requests, alerts, or evidence of exploitation are observed from the same source IP after the initial event window.

<br/>
---
<br/>

## Detection 2: GitLab Process Reading Sensitive Files Outside Expected Paths - CVE-2026-85706

### Detection Opportunity

GitLab web process reading sensitive system files such as /etc/passwd or GitLab secrets outside expected application directories, consistent with arbitrary file read via path traversal

### Intelligence Context

- Rapid7: CVE-2026-85706: Critical GitLab Path Traversal Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild)
  - Context: CVE-2026-85706 allows unauthenticated attackers to read arbitrary files on the GitLab server via path traversal in the commits API. Successful exploitation results in the GitLab web process accessing sensitive files such as /etc/passwd or application secrets outside its expected working directories.

### Search Metadata

- CVEs: CVE-2026-85706
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: GitLab CE, GitLab EE
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-85706, T1190, GitLab CE, GitLab EE

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp >= ago(7d)
| where ActionType == "FileRead"
| where InitiatingProcessName has_any ("puma", "unicorn", "gitlab-workhorse", "ruby")
| where (
    FolderPath has_any ("/etc/", "/.ssh/", "/root/", "/home/")
    or FolderPath has "/var/opt/gitlab/gitlab-rails/etc"
    or FileName has_any ("passwd", "shadow", "secrets.yml", "database.yml", "id_rsa", "authorized_keys")
  )
| where not (
    FolderPath has_any ("/var/opt/gitlab/", "/opt/gitlab/", "/usr/lib/gitlab/")
    and not FolderPath has "/var/opt/gitlab/gitlab-rails/etc"
  )
| project
    Timestamp,
    DeviceName,
    InitiatingProcessName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentName,
    FolderPath,
    FileName,
    AccountName
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- GitLab processes legitimately read /etc/passwd during user resolution operations as part of normal application behavior.
- Ruby-based applications other than GitLab running on the same host that use puma or unicorn process names.
- Configuration management or monitoring agents that read secrets.yml or database.yml for validation purposes under a ruby process.

**Tuning notes:**
- Run DeviceFileEvents → where DeviceName contains 'gitlab' → where InitiatingProcessName has_any('puma','unicorn','ruby','gitlab-workhorse') → summarize count() by InitiatingProcessName to confirm process name coverage before relying on this filter.
- Add DeviceName filter scoped to known GitLab server hostnames to prevent matching other Ruby applications in the environment.
- Consider correlating FileRead events with concurrent network connections from external IPs to the GitLab server to increase confidence that the file read was triggered by an inbound exploit request.

**Risks / caveats:**
- Defender for Endpoint agent must be deployed on the GitLab server host. GitLab servers are frequently Linux-based and may not have MDE Linux agent deployed, resulting in no DeviceFileEvents telemetry for that host.
- FileRead ActionType availability in DeviceFileEvents depends on MDE sensor configuration and Linux kernel audit integration. Not all Linux deployments emit FileRead events for every file access.
- The 7-day lookback window is appropriate for hunting but may be too broad for a scheduled rule. Reduce to 1 day if converted to a scheduled analytic.
- The FolderPath exclusion for GitLab application directories may need adjustment based on the specific GitLab installation path in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the DeviceName is a known GitLab server and identify the deployment type so the process names and paths are interpreted correctly.
- Review the FolderPath and FileName values to see whether the read was of a truly sensitive file such as /etc/passwd, /etc/shadow, secrets.yml, or SSH key material.
- Check InitiatingProcessName, InitiatingProcessCommandLine, and InitiatingProcessParentName to verify the read came from a GitLab worker process rather than an unrelated Ruby application.
- Correlate the file read timestamp with inbound web requests from the same time window to determine whether the access was triggered by an external request.

**Evidence to collect:**
- Timestamp, DeviceName, InitiatingProcessName, InitiatingProcessCommandLine, InitiatingProcessParentName, FolderPath, FileName, and AccountName from the alert.
- Nearby DeviceFileEvents showing additional reads of secrets, configuration files, or SSH material by the same process tree.
- Web or reverse proxy logs from the same host and time window to identify the triggering request and source IP.
- Host context showing whether the file path is expected for the specific GitLab installation or whether it is outside the application directory.

**Pivot points:**
- DeviceFileEvents on the same DeviceName and InitiatingProcessName for the prior 24 hours to identify repeated sensitive file reads.
- DeviceNetworkEvents or proxy logs for the same DeviceName around the file-read time to correlate inbound requests with the file access.
- SecurityAlert or WAF logs for the same source IP if a web request appears to have triggered the file read.
- Process creation telemetry on the GitLab host to validate the process tree and determine whether the read occurred during startup or normal maintenance.

**Benign explanations:**
- GitLab may legitimately read /etc/passwd during user resolution or startup-related operations.
- Configuration management, backup, or monitoring agents may read secrets or database configuration files for validation.
- Another Ruby-based application on the same host may produce similar process names and file-read patterns unrelated to GitLab exploitation.

**Escalation criteria:**
- Escalate if the file read involves secrets, private keys, shadow files, or other high-value material outside the normal GitLab application paths.
- Escalate if the file read is temporally linked to an external request from an untrusted source IP or to a prior path traversal alert.
- Escalate if multiple sensitive files are read in sequence or if there is evidence of subsequent authentication abuse, lateral movement, or credential use.

**Containment actions:**
- If exploitation is suspected, isolate the GitLab host from the network while preserving volatile and log evidence.
- Rotate or revoke any secrets, tokens, SSH keys, or credentials that may have been exposed through the file read.
- Block the triggering source IP and disable public access to the vulnerable GitLab service until patched or mitigated.

**Closure criteria:**
- The file access is confirmed as expected GitLab behavior or an approved administrative action.
- No correlation exists between the file read and external web requests, and no additional suspicious file reads are present.
- The host owner confirms the accessed files are non-sensitive in this environment and the process tree matches normal operation.

<br/>
---
<br/>

## Detection 3: XXE Payload in POST Request to Apache Tika Endpoint - CVE-2025-54988 / CVE-2025-66516

### Detection Opportunity

HTTP POST requests to Apache Tika endpoints containing XML External Entity payload patterns (DOCTYPE or ENTITY declarations) consistent with Metasploit XXE scanner module exploitation

### Intelligence Context

- Rapid7: Metasploit Wrap Up: This One Goes to Sixteen! — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen)
  - Context: Rapid7 released a Metasploit auxiliary scanner module targeting CVE-2025-54988 and CVE-2025-66516, an XML External Entity vulnerability in Apache Tika's XFA parser. The module sends crafted POST requests containing XXE payloads to Tika endpoints to validate exploitability. XXE payloads are identifiable by DOCTYPE and ENTITY XML declarations in request bodies.

### Search Metadata

- CVEs: CVE-2025-66516, CVE-2025-54988
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: Apache Tika
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2025-66516, CVE-2025-54988, Apache Tika, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Not mapped

### Deployment Gates

- FieldDeviceCustomNumber1 is used as a proxy for HTTP status code but this mapping is not standardized across CEF vendors. The field may be empty or contain a different numeric value depending on the appliance.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where RequestMethod == "POST"
| where RequestURL has_any ("/tika", "/rmeta", "/meta", "/unpack")
| where AdditionalExtensions has_any ("DOCTYPE", "ENTITY", "SYSTEM", "PUBLIC")
    or RequestURL has_any ("DOCTYPE", "ENTITY")
| summarize
    AttemptCount = count(),
    DistinctURLs = dcount(RequestURL),
    ResponseCodes = make_set(EventOutcome, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleURLs = make_set(RequestURL, 5)
    by SourceIP, DeviceVendor, DeviceProduct
| extend
    CVEs = "CVE-2025-54988, CVE-2025-66516",
    Tool = "Metasploit"
| project-reorder SourceIP, AttemptCount, DistinctURLs, ResponseCodes, FirstSeen, LastSeen, SampleURLs, DeviceVendor, DeviceProduct, CVEs, Tool
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate XML document processing tools that POST XML content containing DOCTYPE declarations to Tika for document parsing.
- Internal content management or document conversion pipelines that submit XML-based documents to Tika endpoints.
- Authorized security scanning tools testing Tika endpoints for XXE vulnerability.

**Tuning notes:**
- Before deploying, run: CommonSecurityLog → where RequestURL has '/tika' → take 5 → project AdditionalExtensions, DeviceCustomString1, DeviceCustomString2, DeviceCustomString3 to identify which field the WAF uses for request body or content-type inspection.
- If the WAF does not populate AdditionalExtensions with body content, consider pivoting to Syslog and searching for Apache Tika application log entries referencing SAXParseException, DOCTYPE, or ENTITY parse errors as an alternative signal.
- Replace EventOutcome with FieldDeviceCustomNumber1 if the specific WAF connector maps HTTP status code to that field rather than EventOutcome.

**Risks / caveats:**
- AdditionalExtensions is a free-form CEF field and its content is entirely vendor-dependent. The majority of WAF and proxy CEF connectors do not include HTTP request body content in AdditionalExtensions. If the WAF does not forward body content, the DOCTYPE and ENTITY filter conditions will never match and the query will produce no results.
- FieldDeviceCustomNumber1 is used as a proxy for HTTP status code but this mapping is not standardized across CEF vendors. The field may be empty or contain a different numeric value depending on the appliance.
- If AdditionalExtensions does not carry request body content, the primary detection signal is absent and only URL-embedded XXE patterns will match, which are uncommon in practice.
- EventOutcome field may be empty for some WAF vendors; response code visibility depends on the specific CEF connector implementation.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is not an approved scanner, test harness, or internal document-processing system.
- Inspect the RequestURL and AdditionalExtensions values for XXE indicators such as DOCTYPE, ENTITY, SYSTEM, or PUBLIC and verify the request method is POST.
- Check AttemptCount, DistinctURLs, and ResponseCodes to see whether this is a single validation probe or repeated exploitation attempts.
- Determine whether the request was blocked by the WAF/proxy or forwarded to the Apache Tika backend.

**Evidence to collect:**
- SourceIP, RequestURL, RequestMethod, AttemptCount, DistinctURLs, ResponseCodes, FirstSeen, LastSeen, DeviceVendor, DeviceProduct, and CVEs from the alert.
- Raw WAF or proxy log entries showing request body or content-type details, if available, to confirm the XXE payload pattern.
- Apache Tika application logs for parse errors, SAXParseException, or entity resolution activity around the same time.
- Asset context for the Tika deployment path and whether it is exposed externally or only used internally.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DeviceProduct to identify additional POSTs to /tika, /rmeta, /meta, or /unpack.
- Syslog or application logs from the Tika host for XML parsing errors, stack traces, or entity resolution messages.
- SecurityAlert for the same source IP to find related web exploit or scanner alerts.
- Proxy or WAF logs to determine whether the request body was inspected, blocked, or allowed through.

**Benign explanations:**
- Legitimate XML-based document processing workflows may submit XML content that includes DOCTYPE declarations.
- Internal content conversion or indexing pipelines may POST structured documents to Tika endpoints as part of normal operations.
- An authorized vulnerability assessment may intentionally test for XXE exposure using similar payloads.

**Escalation criteria:**
- Escalate if the source is external, not allowlisted, and the payload clearly contains XXE markers.
- Escalate if Tika logs show XML parser errors, entity resolution attempts, or signs that the payload reached the backend service.
- Escalate if there are repeated attempts, multiple endpoints targeted, or any evidence of successful file access or outbound entity resolution.

**Containment actions:**
- Block the source IP at the WAF or perimeter if the activity is unauthorized or clearly malicious.
- If the request reached Tika and exploitation is suspected, restrict access to the Tika service until the vulnerability is mitigated.
- Coordinate with the application owner to disable or limit external exposure of the Tika endpoint if immediate risk is high.

**Closure criteria:**
- The activity is confirmed as an authorized test or expected internal document-processing traffic.
- WAF/proxy logs show the request was blocked and Tika logs show no parsing or entity resolution activity.
- No additional XXE attempts or related alerts are observed from the same source IP after the event window.

<br/>
---
<br/>

## Detection 4: Metasploit Default User Agent or Staging Pattern Detected Against Network Services

### Detection Opportunity

Network requests bearing Metasploit default user agent strings or known payload staging URI patterns targeting vulnerable products including Cisco, PaperCut, SonicWall, JetBrains, and Langflow

### Intelligence Context

- Rapid7: Metasploit Wrap Up: This One Goes to Sixteen! — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen)
  - Context: Rapid7 released sixteen new Metasploit modules including ten exploit modules targeting Cisco, PaperCut, SonicWall, JetBrains, Langflow, Elasticsearch, and Apache Tika. Metasploit framework produces recognizable behavioral signatures including default user agent strings and payload staging URI patterns that are detectable in network and WAF telemetry.

### Search Metadata

- CVEs: CVE-2025-66516, CVE-2025-54988
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: Cisco, PaperCut, SonicWall, JetBrains, Langflow, Elasticsearch, Apache Tika
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2025-66516, CVE-2025-54988, Cisco, PaperCut, SonicWall, JetBrains, Langflow, Elasticsearch, Apache Tika, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- DeviceCustomString1 User-Agent mapping must be validated against the specific WAF or proxy connector before this query produces meaningful UA-based matches.

**Required telemetry:**
- CommonSecurityLog, SecurityAlert

### KQL

```kql
let MetasploitUAs = dynamic(["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "Wget/1.9+cvs-stable"]);
let MetasploitAlerts =
    SecurityAlert
    | where TimeGenerated >= ago(24h)
    | where AlertName has_any ("CVE-2025-54988", "CVE-2025-66516", "Metasploit", "path traversal", "XXE")
    | mv-expand Entity = parse_json(Entities)
    | where Entity.Type == "ip"
    | extend AlertSourceIP = tostring(Entity.Address)
    | where isnotempty(AlertSourceIP)
    | summarize AlertNames = make_set(AlertName, 5), AlertCount = count() by AlertSourceIP;
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where RequestMethod in ("GET", "POST")
| where DeviceCustomString1 has_any (MetasploitUAs)
    or RequestURL has_any ("/MSF", "/payload", "/stage", "meterpreter")
| summarize
    RequestCount = count(),
    DistinctDestinations = dcount(DestinationIP),
    SampleURLs = make_set(RequestURL, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DeviceVendor, DeviceProduct
| join kind=leftouter MetasploitAlerts on $left.SourceIP == $right.AlertSourceIP
| project-reorder SourceIP, RequestCount, DistinctDestinations, AlertNames, AlertCount, SampleURLs, FirstSeen, LastSeen, DeviceVendor, DeviceProduct
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate use of Wget or MSIE 6.0 user agents by legacy internal applications or monitoring tools.
- Authorized penetration testing engagements using Metasploit framework against internal targets.
- Security research or red team activity generating staging URI patterns in controlled environments.

**Tuning notes:**
- Run CommonSecurityLog → take 5 → project DeviceCustomString1, DeviceCustomString2, DeviceCustomString3, AdditionalExtensions to identify which field carries the User-Agent value for the specific WAF connector in the environment.
- Expand MetasploitUAs with additional Metasploit default user agents identified through threat intelligence or red team documentation relevant to the specific modules of concern.
- Add DistinctDestinations >= 2 filter to the final results to focus on scan campaigns rather than single-target probes.

**Risks / caveats:**
- DeviceCustomString1 is not a standardized field for HTTP User-Agent in CommonSecurityLog. The User-Agent field mapping varies by WAF and proxy vendor. If the WAF does not populate DeviceCustomString1 with the User-Agent value, the UA-based filter will never match.
- SecurityAlert population with CVE-specific or Metasploit-specific alert names depends on connected IDS, WAF, or Defender for Cloud having signatures for these CVEs. If no such signatures exist, the MetasploitAlerts subquery returns no rows and the join adds no value.
- The Entities field JSON path parse_json(Entities)[0].Address assumes the first entity in the array is an IP address, which is not guaranteed and may extract incorrect values.
- DeviceCustomString1 User-Agent mapping must be validated against the specific WAF or proxy connector before this query produces meaningful UA-based matches.

### Triage Runbook

**First 15 minutes:**
- Verify whether the source IP belongs to an approved scanner, red team, or penetration test activity.
- Review the RequestURL patterns and the user-agent-like field to confirm whether the traffic matches known Metasploit staging behavior or a generic legacy client.
- Check whether the same source IP targeted multiple destination IPs, which would suggest scanning rather than a single-user request.
- Look for any correlated SecurityAlert entries that reference the same source IP, destination IP, or CVE names.

**Evidence to collect:**
- SourceIP, DestinationIP, RequestCount, DistinctDestinations, SampleURLs, FirstSeen, LastSeen, DeviceVendor, DeviceProduct, and any AlertNames returned by the correlation.
- The exact user-agent or staging pattern values from the proxy/WAF logs, if the connector populates DeviceCustomString1 or related fields.
- Any matching SecurityAlert records showing exploit, web attack, or CVE-specific signatures for the same source IP.
- Asset inventory for the destination hosts to determine whether they are internet-facing and whether the targeted products are present.

**Pivot points:**
- CommonSecurityLog for the same SourceIP across the prior 24 hours to identify broader scanning behavior and additional destinations.
- SecurityAlert for the same SourceIP and DestinationIP to find exploit or malware-related alerts.
- Firewall, proxy, or IDS logs to determine whether the traffic was blocked, allowed, or partially successful.
- Threat intel and allowlist records to validate whether the source is a known security tool or benign legacy client.

**Benign explanations:**
- Authorized vulnerability scanning or penetration testing may use Metasploit and generate recognizable staging patterns.
- Legacy internal applications or monitoring tools may use old or unusual user-agent strings that resemble the detection pattern.
- Security research or lab activity may intentionally generate these requests in controlled environments.

**Escalation criteria:**
- Escalate if the source is external, not allowlisted, and targets multiple destinations or multiple vulnerable products.
- Escalate if correlated SecurityAlert entries indicate exploit success, web shell activity, or CVE-specific malicious behavior.
- Escalate if the destination is a critical internet-facing service and the traffic pattern is repeated or accompanied by suspicious follow-on requests.

**Containment actions:**
- Block the source IP if the activity is unauthorized or clearly malicious.
- If correlated alerts or backend logs suggest compromise, isolate the affected service or host and preserve evidence before remediation.
- Coordinate with the application owner to restrict exposure of the targeted service if the attack surface is unnecessary.

**Closure criteria:**
- The source is confirmed as authorized testing or a known benign legacy client.
- No correlated exploit alerts, backend errors, or suspicious follow-on activity are found for the same source and destination.
- The traffic stops after the initial event and no additional destinations or services are targeted.

<br/>
---
<br/>

## Detection 5: WAF or IDS Alert Referencing CVE-2026-85706 GitLab Path Traversal

### Detection Opportunity

Security appliance alert referencing CVE-2026-85706 or path traversal signatures targeting GitLab endpoints, correlated with network requests from the same source IP

### Intelligence Context

- Rapid7: CVE-2026-85706: Critical GitLab Path Traversal Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild)
  - Context: CISA added CVE-2026-85706 to the Known Exploited Vulnerabilities catalog based on confirmed in-the-wild exploitation. WAF and IDS vendors are expected to release signatures for this CVE. Correlating security appliance alerts with raw network request logs from the same source IP provides a compound signal with higher confidence than either source alone.

### Search Metadata

- CVEs: CVE-2026-85706
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: GitLab CE, GitLab EE
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-85706, T1190, GitLab CE, GitLab EE

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- SecurityAlert must contain CVE-2026-85706-specific or GitLab path traversal alert signatures from a connected WAF, IDS, or Defender for Cloud connector. If no such signatures exist or have been deployed, the GitLabAlerts subquery returns zero rows and the inner join produces no output.

**Required telemetry:**
- SecurityAlert, CommonSecurityLog

### KQL

```kql
let GitLabAlerts =
    SecurityAlert
    | where TimeGenerated >= ago(24h)
    | where AlertName has_any ("CVE-2026-85706", "GitLab", "path traversal")
    | mv-expand Entity = parse_json(Entities)
    | where Entity.Type == "ip"
    | extend AlertSourceIP = tostring(Entity.Address)
    | where isnotempty(AlertSourceIP)
    | summarize
        AlertCount = count(),
        AlertNames = make_set(AlertName, 5),
        AlertSeverity = take_any(AlertSeverity),
        FirstAlert = min(TimeGenerated)
        by AlertSourceIP;
let TraversalRequests =
    CommonSecurityLog
    | where TimeGenerated >= ago(24h)
    | where RequestURL has_any ("/api/v4/projects", "/commits")
    | where RequestURL has_any ("../", "%2e%2e", "..%2f", "%2e%2e%2f", "..%5c", "%2E%2E", "..%2F", "%2E%2E%2F", "..%5C")
    | summarize
        RequestCount = count(),
        MatchedURLs = make_set(RequestURL, 5),
        LastRequest = max(TimeGenerated)
        by SourceIP, RequestMethod;
GitLabAlerts
| join kind=inner TraversalRequests on $left.AlertSourceIP == $right.SourceIP
| where abs(datetime_diff('minute', FirstAlert, LastRequest)) <= 60
| extend CVE = "CVE-2026-85706"
| project-reorder AlertSourceIP, AlertNames, AlertSeverity, AlertCount, RequestCount, RequestMethod, MatchedURLs, FirstAlert, LastRequest, CVE
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- WAF signatures for generic path traversal may fire on legitimate application requests that contain traversal-like patterns in repository or branch names.
- Security monitoring tools that replay or simulate attack traffic for detection validation may trigger both the alert and the raw request log match.

**Tuning notes:**
- Validate SecurityAlert contains relevant alerts by running: SecurityAlert → where AlertName has_any('CVE-2026-85706','GitLab','path traversal') → summarize count() by AlertName before scheduling.
- Extend the datetime_diff threshold from 60 to 120 minutes if WAF alert ingestion latency causes correlation misses.
- Add AlertSeverity filter to restrict GitLabAlerts to High or Critical if lower-severity generic path traversal signatures generate excessive volume.

**Risks / caveats:**
- SecurityAlert must contain CVE-2026-85706-specific or GitLab path traversal alert signatures from a connected WAF, IDS, or Defender for Cloud connector. If no such signatures exist or have been deployed, the GitLabAlerts subquery returns zero rows and the inner join produces no output.
- CommonSecurityLog requires a CEF-compatible WAF or proxy connector forwarding GitLab HTTP traffic. Without this connector, the TraversalRequests subquery returns no rows.
- The Entities field JSON structure in SecurityAlert varies by alert source. The parse_json(Entities)[0].Address pattern assumes the first entity is an IP address, which is not guaranteed across all alert providers.
- The 60-minute correlation window between alert time and request time may miss cases where WAF alert ingestion latency exceeds one hour. Extend the window if alert latency is known to be higher.

### Triage Runbook

**First 15 minutes:**
- Validate that the alert source IP matches a GitLab request in CommonSecurityLog within the same time window.
- Review AlertName and AlertSeverity to determine whether the appliance classified the event as a high-confidence exploit or a generic traversal signature.
- Inspect the matched RequestURL values for encoded or decoded traversal sequences and confirm the target path is the GitLab commits API.
- Check whether the alert was blocked, allowed, or only logged by the security appliance.

**Evidence to collect:**
- AlertSourceIP, AlertName, AlertSeverity, AlertCount, MatchedURLs, FirstAlert, LastRequest, and CVE from the alert.
- The corresponding CommonSecurityLog request details, including RequestMethod, RequestURL, DeviceVendor, and DeviceProduct.
- Any WAF/IDS rule identifiers, action taken, and response codes associated with the alert.
- GitLab server logs or reverse proxy logs to determine whether the request reached the application.

**Pivot points:**
- SecurityAlert for the same AlertSourceIP to find additional exploit or traversal alerts across the environment.
- CommonSecurityLog for the same SourceIP to identify repeated requests, other endpoints, or broader scanning behavior.
- GitLab application and proxy logs to confirm whether the request was forwarded and whether any file access occurred.
- Threat intel or allowlist records to determine whether the source is an approved scanner or test system.

**Benign explanations:**
- An authorized vulnerability scan or penetration test may trigger both the WAF/IDS alert and the raw request match.
- Generic path traversal signatures may fire on legitimate requests that contain traversal-like encoded strings in repository or branch names.
- Security validation tools may intentionally replay attack traffic to verify detection coverage.

**Escalation criteria:**
- Escalate if the alert severity is High or Critical and the same source IP has matching raw traversal requests.
- Escalate if the WAF/IDS indicates the request was allowed through or if GitLab logs show unusual file access or errors.
- Escalate if there are multiple alerts from the same source IP or evidence of follow-on exploitation attempts.

**Containment actions:**
- Block the source IP at the WAF or perimeter if the activity is unauthorized or clearly malicious.
- If the request reached GitLab and exploitation is suspected, isolate the host or restrict access to the affected service while preserving logs.
- Coordinate emergency patching or mitigation for CVE-2026-85706 if the environment is exposed and not yet remediated.

**Closure criteria:**
- The source is confirmed as authorized testing or a known benign scanner.
- The WAF/IDS alert is determined to be a false positive and no matching application-side impact is found.
- No additional matching alerts or raw traversal requests are observed from the same source IP after the event.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- GitLab Commits API Path Traversal Attempt - CVE-2026-85706: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Metasploit Default User Agent or Staging Pattern Detected Against Network Services: DeviceCustomString1 User-Agent mapping must be validated against the specific WAF or proxy connector before this query produces meaningful UA-based matches.
- WAF or IDS Alert Referencing CVE-2026-85706 GitLab Path Traversal: SecurityAlert must contain CVE-2026-85706-specific or GitLab path traversal alert signatures from a connected WAF, IDS, or Defender for Cloud connector. If no such signatures exist or have been deployed, the GitLabAlerts subquery returns zero rows and the inner join produces no output.

**Other deployment dependency:**
- GitLab Process Reading Sensitive Files Outside Expected Paths - CVE-2026-85706: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- XXE Payload in POST Request to Apache Tika Endpoint - CVE-2025-54988 / CVE-2025-66516: FieldDeviceCustomNumber1 is used as a proxy for HTTP status code but this mapping is not standardized across CEF vendors. The field may be empty or contain a different numeric value depending on the appliance.
- Metasploit Default User Agent or Staging Pattern Detected Against Network Services: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- CommonSecurityLog: shared by GitLab Commits API Path Traversal Attempt - CVE-2026-85706; XXE Payload in POST Request to Apache Tika Endpoint - CVE-2025-54988 / CVE-2025-66516; Metasploit Default User Agent or Staging Pattern Detected Against Network Services; WAF or IDS Alert Referencing CVE-2026-85706 GitLab Path Traversal
- SecurityAlert: shared by Metasploit Default User Agent or Staging Pattern Detected Against Network Services; WAF or IDS Alert Referencing CVE-2026-85706 GitLab Path Traversal

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: GitLab Commits API Path Traversal Attempt - CVE-2026-85706; GitLab Process Reading Sensitive Files Outside Expected Paths - CVE-2026-85706; XXE Payload in POST Request to Apache Tika Endpoint - CVE-2025-54988 / CVE-2025-66516; WAF or IDS Alert Referencing CVE-2026-85706 GitLab Path Traversal.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Metasploit Default User Agent or Staging Pattern Detected Against Network Services.

### Hunting Agenda and Promotion Criteria

- Metasploit Default User Agent or Staging Pattern Detected Against Network Services: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- GitLab Commits API Path Traversal Attempt - CVE-2026-85706: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- GitLab Process Reading Sensitive Files Outside Expected Paths - CVE-2026-85706: Defender for Endpoint file-event coverage must be confirmed on the target host population.; confirm required file-access telemetry exists and produces representative events.
- XXE Payload in POST Request to Apache Tika Endpoint - CVE-2025-54988 / CVE-2025-66516: FieldDeviceCustomNumber1 is used as a proxy for HTTP status code but this mapping is not standardized across CEF vendors. The field may be empty or contain a different numeric value depending on the appliance.; baseline expected benign activity and define an alert-volume threshold.
- WAF or IDS Alert Referencing CVE-2026-85706 GitLab Path Traversal: SecurityAlert must contain CVE-2026-85706-specific or GitLab path traversal alert signatures from a connected WAF, IDS, or Defender for Cloud connector. If no such signatures exist or have been deployed, the GitLabAlerts subquery returns zero rows and the inner join produces no output.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
