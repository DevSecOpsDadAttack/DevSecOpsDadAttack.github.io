---
layout: post
title: "Detection Engineering Brief - Monday, September 14, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-14
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
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

0 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-85706, T1190, GitLab CE, GitLab EE, CVE-2025-66516, CVE-2025-54988, Apache Tika, Metasploit.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-85706 GitLab Commits API Path Traversal Attempt; CVE-2026-85706 GitLab Commits API Unauthenticated Access Spike with Successful Response; Apache Tika XXE Out-of-Band Callback Following File Upload.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-85706 GitLab Commits API Path Traversal Attempt

### Detection Opportunity

Unauthenticated HTTP requests to GitLab repository commits API containing path traversal sequences, consistent with exploitation of CVE-2026-85706 to read arbitrary files.

### Intelligence Context

- Rapid7: CVE-2026-85706: Critical GitLab Path Traversal Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild)
  - Context: Rapid7 reported active exploitation of a GitLab path traversal vulnerability allowing unauthenticated users to read arbitrary files via the repository commits API. CISA added the CVE to KEV based on confirmed in-the-wild exploitation.

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
| where TimeGenerated > ago(24h)
| where DeviceProduct has_any ("nginx", "Apache", "GitLab", "HAProxy", "IIS")
| where RequestURL has "/api/v4/projects" and RequestURL has "/commits"
| where RequestURL has_any (
    "../",
    "..%2f",
    "..%2F",
    "%2e%2e",
    "%2e%2e%2f",
    "%2e%2e%2F",
    "..%5c",
    "..%5C",
    "%252e%252e",
    "%252e%252e%252f"
  )
| where RequestMethod in ("GET", "POST")
| where not(ipv4_is_private(SourceIP))
| extend HttpStatusCode = extract(@"(?:cs-status|httpStatusCode|outcome|sc-status)=([0-9]{3})", 1, tostring(AdditionalExtensions))
| extend SuccessfulRead = (HttpStatusCode == "200")
| project
    TimeGenerated,
    SourceIP,
    RequestURL,
    RequestMethod,
    HttpStatusCode,
    SuccessfulRead,
    DestinationPort,
    DeviceVendor,
    DeviceProduct,
    AdditionalExtensions
| order by SuccessfulRead desc, TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate security scanners or penetration testing tools running from internal or authorized external IPs may trigger this rule.
- URL-encoded characters in legitimate commit SHAs or branch names that coincidentally match traversal patterns (rare but possible).
- Automated dependency scanning tools that probe GitLab APIs with encoded path components.

**Tuning notes:**
- Add SuccessfulRead == true as a filter to create a high-fidelity variant focused only on confirmed file reads rather than all traversal probes.
- Extend the DeviceProduct filter with the specific product name emitted by the WAF or load balancer in the environment.
- If the GitLab instance is internal-only, remove the ipv4_is_private exclusion and instead allowlist known scanner IPs explicitly.
- Consider a summarize variant grouped by SourceIP to detect high-volume scanning from a single source alongside this per-request rule.

**Risks / caveats:**
- CommonSecurityLog is only populated when a CEF/syslog connector is configured to forward GitLab or reverse-proxy (nginx, Apache, HAProxy) access logs. If no such connector exists the table will contain no GitLab rows and the query will return zero results.
- RequestURL field population depends on the upstream device emitting the full request path in the CEF cs-URI or request field. Some WAF or proxy CEF implementations omit the path or truncate it; this must be verified for the specific log source.
- AdditionalExtensions is a free-text blob; HTTP response code extraction via has '200' is fragile and may match unrelated numeric strings. The exact key name (e.g., 'cs-status', 'outcome', 'httpStatusCode') varies by vendor and must be confirmed.
- The regex pattern for HttpStatusCode extraction covers common CEF key names but may not match the exact key emitted by all proxy vendors. Validate against a sample of AdditionalExtensions values from the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is external and not a known scanner, proxy, or security testing host.
- Review the full RequestURL for the exact traversal pattern, target path, and whether the request is aimed at the commits API on the expected GitLab instance.
- Check HttpStatusCode and SuccessfulRead to separate blocked probes from responses that likely returned content.
- Identify whether the request volume is isolated or part of a burst from the same SourceIP or related IPs.
- Validate whether the affected GitLab product and version are in the vulnerable range and whether the instance is internet-facing.

**Evidence to collect:**
- All matching RequestURL values, timestamps, SourceIP, RequestMethod, HttpStatusCode, and AdditionalExtensions for the alert window.
- GitLab access logs, reverse proxy logs, and WAF logs around the same time to confirm the request path and response behavior.
- GitLab version, patch level, and exposure details for the affected server.
- Any evidence of file access, unusual downloads, or follow-on requests from the same source IP.
- Authentication and admin activity around the alert time to rule out legitimate internal testing or maintenance.

**Pivot points:**
- CommonSecurityLog for the same SourceIP over the prior 24 hours to find additional traversal attempts or broader scanning.
- CommonSecurityLog for the same DeviceProduct and RequestURL patterns to identify other affected GitLab endpoints.
- GitLab application and reverse proxy logs to confirm whether the request reached the application and what file paths were targeted.
- Threat intelligence or firewall logs for the SourceIP to determine whether it is associated with scanning or exploitation activity.
- If available, file integrity or host telemetry on the GitLab server to look for unusual reads, process activity, or post-exploitation behavior.

**Benign explanations:**
- An authorized vulnerability scan or penetration test against the GitLab instance.
- A security tool or monitoring system probing the API with encoded paths as part of validation.
- A malformed request from a legitimate client or integration that accidentally included traversal-like encoding.
- A public GitLab instance receiving opportunistic internet noise that did not succeed.

**Escalation criteria:**
- HttpStatusCode indicates a successful response and the request appears to have returned content from an unexpected path.
- Multiple traversal attempts come from the same external SourceIP or a small set of related IPs.
- The GitLab instance is confirmed unpatched, internet-facing, and contains sensitive repositories or credentials.
- There is any evidence of follow-on access, data access, or additional exploitation attempts after the initial request.

**Containment actions:**
- Block or rate-limit the offending SourceIP at the WAF, reverse proxy, or firewall if the activity is clearly malicious.
- Temporarily restrict external access to the GitLab instance if exploitation appears active and patching cannot be immediate.
- Apply the vendor fix or mitigation for CVE-2026-85706 as soon as feasible.
- Preserve logs and relevant artifacts before making disruptive changes.

**Closure criteria:**
- The request is confirmed to be a benign scan, test, or malformed request with no evidence of successful file access.
- The GitLab instance is patched or otherwise mitigated, and no additional malicious requests are observed.
- No sensitive file access, follow-on activity, or other indicators of compromise are found in supporting logs.
- Any authorized testing source is documented and allowlisted for future tuning.

<br/>
---
<br/>

## Detection 2: CVE-2026-85706 GitLab Commits API Unauthenticated Access Spike with Successful Response

### Detection Opportunity

Spike in unauthenticated external HTTP requests to GitLab API endpoints returning HTTP 200, consistent with active scanning or exploitation of CVE-2026-85706.

### Intelligence Context

- Rapid7: CVE-2026-85706: Critical GitLab Path Traversal Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild)
  - Context: Rapid7 reported that unauthenticated requests to exposed GitLab servers are being used to exploit the path traversal vulnerability. CISA KEV listing confirms active exploitation in the wild.

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
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceProduct has_any ("nginx", "Apache", "GitLab", "HAProxy", "IIS")
| where RequestURL has "/api/v4/"
| where RequestMethod in ("GET", "POST")
| where not(ipv4_is_private(SourceIP))
| extend HttpStatusCode = extract(@"(?:cs-status|httpStatusCode|outcome|sc-status)=([0-9]{3})", 1, tostring(AdditionalExtensions))
| where HttpStatusCode == "200"
| extend IsTraversal = RequestURL has_any (
    "../", "..%2f", "..%2F", "%2e%2e", "%2e%2e%2f",
    "%2e%2e%2F", "..%5c", "..%5C", "%252e%252e"
  )
| summarize
    RequestCount = count(),
    TraversalAttempts = countif(IsTraversal == true),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleURLs = make_set(RequestURL, 10),
    DeviceProduct = take_any(DeviceProduct)
    by SourceIP, WindowStart = bin(TimeGenerated, 10m)
| where RequestCount > 20
| extend TraversalRatio = round(todouble(TraversalAttempts) / todouble(RequestCount), 2)
| project
    WindowStart,
    SourceIP,
    RequestCount,
    TraversalAttempts,
    TraversalRatio,
    FirstSeen,
    LastSeen,
    SampleURLs,
    DeviceProduct
| order by TraversalAttempts desc, RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate high-volume API consumers (CI/CD pipelines, monitoring agents) calling /api/v4/ endpoints from external IPs without user-level Authorization headers.
- Public GitLab instances with anonymous read access enabled will generate high volumes of unauthenticated 200 responses legitimately.
- Security scanners performing authorized assessments from external IPs.

**Tuning notes:**
- Run the query without the RequestCount > 20 filter over 7 days to establish a per-SourceIP baseline before setting the threshold.
- Add a where TraversalAttempts > 0 filter to create a high-fidelity variant focused exclusively on sources combining volume with traversal patterns.
- Allowlist known CI/CD runner external IPs or NAT gateway ranges that legitimately generate high unauthenticated API call volumes.
- Consider promoting to a scheduled rule with a 10-minute frequency and a 1-hour lookback once the threshold is calibrated.

**Risks / caveats:**
- CommonSecurityLog is only populated when a CEF/syslog connector forwards GitLab or reverse-proxy access logs. Without this connector the query returns zero rows.
- AdditionalExtensions response code extraction is vendor-specific; the regex must match the exact key name emitted by the log source in the environment.
- The has '200' approach on the raw AdditionalExtensions blob can match numeric strings unrelated to HTTP status codes in some CEF implementations.
- The RequestCount threshold of 20 per 10-minute bin is an initial baseline. Environments with high anonymous GitLab API traffic will require this value to be raised significantly after baselining 7 days of normal traffic.

### Triage Runbook

**First 15 minutes:**
- Review the SourceIP, RequestCount, TraversalAttempts, and TraversalRatio to see whether the spike is traversal-focused or just high-volume API traffic.
- Inspect SampleURLs to confirm the requests are centered on /api/v4/projects and /commits and not unrelated GitLab activity.
- Check whether the source is external and whether it matches a known CI/CD runner, monitoring system, or authorized scanner.
- Compare FirstSeen and LastSeen to determine whether the activity is a short burst or sustained probing.
- Verify whether the GitLab instance is public-facing and whether anonymous access is expected in this environment.

**Evidence to collect:**
- All request samples from the alert window, including URLs, methods, response codes, and timestamps.
- Proxy, WAF, and GitLab logs for the SourceIP to confirm request patterns and any returned content.
- Baseline traffic information for the affected GitLab instance to judge whether the RequestCount threshold is abnormal.
- Authentication and access configuration for the GitLab project or instance to determine whether anonymous 200 responses are expected.
- Any correlated alerts from the same SourceIP against other web applications or endpoints.

**Pivot points:**
- CommonSecurityLog grouped by SourceIP over 24 hours to identify broader scanning or repeated access to GitLab endpoints.
- CommonSecurityLog for the same DeviceProduct and /api/v4/ path to see whether other projects or endpoints were targeted.
- GitLab audit and access logs to determine whether the requests were anonymous, successful, and tied to specific repositories.
- Firewall or CDN logs to identify whether the source is part of a larger distributed campaign.
- Threat intelligence lookups for the SourceIP and any related infrastructure.

**Benign explanations:**
- A legitimate external integration or CI/CD workflow that uses anonymous or unauthenticated API access.
- A public GitLab instance intentionally allowing anonymous read access.
- An authorized security assessment or scanner generating repeated successful requests.
- A noisy but harmless client repeatedly polling the API.

**Escalation criteria:**
- TraversalAttempts are present and the requests are returning HTTP 200 responses from an external source.
- The source is not a known business system, scanner, or approved test host.
- The GitLab instance is internet-facing and contains sensitive repositories or secrets.
- The spike is accompanied by other suspicious activity such as repeated path variation, credential probing, or access to unusual projects.

**Containment actions:**
- Block or throttle the SourceIP if the activity is confirmed malicious or clearly abusive.
- Apply the CVE-2026-85706 mitigation or patch if the instance is vulnerable.
- Temporarily tighten external access controls if exploitation appears active and the service cannot be patched immediately.
- Preserve logs and request samples before making changes.

**Closure criteria:**
- The traffic is confirmed to be authorized, expected, or otherwise benign.
- The source is documented and allowlisted if it is a legitimate scanner or integration.
- No evidence of malicious traversal, sensitive data access, or follow-on exploitation is found.
- The GitLab instance is patched or mitigated and the spike does not recur.

<br/>
---
<br/>

## Detection 3: Apache Tika XXE Out-of-Band Callback Following File Upload

### Detection Opportunity

Unexpected outbound network connection from the Apache Tika service process shortly after a file upload request, indicating successful XML External Entity exploitation via the XFA parser.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: This One Goes to Sixteen! — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-goes-to-sixteen)
  - Context: Rapid7 released a Metasploit module validating an XXE vulnerability in Apache Tika's XFA parser. XXE exploitation causes the server-side Tika process to make out-of-band HTTP or DNS callbacks to attacker-controlled infrastructure, which is detectable as unexpected outbound connections from the Tika process.

### Search Metadata

- CVEs: CVE-2025-66516, CVE-2025-54988
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Apache Tika
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2025-66516, CVE-2025-54988, Apache Tika, Metasploit, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 24h;
let CallbackWindow = 5m;
let TikaProcesses = DeviceProcessEvents
| where TimeGenerated > ago(LookbackWindow)
| where ProcessCommandLine has_any ("tika", "tika-server")
| project DeviceId, DeviceName, ProcessStartTime = TimeGenerated, TikaCommandLine = ProcessCommandLine;
DeviceNetworkEvents
| where TimeGenerated > ago(LookbackWindow)
| where InitiatingProcessFileName in~ ("java.exe", "java")
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80, 443, 53, 8080, 8443)
| where not(ipv4_is_private(RemoteIP))
| join kind=inner TikaProcesses on DeviceId
| where TimeGenerated between (ProcessStartTime .. (ProcessStartTime + CallbackWindow))
| extend CallbackDestination = iff(isnotempty(RemoteUrl), RemoteUrl, tostring(RemoteIP))
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    RemoteIP,
    CallbackDestination,
    RemotePort,
    ActionType,
    InitiatingProcessFileName,
    TikaCommandLine,
    InitiatingProcessAccountName,
    ProcessStartTime
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Java-based applications co-located on the same host as Tika that make legitimate external HTTP or DNS connections within 5 minutes of a Tika process start.
- Tika deployments that are intentionally configured to fetch remote schemas or DTDs as part of normal document processing.
- Automated health checks or monitoring agents that trigger Tika process restarts followed by routine network activity.
- Maven or Gradle dependency resolution triggered by Tika process startup in development environments.

**Tuning notes:**
- Reduce CallbackWindow from 5m to 60s to tighten the correlation and reduce false positives from coincidental Java network activity.
- Add a RemotePort != 53 variant focused on HTTP/HTTPS callbacks if DNS-based OOB is not a concern in the environment, to reduce noise from routine DNS lookups.
- Add known internal DNS resolver IPs as explicit exclusions in addition to the ipv4_is_private() filter to handle split-horizon DNS configurations.
- If Tika runs as a dedicated service account, add an InitiatingProcessAccountName filter to that account to further scope the detection.

**Risks / caveats:**
- DeviceProcessEvents and DeviceNetworkEvents are only populated for devices onboarded to Microsoft Defender for Endpoint. If the host running Apache Tika is not onboarded, the query returns zero results.
- On Linux hosts running Tika, the initiating process filename will be 'java' not 'java.exe'. The query must account for both values to cover cross-platform deployments.
- RemoteUrl is not always populated in DeviceNetworkEvents; DNS-based OOB callbacks may only appear as RemoteIP with RemotePort 53 and RemoteUrl empty, which limits URL-based filtering.
- The 5-minute join window between Tika process start and outbound connection is broad and will match any Java network activity on the host within that window, not exclusively XXE-triggered callbacks. Shortening to 60 seconds reduces false positives but may miss slow XXE payloads.

### Triage Runbook

**First 15 minutes:**
- Validate that the host and process are actually running Apache Tika and that the callback occurred shortly after a file upload event.
- Review the RemoteIP, RemoteUrl, and RemotePort to determine whether the destination is external and suspicious or an expected internal service.
- Check the TikaCommandLine and InitiatingProcessFileName to confirm the process context and whether the service was started normally.
- Determine whether the callback was DNS-based or HTTP/HTTPS-based and whether it succeeded.
- Identify the user, service account, or application that submitted the file upload preceding the callback.

**Evidence to collect:**
- DeviceProcessEvents and DeviceNetworkEvents for the host around the alert time, including process start, command line, and outbound connection details.
- File upload request logs from the application fronting Tika, including source user, file name, and timestamp.
- Any DNS logs, proxy logs, or firewall logs that show the callback destination and whether additional outbound traffic followed.
- Tika service logs and application logs to confirm whether parsing errors, XXE indicators, or unusual document types were observed.
- Host telemetry for any subsequent file writes, credential access, or process spawning after the callback.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and time window to find additional outbound connections from java or related processes.
- DeviceProcessEvents for the same DeviceId to identify Tika restarts, wrapper scripts, or suspicious child processes.
- Application or web server logs for file upload activity immediately before the callback.
- DNS and proxy logs to resolve the callback destination and determine whether it is attacker-controlled infrastructure.
- If available, DeviceFileEvents and additional endpoint telemetry to look for post-exploitation staging or data access.

**Benign explanations:**
- A legitimate Tika deployment making routine external connections for updates, schema retrieval, or dependency resolution.
- A development or test environment where Java applications frequently make outbound connections after service startup.
- An internal monitoring or health-check process that restarted Tika and triggered normal network activity.
- A non-malicious document containing external references that caused expected network behavior.

**Escalation criteria:**
- The callback destination is external, unexpected, and not associated with approved infrastructure.
- The callback occurs immediately after a file upload and is consistent with XXE exploitation behavior.
- The same host shows additional suspicious outbound connections, process creation, or file activity after the callback.
- The uploaded file or application context suggests exposure of sensitive documents or internal metadata.

**Containment actions:**
- Isolate the Tika host or service if the callback is confirmed malicious and the system is exposed to ongoing uploads.
- Disable or restrict the file upload workflow until the vulnerable Tika version is patched or mitigated.
- Block the callback destination at the firewall, proxy, or DNS layer if it is clearly attacker-controlled.
- Preserve the uploaded file, logs, and endpoint artifacts before remediation.

**Closure criteria:**
- The outbound connection is confirmed to be expected application behavior or an approved internal dependency.
- No evidence of malicious file content, XXE exploitation, or follow-on compromise is found.
- The callback destination is identified and documented as benign or internal.
- The Tika deployment is patched or mitigated if it was vulnerable, and no further suspicious callbacks occur.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- CVE-2026-85706 GitLab Commits API Path Traversal Attempt: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- CVE-2026-85706 GitLab Commits API Unauthenticated Access Spike with Successful Response: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Schema / correlation keys:**
- Apache Tika XXE Out-of-Band Callback Following File Upload: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- CommonSecurityLog: shared by CVE-2026-85706 GitLab Commits API Path Traversal Attempt; CVE-2026-85706 GitLab Commits API Unauthenticated Access Spike with Successful Response

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: CVE-2026-85706 GitLab Commits API Path Traversal Attempt; CVE-2026-85706 GitLab Commits API Unauthenticated Access Spike with Successful Response.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Apache Tika XXE Out-of-Band Callback Following File Upload.

### Hunting Agenda and Promotion Criteria

- Apache Tika XXE Out-of-Band Callback Following File Upload: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-85706 GitLab Commits API Path Traversal Attempt: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling..
- CVE-2026-85706 GitLab Commits API Unauthenticated Access Spike with Successful Response: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
