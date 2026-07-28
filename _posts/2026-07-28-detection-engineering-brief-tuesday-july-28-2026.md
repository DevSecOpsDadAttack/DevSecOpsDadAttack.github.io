---
layout: post
title: "Detection Engineering Brief - Tuesday, July 28, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-28
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1055
  - AutoIT
  - T1190
  - Spring Boot
  - Java
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

0 production candidates, 0 hunting-only, 3 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: T1055, AutoIT, T1190, Spring Boot, Java.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: AutoIT Process Injection via Remote Process Memory Access; Spring Boot Heapdump Endpoint Scan from External IP; Successful Spring Boot Heapdump Retrieval by External IP.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: AutoIT Process Injection via Remote Process Memory Access

### Detection Opportunity

AutoIT script performs process injection into a remote process by spawning suspicious child processes or accessing remote process memory.

### Intelligence Context

- SANS ISC: AutoIT Payload Injector , (Tue, Jul 28th) — [https://isc.sans.edu/diary/rss/33192](https://isc.sans.edu/diary/rss/33192)
  - Context: SANS ISC documented an AutoIT script capable of performing all required actions to inject a payload into a remote process, indicating active use of AutoIT as a process injection vehicle.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: AutoIT
- Search tags: T1055, AutoIT

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1055 Process Injection (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceEvents

### KQL

```kql
let AutoITInjectionEvents = DeviceEvents
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where ActionType in ("CreateRemoteThreadApiCall", "WriteProcessMemoryApiCall", "QueueUserApcRemoteApiCall", "SetThreadContextRemoteApiCall")
| extend DetectionBranch = "InjectionAPICall",
         FileName = "",
         ProcessCommandLine = "",
         SHA256 = ""
| project Timestamp, DeviceName, DetectionBranch, ActionType, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256;
let AutoITChildProcs = DeviceProcessEvents
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where FileName !in~ ("AutoIt3.exe", "au3check.exe")
| where ProcessCommandLine !contains ".au3"
| where isnotempty(ProcessCommandLine)
| extend DetectionBranch = "SuspiciousChildProcess",
         ActionType = ""
| project Timestamp, DeviceName, DetectionBranch, ActionType, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256;
union AutoITInjectionEvents, AutoITChildProcs
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IT automation built on AutoIT that spawns helper executables such as cmd.exe, powershell.exe, or msiexec.exe will appear in the child process branch.
- Software packaging or deployment tools that use AutoIT as a wrapper may trigger child process results at scale during patch cycles.

**Tuning notes:**
- Add known-legitimate AutoIT child process names (e.g., specific installer executables) to a not in~ exclusion list in the AutoITChildProcs branch after baselining the environment.
- If the environment does not have MDE advanced API call telemetry, remove the AutoITInjectionEvents branch and promote the child process branch alone as a lower-fidelity hunting query.
- Consider adding a time-bound filter such as → where Timestamp > ago(7d) when scheduling as a recurring hunt.

**Risks / caveats:**
- ActionType values CreateRemoteThreadApiCall, WriteProcessMemoryApiCall, QueueUserApcRemoteApiCall, and SetThreadContextRemoteApiCall require MDE advanced API call telemetry to be enabled. If this telemetry is not collected, the AutoITInjectionEvents branch returns zero rows with no error.
- DeviceEvents does not expose SHA256 or ProcessCommandLine for all ActionType rows; projecting SHA256 from the union may produce nulls for injection-event rows.
- The child process branch is broad; legitimate AutoIT-based automation in the environment will require an allowlist of known-good child process names to reduce alert volume.
- InitiatingProcessCommandLine availability in DeviceEvents varies by ActionType row; it may be null for some injection event records.

### Triage Runbook

**First 15 minutes:**
- Check whether the alert came from the InjectionAPICall branch or the SuspiciousChildProcess branch; treat InjectionAPICall as higher confidence.
- Identify the parent process, launch path, and command line for AutoIt3.exe to see whether it was started by a known installer, admin tool, or user-launched script.
- Review the child process name and command line for suspicious payloads such as powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe, mshta.exe, or unusual temp-path executables.
- Look for multiple injection API calls or repeated child process spawning on the same host within a short time window.
- Correlate the host with recent user logons, downloads, email attachments, or other malware alerts to determine initial execution path.

**Evidence to collect:**
- DeviceName, Timestamp, DetectionBranch, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, and InitiatingProcessParentFileName from the alert.
- SHA256 for any child process or related executable if present, plus file path and signer information from endpoint telemetry.
- Process tree around AutoIt3.exe, including parent, siblings, and spawned children.
- Any related Defender XDR alerts, recent file writes, or network connections from the same host and user.
- User context for the session that launched AutoIt3.exe, including whether the activity aligns with approved automation.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName = AutoIt3.exe to reconstruct the full process tree.
- DeviceEvents for additional injection API calls on the same host and around the same Timestamp.
- DeviceNetworkEvents for outbound connections from AutoIt3.exe or its child processes.
- DeviceFileEvents for dropped scripts, payloads, or recently created executables in temp or user-writable paths.
- AlertInfo and AlertEvidence for any correlated detections on the same device or user.

**Benign explanations:**
- Known IT automation or software deployment workflows that use AutoIT to launch helper executables.
- Legitimate installer wrappers or packaging tools that spawn cmd.exe, powershell.exe, or msiexec.exe during setup.
- Internal scripts signed, distributed, and executed by a trusted admin team on managed endpoints.

**Escalation criteria:**
- InjectionAPICall branch fires, especially with CreateRemoteThreadApiCall, WriteProcessMemoryApiCall, QueueUserApcRemoteApiCall, or SetThreadContextRemoteApiCall.
- AutoIt3.exe is launched from a user-writable or temporary directory, email attachment path, or suspicious download location.
- The child process is a known post-exploitation utility, script host, or an unsigned executable from an unusual path.
- There is evidence of additional malicious behavior such as credential dumping, persistence, lateral movement, or outbound C2 traffic.
- No approved business justification exists for AutoIT use on the affected host or by the affected user.

**Containment actions:**
- Isolate the endpoint if injection activity is confirmed or if the process tree shows clear malicious payload execution.
- Terminate the suspicious AutoIt3.exe process and any spawned payload processes if they are still active.
- Block or quarantine the associated file hash if a malicious AutoIT script or dropped executable is identified.
- Reset credentials for the affected user if there are signs of credential theft or interactive compromise.
- Preserve volatile evidence before rebooting or cleaning the host.

**Closure criteria:**
- The activity is confirmed as approved automation or a known installer workflow and matches a documented allowlist entry.
- No injection API calls are present and the child process behavior is consistent with normal AutoIT usage on that host.
- File hash, parent process, and command line are matched to a known-good software deployment or admin script.
- No additional suspicious telemetry, network activity, or correlated alerts are found after review.
- The detection is documented as benign with a tuning recommendation if it is recurring and expected.

<br/>
---
<br/>

## Detection 2: Spring Boot Heapdump Endpoint Scan from External IP

### Detection Opportunity

External IP addresses scanning for exposed Spring Boot /actuator/heapdump endpoints via HTTP GET requests.

### Intelligence Context

- SANS ISC: Java Spring Boot "heapdump" scans, (Mon, Jul 27th) — [https://isc.sans.edu/diary/rss/33188](https://isc.sans.edu/diary/rss/33188)
  - Context: SANS ISC reported active scanning activity targeting the Spring Boot /actuator/heapdump endpoint from external IPs, with the goal of retrieving heap dumps that may contain credentials or secrets.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Spring Boot
- Platforms: Java
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, Spring Boot, Java

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
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where RequestURL contains "/actuator/heapdump"
| where RequestMethod =~ "GET"
| where isnotempty(SourceIP)
| where not(ipv4_is_private(SourceIP))
| summarize
    RequestCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    ResponseCodes = make_set(EventOutcome),
    TargetPorts = make_set(DestinationPort)
    by SourceIP, RequestURL, DeviceVendor, DeviceProduct
| sort by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- External security scanners or penetration testing services authorized by the organization will trigger this rule.
- Cloud-hosted monitoring or uptime services with non-RFC1918 IPs that probe the actuator endpoint for availability checks will appear as scan events.

**Tuning notes:**
- Add authorized external scanner IP ranges to an exclusion list after identifying them in initial alert review.
- Adjust the ago(1d) lookback to match the scheduled rule execution interval.
- Consider adding → where RequestCount > 1 to suppress single-request noise once the environment baseline is established.

**Risks / caveats:**
- RequestURL population in CommonSecurityLog depends entirely on the upstream CEF source (WAF, proxy, or web server). If the connector does not map the URI path into RequestURL, the query returns zero results with no error.
- SourceIP may reflect an intermediate proxy or load balancer address rather than the true client IP depending on the ingestion pipeline, causing the RFC1918 exclusion to incorrectly filter or pass traffic.
- The 1-day lookback window should match the scheduled rule run frequency to avoid duplicate alerting or coverage gaps.
- ipv4_is_private() does not handle IPv6 addresses; if SourceIP contains IPv6 values the function may return unexpected results and an additional isnotempty check or IPv6 exclusion may be needed.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is external and not a proxy, load balancer, or monitoring service that masks the true client address.
- Review the RequestURL, RequestMethod, RequestCount, FirstSeen, and LastSeen to determine whether this is a single probe or repeated scanning.
- Check whether the target application is internet-facing and whether /actuator/heapdump should be reachable in the current environment.
- Look for other requests from the same SourceIP to related Spring Boot actuator paths such as /actuator, /actuator/env, or /actuator/health.
- Determine whether the source belongs to an approved vulnerability scanner, red team, or external monitoring provider.

**Evidence to collect:**
- SourceIP, RequestURL, RequestMethod, RequestCount, FirstSeen, LastSeen, ResponseCodes, TargetPorts, DeviceVendor, and DeviceProduct.
- Any WAF, proxy, or web server logs showing the full request path and response outcome for the same source.
- Application exposure details for the target host, including whether Spring Boot actuator endpoints are intentionally published.
- Any related requests from the same SourceIP to other endpoints on the same destination service.
- Change records or scanner schedules that explain the traffic.

**Pivot points:**
- CommonSecurityLog filtered by the same SourceIP to identify other requests to the same host or related actuator endpoints.
- CommonSecurityLog for the destination service to see whether the same client is probing multiple paths or ports.
- Firewall, WAF, or reverse proxy logs to validate whether SourceIP is the true client or an upstream device.
- Asset inventory or CMDB data to confirm whether the target is a public-facing Spring Boot service.
- Threat intelligence or internal scanner allowlists for the SourceIP.

**Benign explanations:**
- An authorized external vulnerability scan or penetration test.
- A cloud-hosted uptime or monitoring service checking endpoint availability.
- A security research or internet-wide scanning source that reached the service without successful exploitation.

**Escalation criteria:**
- The source is not an approved scanner and the target is confirmed internet-facing.
- Repeated requests from the same SourceIP indicate active reconnaissance rather than a one-off probe.
- The same source is probing multiple actuator endpoints or other sensitive application paths.
- There is evidence that the application exposes additional sensitive endpoints or misconfigurations.
- The traffic is followed by a successful heapdump retrieval or other suspicious application abuse.

**Containment actions:**
- Block the SourceIP at the WAF, proxy, or firewall if it is clearly malicious and not business-approved.
- Restrict or disable public access to Spring Boot actuator endpoints if they are not required.
- Apply temporary rate limiting or IP filtering on the affected service while exposure is assessed.
- Coordinate with the application owner to remove or protect the heapdump endpoint if it is unintentionally exposed.
- Escalate to the web application owner for immediate review if the service is internet-facing and unprotected.

**Closure criteria:**
- The source is confirmed as an approved scanner or monitoring service and the activity matches expected behavior.
- The target endpoint is intentionally exposed and the requests are part of normal testing or validation.
- No additional suspicious requests or follow-on exploitation attempts are observed.
- The event is documented with the source allowlisted or the exposure accepted by the application owner.
- Any required tuning or suppression is approved and recorded.

<br/>
---
<br/>

## Detection 3: Successful Spring Boot Heapdump Retrieval by External IP

### Detection Opportunity

External IP successfully downloads a Spring Boot /actuator/heapdump file indicated by HTTP 200 response with large response body, exposing potential credentials or secrets.

### Intelligence Context

- SANS ISC: Java Spring Boot "heapdump" scans, (Mon, Jul 27th) — [https://isc.sans.edu/diary/rss/33188](https://isc.sans.edu/diary/rss/33188)
  - Context: SANS ISC explicitly recommended alerting on successful retrieval of heapdump files from internet-facing Spring Boot services, as a successful download from an external IP represents near-certain credential or secret exposure.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Spring Boot
- Platforms: Java
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, Spring Boot, Java

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- BytesReceived is not populated by all CEF/CommonSecurityLog sources. If the upstream connector does not map response body size into this field, tolong(BytesReceived) evaluates to null and the > 1048576 filter silently drops all rows, producing zero results.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where RequestURL contains "/actuator/heapdump"
| where RequestMethod =~ "GET"
| where EventOutcome startswith "200"
| where isnotempty(BytesReceived)
| where tolong(BytesReceived) > 1048576
| where isnotempty(SourceIP)
| where not(ipv4_is_private(SourceIP))
| project TimeGenerated, SourceIP, RequestURL, EventOutcome, BytesReceived, DeviceVendor, DeviceProduct
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized external penetration testers or red team operators who successfully retrieve the heapdump will trigger this alert.
- Cloud-hosted monitoring services that download the heapdump for availability or content verification will appear as successful retrievals.

**Tuning notes:**
- Verify EventOutcome field format in CommonSecurityLog for the specific connector in use and adjust the filter from startswith "200" to == "200" or == 200 as appropriate.
- Confirm BytesReceived is populated with numeric response body sizes by running → where RequestURL contains "/actuator/heapdump" → project BytesReceived → take 100 before deploying.
- Adjust the ago(1d) lookback to match the scheduled rule execution interval.
- Increase the BytesReceived threshold above 1048576 if large error pages from the environment's web tier cause false positives.

**Risks / caveats:**
- BytesReceived is not populated by all CEF/CommonSecurityLog sources. If the upstream connector does not map response body size into this field, tolong(BytesReceived) evaluates to null and the > 1048576 filter silently drops all rows, producing zero results.
- EventOutcome may contain the HTTP status code as a string, integer, or descriptive text depending on the CEF source. The =~ "200" comparison may not match if the source emits "200 OK" or an integer 200.
- RequestURL population depends on the upstream CEF source mapping the full URI path; if absent the query returns zero results with no error.
- SourceIP may reflect an intermediate proxy rather than the true client IP depending on the ingestion pipeline.

### Triage Runbook

**First 15 minutes:**
- Treat the alert as potentially high impact and verify the source IP, target URL, HTTP 200 status, and response size.
- Confirm the destination application is internet-facing and that the heapdump file was actually served, not just logged as a false 200.
- Identify whether the source IP is an approved scanner, monitoring service, or known internal testing platform.
- Check for multiple successful downloads or repeated access from the same source and any adjacent requests to other sensitive endpoints.
- Notify the application owner immediately that a heapdump may have been exposed and request confirmation of what secrets or credentials could be present.

**Evidence to collect:**
- SourceIP, RequestURL, RequestMethod, EventOutcome, BytesReceived, TimeGenerated, DeviceVendor, and DeviceProduct.
- Any web server, proxy, or WAF logs that confirm the response body size and the exact file or endpoint returned.
- Application ownership details and whether the heapdump contains secrets, tokens, database credentials, or session data.
- Any subsequent requests from the same SourceIP to login pages, admin paths, or other sensitive endpoints.
- Change records or deployment notes that explain why the heapdump endpoint was exposed.

**Pivot points:**
- CommonSecurityLog for the same SourceIP to identify additional requests before or after the heapdump retrieval.
- CommonSecurityLog for the same RequestURL or destination service to determine whether other clients accessed the endpoint.
- Application logs or reverse proxy logs to validate the exact response and whether the heapdump file was generated or downloaded.
- Asset inventory or CMDB to identify the owner, environment, and exposure status of the affected service.
- Identity and secret management logs to check whether credentials in the heapdump may have been used after exposure.

**Benign explanations:**
- An authorized penetration test or red team exercise that successfully retrieved the heapdump.
- A sanctioned external monitoring or validation service that downloads the file for testing purposes.
- A development or staging environment intentionally exposing the endpoint for troubleshooting.

**Escalation criteria:**
- The source is not approved and the heapdump was successfully downloaded from a production or internet-facing service.
- The response size indicates a real heapdump rather than an error page or small test response.
- The application owner confirms the heapdump may contain secrets, credentials, or sensitive runtime data.
- There is evidence of follow-on access using credentials or tokens that may have been exposed.
- The same source continues probing other sensitive endpoints after the successful download.

**Containment actions:**
- Immediately remove public access to the heapdump endpoint or place it behind authentication and network restrictions.
- Block the external source IP if it is clearly malicious and not business-approved.
- Rotate any credentials, API keys, tokens, or secrets that may be present in the heapdump.
- Engage the application owner to regenerate or invalidate the heapdump and review application exposure.
- If production exposure is confirmed, coordinate emergency remediation with the service owner and platform team.

**Closure criteria:**
- The download is confirmed as authorized testing or a known monitoring workflow.
- The application owner verifies the exposed data is non-sensitive or has already been remediated and rotated.
- No evidence of follow-on abuse, credential use, or additional suspicious access is found.
- Public exposure has been removed or formally accepted with compensating controls.
- The incident is documented with remediation actions completed and validated.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- AutoIT Process Injection via Remote Process Memory Access: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- Spring Boot Heapdump Endpoint Scan from External IP: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Successful Spring Boot Heapdump Retrieval by External IP: BytesReceived is not populated by all CEF/CommonSecurityLog sources. If the upstream connector does not map response body size into this field, tolong(BytesReceived) evaluates to null and the > 1048576 filter silently drops all rows, producing zero results.

**Shared-table notes:**
- CommonSecurityLog: shared by Spring Boot Heapdump Endpoint Scan from External IP; Successful Spring Boot Heapdump Retrieval by External IP

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: AutoIT Process Injection via Remote Process Memory Access; Spring Boot Heapdump Endpoint Scan from External IP; Successful Spring Boot Heapdump Retrieval by External IP.

### Hunting Agenda and Promotion Criteria

- AutoIT Process Injection via Remote Process Memory Access: Defender for Endpoint file-event coverage must be confirmed on the target host population..
- Spring Boot Heapdump Endpoint Scan from External IP: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Successful Spring Boot Heapdump Retrieval by External IP: BytesReceived is not populated by all CEF/CommonSecurityLog sources. If the upstream connector does not map response body size into this field, tolong(BytesReceived) evaluates to null and the > 1048576 filter silently drops all rows, producing zero results.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
