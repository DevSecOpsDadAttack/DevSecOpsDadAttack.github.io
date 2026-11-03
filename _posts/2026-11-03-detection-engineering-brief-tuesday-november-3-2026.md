---
layout: post
title: "Detection Engineering Brief - Tuesday, November 3, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-03
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-118527
  - Ivanti Connect Secure
  - T1190
  - T1027
---

## Detection Engineering Summary

This brief produced 1 detection candidate.

0 production candidates, 0 hunting-only, 1 require environment mapping, and 0 rejected.

1 detection include KQL. 1 include ATT&CK mappings. 1 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-118527, Ivanti Connect Secure, T1190, T1027.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Ivanti Connect Secure - Remote Authenticated File Upload to Known Disk Path (CVE-2026-118527).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Ivanti Connect Secure - Remote Authenticated File Upload to Known Disk Path (CVE-2026-118527)

### Detection Opportunity

Remote authenticated attacker uploads attacker-controlled content to a known disk location on Ivanti Connect Secure via HTTP POST or PUT request.

### Intelligence Context

- Rapid7: Additional Ivanti Connect Secure zero-days exploited in the wild (CVE-2026-111357, CVE-2026-118527) — [https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527](https://www.rapid7.com/blog/post/etr-additional-ivanti-connect-secure-zero-days-exploited-in-the-wild-cve-2026-111357-cve-2026-118527)
  - Context: CVE-2026-118527 allows a remote authenticated attacker to upload attacker-controlled content to a known location on disk on Ivanti Connect Secure appliances. Rapid7 confirmed exploitation in the wild prior to patch availability. The observable action is an authenticated HTTP upload to a predictable file path on the appliance.

### Search Metadata

- CVEs: CVE-2026-118527
- Threat actors: Not specified
- ATT&CK tags: T1190, T1027
- Products: Ivanti Connect Secure
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-118527, Ivanti Connect Secure, T1190, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: initial-access: T1190 Exploit Public-Facing Application (medium); defense-evasion: T1027 Obfuscated Files or Information (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let lookback = 24h;
let ivanti_upload_paths = dynamic(["/dana-na/", "/dana/", "/upload/", "/tmp/", "/home/"]);
let csl_uploads =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceProduct has_any ("Ivanti", "Pulse Connect Secure", "Connect Secure")
    | where isnotempty(HttpMethod) and HttpMethod in ("POST", "PUT")
    | where isnotempty(RequestURL) and RequestURL has_any (ivanti_upload_paths)
    | project
        TimeGenerated,
        SourceIP,
        UserName,
        RequestURL,
        HttpMethod,
        FileName,
        FilePath,
        DeviceProduct,
        AdditionalExtensions,
        Source = "CommonSecurityLog";
let syslog_uploads =
    Syslog
    | where TimeGenerated >= ago(lookback)
    | where tolower(HostName) has_any ("ivanti", "pulse", "connectsecure")
    | where SyslogMessage has_any ("POST", "PUT")
    | where SyslogMessage has_any (ivanti_upload_paths)
    | extend
        SourceIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage),
        UserName = extract(@"user[=:\s]+(\S+)", 1, SyslogMessage),
        RequestURL = extract(@"(?:POST|PUT)\s+(\S+)", 1, SyslogMessage),
        HttpMethod = extract(@"(POST|PUT)", 1, SyslogMessage)
    | project
        TimeGenerated,
        SourceIP,
        UserName,
        RequestURL,
        HttpMethod,
        FileName = "",
        FilePath = "",
        DeviceProduct = HostName,
        AdditionalExtensions = "",
        Source = "Syslog";
union csl_uploads, syslog_uploads
| where isnotempty(SourceIP)
| summarize
    UploadCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    URLs = make_set(RequestURL, 20),
    Methods = make_set(HttpMethod),
    Sources = make_set(Source)
    by SourceIP, UserName, DeviceProduct
| extend CVE = "CVE-2026-118527"
| project-reorder FirstSeen, LastSeen, SourceIP, UserName, DeviceProduct, UploadCount, URLs, Methods, Sources, CVE
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Ivanti Connect Secure administrators uploading configuration files, certificates, or firmware packages via the management interface will match this detection.
- Automated backup or provisioning systems that POST or PUT data to Ivanti appliance endpoints will generate false positives.
- Security scanning tools performing authenticated vulnerability assessments against Ivanti appliances may trigger this detection.

**Tuning notes:**
- After confirming the specific disk paths associated with CVE-2026-118527 from vendor advisories, replace the ivanti_upload_paths list with the confirmed paths to reduce false positives from legitimate uploads to non-exploitable directories.
- Add a not-in exclusion for known administrative source IPs after baselining normal upload activity: '| where SourceIP !in ("<admin_ip_1>", "<admin_ip_2>")' — populate with actual values from the environment before use.
- Consider splitting the union into two separate scheduled rules if the CommonSecurityLog and Syslog connectors have significantly different ingestion latencies, to avoid missed correlations.
- If the environment uses a custom DeviceProduct string for Ivanti appliances, update the has_any filter in the CommonSecurityLog branch to include that string.

**Risks / caveats:**
- CommonSecurityLog is only populated if Ivanti Connect Secure appliances are configured to forward CEF events to the Sentinel workspace via the CEF/Syslog connector. If this connector is absent or misconfigured, the CommonSecurityLog branch returns no results.
- Syslog is only populated if Ivanti Connect Secure appliances forward raw syslog to the Sentinel workspace. If syslog forwarding is not configured, the Syslog branch returns no results.
- HttpMethod and RequestURL are not guaranteed to be populated in CommonSecurityLog for all Ivanti CEF event types. If the appliance does not emit these fields in its CEF output, the CommonSecurityLog branch will match nothing.
- The regex extractions in the Syslog branch (SourceIP, UserName, RequestURL) are pattern-dependent and will silently return empty strings if the actual syslog message format from the appliance does not match the assumed patterns.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert source and affected appliance identity, then verify the upload occurred on the expected Ivanti device and not from a lab, scanner, or backup system.
- Identify the source IP, username, request URL, HTTP method, and timestamp range; compare them to known admin accounts, jump hosts, and approved maintenance windows.
- Check whether the uploaded path is a normal administrative or operational location versus a suspicious writable path such as tmp, home, or web-accessible directories.
- Look for any immediate follow-on activity from the same source IP or account, including repeated uploads, unusual request bursts, or access to other Ivanti endpoints.
- If the activity is not clearly authorized, treat the appliance as potentially compromised and begin incident escalation while continuing evidence collection.

**Evidence to collect:**
- Exact SourceIP, UserName, DeviceProduct, RequestURL, HttpMethod, FirstSeen, LastSeen, and UploadCount from the alert.
- Raw CommonSecurityLog or Syslog events surrounding the alert window to confirm the full request context and any adjacent authentication or error messages.
- Ivanti appliance admin audit logs, authentication logs, and any change-management records covering the same time period.
- A list of known administrative source IPs, service accounts, and scheduled maintenance activities for the appliance.
- Any file metadata available on the appliance for the uploaded object, including filename, path, size, and whether it was later modified, executed, or referenced.

**Pivot points:**
- CommonSecurityLog for the same SourceIP, UserName, or RequestURL over the prior and subsequent 24 hours to identify repeated uploads or related requests.
- Syslog for the same HostName or SourceIP to find authentication events, errors, or suspicious request patterns around the alert time.
- Ivanti appliance audit or management logs to validate whether the upload was performed by an approved administrator or automation account.
- Network telemetry or proxy logs for the SourceIP to determine whether the host also accessed other exposed appliance endpoints or other internal targets.
- Endpoint or server telemetry on the admin workstation or jump host associated with the UserName, if available, to check for credential theft or malicious tooling.

**Benign explanations:**
- A legitimate administrator uploaded a configuration file, certificate, firmware package, or support artifact through the management interface.
- An approved backup, provisioning, or automation system performed a normal authenticated POST or PUT to the appliance.
- A vulnerability scanner or security assessment tool generated the upload traffic during authorized testing.
- The alert matched a benign file transfer to a writable path that is not actually exploitable in this environment.

**Escalation criteria:**
- The source IP, username, or request pattern is not recognized and cannot be tied to an approved change or maintenance activity.
- The upload targeted an unusual or sensitive path, especially a web-accessible or temporary directory, or the same account performed multiple suspicious uploads.
- There is evidence of post-upload activity such as new sessions, command execution, webshell-like behavior, configuration changes, or additional suspicious requests.
- The appliance shows signs of compromise, including unexpected authentication events, integrity changes, crashes, or other anomalous syslog activity around the alert time.

**Containment actions:**
- If the activity is unauthorized or suspicious, disable or rotate the affected Ivanti administrative credentials and any related service accounts.
- Restrict or block the source IP at the network edge if it is external and not required for business operations.
- Place the appliance into heightened monitoring and preserve logs and configuration state before making disruptive changes.
- If compromise is strongly suspected, follow incident response procedures for the appliance, including vendor guidance for containment and recovery.

**Closure criteria:**
- The upload is confirmed as an approved administrative, backup, or automation action and the path is expected for that workflow.
- No additional suspicious activity is found in appliance logs, network telemetry, or related account activity.
- The source IP and username are validated against known-good records and the event is documented as benign.
- Any suspicious activity has been escalated and handed off to incident response with evidence preserved.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- Ivanti Connect Secure - Remote Authenticated File Upload to Known Disk Path (CVE-2026-118527): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Ivanti Connect Secure - Remote Authenticated File Upload to Known Disk Path (CVE-2026-118527).

### Hunting Agenda and Promotion Criteria

- Ivanti Connect Secure - Remote Authenticated File Upload to Known Disk Path (CVE-2026-118527): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
