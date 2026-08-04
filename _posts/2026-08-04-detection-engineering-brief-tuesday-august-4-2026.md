---
layout: post
title: "Detection Engineering Brief - Tuesday, August 4, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-04
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Midnight Blizzard
  - web applications
  - Atomic MacOS
  - macOS
  - CVE-2026-66066
  - Ruby on Rails
  - Active Storage
  - Vips
  - libvips
  - libmatio
  - T1078
  - T1556
  - T1555
  - T1555.001
  - T1555.003
  - T1041
  - T1190
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

0 production candidates, 1 hunting-only, 3 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: Midnight Blizzard, web applications, Atomic MacOS, macOS, CVE-2026-66066, Ruby on Rails, Active Storage, Vips, libvips, libmatio, T1078, T1556, T1555, T1555.001, T1555.003, T1041, T1190.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Midnight Blizzard - Credential Theft Post Hospitality Portal Sign-In from New Location; AMOS Stealer - Suspicious macOS Process Accessing Keychain or Browser Credential Paths; CVE-2026-66066 KindaRails2Shell - Suspicious POST to Rails Direct-Upload Endpoint with Anomalous Content-Type; CVE-2026-66066 KindaRails2Shell - Anomalous Image Response Size from Rails Upload Endpoint Indicating File Exfiltration.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Midnight Blizzard - Credential Theft Post Hospitality Portal Sign-In from New Location

### Detection Opportunity

Successful sign-in from a new or anomalous geolocation shortly after a prior sign-in to a hospitality-category application, consistent with credential theft following portal compromise.

### Intelligence Context

- Microsoft Security Blog: CaptiveCrunch: Midnight Blizzard targets travelers worldwide for malware delivery and credential theft — [https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)
  - Context: Midnight Blizzard was observed compromising hospitality sign-in portals to steal credentials from travelers. Post-compromise credential use from new geolocations is the actionable follow-on behavior reported.

### Search Metadata

- CVEs: Not specified
- Threat actors: Midnight Blizzard
- ATT&CK tags: T1078, T1556
- Products: Not specified
- Platforms: web applications
- Malware: Not specified
- Tools: Not specified
- Search tags: Midnight Blizzard, web applications, T1078, T1556

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1078 Valid Accounts (high); Credential Access: T1556 Modify Authentication Process (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- SigninLogs

### KQL

```kql
let HospitalityKeywords = dynamic(["hotel", "hospitality", "resort", "inn", "lodging", "accommodation"]);
let LookbackWindow = 6h;
let SignInBase = SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend CountryOrRegion = tostring(LocationDetails.countryOrRegion)
| where isnotempty(CountryOrRegion);
let HospitalitySignIns = SignInBase
| where AppDisplayName has_any (HospitalityKeywords)
| project UserPrincipalName, HospitalityTime = TimeGenerated, HospitalityApp = AppDisplayName, HospitalityCountry = CountryOrRegion, HospitalityIP = IPAddress;
let SubsequentSignIns = SignInBase
| project UserPrincipalName, SubsequentTime = TimeGenerated, SubsequentCountry = CountryOrRegion, SubsequentApp = AppDisplayName, SubsequentIP = IPAddress;
HospitalitySignIns
| join kind=inner SubsequentSignIns on UserPrincipalName
| where SubsequentTime > HospitalityTime
| where SubsequentTime <= HospitalityTime + LookbackWindow
| where HospitalityCountry != SubsequentCountry
| where HospitalityIP != SubsequentIP
| extend TimeDeltaMinutes = datetime_diff('minute', SubsequentTime, HospitalityTime)
| project
    UserPrincipalName,
    HospitalityTime,
    HospitalityApp,
    HospitalityCountry,
    HospitalityIP,
    SubsequentTime,
    SubsequentApp,
    SubsequentCountry,
    SubsequentIP,
    TimeDeltaMinutes
| order by HospitalityTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Frequent business travelers who legitimately sign in from multiple countries within hours.
- Users who connect through VPNs or proxies that resolve to different countries than their physical location.
- Shared or kiosk devices at hospitality venues where multiple users sign in sequentially.
- AppDisplayName matches on non-hospitality apps that happen to contain keywords such as 'inn' in a product name.

**Tuning notes:**
- Run the HospitalitySignIns subquery standalone first to validate which AppDisplayName values are matching in your tenant before enabling correlation.
- Consider joining against an AADUserRiskEvents or IdentityInfo watchlist to prioritize alerts for high-value accounts.
- Extend HospitalityKeywords with specific portal application names observed in your environment after initial review.

**Risks / caveats:**
- LocationDetails.countryOrRegion may be empty for sign-ins where geolocation cannot be resolved, causing false negatives or incorrect country comparisons.
- SigninLogs requires Microsoft Entra ID P1 or P2 licensing or the appropriate Sentinel connector; absence of this connector means the table will be empty.
- AppDisplayName keyword matching will miss hospitality portals that use non-descriptive application names registered in Entra ID; analysts should enumerate AppDisplayName values in their tenant to validate coverage.
- The 6-hour correlation window may be too wide for high-volume tenants, generating significant noise; consider tightening to 2 hours after baselining.

### Triage Runbook

**First 15 minutes:**
- Confirm the matched AppDisplayName is truly a hospitality portal and not a false-positive keyword match on an unrelated app.
- Review the two sign-ins side by side: source IPs, countries, user agents, authentication requirement, and whether both were interactive.
- Check whether the user has a travel pattern, VPN usage, or recent approved access from the subsequent country or IP.
- Look for immediate follow-on identity activity such as MFA resets, password changes, consent grants, mailbox access, or additional sign-ins from new geolocations.

**Evidence to collect:**
- SigninLogs for the user covering at least 30 days before and after the alert.
- User agent strings, authentication method, and interactive/non-interactive status for both sign-ins.
- IP reputation and whether either IP belongs to a corporate VPN, proxy, or known travel network.
- Any Entra ID risk events, MFA prompts, or conditional access failures around the same time.

**Pivot points:**
- SigninLogs filtered on the same UserPrincipalName for the prior 30 days to establish normal countries, IPs, and apps.
- SigninLogs for the same source IPs to identify other impacted users or repeated use of the same infrastructure.
- AADUserRiskEvents or IdentityProtection-related tables if available to check for concurrent identity risk signals.
- AuditLogs for password reset, MFA registration, consent, or role assignment activity tied to the account.

**Benign explanations:**
- The user is a frequent traveler and legitimately signed in from a new country after using a hospitality portal.
- A VPN or proxy caused the geolocation to differ from the user’s physical location.
- The hospitality app name matched broadly on an unrelated enterprise application.
- Shared or kiosk devices at a hotel or conference venue produced sequential sign-ins from different locations.

**Escalation criteria:**
- The subsequent sign-in is from an unfamiliar country or IP with no prior history for the user and no credible travel explanation.
- There are additional suspicious identity events such as MFA changes, password reset attempts, or consent grants.
- The account is privileged, handles sensitive data, or is used for admin access.
- Multiple users show the same hospitality portal pattern or the same suspicious source IP.

**Containment actions:**
- If the sign-in appears malicious, disable the account or force a password reset and revoke active sessions.
- Invalidate refresh tokens and require MFA re-registration if identity compromise is suspected.
- Block the suspicious IPs or geolocations at the identity layer if supported and approved by policy.
- Notify the identity team to review conditional access and recent authentication events for related compromise.

**Closure criteria:**
- The hospitality app match is confirmed to be benign and the user’s travel/VPN history explains the geolocation change.
- No additional suspicious identity activity is found in the surrounding time window.
- The source IPs are known corporate or approved travel infrastructure.
- The account owner or business system owner confirms the activity as expected.

<br/>
---
<br/>

## Detection 2: AMOS Stealer - Suspicious macOS Process Accessing Keychain or Browser Credential Paths

### Detection Opportunity

AMOS stealer process execution on macOS accessing keychain files or browser credential storage paths, consistent with credential and data exfiltration behavior documented for Atomic macOS stealer.

### Intelligence Context

- SANS ISC: Atomic MacOS (AMOS) stealer infection, (Sun, Aug 2nd) — [https://isc.sans.edu/diary/rss/33208](https://isc.sans.edu/diary/rss/33208)
  - Context: AMOS stealer was observed executing on macOS and exfiltrating data. Known AMOS behaviors include accessing macOS keychain and browser credential storage paths, often via osascript or Python processes.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1555, T1555.001, T1555.003, T1041
- Products: Not specified
- Platforms: macOS
- Malware: Atomic MacOS
- Tools: Not specified
- Search tags: Atomic MacOS, macOS, T1555, T1555.001, T1555.003, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores/ T1555.001 Keychain (high); Credential Access: T1555 Credentials from Password Stores/ T1555.003 Credentials from Web Browsers (high); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let CredentialPaths = dynamic(["/Library/Keychains", "login.keychain", "Chrome/Default/Login Data", "Firefox/Profiles", "/Cookies", "/Web Data", "keychain-db"]);
let SuspiciousInitiators = dynamic(["osascript", "python3", "python", "bash", "sh", "curl", "wget"]);
let CorrelationWindow = 5m;
let FileAccessEvents = DeviceFileEvents
| where Timestamp > ago(7d)
| where OSPlatform == "macOS"
| where ActionType in ("FileAccessed", "FileRead")
| where FolderPath has_any (CredentialPaths)
| where InitiatingProcessName has_any (SuspiciousInitiators)
| project
    DeviceName,
    FileAccessTime = Timestamp,
    FileName,
    FolderPath,
    InitiatingProcessName,
    ProcessCommandLine = InitiatingProcessCommandLine;
let NetworkEvents = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where OSPlatform == "macOS"
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project
    DeviceName,
    NetworkTime = Timestamp,
    RemoteIP,
    RemoteUrl,
    NetInitiatingProcess = InitiatingProcessName;
FileAccessEvents
| join kind=inner NetworkEvents on DeviceName
| where NetworkTime >= FileAccessTime
| where NetworkTime <= FileAccessTime + CorrelationWindow
| extend TimeDeltaSeconds = datetime_diff('second', NetworkTime, FileAccessTime)
| project
    DeviceName,
    FileAccessTime,
    FileName,
    FolderPath,
    InitiatingProcessName,
    ProcessCommandLine,
    NetworkTime,
    RemoteIP,
    RemoteUrl,
    NetInitiatingProcess,
    TimeDeltaSeconds
| order by FileAccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Password managers and credential sync tools that legitimately access keychain paths.
- Browser update processes accessing their own profile directories.
- Security scanning tools or MDM agents performing inventory of credential stores.
- Developer tools such as Python scripts that access browser profiles for automation testing.

**Tuning notes:**
- Confirm macOS devices appear in DeviceFileEvents by running: DeviceFileEvents → where OSPlatform == 'macOS' → summarize count() by DeviceName → take 10
- Validate ActionType values available for macOS file events by running: DeviceFileEvents → where OSPlatform == 'macOS' → summarize count() by ActionType
- Extend CredentialPaths with additional browser profile paths for Edge, Brave, or Opera if those browsers are present in your environment.
- Consider adding a SHA256 or file size filter on the accessed file to reduce noise from metadata-only accesses.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be enrolled and active on macOS devices; if macOS MDE coverage is absent, DeviceFileEvents will contain no macOS records and the query will return no results.
- InitiatingProcessCommandLine may not be populated for all file access events on macOS depending on MDE sensor version; this field should be verified before relying on it for filtering.
- RemoteUrl is not always populated in DeviceNetworkEvents for direct IP connections; the query falls back to RemoteIP but analysts should confirm which field is populated in their environment.
- OSPlatform field availability in DeviceFileEvents and DeviceNetworkEvents should be confirmed; it is standard in MDE Advanced Hunting but may require schema version validation.

### Triage Runbook

**First 15 minutes:**
- Identify the device owner, recent logon user, and whether the process name and command line are expected on that host.
- Review the accessed FolderPath and FileName to confirm the process touched keychain or browser credential locations, not a benign profile directory.
- Check the network destination immediately after the file access for suspicious external IPs, uncommon domains, or direct IP connections.
- Look for parent/child process context, especially osascript, python, shell, curl, or wget launching the activity.

**Evidence to collect:**
- DeviceFileEvents for the device around the alert time, including FolderPath, FileName, InitiatingProcessName, and command line.
- DeviceNetworkEvents for the same device and time window, including RemoteIP, RemoteUrl, and initiating process.
- DeviceProcessEvents to reconstruct the process tree and identify the parent process and user context.
- Any file hashes, quarantine actions, or Defender detections associated with the initiating process.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to identify the full process tree and any repeated execution of the same binary or script.
- DeviceNetworkEvents for the same DeviceName to find other outbound connections from the same process or host.
- DeviceFileEvents for the same DeviceName to see whether additional credential stores or browser profiles were accessed.
- DeviceLogonEvents or equivalent identity telemetry to determine who was active on the device at the time.

**Benign explanations:**
- A password manager, browser sync tool, or enterprise MDM agent legitimately accessed keychain or browser storage.
- A developer or automation script used Python or shell to inspect browser profiles for testing.
- A security tool or inventory process enumerated credential-related paths as part of endpoint assessment.
- The path match was broad and hit a non-sensitive browser profile or cache location.

**Escalation criteria:**
- The process is unknown, unsigned, or launched from a user-writable location such as Downloads, tmp, or a hidden directory.
- There is evidence of outbound connections to suspicious external infrastructure shortly after credential-store access.
- Multiple credential-related paths were accessed, or the same host shows repeated suspicious file access.
- The affected device belongs to a privileged user, executive, or developer with access to sensitive systems.

**Containment actions:**
- Isolate the macOS host from the network if the process is confirmed suspicious or the user cannot explain it.
- Terminate the suspicious process and preserve the binary, script, and related artifacts for analysis.
- Reset credentials for the logged-in user and any accounts that may have been stored in the browser or keychain.
- Block the observed remote IPs or domains if they are clearly malicious and approved for blocking.

**Closure criteria:**
- The process is identified as a legitimate enterprise tool, password manager, or approved automation script.
- No suspicious outbound activity or additional credential-store access is found.
- The accessed paths are confirmed to be non-sensitive or expected for the application.
- Endpoint owner or IT confirms the activity matches a known maintenance or support task.

<br/>
---
<br/>

## Detection 3: CVE-2026-66066 KindaRails2Shell - Suspicious POST to Rails Direct-Upload Endpoint with Anomalous Content-Type

### Detection Opportunity

Attacker uploads a malicious file to the Ruby on Rails Active Storage direct-upload endpoint using an attacker-controlled or mismatched Content-Type header to trigger arbitrary file read via the Vips image processor.

### Intelligence Context

- Rapid7: Rapid7 Analysis: KindaRails2Shell (CVE-2026-66066) — [https://www.rapid7.com/blog/post/ra-kindarails2shell-technical-analysis-cve-2026-66066](https://www.rapid7.com/blog/post/ra-kindarails2shell-technical-analysis-cve-2026-66066)
  - Context: Exploitation of CVE-2026-66066 requires a POST request to the Rails Active Storage direct-upload endpoint with an attacker-controlled Content-Type that causes the Vips image processor to read arbitrary files and return their contents as image pixel data in the response.

### Search Metadata

- CVEs: CVE-2026-66066
- Threat actors: Not specified
- ATT&CK tags: T1190, T1041
- Products: Ruby on Rails, Active Storage, Vips, libvips, libmatio
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-66066, Ruby on Rails, Active Storage, Vips, libvips, libmatio, T1190, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let DirectUploadPattern = "/rails/active_storage/direct_uploads";
let SuspiciousContentTypes = dynamic(["application/x-matlab", "application/mat", "image/x-portable-bitmap", "application/x-hdf", "application/x-netcdf"]);
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where RequestMethod == "POST"
| where RequestURL has DirectUploadPattern
| extend ParsedContentType = coalesce(
    extract(@"(?i)cs-content-type=([^;\s]+)", 1, AdditionalExtensions),
    extract(@"(?i)Content-Type:\s*([^;\r\n\s]+)", 1, AdditionalExtensions)
  )
| where ParsedContentType has_any (SuspiciousContentTypes) or isempty(ParsedContentType)
| where ResponseCode in ("200", "201", "202") or isempty(ResponseCode)
| project
    TimeGenerated,
    SourceIP,
    RequestURL,
    RequestMethod,
    ParsedContentType,
    ResponseCode,
    DeviceVendor,
    DeviceProduct,
    AdditionalExtensions
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate file uploads with unusual MIME types from internal development or testing pipelines.
- Security scanners performing automated vulnerability assessments against the Rails endpoint.
- Misconfigured clients sending incorrect Content-Type headers for valid file uploads.

**Tuning notes:**
- Before running, inspect AdditionalExtensions values from the Rails log source by running: CommonSecurityLog → where RequestURL has '/rails/active_storage' → take 20 → project AdditionalExtensions
- Extend SuspiciousContentTypes with additional libmatio-supported MIME types after reviewing the libmatio documentation for your Rails version.
- If the WAF captures response size, add a filter for responses larger than a baseline threshold to reduce false positives from empty or error responses.

**Risks / caveats:**
- CommonSecurityLog requires a CEF or syslog connector forwarding Rails or WAF access logs; if no such connector is configured, the table will not contain Rails request data and the query will return no results.
- RequestURL and RequestMethod are standard CEF fields but are only populated if the upstream log source maps them to cs-uri-stem and cs-method equivalents; this must be verified per log source.
- Content-Type header capture in AdditionalExtensions is non-standard and depends on the WAF or reverse proxy configuration; many default CEF log profiles do not include request headers.
- The regex for extracting Content-Type from AdditionalExtensions is a best-effort pattern; the actual field name and format depend on the CEF log source and may require adjustment after inspecting raw AdditionalExtensions values.

### Triage Runbook

**First 15 minutes:**
- Confirm the request targets the expected Rails direct-upload path and not a benign upload workflow or test endpoint.
- Review the parsed Content-Type, source IP, response code, and any repeated requests from the same source.
- Check whether the source IP is external, known scanner infrastructure, or an internal testing host.
- Look for adjacent requests to the same application that indicate probing, enumeration, or follow-on exploitation.

**Evidence to collect:**
- CommonSecurityLog entries for the source IP and URL over a wider time window.
- Raw AdditionalExtensions values to validate how Content-Type was captured and whether the header was attacker-controlled.
- Response codes, response sizes if available, and any server-side error messages tied to the request.
- Application or WAF logs showing whether the upload was accepted, rejected, or followed by unusual file processing.

**Pivot points:**
- CommonSecurityLog filtered on the same SourceIP to identify other requests to the application or other targets.
- CommonSecurityLog filtered on the same RequestURL or direct-upload path to find repeated attempts and other source IPs.
- Web server, reverse proxy, or WAF logs for the same timestamp to inspect request headers and body size.
- If available, application logs for Active Storage or Vips processing errors around the same time.

**Benign explanations:**
- A legitimate client or integration sent an unusual but harmless Content-Type header.
- A security scanner or penetration test generated the request.
- A misconfigured upload client used the wrong MIME type for a valid file upload.
- The log source captured incomplete header data, making the request appear more suspicious than it was.

**Escalation criteria:**
- The source IP is external and the request pattern matches exploitation attempts against the direct-upload endpoint.
- Multiple requests with anomalous Content-Type values are observed from the same source or campaign infrastructure.
- The application returned successful responses and server-side logs show unexpected file processing or errors consistent with exploitation.
- The target application is internet-facing and unpatched or known to be vulnerable.

**Containment actions:**
- Block the source IP or associated scanner infrastructure at the WAF or reverse proxy if the activity is clearly malicious.
- Temporarily restrict access to the direct-upload endpoint if exploitation is suspected and business impact is acceptable.
- Notify the application owner to validate patch status and review upload handling immediately.
- Preserve relevant web, WAF, and application logs before making changes.

**Closure criteria:**
- The request is confirmed to be from an approved scanner, tester, or internal client.
- The Content-Type and URL are explained by a legitimate upload workflow.
- No additional suspicious requests or server-side anomalies are found.
- The application owner confirms the endpoint behavior is expected and not vulnerable in the deployed version.

<br/>
---
<br/>

## Detection 4: CVE-2026-66066 KindaRails2Shell - Anomalous Image Response Size from Rails Upload Endpoint Indicating File Exfiltration

### Detection Opportunity

Rails Active Storage upload endpoint returns an anomalously large or unexpected image response to an external IP, consistent with arbitrary file contents being encoded as image pixel data and returned to the attacker.

### Intelligence Context

- Rapid7: Rapid7 Analysis: KindaRails2Shell (CVE-2026-66066) — [https://www.rapid7.com/blog/post/ra-kindarais2shell-technical-analysis-cve-2026-66066](https://www.rapid7.com/blog/post/ra-kindarais2shell-technical-analysis-cve-2026-66066)
  - Context: CVE-2026-66066 exploitation causes the Vips image processor to return target file bytes encoded as image pixels in the HTTP response. This produces anomalous response sizes from the direct-upload endpoint that are detectable in web access logs when baselined against normal upload responses.

### Search Metadata

- CVEs: CVE-2026-66066
- Threat actors: Not specified
- ATT&CK tags: T1190, T1041
- Products: Ruby on Rails, Active Storage, Vips, libvips, libmatio
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-66066, Ruby on Rails, Active Storage, Vips, libvips, libmatio, T1190, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SensitivePaths = dynamic(["/etc/passwd", "/etc/shadow", "/credentials", "/secrets", ".env", "database.yml", "master.key"]);
let VipsProcesses = dynamic(["vips", "ruby", "puma", "unicorn"]);
let CorrelationWindow = 2m;
let FileReads = DeviceProcessEvents
| where Timestamp > ago(7d)
| where OSPlatform == "Linux"
| where InitiatingProcessName has_any (VipsProcesses) or FileName has_any (VipsProcesses)
| where ProcessCommandLine has_any (SensitivePaths)
| project
    DeviceName,
    FileReadTime = Timestamp,
    InitiatingProcessName,
    FileName,
    ProcessCommandLine,
    AccountName;
let OutboundConns = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where OSPlatform == "Linux"
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| where InitiatingProcessName has_any (VipsProcesses)
| project
    DeviceName,
    ConnTime = Timestamp,
    RemoteIP,
    RemoteUrl,
    NetInitiatingProcess = InitiatingProcessName;
FileReads
| join kind=inner OutboundConns on DeviceName
| where ConnTime >= FileReadTime
| where ConnTime <= FileReadTime + CorrelationWindow
| extend TimeDeltaSeconds = datetime_diff('second', ConnTime, FileReadTime)
| project
    DeviceName,
    FileReadTime,
    InitiatingProcessName,
    FileName,
    ProcessCommandLine,
    AccountName,
    ConnTime,
    RemoteIP,
    RemoteUrl,
    NetInitiatingProcess,
    TimeDeltaSeconds
| order by FileReadTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Ruby or Puma processes making routine outbound connections to cloud services, APIs, or monitoring endpoints shortly after any file operation.
- Vips CLI being used legitimately for image processing tasks that happen to coincide with outbound connections.
- Deployment or configuration management processes that read credential files and make outbound connections as part of normal operation.

**Tuning notes:**
- Confirm the Rails server appears in DeviceProcessEvents by running: DeviceProcessEvents → where FileName in ('ruby', 'puma', 'vips') → summarize count() by DeviceName, FileName → take 20
- Validate that ProcessCommandLine is populated for Ruby processes by running: DeviceProcessEvents → where FileName == 'ruby' → take 10 → project ProcessCommandLine
- Extend SensitivePaths with application-specific credential or configuration file paths for your Rails deployment such as config/database.yml absolute paths.
- Consider supplementing this detection with a DeviceFileEvents query on the same host for the same SensitivePaths if file read telemetry is available.

**Risks / caveats:**
- Defender for Endpoint must be deployed and active on the Linux host running the Rails application; if the server is not enrolled, DeviceProcessEvents and DeviceNetworkEvents will contain no records for it.
- ProcessCommandLine for Ruby application server processes may not include the file path being processed by Vips; Vips typically operates as a library call within the Ruby process rather than as a separate process with command-line arguments referencing the target file.
- ipv4_is_private() is a standard KQL function in Defender XDR Advanced Hunting but should be validated against the actual RemoteIP field type; if RemoteIP contains hostnames rather than IPs, the function will return errors.
- Vips operates as a shared library within the Ruby process in most Rails deployments; ProcessCommandLine for the Ruby/Puma process will typically not contain the target file path unless vips CLI is invoked directly. This significantly limits detection coverage for the primary exploitation path.

### Triage Runbook

**First 15 minutes:**
- Confirm the response size is abnormal compared with normal upload responses for the same endpoint.
- Review the source IP, request path, and timing to determine whether the request is part of a broader exploitation sequence.
- Check whether the response was delivered to an external IP and whether the destination is known or suspicious.
- Correlate the event with application or server logs for errors, unusual image processing, or file access activity.

**Evidence to collect:**
- Web access logs showing request and response sizes for the same endpoint and source IP.
- Application logs or error logs from Rails, Active Storage, Vips, or the reverse proxy.
- Any available file access or process telemetry on the application host around the same timestamp.
- Historical baseline of normal response sizes for the direct-upload endpoint.

**Pivot points:**
- CommonSecurityLog or web server logs for the same SourceIP and RequestURL to identify repeated attempts and response patterns.
- Application logs for the Rails host to look for Vips processing errors or file read indicators.
- Host telemetry on the Rails server, if available, to identify suspicious process or file activity around the request.
- Logs for other endpoints on the same host to determine whether the source IP is probing additional paths.

**Benign explanations:**
- A legitimate large file upload or image transformation produced an unusually large response.
- A test or staging environment generated non-production traffic with atypical response sizes.
- Compression, encoding, or logging artifacts made the response appear larger than it was.
- A benign client retried the upload and received a larger-than-normal but expected response.

**Escalation criteria:**
- The response size is far outside the normal baseline and aligns with known exploitation behavior.
- The source IP is external and the request pattern matches active exploitation of the Rails vulnerability.
- Server-side logs show unexpected file reads, Vips errors, or other signs of arbitrary file access.
- The application is internet-facing and the vulnerability is unpatched or not mitigated.

**Containment actions:**
- Block the source IP or malicious request pattern at the WAF or reverse proxy if exploitation is likely.
- Temporarily disable or restrict the affected upload endpoint if the business can tolerate it.
- Escalate to the application owner to patch or mitigate the vulnerable Rails component immediately.
- Preserve logs and any affected files before remediation changes are made.

**Closure criteria:**
- The response size is explained by a legitimate upload, test, or image-processing workflow.
- No server-side evidence supports arbitrary file read or exfiltration.
- The source IP is approved or internal and the activity matches expected behavior.
- The application owner confirms the endpoint is patched or otherwise not exploitable in the observed configuration.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Midnight Blizzard - Credential Theft Post Hospitality Portal Sign-In from New Location: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Other deployment dependency:**
- AMOS Stealer - Suspicious macOS Process Accessing Keychain or Browser Credential Paths: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- CVE-2026-66066 KindaRails2Shell - Suspicious POST to Rails Direct-Upload Endpoint with Anomalous Content-Type: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- CVE-2026-66066 KindaRails2Shell - Anomalous Image Response Size from Rails Upload Endpoint Indicating File Exfiltration: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Shared-table notes:**
- DeviceNetworkEvents: shared by AMOS Stealer - Suspicious macOS Process Accessing Keychain or Browser Credential Paths; CVE-2026-66066 KindaRails2Shell - Anomalous Image Response Size from Rails Upload Endpoint Indicating File Exfiltration

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: AMOS Stealer - Suspicious macOS Process Accessing Keychain or Browser Credential Paths; CVE-2026-66066 KindaRails2Shell - Suspicious POST to Rails Direct-Upload Endpoint with Anomalous Content-Type; CVE-2026-66066 KindaRails2Shell - Anomalous Image Response Size from Rails Upload Endpoint Indicating File Exfiltration.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Midnight Blizzard - Credential Theft Post Hospitality Portal Sign-In from New Location.

### Hunting Agenda and Promotion Criteria

- Midnight Blizzard - Credential Theft Post Hospitality Portal Sign-In from New Location: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- AMOS Stealer - Suspicious macOS Process Accessing Keychain or Browser Credential Paths: Defender for Endpoint file-event coverage must be confirmed on the target host population.; confirm required file-access telemetry exists and produces representative events.
- CVE-2026-66066 KindaRails2Shell - Suspicious POST to Rails Direct-Upload Endpoint with Anomalous Content-Type: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-66066 KindaRails2Shell - Anomalous Image Response Size from Rails Upload Endpoint Indicating File Exfiltration: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling..

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
