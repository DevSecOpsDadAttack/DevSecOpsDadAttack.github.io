---
layout: post
title: "Detection Engineering Brief - Sunday, August 2, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-02
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Midnight Blizzard
  - Storm-2945
  - web
  - email
  - identity
  - Xcode
  - macOS
  - XCSSET
  - CVE-2026-66066
  - T1190
  - Ruby on Rails
  - Active Storage
  - libvips
  - T1078
  - T1621
  - T1547
  - T1021
  - T1059
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

2 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: Midnight Blizzard, Storm-2945, web, email, identity, Xcode, macOS, XCSSET, CVE-2026-66066, T1190, Ruby on Rails, Active Storage, libvips, T1078, T1621, T1547, T1021, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: XCSSET - Unexpected File Write into Xcode Project Directory by Non-Xcode Process on macOS; CVE-2026-66066 - Anomalous POST to Active Storage Upload Endpoint with Path Traversal Pattern.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Midnight Blizzard - Risky Sign-In Followed by Sensitive Resource Access from Atypical Travel Location

### Detection Opportunity

Credential theft via compromised hospitality captive portals resulting in successful sign-in from atypical travel geography followed by resource access.

### Intelligence Context

- Microsoft Security Blog: CaptiveCrunch: Midnight Blizzard targets travelers worldwide for malware delivery and credential theft — [https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)
  - Context: Midnight Blizzard (Storm-2945) compromised hospitality sign-in portals to steal credentials from travelers. Stolen credentials are used to authenticate into corporate identity infrastructure from atypical geographic locations. The campaign specifically targets travelers, making sign-ins from hotel or travel-associated locations combined with elevated Entra ID risk signals and subsequent resource access the key detection pivot.

### Search Metadata

- CVEs: Not specified
- Threat actors: Midnight Blizzard, Storm-2945
- ATT&CK tags: T1078, T1621
- Products: Not specified
- Platforms: web, email, identity
- Malware: Not specified
- Tools: Not specified
- Search tags: Midnight Blizzard, Storm-2945, web, email, identity, T1078, T1621

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1078 Valid Accounts (high); Defense Evasion: T1621 Multi-Factor Authentication Request Generation (low)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- SigninLogs, AADRiskyUsers

### KQL

```kql
let LookbackSignIn = 24h;
let LookbackRisk = 7d;
let CorrelationWindow = 48h;
let RiskySignIns = SigninLogs
| where TimeGenerated >= ago(LookbackSignIn)
| where ResultType == 0
| where RiskLevelDuringSignIn in ("medium", "high")
| project UserPrincipalName, UserDisplayName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, SignInTime = TimeGenerated;
let RiskyUsers = AADRiskyUsers
| where TimeGenerated >= ago(LookbackRisk)
| where RiskLevel in ("medium", "high")
| where RiskState in ("atRisk", "confirmedCompromised")
| project UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdated = TimeGenerated;
RiskySignIns
| join kind=inner RiskyUsers on UserPrincipalName
| where abs(datetime_diff('hour', SignInTime, RiskLastUpdated)) <= totimespan(CorrelationWindow) / 1h
| project SignInTime, RiskLastUpdated, UserPrincipalName, UserDisplayName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, RiskLevel, RiskState, RiskDetail
| order by SignInTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate travelers using corporate credentials from hotel networks may trigger Entra ID atypical travel risk without being compromised.
- Users with pre-existing elevated risk state from unrelated prior events may match if they sign in successfully during the lookback window.
- VPN exit nodes in geographically distant regions may produce atypical location signals for users who are not actually traveling.

**Tuning notes:**
- Raise RiskLevelDuringSignIn and RiskLevel filters to 'high' only in high-volume environments to reduce FP rate.
- Scope AppDisplayName to sensitive applications such as 'Office 365 Exchange Online', 'Microsoft SharePoint', or 'Azure Portal' to focus on post-authentication resource access.
- Consider adding a watchlist of known VPN egress IPs to exclude from IPAddress to suppress travel-simulation FPs.

**Risks / caveats:**
- AADRiskyUsers requires Entra ID Identity Protection P2 licensing. If the license is absent the table will be empty and the join will produce no results.
- SigninLogs requires Entra ID Diagnostic Settings to be configured to stream to the Sentinel workspace. If the connector is not enabled the table will be absent.
- AADRiskyUsers does not always carry a TimeGenerated field that reflects the risk detection time with high fidelity; RiskLastUpdatedDateTime is the canonical field in some schema versions. Verify the field name in the workspace before scheduling.
- The 48-hour bidirectional correlation window may match risk records that predate the sign-in by up to 48 hours, potentially linking unrelated risk elevations to a sign-in event. Tighten to 12h if FP volume is high.

### Triage Runbook

**First 15 minutes:**
- Validate the account owner, recent travel status, and whether the sign-in location matches a known VPN, hotel, or mobile carrier egress.
- Review the sign-in details for the IP, location, app, device, MFA status, and RiskDetail to see whether the session was interactive and whether the risk was elevated for a specific reason.
- Check whether the account accessed sensitive applications or data immediately after the sign-in, especially Exchange Online, SharePoint, OneDrive, Azure Portal, or admin portals.
- Look for follow-on identity activity such as password changes, MFA method changes, consent grants, mailbox rule creation, or additional risky sign-ins from the same IP.

**Evidence to collect:**
- UserPrincipalName, UserDisplayName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, RiskLevel, RiskState, RiskDetail, SignInTime, RiskLastUpdated.
- Any recent Entra ID audit events for the same user, including MFA registration, password reset, consent, or role assignment changes.
- Session context such as device compliance, browser/user agent, and whether the sign-in was from a managed device or unfamiliar endpoint.
- Timeline of subsequent resource access from the same account and IP within the next 24 hours.

**Pivot points:**
- SigninLogs for the same UserPrincipalName, IPAddress, and AppDisplayName over the prior and next 24 hours.
- AADRiskyUsers for current and recent risk state changes on the account.
- AuditLogs for MFA, password, consent, and role changes tied to the account.
- Cloud app access logs for Exchange, SharePoint, OneDrive, and Azure Portal activity from the same user and IP.

**Benign explanations:**
- The user may be traveling and using a hotel or airport network that triggers atypical travel risk.
- A corporate VPN or cloud egress node in a distant region may make a normal sign-in appear suspicious.
- The account may already have an unrelated elevated risk state from a prior event that is now surfacing during a legitimate sign-in.

**Escalation criteria:**
- Escalate immediately if the user denies travel or does not recognize the sign-in location or device.
- Escalate if the account accessed sensitive data, admin portals, or performed mailbox, consent, or MFA changes after the risky sign-in.
- Escalate if there are multiple risky sign-ins, impossible travel patterns, or evidence of additional accounts being accessed from the same IP.
- Escalate if the account is privileged, service-critical, or used for email, identity administration, or sensitive business data.

**Containment actions:**
- If compromise is likely, disable the account or force sign-out and revoke active sessions.
- Reset the password and require MFA re-registration if the account is confirmed or strongly suspected compromised.
- Block the source IP or session only if it is clearly malicious and not a known VPN or travel egress point.
- Preserve identity logs and notify the identity team before making changes that could destroy evidence.

**Closure criteria:**
- The sign-in is confirmed as legitimate travel or approved VPN activity and no suspicious follow-on access is found.
- The risk state is explained by a known benign event and the user or business owner confirms the activity.
- No sensitive resource access, privilege changes, or additional suspicious sign-ins are observed within the investigation window.
- Document the travel/VPN explanation and any tuning needed for known benign locations or egress IPs.

<br/>
---
<br/>

## Detection 2: XCSSET - Unexpected File Write into Xcode Project Directory by Non-Xcode Process on macOS

### Detection Opportunity

XCSSET malware injects malicious content into Xcode project directories on macOS developer endpoints by writing files from processes other than Xcode itself.

### Intelligence Context

- Unit 42: The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version — [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
  - Context: XCSSET v40 is a macOS malware that persists and spreads by injecting malicious files into Xcode project directories. The injection is performed by processes other than Xcode, making unexpected file creation events inside .xcodeproj or related Xcode workspace paths by non-Xcode parent processes the primary behavioral indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1547, T1021
- Products: Xcode
- Platforms: macOS
- Malware: XCSSET
- Tools: Not specified
- Search tags: Xcode, macOS, XCSSET, T1547, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution (low); Lateral Movement: T1021 Remote Services (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp >= ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (".xcodeproj", ".xcworkspace", "DerivedData")
| where InitiatingProcessName !in~ (
    "Xcode",
    "xcodebuild",
    "xcrun",
    "swift",
    "clang",
    "clang++",
    "ld",
    "lld",
    "git",
    "git-remote-https",
    "com.apple.dt.Xcode"
)
| summarize
    EventCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    FilesWritten = make_set(FileName, 50),
    FolderPaths = make_set(FolderPath, 20)
    by DeviceId, DeviceName, InitiatingProcessName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CocoaPods, fastlane, Homebrew, and other macOS developer dependency managers legitimately write into Xcode project directories.
- CI/CD agents (e.g., Jenkins, GitHub Actions runner, Buildkite) running on macOS build hosts may write into project directories as part of automated builds.
- IDE plugins and extensions (e.g., AppCode, Nova) may write into .xcodeproj structures.
- Backup agents and file sync tools (e.g., Time Machine, Dropbox, iCloud Drive daemon) may trigger FileModified events on project files.

**Tuning notes:**
- Run the query in hunting mode first and review the InitiatingProcessName values in results to build an environment-specific exclusion list before scheduling.
- Narrow FolderPath to user home directory prefixes (e.g., '/Users/') to exclude system-level or CI agent paths.
- Consider adding InitiatingProcessSHA256 to the projection and cross-referencing against known-good hashes for build tools to reduce name-spoofing risk.

**Risks / caveats:**
- Microsoft Defender for Endpoint macOS agent must be deployed with file event telemetry enabled. If macOS endpoints are not onboarded to MDE, DeviceFileEvents will contain no macOS records.
- FolderPath population for macOS file events depends on MDE agent version and telemetry configuration. Verify the field is non-null for macOS hosts before relying on path-based filtering.
- The DeviceFileEvents ActionType values FileCreated and FileModified must be confirmed as supported on the macOS MDE agent version deployed in the environment.
- The InitiatingProcessName exclusion list is not exhaustive. Environments with non-standard build tooling will require additional exclusions before the query produces actionable signal.

### Triage Runbook

**First 15 minutes:**
- Identify the device owner and confirm whether the host is a developer workstation, build server, or CI agent that normally writes into Xcode project paths.
- Review the initiating process name, command line, and account to determine whether the writer is a known build tool, sync agent, or an unexpected user-space process.
- Check whether the file write occurred in a user home project path versus a system or CI path, and whether multiple project directories were touched.
- Look for concurrent signs of malware activity such as new launch agents, unusual network connections, shell execution, or additional file modifications in developer directories.

**Evidence to collect:**
- Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ActionType, EventCount.
- Any related process tree or parent process information for the initiating process.
- Recent file writes in .xcodeproj, .xcworkspace, DerivedData, and adjacent project folders on the same host.
- Network, persistence, and execution telemetry from the same device around the alert time.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and FolderPath patterns to identify repeated writes or additional affected projects.
- DeviceProcessEvents for the initiating process and its parent to validate whether it is a known build tool or suspicious binary.
- DeviceNetworkEvents for outbound connections from the same host around the alert time.
- DeviceRegistryEvents or macOS persistence telemetry for launch agents, login items, or other autostart artifacts if available.

**Benign explanations:**
- CocoaPods, fastlane, Homebrew, or other developer tooling may legitimately modify Xcode project files.
- CI/CD agents or build runners on macOS may write into project directories during automated builds.
- Backup, sync, or indexing tools such as Time Machine, Dropbox, or iCloud Drive may create or modify files in project paths.

**Escalation criteria:**
- Escalate if the initiating process is not a known build tool and is running from an unusual path or under an unexpected account.
- Escalate if multiple Xcode projects or developer directories are modified by the same process in a short period.
- Escalate if the host also shows persistence, suspicious network activity, or execution of shell commands.
- Escalate if the device is a high-value developer workstation or contains sensitive source code or signing material.

**Containment actions:**
- If the process is clearly malicious or the host shows additional compromise indicators, isolate the macOS endpoint from the network.
- Preserve the suspicious files, process command line, and any modified project artifacts before remediation.
- Remove or quarantine the malicious file only after evidence collection and coordination with the endpoint team.
- If the alert is tied to a developer workstation with active code changes, coordinate with the owner before taking disruptive action.

**Closure criteria:**
- The initiating process is confirmed as a legitimate build or sync tool and the file writes match expected developer activity.
- No additional suspicious process, persistence, or network indicators are found on the host.
- The affected paths and process names are added to an environment-specific allowlist or tuning note if appropriate.
- Document the benign workflow and retain the event as a hunting reference for future baselining.

<br/>
---
<br/>

## Detection 3: CVE-2026-66066 - Anomalous POST to Active Storage Upload Endpoint with Path Traversal Pattern

### Detection Opportunity

Unauthenticated attacker exploits CVE-2026-66066 in Ruby on Rails Active Storage by submitting crafted image upload requests containing file path traversal sequences to read arbitrary files accessible to the Rails process.

### Intelligence Context

- Rapid7: KindaRails2Shell: CVE-2026-66066, Critical Arbitrary File Read and Possible Remote Code Execution in Ruby on Rails — [https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails](https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails)
  - Context: CVE-2026-66066 allows an unauthenticated attacker to read files accessible to the Rails process by submitting malicious image uploads to Active Storage endpoints that use libvips for processing. The attack vector is a crafted POST request to the Active Storage upload path containing path traversal or malicious image metadata that causes libvips to open unintended file paths.

### Search Metadata

- CVEs: CVE-2026-66066
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Ruby on Rails, Active Storage, libvips
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-66066, T1190, Ruby on Rails, Active Storage, libvips, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated >= ago(7d)
| where RequestMethod == "POST"
| where RequestURL has_any (
    "/rails/active_storage",
    "/active_storage/blobs",
    "/active_storage/disk"
)
| where RequestURL has_any (
    "../",
    "%2e%2e",
    "%2E%2E",
    "%00",
    "..%2f",
    "..%2F",
    "%2f..",
    "%2F..",
    "%252e%252e",
    "%252f"
)
| summarize
    AttemptCount = count(),
    ResponseCodes = make_set(ResponseCode),
    RequestURLs = make_set(RequestURL, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationHostName, DeviceVendor, DeviceProduct
| order by AttemptCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated vulnerability scanners (e.g., Qualys, Tenable, Burp Suite) may generate path traversal probes against Active Storage endpoints as part of scheduled scans.
- Penetration testing activity against the Rails application will match this query.
- Misconfigured clients that send malformed URLs containing dot-dot sequences unintentionally may generate low-volume matches.

**Tuning notes:**
- Add DeviceVendor or DeviceProduct filters to scope to the specific WAF product forwarding logs if multiple CEF sources are present in CommonSecurityLog.
- Add DestinationHostName filter to restrict results to the specific Rails application server hostname.
- Raise AttemptCount threshold to 3 or more to suppress single-probe scanner noise if scan activity is high in the environment.

**Risks / caveats:**
- CommonSecurityLog RequestURL and RequestMethod fields are only populated when the upstream WAF or proxy product maps these values into the CEF RequestURL and RequestMethod fields. Many WAF products use DeviceCustomString fields instead. Confirm field population with: CommonSecurityLog → where isnotempty(RequestURL) → take 5.
- If the Rails application is not fronted by a WAF or proxy that forwards logs to Sentinel via CEF, this query will produce no results regardless of exploitation activity.
- ResponseCode in CommonSecurityLog maps to the CEF field 'cn1' or 'outcome' depending on the product. Verify the field name resolves correctly in the workspace.
- The 7-day lookback may miss exploitation that occurred before log ingestion was configured or before the CVE was publicly disclosed.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination host, application, and whether the request reached a production Rails service behind a WAF or reverse proxy.
- Review the source IP, request URL, response code, and request frequency to determine whether this is a single probe, repeated exploitation attempt, or scanner activity.
- Check whether the request used encoded traversal variants and whether the WAF or proxy normalized or blocked the payload.
- Look for signs of successful file access or follow-on activity in application logs, error logs, and any correlated server-side process activity.

**Evidence to collect:**
- SourceIP, RequestURL, ResponseCode, AttemptCount, FirstSeen, LastSeen, DeviceVendor, DeviceProduct, DestinationHostName.
- WAF or reverse proxy logs showing whether the request was blocked, allowed, or rewritten.
- Rails application logs, Active Storage logs, and web server logs for the same time window.
- Any server-side indicators of file read, error messages, or unexpected process behavior after the request.

**Pivot points:**
- CommonSecurityLog for the same SourceIP, DestinationHostName, and RequestURL patterns.
- Web server and application logs for the Rails host to confirm whether the request reached the app and whether errors occurred.
- DeviceProcessEvents on the Rails host if there is any sign of post-exploitation execution.
- Threat intel or firewall logs for repeated requests from the same source across other hosts.

**Benign explanations:**
- A vulnerability scanner or penetration test may intentionally probe Active Storage endpoints with traversal strings.
- A developer or QA test may generate malformed upload requests during application testing.
- A misconfigured client or integration may accidentally send malformed URLs containing dot-dot sequences.

**Escalation criteria:**
- Escalate if the request was allowed through the WAF or proxy and the application shows signs of file access or abnormal errors.
- Escalate if the same source IP repeats the request across multiple hosts or endpoints.
- Escalate if there is any evidence of post-request command execution, new child processes, or suspicious outbound connections from the Rails host.
- Escalate if the application contains sensitive data, secrets, or internal files that could be exposed by arbitrary file read.

**Containment actions:**
- Block the source IP or upstream scanner if the activity is clearly malicious and not a sanctioned test.
- Temporarily restrict access to the affected upload endpoint or place the application behind stricter WAF rules if exploitation is ongoing.
- Preserve WAF, proxy, and application logs before making changes.
- If compromise is suspected, coordinate with application owners to isolate the host or take the service into maintenance mode.

**Closure criteria:**
- The activity is confirmed as a sanctioned scan, test, or benign malformed request with no evidence of successful exploitation.
- The WAF or proxy blocked the request and the application shows no corresponding server-side impact.
- No repeated attempts, no suspicious server-side behavior, and no evidence of file read or post-exploitation activity are found.
- Document the source, request pattern, and any WAF tuning or allowlisting decisions.

<br/>
---
<br/>

## Detection 4: CVE-2026-66066 - Unexpected Child Process Spawned from Ruby or Rails Web Server Process on Linux

### Detection Opportunity

Possible remote code execution via CVE-2026-66066 where exploitation of the libvips image processing path in Ruby on Rails causes the web server process to spawn unexpected child processes on Linux hosts.

### Intelligence Context

- Rapid7: KindaRails2Shell: CVE-2026-66066, Critical Arbitrary File Read and Possible Remote Code Execution in Ruby on Rails — [https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails](https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails)
  - Context: CVE-2026-66066 includes a possible RCE path via libvips image processing within Ruby on Rails Active Storage. If RCE is achieved, the Rails web server process (ruby, puma, unicorn, or passenger) would spawn unexpected child processes such as shells or system utilities. Detecting anomalous child process creation from these parent processes on Linux servers is a reliable post-exploitation indicator.

### Search Metadata

- CVEs: CVE-2026-66066
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Ruby on Rails, Active Storage, libvips
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-66066, T1190, Ruby on Rails, Active Storage, libvips, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp >= ago(1d)
| where InitiatingProcessName in~ (
    "ruby",
    "puma",
    "unicorn",
    "passenger",
    "bundle"
)
| where FileName in~ (
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "python",
    "python3",
    "perl",
    "curl",
    "wget",
    "nc",
    "ncat",
    "socat",
    "id",
    "whoami",
    "awk",
    "base64",
    "chmod",
    "chown",
    "crontab",
    "env",
    "mkfifo",
    "nohup",
    "openssl",
    "php",
    "tee"
)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Deployment scripts or health check scripts that invoke shell commands via the Rails process (e.g., rake tasks, Capistrano hooks) may match if they run in the context of the web server process.
- Developer workstations running local Rails servers with rails console or rake commands may spawn ruby or bash child processes legitimately.
- Application monitoring agents that attach to the Ruby process and spawn diagnostic utilities may trigger matches.

**Tuning notes:**
- Scope DeviceName or DeviceId to known Rails application servers using a watchlist or dynamic group to reduce FP volume from developer workstations.
- Add AccountName exclusions for known deployment service accounts that legitimately invoke shell commands via the Rails process.
- Extend InitiatingProcessName to include versioned Ruby binary names such as 'ruby2.7', 'ruby3.1', or 'ruby3.2' if the environment uses version-pinned Ruby installations.
- In containerized environments, consider filtering on DeviceName patterns that match known Rails pod naming conventions.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be deployed on Linux hosts running the Rails application. If Linux servers are not onboarded to MDE, DeviceProcessEvents will contain no records for those hosts.
- Process event telemetry depth on Linux MDE agents depends on agent version and audit configuration. Verify that InitiatingProcessName is populated for Linux process events in the environment.
- The parent process name list may not cover all Ruby web server variants or process names used by containerized Rails deployments (e.g., the process may appear as 'ruby2.7' or a versioned binary name).
- In containerized environments (Docker, Kubernetes), DeviceName may reflect the container host rather than the specific pod, making scoping to Rails servers less precise.

### Triage Runbook

**First 15 minutes:**
- Identify the parent process, child process, command line, and account context to confirm whether the spawn is expected for this host and workload.
- Check whether the child process is a shell, downloader, scripting interpreter, or system utility that is unusual for a web server to launch.
- Review the host’s recent web requests, application errors, and any signs of the CVE-2026-66066 exploit pattern around the same time.
- Look for immediate follow-on behavior such as outbound connections, file creation in temporary or web directories, or additional spawned processes.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, InitiatingProcessAccountName, InitiatingProcessName, InitiatingProcessCommandLine, InitiatingProcessParentName, FileName, FolderPath, ProcessCommandLine, SHA256.
- Process tree for the parent Rails process and the spawned child process.
- Web access logs, application logs, and error logs from the same host and time window.
- Network connections and file activity from the child process and any descendants.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to identify additional child processes or repeated spawns.
- DeviceNetworkEvents for outbound connections from the child process or its descendants.
- DeviceFileEvents for suspicious file writes, downloads, or script drops on the Rails host.
- Web or reverse proxy logs to correlate the process spawn with a suspicious request to the application.

**Benign explanations:**
- Deployment scripts, health checks, or maintenance tasks may legitimately invoke shell commands through the Rails process.
- Local developer environments running Rails may spawn ruby, bash, or related utilities during normal testing.
- Monitoring or diagnostic agents may attach to the Ruby process and launch helper utilities.

**Escalation criteria:**
- Escalate if the child process is a shell, downloader, scripting interpreter, or network utility with no clear operational justification.
- Escalate if the process tree shows web-server-originated execution followed by outbound connections or file drops.
- Escalate if the host is internet-facing, production, or contains sensitive application data.
- Escalate if the same host also shows the Active Storage traversal alert or other signs of exploitation.

**Containment actions:**
- If compromise is likely, isolate the Linux host from the network to stop further execution and data access.
- Preserve the process tree, command lines, hashes, and relevant logs before remediation.
- Terminate only the clearly malicious child process if isolation is not immediately possible and the service impact is acceptable.
- Coordinate with application owners before restarting services or applying patches to avoid destroying evidence.

**Closure criteria:**
- The child process is confirmed as expected maintenance, deployment, or monitoring activity with documented justification.
- No suspicious network, file, or persistence activity is found on the host after the process spawn.
- The host is patched or otherwise protected against the vulnerable condition if the alert was triggered during a real exposure window.
- Document the benign process lineage and add tuning for approved maintenance accounts or known helper binaries.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Schema / correlation keys:**
- XCSSET - Unexpected File Write into Xcode Project Directory by Non-Xcode Process on macOS: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- CVE-2026-66066 - Anomalous POST to Active Storage Upload Endpoint with Path Traversal Pattern: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Midnight Blizzard - Risky Sign-In Followed by Sensitive Resource Access from Atypical Travel Location; CVE-2026-66066 - Unexpected Child Process Spawned from Ruby or Rails Web Server Process on Linux.
2. Resolve environment-mapping detections next: CVE-2026-66066 - Anomalous POST to Active Storage Upload Endpoint with Path Traversal Pattern.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: XCSSET - Unexpected File Write into Xcode Project Directory by Non-Xcode Process on macOS.

### Hunting Agenda and Promotion Criteria

- XCSSET - Unexpected File Write into Xcode Project Directory by Non-Xcode Process on macOS: Do not schedule yet; validate as an analyst-led hunt first..
- CVE-2026-66066 - Anomalous POST to Active Storage Upload Endpoint with Path Traversal Pattern: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
