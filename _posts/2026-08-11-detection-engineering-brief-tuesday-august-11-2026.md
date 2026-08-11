---
layout: post
title: "Detection Engineering Brief - Tuesday, August 11, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-11
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - DeadLock
  - Windows
  - Rust
  - Google Apps Script
  - Google Workspace
  - DNS
  - Kimwolf
  - Android
  - IoT
  - Tor
  - Ethereum
  - T1041
  - T1486
  - T1071
  - T1071.004
  - T1090
  - T1090.003
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: DeadLock, Windows, Rust, Google Apps Script, Google Workspace, DNS, Kimwolf, Android, IoT, Tor, Ethereum, T1041, T1486, T1071, T1071.004, T1090, T1090.003.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: DeadLock Ransomware - Large Outbound Transfer Concurrent with File Encryption Activity; CAV3RN - Non-Browser Process Connecting to Google Apps Script C2 Relay; CAV3RN - High-Frequency DNS Queries Preceding C2 Channel Establishment.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: DeadLock Ransomware - Mass File Encryption by Rust Binary

### Detection Opportunity

High-volume file modification events consistent with DeadLock ransomware encrypting victim files via a Rust-based encryptor.

### Intelligence Context

- Microsoft Security Blog: DeadLock ransomware: Breaking down a Rust-based encryptor with decentralized recovery infrastructure — [https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/)
  - Context: DeadLock ransomware uses a Rust-based encryptor to mass-encrypt victim files. The Rust binary origin may reduce PE metadata richness, but the mass file rename and write pattern is a reliable telemetry signal for detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1041, T1486
- Products: Not specified
- Platforms: Windows, Rust
- Malware: DeadLock
- Tools: Not specified
- Search tags: DeadLock, Windows, Rust, T1041, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Exfiltration: T1041 Exfiltration Over C2 Channel (medium); Impact: T1486 Data Encrypted for Impact (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let lookback = 5m;
let encryptionThreshold = 100;
let excludedPaths = dynamic([
    @"C:\Windows\\",
    @"C:\Program Files\\",
    @"C:\Program Files (x86)\\",
    @"C:\ProgramData\\",
    @"C:\Users\\Public\\"
]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileRenamed", "FileCreated", "FileModified")
| where not(FolderPath has_any (excludedPaths))
| extend FileExtension = tostring(split(FileName, ".")[-1])
| where strlen(FileExtension) between (3 .. 10)
| summarize
    FileCount = count(),
    DistinctExtensions = dcount(FileExtension),
    SampleExtensions = make_set(FileExtension, 10),
    SampleFolderPaths = make_set(FolderPath, 10),
    InitiatingProcessCommandLine = any(InitiatingProcessCommandLine),
    InitiatingProcessSHA256 = any(InitiatingProcessSHA256),
    WindowStart = min(Timestamp)
    by DeviceId, DeviceName, InitiatingProcessFileName, bin(Timestamp, lookback)
| where FileCount >= encryptionThreshold
| project
    WindowStart,
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    FileCount,
    DistinctExtensions,
    SampleExtensions,
    SampleFolderPaths
| order by FileCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents performing bulk file versioning or snapshot operations may exceed the threshold; exclude by InitiatingProcessFileName if identified.
- Cloud sync clients (OneDrive, Dropbox) performing initial sync of large libraries may trigger; exclude by InitiatingProcessFileName.
- Automated test frameworks generating large file sets on developer endpoints.

**Tuning notes:**
- Adjust encryptionThreshold based on a 30-day baseline of per-device file event rates during business hours.
- Consider narrowing ActionType to FileRenamed only if backup or sync tools generate excessive FileCreated volume.
- Add InitiatingProcessFileName exclusions for identified backup agents after reviewing initial alert output.
- Extend lookback to 10m if the encryptor operates at a slower pace to avoid missing slower encryption campaigns.

**Risks / caveats:**
- DeviceFileEvents telemetry requires Defender for Endpoint Plan 2 with file activity monitoring enabled; endpoints without this license tier will produce no results.
- The 5-minute lookback window and 100-file threshold are starting points; environments with high-throughput legitimate file operations require baselining before deployment to avoid alert fatigue.
- Rust binaries may not populate InitiatingProcessCommandLine richly; SHA256 is the primary binary identifier for these cases.
- The excluded path list covers common system directories but may need expansion for environment-specific application directories that generate high file volumes legitimately.

### Triage Runbook

**First 15 minutes:**
- Check whether FileCount is sustained across multiple 5-minute windows or isolated to a single burst.
- Review InitiatingProcessFileName, InitiatingProcessSHA256, and InitiatingProcessCommandLine for ransomware-like behavior such as random-looking names, no signed publisher, or execution from user-writable paths.
- Inspect SampleFolderPaths and SampleExtensions for broad user-data impact rather than a single application or installer directory.
- Look for concurrent signs of user impact such as inaccessible files, ransom notes, or unusual CPU/disk activity on the host.
- Determine whether the same process hash or device is appearing in other ransomware or exfiltration alerts.

**Evidence to collect:**
- InitiatingProcessFileName, InitiatingProcessSHA256, and full command line from the alert.
- SampleFolderPaths and SampleExtensions to confirm breadth of encryption activity.
- Device timeline around WindowStart for process creation, file renames, and any archive or staging activity.
- Any ransom note filenames, extension changes, or user reports of inaccessible files.
- Related alerts or incidents involving the same DeviceId or process hash.

**Pivot points:**
- DeviceFileEvents for the same DeviceId and InitiatingProcessSHA256 over the prior 24 hours.
- DeviceProcessEvents for the encryptor parent process and any child processes spawned near WindowStart.
- DeviceNetworkEvents for the same DeviceId to check for outbound transfer or C2 activity.
- Advanced hunting across other hosts for the same InitiatingProcessSHA256.
- Incident timeline and related alerts in Defender XDR for the same host or hash.

**Benign explanations:**
- Backup, snapshot, or file versioning tools can generate high file-modification volume.
- Cloud sync clients can create large bursts of file changes during initial sync or resync.
- Developer or test systems may legitimately generate many file operations in a short window.

**Escalation criteria:**
- The process is unsigned, unknown, or running from a user profile, temp, or downloads path.
- File activity spans many user data directories and multiple extensions, especially with rename-heavy behavior.
- There are concurrent exfiltration, ransom note, or lateral movement indicators.
- The same hash or process appears on multiple endpoints.
- The user reports file corruption or inability to open files.

**Containment actions:**
- Isolate the host from the network if encryption is ongoing or user data is actively being impacted.
- Terminate the suspicious process only if you have confirmed it is not a legitimate backup or sync agent.
- Preserve the binary and relevant files for forensic collection before rebooting or cleaning.
- Block the process hash and any confirmed related executables across the environment.

**Closure criteria:**
- Confirmed backup, sync, or test activity with matching process name, hash, and expected command line.
- File activity is limited to approved directories and aligns with known maintenance windows.
- No additional suspicious process, network, or incident evidence is found after host review.
- An approved allowlist entry is created for the verified benign process and path.

<br/>
---
<br/>

## Detection 2: DeadLock Ransomware - Large Outbound Transfer Concurrent with File Encryption Activity

### Detection Opportunity

Large outbound data transfers from an endpoint exhibiting concurrent file encryption activity, consistent with DeadLock double extortion exfiltration prior to or during ransomware deployment.

### Intelligence Context

- Microsoft Security Blog: DeadLock ransomware: Breaking down a Rust-based encryptor with decentralized recovery infrastructure — [https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/](https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/)
  - Context: DeadLock supports double extortion by exfiltrating data alongside file encryption. The reporting identifies data leak operations as a distinct capability, making correlation of large outbound transfers with encryption-phase file activity a meaningful compound detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1041, T1486
- Products: Not specified
- Platforms: Windows, Rust
- Malware: DeadLock
- Tools: Not specified
- Search tags: DeadLock, Windows, Rust, T1041, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Exfiltration: T1041 Exfiltration Over C2 Channel (medium); Impact: T1486 Data Encrypted for Impact (high)

### Deployment Gates

- If BytesSent is not populated in the environment, this query returns no results; confirm field population before scheduling.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let correlationWindow = 30m;
let fileEncryptionThreshold = 50;
let exfilByteThreshold = 50000000;
let excludedNetworkProcesses = dynamic(["backup.exe", "veeam.exe", "robocopy.exe"]);
let encryptingDevices =
    DeviceFileEvents
    | where Timestamp > ago(correlationWindow)
    | where ActionType in ("FileRenamed", "FileModified", "FileCreated")
    | summarize
        FileEventCount = count(),
        FileWindowStart = min(Timestamp)
        by DeviceId, DeviceName, bin(Timestamp, correlationWindow)
    | where FileEventCount >= fileEncryptionThreshold
    | project DeviceId, DeviceName, FileEventCount, FileWindowStart;
DeviceNetworkEvents
| where Timestamp > ago(correlationWindow)
| where ActionType == "ConnectionSuccess"
| where isnotnull(BytesSent) and BytesSent > 0
| where not(InitiatingProcessFileName in~ (excludedNetworkProcesses))
| summarize
    TotalBytesSent = sum(BytesSent),
    RemoteIPs = make_set(RemoteIP, 5),
    NetworkProcesses = make_set(InitiatingProcessFileName, 5),
    NetworkWindowStart = min(Timestamp)
    by DeviceId, DeviceName, bin(Timestamp, correlationWindow)
| where TotalBytesSent >= exfilByteThreshold
| join kind=inner encryptingDevices on DeviceId
| project
    NetworkWindowStart,
    FileWindowStart,
    DeviceName,
    DeviceId,
    TotalBytesSent,
    RemoteIPs,
    NetworkProcesses,
    FileEventCount
| order by TotalBytesSent desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents performing large uploads concurrent with file versioning operations will match both signals; exclude by InitiatingProcessFileName in the network events subquery.
- Cloud sync clients performing initial library upload while also writing local cache files.
- Patch management tools downloading and staging large update packages while also modifying files.

**Tuning notes:**
- Confirm BytesSent is non-null and non-zero for a sample of outbound connections before deploying.
- Populate excludedNetworkProcesses with process names of backup and sync agents identified in the environment.
- Consider raising fileEncryptionThreshold to 100 to align with the standalone encryption detection if false positive rates are high.
- Adjust exfilByteThreshold based on the 95th percentile of legitimate outbound transfer sizes observed over a 30-day baseline period.

**Risks / caveats:**
- BytesSent in DeviceNetworkEvents is not guaranteed to be populated; it depends on the network driver and OS version. If BytesSent is null or zero for all outbound connections, the exfiltration signal will never fire and the detection will produce no results.
- DeviceNetworkEvents requires Defender for Endpoint Plan 2 with network protection or advanced network monitoring enabled.
- If BytesSent is not populated in the environment, this query returns no results; confirm field population before scheduling.
- The 50 MB threshold requires baselining against backup and cloud sync tool transfer sizes in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm that TotalBytesSent is materially above normal for the host and that the transfer overlaps the file-encryption window.
- Review RemoteIPs and NetworkProcesses to identify the destination and initiating process.
- Check whether the same device also triggered the standalone encryption detection or other suspicious file activity.
- Assess whether the outbound traffic is to cloud storage, backup infrastructure, or an unknown external IP.
- Look for signs of staging such as archive creation, compression tools, or large file reads before the transfer.

**Evidence to collect:**
- TotalBytesSent, RemoteIPs, NetworkProcesses, FileEventCount, FileWindowStart, and NetworkWindowStart from the alert.
- InitiatingProcessFileName, SHA256, and command line for the network process.
- DeviceNetworkEvents around the alert window for repeated connections to the same destination.
- DeviceFileEvents showing file rename, modify, or create bursts before the transfer.
- Any user reports of slow performance, file corruption, or ransom notes.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and RemoteIP over the prior 24 hours.
- DeviceFileEvents for the same DeviceId and InitiatingProcessSHA256 to confirm encryption behavior.
- DeviceProcessEvents for archive, compression, or staging utilities launched near the alert time.
- Incident and alert history for the same host, process hash, or destination IP.
- If available, proxy or firewall logs for the same RemoteIP and time window.

**Benign explanations:**
- Backup agents can upload large volumes while also modifying files locally.
- Cloud sync clients may upload initial libraries while creating local cache or metadata files.
- Patch or software deployment tools can stage and transfer large packages while updating files.

**Escalation criteria:**
- The destination IP is unknown, external, or associated with suspicious infrastructure.
- The same host is also showing active encryption, ransom notes, or other ransomware indicators.
- The initiating process is not a known backup, sync, or deployment tool.
- Multiple hosts show the same process hash or destination pattern.
- BytesSent is large enough to indicate potential data theft and the activity is ongoing.

**Containment actions:**
- Isolate the host if exfiltration is active and the process is not a known business tool.
- Block the destination IP or domain if confirmed malicious and not shared infrastructure.
- Stop the suspicious process only after preserving evidence and confirming it is not a sanctioned transfer tool.
- Escalate to incident response for possible data breach handling if sensitive data may have left the environment.

**Closure criteria:**
- The transfer is attributable to a known backup, sync, or deployment process with expected destination and timing.
- No concurrent malicious encryption or other compromise indicators are present.
- The destination and process are validated as sanctioned by the business owner.
- A tuning exclusion is documented for the verified benign process or destination.

<br/>
---
<br/>

## Detection 3: CAV3RN - Non-Browser Process Connecting to Google Apps Script C2 Relay

### Detection Opportunity

Non-browser processes making outbound HTTPS connections to script.google.com, consistent with Project CAV3RN's use of Google Apps Script as a C2 relay to blend malicious traffic with legitimate Google services.

### Intelligence Context

- Securelist: Project CAV3RN continues: Google Apps Script as C2 relay and DNS-based C2 channel selection — [https://securelist.com/project-cav3rn-continues/120991/](https://securelist.com/project-cav3rn-continues/120991/)
  - Context: Project CAV3RN uses Google Apps Script endpoints as C2 relays, deliberately blending malicious command traffic with legitimate Google service traffic. Detection relies on identifying non-browser processes initiating connections to script.google.com, which is anomalous in enterprise environments.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.004
- Products: Google Apps Script, Google Workspace
- Platforms: Windows, Google Workspace, DNS
- Malware: Not specified
- Tools: Not specified
- Search tags: Google Apps Script, Google Workspace, Windows, DNS, T1071, T1071.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let knownBrowsers = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "safari.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 443
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_cs "script.google.com"
| where not(InitiatingProcessFileName in~ (knownBrowsers))
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    CommandLines = make_set(InitiatingProcessCommandLine, 5),
    RemoteUrls = make_set(RemoteUrl, 5),
    InitiatingProcessSHA256 = any(InitiatingProcessSHA256),
    InitiatingProcessParentFileName = any(InitiatingProcessParentFileName)
    by DeviceId, DeviceName, InitiatingProcessFileName
| where ConnectionCount >= 3
| extend ConnectionSpanMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    InitiatingProcessSHA256,
    InitiatingProcessParentFileName,
    ConnectionCount,
    ConnectionSpanMinutes,
    FirstSeen,
    LastSeen,
    CommandLines,
    RemoteUrls
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Google Drive for Desktop or Google Workspace sync clients may connect to script.google.com from non-browser processes; identify and exclude by InitiatingProcessFileName after initial review.
- Enterprise automation tools or RPA platforms that invoke Google Apps Script APIs programmatically.
- Developer tooling or CI/CD agents that call Google Apps Script endpoints as part of build pipelines.

**Tuning notes:**
- Run the query over 7 days and review all unique InitiatingProcessFileName values before adding exclusions.
- Add InitiatingProcessParentFileName filter to prioritize results where the parent is a document reader, script interpreter, or Office application.
- Reduce lookback to 1d and lower ConnectionCount threshold to 2 if promoting to a scheduled rule with analyst triage workflow.
- Consider adding InitiatingProcessSHA256 to a watchlist for follow-on enrichment against threat intelligence.

**Risks / caveats:**
- RemoteUrl may not be populated for all outbound connections in DeviceNetworkEvents; connections resolved to IP before the event is logged will not match the has 'script.google.com' filter, producing incomplete coverage.
- RemoteUrl field population is not guaranteed; connections where DNS resolution occurs before event logging may appear as IP-only and will not match the script.google.com filter.
- The 7-day lookback window means this query is suited for scheduled hunting runs rather than near-real-time alerting; reduce to 1d if scheduling as a daily hunt.
- The knownBrowsers list must be maintained to reflect the actual browser inventory in the environment; unlisted browsers will generate false positives.

### Triage Runbook

**First 15 minutes:**
- Review InitiatingProcessFileName, ParentFileName, and CommandLines to determine whether the process is a browser, automation tool, or unusual binary.
- Check whether the process is repeatedly connecting to script.google.com over time rather than making a single legitimate request.
- Inspect the initiating process hash for reputation, signer, and prevalence in the environment.
- Determine whether the parent process is Office, script interpreter, archive utility, or another suspicious launcher.
- Look for related DNS, proxy, or network alerts from the same host around FirstSeen and LastSeen.

**Evidence to collect:**
- InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessParentFileName, and command lines from the alert.
- ConnectionCount, ConnectionSpanMinutes, FirstSeen, LastSeen, and RemoteUrls.
- DeviceNetworkEvents for the same host to identify other Google or suspicious destinations.
- DeviceProcessEvents for the parent-child chain leading to the network activity.
- Any user or admin context explaining why the process should contact Google Apps Script.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and InitiatingProcessSHA256 over 7 days.
- DeviceProcessEvents for the same process hash and parent process chain.
- DeviceFileEvents if the process is associated with a downloaded or dropped binary.
- Proxy or secure web gateway logs for script.google.com access from the same host.
- Threat intelligence or reputation checks for the process hash.

**Benign explanations:**
- Google Workspace automation or RPA tools may legitimately call Apps Script endpoints.
- Developer tooling or CI/CD agents may use Google APIs as part of build workflows.
- Google Drive or sync-related utilities may generate non-browser traffic in some environments.

**Escalation criteria:**
- The process is unsigned, rare, or launched from a user-writable location.
- The parent process is Office, a script host, or another suspicious application.
- Connections are periodic or beacon-like and not explainable by approved automation.
- The same hash or behavior appears on multiple hosts.
- There is any accompanying credential, document, or persistence activity.

**Containment actions:**
- Isolate the host if the process is unknown and beaconing persists.
- Block the process hash if confirmed malicious and not required for business use.
- Disable or suspend the user account if the activity appears tied to a compromised identity and policy allows it.
- Preserve the binary and command line before removal.

**Closure criteria:**
- The process is confirmed as an approved automation or Google Workspace component.
- The parent chain and command line match documented business use.
- No additional suspicious network destinations or process behaviors are found.
- A documented allowlist or exception is created for the verified process.

<br/>
---
<br/>

## Detection 4: CAV3RN - High-Frequency DNS Queries Preceding C2 Channel Establishment

### Detection Opportunity

Processes issuing high-frequency or sequenced DNS queries to multiple distinct domains shortly before establishing outbound connections, consistent with Project CAV3RN's DNS-based C2 channel selection mechanism.

### Intelligence Context

- Securelist: Project CAV3RN continues: Google Apps Script as C2 relay and DNS-based C2 channel selection — [https://securelist.com/project-cav3rn-continues/120991/](https://securelist.com/project-cav3rn-continues/120991/)
  - Context: Project CAV3RN uses DNS-based routing to select its active C2 channel. This produces a pattern of sequenced DNS queries to multiple domains from the same process before a C2 connection is established, distinguishable from normal browsing by the non-browser process context and query density.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.004
- Products: Google Apps Script, Google Workspace
- Platforms: Windows, Google Workspace, DNS
- Malware: Not specified
- Tools: Not specified
- Search tags: Google Apps Script, Google Workspace, Windows, DNS, T1071, T1071.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (high)

### Deployment Gates

- RemoteUrl is typically not populated for UDP port 53 events in DeviceNetworkEvents; DistinctDomains counting via dcount(RemoteUrl) will likely count distinct IPs or empty strings rather than domain names, making the threshold meaningless.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let knownBrowsers = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "safari.exe"]);
let dnsWindow = 2m;
let dnsQueryThreshold = 10;
let dnsEvents =
    DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where RemotePort == 53
    | where not(InitiatingProcessFileName in~ (knownBrowsers))
    | summarize
        DnsQueryCount = count(),
        DistinctDomains = dcountif(RemoteUrl, isnotnull(RemoteUrl) and RemoteUrl != ""),
        DistinctDnsIPs = dcount(RemoteIP),
        DomainList = make_set(RemoteUrl, 20),
        WindowStart = min(Timestamp),
        InitiatingProcessSHA256 = any(InitiatingProcessSHA256)
        by DeviceId, DeviceName, InitiatingProcessFileName, bin(Timestamp, dnsWindow)
    | where DistinctDomains >= dnsQueryThreshold or DistinctDnsIPs >= dnsQueryThreshold;
let followOnConnections =
    DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where RemotePort == 443
    | where ActionType == "ConnectionSuccess"
    | where not(InitiatingProcessFileName in~ (knownBrowsers))
    | project DeviceId, InitiatingProcessFileName, ConnectTimestamp = Timestamp, RemoteIP, RemoteUrl
    | take 500000;
dnsEvents
| join kind=inner followOnConnections on DeviceId, InitiatingProcessFileName
| where ConnectTimestamp between (WindowStart .. (WindowStart + dnsWindow + 5m))
| summarize
    ConnectionCount = count(),
    SampleRemoteIPs = make_set(RemoteIP, 5),
    SampleRemoteUrls = make_set(RemoteUrl, 5)
    by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessSHA256, DnsQueryCount, DistinctDomains, DistinctDnsIPs, DomainList, WindowStart
| project
    WindowStart,
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    InitiatingProcessSHA256,
    DnsQueryCount,
    DistinctDomains,
    DistinctDnsIPs,
    DomainList,
    ConnectionCount,
    SampleRemoteIPs,
    SampleRemoteUrls
| order by DnsQueryCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software updaters or telemetry agents that perform CDN endpoint discovery via multiple DNS lookups before connecting.
- Security tools performing domain reputation checks via direct DNS socket calls.
- Any process using a custom DNS resolver library that bypasses the OS stub resolver.

**Tuning notes:**
- Before relying on this query, run DeviceNetworkEvents → where RemotePort == 53 → summarize count() by InitiatingProcessFileName to confirm port 53 events are present and attributed to non-svchost processes in the environment.
- If port 53 events are absent, consider pivoting to DNS query logs from a network-level DNS sensor or Microsoft Defender for DNS if available.
- Increase dnsQueryThreshold if legitimate software updaters generate high DNS burst counts from non-browser processes.
- Reduce the 1-day lookback to 6h if scheduling as a recurring hunt to reduce query cost.

**Risks / caveats:**
- Port 53 outbound connections in DeviceNetworkEvents represent raw DNS socket calls by the process, not OS-level DNS resolution. Most processes use the OS resolver (svchost.exe/dnscache) and will not appear as port 53 initiators; this means the DNS query signal will be absent for the majority of malware that uses standard Windows DNS APIs.
- RemoteUrl is typically not populated for UDP port 53 events in DeviceNetworkEvents; DistinctDomains counting via dcount(RemoteUrl) will likely count distinct IPs or empty strings rather than domain names, making the threshold meaningless.
- The temporal join between dnsEvents and followOnConnections uses a between() range on ConnectTimestamp relative to WindowStart; this pattern can produce a large cross-product if many connections occur in the follow-on window, requiring a row-count guard.
- The fundamental telemetry dependency on port 53 events in DeviceNetworkEvents representing per-process DNS calls must be validated before this query is relied upon; most environments will see very few or no such events for standard Windows processes.

### Triage Runbook

**First 15 minutes:**
- Review DnsQueryCount, DistinctDomains, DistinctDnsIPs, and DomainList to see whether the pattern is unusually broad or sequential.
- Check the initiating process name, hash, and parent process for suspicious launch context.
- Determine whether the same process establishes outbound connections shortly after the DNS burst.
- Look for signs of custom DNS usage, raw socket behavior, or a non-browser application making many lookups.
- Assess whether the host is a developer machine, updater host, or security tool that may legitimately generate DNS bursts.

**Evidence to collect:**
- InitiatingProcessFileName, InitiatingProcessSHA256, and command line from the alert.
- DnsQueryCount, DistinctDomains, DistinctDnsIPs, DomainList, and WindowStart.
- ConnectTimestamp, RemoteIP, and RemoteUrl from follow-on connections.
- DeviceProcessEvents for the parent-child chain and process start time.
- Any related network or proxy events from the same host during the same time window.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and InitiatingProcessSHA256 over the prior 24 hours.
- DeviceProcessEvents for the same process and parent chain.
- DNS or network sensor logs if DeviceNetworkEvents port 53 visibility is incomplete.
- DeviceNetworkEvents for subsequent 443 connections from the same process.
- Incident history for the same host or hash.

**Benign explanations:**
- Software updaters may query many domains before connecting to a CDN or service endpoint.
- Security tools may perform reputation or discovery lookups in bursts.
- Custom resolver libraries or enterprise agents may generate high DNS activity without malicious intent.

**Escalation criteria:**
- The process is unknown, unsigned, or launched from a suspicious parent.
- DNS bursts are followed by outbound connections to unusual or external infrastructure.
- The same behavior repeats periodically and resembles beaconing.
- The host also shows other compromise indicators such as credential theft, persistence, or lateral movement.
- The process hash is rare or has poor reputation.

**Containment actions:**
- Isolate the host if the DNS burst is clearly tied to malicious follow-on traffic.
- Block the process hash if confirmed malicious and not business-critical.
- Coordinate with network teams to block confirmed malicious domains or destinations.
- Preserve process and network evidence before remediation.

**Closure criteria:**
- The DNS burst is attributable to a known updater, security tool, or approved enterprise agent.
- Follow-on connections are benign and match documented behavior.
- No suspicious parent chain, hash, or secondary compromise indicators are present.
- An allowlist or tuning exception is documented for the verified process.

<br/>
---
<br/>

## Detection 5: Kimwolf Botnet - Non-Browser Process Connecting to Tor Guard Nodes or Characteristic Tor Ports

### Detection Opportunity

Non-browser processes making outbound connections to known Tor guard node IPs or on ports 9001 or 9050, consistent with Kimwolf v7's use of Tor as a backup C2 routing mechanism.

### Intelligence Context

- Unit 42: Kimwolf v7: An Evolution of the Kimwolf Botnet — [https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/](https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/)
  - Context: Kimwolf v7 uses Tor as a backup routing mechanism for C2 communications. In enterprise Windows environments, outbound connections to Tor guard node IPs or on Tor characteristic ports from non-browser processes are a high-confidence signal of malicious activity given the low prevalence of sanctioned Tor use.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090, T1090.003
- Products: Not specified
- Platforms: Android, IoT, DNS, Tor, Ethereum
- Malware: Kimwolf
- Tools: Not specified
- Search tags: Kimwolf, Android, IoT, DNS, Tor, Ethereum, T1090, T1090.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.003 Multi-hop Proxy (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let knownBrowsers = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "safari.exe"]);
let torPorts = dynamic([9001, 9050, 9150]);
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (torPorts) or (isnotnull(RemoteUrl) and RemoteUrl has ".onion")
| where not(InitiatingProcessFileName in~ (knownBrowsers))
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    RemotePorts = make_set(RemotePort, 5),
    RemoteIPs = make_set(RemoteIP, 10),
    RemoteUrls = make_set(RemoteUrl, 5),
    InitiatingProcessCommandLine = any(InitiatingProcessCommandLine),
    InitiatingProcessSHA256 = any(InitiatingProcessSHA256),
    InitiatingProcessParentFileName = any(InitiatingProcessParentFileName)
    by DeviceId, DeviceName, InitiatingProcessFileName
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    InitiatingProcessSHA256,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ConnectionCount,
    RemotePorts,
    RemoteIPs,
    RemoteUrls
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Tor Browser installed by users in environments without application control; tor.exe will appear as the initiating process and is intentionally surfaced.
- Security research tools or penetration testing frameworks that use Tor for anonymization.
- Privacy-focused VPN clients that route through Tor exit nodes on port 9050.

**Tuning notes:**
- Integrate a Tor guard node IP watchlist into the RemoteIP filter to catch Tor traffic on non-standard ports: add '| where RemoteIP in (TorGuardNodeWatchlist)' as an additional OR condition.
- If Tor Browser is sanctioned in the environment, add the specific process name and SHA256 of the approved binary to an exclusion list rather than broadly excluding tor.exe.
- Review InitiatingProcessParentFileName in alert output to prioritize cases where the parent is a document reader, Office application, or script interpreter.
- Consider reducing lookback to 6h and scheduling every 6 hours to reduce query cost while maintaining near-real-time coverage.

**Risks / caveats:**
- DeviceNetworkEvents requires Defender for Endpoint Plan 2 with network protection enabled; endpoints without this configuration will not surface outbound connection events.
- RemoteUrl may not be populated for all connection types; the .onion domain filter relies on RemoteUrl being present, so Tor connections where only RemoteIP is logged will only be caught by the port-based filter.
- Port-based detection does not catch Tor traffic tunneled over non-standard ports or wrapped in TLS on port 443; a Tor guard node IP watchlist would be required to extend coverage.
- The .onion domain filter depends on RemoteUrl being populated; connections where only RemoteIP is logged will only be caught by the port filter.

### Triage Runbook

**First 15 minutes:**
- Review the initiating process name, hash, command line, and parent process to determine whether Tor usage is expected.
- Check whether the destination is a Tor port, a .onion URL, or a known Tor guard-node IP.
- Assess whether the host is a workstation, server, or user device where Tor use would be unusual.
- Look for repeated connections or multiple Tor-related destinations from the same process.
- Search for other signs of botnet activity such as persistence, suspicious downloads, or outbound connections to additional C2 infrastructure.

**Evidence to collect:**
- InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessCommandLine, and InitiatingProcessParentFileName.
- ConnectionCount, FirstSeen, LastSeen, RemotePorts, RemoteIPs, and RemoteUrls.
- DeviceNetworkEvents for the same host to identify other proxy or C2 traffic.
- DeviceProcessEvents for process creation and any child processes.
- User or asset owner confirmation of sanctioned Tor use, if any.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and process hash over 24 hours.
- DeviceProcessEvents for the same process and parent chain.
- Threat intelligence or reputation checks for the process hash and remote IPs.
- Proxy, firewall, or secure web gateway logs for Tor-related traffic.
- Incident history for the same host or user.

**Benign explanations:**
- Tor Browser may be intentionally installed for privacy or research use.
- Security researchers or penetration testers may use Tor for anonymization.
- Some VPN or privacy tools may route through Tor-related infrastructure in controlled environments.

**Escalation criteria:**
- Tor use is not sanctioned on the host or in the business unit.
- The process is not Tor Browser and is making Tor-port or .onion connections.
- The process is rare, unsigned, or launched from a suspicious parent.
- There are additional botnet, persistence, or credential theft indicators.
- Multiple hosts show the same process hash or Tor-related behavior.

**Containment actions:**
- Isolate the host if Tor use is unsanctioned and the process is suspicious.
- Block the process hash and associated destinations if confirmed malicious.
- Remove or disable the unauthorized Tor client if policy allows and evidence is preserved.
- Escalate to incident response if the host may be part of a botnet or proxy chain.

**Closure criteria:**
- Tor use is confirmed as sanctioned and tied to an approved process and hash.
- The destination ports and URLs match documented legitimate use.
- No additional malicious activity or suspicious parent chain is present.
- An approved exception or allowlist entry is recorded for the verified software.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- DeadLock Ransomware - Mass File Encryption by Rust Binary: Defender for Endpoint file-event coverage must be confirmed on the target host population.
- CAV3RN - High-Frequency DNS Queries Preceding C2 Channel Establishment: RemoteUrl is typically not populated for UDP port 53 events in DeviceNetworkEvents; DistinctDomains counting via dcount(RemoteUrl) will likely count distinct IPs or empty strings rather than domain names, making the threshold meaningless.

**Schema / correlation keys:**
- DeadLock Ransomware - Large Outbound Transfer Concurrent with File Encryption Activity: If BytesSent is not populated in the environment, this query returns no results; confirm field population before scheduling.
- CAV3RN - Non-Browser Process Connecting to Google Apps Script C2 Relay: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceFileEvents: shared by DeadLock Ransomware - Mass File Encryption by Rust Binary; DeadLock Ransomware - Large Outbound Transfer Concurrent with File Encryption Activity
- DeviceNetworkEvents: shared by DeadLock Ransomware - Large Outbound Transfer Concurrent with File Encryption Activity; CAV3RN - Non-Browser Process Connecting to Google Apps Script C2 Relay; CAV3RN - High-Frequency DNS Queries Preceding C2 Channel Establishment; Kimwolf Botnet - Non-Browser Process Connecting to Tor Guard Nodes or Characteristic Tor Ports

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: DeadLock Ransomware - Mass File Encryption by Rust Binary; Kimwolf Botnet - Non-Browser Process Connecting to Tor Guard Nodes or Characteristic Tor Ports.
2. Resolve environment-mapping detections next: DeadLock Ransomware - Large Outbound Transfer Concurrent with File Encryption Activity; CAV3RN - High-Frequency DNS Queries Preceding C2 Channel Establishment.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: CAV3RN - Non-Browser Process Connecting to Google Apps Script C2 Relay.

### Hunting Agenda and Promotion Criteria

- CAV3RN - Non-Browser Process Connecting to Google Apps Script C2 Relay: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- DeadLock Ransomware - Large Outbound Transfer Concurrent with File Encryption Activity: If BytesSent is not populated in the environment, this query returns no results; confirm field population before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- CAV3RN - High-Frequency DNS Queries Preceding C2 Channel Establishment: RemoteUrl is typically not populated for UDP port 53 events in DeviceNetworkEvents; DistinctDomains counting via dcount(RemoteUrl) will likely count distinct IPs or empty strings rather than domain names, making the threshold meaningless.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
