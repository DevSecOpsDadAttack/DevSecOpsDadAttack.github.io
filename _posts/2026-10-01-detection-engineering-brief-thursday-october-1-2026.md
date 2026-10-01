---
layout: post
title: "Detection Engineering Brief - Thursday, October 1, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-01
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-73570
  - T1190
  - T1059
  - Zimbra
  - mail servers
  - MSP360
  - ScreenConnect
  - Windows
  - CVE-2026-76504
  - Cisco Catalyst SD-WAN Manager
  - CVE-2026-88771
  - CVE-2026-88772
  - NetScaler
  - T1219
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-73570, T1190, T1059, Zimbra, mail servers, MSP360, ScreenConnect, Windows, CVE-2026-76504, Cisco Catalyst SD-WAN Manager, CVE-2026-88771, CVE-2026-88772, NetScaler, T1219.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: RMM Abuse - ScreenConnect Spawned or Co-Executed with MSP360 for Redundant Remote Access; Zimbra Exploitation - Anomalous POST to Mail Server from External IP with Successful Response (CVE-2026-73570); Cisco SD-WAN Manager - Unauthenticated External Access to Admin API Endpoints (CVE-2026-76504); NetScaler Zero-Day - Inbound Exploitation Attempt Followed by Anomalous Process Activity (CVE-2026-88771, CVE-2026-88772).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Zimbra Command Injection - Shell Spawned from Web Service Process (CVE-2026-73570)

### Detection Opportunity

Shell interpreter spawned by Zimbra web service process following unauthenticated inbound HTTP request, indicating command injection exploitation.

### Intelligence Context

- Microsoft Security Blog: Unauthenticated command injection on internet-facing mail servers: tracking CVE-2026-73570 — [https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/](https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/)
  - Context: Microsoft Threat Intelligence observed unauthenticated command injection against internet-facing Zimbra mail servers via CVE-2026-73570, where exploitation produces shell interpreter child processes spawned from Zimbra web service processes.

### Search Metadata

- CVEs: CVE-2026-73570
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Zimbra, mail servers
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-73570, T1190, T1059, Zimbra, mail servers

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName has_any ("java", "jetty", "zimbra", "zmmailboxd", "zmconfigd", "zmlmtpserver")
| where FileName in~ ("bash", "sh", "dash", "python", "python3", "perl", "ruby", "wget", "curl", "nc", "ncat", "netcat")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Zimbra health-check or maintenance scripts that legitimately invoke shell interpreters from Java-based service processes.
- Authorized administrative automation running under Zimbra service accounts that calls wget or curl for package updates.

**Tuning notes:**
- Restrict InitiatingProcessFileName list to exact process names observed in your Zimbra deployment to reduce substring false positives.
- Consider adding an AccountName filter to scope detections to the Zimbra service account (e.g., 'zimbra') if the service runs under a dedicated OS account.
- Add FolderPath exclusions for known-legitimate shell invocations (e.g., /opt/zimbra/bin/) if Zimbra's own scripts routinely call shell utilities.

**Risks / caveats:**
- Microsoft Defender for Endpoint Linux agent must be deployed on Zimbra host devices; if MDE Linux is not licensed or deployed, DeviceProcessEvents will contain no records for these hosts.
- The 24-hour lookback window may miss detections if scheduled rule execution is delayed; adjust to match rule run frequency.
- Legitimate Zimbra maintenance tasks may generate matches; allowlist known-good InitiatingProcessFileName + FileName + AccountName combinations after baselining.
- has_any on InitiatingProcessFileName uses substring matching; a process named 'javaagent' would match 'java'. Monitor for such collisions in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process is a Zimbra web service component and verify the child process is a real shell or utility binary, not a benign wrapper or script under /opt/zimbra/bin.
- Check the exact command line for injected shell metacharacters, unexpected arguments, downloads, reverse shell indicators, or commands that touch sensitive paths such as /tmp, /var/tmp, /etc, or Zimbra config directories.
- Review the account context and folder path to see whether the process ran under the Zimbra service account and whether the binary location is expected for the host.
- Look for nearby process activity from the same parent, especially curl, wget, python, perl, nc, or outbound connection attempts that would suggest post-exploitation.
- Correlate the timestamp with inbound web access logs or proxy logs for the same host to confirm an unauthenticated request preceded the process spawn.

**Evidence to collect:**
- DeviceProcessEvents for the parent and child process chain, including InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, and AccountName.
- Web access or reverse proxy logs for the Zimbra host around the alert time, including source IP, URL path, HTTP method, and response code.
- Any outbound network connections from the host within minutes of the alert, especially to uncommon external IPs or ports.
- Host indicators of compromise such as new files in temporary directories, modified Zimbra scripts, or unexpected cron entries.
- Patch level and exposure status for the Zimbra server, including whether CVE-2026-73570 mitigation or vendor guidance has been applied.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and a wider time window to find additional child processes from the Zimbra parent.
- DeviceNetworkEvents or equivalent network telemetry to identify outbound connections from the Zimbra host after the shell spawn.
- Web server, reverse proxy, or WAF logs to pivot on the source IP and request path that preceded the process activity.
- File events or EDR telemetry on the Zimbra host to look for dropped scripts, modified binaries, or persistence artifacts.

**Benign explanations:**
- Planned Zimbra maintenance or health-check scripts may legitimately spawn bash or sh from Java-based service processes.
- Authorized administrative automation under the Zimbra service account may invoke shell utilities for updates or backups.
- A non-malicious script or wrapper with a similar name may have been launched from an expected Zimbra path.

**Escalation criteria:**
- The shell command line contains attacker-like content such as command chaining, encoded payloads, download-and-execute behavior, or reverse shell indicators.
- There is evidence of outbound connections, file creation, or persistence activity following the shell spawn.
- The parent-child chain is not consistent with known-good Zimbra maintenance behavior or occurs outside approved maintenance windows.
- The same source IP or request pattern appears across multiple Zimbra hosts or repeated attempts are observed.

**Containment actions:**
- Isolate the Zimbra host from the network if command injection appears successful or if follow-on activity is confirmed.
- Block the source IPs observed in the web logs if they are clearly malicious and not shared infrastructure.
- Disable or restrict external access to the affected Zimbra management or web interface until the host is validated and patched.
- Preserve volatile evidence before rebooting or rebuilding the server.

**Closure criteria:**
- The process chain is confirmed as a documented, benign Zimbra maintenance action with matching command line and approved account context.
- No suspicious outbound connections, file changes, or persistence artifacts are found after review.
- The host is patched or otherwise mitigated for CVE-2026-73570 and the activity is attributed to approved administration.
- Any suspicious source IPs or request paths have been documented for future allowlisting or blocking decisions.

<br/>
---
<br/>

## Detection 2: RMM Abuse - ScreenConnect Spawned or Co-Executed with MSP360 for Redundant Remote Access

### Detection Opportunity

ScreenConnect deployed by or alongside MSP360 on the same host within a short time window, establishing redundant remote-access channels consistent with phishing-delivered RMM abuse.

### Intelligence Context

- Microsoft Security Blog: Phishing Abuses RMM Tools for Persistent Access — [https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
  - Context: Microsoft observed phishing campaigns abusing MSP360 RMM to deploy ScreenConnect, creating redundant remote-access channels for follow-on attacker activity. The chained deployment of two RMM tools on the same host is the key behavioral indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1219
- Products: MSP360, ScreenConnect
- Platforms: Windows
- Malware: Not specified
- Tools: MSP360, ScreenConnect
- Search tags: MSP360, ScreenConnect, Windows, T1219

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: medium
- MITRE ATT&CK: Persistence: T1219 Remote Access Software (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookbackWindow = 24h;
let correlationWindowSec = 1800;
let msp360Events = DeviceProcessEvents
| where Timestamp > ago(lookbackWindow)
| where FileName in~ ("MSP360.exe", "CloudBerry.exe", "MBS.exe", "OnlineBackup.exe")
    or ProcessCommandLine has_any ("msp360", "cloudberry")
| summarize
    msp360Time = min(Timestamp),
    msp360Process = take_any(FileName),
    msp360Cmdline = take_any(ProcessCommandLine),
    msp360InitiatingProcess = take_any(InitiatingProcessFileName),
    msp360FolderPath = take_any(FolderPath)
    by DeviceName;
let scEvents = DeviceProcessEvents
| where Timestamp > ago(lookbackWindow)
| where FileName in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ConnectWiseControl.exe")
    or ProcessCommandLine has "screenconnect"
| summarize
    scTime = min(Timestamp),
    scProcess = take_any(FileName),
    scCmdline = take_any(ProcessCommandLine),
    scInitiatingProcess = take_any(InitiatingProcessFileName),
    scFolderPath = take_any(FolderPath)
    by DeviceName;
msp360Events
| join kind=inner scEvents on DeviceName
| extend TimeDeltaSeconds = abs(datetime_diff('second', msp360Time, scTime))
| where TimeDeltaSeconds <= correlationWindowSec
| project
    DeviceName,
    msp360Time,
    msp360Process,
    msp360InitiatingProcess,
    msp360FolderPath,
    msp360Cmdline,
    scTime,
    scProcess,
    scInitiatingProcess,
    scFolderPath,
    scCmdline,
    TimeDeltaSeconds
| order by TimeDeltaSeconds asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Managed service provider endpoints where both MSP360 and ScreenConnect are standard tooling.
- IT helpdesk scenarios where ScreenConnect is used for remote support alongside MSP360 for backup management.

**Tuning notes:**
- Add a DeviceName exclusion list for endpoints where both tools are approved and expected before promoting to a scheduled alert.
- Consider adding a filter on InitiatingProcessFileName to flag only cases where either tool was launched by a suspicious parent (e.g., winword.exe, powershell.exe, mshta.exe) to increase precision.
- Adjust correlationWindowSec based on observed attacker dwell time in your environment; 1800 seconds (30 minutes) is a starting point.

**Risks / caveats:**
- Both tools are legitimate RMM products; without an exclusion list of approved dual-RMM hosts, alert volume will be high in MSP-managed environments.
- The 30-minute correlation window is arbitrary; attacker deployment sequences may span longer periods, and legitimate co-deployment may occur within the same window.
- Summarizing by first-seen event per device may miss cases where the tools are installed hours apart within the 24-hour lookback; consider expanding the correlation window for hunting.
- Process name lists are based on known installer/client binary names and may not cover all MSP360 or ScreenConnect deployment variants.

### Triage Runbook

**First 15 minutes:**
- Confirm whether the host is managed by IT or an MSP that legitimately uses both MSP360 and ScreenConnect.
- Check the installation paths, parent processes, and command lines for both tools to see whether they were installed by software deployment, a user, a browser, Office, or a script host.
- Review the timing between the two tool executions and determine whether they were installed or started in close succession from the same user session.
- Identify the logged-on user and account context at the time of execution and compare it to the expected admin or support account.
- Look for evidence of remote sessions, service creation, scheduled tasks, or persistence changes associated with either tool.

**Evidence to collect:**
- DeviceProcessEvents for both MSP360 and ScreenConnect, including FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, DeviceName, and Timestamp.
- Software inventory or installed programs data to confirm whether both tools are approved on the endpoint.
- Service, scheduled task, and autorun telemetry to determine whether either tool was configured for persistence.
- Remote access logs, if available, showing session initiation, operator identity, and source IPs.
- User and device ownership context to determine whether the endpoint belongs to IT, an MSP, or a standard business user.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to find the first-seen installation or launch of each RMM tool.
- DeviceFileEvents or equivalent to look for installer artifacts, dropped binaries, or modified service files.
- DeviceRegistryEvents or scheduled task telemetry to identify persistence mechanisms tied to the RMM tools.
- Identity and sign-in logs to see whether the user account associated with the install or launch is expected.

**Benign explanations:**
- The endpoint is a managed device where both MSP360 and ScreenConnect are standard support tooling.
- IT helpdesk or MSP staff legitimately used ScreenConnect for remote support while MSP360 handled backup or management.
- A software deployment or imaging process installed both tools during provisioning.

**Escalation criteria:**
- Either tool was launched by an unusual parent such as winword.exe, powershell.exe, mshta.exe, wscript.exe, or a browser process.
- The tools were installed outside of normal IT change windows or on a device that should not have remote support software.
- There is evidence of unauthorized remote sessions, persistence, or lateral movement after the tools appeared.
- The host is not on the approved dual-RMM allowlist and the installation path or command line is inconsistent with standard deployment.

**Containment actions:**
- If unauthorized remote access is suspected, disable the RMM services or isolate the host from the network after preserving evidence.
- Remove or suspend the unauthorized RMM software only after confirming it is not required for business operations.
- Revoke any associated support credentials or tokens if the tools were installed with attacker-controlled access.
- Notify endpoint management owners before taking action on managed devices to avoid disrupting legitimate support operations.

**Closure criteria:**
- The host is confirmed to be an approved managed endpoint with documented use of both tools.
- The parent processes, install paths, and timing match standard IT deployment or support activity.
- No suspicious persistence, remote sessions, or unauthorized operator activity is found.
- The device is added to an approved exclusion list if dual-RMM use is expected.

<br/>
---
<br/>

## Detection 3: Zimbra Exploitation - Anomalous POST to Mail Server from External IP with Successful Response (CVE-2026-73570)

### Detection Opportunity

Unauthenticated HTTP POST requests from external IPs to internet-facing Zimbra mail server endpoints returning HTTP 200, consistent with exploitation attempts for CVE-2026-73570.

### Intelligence Context

- Microsoft Security Blog: Unauthenticated command injection on internet-facing mail servers: tracking CVE-2026-73570 — [https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/](https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/)
  - Context: Exploitation of CVE-2026-73570 involves unauthenticated HTTP requests to internet-facing Zimbra servers. Network-layer detection of anomalous POST requests returning 200 from external sources provides a supplementary detection layer to process-based signals.

### Search Metadata

- CVEs: CVE-2026-73570
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Zimbra, mail servers
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-73570, T1190, T1059, Zimbra, mail servers

### Relevant IOCs

No explicit IOCs were preserved for this detection.

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
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where RequestMethod == "POST"
| where ResponseCode == 200
| where DestinationPort in (80, 443, 8080, 8443, 7071)
| where not (ipv4_is_private(SourceIP))
| where RequestURL has_any ("/zimbra", "/service", "/mail", "/zimbraAdmin")
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    SampleURLs = make_set(RequestURL, 10),
    SampleUserAgents = make_set(UserAgent, 5),
    DestinationIP = take_any(DestinationIP),
    WindowStart = min(TimeGenerated)
    by SourceIP, DestinationPort, bin(TimeGenerated, 5m)
| where RequestCount > 5
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate webmail clients making authenticated POST requests to /zimbra or /mail paths.
- Security scanners or vulnerability assessment tools targeting Zimbra endpoints from authorized external IPs.

**Tuning notes:**
- Increase RequestCount threshold if legitimate automated clients generate high POST volumes to Zimbra endpoints.
- Add a DestinationIP filter scoped to confirmed Zimbra server IPs in the environment to eliminate false positives from other services on the same ports.
- Substitute the specific vulnerable URL path for CVE-2026-73570 in the RequestURL filter once the exact endpoint is publicly confirmed.

**Risks / caveats:**
- CommonSecurityLog RequestMethod and ResponseCode fields are only populated when the data source (WAF, proxy, or NGFW) is configured to log HTTP application-layer details; many firewall connectors do not populate these fields, which would cause the query to return no results.
- CommonSecurityLog does not natively contain a DestinationHostname field that maps to Zimbra; the query relies on DestinationPort as a proxy for Zimbra traffic, which will match any service on those ports, not specifically Zimbra.
- The RequestCount > 5 threshold within a 5-minute bin is arbitrary; legitimate webmail automation may exceed this threshold, and slow exploitation may fall below it.
- ipv4_is_private() does not handle IPv6 addresses; if SourceIP contains IPv6 values, add a separate IPv6 private-range exclusion.

### Triage Runbook

**First 15 minutes:**
- Validate that the destination IP is a real Zimbra host and confirm whether the request path matches a known Zimbra endpoint or a suspicious vulnerable path.
- Review the source IP reputation, geolocation, and whether the same source is hitting multiple mail servers or multiple paths on the same host.
- Check whether the requests were authenticated or tied to a normal user session, and whether the response codes and timing are consistent with legitimate use.
- Correlate the POSTs with process telemetry on the Zimbra host to see whether a shell or utility process spawned shortly afterward.
- Look for repeated requests, unusual user agents, or bursts of traffic that suggest scanning or exploitation automation.

**Evidence to collect:**
- CommonSecurityLog entries for the source IP, destination IP, request URL, request method, response code, destination port, and user agent.
- Zimbra web, proxy, or WAF logs showing the full request path, headers, and any authentication context.
- DeviceProcessEvents from the Zimbra host around the same time to confirm or refute command execution.
- Any outbound connections or file changes on the Zimbra host after the POST activity.
- Patch and exposure status for the Zimbra server, including whether it is internet-facing and whether CVE-2026-73570 mitigations are in place.

**Pivot points:**
- CommonSecurityLog for the same SourceIP across a wider time window to identify repeated attempts or other targeted hosts.
- DeviceProcessEvents on the Zimbra host to correlate the POST time with shell spawns or utility execution.
- Web proxy or WAF logs to inspect request bodies, headers, and authentication state.
- DNS or network telemetry to see whether the source IP is associated with broader scanning activity.

**Benign explanations:**
- Legitimate webmail clients or automated mail integrations may generate POST requests to Zimbra endpoints.
- Authorized vulnerability scanners or security testing from known external IPs may trigger the rule.
- Normal authenticated user activity may produce successful POSTs to mail-related paths.

**Escalation criteria:**
- The source IP is untrusted and the request path or user agent is consistent with exploitation or scanning.
- The same source IP generates repeated successful POSTs to multiple Zimbra endpoints or multiple hosts.
- A shell spawn, outbound connection, or file modification occurs on the Zimbra host shortly after the POSTs.
- The server is internet-facing and unpatched for CVE-2026-73570.

**Containment actions:**
- Block the malicious source IPs at the perimeter if they are clearly hostile and not part of approved testing.
- Restrict external access to the Zimbra service or vulnerable endpoint until patching and validation are complete.
- If host compromise is suspected, isolate the Zimbra server and preserve logs before remediation.
- Coordinate with messaging administrators before making service-impacting changes.

**Closure criteria:**
- The POSTs are confirmed to be legitimate authenticated traffic or approved scanning activity.
- No correlated host-side execution or post-exploitation activity is found.
- The source IPs and request paths are documented as benign or added to an approved allowlist.
- The Zimbra server is patched or otherwise mitigated and no further suspicious requests are observed.

<br/>
---
<br/>

## Detection 4: Cisco SD-WAN Manager - Unauthenticated External Access to Admin API Endpoints (CVE-2026-76504)

### Detection Opportunity

Inbound HTTP requests from external IPs to Cisco SD-WAN Manager admin API paths returning HTTP 200 without a preceding authentication event, consistent with authentication bypass exploitation of CVE-2026-76504.

### Intelligence Context

- Rapid7: Critical Cisco Catalyst SD-WAN Manager API authentication bypass exploited in the wild (CVE-2026-76504) — [https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504)
  - Context: CVE-2026-76504 allows an unauthenticated remote attacker to send a crafted HTTP request that bypasses an authentication rule for a specific API endpoint, granting admin-level API access. Internet-exposed SD-WAN Manager systems are at risk. Rapid7 confirmed active exploitation in the wild.

### Search Metadata

- CVEs: CVE-2026-76504
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Cisco Catalyst SD-WAN Manager
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-76504, T1190, Cisco Catalyst SD-WAN Manager

### Relevant IOCs

No explicit IOCs were preserved for this detection.

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
let sdwanPorts = dynamic([443, 8443, 8080, 9090]);
let adminPaths = dynamic(["/dataservice", "/api", "/admin", "/j_security_check"]);
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DestinationPort in (sdwanPorts)
| where not (ipv4_is_private(SourceIP))
| where ResponseCode == 200
| where RequestURL has_any (adminPaths)
| summarize
    RequestCount = count(),
    DistinctPaths = dcount(RequestURL),
    SamplePaths = make_set(RequestURL, 20),
    SampleMethods = make_set(RequestMethod, 5),
    SampleUserAgents = make_set(UserAgent, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized remote administrators accessing SD-WAN Manager API from non-RFC1918 addresses.
- Automated network management platforms polling SD-WAN Manager API endpoints from external IPs.

**Tuning notes:**
- Add a DestinationIP filter (e.g., DestinationIP in ("<sdwan-mgr-ip-1>", "<sdwan-mgr-ip-2>")) scoped to confirmed SD-WAN Manager appliance IPs before deploying as a scheduled rule.
- Add known legitimate management source IPs to an exclusion filter to reduce false positives from authorized administrators.
- Narrow adminPaths to the specific vulnerable endpoint path once it is publicly confirmed for CVE-2026-76504.

**Risks / caveats:**
- CommonSecurityLog RequestURL and ResponseCode fields are only populated when the upstream data source logs HTTP application-layer details; Cisco SD-WAN Manager syslog forwarded without a WAF or proxy in the path may not populate these fields.
- Without a DestinationIP filter scoped to the SD-WAN Manager appliance IPs, the query will match any device on ports 443, 8443, 8080, and 9090, producing results unrelated to SD-WAN Manager.
- The query does not scope DestinationIP to confirmed SD-WAN Manager appliance IPs; results will include any device on the listed ports unless a DestinationIP filter is added during deployment.
- The specific vulnerable API endpoint path for CVE-2026-76504 is described as a specific endpoint; if that path becomes publicly known, the adminPaths list should be narrowed to it for higher precision.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination IP is a Cisco SD-WAN Manager appliance and not another service on the same ports.
- Check whether the source IP belongs to an approved administrator, automation platform, or monitoring system.
- Review the request path, method, and response code to determine whether the traffic matches normal API use or suspicious unauthenticated access.
- Look for repeated requests, multiple admin paths, or a burst of successful 200 responses from the same source.
- Correlate with authentication and admin activity logs to see whether a valid login or session preceded the API access.

**Evidence to collect:**
- CommonSecurityLog entries for the source IP, destination IP, request URL, request method, response code, and user agent.
- Cisco SD-WAN Manager authentication and audit logs to verify whether the request was preceded by a valid login.
- Appliance management logs showing any configuration changes, new users, or API actions around the alert time.
- Network telemetry to determine whether the source IP is external, known, or associated with other scanning activity.
- Patch level and exposure status for the SD-WAN Manager appliance.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DestinationIP over a wider time window to identify repeated API access.
- Authentication logs for the appliance to correlate successful or failed logins with the request time.
- Configuration and audit logs to identify changes made through the API.
- Threat intelligence or firewall logs to determine whether the source IP is known malicious.

**Benign explanations:**
- An authorized administrator accessed the API from a non-RFC1918 address.
- A legitimate monitoring or automation platform polled the API from an external network.
- The request hit a management endpoint on a device that is not actually the SD-WAN Manager appliance.

**Escalation criteria:**
- The source IP is not recognized and there is no corresponding authentication event.
- The request path matches an admin API endpoint and returns successful responses from an external source.
- There are signs of configuration changes, new accounts, or other administrative actions after the request.
- The appliance is internet-exposed and not patched or mitigated for CVE-2026-76504.

**Containment actions:**
- Restrict external access to the SD-WAN Manager management interface immediately if unauthorized access is suspected.
- Block the source IPs if they are clearly malicious and not part of approved management traffic.
- If compromise is suspected, isolate the appliance from the internet and preserve audit logs before remediation.
- Coordinate with network operations before making changes that could affect SD-WAN control plane availability.

**Closure criteria:**
- The source is confirmed as an approved administrator or automation system.
- Authentication and audit logs show the access was legitimate and expected.
- No unauthorized configuration changes or suspicious follow-on activity are found.
- The appliance is patched or access-restricted and the event is documented as benign.

<br/>
---
<br/>

## Detection 5: NetScaler Zero-Day - Inbound Exploitation Attempt Followed by Anomalous Process Activity (CVE-2026-88771, CVE-2026-88772)

### Detection Opportunity

Inbound HTTP/S requests from external IPs to NetScaler management interfaces correlated with subsequent anomalous process or outbound connection activity on the appliance, indicating zero-day exploitation and post-exploitation behavior.

### Intelligence Context

- Unit 42: Threat Brief: NetScaler Zero Days CVE-2026-88771 and CVE-2026-88772 Exploited in the Wild (Updated September 30) — [https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/)
  - Context: Unit 42 and Citrix confirmed active exploitation of CVE-2026-88771 and CVE-2026-88772 against internet-facing NetScaler devices. Detection guidance includes monitoring for exploitation attempts and post-exploitation activity on NetScaler appliances.

### Search Metadata

- CVEs: CVE-2026-88771, CVE-2026-88772
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: NetScaler
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-88771, CVE-2026-88772, T1190, NetScaler

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog must be populated by a connector that captures HTTP application-layer fields (ResponseCode, RequestURL) for NetScaler management traffic; a raw firewall flow log without application-layer inspection will not populate these fields.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let netscalerPorts = dynamic([443, 8443, 9080, 9443]);
let postExploitWindowMin = 15m;
let inboundHits = CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DestinationPort in (netscalerPorts)
| where not (ipv4_is_private(SourceIP))
| where ResponseCode in (200, 500, 400)
| project HitTime = TimeGenerated, SourceIP, DestinationIP, DestinationPort, ResponseCode, RequestURL;
let postExploit = Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("sh ", "bash", "wget", "curl", "python", "exec(", "/bin/", "nsroot")
| project SyslogTime = TimeGenerated, Computer, HostName, SyslogMessage;
inboundHits
| join kind=inner postExploit on $left.DestinationIP == $right.HostName
| where SyslogTime between (HitTime .. (HitTime + postExploitWindowMin))
| extend DeltaSeconds = datetime_diff('second', SyslogTime, HitTime)
| project
    HitTime,
    SyslogTime,
    DeltaSeconds,
    SourceIP,
    DestinationIP,
    DestinationPort,
    ResponseCode,
    RequestURL,
    SyslogMessage,
    Computer
| order by HitTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate NetScaler administrative CLI sessions generating syslog messages containing shell-related strings.
- Other devices forwarding syslog to the same workspace whose messages contain the keyword list terms.

**Tuning notes:**
- Replace the HostName join key with Computer if NetScaler syslog records use the Computer field for the appliance identifier in your Sentinel workspace.
- Add a DestinationIP filter scoped to confirmed NetScaler appliance IPs to prevent matching unrelated devices on the same ports.
- Narrow the Syslog keyword list to strings confirmed present in NetScaler post-exploitation syslog output for CVE-2026-88771 and CVE-2026-88772 once forensic samples are available.
- Consider restricting ResponseCode to 200 only if the goal is confirmed successful exploitation rather than attempted exploitation.

**Risks / caveats:**
- The join on DestinationIP == HostName requires that the NetScaler Syslog HostName field contains the same IP address value used as DestinationIP in CommonSecurityLog; if HostName contains a DNS name rather than an IP, the join will produce no results.
- Syslog records from NetScaler must be forwarded to the Microsoft Sentinel Syslog table; if NetScaler syslog is not configured to forward to the Sentinel workspace, the postExploit sub-query will return no records.
- CommonSecurityLog must be populated by a connector that captures HTTP application-layer fields (ResponseCode, RequestURL) for NetScaler management traffic; a raw firewall flow log without application-layer inspection will not populate these fields.
- The join on DestinationIP == HostName will produce no results if NetScaler syslog HostName contains a DNS name rather than an IP address; an alternative join on Computer may be needed depending on the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination is a NetScaler management interface and identify the source IP, request path, and response code for the inbound hit.
- Review the NetScaler syslog message for evidence of shell execution, command invocation, downloads, or other post-exploitation behavior.
- Check whether the syslog event occurred shortly after the inbound request and whether the same appliance shows repeated suspicious requests.
- Look for outbound connections from the appliance to unusual external IPs or ports that could indicate command-and-control or staging activity.
- Verify whether the appliance is internet-facing and whether any emergency vendor guidance or mitigations have already been applied.

**Evidence to collect:**
- CommonSecurityLog entries for the inbound request, including source IP, destination IP, destination port, request URL, and response code.
- Syslog records from the NetScaler appliance around the same time, including the full message text and appliance identifier.
- Any network telemetry showing outbound connections from the appliance after the inbound request.
- Administrative access logs and configuration change logs for the appliance.
- Patch status, firmware version, and exposure details for the NetScaler device.

**Pivot points:**
- CommonSecurityLog for the same SourceIP to identify repeated attempts or other targeted appliances.
- Syslog for the same appliance over a wider time window to find additional shell, download, or execution indicators.
- Network telemetry or firewall logs to identify outbound connections from the appliance after the hit.
- Configuration and admin audit logs to determine whether any changes were made on the appliance.

**Benign explanations:**
- A legitimate administrator session or maintenance action generated shell-related syslog messages near the same time as the inbound request.
- The inbound request was a failed or noisy scan rather than a successful exploit.
- Other devices forwarding to the same syslog workspace produced messages containing shell-like keywords.

**Escalation criteria:**
- The syslog message clearly shows command execution, download activity, or other post-exploitation behavior on the appliance.
- Outbound connections from the appliance occur shortly after the inbound request and are not part of normal management traffic.
- The same source IP or request pattern is seen across multiple NetScaler devices or repeated attempts are observed.
- The appliance is internet-facing and unpatched for the affected CVEs.

**Containment actions:**
- If compromise is suspected, isolate the NetScaler appliance from external access while preserving logs and configuration state.
- Block the source IPs at the perimeter if they are clearly malicious and not part of approved testing.
- Disable or restrict management access until the appliance is validated and remediated.
- Engage the network and platform owners immediately because the appliance may be a critical access point.

**Closure criteria:**
- The syslog activity is confirmed to be legitimate administrative behavior or unrelated noise.
- No outbound connections, unauthorized changes, or other compromise indicators are found.
- The inbound request is assessed as a scan or failed attempt with no evidence of exploitation.
- The appliance is patched or mitigated and monitoring is in place for recurrence.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- Zimbra Command Injection - Shell Spawned from Web Service Process (CVE-2026-73570): Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- RMM Abuse - ScreenConnect Spawned or Co-Executed with MSP360 for Redundant Remote Access: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Zimbra Exploitation - Anomalous POST to Mail Server from External IP with Successful Response (CVE-2026-73570): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Cisco SD-WAN Manager - Unauthenticated External Access to Admin API Endpoints (CVE-2026-76504): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- NetScaler Zero-Day - Inbound Exploitation Attempt Followed by Anomalous Process Activity (CVE-2026-88771, CVE-2026-88772): CommonSecurityLog must be populated by a connector that captures HTTP application-layer fields (ResponseCode, RequestURL) for NetScaler management traffic; a raw firewall flow log without application-layer inspection will not populate these fields.

**Shared-table notes:**
- DeviceProcessEvents: shared by Zimbra Command Injection - Shell Spawned from Web Service Process (CVE-2026-73570); RMM Abuse - ScreenConnect Spawned or Co-Executed with MSP360 for Redundant Remote Access
- CommonSecurityLog: shared by Zimbra Exploitation - Anomalous POST to Mail Server from External IP with Successful Response (CVE-2026-73570); Cisco SD-WAN Manager - Unauthenticated External Access to Admin API Endpoints (CVE-2026-76504); NetScaler Zero-Day - Inbound Exploitation Attempt Followed by Anomalous Process Activity (CVE-2026-88771, CVE-2026-88772)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Zimbra Command Injection - Shell Spawned from Web Service Process (CVE-2026-73570).
2. Resolve environment-mapping detections next: Zimbra Exploitation - Anomalous POST to Mail Server from External IP with Successful Response (CVE-2026-73570); Cisco SD-WAN Manager - Unauthenticated External Access to Admin API Endpoints (CVE-2026-76504); NetScaler Zero-Day - Inbound Exploitation Attempt Followed by Anomalous Process Activity (CVE-2026-88771, CVE-2026-88772).
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: RMM Abuse - ScreenConnect Spawned or Co-Executed with MSP360 for Redundant Remote Access.

### Hunting Agenda and Promotion Criteria

- RMM Abuse - ScreenConnect Spawned or Co-Executed with MSP360 for Redundant Remote Access: Do not schedule yet; validate as an analyst-led hunt first..
- Zimbra Exploitation - Anomalous POST to Mail Server from External IP with Successful Response (CVE-2026-73570): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Cisco SD-WAN Manager - Unauthenticated External Access to Admin API Endpoints (CVE-2026-76504): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- NetScaler Zero-Day - Inbound Exploitation Attempt Followed by Anomalous Process Activity (CVE-2026-88771, CVE-2026-88772): CommonSecurityLog must be populated by a connector that captures HTTP application-layer fields (ResponseCode, RequestURL) for NetScaler management traffic; a raw firewall flow log without application-layer inspection will not populate these fields.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
