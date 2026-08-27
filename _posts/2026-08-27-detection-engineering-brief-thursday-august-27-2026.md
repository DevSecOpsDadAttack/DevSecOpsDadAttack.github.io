---
layout: post
title: "Detection Engineering Brief - Thursday, August 27, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-27
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1190
  - LiteLLM
  - cloud
  - web applications
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1190, LiteLLM, cloud, web applications.

Relevant IOCs were preserved and rendered inside their associated detection sections.

Deployment blockers or scheduling gates were identified for: Credential Harvesting Activity Following AI Gateway Compromise; SSRF Attempt Targeting Cloud Metadata Service via Obfuscated Hostname; Unexpected Inbound Connection to AI Gateway Port from External IP.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Cryptomining Process and Network Activity on Cloud Workload

### Detection Opportunity

Cryptomining binaries executed and outbound mining pool connections established on compromised cloud workloads following AI gateway exploitation.

### Intelligence Context

- Microsoft Security Blog: When AI infrastructure becomes the target: Securing gateways and control points — [https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/](https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/)
  - Context: Attackers exploited exposed LiteLLM AI gateway instances and subsequently deployed cryptomining software on the compromised cloud workloads, producing distinctive miner process names and outbound stratum protocol connections.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: LiteLLM
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, LiteLLM, cloud

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackWindow = 1d;
let CorrelationWindowMin = 30;
let MinerProcesses = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where FileName has_any ("xmrig", "minerd", "cpuminer", "ethminer", "nbminer", "t-rex", "lolminer", "gminer")
    or ProcessCommandLine has_any ("stratum+tcp", "stratum+ssl", "--pool", "-o stratum", "mining.pool", "xmrig")
| project DeviceId, DeviceName, AccountName, AccountDomain, MinerTime = Timestamp, FileName, ProcessCommandLine;
let MinerNetwork = DeviceNetworkEvents
| where Timestamp > ago(LookbackWindow)
| where RemotePort in (3333, 4444, 5555, 7777, 9999, 14444, 45700)
| where ActionType == "ConnectionSuccess"
| project DeviceId, NetTime = Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName;
MinerProcesses
| join kind=inner MinerNetwork on DeviceId
| where NetTime >= MinerTime - 5m and NetTime <= MinerTime + totimespan(CorrelationWindowMin * 1m)
| project
    DeviceName,
    AccountName,
    AccountDomain,
    FileName,
    ProcessCommandLine,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    MinerTime,
    NetTime
| order by MinerTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security researchers or red team operators running miner binaries in isolated lab VMs that share the same Defender for Endpoint tenant.
- Legitimate high-performance computing workloads that happen to use ports 3333 or 4444 for non-mining purposes.

**Tuning notes:**
- Adjust CorrelationWindowMin variable based on observed dwell time in the environment.
- Add additional mining pool ports (e.g., 80, 443 used by some pools for firewall evasion) if intelligence indicates their use.
- Consider adding an AccountName exclusion list for known service accounts that legitimately run compute-intensive workloads.

**Risks / caveats:**
- DeviceNetworkEvents may not capture link-local or host-only network traffic on all cloud VM configurations; validate that outbound connections to external mining pool IPs are recorded for the monitored workloads.
- The 30-minute correlation window is a starting point; environments with high process churn may benefit from a tighter window to reduce cross-device join noise if DeviceId is not sufficiently unique across tenants.
- Mining pool operators frequently rotate ports; the port list should be updated periodically against current threat intelligence.

### Triage Runbook

**First 15 minutes:**
- Validate the host is an internet-facing AI gateway or adjacent workload and identify the owning service/team.
- Check whether the miner process name or command line matches known mining tools or a renamed binary launching stratum connections.
- Review the outbound connection details for mining ports and confirm the destination IP is not an approved internal HPC or lab endpoint.
- Determine whether the same account or host shows other post-exploitation activity such as new processes, persistence, or unusual admin actions.

**Evidence to collect:**
- DeviceName, AccountName, AccountDomain, FileName, ProcessCommandLine, RemoteIP, RemotePort, MinerTime, NetTime, and InitiatingProcessFileName.
- Process tree and parent process for the miner binary, including any shell, downloader, or container runtime ancestry.
- Network history for the host around MinerTime to identify additional pool IPs, repeated connections, or lateral movement.
- Any recent changes to the LiteLLM deployment, exposed ports, or gateway configuration that could explain access.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId to find earlier suspicious downloads, script execution, or persistence.
- DeviceNetworkEvents for the same DeviceId to look for other external connections, especially to unusual ports or newly seen IPs.
- Alert, incident, and device timeline views to correlate with the initial gateway exploitation window.
- Cloud workload inventory or CMDB to confirm whether the host should ever run compute-intensive jobs or mining-like software.

**Benign explanations:**
- Security research or red-team activity in an isolated lab VM that shares the tenant.
- Legitimate high-performance computing or benchmarking software using ports that overlap with mining defaults.
- A renamed internal tool that happens to use stratum-like command-line arguments, though this should be rare.

**Escalation criteria:**
- Miner process is confirmed and outbound pool traffic is successful from a production workload.
- The host is internet-facing and shows additional compromise indicators such as persistence, credential access, or suspicious admin activity.
- Multiple workloads or accounts show the same pattern, suggesting broader exploitation of exposed AI infrastructure.

**Containment actions:**
- Isolate the affected host from the network if it is a production workload and active mining is confirmed.
- Terminate the miner process and any associated downloader or persistence processes after preserving evidence.
- Block the observed mining pool IPs and ports at the egress layer if they are not required for business use.
- Disable or rotate credentials used on the host if there is evidence of post-compromise account abuse.

**Closure criteria:**
- Confirmed legitimate lab or approved benchmarking activity with documented change approval.
- Miner process and outbound pool traffic are absent after investigation, and no other compromise indicators are found.
- The host is patched or removed from exposure, and the detection is tuned with an approved allowlist for known benign workloads.

<br/>
---
<br/>

## Detection 2: Credential Harvesting Activity Following AI Gateway Compromise

### Detection Opportunity

Credential harvesting processes executed on Linux-hosted AI gateway workloads after external exploitation, followed by anomalous sign-in activity from the same account.

### Intelligence Context

- Microsoft Security Blog: When AI infrastructure becomes the target: Securing gateways and control points — [https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/](https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/)
  - Context: Following exploitation of exposed LiteLLM gateway instances, attackers performed credential harvesting. The reporting explicitly identifies credential harvesting as a post-compromise action, suggesting process-level credential dumping followed by use of harvested credentials.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: LiteLLM
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, LiteLLM, cloud

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- Syslog, SigninLogs

### KQL

```kql
let LookbackWindow = 1d;
let CorrelationWindowHours = 2;
let CredHarvestEvents = Syslog
| where TimeGenerated > ago(LookbackWindow)
| where SyslogMessage has_any (
    "/etc/shadow",
    "mimipenguin",
    "LaZagne",
    "secretsdump",
    "/root/.ssh",
    "id_rsa",
    "HISTFILE"
    )
| extend ExtractedUser = extract(@"(?:user[=:\s]+|for\s+)(\S+)", 1, SyslogMessage)
| where isnotempty(ExtractedUser)
| project HarvestTime = TimeGenerated, HostName, SyslogMessage, ExtractedUser;
let SuspiciousSignins = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where ResultType == 0
| where RiskLevelDuringSignIn in ("medium", "high") or ConditionalAccessStatus == "notApplied"
| project
    SigninTime = TimeGenerated,
    UserPrincipalName,
    IPAddress,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    AppDisplayName,
    LocationDetails;
CredHarvestEvents
| join kind=inner SuspiciousSignins on $left.ExtractedUser == $right.UserPrincipalName
| where SigninTime > HarvestTime and SigninTime <= HarvestTime + totimespan(CorrelationWindowHours * 1h)
| project
    HostName,
    UserPrincipalName,
    IPAddress,
    HarvestTime,
    SigninTime,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    AppDisplayName,
    LocationDetails,
    SyslogMessage
| order by HarvestTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators reading /etc/shadow or SSH key files during maintenance will trigger the Syslog leg; without a subsequent anomalous sign-in the join will not fire.
- Security scanning tools (e.g., Lynis, OpenSCAP) that read sensitive file paths during compliance checks.

**Tuning notes:**
- Replace the ExtractedUser regex join with a lookup against a watchlist that maps Linux hostnames and local usernames to Entra UPNs for reliable correlation.
- Add Facility in ('auth', 'authpriv', 'daemon') filter to Syslog leg to reduce volume and improve signal quality.
- Consider adding AuditLogs or IdentityLogonEvents as an alternative or supplementary sign-in source if SigninLogs coverage is incomplete.

**Risks / caveats:**
- Syslog ingestion from Linux hosts requires the Log Analytics agent or AMA with a Syslog data source configured; if not deployed on LiteLLM hosts, the CredHarvestEvents leg will return no results.
- The join between Syslog ExtractedUser and SigninLogs UserPrincipalName requires Linux local usernames to match Entra ID UPNs exactly, which is not a standard configuration. Without a watchlist or lookup table mapping Linux usernames to UPNs, the join will produce no matches in most environments.
- RiskLevelDuringSignIn is only populated when Microsoft Entra ID Protection (P2 licensing) is active; environments without P2 will have null values, causing the ConditionalAccessStatus fallback to carry the full detection load.
- The ExtractedUser-to-UserPrincipalName join is the primary reliability risk; a watchlist mapping Linux usernames to Entra UPNs should be created and substituted for the regex extraction before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a Linux AI gateway workload and identify the user context associated with the harvesting activity.
- Review the SyslogMessage to see which sensitive file or tool name triggered the alert and whether it indicates local credential access or dumping.
- Validate the sign-in event for the same user principal, including source IP, risk level, conditional access result, and application used.
- Check whether the sign-in source is consistent with the user’s normal geography, device, and access pattern.

**Evidence to collect:**
- HostName, UserPrincipalName, IPAddress, HarvestTime, SigninTime, RiskLevelDuringSignIn, ConditionalAccessStatus, AppDisplayName, and SyslogMessage.
- The exact syslog line and surrounding log context to identify the process, command, or file path involved.
- SigninLogs details including source IP reputation, location, device info if available, and whether MFA or conditional access was bypassed.
- Any evidence of local privilege escalation, new accounts, SSH key changes, or shell history tampering on the host.

**Pivot points:**
- Syslog on the same HostName for nearby auth, daemon, and process events before and after HarvestTime.
- SigninLogs for the same UserPrincipalName over a wider time range to identify additional suspicious sign-ins or token use.
- AuditLogs or identity protection logs to see whether the account had password resets, MFA changes, or risky user actions.
- DeviceProcessEvents or host telemetry if available to identify credential dumping tools, archive creation, or file access patterns.

**Benign explanations:**
- Legitimate administrative maintenance that accessed sensitive files on the Linux host, followed by a normal sign-in.
- Security scanning or compliance tooling that reads credential-related paths as part of baseline checks.
- A false join caused by username-to-UPN mismatch or a shared service account mapping issue.

**Escalation criteria:**
- The sign-in is successful, high risk, or from an unfamiliar IP/location and aligns temporally with the harvesting event.
- The same account is used to access sensitive applications, create tokens, or perform privileged actions after the alert.
- Additional hosts show similar credential harvesting behavior, indicating a broader compromise campaign.

**Containment actions:**
- Disable or reset the affected account if the sign-in is suspicious and not clearly benign.
- Isolate the Linux host if credential dumping or post-compromise activity is confirmed.
- Revoke active sessions and refresh tokens for the impacted account where supported.
- Preserve syslog and sign-in evidence before making disruptive changes.

**Closure criteria:**
- The syslog activity is explained by approved admin or security tooling and the sign-in is verified as normal.
- The username-to-UPN mapping is proven incorrect and the alert is a known environment mapping issue.
- No additional suspicious sign-ins, host compromise indicators, or account abuse are found after review.

<br/>
---
<br/>

## Detection 3: SSRF Attempt Targeting Cloud Metadata Service via Obfuscated Hostname

### Detection Opportunity

HTTP requests containing obfuscated representations of 169.254.169.254 submitted to web-facing services in an attempt to exploit SSRF vulnerabilities and reach the cloud metadata endpoint.

### Intelligence Context

- SANS ISC: Obfuscating IP Addresses as Hostnames, (Tue, Aug 25th) — [https://isc.sans.edu/diary/rss/33280](https://isc.sans.edu/diary/rss/33280)
  - Context: Attackers scanned for the cloud metadata service at 169.254.169.254 using SSRF techniques and employed hostname obfuscation (decimal, octal, hex, and mixed encodings of the link-local IP) to bypass string-based IP filtering controls on web applications.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Not specified
- Platforms: cloud, web applications
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, cloud, web applications

### Relevant IOCs

| Type | Indicator |
|---|---|
| IPv4 | `169.254.169.254` |

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- The field name 'RemoteIP' referenced in the original detection's required_fields does not exist in CommonSecurityLog; the correct field is SourceIP.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where isnotempty(RequestURL)
| where RequestURL has_any (
    "169.254.169.254",
    "2852039166",
    "0xa9fea9fe",
    "0xa9fe.0xa9fe",
    "0251.0376.0251.0376",
    "169.254.169.254%00",
    "[::ffff:169.254.169.254]",
    "metadata.google.internal"
    )
    or DestinationIP == "169.254.169.254"
| project
    TimeGenerated,
    SourceIP,
    RequestURL,
    DestinationIP,
    ResponseCode,
    ActionType,
    DeviceVendor,
    DeviceProduct
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security scanners (Burp Suite, Nuclei) run by internal red teams or penetration testers against the web application.
- WAF rule testing traffic that includes metadata IP patterns in test payloads.
- Legitimate GCP workloads accessing 'metadata.google.internal' through a proxy that logs the hostname in RequestURL.

**Tuning notes:**
- Validate that the specific WAF or proxy product populates RequestURL with the raw, pre-normalization value by submitting a test request with a known obfuscated encoding and checking the resulting log entry.
- Add SourceIP exclusions for internal security scanning infrastructure to reduce red team noise.
- Consider adding additional IPv6-mapped forms such as '::ffff:a9fe:a9fe' if the environment uses IPv6-capable proxies.

**Risks / caveats:**
- CommonSecurityLog.RequestURL population depends on the specific WAF or proxy CEF connector; many products do not forward the raw pre-normalization URL, meaning obfuscated encodings may be decoded before logging and would not match the string patterns in the query.
- CommonSecurityLog.DestinationIP is not reliably populated by all CEF sources; the DestinationIP == '169.254.169.254' filter may never match if the product resolves hostnames before logging.
- The field name 'RemoteIP' referenced in the original detection's required_fields does not exist in CommonSecurityLog; the correct field is SourceIP.
- If the WAF normalizes or decodes URLs before writing to CEF, obfuscated encodings will be resolved to the literal IP and only the '169.254.169.254' literal match will fire; validate URL fidelity in the specific WAF product's CEF output.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, application, and device product that generated the request and confirm whether it is internet-facing.
- Inspect the RequestURL for the obfuscated metadata representation and determine whether the request was blocked or allowed.
- Check whether the source is an internal scanner, red team, or known testing platform before treating it as hostile.
- Look for repeated requests from the same source or to other SSRF-sensitive endpoints on the same application.

**Evidence to collect:**
- TimeGenerated, SourceIP, RequestURL, DestinationIP, ResponseCode, ActionType, DeviceVendor, and DeviceProduct.
- The raw request path and any decoded form of the payload if the WAF or proxy preserves it.
- WAF or proxy action details showing whether the request was blocked, challenged, or forwarded to the backend.
- Application logs for the same timestamp to see whether the payload reached the app and triggered server-side outbound behavior.

**Pivot points:**
- CommonSecurityLog for the same SourceIP to identify other suspicious payloads, scanning patterns, or repeated metadata probes.
- Application or reverse proxy logs to confirm whether the request was forwarded and whether backend errors occurred.
- Threat intelligence or internal scanner allowlists to determine whether the source is authorized.
- If available, cloud workload logs for outbound requests to metadata-related endpoints after the probe.

**Benign explanations:**
- Authorized penetration testing or red-team validation of SSRF defenses.
- Internal WAF rule testing or security research traffic from approved tooling.
- Legitimate GCP-related traffic where metadata hostnames appear in documentation or test payloads, though this should still be reviewed.

**Escalation criteria:**
- The request was allowed through and the application shows signs of backend SSRF behavior or metadata access.
- Multiple obfuscated metadata probes are seen from the same source or across several applications.
- The source IP is external and not part of an approved testing program.

**Containment actions:**
- Block or rate-limit the source IP if it is clearly malicious and not an approved tester.
- Tighten WAF or proxy rules to detect obfuscated metadata encodings if the application is exposed.
- If the app is confirmed vulnerable, disable the affected endpoint or apply a temporary mitigation until fixed.

**Closure criteria:**
- The source is confirmed as an approved scanner or test and the activity matches the test scope.
- The WAF blocked the request and no backend SSRF behavior occurred.
- The payload is a false positive caused by benign documentation or proxy logging behavior, with no repeated suspicious activity.

<br/>
---
<br/>

## Detection 4: Direct Outbound Connection to Cloud Metadata IP from Non-System Process

### Detection Opportunity

Non-system processes on cloud workloads initiating direct network connections to 169.254.169.254, indicating SSRF exploitation or unauthorized metadata service reconnaissance.

### Intelligence Context

- SANS ISC: Obfuscating IP Addresses as Hostnames, (Tue, Aug 25th) — [https://isc.sans.edu/diary/rss/33280](https://isc.sans.edu/diary/rss/33280)
  - Context: Scans explicitly targeted the cloud metadata service at 169.254.169.254. Direct connections to this link-local address from application processes rather than system agents are a strong indicator of SSRF exploitation success or active reconnaissance.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Not specified
- Platforms: cloud, web applications
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, cloud, web applications

### Relevant IOCs

| Type | Indicator |
|---|---|
| IPv4 | `169.254.169.254` |

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIP == "169.254.169.254"
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where InitiatingProcessName !in~ (
    "waagent",
    "cloud-init",
    "imds-agent",
    "AzureGuestAgent",
    "WindowsAzureGuestAgent.exe",
    "WaAppAgent.exe",
    "amazon-ssm-agent",
    "aws-cfn-bootstrap",
    "google_guest_agent",
    "google-guest-agent"
    )
| project
    Timestamp,
    DeviceName,
    InitiatingProcessName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessParentFileName,
    RemoteIP,
    RemotePort,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Cloud monitoring agents or custom scripts that legitimately query the metadata service but are not in the exclusion list; review InitiatingProcessName values in the environment before scheduling.
- Container orchestration agents (e.g., kubelet, containerd) on Kubernetes nodes that query IMDS for node identity.

**Tuning notes:**
- Run the query without the InitiatingProcessName exclusion filter first to enumerate all processes currently connecting to 169.254.169.254 in the environment, then add legitimate ones to the exclusion list.
- Consider scoping DeviceName to specific device groups or tags associated with internet-facing workloads to reduce noise from internal infrastructure.
- Add RemotePort == 80 as an optional additional filter if only standard IMDS HTTP traffic is of interest and other ports generate noise.

**Risks / caveats:**
- DeviceNetworkEvents may not capture link-local (169.254.0.0/16) traffic on all cloud VM configurations depending on the network driver and Defender for Endpoint sensor version; validate that connections to 169.254.169.254 are recorded before scheduling.
- The exclusion list is not exhaustive; cloud environments with custom metadata polling agents or container runtimes will require additional exclusions identified through baseline review.
- On Windows cloud VMs, additional Microsoft processes may legitimately query IMDS; a baseline review of existing 169.254.169.254 connections in the environment is recommended before scheduling to identify missing exclusions.
- Defender for Endpoint sensor coverage on all cloud workloads must be confirmed; unmonitored instances will not appear in results.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, command line, and account context and determine whether it is an approved cloud agent.
- Check whether the process name is one of the known legitimate metadata callers excluded by the rule or a custom agent in your environment.
- Review the connection timing and frequency to see whether this is a one-off probe or repeated metadata access.
- Assess whether the host is an internet-facing workload that could have been used as an SSRF pivot.

**Evidence to collect:**
- Timestamp, DeviceName, InitiatingProcessName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName, RemoteIP, RemotePort, and ActionType.
- Process tree and any child processes spawned after the metadata connection.
- Host logs or application logs showing whether the process requested instance credentials, identity tokens, or role metadata.
- Any recent web requests, errors, or suspicious inbound traffic that could have led to SSRF exploitation.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName to find other connections to 169.254.169.254 or unusual external destinations.
- DeviceProcessEvents to identify the parent process, script, or service that launched the metadata caller.
- Web server, reverse proxy, or application logs to correlate inbound requests with the metadata access time.
- Cloud control plane or identity logs to check for new tokens, role assumptions, or suspicious API calls after the event.

**Benign explanations:**
- A legitimate cloud agent or custom automation script that was not yet added to the exclusion list.
- Container or node management software that queries IMDS for identity or configuration.
- Approved administrative tooling on a cloud VM that uses metadata for normal operations.

**Escalation criteria:**
- The process is not a known agent and the host is internet-facing or hosts a web application.
- There is evidence of token retrieval, credential use, or follow-on suspicious cloud API activity.
- The metadata access coincides with suspicious inbound web traffic or other signs of SSRF exploitation.

**Containment actions:**
- Isolate the host if the metadata access is unexpected and the workload is production-facing.
- Disable or rotate any credentials, tokens, or instance roles that may have been exposed.
- Block or patch the vulnerable application path if SSRF is confirmed or strongly suspected.
- Preserve process and network evidence before restarting services or applying remediation.

**Closure criteria:**
- The process is confirmed as an approved metadata caller and is added to the environment allowlist.
- No token retrieval, suspicious API activity, or vulnerable application behavior is found.
- The host is not internet-facing and the connection is attributable to a documented cloud management function.

<br/>
---
<br/>

## Detection 5: Unexpected Inbound Connection to AI Gateway Port from External IP

### Detection Opportunity

External IP addresses establishing inbound connections to ports commonly used by LiteLLM and similar AI gateway services on cloud workloads, indicating potential exploitation attempts against exposed AI infrastructure.

### Intelligence Context

- Microsoft Security Blog: When AI infrastructure becomes the target: Securing gateways and control points — [https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/](https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/)
  - Context: Attackers targeted exposed AI gateway workloads including LiteLLM instances accessible from the internet. Inbound connections from external IPs to AI gateway service ports represent the initial access vector described in the reporting.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: LiteLLM
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, LiteLLM, cloud

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- The field 'RemoteIP' referenced in the original required_fields does not exist in CommonSecurityLog; the correct field is SourceIP.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DestinationPort in (4000, 8000, 8080, 8443)
| where isnotempty(SourceIP)
| where not(ipv4_is_private(SourceIP))
| summarize
    ConnectionCount = count(),
    DistinctResponseCodes = make_set(ResponseCode, 20),
    DistinctDestinationIPs = dcount(DestinationIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationPort, DeviceVendor, DeviceProduct
| where ConnectionCount > 5
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external API consumers of the AI gateway service will appear as high-volume external sources on the monitored ports.
- CDN health check probes and load balancer monitors from cloud provider IP ranges.
- Internet-wide scanners (Shodan, Censys, security researchers) that routinely probe common web ports.
- Penetration testing firms engaged by the organization.

**Tuning notes:**
- Scope the query to the specific DestinationIP or DeviceName of the LiteLLM host if that information is available in CommonSecurityLog to eliminate noise from other services on the same monitored boundary.
- Replace the port list with the actual listening port of the LiteLLM deployment if it differs from the defaults.
- Consider adding a TI lookup join against ThreatIntelligenceIndicator to prioritize SourceIPs with known malicious reputation.
- Increase ConnectionCount threshold significantly (e.g., > 50 or > 100) if legitimate API consumers generate high volumes, or switch to rate-of-change analysis.

**Risks / caveats:**
- CommonSecurityLog.SourceIP and DestinationPort population depends on the specific WAF or firewall CEF connector; not all products populate these fields consistently.
- The field 'RemoteIP' referenced in the original required_fields does not exist in CommonSecurityLog; the correct field is SourceIP.
- Ports 8000, 8080, and 8443 are generic web service ports; without scoping to the specific device or network segment hosting the AI gateway, results will include traffic to unrelated services on the same monitored network boundary.
- The ConnectionCount > 5 threshold is arbitrary; legitimate API consumers will exceed it, requiring analyst review of each result.

### Triage Runbook

**First 15 minutes:**
- Identify the destination service and confirm whether the port is expected for the LiteLLM or related AI gateway deployment.
- Review the source IP reputation, volume, and whether the traffic pattern looks like scanning, health checks, or normal client use.
- Check whether the destination host is internet-facing and whether the service should be publicly reachable at all.
- Look for concurrent signs of exploitation on the same host, such as unusual processes, outbound mining traffic, or metadata access.

**Evidence to collect:**
- SourceIP, DestinationPort, ConnectionCount, DistinctResponseCodes, DistinctDestinationIPs, FirstSeen, LastSeen, DeviceVendor, and DeviceProduct.
- Firewall, WAF, or load balancer logs showing whether the connections were allowed, blocked, or challenged.
- Service configuration for the AI gateway, including listening ports, authentication requirements, and exposure scope.
- Any correlated host telemetry showing process creation, outbound connections, or authentication anomalies after the inbound traffic.

**Pivot points:**
- CommonSecurityLog or equivalent network logs for the same SourceIP to identify other ports, hosts, or repeated probes.
- DeviceNetworkEvents and DeviceProcessEvents on the destination host to look for post-access compromise indicators.
- Threat intelligence and internal scanner allowlists to classify the source IP.
- Cloud load balancer or reverse proxy logs to determine whether the traffic reached the application layer.

**Benign explanations:**
- Legitimate API consumers or partner integrations using the exposed gateway.
- CDN, load balancer, or health-check traffic from cloud infrastructure.
- Authorized penetration testing or external scanning by a security team.

**Escalation criteria:**
- The destination service should not be internet-facing, or exposure is unexpected.
- The source IP is external, untrusted, and the traffic pattern is consistent with scanning or exploitation attempts.
- There are correlated host indicators of compromise such as miner activity, credential harvesting, or suspicious outbound connections.

**Containment actions:**
- Restrict exposure of the AI gateway port to approved source ranges if public access is not required.
- Block clearly malicious source IPs or rate-limit abusive traffic at the edge.
- If exploitation is suspected, isolate the host and preserve logs before making service changes.
- Coordinate with the service owner before changing firewall or load balancer rules in production.

**Closure criteria:**
- The traffic is confirmed as legitimate and matches an approved client, health check, or test source.
- The service is intentionally public and no additional compromise indicators are present.
- The alert is attributable to known scanner or monitoring infrastructure and is documented in an allowlist or suppression rule.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Schema / correlation keys:**
- SSRF Attempt Targeting Cloud Metadata Service via Obfuscated Hostname: The field name 'RemoteIP' referenced in the original detection's required_fields does not exist in CommonSecurityLog; the correct field is SourceIP.
- Unexpected Inbound Connection to AI Gateway Port from External IP: Do not schedule yet; validate as an analyst-led hunt first.
- Unexpected Inbound Connection to AI Gateway Port from External IP: The field 'RemoteIP' referenced in the original required_fields does not exist in CommonSecurityLog; the correct field is SourceIP.

**Shared-table notes:**
- DeviceNetworkEvents: shared by Cryptomining Process and Network Activity on Cloud Workload; Direct Outbound Connection to Cloud Metadata IP from Non-System Process
- CommonSecurityLog: shared by SSRF Attempt Targeting Cloud Metadata Service via Obfuscated Hostname; Unexpected Inbound Connection to AI Gateway Port from External IP

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Cryptomining Process and Network Activity on Cloud Workload; Direct Outbound Connection to Cloud Metadata IP from Non-System Process.
2. Resolve environment-mapping detections next: Credential Harvesting Activity Following AI Gateway Compromise; SSRF Attempt Targeting Cloud Metadata Service via Obfuscated Hostname.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Unexpected Inbound Connection to AI Gateway Port from External IP.

### Hunting Agenda and Promotion Criteria

- Unexpected Inbound Connection to AI Gateway Port from External IP: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Credential Harvesting Activity Following AI Gateway Compromise: Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.; prove correlation keys join correctly on real tenant telemetry.
- SSRF Attempt Targeting Cloud Metadata Service via Obfuscated Hostname: The field name 'RemoteIP' referenced in the original detection's required_fields does not exist in CommonSecurityLog; the correct field is SourceIP..

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

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
