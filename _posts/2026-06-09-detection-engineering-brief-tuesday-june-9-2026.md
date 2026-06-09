---
layout: post
title: "Detection Engineering Brief - Tuesday, June 9, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-09
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-50751
  - T1190
  - Check Point Remote Access VPN
  - Check Point Mobile Access
  - Check Point Spark Firewall
  - CVE-2026-0257
  - PAN-OS
  - T1059
  - Gogs
  - Windows
  - Metasploit
  - Apache ActiveMQ
---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-50751, T1190, Check Point Remote Access VPN, Check Point Mobile Access, Check Point Spark Firewall, CVE-2026-0257, PAN-OS, T1059, Gogs, Windows, Metasploit, Apache ActiveMQ.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Check Point VPN Auth Bypass - Successful Session Without Credential Validation (CVE-2026-50751); Check Point VPN Legacy Client Connection Without Certificate Authentication (CVE-2026-50751); PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257); Apache ActiveMQ RCE via Jolokia addNetworkConnector Endpoint Access.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Check Point VPN Auth Bypass - Successful Session Without Credential Validation (CVE-2026-50751)

### Detection Opportunity

Unauthenticated VPN session established without valid credentials via CVE-2026-50751 authentication bypass

### Intelligence Context

- Rapid7: Critical Check Point VPN Zero-Day Exploited in the Wild (CVE-2026-50751) — [https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751)
  - Context: CVE-2026-50751 allows an unauthenticated attacker to establish a VPN session without providing valid credentials on gateways accepting legacy Remote Access clients without machine certificate requirements. The exploit leaves a detectable gap: a successful VPN session with no corresponding credential validation event.

### Search Metadata

- CVEs: CVE-2026-50751
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point Remote Access VPN, Check Point Mobile Access, Check Point Spark Firewall
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-50751, T1190, Check Point Remote Access VPN, Check Point Mobile Access, Check Point Spark Firewall

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Check Point CEF connector must be configured with sufficient log verbosity to emit both session-establishment and authentication event types; if only one type is forwarded, the correlation is invalid.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let joinWindow = 15m;
let AuthEvents = CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Check Point"
| where DeviceProduct has_any ("VPN-1", "Remote Access", "Mobile Access", "Firewall")
| where Activity has_any ("Authentication", "Login", "Credential", "IKE", "XAUTH", "User Authentication")
    or Message has_any ("authentication", "credential", "IKE", "XAUTH", "login")
| project AuthTime = TimeGenerated, SourceIP;
let SessionEvents = CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Check Point"
| where DeviceProduct has_any ("VPN-1", "Remote Access", "Mobile Access", "Firewall")
| where Activity has_any ("VPN session established", "Remote Access", "Connected", "Tunnel established", "Session opened")
| where LogSeverity in ("Medium", "High", "Critical", "3", "4", "5", "6", "7", "8", "9", "10")
| project SessionTime = TimeGenerated, SourceIP, DestinationIP, Activity, Message, DeviceProduct, LogSeverity, DeviceExternalID;
SessionEvents
| join kind=leftanti (
    AuthEvents
) on SourceIP
| where SessionTime >= ago(lookback)
| project SessionTime, SourceIP, DestinationIP, Activity, Message, DeviceProduct, LogSeverity, DeviceExternalID
| sort by SessionTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate VPN sessions where the authentication event is emitted with a different Activity string not covered by the keyword list will appear as false positives until the keyword list is tuned to the environment.
- Sessions where authentication and session events arrive out of order or with ingestion delay exceeding the join window will be flagged.
- Reconnection or keepalive session events that do not have a paired authentication event in the same window may trigger.

Tuning notes:
- Run the AuthEvents subquery alone against a known-good authenticated session to confirm the Activity or Message keywords match before enabling the full query.
- Extend lookback to 24h for initial hunting; reduce to 1h for scheduled alerting once keyword lists are validated.
- Consider adding a summarize step to group repeated alerts from the same SourceIP within a short window to reduce alert volume.

Risks / caveats:
- CommonSecurityLog Activity field values for Check Point session and authentication events are firmware-version-dependent and may not match the keyword lists used in this query; if the strings do not match, the leftanti join will incorrectly flag all sessions.
- Check Point CEF connector must be configured with sufficient log verbosity to emit both session-establishment and authentication event types; if only one type is forwarded, the correlation is invalid.
- The 15-minute join window is a flat SourceIP correlation, not a true session-scoped correlation; a source IP that authenticated in a prior session within the window will suppress a genuinely unauthenticated session in the same window.
- Ingestion delays exceeding the join window will cause false positives; consider extending the lookback and join window if ingestion latency is observed.

### Triage Runbook

First 15 minutes:
- Confirm the alert is tied to a Check Point gateway that accepts legacy Remote Access clients and note the DeviceExternalID or gateway identity.
- Review the session timeline for the SourceIP and DestinationIP to verify there is a successful VPN session event with no corresponding authentication event in the same window.
- Check whether the source is a known corporate VPN user, remote office, or approved testing/scanning host before treating it as malicious.
- Look for immediate follow-on activity from the same SourceIP after session establishment, such as additional VPN logins, unusual access to internal subnets, or repeated session attempts.

Evidence to collect:
- TimeGenerated, SourceIP, DestinationIP, Activity, Message, LogSeverity, and DeviceExternalID from the triggering event.
- Any Check Point authentication, certificate, or machine-validation events for the same SourceIP within at least 30 minutes before and after the alert.
- VPN gateway firmware/version, connector configuration, and whether legacy clients without machine certificates are permitted.
- Any internal network access or lateral movement from the SourceIP after the VPN session was established.

Pivot points:
- CommonSecurityLog filtered to the same SourceIP and DeviceExternalID over a wider time range.
- CommonSecurityLog for authentication, certificate, IKE, XAUTH, login, and session-establishment events on the same gateway.
- Firewall, proxy, and internal network logs for the SourceIP to identify post-VPN access.
- Asset inventory or VPN user records to determine whether the source IP maps to a known user or managed endpoint.

Benign explanations:
- The authentication event may exist but use a different Activity or Message string than the detection expects.
- Ingestion delay or out-of-order log arrival can make a legitimate authenticated session appear unauthenticated.
- A prior authentication event from the same SourceIP may suppress or confuse correlation if the user reconnected quickly.
- Known legacy-client environments without machine certificate enforcement can generate expected matches.

Escalation criteria:
- The SourceIP is external, unknown, or associated with repeated unauthenticated VPN sessions.
- There is evidence of internal network access, privilege escalation, or lateral movement after the VPN session starts.
- Multiple gateways or multiple source IPs show the same pattern within a short period.
- The gateway is internet-facing and certificate authentication is expected but absent.

Containment actions:
- Disable or block the suspicious VPN account or source IP if the session is confirmed malicious.
- Temporarily restrict or disable legacy Remote Access client access or require machine certificate validation on the affected gateway if operationally feasible.
- Force reauthentication and review active VPN sessions on the gateway.
- Preserve gateway logs and configuration before making changes.

Closure criteria:
- A matching authentication or certificate event is found and the session is confirmed legitimate.
- The alert is attributable to a known legacy-client exception or approved testing activity.
- No post-session suspicious activity is observed and the gateway configuration explains the correlation gap.
- The event is determined to be a logging/mapping issue after validating the Check Point Activity and Message fields in the environment.

---

## Detection 2: Check Point VPN Legacy Client Connection Without Certificate Authentication (CVE-2026-50751)

### Detection Opportunity

Legacy Remote Access client connects to Check Point VPN gateway without machine certificate validation, a precondition exploited by CVE-2026-50751

### Intelligence Context

- Rapid7: Critical Check Point VPN Zero-Day Exploited in the Wild (CVE-2026-50751) — [https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751)
  - Context: Gateways that accept legacy Remote Access clients without requiring a machine certificate are vulnerable to CVE-2026-50751. Sessions from legacy clients lacking certificate checks are anomalous in hardened environments and can be detected by correlating session establishment events with the absence of certificate authentication log entries.

### Search Metadata

- CVEs: CVE-2026-50751
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point Remote Access VPN, Check Point Mobile Access, Check Point Spark Firewall
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-50751, T1190, Check Point Remote Access VPN, Check Point Mobile Access, Check Point Spark Firewall

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Legacy client type strings in the Message and AdditionalExtensions fields are not standardized across Check Point firmware versions; if the gateway does not emit these strings, the query returns no results.
- Certificate authentication events may not be logged as distinct entries in all Check Point CEF connector configurations; if absent, the leftanti join cannot function as intended.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let CertAuthEvents = CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Check Point"
| where Message has_any ("certificate", "cert", "machine auth", "PKI", "machine certificate")
    or Activity has_any ("Certificate", "PKI", "Machine Authentication")
| project CertTime = TimeGenerated, SourceIP;
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Check Point"
| where DeviceProduct has_any ("VPN-1", "Remote Access", "Mobile Access", "Firewall")
| where Activity has_any ("VPN session established", "Remote Access", "Tunnel established", "Connected", "Session opened")
| where Message has_any ("legacy", "L2TP", "PPTP", "SecureClient", "Endpoint Connect", "old client")
    or AdditionalExtensions has_any ("legacy", "SecureClient", "L2TP", "PPTP")
| join kind=leftanti (
    CertAuthEvents
) on SourceIP
| project TimeGenerated, SourceIP, Activity, Message, LogSeverity, DeviceProduct, AdditionalExtensions, DeviceExternalID
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Environments that legitimately permit legacy clients without certificate requirements will generate high volumes of results; this detection is most useful in environments where certificate authentication is enforced policy.
- Sessions where certificate auth events are logged with different terminology than the keyword list will appear as false positives.
- Reconnection events from previously authenticated legacy clients may trigger if the certificate auth event falls outside the lookback window.

Tuning notes:
- Before scheduling, run the CertAuthEvents subquery alone to confirm certificate auth events are present in the environment and that the keyword list captures them.
- Run the session subquery alone to confirm legacy client strings appear in Message or AdditionalExtensions for actual legacy client connections.
- Consider building a watchlist of known-permitted legacy client source IPs and adding an anti-join against it to suppress authorized connections.

Risks / caveats:
- Legacy client type strings in the Message and AdditionalExtensions fields are not standardized across Check Point firmware versions; if the gateway does not emit these strings, the query returns no results.
- Certificate authentication events may not be logged as distinct entries in all Check Point CEF connector configurations; if absent, the leftanti join cannot function as intended.
- AdditionalExtensions is a free-text field in CommonSecurityLog and its content depends entirely on the CEF connector mapping; it may be empty or differently structured.
- The legacy client keyword list is speculative without access to actual Check Point log samples from the target environment; the query must be validated against real log output before results are meaningful.

### Triage Runbook

First 15 minutes:
- Identify the source host or user associated with the SourceIP and determine whether it is a known legacy client or unmanaged device.
- Review the Message and AdditionalExtensions fields to confirm the client type indicators and whether certificate-authentication evidence is absent.
- Check the gateway policy to see whether legacy clients without machine certificates are allowed anywhere in the environment.
- Look for repeated connection attempts, multiple source IPs, or concurrent suspicious VPN sessions from the same gateway.

Evidence to collect:
- TimeGenerated, SourceIP, Activity, Message, LogSeverity, AdditionalExtensions, DeviceProduct, and DeviceExternalID from the alert.
- Any certificate-authentication, machine-authentication, or PKI-related events for the same SourceIP around the alert time.
- VPN policy/configuration showing whether machine certificate validation is required for Remote Access clients.
- User/device inventory mapping for the source to determine whether it is a managed endpoint, legacy client, or external host.

Pivot points:
- CommonSecurityLog for the same SourceIP across session, authentication, and certificate-related events.
- CommonSecurityLog for other SourceIPs showing legacy client strings such as SecureClient, Endpoint Connect, L2TP, or PPTP.
- VPN gateway logs or admin audit logs to confirm policy settings and recent changes.
- Endpoint or identity logs to identify the user/device behind the source IP.

Benign explanations:
- The environment may intentionally allow legacy clients without certificate enforcement.
- The client-type strings may be emitted differently by the gateway firmware, causing a legitimate session to appear suspicious.
- Certificate-authentication events may not be logged as distinct entries in the current connector configuration.
- A previously authenticated legacy client may reconnect and fall outside the correlation window.

Escalation criteria:
- The source is unknown, external, or not on an approved legacy-client exception list.
- Certificate validation is required by policy but no certificate-authentication evidence exists.
- There are multiple suspicious legacy-client connections from the same or related source IPs.
- The alert coincides with other signs of exploitation on the gateway or internal network.

Containment actions:
- Block the suspicious source IP or disable the associated VPN account if the connection is unauthorized.
- Remove or isolate legacy-client exceptions if exploitation is suspected and business impact is acceptable.
- Require machine certificate validation on the affected gateway or tighten Remote Access policy.
- Preserve logs and configuration before making changes.

Closure criteria:
- The source is confirmed as an approved legacy client and the lack of certificate validation is expected.
- The alert is explained by connector logging gaps or firmware-specific field mapping after validation.
- No suspicious follow-on activity is observed and the connection is tied to a known user/device exception.
- Policy review confirms the gateway is not exposed to the vulnerable legacy-client condition.

---

## Detection 3: PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257)

### Detection Opportunity

Active exploitation of PAN-OS CVE-2026-0257 producing high-severity anomalous events on internet-exposed Palo Alto devices

### Intelligence Context

- Unit 42: Threat Brief: Active Exploitation of PAN-OS CVE-2026-0257 — [https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/](https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/)
  - Context: Unit 42 confirmed active in-the-wild exploitation of CVE-2026-0257 targeting internet-exposed PAN-OS devices. The reporting confirms exploitation is occurring and that indicators of activity exist on affected devices, though specific payload signatures were not enumerated.

### Search Metadata

- CVEs: CVE-2026-0257
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: PAN-OS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-0257, T1190, PAN-OS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- PAN-OS threat logs must be forwarded to Sentinel via CEF connector with LogSeverity populated; if PAN-OS is forwarding only traffic logs or system logs, threat log entries will be absent.
- DeviceProduct string 'PAN-OS' must match the exact value emitted by the CEF connector; some PAN-OS connector configurations emit 'Palo Alto Networks Firewall' or 'NGFW' instead.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let lookback = 24h;
let minEvents = 3;
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Palo Alto Networks"
| where DeviceProduct has_any ("PAN-OS", "NGFW", "Firewall")
| where LogSeverity in ("High", "Critical", "7", "8", "9", "10")
| where Message has "CVE-2026-0257"
    or (
        Activity has_any ("threat", "exploit", "vulnerability", "attack", "intrusion")
        or Message has_any ("exploit", "vulnerability", "attack", "intrusion")
    )
| extend IsCVESpecific = iff(Message has "CVE-2026-0257", true, false)
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Activities = make_set(Activity, 10),
    CVESpecificHits = countif(IsCVESpecific == true),
    SampleMessage = take_any(Message)
    by SourceIP, DestinationIP, DeviceProduct
| where EventCount >= minEvents or CVESpecificHits >= 1
| sort by CVESpecificHits desc, EventCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Existing IPS/threat prevention signatures for unrelated CVEs will generate high-severity events that match the generic keyword filter.
- Internet-facing PAN-OS devices routinely generate high-severity threat log entries from mass scanners and opportunistic probes unrelated to CVE-2026-0257.
- Internal vulnerability scanners targeting PAN-OS management interfaces will trigger the query.

Tuning notes:
- Once Palo Alto publishes the threat signature ID for CVE-2026-0257, replace the generic keyword filter with a targeted DeviceCustomNumber1 or AdditionalExtensions signature ID filter and promote to production_candidate.
- Baseline the EventCount threshold by running the query over 7 days of historical data and reviewing the distribution of event counts per SourceIP to set an appropriate threshold.
- Add an exclusion for known internal vulnerability scanner IP ranges in SourceIP to reduce false positives.

Risks / caveats:
- PAN-OS threat logs must be forwarded to Sentinel via CEF connector with LogSeverity populated; if PAN-OS is forwarding only traffic logs or system logs, threat log entries will be absent.
- DeviceProduct string 'PAN-OS' must match the exact value emitted by the CEF connector; some PAN-OS connector configurations emit 'Palo Alto Networks Firewall' or 'NGFW' instead.
- The minEvents threshold of 3 is a starting point and must be baselined against normal PAN-OS threat log volume in the environment to avoid alert fatigue.
- Without a CVE-2026-0257-specific threat signature ID from Palo Alto, the generic keyword filter will produce significant noise from unrelated threat events.

### Triage Runbook

First 15 minutes:
- Confirm the affected device is internet-exposed and identify whether the alert is CVE-specific or only generic high-severity threat activity.
- Review the Message and Activities fields to see whether the event references CVE-2026-0257 or a known exploit/threat signature.
- Check whether the SourceIP is a known scanner, vulnerability management system, or security vendor IP range.
- Determine whether multiple high-severity events occurred from the same SourceIP/DestinationIP pair within a short time window.

Evidence to collect:
- FirstSeen, LastSeen, SourceIP, DestinationIP, DeviceProduct, EventCount, Activities, and SampleMessage from the alert.
- PAN-OS threat, system, and traffic logs for the same device and time window.
- Device exposure details: public IP, management interface exposure, and whether the device is a perimeter firewall.
- Any recent PAN-OS configuration changes, content updates, or signature updates.

Pivot points:
- CommonSecurityLog for the same DestinationIP and SourceIP over 24 hours to identify related threat events.
- PAN-OS threat logs filtered by the same device and time window to look for repeated exploit indicators.
- Traffic logs to determine whether the source reached management or user-facing services.
- Asset inventory or CMDB to confirm whether the device is internet-facing and business critical.

Benign explanations:
- Internet-facing PAN-OS devices commonly receive scanner and probe traffic that can generate high-severity events.
- Internal vulnerability scanners or red-team activity may trigger the same pattern.
- The detection is intentionally broad and may match unrelated threat signatures until a CVE-specific signature is available.
- A burst of unrelated IPS events can meet the EventCount threshold without indicating compromise.

Escalation criteria:
- The event is CVE-specific or strongly correlated with other exploitation indicators on the same device.
- The source is external and not attributable to an approved scanner or test.
- There are repeated high-severity events against the same exposed device or management interface.
- The device shows signs of follow-on compromise, configuration change, or unexpected outbound activity.

Containment actions:
- If exploitation is plausible, restrict exposure of the affected PAN-OS interface or temporarily block the source IP at the perimeter.
- Validate that management interfaces are not publicly exposed and disable unnecessary external access paths.
- Preserve threat logs and device configuration before remediation.
- Engage the firewall owner and incident response team if the device is business critical or shows compromise indicators.

Closure criteria:
- The activity is confirmed as scanner, test, or unrelated threat traffic.
- No CVE-specific evidence or follow-on compromise is found after log review.
- The device is not exposed in a way consistent with the exploit scenario and the alert is attributable to generic noise.
- A known internal security tool or approved activity explains the events.

---

## Detection 4: Gogs RCE via --exec Branch Name Triggering Command Injection on Rebase

### Detection Opportunity

Gogs RCE exploited by naming a branch '--exec' and triggering a rebase operation, causing arbitrary command execution on the Gogs host

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Apache ActiveMQ RCE, Gogs Rebase RCE, and Windows Kernel Pointer Enum — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026)
  - Context: A Metasploit module was published exploiting a Gogs RCE vulnerability where an attacker names a branch '--exec' and requests a rebase, causing the Gogs process to execute attacker-controlled commands. The '--exec' string in process arguments spawned by Gogs is a highly specific and low-false-positive indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Gogs
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1059, Gogs, Windows, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where InitiatingProcessFileName in~ ("gogs.exe", "gogs")
    or (InitiatingProcessCommandLine has "gogs" and InitiatingProcessFileName has "gogs")
| where ProcessCommandLine has "--exec"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessParentFileName,
    SHA256
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Gogs deployments using a renamed binary will not be detected; the binary name must match 'gogs' or 'gogs.exe'.
- Automated testing or CI/CD pipelines that invoke git rebase with '--exec' flags on the Gogs host outside of the Gogs process context could trigger if the parent process filter is broadened.

Tuning notes:
- Scope the query to known Gogs server device names using a DeviceName filter once the Gogs host inventory is confirmed, to reduce unnecessary scanning of the full DeviceProcessEvents table.
- Reduce the lookback to 1 day when scheduling as a recurring rule; 7 days is appropriate for initial deployment and historical sweep.

Risks / caveats:
- Gogs must be running on a Windows host enrolled in Defender for Endpoint with process creation events enabled; Linux-hosted Gogs deployments are not covered by this query.
- DeviceProcessEvents uses Timestamp as the primary time field in Defender XDR advanced hunting, not TimeGenerated; the improved KQL uses Timestamp.
- Gogs deployments using a renamed binary will evade this detection; if the binary is renamed, the InitiatingProcessFileName filter must be updated.
- Linux-hosted Gogs instances are not covered; a separate query targeting DeviceProcessEvents on Linux with the equivalent process name would be needed.

### Triage Runbook

First 15 minutes:
- Identify the Gogs host, the initiating account, and the child process name and command line from the alert.
- Review the process tree to confirm the child process was spawned by Gogs and not by an unrelated administrative or CI/CD process.
- Check whether the host is expected to run Gogs on Windows and whether the binary name matches the approved deployment.
- Look for immediate signs of compromise such as unusual child processes, script interpreters, network connections, or file creation on the host.

Evidence to collect:
- Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, ProcessId, InitiatingProcessId, and SHA256.
- Full process tree around the alert time, including parent and sibling processes.
- Gogs application logs and repository activity around the same timestamp, especially branch creation, rebase, or admin actions.
- Any outbound network connections, new services, scheduled tasks, or file modifications on the host after the event.

Pivot points:
- DeviceProcessEvents for the same DeviceName and time window to build the full process tree.
- DeviceNetworkEvents for the same host to identify outbound connections after the suspicious process starts.
- File and registry activity tables to look for persistence or dropped payloads.
- Gogs application or web access logs to identify the user, repository, and request that triggered the rebase.

Benign explanations:
- A renamed or custom Gogs binary may not match the expected parent process filter and can create unusual but legitimate process trees.
- Administrative or test activity on the Gogs host could invoke git operations, though '--exec' in a child command line is still unusual.
- The host may be running a development or CI workflow that resembles exploit behavior.
- A non-Gogs process with a similar name could be misidentified if the environment uses custom naming.

Escalation criteria:
- The child process is a script interpreter, shell, downloader, or other suspicious binary.
- There is evidence of outbound command-and-control, file drops, or persistence on the Gogs host.
- The Gogs host is internet-facing or the triggering request came from an external source.
- Multiple suspicious process creations occur from the same host or account.

Containment actions:
- Isolate the Gogs host from the network if malicious execution is confirmed or strongly suspected.
- Terminate the suspicious child process and any related spawned processes.
- Disable external access to the Gogs service or place it behind a maintenance window if exploitation is ongoing.
- Preserve process, application, and web logs before remediation.

Closure criteria:
- The process tree is confirmed as legitimate administrative or test activity.
- The alert is attributable to a known benign automation workflow and no suspicious follow-on activity exists.
- The host is not a Gogs server or the process lineage is explained by a renamed binary and approved activity.
- No evidence of payload execution, persistence, or outbound malicious activity is found.

---

## Detection 5: Apache ActiveMQ RCE via Jolokia addNetworkConnector Endpoint Access

### Detection Opportunity

Apache ActiveMQ exploited via the Jolokia addNetworkConnector endpoint, enabling remote code execution through an externally accessible management interface

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Apache ActiveMQ RCE, Gogs Rebase RCE, and Windows Kernel Pointer Enum — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026)
  - Context: A Metasploit module was published targeting Apache ActiveMQ RCE via the Jolokia addNetworkConnector endpoint. Jolokia is a JMX-HTTP bridge; the addNetworkConnector operation is rarely called legitimately from external sources, making network-level detection on this specific path low false-positive.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Apache ActiveMQ
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1059, Apache ActiveMQ, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- If RemoteUrl is not populated in the environment, the primary detection path will return no results; supplement with web access log analysis via CommonSecurityLog or Syslog if available.

Required telemetry:
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| where (
    isnotempty(RemoteUrl)
    and RemoteUrl has "jolokia"
    and RemoteUrl has "addNetworkConnector"
)
or (
    isempty(RemoteUrl)
    and InitiatingProcessFileName has_any ("activemq", "java")
    and RemotePort in (8161, 8778, 1099)
)
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    LocalPort,
    RemoteUrl,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate internal monitoring or management tools that call the Jolokia addNetworkConnector endpoint from authorized internal IP ranges will trigger; these should be suppressed by adding an exclusion for known management IP ranges.
- Security scanners performing vulnerability assessments against ActiveMQ will trigger.

Tuning notes:
- Validate whether RemoteUrl is populated for HTTP connections to ActiveMQ by querying DeviceNetworkEvents for any connections to the ActiveMQ host and checking the RemoteUrl field before relying on this detection.
- Add a RemoteIP exclusion for known internal management and monitoring IP ranges to suppress authorized Jolokia access.
- If Defender for Endpoint does not populate RemoteUrl for this traffic, consider deploying a Syslog-based detection against ActiveMQ access logs forwarded to Sentinel as a complementary detection.

Risks / caveats:
- RemoteUrl in DeviceNetworkEvents is only populated when Defender for Endpoint performs HTTP-layer inspection; for non-inspected connections the field is empty and the query returns no results.
- 'HttpConnectionInspected' is not a documented standard ActionType in Defender XDR DeviceNetworkEvents; using it may cause the ActionType filter to silently drop all results. Valid ActionTypes include 'ConnectionSuccess', 'InboundConnectionAccepted', 'ConnectionFailed', 'ConnectionRequest'.
- If ActiveMQ is not enrolled in Defender for Endpoint or runs on a platform without MDE sensor coverage, no results will be returned.
- The fallback condition using RemotePort and InitiatingProcessFileName is a weak signal that will produce false positives from any Java process communicating on ActiveMQ ports; it is included only as a coverage fallback when URL inspection is unavailable.

### Triage Runbook

First 15 minutes:
- Confirm the target host is an ActiveMQ server and identify whether the connection was inbound from an external or untrusted source.
- Review the RemoteUrl, RemoteIP, RemotePort, and InitiatingProcessFileName to verify the request path and whether it matches Jolokia addNetworkConnector access.
- Check whether the source IP belongs to an approved management, monitoring, or vulnerability scanning system.
- Look for signs of post-access compromise on the host, including new processes, unusual Java activity, service changes, or outbound connections.

Evidence to collect:
- Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, RemoteUrl, ActionType, InitiatingProcessFileName, and InitiatingProcessCommandLine.
- ActiveMQ application logs and Jolokia access logs for the same time window.
- Process and network telemetry from the ActiveMQ host to identify any spawned child processes or outbound connections.
- Host exposure details, including whether Jolokia is internet-facing or restricted to internal management networks.

Pivot points:
- DeviceNetworkEvents for the same host and time window to identify related HTTP or management traffic.
- DeviceProcessEvents on the ActiveMQ host to look for Java child processes, shells, or script interpreters after the request.
- Application logs or Syslog from ActiveMQ/Jolokia if available in Sentinel.
- Firewall or proxy logs to confirm the source IP and whether the request came from outside the trusted network.

Benign explanations:
- Authorized administrators or monitoring tools may legitimately access Jolokia from internal management ranges.
- Security scanners and vulnerability assessments can hit the addNetworkConnector endpoint.
- RemoteUrl may be empty or incomplete if HTTP inspection is not enabled, making the signal weaker than intended.
- The fallback port-based logic can surface normal Java traffic on ActiveMQ-related ports.

Escalation criteria:
- The source IP is external, unknown, or not in an approved management range.
- There is evidence of command execution, new processes, or persistence on the ActiveMQ host after the request.
- Multiple suspicious Jolokia requests occur from the same source or across multiple ActiveMQ hosts.
- The host is internet-facing and the endpoint should not be reachable from the observed source.

Containment actions:
- Block the suspicious source IP or restrict access to the Jolokia/ActiveMQ management interface if exploitation is suspected.
- Disable or isolate Jolokia exposure from untrusted networks until the host is reviewed.
- Preserve ActiveMQ, Jolokia, process, and network logs before making changes.
- If compromise is confirmed, isolate the host and coordinate credential rotation for any accounts used on the system.

Closure criteria:
- The request is confirmed as authorized management or monitoring activity.
- The source is a known scanner or internal test system and no follow-on compromise is observed.
- The endpoint is not externally reachable and the alert is explained by benign internal traffic or inspection artifacts.
- Host review shows no suspicious process execution, persistence, or unauthorized configuration changes.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Check Point VPN Auth Bypass - Successful Session Without Credential Validation (CVE-2026-50751): Check Point CEF connector must be configured with sufficient log verbosity to emit both session-establishment and authentication event types; if only one type is forwarded, the correlation is invalid.
- Check Point VPN Legacy Client Connection Without Certificate Authentication (CVE-2026-50751): Certificate authentication events may not be logged as distinct entries in all Check Point CEF connector configurations; if absent, the leftanti join cannot function as intended.
- PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257): PAN-OS threat logs must be forwarded to Sentinel via CEF connector with LogSeverity populated; if PAN-OS is forwarding only traffic logs or system logs, threat log entries will be absent.
- PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257): DeviceProduct string 'PAN-OS' must match the exact value emitted by the CEF connector; some PAN-OS connector configurations emit 'Palo Alto Networks Firewall' or 'NGFW' instead.

Schema / correlation keys:
- Check Point VPN Legacy Client Connection Without Certificate Authentication (CVE-2026-50751): Legacy client type strings in the Message and AdditionalExtensions fields are not standardized across Check Point firmware versions; if the gateway does not emit these strings, the query returns no results.
- PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257): Do not schedule yet; validate as an analyst-led hunt first.

Environment scope / baselines:
- Apache ActiveMQ RCE via Jolokia addNetworkConnector Endpoint Access: If RemoteUrl is not populated in the environment, the primary detection path will return no results; supplement with web access log analysis via CommonSecurityLog or Syslog if available.

Shared-table notes:
- CommonSecurityLog: shared by Check Point VPN Auth Bypass - Successful Session Without Credential Validation (CVE-2026-50751); Check Point VPN Legacy Client Connection Without Certificate Authentication (CVE-2026-50751); PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Gogs RCE via --exec Branch Name Triggering Command Injection on Rebase.
2. Resolve environment-mapping detections next: Check Point VPN Auth Bypass - Successful Session Without Credential Validation (CVE-2026-50751); Check Point VPN Legacy Client Connection Without Certificate Authentication (CVE-2026-50751); Apache ActiveMQ RCE via Jolokia addNetworkConnector Endpoint Access.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257).

### Hunting Agenda and Promotion Criteria

- PAN-OS High Severity Anomalous Activity - Active Exploitation Indicator (CVE-2026-0257): Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Check Point VPN Auth Bypass - Successful Session Without Credential Validation (CVE-2026-50751): Check Point CEF connector must be configured with sufficient log verbosity to emit both session-establishment and authentication event types; if only one type is forwarded, the correlation is invalid.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Check Point VPN Legacy Client Connection Without Certificate Authentication (CVE-2026-50751): Legacy client type strings in the Message and AdditionalExtensions fields are not standardized across Check Point firmware versions; if the gateway does not emit these strings, the query returns no results.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Apache ActiveMQ RCE via Jolokia addNetworkConnector Endpoint Access: If RemoteUrl is not populated in the environment, the primary detection path will return no results; supplement with web access log analysis via CommonSecurityLog or Syslog if available.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
