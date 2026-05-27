---
layout: post
title: "Detection Engineering Brief - Tuesday, May 26, 2026"
subtitle: "Machine-speed threat intelligence translated into detection engineering action."
date: 2026-05-26
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - MITRE ATT&CK

---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Deployment blockers or scheduling gates were identified for: Kerberos Relay Attempt from Linux Edge Host; Suspicious Child Process Spawned by Confluence JVM Accessing Credential Paths; Unauthenticated HTTP Request to Cisco SD-WAN Management Interface Matching CVE-2026-20182 Pattern; Package Manager Spawning Unexpected Child Process or Writing to Sensitive Path - TeamPCP Supply Chain.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Kerberos Relay Attempt from Linux Edge Host

### Detection Opportunity

Linux-based edge appliance (F5 BIG-IP) performing Kerberos relay to internal KDC as part of lateral movement chain

### Intelligence Context

- Microsoft Security Blog: From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5 and Confluence — [https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/](https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/)
  - Context: Attackers compromised an F5 BIG-IP edge appliance and used it to perform Kerberos relay attacks against the internal KDC, enabling lateral movement to internal servers including Confluence. The relay originated from a Linux host that would not normally generate Kerberos TGS requests.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1550 Use Alternate Authentication Material/ T1550.003 Pass the Ticket (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceNetworkEvents, DeviceLogonEvents

### KQL

```kql
let LookbackWindow = 7d;
let KnownKerberosClients = dynamic(["kinit", "kvno", "sssd", "winbindd", "krb5kdc", "adcli", "realm", "net"]);
let KerberosConnections = DeviceNetworkEvents
| where TimeGenerated > ago(LookbackWindow)
| where DestinationPort == 88
| where Protocol in ("Tcp", "Udp")
| where InitiatingProcessName !in~ (KnownKerberosClients)
| project KerberosTime = TimeGenerated, DeviceName, KDC_IP = RemoteIP, InitiatingProcessName, Protocol;
let LinuxLogons = DeviceLogonEvents
| where TimeGenerated > ago(LookbackWindow)
| where ActionType in ("LogonSuccess", "LogonAttempted")
| where LogonType == "Network"
| project LogonTime = TimeGenerated, DeviceName, AccountName, LogonRemoteIP = RemoteIP, LogonActionType = ActionType;
KerberosConnections
| join kind=inner LinuxLogons on DeviceName
| where LogonTime >= KerberosTime and datetime_diff('minute', LogonTime, KerberosTime) <= 10
| project
    KerberosTime,
    DeviceName,
    KDC_IP,
    InitiatingProcessName,
    Protocol,
    LogonTime,
    AccountName,
    LogonActionType,
    LogonRemoteIP,
    MinutesDelta = datetime_diff('minute', LogonTime, KerberosTime)
| order by KerberosTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Linux servers running SSSD, winbind, or custom Kerberos-aware applications not in the exclusion list will generate hits.
- Any Linux host that legitimately contacts a KDC on port 88 via a non-standard binary will appear, including custom automation scripts.
- Internal Linux servers with both Kerberos traffic and network logon activity within the time window will match regardless of edge appliance status.

Tuning notes:
- Add known edge appliance hostnames to a DeviceName filter to scope results to the relevant host population.
- Add internal KDC IP addresses as a RemoteIP allowlist filter to exclude connections to external Kerberos infrastructure.
- Extend KnownKerberosClients with any additional legitimate Kerberos client binaries observed in your Linux fleet via baseline review.

Risks / caveats:
- MDE sensor must be deployed on the Linux edge host and actively forwarding DeviceNetworkEvents and DeviceLogonEvents. If the F5 BIG-IP does not have an MDE sensor, neither table will contain records for that device and the query will return no results.
- Protocol field values in DeviceNetworkEvents are platform-dependent; confirm 'Tcp' and 'Udp' casing matches actual ingested values in your tenant before relying on the protocol filter.
- LogonType in DeviceLogonEvents for Linux hosts may not populate the 'Network' string consistently across all MDE Linux sensor versions; verify field population before scheduling.
- The InitiatingProcessName exclusion list requires environment-specific baselining to avoid both false positives and false negatives.

### Triage Runbook

First 15 minutes:
- Confirm the source host is the expected F5 BIG-IP or other edge appliance and verify it should not normally generate Kerberos TGS or network logon activity.
- Review the correlated Kerberos connection and logon timestamps, account name, and KDC IP to see whether the activity is consistent with relay behavior rather than normal service authentication.
- Check whether the initiating process name is a known Kerberos client or an unexpected binary/script on the appliance.
- Look for follow-on authentication or access to internal servers from the same source host or account within the same time window.

Evidence to collect:
- DeviceNetworkEvents for the source host around the KerberosTime, including RemoteIP, DestinationPort, Protocol, and InitiatingProcessName.
- DeviceLogonEvents for the same host and time window, including AccountName, LogonType, LogonActionType, and LogonRemoteIP.
- Host inventory or CMDB data confirming whether the device is an edge appliance and whether MDE coverage is expected on it.
- Any recent process execution telemetry on the appliance that shows new or unusual binaries, scripts, or admin activity.

Pivot points:
- Pivot on DeviceName to find other DeviceNetworkEvents to port 88 and other unusual outbound connections from the same host.
- Pivot on AccountName in DeviceLogonEvents to identify other hosts accessed by the same account in the last 24 hours.
- Search DeviceProcessEvents on the appliance for the initiating process name and any parent-child process chains around the alert time.
- Review KDC-side logs or authentication telemetry for the same source IP and account to confirm relay success.

Benign explanations:
- The host may be a legitimate Linux server or appliance running SSSD, winbind, or a custom Kerberos-aware application that was not added to the allowlist.
- A scheduled admin script or automation job may legitimately contact the KDC using a non-standard binary.
- The alert may be caused by an internal Linux server rather than an edge appliance if the hostname scoping is incomplete.

Escalation criteria:
- The source host is confirmed to be an edge appliance and the initiating process is not a known Kerberos client.
- The same account is observed authenticating to multiple internal systems shortly after the Kerberos connection.
- There is evidence of successful lateral movement, privilege escalation, or additional suspicious process activity on internal hosts.
- The KDC or downstream server logs show authentication patterns consistent with relay or ticket abuse.

Containment actions:
- Isolate the edge appliance or restrict its outbound access to the KDC if the activity is confirmed malicious and business impact is acceptable.
- Disable or reset any accounts observed in suspicious logon activity if they are not service accounts and compromise is likely.
- Block the source IP or appliance management interface at the network edge if the host is actively relaying and cannot be immediately remediated.
- Preserve volatile evidence and coordinate with the platform owner before rebooting or patching the appliance.

Closure criteria:
- The source host is validated as a legitimate Kerberos client and the process is approved by the platform owner.
- The correlated logon activity is explained by normal service authentication and no other suspicious pivots are found.
- No additional internal hosts, accounts, or KDC events indicate relay success or lateral movement.
- Any required allowlist or scoping updates are documented for future tuning.

---

## Detection 2: Suspicious Child Process Spawned by Confluence JVM Accessing Credential Paths

### Detection Opportunity

Credential theft from Confluence server via suspicious processes spawned under the Confluence JVM accessing credential store paths on Linux

### Intelligence Context

- Microsoft Security Blog: From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5 and Confluence — [https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/](https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/)
  - Context: After pivoting to the Confluence server, attackers spawned processes under the Confluence JVM to access credential stores on the Linux host. The JVM parent process (java) spawning shell utilities or credential-harvesting tools accessing sensitive file paths is the key behavioral indicator.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores (medium); Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let LookbackWindow = 7d;
let ConfluenceJVMPath = "/opt/atlassian/confluence";
let SuspiciousChildBinaries = dynamic(["bash", "sh", "dash", "curl", "wget", "cat", "base64", "python", "python3", "perl", "openssl", "klist", "id", "whoami", "find", "grep", "awk", "sed"]);
let CredentialFileNames = dynamic(["passwd", "shadow", "krb5.keytab", "id_rsa", "id_ecdsa", "id_ed25519", "confluence.cfg.xml", ".bash_history", "authorized_keys"]);
let CredentialPaths = dynamic(["/etc", "/root", "/home", "/opt/atlassian/confluence/confluence/WEB-INF", ".ssh", ".keytab", "krb5"]);
let ConfluenceChildProcs = DeviceProcessEvents
| where TimeGenerated > ago(LookbackWindow)
| where InitiatingProcessName =~ "java"
| where InitiatingProcessFolderPath has ConfluenceJVMPath
| where FileName in~ (SuspiciousChildBinaries)
| project ProcTime = TimeGenerated, DeviceName, AccountName, ProcessCommandLine, SpawnedFileName = FileName, InitiatingProcessFolderPath;
let CredFileAccess = DeviceFileEvents
| where TimeGenerated > ago(LookbackWindow)
| where ActionType in ("FileAccessed", "FileRead", "FileCreated")
| where FolderPath has_any (CredentialPaths)
| where FileName has_any (CredentialFileNames)
| project FileAccessTime = TimeGenerated, DeviceName, FolderPath, AccessedFileName = FileName, FileActionType = ActionType;
ConfluenceChildProcs
| join kind=leftouter CredFileAccess on DeviceName
| where isnotempty(FileAccessTime) and FileAccessTime >= ProcTime and datetime_diff('minute', FileAccessTime, ProcTime) <= 5
| project
    ProcTime,
    DeviceName,
    AccountName,
    InitiatingProcessFolderPath,
    ProcessCommandLine,
    SpawnedFileName,
    FileAccessTime,
    FolderPath,
    AccessedFileName,
    FileActionType
| order by ProcTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate Confluence maintenance scripts run by administrators under the Confluence service account will match if they invoke shell utilities.
- Confluence backup or diagnostic processes that read configuration files will generate file access matches.
- Other Java applications installed under /opt/atlassian/ (e.g., Jira) will match if the folder path filter is not sufficiently specific.

Tuning notes:
- Scope DeviceName to known Confluence server hostnames to avoid matching other Java application servers in the estate.
- Add the Confluence service account name as an AccountName filter once identified to reduce false positives from administrator activity.
- Extend CredentialFileNames and CredentialPaths based on credential paths identified during incident investigation.
- Consider splitting into two separate detections: one for process spawn (higher confidence) and one for file access correlation (broader coverage).

Risks / caveats:
- MDE sensor must be deployed on the Confluence Linux host with file access telemetry enabled. DeviceFileEvents coverage for Linux file reads depends on MDE sensor configuration and may not capture all file access events by default.
- InitiatingProcessFolderPath is used to scope to Confluence JVM paths; if the Confluence installation path differs from /opt/atlassian/confluence, the path filter will not match.
- If Confluence is installed to a non-default path, the ConfluenceJVMPath variable must be updated to match the actual installation directory.
- DeviceFileEvents on Linux may not capture all file read events depending on MDE sensor audit configuration; file access telemetry gaps could cause the file correlation to miss events.

### Triage Runbook

First 15 minutes:
- Confirm the host is a Confluence server and that the java process path matches the expected Confluence installation directory.
- Inspect the spawned child process name and command line to determine whether it is a shell, downloader, recon tool, or credential access utility.
- Review the file access event to see which credential path or sensitive file was touched and whether the access was read-only or involved modification.
- Check whether the activity occurred under the Confluence service account or an unexpected administrative account.

Evidence to collect:
- DeviceProcessEvents for the Confluence host around the alert time, including parent and child process command lines, account name, and initiating process folder path.
- DeviceFileEvents for the same host and time window, including folder path, file name, and action type.
- Service configuration or process inventory showing the expected Confluence JVM path and service account.
- Any recent authentication, SSH, or privilege escalation activity on the host.

Pivot points:
- Pivot on DeviceName to enumerate all child processes spawned by java on the Confluence host in the last 24 hours.
- Pivot on AccountName to identify other hosts or services accessed by the same account.
- Search DeviceFileEvents for reads or modifications to /etc, /root, /home, .ssh, keytab, and Confluence configuration files.
- Review DeviceNetworkEvents from the same host for outbound connections to unusual IPs or download destinations.

Benign explanations:
- Legitimate Confluence maintenance, backup, or diagnostic scripts may spawn shell utilities and read configuration files.
- Other Java applications on the same host may be misidentified if the folder path scoping is incomplete.
- An administrator may have run troubleshooting commands under the Confluence service account during maintenance.

Escalation criteria:
- The child process is a known credential theft, recon, or download tool and is not part of approved maintenance.
- Sensitive files such as shadow, keytab, SSH keys, or Confluence secrets were accessed unexpectedly.
- There is evidence of additional post-exploitation activity such as outbound C2, privilege escalation, or persistence.
- The activity occurred outside a maintenance window or under an account that should not have interactive access.

Containment actions:
- Isolate the Confluence server if malicious process execution or credential access is confirmed.
- Disable or rotate credentials and key material that may have been exposed, including service account secrets and SSH keys.
- Terminate the suspicious child process and preserve the parent java process and file access evidence before remediation.
- Block any observed outbound destinations if the host is making follow-on connections.

Closure criteria:
- The spawned process is validated as an approved maintenance or backup utility.
- The file access is explained by documented administrative activity and no sensitive secrets were exposed.
- No additional suspicious child processes, file reads, or network connections are present.
- The Confluence path and service account are confirmed and any tuning updates are recorded.

---

## Detection 3: Unauthenticated HTTP Request to Cisco SD-WAN Management Interface Matching CVE-2026-20182 Pattern

### Detection Opportunity

Authentication bypass exploitation against Cisco Catalyst SD-WAN Controller management interface via crafted HTTP requests matching Metasploit module path patterns for CVE-2026-20182

### Intelligence Context

- Rapid7: Metasploit Wrap Up 05/22/2026 — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-22-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-22-2026)
  - Context: Rapid7 published a Metasploit module for CVE-2026-20182, an authentication bypass vulnerability in Cisco Catalyst SD-WAN Controller. The module targets the management interface via HTTP requests that bypass authentication controls. Detection relies on perimeter log ingestion from the SD-WAN appliance into Sentinel via CommonSecurityLog.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog connector must be configured and the Cisco SD-WAN Controller must be sending syslog to the Sentinel workspace. If the connector is absent or the device is not forwarding logs, the table will contain no relevant records.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let LookbackDays = 7d;
let ManagementPorts = dynamic([443, 8443, 8080, 80]);
let SDWanPaths = dynamic(["/dataservice", "/apidocs", "/j_security_check", "/login", "/admin"]);
let RFC1918 = dynamic(["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]);
CommonSecurityLog
| where TimeGenerated > ago(LookbackDays)
| where DeviceVendor =~ "Cisco"
| where DestinationPort in (ManagementPorts)
| where RequestURL has_any (SDWanPaths)
| where isnotempty(SourceIP)
| where not(SourceIP has_any (RFC1918))
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    URLs = make_set(RequestURL, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP, DestinationPort, DeviceVendor
| where RequestCount >= 3
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate external administrators accessing the SD-WAN management interface from known IPs will match; allowlisting known admin source IPs will reduce this.
- Security scanners and vulnerability assessment tools targeting the management interface will generate hits.
- Load balancer health checks or monitoring probes hitting management paths will appear if sourced from non-RFC1918 addresses.

Tuning notes:
- Add a DestinationIP filter scoped to the specific SD-WAN controller management IP once confirmed in the environment.
- Allowlist known external administrator source IPs to reduce false positives from legitimate management access.
- Adjust RequestCount threshold after reviewing baseline management interface traffic volume over a 7-day period.
- Confirm the exact DeviceVendor string value in CommonSecurityLog for the SD-WAN syslog source before scheduling.

Risks / caveats:
- CommonSecurityLog connector must be configured and the Cisco SD-WAN Controller must be sending syslog to the Sentinel workspace. If the connector is absent or the device is not forwarding logs, the table will contain no relevant records.
- RequestURL field population in CommonSecurityLog depends on the Cisco SD-WAN syslog format and verbosity settings. If HTTP request URLs are not included in the syslog output, the RequestURL filter will match nothing.
- DeviceVendor string 'Cisco' must exactly match the value ingested from the SD-WAN syslog source. Cisco devices may log with different vendor strings depending on the syslog format configured on the appliance.
- DestinationIP is not scoped to the SD-WAN controller management IP in the base query, meaning all Cisco devices forwarding to CommonSecurityLog will be evaluated. This is a required environment-specific mapping before the query is meaningful.

### Triage Runbook

First 15 minutes:
- Confirm the destination IP is the actual SD-WAN controller management interface and not another Cisco device.
- Review the source IP, request paths, and request count to determine whether this is a single probe, scanner activity, or repeated exploitation attempt.
- Check whether the requests came from an external IP or from an internal admin/monitoring source that should be allowlisted.
- Look for signs of successful exploitation such as new sessions, configuration changes, or unusual management actions after the requests.

Evidence to collect:
- CommonSecurityLog entries for the source IP and destination IP around the alert window, including RequestURL, DestinationPort, and any available action fields.
- Device or appliance logs showing authentication failures, session creation, or management actions following the suspicious requests.
- Network perimeter logs to confirm whether the source IP is external and whether the traffic was allowed or blocked.
- Baseline management access records for known administrator source IPs and expected request paths.

Pivot points:
- Pivot on SourceIP in CommonSecurityLog to find other requests to the same controller or other Cisco management interfaces.
- Pivot on DestinationIP to review all inbound management traffic to the SD-WAN controller during the same period.
- Search for repeated RequestURL values or path enumeration patterns from the same source IP.
- Review firewall or proxy logs for the same source IP to identify broader scanning or exploitation activity.

Benign explanations:
- A legitimate external administrator may be accessing the management interface from a known IP address.
- A vulnerability scanner or security assessment tool may be testing the interface.
- Load balancer health checks or monitoring probes may hit management paths if they originate from non-RFC1918 addresses.

Escalation criteria:
- The source IP is external and not a known administrator or approved scanner.
- Multiple requests target management or authentication paths in a short period, indicating active exploitation.
- There are signs of successful access, configuration changes, or new sessions on the controller.
- The controller is internet-facing and the request pattern matches known exploit behavior.

Containment actions:
- Block the source IP at the perimeter if exploitation is suspected and the IP is not trusted.
- Restrict management interface access to approved admin networks if exposure is broader than intended.
- Place the controller into a monitored maintenance state or isolate it if compromise is confirmed and business impact is acceptable.
- Preserve logs and configuration state before making changes to the appliance.

Closure criteria:
- The source IP is confirmed as a trusted administrator or approved scanner.
- The request pattern is explained by normal management activity and no post-request compromise indicators exist.
- The destination IP is validated and the detection is scoped correctly for future alerts.
- Any allowlist or destination scoping updates are documented.

---

## Detection 4: Trojanized Microsoft Python SDK - Outbound C2 Connection Following Package Installation

### Detection Opportunity

Python process making outbound network connections to non-Microsoft infrastructure shortly after pip installation of a trojanized Microsoft-published Python SDK as part of the TeamPCP supply chain campaign

### Intelligence Context

- SANS ISC: TeamPCP Supply Chain Campaign: Activity Through 2026-05-24, (Mon, May 25th) — [https://isc.sans.edu/diary/rss/33016](https://isc.sans.edu/diary/rss/33016)
  - Context: The TeamPCP campaign trojanized a Microsoft-published Python SDK distributed via PyPI. When installed via pip, the malicious package executes code that initiates outbound connections to attacker-controlled infrastructure. The compound signal of pip execution followed within minutes by Python-initiated outbound connections to non-Microsoft IPs is the key behavioral indicator.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackWindow = 7d;
let CorrelationWindowMinutes = 10;
let MicrosoftIPPrefixes = dynamic(["20.", "40.", "13.", "51.", "52.", "104."]);
let TrustedDomains = dynamic(["microsoft.com", "azure.com", "pypi.org", "files.pythonhosted.org", "azureedge.net", "msftconnecttest.com"]);
let PipInstalls = DeviceProcessEvents
| where TimeGenerated > ago(LookbackWindow)
| where FileName in~ ("pip", "pip3", "pip.exe")
| where ProcessCommandLine has "install"
| project InstallTime = TimeGenerated, DeviceName, ProcessCommandLine, InstallAccount = AccountName;
let PythonOutbound = DeviceNetworkEvents
| where TimeGenerated > ago(LookbackWindow)
| where InitiatingProcessName in~ ("python", "python3", "python.exe")
| where ActionType == "ConnectionSuccess"
| where not(RemoteIP has_any (MicrosoftIPPrefixes))
| where not(RemoteUrl has_any (TrustedDomains))
| project ConnectTime = TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessName, InitiatingProcessParentFileName;
PipInstalls
| join kind=inner PythonOutbound on DeviceName
| where ConnectTime > InstallTime
| where datetime_diff('minute', ConnectTime, InstallTime) <= CorrelationWindowMinutes
| project
    DeviceName,
    InstallAccount,
    InstallTime,
    ProcessCommandLine,
    ConnectTime,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    InitiatingProcessName,
    InitiatingProcessParentFileName,
    MinutesDelta = datetime_diff('minute', ConnectTime, InstallTime)
| order by InstallTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Python packages with legitimate post-install network activity (e.g., license validation, telemetry, update checks) will match if they connect to non-Microsoft IPs within the time window.
- CI/CD pipelines that install packages and immediately run tests connecting to external APIs will generate hits.
- Developer environments with custom PyPI mirrors or artifact repositories not in the exclusion list will produce false positives.

Tuning notes:
- Extend TrustedDomains with internal PyPI mirrors, artifact repositories, and other trusted Python package sources specific to the environment.
- Scope DeviceName to developer workstations and CI/CD build hosts using a device group or hostname pattern to reduce noise from servers.
- Consider parsing ProcessCommandLine to extract the installed package name and adding it to the alert output for faster triage.
- Adjust CorrelationWindowMinutes based on observed post-install execution timing in the environment after reviewing baseline pip activity.

Risks / caveats:
- MDE sensor must be deployed on developer workstations and CI/CD build hosts where pip execution occurs. If these hosts are not onboarded to MDE, DeviceProcessEvents will contain no pip records.
- RemoteUrl field in DeviceNetworkEvents may not be populated for all outbound connections depending on the protocol and MDE sensor version; detections relying on RemoteUrl filtering may miss connections where only RemoteIP is recorded.
- Microsoft IP prefix exclusions cover common Azure ranges but are not exhaustive; additional Microsoft-owned prefixes may need to be added based on observed false positives.
- The 10-minute correlation window may miss trojanized packages with delayed execution or may be too wide for environments with high Python network activity.

### Triage Runbook

First 15 minutes:
- Confirm the pip command line and package name to determine whether the installation was from a trusted source or an unexpected dependency.
- Review the outbound connection details, including RemoteIP, RemoteUrl, and RemotePort, to assess whether the destination is suspicious or related to legitimate Microsoft infrastructure.
- Check whether the Python process was spawned directly by pip or by another installer, script, or CI job.
- Identify the user or service account that performed the installation and whether the host is a developer workstation, build server, or production system.

Evidence to collect:
- DeviceProcessEvents showing the pip installation command line, account name, and parent process chain.
- DeviceNetworkEvents showing the Python outbound connection, destination IP, URL, port, and connection success status.
- Package manager logs, build logs, or shell history that identify the exact package version and source index used.
- Host inventory data to determine whether the device is a developer endpoint, CI/CD runner, or server.

Pivot points:
- Pivot on DeviceName to find other Python processes and outbound connections within the same 24-hour period.
- Pivot on InstallAccount to identify other hosts where the same user installed packages recently.
- Search DeviceProcessEvents for additional pip, python, or package manager executions with the same package name or command line pattern.
- Review proxy, DNS, or firewall logs for the RemoteIP or RemoteUrl to determine whether the destination is newly observed.

Benign explanations:
- A legitimate package may perform post-install telemetry, license validation, or update checks to non-Microsoft infrastructure.
- CI/CD pipelines may install packages and immediately run tests that connect to external APIs.
- The destination may be a trusted internal mirror or artifact repository not covered by the current allowlist.

Escalation criteria:
- The package name or source index is unexpected, unsigned, or not approved for the environment.
- The outbound destination is newly observed, untrusted, or associated with threat intelligence.
- The Python process persists, spawns additional suspicious processes, or makes repeated connections after installation.
- Multiple hosts or accounts show the same package-to-connection pattern, indicating broader supply chain impact.

Containment actions:
- Isolate the host if the package is confirmed malicious or the outbound destination is clearly attacker-controlled.
- Remove the trojanized package and rotate any credentials or tokens that may have been exposed on the host.
- Block the destination IP or domain at the proxy or firewall if it is confirmed malicious.
- Pause affected build pipelines or developer workflows until package provenance is verified.

Closure criteria:
- The package is verified as legitimate and the outbound connection is explained by approved application behavior.
- The destination is a trusted service, mirror, or internal endpoint and no other suspicious activity is present.
- No additional hosts show the same package-to-connection pattern.
- Any required allowlist updates or package provenance notes are documented.

---

## Detection 5: Package Manager Spawning Unexpected Child Process or Writing to Sensitive Path - TeamPCP Supply Chain

### Detection Opportunity

Package manager processes (pip, npm, gem) spawning unexpected child processes or writing files outside expected package directories following installation, consistent with TeamPCP multi-ecosystem supply chain compromise

### Intelligence Context

- SANS ISC: TeamPCP Supply Chain Campaign: Activity Through 2026-05-24, (Mon, May 25th) — [https://isc.sans.edu/diary/rss/33016](https://isc.sans.edu/diary/rss/33016)
  - Context: The TeamPCP campaign compromised packages across multiple ecosystems including Python, npm, and gem. Malicious packages execute post-install hooks that spawn shell processes or write payloads to sensitive system paths outside the expected package installation directories. This behavior is observable via process and file telemetry.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (medium); Persistence: T1547 Boot or Logon Autostart Execution (low); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let LookbackWindow = 7d;
let CorrelationWindowMinutes = 3;
let SensitivePaths = dynamic(["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/tmp", "/var/tmp", "C:\\Windows\\System32", "C:\\Windows\\Temp", "C:\\ProgramData"]);
let LegitInstallPaths = dynamic(["/usr/local/lib/python", "/usr/lib/python", "node_modules", "/usr/local/lib/node", "/var/lib/gems"]);
let PackageManagerProcs = DeviceProcessEvents
| where TimeGenerated > ago(LookbackWindow)
| where InitiatingProcessName in~ ("pip", "pip3", "npm", "gem", "yarn", "pip.exe", "npm.cmd")
| where FileName in~ ("bash", "sh", "dash", "cmd.exe", "powershell.exe", "python", "python3", "perl", "ruby", "curl", "wget", "nc", "ncat")
| project SpawnTime = TimeGenerated, DeviceName, InitiatingProcessName, InitiatingProcessCommandLine, SpawnedProcess = FileName, ProcessCommandLine, AccountName;
let SensitiveWrites = DeviceFileEvents
| where TimeGenerated > ago(LookbackWindow)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (SensitivePaths)
| where not(FolderPath has_any (LegitInstallPaths))
| project WriteTime = TimeGenerated, DeviceName, SensitiveFolderPath = FolderPath, WrittenFile = FileName, FileActionType = ActionType;
PackageManagerProcs
| join kind=inner SensitiveWrites on DeviceName
| where WriteTime >= SpawnTime and datetime_diff('minute', WriteTime, SpawnTime) <= CorrelationWindowMinutes
| project
    DeviceName,
    AccountName,
    SpawnTime,
    InitiatingProcessName,
    InitiatingProcessCommandLine,
    SpawnedProcess,
    ProcessCommandLine,
    WriteTime,
    SensitiveFolderPath,
    WrittenFile,
    FileActionType,
    MinutesDelta = datetime_diff('minute', WriteTime, SpawnTime)
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate npm or pip packages with post-install scripts that invoke shell utilities for configuration will match.
- Build systems that run shell scripts as part of package installation and write build artifacts to system paths will generate hits.
- System package managers (apt, yum) that invoke pip or npm as part of system package installation may appear if the parent process chain is not filtered.

Tuning notes:
- Scope DeviceName to developer workstations and CI/CD build hosts to reduce noise from servers where package managers are not expected.
- Extend LegitInstallPaths with environment-specific package installation directories where legitimate post-install scripts write files.
- Consider splitting into separate Linux and Windows variants to apply OS-appropriate path filters and reduce cross-platform noise.
- Review SpawnedProcess list against baseline package manager child process activity in the environment to identify legitimate binaries that should be excluded.

Risks / caveats:
- MDE sensor must be deployed on hosts where package managers are used. If developer workstations or CI/CD build hosts are not onboarded to MDE, DeviceProcessEvents will contain no package manager records.
- DeviceFileEvents coverage for sensitive system paths on Linux depends on MDE sensor audit configuration. File write events to /etc, /usr/bin, and /sbin may not be captured by default without explicit audit rules configured on the Linux host.
- The SensitivePaths list includes /tmp and /var/tmp which are high-traffic directories; the inner join requirement mitigates but does not eliminate noise from these paths.
- LegitInstallPaths exclusion list covers common Python and Node.js installation directories but may not cover all legitimate package installation paths in the environment.

### Triage Runbook

First 15 minutes:
- Identify the package manager, child process, and command line to see whether the spawned process is a shell, downloader, or scripting interpreter.
- Review the file write path to determine whether the write occurred in a sensitive system location or a normal package installation directory.
- Confirm whether the host is a developer workstation, CI/CD runner, or server where package installation is expected.
- Check whether the activity occurred during a known software deployment, build, or maintenance window.

Evidence to collect:
- DeviceProcessEvents showing the package manager command line, spawned process name, and parent-child relationship.
- DeviceFileEvents showing the written file path, file name, action type, and timing relative to the process spawn.
- Package installation logs or build logs that identify the package name and installation source.
- Host role information to determine whether the activity is expected on this system.

Pivot points:
- Pivot on DeviceName to find other package manager executions and file writes in the same time window.
- Pivot on AccountName to identify whether the same user is installing packages on multiple hosts.
- Search DeviceProcessEvents for repeated shell, curl, wget, python, ruby, or powershell child processes spawned by package managers.
- Review DeviceFileEvents for writes to /etc, /usr/bin, /sbin, C:\Windows\System32, and C:\ProgramData from the same host.

Benign explanations:
- Legitimate package installation scripts may invoke shell utilities to configure dependencies or compile native extensions.
- Build systems may write artifacts to temporary or system-adjacent paths as part of packaging or deployment.
- Some package ecosystems legitimately run post-install hooks that appear unusual without package context.

Escalation criteria:
- The spawned child process is clearly a downloader, shell, or interpreter executing unexpected commands.
- Files are written outside expected package directories or into sensitive system paths without a documented reason.
- The same package or behavior appears on multiple hosts, suggesting a broader supply chain issue.
- The host is a production system where package installation should not normally occur.

Containment actions:
- Stop the installation or build job if malicious behavior is confirmed and the process is still active.
- Isolate the host if the package manager is writing to sensitive paths or spawning suspicious processes outside approved workflows.
- Remove any dropped files or persistence artifacts after preserving evidence.
- Block the package source or version in internal repositories if the package is confirmed malicious.

Closure criteria:
- The package manager activity is tied to an approved installation, build, or deployment process.
- The child process and file writes are explained by the package’s documented behavior or by a known build workflow.
- No sensitive path writes or suspicious child processes remain unexplained.
- The package, path, or host scoping is tuned if the alert was caused by expected activity.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- Kerberos Relay Attempt from Linux Edge Host: Do not schedule yet; validate as an analyst-led hunt first.
- Suspicious Child Process Spawned by Confluence JVM Accessing Credential Paths: Do not schedule yet; validate as an analyst-led hunt first.
- Package Manager Spawning Unexpected Child Process or Writing to Sensitive Path - TeamPCP Supply Chain: Do not schedule yet; validate as an analyst-led hunt first.

Telemetry availability:
- Unauthenticated HTTP Request to Cisco SD-WAN Management Interface Matching CVE-2026-20182 Pattern: CommonSecurityLog connector must be configured and the Cisco SD-WAN Controller must be sending syslog to the Sentinel workspace. If the connector is absent or the device is not forwarding logs, the table will contain no relevant records.

Shared-table notes:
- DeviceNetworkEvents: shared by Kerberos Relay Attempt from Linux Edge Host; Trojanized Microsoft Python SDK - Outbound C2 Connection Following Package Installation
- DeviceProcessEvents: shared by Suspicious Child Process Spawned by Confluence JVM Accessing Credential Paths; Trojanized Microsoft Python SDK - Outbound C2 Connection Following Package Installation; Package Manager Spawning Unexpected Child Process or Writing to Sensitive Path - TeamPCP Supply Chain
- DeviceFileEvents: shared by Suspicious Child Process Spawned by Confluence JVM Accessing Credential Paths; Package Manager Spawning Unexpected Child Process or Writing to Sensitive Path - TeamPCP Supply Chain

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Trojanized Microsoft Python SDK - Outbound C2 Connection Following Package Installation.
2. Resolve environment-mapping detections next: Unauthenticated HTTP Request to Cisco SD-WAN Management Interface Matching CVE-2026-20182 Pattern.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Kerberos Relay Attempt from Linux Edge Host; Suspicious Child Process Spawned by Confluence JVM Accessing Credential Paths; Package Manager Spawning Unexpected Child Process or Writing to Sensitive Path - TeamPCP Supply Chain.

### Hunting Agenda and Promotion Criteria

- Kerberos Relay Attempt from Linux Edge Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Suspicious Child Process Spawned by Confluence JVM Accessing Credential Paths: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Package Manager Spawning Unexpected Child Process or Writing to Sensitive Path - TeamPCP Supply Chain: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Unauthenticated HTTP Request to Cisco SD-WAN Management Interface Matching CVE-2026-20182 Pattern: CommonSecurityLog connector must be configured and the Cisco SD-WAN Controller must be sending syslog to the Sentinel workspace. If the connector is absent or the device is not forwarding logs, the table will contain no relevant records.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack Threat Intelligence and Detection Engineering. Validate all detections before deployment. Stay dangerous._
