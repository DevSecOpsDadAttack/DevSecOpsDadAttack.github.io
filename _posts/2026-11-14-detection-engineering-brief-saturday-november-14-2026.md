---
layout: post
title: "Detection Engineering Brief - Saturday, November 14, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-14
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - ScreenConnect
  - Microsoft Defender XDR
  - CVE-2026-102895
  - GPUStack
  - VMware ESXi
  - vCenter
  - T1133
  - T1078
  - T1190
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 0 hunting-only, 4 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: ScreenConnect, Microsoft Defender XDR, CVE-2026-102895, GPUStack, VMware ESXi, vCenter, T1133, T1078, T1190.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SCKit - ScreenConnect Logon Targeting Privileged or Technician Accounts; CVE-2026-102895 - GPUStack Authentication Bypass Exploit Attempts; ESXi Ransomware - Hypervisor Shell Enable and Mass VM Shutdown; ESXi Ransomware - Anomalous Authentication to Hypervisor Management Interfaces.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SCKit - ScreenConnect Spawning Suspicious Child Processes

### Detection Opportunity

ScreenConnect process spawning unexpected child processes indicative of SCKit abuse for unauthorized remote access.

### Intelligence Context

- Microsoft Security Blog: SCKit abuses ScreenConnect to deploy remote access and target technician sessions — [https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)
  - Context: SCKit was reported to abuse ScreenConnect to deploy unauthorized remote access tools and target technician sessions, with activity visible in Microsoft Defender XDR telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1133, T1078
- Products: ScreenConnect, Microsoft Defender XDR
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: ScreenConnect, Microsoft Defender XDR, T1133, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1133 External Remote Services (high); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackHours = 48h;
let SuspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "net.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe"]);
let ScreenConnectParents = dynamic(["ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe"]);
let ScreenConnectProcs = DeviceProcessEvents
| where Timestamp > ago(LookbackHours)
| where InitiatingProcessFileName has_any (ScreenConnectParents)
| where FileName in~ (SuspiciousChildren)
| project DeviceId, DeviceName, AccountName, Timestamp, ChildProcess = FileName,
    ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let NetworkFollowOn = DeviceNetworkEvents
| where Timestamp > ago(LookbackHours)
| where InitiatingProcessFileName in~ (SuspiciousChildren)
| where RemotePort !in (80, 443)
| project DeviceId, NetTimestamp = Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName;
ScreenConnectProcs
| join kind=leftouter (
    NetworkFollowOn
) on DeviceId
| where isnull(NetTimestamp) or NetTimestamp between (Timestamp .. (Timestamp + 5m))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, ChildProcess, ProcessCommandLine,
    NetTimestamp, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IT automation scripts invoked through ScreenConnect remote sessions may spawn cmd.exe or powershell.exe.
- Software deployment workflows initiated by technicians via ScreenConnect may trigger certutil.exe or bitsadmin.exe.
- Monitoring or RMM tools that chain ScreenConnect with net.exe for inventory tasks will generate hits.

**Tuning notes:**
- Expand SuspiciousChildren to include regsvr32.exe, cscript.exe, or msiexec.exe if post-exploitation tooling in the environment uses those binaries.
- Add AccountName exclusions for known automation service accounts that legitimately use ScreenConnect to invoke scripting engines.
- Consider promoting to a scheduled rule with a 1-hour lookback and alert grouping by DeviceName to reduce alert volume.

**Risks / caveats:**
- DeviceNetworkEvents.RemoteUrl may be empty for non-HTTP connections; RemoteIP should be added as a fallback triage field to avoid silent data gaps.
- ScreenConnect may be installed under a custom service name in some environments; validate InitiatingProcessFileName values against DeviceProcessEvents before scheduling.
- The 5-minute network correlation window may miss delayed C2 beaconing; consider extending to 15 minutes for broader coverage at the cost of more join rows.
- Non-standard port filtering (excluding 80 and 443) will miss C2 over HTTPS; consider adding RemoteUrl-based filtering for known-bad domains if threat intel is available.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process is a known ScreenConnect service/client binary and identify the exact child process, command line, and account involved.
- Check whether the activity occurred during an approved remote support session and whether the account is a sanctioned technician or automation account.
- Review the network follow-on details for unusual remote IPs, non-standard ports, or repeated outbound connections from the child process.
- Look for additional suspicious process chains on the same host around the same time, especially cmd.exe, powershell.exe, wscript.exe, mshta.exe, certutil.exe, bitsadmin.exe, or rundll32.exe.

**Evidence to collect:**
- Device name, account name, timestamp, initiating process command line, child process name, child process command line, and any correlated remote URL/IP/port.
- ScreenConnect session records or helpdesk ticket references showing who initiated the session and why.
- Nearby DeviceProcessEvents and DeviceNetworkEvents for the same host to identify follow-on execution, downloads, or lateral movement.
- Any evidence of credential use or privilege escalation by the same account on the host or adjacent systems.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and a 2-hour window around the alert to enumerate parent/child chains.
- DeviceNetworkEvents for the same DeviceId and initiating process to identify external destinations and non-standard ports.
- DeviceLogonEvents for the same account to see whether the account logged on interactively or remotely around the same time.
- Microsoft Defender XDR advanced hunting pivots on DeviceName, AccountName, and InitiatingProcessCommandLine.

**Benign explanations:**
- Authorized technician troubleshooting through ScreenConnect may legitimately launch cmd.exe or powershell.exe.
- Software deployment or inventory scripts run by IT staff can trigger certutil.exe, bitsadmin.exe, or net.exe.
- RMM or monitoring tools may chain ScreenConnect with scripting binaries for routine administration.

**Escalation criteria:**
- The child process command line shows download, execution, credential access, or defense evasion behavior.
- The ScreenConnect session is not tied to a known ticket, approved technician, or expected maintenance window.
- The host shows additional suspicious activity such as new services, persistence, unusual outbound connections, or multiple post-exploitation binaries.
- The account involved is privileged, a technician account, or appears to be abused from an unexpected source.

**Containment actions:**
- If the session is unauthorized or clearly malicious, terminate the ScreenConnect session and isolate the affected host from the network.
- Disable or reset the involved account if there is evidence of credential abuse or unauthorized access.
- Preserve volatile evidence and collect process/network telemetry before rebooting or remediating the host.

**Closure criteria:**
- The activity is matched to a valid support ticket and the process tree is consistent with approved administration.
- No additional suspicious processes, network activity, or persistence mechanisms are found on the host.
- The account and ScreenConnect session are confirmed as expected and no other hosts show related activity.

<br/>
---
<br/>

## Detection 2: SCKit - ScreenConnect Logon Targeting Privileged or Technician Accounts

### Detection Opportunity

Remote logon events via ScreenConnect correlated with privileged or technician-named accounts, consistent with SCKit session hijacking behavior.

### Intelligence Context

- Microsoft Security Blog: SCKit abuses ScreenConnect to deploy remote access and target technician sessions — [https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)
  - Context: SCKit specifically targeted technician sessions through ScreenConnect, making logon events associated with technician-named or privileged accounts initiated via ScreenConnect a meaningful detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1133, T1078
- Products: ScreenConnect, Microsoft Defender XDR
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: ScreenConnect, Microsoft Defender XDR, T1133, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1133 External Remote Services (high); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- If InitiatingProcessFileName is not populated in DeviceLogonEvents for ScreenConnect sessions in the environment, this query will return zero results; validate with a count query before scheduling.

**Required telemetry:**
- DeviceLogonEvents

### KQL

```kql
let LookbackDays = 14d;
let TechnicianPatterns = dynamic(["tech", "admin", "helpdesk", "support", "svc"]);
DeviceLogonEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName has_any ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe")
| where LogonType in (10, 3)
| where AccountName has_any (TechnicianPatterns)
| summarize LogonCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName),
    RemoteIPs = make_set(RemoteIP)
    by AccountName, InitiatingProcessFileName
| order by LogonCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate technician accounts using ScreenConnect for authorized remote support will match the account name patterns.
- Scheduled tasks or service accounts with names containing svc or admin that authenticate via ScreenConnect will generate hits.
- Bulk IT operations performed by helpdesk staff during business hours will produce high LogonCount values.

**Tuning notes:**
- Add a LogonCount threshold filter (e.g., LogonCount > 3) if the environment has high-volume legitimate ScreenConnect usage by technician accounts.
- Consider adding a time-of-day filter using hourofday(Timestamp) to surface logons outside business hours as a higher-confidence signal.
- Cross-reference Devices list against a known-good device baseline for each AccountName to identify logons to unusual endpoints.

**Risks / caveats:**
- DeviceLogonEvents.InitiatingProcessFileName is not consistently populated for all logon types in all Defender XDR agent versions; if this field is empty for ScreenConnect-initiated logons in the environment, the query will return no results.
- DeviceLogonEvents does not include a standard field for the initiating remote IP of the ScreenConnect session, limiting the ability to identify the true session origin.
- TechnicianPatterns must be reviewed against the organization's Active Directory naming conventions before this query produces reliable signal; generic patterns will cause both false positives and false negatives.
- If InitiatingProcessFileName is not populated in DeviceLogonEvents for ScreenConnect sessions in the environment, this query will return zero results; validate with a count query before scheduling.

### Triage Runbook

**First 15 minutes:**
- Verify the account owner, role, and whether the logon aligns with an approved remote support session or maintenance window.
- Check the source IP and device for the logon and compare it to known ScreenConnect infrastructure, jump hosts, or expected technician locations.
- Review whether the same account logged on to unusual devices, outside business hours, or with an abnormal frequency.
- Confirm whether the logon type and initiating process are consistent with ScreenConnect behavior in your environment.

**Evidence to collect:**
- Account name, device name, device ID, logon type, first/last seen timestamps, and source IPs associated with the event.
- Helpdesk ticket, change record, or remote support approval tied to the account and device.
- Historical logon baseline for the account to determine whether the device and source IP are new or unusual.
- Any concurrent alerts for the same account, especially privilege changes, mailbox access, or lateral movement.

**Pivot points:**
- DeviceLogonEvents for the same account over 30 days to identify unusual devices, source IPs, and logon types.
- DeviceProcessEvents and DeviceNetworkEvents on the target device around the logon time for follow-on activity.
- Identity or Entra sign-in telemetry, if available, to compare ScreenConnect-initiated access with normal authentication patterns.
- Microsoft Defender XDR pivots on AccountName and DeviceName to find other impacted endpoints.

**Benign explanations:**
- Helpdesk or admin staff may legitimately use ScreenConnect to access endpoints for support or maintenance.
- Service accounts or automation accounts may contain admin/svc naming patterns and generate false positives.
- Bulk IT operations can create multiple logons from the same technician account during business hours.

**Escalation criteria:**
- The account is privileged and the logon source is not a known ScreenConnect or corporate support source.
- The logon occurred outside approved support windows or without a corresponding ticket.
- The same account shows access to multiple unexpected devices or signs of privilege abuse.
- There is evidence of session hijacking, credential theft, or subsequent malicious activity on the endpoint.

**Containment actions:**
- If unauthorized, disable or reset the account and revoke active sessions or tokens associated with it.
- Block or investigate the source IP if it is not an approved support endpoint.
- Isolate the affected device if follow-on malicious activity is observed.

**Closure criteria:**
- The logon is validated against a support ticket and the source IP/device are expected.
- The account is confirmed to be a legitimate technician or automation account with no abnormal follow-on activity.
- No additional suspicious logons or endpoint activity are found for the account or device.

<br/>
---
<br/>

## Detection 3: CVE-2026-102895 - GPUStack Authentication Bypass Exploit Attempts

### Detection Opportunity

Repeated unauthenticated or anomalous HTTP requests to GPUStack API endpoints consistent with exploitation of the authentication bypass vulnerability CVE-2026-102895.

### Intelligence Context

- SANS ISC: Exploit Attempts for GPUStack Authentication Bypass (CVE-2026-102895), (Thu, Nov 12th) — [https://isc.sans.edu/diary/rss/33514](https://isc.sans.edu/diary/rss/33514)
  - Context: Active exploit attempts were observed against CVE-2026-102895, a trivial authentication bypass in GPUStack versions prior to 2.2.0, generating anomalous unauthenticated HTTP requests to the GPUStack API.

### Search Metadata

- CVEs: CVE-2026-102895
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: GPUStack
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-102895, GPUStack, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let LookbackHours = 24h;
let GPUStackPorts = dynamic([80, 443, 8080, 8000]);
let AuthBypassThreshold = 5;
let CslBranch = CommonSecurityLog
| where TimeGenerated > ago(LookbackHours)
| where DestinationPort in (GPUStackPorts)
| where isnotempty(RequestURL)
| where RequestURL has_any ("/api/", "/v1/", "/auth", "/login")
| where isnotempty(SourceIP)
| summarize AttemptCount = count(),
    RequestPaths = make_set(RequestURL, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP, DestinationPort
| where AttemptCount >= AuthBypassThreshold
| extend HostName = "", SyslogSample = ""
| project FirstSeen, LastSeen, SourceIP, DestinationIP, DestinationPort, AttemptCount, RequestPaths, HostName, SyslogSample;
let SyslogBranch = Syslog
| where TimeGenerated > ago(LookbackHours)
| where SyslogMessage has_any ("/api/", "/v1/", "gpustack", "401", "403")
| where SyslogMessage !has "successful"
| summarize AttemptCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SyslogSample = any(SyslogMessage)
    by HostName
| where AttemptCount >= AuthBypassThreshold
| extend SourceIP = "", DestinationIP = "", DestinationPort = int(null), RequestPaths = dynamic([])
| project FirstSeen, LastSeen, SourceIP, DestinationIP, DestinationPort, AttemptCount, RequestPaths, HostName, SyslogSample;
CslBranch
| union SyslogBranch
| order by AttemptCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate API clients making repeated unauthenticated requests due to misconfigured authentication tokens will trigger the threshold.
- Security scanners or vulnerability assessment tools run against GPUStack by the organization's own security team will generate hits.
- Load balancer health checks targeting /api/ paths may accumulate above the threshold.

**Tuning notes:**
- Add HostName or DestinationIP filters scoped to known GPUStack server identifiers to reduce cross-host noise in shared Syslog or CommonSecurityLog tables.
- Adjust GPUStackPorts to match the actual deployment port if GPUStack is running on a non-standard port.
- Consider adding HTTP response code filtering in CommonSecurityLog using EventOutcome or AdditionalExtensions if the log source populates those fields.

**Risks / caveats:**
- CommonSecurityLog.RequestURL is only populated when the log source is a WAF, proxy, or application firewall forwarding HTTP-layer data; if GPUStack logs are forwarded as generic syslog, this field will be empty and the CommonSecurityLog branch will return no results.
- The union of CommonSecurityLog and Syslog produces incompatible column sets; the original query projects different columns from each branch, which will cause a schema mismatch error at runtime. The improved KQL resolves this by separating the branches.
- GPUStack has no native Microsoft Sentinel data connector; log availability depends entirely on a custom syslog or CEF forwarder configured by the organization.
- CommonSecurityLog.DestinationPort filtering on ports 80, 443, 8080, 8000 will miss GPUStack deployments on non-standard ports without environment-specific port configuration.

### Triage Runbook

**First 15 minutes:**
- Confirm the target host is actually running GPUStack and identify the exposed port, interface, and deployment path.
- Review the request paths, source IP, and attempt count to determine whether the traffic is a scanner, a targeted exploit attempt, or benign health checking.
- Check whether any requests succeeded after the unauthenticated attempts and whether there are signs of new sessions, admin actions, or unexpected API use.
- Validate whether the observed traffic matches known load balancer, proxy, or security scanner behavior in your environment.

**Evidence to collect:**
- Source IP, destination IP, destination port, request paths, first/last seen timestamps, and any syslog samples or HTTP request details.
- GPUStack version and exposure details, including whether the instance is internet-facing or behind a proxy/WAF.
- Application logs showing authentication outcomes, session creation, admin actions, or configuration changes around the alert time.
- Any correlated alerts on the same host, such as web shell activity, new processes, or outbound connections.

**Pivot points:**
- CommonSecurityLog for the same destination IP or source IP to find related HTTP requests and response patterns.
- Syslog for the GPUStack host to identify authentication failures, unexpected admin actions, or service errors.
- Firewall, proxy, or WAF logs to determine whether the source IP is external and whether the traffic was blocked or allowed.
- Host telemetry for the GPUStack server to look for process creation, file changes, or outbound connections after the attempt window.

**Benign explanations:**
- Legitimate API clients may generate repeated unauthenticated requests because of misconfigured tokens or expired credentials.
- Security testing or vulnerability scanning by your own team may resemble exploit traffic.
- Load balancer or health-check traffic can create repeated requests to API paths if misconfigured.

**Escalation criteria:**
- The source IP is external and the request pattern matches active exploitation rather than routine health checks.
- There is evidence of successful unauthorized access, new sessions, or administrative actions after the requests.
- The GPUStack host shows post-exploitation indicators such as new processes, unexpected outbound connections, or configuration changes.
- The instance is internet-facing and running a vulnerable version or unknown patch level.

**Containment actions:**
- If exploitation appears successful or highly likely, restrict access to the GPUStack service at the firewall, proxy, or WAF.
- Take the GPUStack instance out of service if needed to preserve evidence and prevent further abuse.
- Rotate any credentials or API tokens that may have been exposed or used during the attack window.

**Closure criteria:**
- The traffic is confirmed to be benign scanner, health-check, or misconfigured client activity.
- GPUStack logs show no successful bypass, no unauthorized sessions, and no follow-on malicious activity.
- The source is internal and tied to an approved security test or maintenance activity.

<br/>
---
<br/>

## Detection 4: ESXi Ransomware - Hypervisor Shell Enable and Mass VM Shutdown

### Detection Opportunity

ESXi shell enable events followed by mass virtual machine power-off commands, consistent with ransomware pre-encryption activity at the hypervisor layer.

### Intelligence Context

- Securelist: Ransomware at the hypervisor layer: how attackers use ESXi and vCenter features for malicious purposes — [https://securelist.com/esxi-ransomware/121959/](https://securelist.com/esxi-ransomware/121959/)
  - Context: Ransomware operators were reported to abuse ESXi and vCenter native features, including enabling the ESXi shell and issuing mass VM power-off commands, as part of hypervisor-layer ransomware deployment.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1133, T1078
- Products: VMware ESXi, vCenter
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: VMware ESXi, vCenter, T1133, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1133 External Remote Services (high); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
let LookbackHours = 48h;
let CorrelationWindow = 30m;
let ShellEnableEvents = Syslog
| where TimeGenerated > ago(LookbackHours)
| where SyslogMessage has_any (
    "ESXi Shell for the ESXi",
    "shell.set --enabled true",
    "vim-cmd hostsvc/enable_ssh",
    "vim-cmd hostsvc/enable_esx_shell",
    "SSH login enabled",
    "ESXi Shell is enabled"
  )
| project ShellTime = TimeGenerated, HostName, ShellMsg = SyslogMessage;
let VMShutdownEvents = Syslog
| where TimeGenerated > ago(LookbackHours)
| where SyslogMessage has_any (
    "vim-cmd vmsvc/power.off",
    "vim-cmd vmsvc/power.shutdown",
    "powerOff",
    "Powering off virtual machine",
    "esxcli vm process kill"
  )
| project ShutdownTime = TimeGenerated, HostName, ShutdownMsg = SyslogMessage;
ShellEnableEvents
| join kind=inner (
    VMShutdownEvents
) on HostName
| where ShutdownTime between (ShellTime .. (ShellTime + CorrelationWindow))
| summarize ShellTime = min(ShellTime),
    ShellMsg = any(ShellMsg),
    FirstShutdown = min(ShutdownTime),
    LastShutdown = max(ShutdownTime),
    ShutdownCount = count(),
    ShutdownSamples = make_set(ShutdownMsg, 5)
    by HostName
| order by ShutdownCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Planned maintenance windows where administrators enable the ESXi shell and then shut down VMs for patching will trigger this detection.
- Automated orchestration scripts that enable the shell for configuration management and subsequently power off VMs for snapshots will match.
- ESXi host reboots initiated by vCenter during update cycles may generate both shell enable and VM shutdown messages.

**Tuning notes:**
- Add a HostName filter scoped to known ESXi host name prefixes or suffixes to prevent matching on non-ESXi Linux hosts forwarding syslog to the same workspace.
- Increase ShutdownCount threshold to 3 or more to focus on mass VM shutdown rather than single-VM operations.
- Consider adding a time-of-day filter to flag sequences occurring outside scheduled maintenance windows.

**Risks / caveats:**
- ESXi syslog forwarding to Microsoft Sentinel requires explicit configuration of a syslog forwarder or direct ESXi syslog target pointing to the Sentinel Log Analytics workspace; this is not enabled by default and must be confirmed before the query can return results.
- Exact syslog message strings for ESXi shell enable and VM power-off commands vary across ESXi versions (6.x, 7.x, 8.x); the string patterns used must be validated against actual ESXi syslog output in the environment.
- ESXi syslog message formats differ between ESXi 6.x, 7.x, and 8.x; the string patterns must be validated against actual syslog output before the query is relied upon for detection.
- If the Syslog table contains mixed infrastructure (Linux servers, network devices, ESXi), the shell enable patterns may match non-ESXi SSH enable events; add HostName filtering to known ESXi host names to reduce cross-host noise.

### Triage Runbook

**First 15 minutes:**
- Identify the ESXi host, shell enable message, shutdown message, and the number of VMs affected within the correlation window.
- Check whether the activity aligns with a scheduled maintenance window, change ticket, or known automation job.
- Determine whether the shutdowns were mass power-offs across multiple VMs or a small set of expected administrative actions.
- Assess whether other hypervisor hosts show similar shell enable or shutdown activity in the same time period.

**Evidence to collect:**
- HostName, shell enable timestamp, shutdown timestamps, shutdown count, and representative syslog messages.
- vCenter or ESXi administrative logs showing who enabled the shell and from where.
- Change management records, maintenance approvals, or orchestration job logs for the affected host.
- Inventory of impacted VMs and whether they were intentionally powered off or unexpectedly unavailable.

**Pivot points:**
- Syslog for the same HostName before and after the alert to find related authentication, shell, and power events.
- vCenter logs or management plane telemetry for administrative actions on the same host and VMs.
- Other ESXi hosts in Syslog to determine whether the behavior is isolated or part of a broader campaign.
- Incident management or change records to validate whether the shutdowns were planned.

**Benign explanations:**
- Planned maintenance may require enabling the ESXi shell and powering off multiple VMs.
- Automation or orchestration scripts may temporarily enable shell access for configuration tasks.
- Host patching or reboot workflows can generate shell and VM shutdown messages.

**Escalation criteria:**
- The shell was enabled outside a maintenance window or by an unexpected account.
- Multiple VMs were powered off rapidly without a corresponding change record.
- Other hypervisors show similar activity, suggesting coordinated attack behavior.
- There are additional signs of ransomware preparation, such as backup deletion, snapshot tampering, or credential abuse.

**Containment actions:**
- If malicious activity is suspected, isolate the ESXi host from management access and restrict administrative credentials immediately.
- Preserve syslog and management-plane evidence before rebooting or making disruptive changes.
- Coordinate with virtualization operations to prevent further VM impact while investigating.

**Closure criteria:**
- The event is matched to a valid maintenance or automation record and the shutdowns are expected.
- No other hosts show related shell enable or mass shutdown behavior.
- There is no evidence of unauthorized access, ransomware preparation, or broader hypervisor compromise.

<br/>
---
<br/>

## Detection 5: ESXi Ransomware - Anomalous Authentication to Hypervisor Management Interfaces

### Detection Opportunity

Authentication to ESXi or vCenter management interfaces from unexpected source IPs, consistent with adversary initial access to hypervisors prior to ransomware deployment.

### Intelligence Context

- Securelist: Ransomware at the hypervisor layer: how attackers use ESXi and vCenter features for malicious purposes — [https://securelist.com/esxi-ransomware/121959/](https://securelist.com/esxi-ransomware/121959/)
  - Context: The reporting identified common access paths adversaries use to reach ESXi and vCenter, making authentication anomalies to hypervisor management interfaces a key early-stage detection opportunity before ransomware execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1133, T1078
- Products: VMware ESXi, vCenter
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: VMware ESXi, vCenter, T1133, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1133 External Remote Services (high); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
let LookbackDays = 14d;
let RecentWindow = 1d;
let AuthPatterns = dynamic([
    "Accepted password",
    "Accepted publickey",
    "session opened for user",
    "vpxd",
    "vCenter Server",
    "com.vmware.vim.sso"
]);
let HistoricSources = Syslog
| where TimeGenerated between (ago(LookbackDays) .. ago(RecentWindow))
| where SyslogMessage has_any (AuthPatterns)
| extend SourceIP = extract(@"from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize HistoricIPs = make_set(SourceIP) by HostName;
let RecentLogins = Syslog
| where TimeGenerated > ago(RecentWindow)
| where SyslogMessage has_any (AuthPatterns)
| extend SourceIP = extract(@"from ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})", 1, SyslogMessage)
| where isnotempty(SourceIP)
| project TimeGenerated, HostName, SourceIP, SyslogMessage;
RecentLogins
| join kind=leftouter (
    HistoricSources
) on HostName
| where not(SourceIP in (HistoricIPs))
| project TimeGenerated, HostName, SourceIP, SyslogMessage
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- New administrator workstations or jump hosts added to the environment within the baseline period will appear as new sources.
- VPN IP address changes for administrators who connect from dynamic IP ranges will generate hits on each new IP.
- Automated monitoring or backup systems that authenticate to ESXi from IPs not seen in the baseline window will trigger alerts.

**Tuning notes:**
- Add a HostName filter scoped to known ESXi and vCenter host name patterns to prevent matching on unrelated Linux hosts in the Syslog table.
- Consider adding a private IP exclusion (e.g., excluding RFC1918 ranges from SourceIP) if all legitimate management access originates from internal jump hosts and external IPs are always anomalous.
- Validate the regex extraction against actual ESXi SSH and vCenter syslog samples before scheduling; adjust the pattern if vCenter uses a different IP embedding format.

**Risks / caveats:**
- Syslog.HostIP is not a standard field in the Microsoft Sentinel Syslog table; the standard fields are HostName and Computer. The original query uses HostIP in the historic baseline make_set, which will produce an empty set and cause all recent logins to appear as new sources. The improved KQL replaces HostIP with extracted SourceIP from the syslog message text.
- ESXi syslog forwarding to Microsoft Sentinel requires explicit configuration per hypervisor host; without confirmed ingestion, the query returns no results.
- The regex pattern for extracting source IP from syslog message text is format-dependent; ESXi SSH authentication messages use 'from <IP> port <port>' format, but vCenter authentication messages use a different format that may not match the same regex.
- The regex pattern extracts the first IPv4 address matching the 'from <IP>' pattern in the syslog message; vCenter authentication log formats may embed the source IP differently, causing extraction failures for vCenter-sourced events.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, host, and account associated with the authentication and compare them to known admin jump hosts and management networks.
- Check whether the source IP is new relative to the historical baseline and whether the login occurred outside normal administrative hours.
- Review the syslog message to determine whether the event is an ESXi SSH login, vCenter authentication, or another management-plane access.
- Look for subsequent management actions on the same host, such as shell enablement, VM shutdowns, configuration changes, or account changes.

**Evidence to collect:**
- TimeGenerated, HostName, SourceIP, and the raw SyslogMessage for the authentication event.
- Historical baseline of known-good management source IPs for the host or vCenter instance.
- vCenter or ESXi audit logs showing the authenticated user, source, and any actions taken after login.
- Any correlated alerts on the same host or source IP, including shell enablement, VM power events, or suspicious admin activity.

**Pivot points:**
- Syslog for the same HostName and SourceIP over a wider time range to find repeated logins or follow-on actions.
- vCenter audit logs or ESXi management logs to identify the account and commands executed after authentication.
- Network/security logs to determine whether the source IP is internal, VPN-based, or external.
- Other hosts in Syslog to see whether the same source IP is attempting access across multiple hypervisors.

**Benign explanations:**
- A new administrator workstation, jump host, or VPN egress IP may legitimately appear as a new source.
- Planned maintenance or emergency response may use a source IP not seen in the baseline window.
- Backup, monitoring, or orchestration systems may authenticate from previously unseen infrastructure.

**Escalation criteria:**
- The source IP is external or otherwise not approved for hypervisor management.
- The account is privileged and the login is followed by shell enablement, VM shutdowns, or configuration changes.
- Multiple ESXi or vCenter hosts show similar anomalous authentication from the same source.
- The authentication cannot be tied to a known administrator, change ticket, or approved automation.

**Containment actions:**
- If unauthorized, block the source IP from management interfaces and disable or reset the involved account.
- Restrict ESXi/vCenter management access to approved admin networks only while investigating.
- Preserve logs and avoid disruptive remediation until the scope of access is understood.

**Closure criteria:**
- The source IP is confirmed as an approved admin, jump host, or automation system.
- The login is tied to a valid change or maintenance activity and no suspicious follow-on actions are found.
- No additional anomalous authentications or management actions are observed on related hosts.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Environment scope / baselines:**
- SCKit - ScreenConnect Logon Targeting Privileged or Technician Accounts: If InitiatingProcessFileName is not populated in DeviceLogonEvents for ScreenConnect sessions in the environment, this query will return zero results; validate with a count query before scheduling.

**Telemetry availability:**
- CVE-2026-102895 - GPUStack Authentication Bypass Exploit Attempts: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.
- ESXi Ransomware - Hypervisor Shell Enable and Mass VM Shutdown: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.
- ESXi Ransomware - Anomalous Authentication to Hypervisor Management Interfaces: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Shared-table notes:**
- Syslog: shared by CVE-2026-102895 - GPUStack Authentication Bypass Exploit Attempts; ESXi Ransomware - Hypervisor Shell Enable and Mass VM Shutdown; ESXi Ransomware - Anomalous Authentication to Hypervisor Management Interfaces

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SCKit - ScreenConnect Spawning Suspicious Child Processes.
2. Resolve environment-mapping detections next: SCKit - ScreenConnect Logon Targeting Privileged or Technician Accounts; CVE-2026-102895 - GPUStack Authentication Bypass Exploit Attempts; ESXi Ransomware - Hypervisor Shell Enable and Mass VM Shutdown; ESXi Ransomware - Anomalous Authentication to Hypervisor Management Interfaces.

### Hunting Agenda and Promotion Criteria

- SCKit - ScreenConnect Logon Targeting Privileged or Technician Accounts: If InitiatingProcessFileName is not populated in DeviceLogonEvents for ScreenConnect sessions in the environment, this query will return zero results; validate with a count query before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-102895 - GPUStack Authentication Bypass Exploit Attempts: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- ESXi Ransomware - Hypervisor Shell Enable and Mass VM Shutdown: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- ESXi Ransomware - Anomalous Authentication to Hypervisor Management Interfaces: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
