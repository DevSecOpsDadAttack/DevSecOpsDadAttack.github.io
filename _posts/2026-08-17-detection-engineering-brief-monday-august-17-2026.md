---
layout: post
title: "Detection Engineering Brief - Monday, August 17, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-17
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-46300
  - T1190
  - WordPress
  - Ghost CMS
  - Joomla
  - Langflow
  - OpenCATS
  - Pterodactyl Panel
  - SonicWall SMA1000
  - Ray Dashboard
  - Pix-for-WooCommerce
  - Metasploit
  - Linux
  - Windows
  - Metasploit Framework
  - HoneyMyte
  - CoolClient
  - Armored Likho
  - Still Toolkit
  - Telegram
  - T1095
  - T1547
  - T1547.006
  - T1014
  - T1068
  - T1213
  - T1213.001
  - T1555
  - T1555.003
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-46300, T1190, WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Metasploit, Linux, Windows, Metasploit Framework, HoneyMyte, CoolClient, Armored Likho, Still Toolkit, Telegram, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Metasploit RCE - Anomalous Child Process Spawned by Web Server Process; Metasploit HTTP Malleable Profile - Anomalous Outbound HTTP from Server Process; Metasploit AArch64 Reverse-TCP Shell - Outbound TCP from Unexpected Process on ARM Windows; CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Installation.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Metasploit RCE - Anomalous Child Process Spawned by Web Server Process

### Detection Opportunity

New Metasploit modules targeting public-facing web applications spawn unexpected child processes from web server parent processes as part of remote code execution.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Lot of summer shells and fit http profiles — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles)
  - Context: Rapid7 reported thirteen new Metasploit modules targeting multiple public-facing web applications including WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, and Pix-for-WooCommerce for remote code execution. Successful exploitation results in shell access spawned from the web server process.

### Search Metadata

- CVEs: CVE-2026-46300
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095
- Products: WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce
- Platforms: Linux, Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-46300, T1190, WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Metasploit, Linux, Windows, Metasploit Framework, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1095 Non-Application Layer Protocol (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let WebServerParents = dynamic(["apache2", "nginx", "php", "php-fpm", "php-cgi", "httpd", "node", "python", "python3", "java", "tomcat", "ghost", "wp-cli", "uwsgi", "gunicorn"]);
let SuspiciousChildren = dynamic(["sh", "bash", "dash", "cmd.exe", "powershell.exe", "whoami", "id", "curl", "wget", "nc", "ncat", "nmap", "perl", "ruby", "python", "python3"]);
let SuspiciousProcs = DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where InitiatingProcessFileName in~ (WebServerParents)
| where FileName in~ (SuspiciousChildren)
| project DeviceName, ProcTime = TimeGenerated, InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessCommandLine, ProcessId;
let OutboundConns = DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 8080, 8443)
| project DeviceName, NetTime = TimeGenerated, RemoteIP, RemotePort, InitiatingProcessId;
SuspiciousProcs
| join kind=inner OutboundConns on DeviceName, $left.ProcessId == $right.InitiatingProcessId
| where NetTime between (ProcTime .. (ProcTime + 5m))
| project DeviceName, ProcTime, InitiatingProcessFileName, FileName, ProcessCommandLine, RemoteIP, RemotePort, InitiatingProcessId
| summarize EventCount = count(), arg_max(ProcTime, *) by DeviceName, InitiatingProcessFileName, FileName, RemoteIP, RemotePort
| order by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative scripts executed via cron jobs or deployment pipelines that run under web server accounts will match the parent process filter.
- Package managers or health-check scripts spawned by application runtimes (e.g., pip, npm, composer) that make outbound connections will trigger this detection.
- CI/CD agents running under web server process accounts may spawn shell children with outbound connections.

**Tuning notes:**
- Extend WebServerParents to include environment-specific application server names such as unicorn, puma, uvicorn, or daphne if those runtimes are deployed.
- Adjust the 5-minute network correlation window to a shorter interval (e.g., 2 minutes) in high-traffic environments to reduce coincidental matches.
- If ProcessId join yields no results due to missing InitiatingProcessId in DeviceNetworkEvents on Linux, revert to DeviceName-only join and accept higher FP rate during hunting.
- Consider adding a filter on RemoteIP to exclude RFC1918 private address ranges if internal pivot activity is not in scope.

**Risks / caveats:**
- DeviceProcessEvents parent-child telemetry for Linux endpoints requires MDE Linux agent version that supports InitiatingProcessFileName population; this field may be empty on older agent deployments.
- DeviceNetworkEvents InitiatingProcessFileName may not be populated for all network events on Linux endpoints depending on MDE agent version.
- ProcessId-based join requires that DeviceNetworkEvents populates InitiatingProcessId for Linux endpoints; if this field is absent, the join will return no results and the query should fall back to DeviceName-only correlation with analyst awareness of increased noise.
- Metasploit reverse shells configured to use ports 80 or 443 with malleable HTTP profiles will evade the port exclusion filter.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process and child process are consistent with a web server spawning a shell or utility process, not a normal application worker.
- Check the child process command line for attacker tradecraft such as whoami, id, curl, wget, nc, bash -c, cmd.exe /c, or encoded/obfuscated arguments.
- Review the correlated outbound connection for destination IP, port, and timing; treat non-standard ports and immediate post-spawn connections as higher risk.
- Identify the exposed application on the host and determine whether it matches one of the products in scope and whether it was recently patched or changed.
- If the process lineage and network activity are suspicious, treat the host as potentially compromised and begin incident handling.

**Evidence to collect:**
- DeviceProcessEvents for the parent and child process lineage, including ProcessId, InitiatingProcessId, FileName, and ProcessCommandLine.
- DeviceNetworkEvents for the same InitiatingProcessId, including RemoteIP, RemotePort, ActionType, and TimeGenerated.
- Host role and application inventory for the device to confirm whether it runs WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, or Pix-for-WooCommerce.
- Any recent web application changes, patching history, or exposed management interfaces on the host.
- If available, web server logs or reverse proxy logs around the same timestamp to identify the request that preceded the spawn.

**Pivot points:**
- DeviceProcessEvents filtered on the host and parent process name to find additional child processes spawned by the same web server account.
- DeviceNetworkEvents filtered on the host and InitiatingProcessId to enumerate all outbound destinations from the suspicious child process.
- DeviceLogonEvents or equivalent authentication telemetry to look for new logons or lateral movement after the suspected exploit.
- Web server, reverse proxy, or application logs for the same time window to identify the triggering request path and source IP.
- DeviceFileEvents for recent web root changes, dropped scripts, or new binaries near the alert time.

**Benign explanations:**
- Legitimate deployment, maintenance, or health-check scripts running under a web server account.
- Application runtimes such as php-fpm, node, python, or java spawning helper utilities during normal package installation or startup.
- CI/CD or automation jobs that execute shell commands and make outbound connections from a server host.
- Known administrative scripts that use curl or wget to fetch dependencies or configuration updates.

**Escalation criteria:**
- The child process is a shell, downloader, or recon tool with suspicious arguments and no approved maintenance change explains it.
- The same process makes an outbound connection to an unusual external IP or non-standard port shortly after spawning.
- The host runs an exposed application in the affected product list and there is evidence of recent exploitation or web shell activity.
- Multiple child processes or repeated callbacks occur from the same web server lineage, indicating active post-exploitation.

**Containment actions:**
- Isolate the host from the network if the child process appears to be an attacker shell or downloader and the system is internet-facing.
- Block the observed remote IP or destination at the perimeter if it is clearly malicious and not a business service.
- Disable or restrict the exposed application or virtual host until patching and validation are complete.
- Preserve volatile evidence before rebooting or reimaging, including running processes and active network connections.

**Closure criteria:**
- The spawned child process is confirmed to be an approved administrative or deployment action with matching change records.
- The outbound connection is tied to a known-good service, package repository, or monitoring endpoint.
- No additional suspicious child processes, web shell artifacts, or follow-on activity are found on the host.
- The application owner confirms the activity is expected and the host is not exposed to the vulnerable condition.

<br/>
---
<br/>

## Detection 2: Metasploit HTTP Malleable Profile - Anomalous Outbound HTTP from Server Process

### Detection Opportunity

Metasploit HTTP malleable profiles and Linux multi-fetch payloads generate repeated outbound HTTP connections from server-side processes to uncommon ports shortly after exploitation.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Lot of summer shells and fit http profiles — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles)
  - Context: Rapid7 reported that Metasploit added HTTP malleable profiles and Linux multi-fetch payloads. These features allow post-exploitation payloads to blend outbound C2 traffic with legitimate-looking HTTP patterns, initiated from compromised server processes.

### Search Metadata

- CVEs: CVE-2026-46300
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095
- Products: WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce
- Platforms: Linux, Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-46300, T1190, WordPress, Ghost CMS, Joomla, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Metasploit, Linux, Windows, Metasploit Framework, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1095 Non-Application Layer Protocol (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let WebServerProcs = dynamic(["apache2", "nginx", "php", "php-fpm", "php-cgi", "httpd", "node", "python", "python3", "java", "tomcat", "ghost", "uwsgi", "gunicorn"]);
DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ (WebServerProcs)
| where RemotePort !in (80, 443, 8080, 8443)
| where Protocol == "Tcp" or isempty(Protocol)
| summarize ConnectionCount = count(),
            Ports = make_set(RemotePort),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessId, RemoteIP, bin(TimeGenerated, 10m)
| where ConnectionCount >= 3
| extend DurationSeconds = datetime_diff('second', LastSeen, FirstSeen)
| project DeviceName, InitiatingProcessFileName, InitiatingProcessId, RemoteIP, Ports, ConnectionCount, DurationSeconds, FirstSeen, LastSeen
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Application runtimes that poll internal monitoring endpoints, metrics collectors, or service mesh sidecars on non-standard ports will trigger this detection.
- Package managers or dependency fetchers (pip, npm, gem) running under web server accounts that contact package registries on non-standard ports.
- Legitimate health-check or webhook integrations from web application processes to third-party services on custom ports.

**Tuning notes:**
- Extend WebServerProcs to include environment-specific runtimes such as unicorn, puma, uvicorn, or daphne.
- Increase ConnectionCount threshold above 3 in environments where server processes make frequent legitimate outbound calls.
- Add known CDN, package registry, or monitoring endpoint IP ranges to a RemoteIP exclusion list to suppress legitimate multi-connection patterns.
- Consider replacing the 10-minute bin with a sliding window using serialize and row_window_session if bin-boundary splitting is observed during validation.

**Risks / caveats:**
- The Protocol field in DeviceNetworkEvents may not be consistently populated across all MDE agent versions and OS types; on some Linux agent versions this field may be empty, causing the Protocol == 'Tcp' filter to drop valid events.
- InitiatingProcessFileName may not be populated for all network events on Linux endpoints depending on MDE Linux agent version.
- Single-connection Metasploit C2 using malleable HTTP profiles will not be detected by this query; the 3-connection threshold is specific to multi-fetch staging behavior.
- Metasploit reverse shells configured to use ports 80 or 443 will evade the port exclusion filter.

### Triage Runbook

**First 15 minutes:**
- Confirm the process name and parent lineage are consistent with a server runtime rather than a user application.
- Review the connection burst: destination IP, ports, count, and timing; repeated connections to the same uncommon destination are more suspicious than a single callout.
- Check the command line and process context for signs of fetchers, package managers, or scripted automation.
- Determine whether the destination is an approved internal service, CDN, package registry, or monitoring endpoint.
- If the pattern is not explained by normal application behavior, escalate to host compromise review.

**Evidence to collect:**
- DeviceNetworkEvents for the same InitiatingProcessId, including RemoteIP, RemotePort, Protocol, and timestamps.
- DeviceProcessEvents for the initiating process and its parent to understand the runtime and command line.
- Host application inventory and service configuration to identify the server role and expected outbound dependencies.
- Proxy, firewall, or DNS logs for the destination IP to determine whether the traffic is external, internal, or part of a known service.
- Any recent deployment, update, or health-check activity that could explain repeated outbound connections.

**Pivot points:**
- DeviceNetworkEvents grouped by InitiatingProcessId and RemoteIP to see whether the same process is contacting multiple destinations or ports.
- DeviceProcessEvents on the host for other server processes making similar outbound connections.
- DNS and proxy telemetry for the destination IP or domain to identify the service owner and reputation.
- DeviceFileEvents for recent script or binary drops associated with the server process.
- If available, web server logs to correlate the outbound burst with a specific inbound request or exploit attempt.

**Benign explanations:**
- Application runtimes polling internal APIs, metrics endpoints, or service mesh sidecars on non-standard ports.
- Package managers or dependency fetchers such as pip, npm, or gem running under a server account.
- Legitimate webhook integrations or third-party service calls from the application.
- Health-check or monitoring agents that retry connections during transient failures.

**Escalation criteria:**
- Three or more outbound connections in a short window to an unusual external destination with no approved business purpose.
- The initiating process is a server runtime and the destination is not a known internal service or sanctioned external dependency.
- The traffic follows a recent exploit indicator such as a suspicious child process, web shell, or abnormal file write.
- The same host shows additional signs of compromise, such as new processes, persistence, or credential access.

**Containment actions:**
- If the destination is clearly malicious and the host is likely compromised, isolate the host from the network.
- Block the malicious destination at the firewall or proxy if confirmed and not business-critical.
- Suspend the affected service only if it is necessary to stop active exfiltration or staging and business impact is understood.
- Preserve logs and process evidence before remediation.

**Closure criteria:**
- The repeated outbound connections are matched to a documented application dependency or approved monitoring workflow.
- The destination is confirmed as internal or sanctioned and the process behavior is normal for the service.
- No additional suspicious process activity or exploit indicators are present on the host.
- The alert is explained by a known deployment, update, or health-check pattern and validated by the application owner.

<br/>
---
<br/>

## Detection 3: Metasploit AArch64 Reverse-TCP Shell - Outbound TCP from Unexpected Process on ARM Windows

### Detection Opportunity

AArch64 reverse-TCP shell payloads added to Metasploit establish outbound TCP connections from unexpected processes on Windows ARM-architecture devices.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Lot of summer shells and fit http profiles — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles)
  - Context: Rapid7 reported that Metasploit added brand-new AArch64 reverse-TCP shells (both inline and staged) targeting Windows on ARM architecture. These payloads establish outbound TCP connections from the exploited process to attacker-controlled infrastructure on non-standard ports.

### Search Metadata

- CVEs: CVE-2026-46300
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-46300, T1190, Metasploit, Windows, Metasploit Framework, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1095 Non-Application Layer Protocol (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents, DeviceProcessEvents, DeviceInfo before scheduling.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents, DeviceInfo

### KQL

```kql
let CommonProcs = dynamic(["svchost.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "onedrive.exe", "teams.exe", "outlook.exe", "explorer.exe", "msiexec.exe", "wuauclt.exe"]);
let LegitShellParents = dynamic(["explorer.exe", "taskmgr.exe", "mmc.exe", "devenv.exe"]);
let ArmDevices = DeviceInfo
| where TimeGenerated >= ago(1d)
| where OSPlatform == "Windows"
| where OSArchitecture has_any ("arm", "arm64", "aarch64")
| summarize arg_max(TimeGenerated, *) by DeviceName
| project DeviceName, OSArchitecture;
let ShellProcs = DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| where not(InitiatingProcessFileName in~ (LegitShellParents))
| project DeviceName, ProcTime = TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessId;
let SuspiciousNetConns = DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 3389, 445, 135, 53, 8080, 8443)
| where not(InitiatingProcessFileName in~ (CommonProcs))
| project DeviceName, NetTime = TimeGenerated, InitiatingProcessFileName, RemoteIP, RemotePort, InitiatingProcessId;
ShellProcs
| join kind=inner ArmDevices on DeviceName
| join kind=inner SuspiciousNetConns on DeviceName, $left.ProcessId == $right.InitiatingProcessId
| where NetTime between ((ProcTime - 2m) .. (ProcTime + 2m))
| project DeviceName, OSArchitecture, ProcTime, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, RemoteIP, RemotePort
| summarize EventCount = count(), arg_max(ProcTime, *) by DeviceName, OSArchitecture, FileName, RemoteIP, RemotePort
| order by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Development tools, build systems, or test runners on ARM Windows devices that spawn shell processes and make outbound connections during normal operation.
- Remote management tools or MDM agents on ARM Windows devices that use cmd.exe or powershell.exe with outbound connections.
- ARM Windows devices where DeviceInfo.OSArchitecture is not populated will be excluded from results, creating false negatives rather than false positives.

**Tuning notes:**
- If DeviceInfo.OSArchitecture is not reliably populated, replace the ArmDevices subquery with a static list of known ARM Windows device names from your asset inventory.
- Expand the RemotePort exclusion list to include additional known-good ports used in the environment.
- Add known administrative tool process names to LegitShellParents if legitimate remote management generates false positives.
- Validate that the DeviceInfo lookback of 1 day captures all active ARM devices; extend to 7 days if device check-in frequency is low.

**Risks / caveats:**
- OSPlatform is not a standard field in DeviceNetworkEvents or DeviceProcessEvents in Defender XDR Advanced Hunting; ARM architecture filtering requires DeviceInfo.OSArchitecture or a pre-populated device inventory, which may not be available in all tenants.
- DeviceInfo.OSArchitecture field availability depends on MDE agent version and device onboarding completeness; ARM Windows devices may not report this field if running older agent versions.
- DeviceInfo.OSArchitecture may not be populated for all ARM Windows devices; devices with missing architecture data will be excluded from results, creating false negatives.
- ProcessId-based join between DeviceProcessEvents and DeviceNetworkEvents requires InitiatingProcessId to be populated in DeviceNetworkEvents; if absent, the join returns no results.

### Triage Runbook

**First 15 minutes:**
- Verify the device is actually a Windows ARM host and that the alert is not from a misclassified or non-ARM endpoint.
- Inspect the initiating process and parent process for shell activity such as cmd.exe, powershell.exe, or pwsh.exe launched by an unusual parent.
- Review the outbound connection destination, port, and timing; treat non-standard ports and immediate callbacks as high risk.
- Check whether the process command line shows encoded commands, downloaders, or remote execution behavior.
- If the process lineage and network activity are suspicious, escalate as a likely compromise on an ARM Windows endpoint.

**Evidence to collect:**
- DeviceInfo for OSArchitecture and device identity to confirm ARM Windows scope.
- DeviceProcessEvents for the suspicious shell process, including ProcessId, InitiatingProcessId, FileName, ProcessCommandLine, and parent process details.
- DeviceNetworkEvents for the same InitiatingProcessId, including RemoteIP, RemotePort, and TimeGenerated.
- Any recent software installation, remote management, or developer tooling activity on the device that could explain shell execution.
- If available, endpoint or proxy logs showing whether the destination is external and whether the connection was repeated.

**Pivot points:**
- DeviceProcessEvents on the same host for other shell launches or suspicious child processes around the alert time.
- DeviceNetworkEvents filtered to the host and InitiatingProcessId to enumerate all outbound destinations from the shell.
- DeviceInfo to identify other ARM Windows devices that may need review for similar behavior.
- Authentication telemetry to look for new logons, remote sessions, or lateral movement after the shell activity.
- DeviceFileEvents for dropped scripts, payloads, or staging artifacts near the alert time.

**Benign explanations:**
- Developer tools, build systems, or test runners on ARM Windows devices that legitimately spawn shells and make outbound connections.
- Remote management or MDM agents that use cmd.exe or powershell.exe for scripted administration.
- Approved automation or troubleshooting scripts executed by IT staff.
- Known-good software installers or updaters that briefly launch shells during setup.

**Escalation criteria:**
- The shell process is not associated with an approved administrative workflow and makes an external callback.
- The command line shows attacker-like behavior such as encoded commands, download-and-execute, or reverse shell indicators.
- The device is an ARM Windows endpoint exposed to the internet or recently received a suspicious inbound request.
- Additional compromise indicators are present, such as persistence, credential access, or multiple suspicious network callbacks.

**Containment actions:**
- Isolate the device from the network if the shell and callback are not clearly authorized.
- Block the remote IP or destination if it is confirmed malicious.
- Disable remote management access to the device until the investigation confirms legitimacy.
- Preserve volatile evidence before remediation or reboot.

**Closure criteria:**
- The shell activity is confirmed to be part of an approved administrative or development workflow.
- The outbound connection is tied to a sanctioned service or internal endpoint.
- No additional suspicious processes, callbacks, or persistence indicators are found.
- The device owner or administrator validates the activity and no compromise evidence remains.

<br/>
---
<br/>

## Detection 4: CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Installation

### Detection Opportunity

CoolClient backdoor loads a kernel-mode rootkit driver on Windows to hide malicious processes, files, and network connections from security tools.

### Intelligence Context

- Securelist: APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit — [https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/)
  - Context: Kaspersky Securelist reported that the HoneyMyte APT group upgraded the CoolClient backdoor with a kernel-mode rootkit driver that hides malicious processes, files, and network connections from security tools on Windows systems. The driver is loaded as part of the CoolClient infection chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: HoneyMyte
- ATT&CK tags: T1547, T1547.006, T1014, T1068
- Products: Not specified
- Platforms: Windows
- Malware: CoolClient
- Tools: Not specified
- Search tags: HoneyMyte, CoolClient, Windows, T1547, T1547.006, T1014, T1068

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.006 Kernel Modules and Extensions (high); Defense Evasion: T1014 Rootkit (high); Privilege Escalation: T1068 Exploitation for Privilege Escalation (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let KnownInstallers = dynamic(["msiexec.exe", "setup.exe", "install.exe", "windowsupdate.exe", "trustedinstaller.exe", "sccmsetup.exe"]);
let SuspiciousDriverPaths = dynamic(["\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\", "\\programdata\\", "\\downloads\\"]);
let DriverDrops = DeviceFileEvents
| where TimeGenerated >= ago(14d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".sys"
| where FolderPath has_any (SuspiciousDriverPaths)
| where not(InitiatingProcessFileName in~ (KnownInstallers))
| project DeviceName, FileTime = TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessId, ActionType, InitiatingProcessCommandLine;
let ServiceInstalls = DeviceProcessEvents
| where TimeGenerated >= ago(14d)
| where FileName in~ ("sc.exe", "services.exe", "cmd.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("create", "binPath", "type= kernel", "start= auto")
| project DeviceName, ProcTime = TimeGenerated, ProcessCommandLine, InitiatingProcessFileName, ProcessId;
DriverDrops
| join kind=leftouter ServiceInstalls on DeviceName
| where isempty(ProcTime) or ProcTime between ((FileTime - 5m) .. (FileTime + 5m))
| project DeviceName, FileTime, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, ProcessCommandLine
| summarize EventCount = count(), arg_max(FileTime, *) by DeviceName, FileName, FolderPath
| order by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Third-party security software, VPN clients, or hardware drivers that drop .sys files to AppData or ProgramData directories during installation.
- Software deployment tools not included in the KnownInstallers list that install legitimate drivers to non-standard paths.
- Portable or self-extracting software packages that stage driver files in temp directories before moving them to System32.

**Tuning notes:**
- Extend KnownInstallers to include environment-specific deployment tools such as SCCM client, Intune management agent, or third-party patch management executables.
- Narrow SuspiciousDriverPaths to the most anomalous locations for the environment; remove paths that are legitimately used by approved software.
- For Microsoft Sentinel deployments, supplement this query with a SecurityEvent query filtering on EventID 7045 where ServiceType contains 'kernel' and ImagePath matches suspicious directories.
- If file hashes become available from threat intelligence, add a SHA256 filter to the DriverDrops subquery for high-confidence matching.

**Risks / caveats:**
- DeviceFileEvents may not capture kernel driver file creation events if the file is written directly by a kernel-mode component rather than a user-mode process; in such cases InitiatingProcessFileName will be empty or system.
- The SecurityEvent table (Windows Event ID 7045) is available in Microsoft Sentinel but not in Defender XDR Advanced Hunting; the target_platform is Both, but the KQL only uses Defender XDR tables. Sentinel-specific validation against SecurityEvent requires a separate query.
- Rootkit drivers that are loaded directly by a kernel exploit without a user-mode file write event will not be detected by this query.
- If the CoolClient driver is dropped to System32\drivers (a standard path), it will be excluded by the SuspiciousDriverPaths filter and missed.

### Triage Runbook

**First 15 minutes:**
- Confirm the .sys file path, creation time, and initiating process to determine whether the driver was dropped in a non-standard location.
- Check whether the initiating process is a known installer, service tool, or an unexpected process such as cmd.exe, powershell.exe, or sc.exe.
- Review the service-install or driver-load command line for kernel driver indicators such as create, binPath, type= kernel, or start= auto.
- Look for any signs of process hiding, network hiding, or tampering with security tools on the host.
- If the driver is suspicious and not tied to a trusted installer, treat the host as potentially rootkitted and escalate immediately.

**Evidence to collect:**
- DeviceFileEvents for the .sys file, including FolderPath, FileName, ActionType, InitiatingProcessFileName, and InitiatingProcessCommandLine.
- DeviceProcessEvents for service creation or driver installation commands, including sc.exe, services.exe, cmd.exe, powershell.exe, and their command lines.
- Any available driver signature or publisher information from endpoint tooling or file properties.
- Recent software installation, patching, or hardware driver activity on the host.
- Security or EDR alerts indicating hidden processes, hidden files, or tampering around the same time.

**Pivot points:**
- DeviceFileEvents for other .sys files created on the same host or by the same initiating process.
- DeviceProcessEvents for service creation, driver installation, or suspicious administrative commands on the host.
- DeviceImageLoadEvents or equivalent telemetry, if available, to identify loaded drivers and unsigned modules.
- Windows service and driver inventory to compare the new driver against known-good drivers on the host.
- If using Sentinel, SecurityEvent 7045 to validate suspicious service installation activity.

**Benign explanations:**
- Legitimate third-party security software, VPN clients, or hardware drivers installing to non-standard paths during setup.
- Software deployment tools or patching agents not included in the known installer list.
- Temporary staging of driver files by installers before moving them to standard driver locations.
- Vendor support tools or device management software that install kernel components as part of normal operation.

**Escalation criteria:**
- The driver is unsigned, low-prevalence, or dropped by an unexpected process in a user-writable directory.
- The service-install command indicates a kernel driver and there is no approved change record.
- There are signs of defense evasion such as hidden processes, hidden network activity, or tampering with security tooling.
- The host is a high-value system or shows additional compromise indicators beyond the driver drop.

**Containment actions:**
- Isolate the host if the driver appears malicious or if rootkit behavior is suspected.
- Prevent further driver loading by disabling the suspicious service only if it can be done safely and with change control.
- Block the associated installer or dropper process if it is still active.
- Preserve the driver file and system state for forensic analysis before rebooting.

**Closure criteria:**
- The driver is verified as signed and associated with an approved vendor or change request.
- The file path and installation method match a legitimate software deployment or hardware driver update.
- No evidence of hidden processes, tampering, or unauthorized service installation is found.
- The suspicious driver artifact is removed or accounted for and the host is stable.

<br/>
---
<br/>

## Detection 5: Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Data

### Detection Opportunity

The Still Toolkit targets Telegram data theft by having non-Telegram processes access Telegram local session and profile data stored in the user AppData directory.

### Intelligence Context

- Securelist: Armored Likho expands its cyber-espionage toolkit — [https://securelist.com/armored-likho-still-toolkit/121033/](https://securelist.com/armored-likho-still-toolkit/121033/)
  - Context: Kaspersky Securelist reported that the Armored Likho APT group deployed the Still Toolkit to steal Telegram data and eavesdrop on victims. The toolkit accesses Telegram local session files stored in the user profile AppData directory using processes other than the legitimate Telegram client.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1213, T1213.001, T1555, T1555.003
- Products: Telegram
- Platforms: Windows
- Malware: Still Toolkit
- Tools: Not specified
- Search tags: Armored Likho, Still Toolkit, Telegram, Windows, T1213, T1213.001, T1555, T1555.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories/ T1213.001 Local Data from Information Repositories (high); Credential Access: T1555 Credentials from Password Stores/ T1555.003 Credentials from Web Browsers (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let TelegramDataPath = "Telegram Desktop";
let LegitTelegramProcs = dynamic(["Telegram.exe", "Updater.exe"]);
let TelegramFileAccess = DeviceFileEvents
| where TimeGenerated >= ago(14d)
| where FolderPath has TelegramDataPath
| where ActionType in ("FileRead", "FileAccessed", "FileCopied", "FileCreated")
| where not(InitiatingProcessFileName in~ (LegitTelegramProcs))
| project DeviceName, FileTime = TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessId, ActionType, InitiatingProcessCommandLine;
let OutboundAfterAccess = DeviceNetworkEvents
| where TimeGenerated >= ago(14d)
| where ActionType == "ConnectionSuccess"
| project DeviceName, NetTime = TimeGenerated, RemoteIP, RemotePort, InitiatingProcessId;
TelegramFileAccess
| join kind=inner OutboundAfterAccess on DeviceName, InitiatingProcessId
| where NetTime between (FileTime .. (FileTime + 10m))
| project DeviceName, FileTime, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, RemoteIP, RemotePort
| summarize FileCount = count(), arg_max(FileTime, *) by DeviceName, InitiatingProcessFileName, RemoteIP
| order by FileCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup software or endpoint management agents that scan user AppData directories and make outbound connections during backup operations.
- Antivirus or EDR products that read Telegram session files during scanning and generate network telemetry.
- Sync tools such as OneDrive or Dropbox that access AppData directories and upload files to cloud storage endpoints.

**Tuning notes:**
- Add known backup, sync, or endpoint management tool process names to the LegitTelegramProcs exclusion list to reduce false positives from legitimate Telegram data access.
- If HTTPS-based exfiltration is not a concern and port 443 traffic generates excessive noise, add RemotePort != 443 to the OutboundAfterAccess filter.
- Validate that the Updater.exe exclusion is scoped correctly by checking InitiatingProcessFolderPath for any Updater.exe matches to confirm they originate from the legitimate Telegram installation directory.
- Consider adding a FolderPath filter on InitiatingProcessFolderPath to exclude processes running from known-good directories such as Program Files when reviewing Updater.exe matches.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileRead' and 'FileAccessed' may not be generated for all file access operations on Windows endpoints; MDE may only log 'FileCreated' and 'FileModified' by default for some file types, potentially missing read-only access to Telegram session files.
- DeviceFileEvents may not capture file access events within AppData\Roaming if the MDE agent file monitoring scope excludes user profile directories on the monitored endpoints.
- If DeviceFileEvents does not generate FileRead or FileAccessed events for Telegram session files in the monitored environment, the detection will produce no results; FileCreated is included as a fallback but may not capture read-only exfiltration.
- Telegram installations using portable or non-standard AppData paths will not be detected by the FolderPath has 'Telegram Desktop' filter.

### Triage Runbook

**First 15 minutes:**
- Confirm the accessing process is not Telegram.exe or Updater.exe and review its command line and parent process.
- Check whether the file access targeted Telegram Desktop data under the user profile AppData path and whether multiple files were touched.
- Review the correlated network connection from the same process for unusual external destinations or immediate exfiltration behavior.
- Identify the user account associated with the process and determine whether the user was expected to run the application.
- If the process is unfamiliar or the network activity is suspicious, escalate for credential-theft investigation.

**Evidence to collect:**
- DeviceFileEvents showing the Telegram-related file access, including FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, and AccountName if available.
- DeviceNetworkEvents for the same InitiatingProcessId, including RemoteIP, RemotePort, and TimeGenerated.
- DeviceProcessEvents for the process lineage to identify the parent and any child processes spawned after file access.
- User context and recent logon activity for the affected account.
- Any Telegram-related application logs or endpoint telemetry showing whether the legitimate client was active at the same time.

**Pivot points:**
- DeviceFileEvents for additional accesses to Telegram Desktop paths by the same process or user.
- DeviceNetworkEvents filtered to the same InitiatingProcessId to enumerate all outbound destinations after file access.
- DeviceProcessEvents for the host to find other processes accessing AppData or browser/profile data.
- Authentication telemetry to look for suspicious sign-ins, token use, or lateral movement after the access.
- If available, browser or cloud sync telemetry to determine whether the process is a known backup or sync tool.

**Benign explanations:**
- Backup, sync, or endpoint management tools scanning user AppData directories as part of normal operation.
- Antivirus or EDR products reading Telegram files during scanning.
- Legitimate user activity involving Telegram data migration, backup, or troubleshooting.
- Telegram updater or related maintenance activity if the process path and signature are verified.

**Escalation criteria:**
- A non-Telegram process accesses Telegram session or profile data and then makes an external connection shortly afterward.
- The process is unknown, unsigned, or launched from a user-writable directory.
- Multiple Telegram-related files are accessed in a short period, suggesting collection rather than incidental scanning.
- There are signs of broader credential theft, such as browser profile access, token theft, or suspicious logons.

**Containment actions:**
- Isolate the host if the process is clearly malicious or if exfiltration is in progress.
- Terminate the suspicious process if it is still active and containment is approved.
- Reset or revoke affected user credentials if Telegram session theft is confirmed or strongly suspected.
- Block the remote destination if it is confirmed malicious and not business-related.

**Closure criteria:**
- The process is identified as a legitimate backup, sync, security, or maintenance tool.
- The file access is explained by approved user activity or a documented support workflow.
- No suspicious outbound connection, credential theft, or additional profile access is found.
- The alert is tied to a known-good process path and command line and no further action is needed.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Metasploit RCE - Anomalous Child Process Spawned by Web Server Process: Do not schedule yet; validate as an analyst-led hunt first.
- Metasploit HTTP Malleable Profile - Anomalous Outbound HTTP from Server Process: Do not schedule yet; validate as an analyst-led hunt first.
- CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Installation: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Metasploit AArch64 Reverse-TCP Shell - Outbound TCP from Unexpected Process on ARM Windows: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents, DeviceProcessEvents, DeviceInfo before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by Metasploit RCE - Anomalous Child Process Spawned by Web Server Process; Metasploit AArch64 Reverse-TCP Shell - Outbound TCP from Unexpected Process on ARM Windows; CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Installation
- DeviceNetworkEvents: shared by Metasploit RCE - Anomalous Child Process Spawned by Web Server Process; Metasploit HTTP Malleable Profile - Anomalous Outbound HTTP from Server Process; Metasploit AArch64 Reverse-TCP Shell - Outbound TCP from Unexpected Process on ARM Windows; Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Data
- DeviceFileEvents: shared by CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Installation; Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Data

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Data.
2. Resolve environment-mapping detections next: Metasploit AArch64 Reverse-TCP Shell - Outbound TCP from Unexpected Process on ARM Windows.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Metasploit RCE - Anomalous Child Process Spawned by Web Server Process; Metasploit HTTP Malleable Profile - Anomalous Outbound HTTP from Server Process; CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Installation.

### Hunting Agenda and Promotion Criteria

- Metasploit RCE - Anomalous Child Process Spawned by Web Server Process: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Metasploit HTTP Malleable Profile - Anomalous Outbound HTTP from Server Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Installation: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Metasploit AArch64 Reverse-TCP Shell - Outbound TCP from Unexpected Process on ARM Windows: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents, DeviceProcessEvents, DeviceInfo before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
