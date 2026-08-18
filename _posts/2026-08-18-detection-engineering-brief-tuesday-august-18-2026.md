---
layout: post
title: "Detection Engineering Brief - Tuesday, August 18, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-18
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Electron
  - Windows
  - Telegram
  - Web
  - HoneyMyte
  - CoolClient
  - CVE-2026-46300
  - T1190
  - WordPress
  - Ghost CMS
  - Joomla
  - JCE
  - Langflow
  - OpenCATS
  - Pterodactyl Panel
  - SonicWall SMA1000
  - Ray Dashboard
  - Pix-for-WooCommerce
  - Linux
  - Metasploit
  - Windows on ARM
  - Armored Likho
  - Still Toolkit
  - T1567
  - T1567.003
  - T1547
  - T1547.006
  - T1014
  - T1095
  - T1555
  - T1555.007
  - T1213
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 2 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Electron, Windows, Telegram, Web, HoneyMyte, CoolClient, CVE-2026-46300, T1190, WordPress, Ghost CMS, Joomla, JCE, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Linux, Metasploit, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Non-Browser Process Outbound Connection to Telegram API - Potential Exfiltration; Unsigned or Anomalous Kernel Driver Load from Non-Standard Path - HoneyMyte CoolClient Rootkit Pattern; Privilege Escalation to Root from Web Server Parent Process - CVE-2026-46300 Linux Kernel LPE Pattern; Outbound Reverse Shell Connection from Unexpected Process on Windows ARM Device.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Non-Browser Process Outbound Connection to Telegram API - Potential Exfiltration

### Detection Opportunity

Non-browser process making outbound network connections to Telegram API endpoints, consistent with fraud infrastructure exfiltrating data via Telegram bot API.

### Intelligence Context

- Rapid7: Operation ASTERIX: Anatomy of a Crypto Fraud Pipeline — [https://www.rapid7.com/blog/post/tr-operation-asterix-crypto-fraud-vishing-phishing](https://www.rapid7.com/blog/post/tr-operation-asterix-crypto-fraud-vishing-phishing)
  - Context: The fraud infrastructure used Telegram exfiltration code to send stolen data out via the Telegram API. The reporting explicitly identified Telegram as the exfiltration channel from non-browser fraud tooling, including Electron-packaged fake wallet applications.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1567, T1567.003
- Products: Electron
- Platforms: Windows, Telegram, Web
- Malware: Not specified
- Tools: Not specified
- Search tags: Electron, Windows, Telegram, Web, T1567, T1567.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Exfiltration: T1567 Exfiltration Over Web Service/ T1567.003 Exfiltration to Cloud Storage (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- If RemoteUrl is not populated, consider correlating DeviceNetworkEvents with DeviceDnsEvents on RemoteIP to identify Telegram API destinations via DNS resolution.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any ("api.telegram.org", "t.me")
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "iexplore.exe", "safari.exe", "Telegram.exe", "telegram.exe", "Updater.exe"
  )
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    RemoteUrl,
    RemoteIP,
    RemotePort
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal automation tools, bots, or monitoring scripts that use the Telegram API for alerting.
- Development environments where developers test Telegram bot integrations from non-browser executables.
- Electron-based applications with legitimate Telegram notification integrations.

**Tuning notes:**
- To focus on Electron-based processes, add: → where InitiatingProcessCommandLine has '--type=' or InitiatingProcessFolderPath !startswith 'C:\\Program Files'
- Extend lookback to 14d for initial hunting baseline before reducing to 1d for scheduled alerting.

**Risks / caveats:**
- RemoteUrl is only populated in DeviceNetworkEvents when HTTPS inspection or a DNS proxy is in place; without it, the api.telegram.org and t.me filters will return no results and the query will silently produce empty output.
- If RemoteUrl is not populated, consider correlating DeviceNetworkEvents with DeviceDnsEvents on RemoteIP to identify Telegram API destinations via DNS resolution.
- The browser exclusion list should be reviewed against browsers deployed in the environment and extended as needed.
- Electron-based applications vary widely; narrowing by InitiatingProcessFolderPath not starting with standard Program Files paths can reduce noise.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process name, command line, and folder path; prioritize Electron-packaged apps, unsigned binaries, and processes running from user-writable locations.
- Check whether the destination is api.telegram.org or t.me and whether the connection is from a known browser or Telegram desktop client; if not, treat as suspicious.
- Identify the user context and device role; compare against any approved internal automation, alerting, or developer test systems that are known to use Telegram.
- Look for nearby process creation, archive creation, browser credential access, or file staging activity on the same host around the alert time.

**Evidence to collect:**
- DeviceNetworkEvents for the same host and time window to see all Telegram-related outbound connections and the initiating process lineage.
- DeviceProcessEvents for the initiating process parent/child chain, command line, and any suspicious child processes.
- DeviceFileEvents for recent creation or access of archives, documents, browser profiles, wallet files, or staging directories.
- Any proxy, DNS, or firewall logs that show the full destination and volume of traffic to Telegram endpoints.

**Pivot points:**
- DeviceNetworkEvents filtered on DeviceName and a 24-hour window around the alert to find other external destinations from the same process.
- DeviceProcessEvents filtered on InitiatingProcessFileName and DeviceName to identify the parent process and execution path.
- DeviceFileEvents filtered on DeviceName for recent access to sensitive user data, browser profiles, or compressed archives.
- If available, correlate with DeviceDnsEvents for Telegram-related resolution when RemoteUrl is missing.

**Benign explanations:**
- Approved internal bots or monitoring scripts that send alerts through Telegram.
- Developer test environments validating Telegram bot integrations from non-browser executables.
- Legitimate Electron applications with documented Telegram notification features.

**Escalation criteria:**
- The process is unsigned, runs from a user profile or temp directory, and has no approved business purpose.
- The host also shows file staging, credential access, archive creation, or suspicious child processes consistent with data theft.
- Multiple Telegram connections occur from the same non-browser process or from several hosts in a short period.
- The destination is Telegram API traffic from a server or privileged workstation that should not use consumer messaging services.

**Containment actions:**
- If the process is unauthorized or clearly malicious, isolate the host from the network to stop further exfiltration.
- Terminate the suspicious process only after preserving volatile evidence if your response workflow supports it.
- Block the specific executable path or hash if confirmed malicious and coordinate with endpoint containment procedures.

**Closure criteria:**
- The process is confirmed as an approved internal tool or documented application with a valid business owner.
- No additional suspicious process activity, file staging, or repeated Telegram exfiltration behavior is found on the host.
- Telemetry confirms the connection originated from a known browser or Telegram client that was excluded by design.
- A baseline exception is documented for the approved process, path, and user group.

<br/>
---
<br/>

## Detection 2: Unsigned or Anomalous Kernel Driver Load from Non-Standard Path - HoneyMyte CoolClient Rootkit Pattern

### Detection Opportunity

Kernel-mode driver loaded from a non-standard directory without a valid signature, consistent with HoneyMyte deploying a rootkit driver alongside the CoolClient backdoor.

### Intelligence Context

- Securelist: APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit — [https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/)
  - Context: HoneyMyte deployed a new CoolClient variant that includes a kernel-mode rootkit driver designed to hide malicious processes, files, and network connections from security tools. The driver load is the initial foothold for rootkit capability and is detectable before hiding behavior takes effect.

### Search Metadata

- CVEs: Not specified
- Threat actors: HoneyMyte
- ATT&CK tags: T1547, T1547.006, T1014
- Products: Not specified
- Platforms: Windows
- Malware: CoolClient
- Tools: Not specified
- Search tags: HoneyMyte, CoolClient, Windows, T1547, T1547.006, T1014

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.006 Kernel Modules and Extensions (high); Defense Evasion: T1014 Rootkit (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents before scheduling.

**Required telemetry:**
- DeviceEvents

### KQL

```kql
DeviceEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "DriverLoad"
| where not (
    FolderPath has_any (
      @"\Windows\System32\drivers\",
      @"\Windows\SysWOW64\drivers\",
      @"\Windows\System32\",
      @"\Windows\WinSxS\"
    )
  )
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Third-party security software (EDR, AV, DLP) that installs drivers to non-standard paths during installation.
- Hardware vendor drivers installed to vendor-specific subdirectories under Program Files.
- Virtualization software drivers loaded from application installation directories.

**Tuning notes:**
- Run DeviceEvents → summarize count() by ActionType → where ActionType == 'DriverLoad' to confirm telemetry availability before deploying.
- Add additional trusted FolderPath values for known security or hardware vendor software after baselining.
- Consider joining with DeviceFileCertificateInfo on SHA256 to surface unsigned drivers as a higher-priority signal.

**Risks / caveats:**
- ActionType 'DriverLoad' availability in DeviceEvents depends on Defender for Endpoint kernel telemetry being enabled; this must be verified with: DeviceEvents → where ActionType == 'DriverLoad' → take 1
- SHA256 may not be populated for all driver load events depending on sensor configuration and driver file accessibility at load time.
- Legitimate third-party drivers installed outside System32\drivers will generate false positives until an environment-specific allowlist is built.
- Restricting to high-value device groups (servers, privileged workstations) during initial rollout will reduce noise.

### Triage Runbook

**First 15 minutes:**
- Validate the driver file name, folder path, and SHA256; treat unsigned drivers outside standard Windows driver paths as high risk.
- Check the initiating process and command line to see what installed or loaded the driver and whether it matches a known software deployment.
- Confirm whether the device is a server, admin workstation, or endpoint with approved third-party security, virtualization, or hardware drivers.
- Look for signs of rootkit behavior on the host such as hidden processes, missing files, unusual network connections, or tampering with security tools.

**Evidence to collect:**
- DeviceEvents for the driver load event details, including file path, hash, and initiating process lineage.
- DeviceFileEvents for the driver file creation, modification, or copy history before the load event.
- DeviceProcessEvents for the installer or loader process and any subsequent suspicious child processes.
- Certificate/signing information for the driver hash if available, plus any threat intelligence matches on the SHA256.

**Pivot points:**
- DeviceEvents filtered on the same SHA256 or FileName across the environment to see whether the driver appeared on other hosts.
- DeviceFileEvents filtered on the driver hash or folder path to identify distribution patterns and staging locations.
- DeviceProcessEvents filtered on the initiating process name to find the installer, service, or script that introduced the driver.
- If available, DeviceNetworkEvents for the same host to check for post-load command-and-control or unusual outbound traffic.

**Benign explanations:**
- Legitimate third-party security software, DLP, EDR, or virtualization products that install drivers outside standard paths.
- Hardware vendor drivers installed into vendor-specific application directories.
- Software deployment or upgrade activity that temporarily stages drivers in non-standard locations before moving them.

**Escalation criteria:**
- The driver is unsigned, unknown, or signed by an untrusted publisher and loaded from a non-standard path.
- The host shows evidence of process hiding, security tool tampering, or unexplained network activity after the driver load.
- The initiating process is not tied to a known software deployment, vendor installer, or approved maintenance window.
- The same driver hash or path appears on multiple hosts without a clear administrative explanation.

**Containment actions:**
- Isolate the host if the driver is untrusted or rootkit behavior is suspected.
- Preserve the driver file, memory, and relevant logs before remediation if your process allows.
- Disable or remove the malicious driver only through approved incident response procedures and coordinate with endpoint protection teams.

**Closure criteria:**
- The driver is verified as a legitimate, signed component from an approved vendor and matches an expected deployment.
- The path, publisher, and hash are added to an environment-specific allowlist after validation.
- No rootkit indicators, hidden processes, or related suspicious activity are found on the host or across peers.
- The event is linked to a documented software installation or maintenance action.

<br/>
---
<br/>

## Detection 3: Privilege Escalation to Root from Web Server Parent Process - CVE-2026-46300 Linux Kernel LPE Pattern

### Detection Opportunity

A process spawned by a web server parent transitions to root-level privilege without use of sudo or su, consistent with post-exploitation Linux kernel local privilege escalation via CVE-2026-46300.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Lot of summer shells and fit http profiles — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles)
  - Context: Metasploit added an exploit module for CVE-2026-46300, a Linux kernel local privilege escalation vulnerability. The expected post-exploitation pattern is a web-server-spawned process gaining root privileges without standard privilege escalation utilities, following initial RCE against one of the listed internet-facing products.

### Search Metadata

- CVEs: CVE-2026-46300
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095
- Products: WordPress, Ghost CMS, Joomla, JCE, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce
- Platforms: Linux, Web
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-46300, T1190, WordPress, Ghost CMS, Joomla, JCE, Langflow, OpenCATS, Pterodactyl Panel, SonicWall SMA1000, Ray Dashboard, Pix-for-WooCommerce, Linux, Web, Metasploit, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (medium); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where OSPlatform == "Linux"
| where EffectiveAccountName == "root"
| where AccountName != "root"
| where InitiatingProcessFileName in~ (
    "apache2", "httpd", "nginx", "php-fpm", "php", "node",
    "python", "python3", "java", "ghost", "gunicorn", "uwsgi"
  )
| where ProcessCommandLine !has "sudo" and ProcessCommandLine !has " su "
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    EffectiveAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Managed services or container orchestration systems that legitimately spawn root processes from web server parents during initialization.
- Application health check scripts running as root from web server process trees.
- Legitimate setuid binaries invoked from web server contexts that result in root-owned child processes.

**Tuning notes:**
- Confirm EffectiveAccountName availability: DeviceProcessEvents → where OSPlatform == 'Linux' → summarize count() by isnotempty(EffectiveAccountName)
- Extend InitiatingProcessFileName list with environment-specific runtimes such as ruby, perl, or application-specific binaries.
- Consider adding a DeviceName filter joined against a known internet-facing host inventory to focus on highest-risk attack surface.

**Risks / caveats:**
- EffectiveAccountName is not consistently populated for Linux process events in all Defender for Endpoint Linux agent versions; verify with: DeviceProcessEvents → where OSPlatform == 'Linux' → where isnotempty(EffectiveAccountName) → take 1
- AccountName may reflect the process owner rather than the spawning user context on some Linux configurations, affecting the AccountName != 'root' exclusion logic.
- EffectiveAccountName must be confirmed populated for Linux hosts in the tenant before relying on this detection.
- Web server process names vary by distribution and deployment; the InitiatingProcessFileName list should be extended to match environment-specific application server names.

### Triage Runbook

**First 15 minutes:**
- Verify the parent process is a web server or application runtime and confirm the child process unexpectedly runs as root.
- Check the child process command line for exploit artifacts, shell invocation, or post-exploitation tooling.
- Identify the affected Linux host’s role and whether it is internet-facing or runs one of the listed vulnerable products.
- Look for adjacent signs of compromise such as web shell activity, suspicious outbound connections, file writes in web directories, or new privileged accounts.

**Evidence to collect:**
- DeviceProcessEvents for the full process tree around the alert, including parent, child, and sibling processes.
- Web server and application logs for the same timestamp to identify the request or payload that preceded the escalation.
- DeviceFileEvents for recent writes to web roots, temporary directories, cron locations, or suspicious binaries.
- Authentication and sudo logs, if available, to confirm the escalation did not occur through legitimate administrative activity.

**Pivot points:**
- DeviceProcessEvents filtered on the host and a 24-hour window to find other root-owned processes spawned by the same web server parent.
- DeviceFileEvents filtered on the host for recent changes in web directories, /tmp, /var/tmp, /etc/cron*, or SSH-related paths.
- DeviceNetworkEvents for the host to identify outbound reverse shells, unusual ports, or new external destinations.
- Application and reverse proxy logs to correlate the exact request path, source IP, and exploit timing.

**Benign explanations:**
- Managed services or application startup scripts that legitimately spawn root-owned helper processes.
- Container orchestration or health-check tooling that runs privileged maintenance tasks from a web-facing service context.
- Approved setuid binaries or administrative wrappers invoked by the application stack during maintenance.

**Escalation criteria:**
- A web server or application process spawns root-owned children without a documented maintenance action.
- The host also shows web shell indicators, suspicious outbound connections, or unauthorized file changes.
- The affected system is internet-facing and runs one of the products named in the detection context.
- The escalation is repeated or occurs on multiple hosts in the same application tier.

**Containment actions:**
- If compromise is likely, isolate the Linux host from the network to prevent further post-exploitation activity.
- Disable the exposed application or virtual host if it is actively being abused and business impact is acceptable.
- Preserve volatile evidence and logs before remediation, then rotate credentials and secrets that may have been exposed.

**Closure criteria:**
- The root-owned process is explained by a documented administrative or application maintenance workflow.
- No exploit artifacts, web shell indicators, or suspicious outbound activity are found in the surrounding telemetry.
- The host is confirmed not to be internet-facing or not running the vulnerable application stack at the time of the event.
- A benign root-spawn pattern is baselined and approved by the system owner.

<br/>
---
<br/>

## Detection 4: Outbound Reverse Shell Connection from Unexpected Process on Windows ARM Device

### Detection Opportunity

An unexpected process on a Windows ARM (AArch64) device establishes an outbound TCP connection to a non-corporate IP, consistent with Metasploit AArch64 reverse-TCP shell post-exploitation.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Lot of summer shells and fit http profiles — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles)
  - Context: Metasploit added brand-new AArch64 reverse-TCP shell payloads targeting Windows on ARM. Post-exploitation reverse shells produce outbound TCP connections from unusual processes to attacker-controlled infrastructure, a pattern detectable via network telemetry correlated with process context.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095
- Products: Not specified
- Platforms: Windows, Windows on ARM
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Windows, Windows on ARM, Metasploit, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (medium); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let arm_devices =
    DeviceProcessEvents
    | where TimeGenerated >= ago(1d)
    | where ProcessVersionInfoProductName has_any ("ARM", "AArch64") or FolderPath has "ARM64"
    | distinct DeviceName;
DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| where DeviceName in (arm_devices)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (4444, 4445, 5555, 8080, 8443, 1337)
| where InitiatingProcessFileName !in~ (
    "svchost.exe", "MsMpEng.exe", "OneDrive.exe", "Teams.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe"
  )
| where not (
    RemoteIP startswith "10." or
    RemoteIP startswith "192.168." or
    RemoteIP startswith "172.16." or
    RemoteIP startswith "172.17." or
    RemoteIP startswith "172.18." or
    RemoteIP startswith "172.19." or
    RemoteIP startswith "172.20." or
    RemoteIP startswith "172.21." or
    RemoteIP startswith "172.22." or
    RemoteIP startswith "172.23." or
    RemoteIP startswith "172.24." or
    RemoteIP startswith "172.25." or
    RemoteIP startswith "172.26." or
    RemoteIP startswith "172.27." or
    RemoteIP startswith "172.28." or
    RemoteIP startswith "172.29." or
    RemoteIP startswith "172.30." or
    RemoteIP startswith "172.31." or
    RemoteIP startswith "127."
  )
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Development tools or build agents on ARM devices making outbound connections on common ports.
- Remote management or monitoring agents not included in the exclusion list.
- VPN or tunneling software initiating connections on ports overlapping with the filter list.

**Tuning notes:**
- If DeviceInfo table is available with an OSArchitecture field, replace the arm_devices subquery with: DeviceInfo → where OSArchitecture has_any ('ARM', 'ARM64') → distinct DeviceName
- Extend the RemotePort list based on observed attacker handler configurations from threat intelligence.
- Add corporate proxy or egress IP ranges to the exclusion list if outbound traffic is routed through known infrastructure.

**Risks / caveats:**
- ProcessVersionInfoProductName is not reliably populated for all processes in DeviceProcessEvents and may not contain ARM/AArch64 strings for most executables, making the ARM device identification subquery unreliable.
- The broad RemotePort range (1024-65535) combined with the process exclusion list will generate extremely high result volumes in most environments, making this impractical as a scheduled rule.
- The arm_devices subquery relies on ProcessVersionInfoProductName and FolderPath heuristics which are not reliable identifiers for Windows ARM devices; a device inventory join or DeviceInfo table filter on OSArchitecture would be more accurate if that field is available.
- Port list covers only known Metasploit defaults; operators may configure custom handler ports that would be missed.

### Triage Runbook

**First 15 minutes:**
- Validate the initiating process name, parent process, and command line; unexpected shells, script hosts, or uncommon binaries are highest priority.
- Confirm the destination IP is not a corporate, VPN, proxy, or management endpoint and check whether the port matches common reverse-shell handlers.
- Determine whether the device is truly Windows on ARM and whether the process is expected on that device class.
- Look for concurrent signs of compromise such as new services, scheduled tasks, suspicious downloads, or credential access on the same host.

**Evidence to collect:**
- DeviceNetworkEvents for the host to identify all outbound connections from the same process and any repeated beaconing.
- DeviceProcessEvents for the process tree, including parent process, command line, and any spawned children.
- DeviceFileEvents for recent downloads, script drops, or executable creation in user-writable directories.
- DeviceInfo or asset inventory data to confirm OS architecture and device ownership, if available.

**Pivot points:**
- DeviceNetworkEvents filtered on DeviceName and RemoteIP to find other connections to the same destination or port.
- DeviceProcessEvents filtered on the initiating process name and parent process to identify the launch chain and any shell activity.
- DeviceFileEvents filtered on the host for recent executable, script, or archive creation in Downloads, Temp, or AppData.
- If available, DeviceInfo to validate ARM architecture and whether the device is managed or high risk.

**Benign explanations:**
- Development tools, build agents, or remote administration software on ARM devices.
- VPN, tunneling, or monitoring agents that use ports overlapping with the detection.
- Legitimate application testing or lab activity on a Windows on ARM device.

**Escalation criteria:**
- The process is not recognized, is unsigned, or runs from a user-writable or temporary path.
- The destination IP is external and not associated with approved corporate infrastructure.
- The host shows additional compromise indicators such as persistence, credential theft, or repeated outbound callbacks.
- Multiple ARM devices exhibit the same process and destination pattern, suggesting a broader campaign.

**Containment actions:**
- Isolate the host if the connection is confirmed or strongly suspected to be a reverse shell.
- Terminate the suspicious process only after preserving evidence if your incident workflow requires it.
- Block the destination IP or port at the egress layer if it is clearly malicious and not business-related.

**Closure criteria:**
- The process is identified as a legitimate application or management tool with an approved business purpose.
- The destination is confirmed to be corporate infrastructure, a proxy, or a sanctioned testing endpoint.
- No additional suspicious process activity or persistence is found on the device.
- The event is attributed to a known lab, developer, or remote support workflow and documented.

<br/>
---
<br/>

## Detection 5: Non-Telegram Process Accessing Telegram tdata Directory - Still Toolkit Data Theft Pattern

### Detection Opportunity

A process other than the Telegram client reads files from the Telegram AppData tdata directory, consistent with the Still Toolkit stealing Telegram session data as used by Armored Likho.

### Intelligence Context

- Securelist: Armored Likho expands its cyber-espionage toolkit — [https://securelist.com/armored-likho-still-toolkit/121033/](https://securelist.com/armored-likho-still-toolkit/121033/)
  - Context: Armored Likho's Still Toolkit is designed to steal Telegram data from victims. On Windows, Telegram stores session data in the user's AppData roaming directory under Telegram Desktop\tdata. Access to this directory by any process other than Telegram.exe is a strong indicator of credential or session theft.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1555, T1555.007, T1213
- Products: Telegram
- Platforms: Windows, Telegram
- Malware: Still Toolkit
- Tools: Not specified
- Search tags: Armored Likho, Still Toolkit, Telegram, Windows, T1555, T1555.007, T1213

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores/ T1555.007 Cloud Account (low); Collection: T1213 Data from Information Repositories (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where TimeGenerated >= ago(1d)
| where FolderPath has_all ("Telegram Desktop", "tdata")
| where ActionType in ("FileRead", "FileAccessed", "FileCopied")
| where InitiatingProcessFileName !in~ ("Telegram.exe", "Updater.exe")
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FolderPath,
    FileName,
    ActionType,
    SHA256
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup software agents that perform file-level backups of AppData directories.
- Antivirus or EDR scanning processes accessing tdata files during scheduled scans.
- Telegram variants or forks installed in non-standard paths that use different executable names.

**Tuning notes:**
- Confirm ActionType availability: DeviceFileEvents → where TimeGenerated >= ago(1d) → summarize count() by ActionType
- Add backup agent process names to the !in~ exclusion list after identifying them in your environment.
- Extend lookback to 7d for initial hunting to establish baseline before reducing to 1d for scheduled alerting.

**Risks / caveats:**
- ActionType values 'FileRead' and 'FileAccessed' may not be present in all Defender for Endpoint configurations; verify with: DeviceFileEvents → summarize count() by ActionType → where ActionType in ('FileRead', 'FileAccessed', 'FileCopied')
- Backup software and AV scanning processes will generate false positives until excluded; build an allowlist of known backup agent process names after initial baselining.
- Portable Telegram installations or Telegram forks using different executable names will not be covered by the current exclusion list.
- FileRead and FileAccessed ActionType availability should be confirmed before scheduling to avoid silent empty results.

### Triage Runbook

**First 15 minutes:**
- Check the accessing process name, path, and command line; prioritize unknown binaries, script hosts, archive tools, and processes running from user profile or temp paths.
- Confirm whether the process is Telegram.exe or Updater.exe; if not, treat the access as suspicious until explained.
- Identify the user account and device owner to see whether the activity aligns with a known backup, migration, or support task.
- Look for nearby evidence of credential theft, file staging, or exfiltration from the same host.

**Evidence to collect:**
- DeviceFileEvents for all accesses to the Telegram Desktop tdata path on the host during the alert window.
- DeviceProcessEvents for the accessing process and its parent/child chain, including command line and folder path.
- DeviceNetworkEvents for outbound connections shortly after the file access, especially to cloud storage, messaging, or paste sites.
- Any endpoint protection or backup agent logs that can explain the file read or copy activity.

**Pivot points:**
- DeviceFileEvents filtered on DeviceName and the Telegram tdata path to identify repeated access patterns and other accessing processes.
- DeviceProcessEvents filtered on the initiating process name to determine whether the binary is known, signed, and expected.
- DeviceNetworkEvents filtered on the host for post-access exfiltration destinations or unusual upload behavior.
- If available, correlate with user logon events to see whether the access occurred during a normal user session or outside business hours.

**Benign explanations:**
- Backup software or endpoint migration tools that scan AppData directories.
- Antivirus or EDR products that inspect Telegram files during scheduled scans.
- A legitimate Telegram client variant or portable installation using a different executable name than expected.

**Escalation criteria:**
- A non-approved process accesses the tdata directory and is not tied to backup, security, or support tooling.
- The same host shows file staging, archive creation, or outbound connections after the access.
- The process is unsigned, runs from an unusual path, or is associated with known infostealer behavior.
- Multiple Telegram-related files are accessed in a short period, suggesting automated collection.

**Containment actions:**
- If unauthorized access is confirmed, isolate the host to prevent further credential theft or exfiltration.
- Terminate the suspicious process only after preserving evidence if your response process supports it.
- Reset Telegram-related sessions or credentials for the affected user if compromise is likely and coordinate with the account owner.

**Closure criteria:**
- The accessing process is verified as a legitimate backup, security, or Telegram-related application.
- The activity is consistent with a documented support, migration, or maintenance task and no exfiltration follows.
- No other suspicious file access, process activity, or network behavior is found on the host.
- An allowlist exception is created for the approved process, path, and user context.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Non-Browser Process Outbound Connection to Telegram API - Potential Exfiltration: Do not schedule yet; validate as an analyst-led hunt first.
- Non-Browser Process Outbound Connection to Telegram API - Potential Exfiltration: If RemoteUrl is not populated, consider correlating DeviceNetworkEvents with DeviceDnsEvents on RemoteIP to identify Telegram API destinations via DNS resolution.
- Outbound Reverse Shell Connection from Unexpected Process on Windows ARM Device: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Unsigned or Anomalous Kernel Driver Load from Non-Standard Path - HoneyMyte CoolClient Rootkit Pattern: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents before scheduling.
- Privilege Escalation to Root from Web Server Parent Process - CVE-2026-46300 Linux Kernel LPE Pattern: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: DeviceProcessEvents before scheduling.

**Shared-table notes:**
- DeviceNetworkEvents: shared by Non-Browser Process Outbound Connection to Telegram API - Potential Exfiltration; Outbound Reverse Shell Connection from Unexpected Process on Windows ARM Device
- DeviceProcessEvents: shared by Privilege Escalation to Root from Web Server Parent Process - CVE-2026-46300 Linux Kernel LPE Pattern; Outbound Reverse Shell Connection from Unexpected Process on Windows ARM Device

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Non-Telegram Process Accessing Telegram tdata Directory - Still Toolkit Data Theft Pattern.
2. Resolve environment-mapping detections next: Unsigned or Anomalous Kernel Driver Load from Non-Standard Path - HoneyMyte CoolClient Rootkit Pattern; Privilege Escalation to Root from Web Server Parent Process - CVE-2026-46300 Linux Kernel LPE Pattern.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Non-Browser Process Outbound Connection to Telegram API - Potential Exfiltration; Outbound Reverse Shell Connection from Unexpected Process on Windows ARM Device.

### Hunting Agenda and Promotion Criteria

- Non-Browser Process Outbound Connection to Telegram API - Potential Exfiltration: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Outbound Reverse Shell Connection from Unexpected Process on Windows ARM Device: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Unsigned or Anomalous Kernel Driver Load from Non-Standard Path - HoneyMyte CoolClient Rootkit Pattern: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Privilege Escalation to Root from Web Server Parent Process - CVE-2026-46300 Linux Kernel LPE Pattern: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
