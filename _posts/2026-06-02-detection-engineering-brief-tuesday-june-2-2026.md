---
layout: post
title: "Detection Engineering Brief - Tuesday, June 2, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-02
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - NetSupport RAT
  - Windows
  - FlutterShell
  - macOS
  - containers
  - cloud
  - T1071
  - T1543.001
  - T1543.004
  - T1543
  - T1552.001
  - T1526
  - T1552
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: NetSupport RAT, Windows, FlutterShell, macOS, containers, cloud, T1071, T1543.001, T1543.004, T1543, T1552.001, T1526, T1552.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: macOS Browser Spawning Shell Interpreter or Unsigned Binary - FlutterShell Dropper Chain; macOS LaunchAgent or LaunchDaemon Plist Written by Non-System Process - FlutterShell Persistence; Anomalous Azure Key Vault or Kubernetes Secret Access by Unexpected Identity in Container Environment.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: NetSupport RAT Binary Spawned by Suspicious Parent Process

### Detection Opportunity

NetSupport RAT client binary executed as child of scripting engine, Office application, or unknown parent process on Windows host

### Intelligence Context

- SANS ISC: Unidentified RAT pushes NetSupport RAT, (Mon, Jun 1st) — [https://isc.sans.edu/diary/rss/33034](https://isc.sans.edu/diary/rss/33034)
  - Context: An unidentified RAT was observed deploying NetSupport RAT on Windows hosts. The campaign involves suspicious process chains where NetSupport RAT binaries are executed as children of unexpected parent processes, indicating malicious delivery rather than legitimate IT deployment.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071
- Products: Not specified
- Platforms: Windows
- Malware: NetSupport RAT
- Tools: Not specified
- Search tags: NetSupport RAT, Windows, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: command and control: T1071 Application Layer Protocol (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let NetSupportBinaries = dynamic(["client32.exe", "nsm.exe", "nscm.exe", "pcicl32.exe", "remcmdstub.exe"]);
let SuspiciousParents = dynamic(["wscript.exe", "cscript.exe", "powershell.exe", "cmd.exe", "mshta.exe", "winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "msiexec.exe", "regsvr32.exe", "rundll32.exe"]);
let PrivateRanges = dynamic(["10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254."]);
let NetSupportProcs = DeviceProcessEvents
| where FileName in~ (NetSupportBinaries)
| where InitiatingProcessFileName in~ (SuspiciousParents)
| project DeviceId, DeviceName, AccountName, AccountDomain, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, ProcessTimestamp = Timestamp, ProcessId;
let NetSupportNet = DeviceNetworkEvents
| where InitiatingProcessFileName in~ (NetSupportBinaries)
| where ActionType == "ConnectionSuccess"
| where not(RemoteIP has_any (PrivateRanges))
| project DeviceId, RemoteIP, RemotePort, NetworkTimestamp = Timestamp, NetInitiatingProcessFileName = InitiatingProcessFileName;
NetSupportProcs
| join kind=leftouter (NetSupportNet) on DeviceId
| project
    ProcessTimestamp,
    NetworkTimestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    RemoteIP,
    RemotePort
| order by ProcessTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate NetSupport Manager deployments where IT staff launch client32.exe from cmd.exe or PowerShell during troubleshooting.
- Software packaging workflows that invoke msiexec.exe to install NetSupport Manager, triggering the parent process match.
- Browser-based IT portals that launch remote support tools via chrome.exe or msedge.exe in managed environments.

Tuning notes:
- Add known corporate NetSupport Manager server IPs to the PrivateRanges list or a separate exclusion dynamic variable to suppress legitimate management traffic.
- If cmd.exe or PowerShell are common legitimate parent processes in the environment for NetSupport, scope those entries with additional ProcessCommandLine filters rather than removing them from SuspiciousParents entirely.
- Consider adding InitiatingProcessFolderPath filters to exclude known IT deployment paths such as C:\Program Files\NetSupport\ from the parent process match.

Risks / caveats:
- The leftouter join may produce multiple rows per process event if the binary makes multiple outbound connections; analysts should be aware of row fan-out during triage.
- Ingestion delay between DeviceProcessEvents and DeviceNetworkEvents may cause network rows to be absent in near-real-time scheduled runs; a lookback window of at least 15 minutes is recommended for the scheduled rule frequency.

### Triage Runbook

First 15 minutes:
- Validate the parent process, command line, and folder path for the NetSupport binary; treat execution from user-writable or temporary paths as highly suspicious.
- Check whether the account is a helpdesk/admin identity and whether the host is a managed support endpoint with an approved NetSupport deployment.
- Review DeviceNetworkEvents for the same DeviceId and ProcessId to confirm outbound connections to non-private IPs and note the remote port and timestamp.
- Look for adjacent process activity on the host such as script interpreters, Office spawning, archive extraction, or download activity that would support malicious delivery.

Evidence to collect:
- Device name, account name, account domain, process command line, initiating process name, initiating process command line, and initiating process folder path.
- Network timestamp, remote IP, remote port, and whether the connection was to an external address or a known corporate support server.
- Any file path details showing whether the binary is in Program Files, a user profile, Downloads, Temp, or another staging location.
- Recent process tree and any preceding email, browser, or script activity on the same host.

Pivot points:
- DeviceProcessEvents for the same DeviceId to reconstruct the parent-child process tree and identify earlier suspicious execution.
- DeviceNetworkEvents for the same DeviceId and InitiatingProcessFileName to enumerate all outbound connections from the NetSupport binary.
- DeviceFileEvents for the same host to look for dropped installers, archives, or persistence artifacts near the alert time.
- Email, browser, or download telemetry if available to identify the initial delivery vector.

Benign explanations:
- Legitimate IT troubleshooting where helpdesk staff launched NetSupport client32.exe or related binaries from cmd.exe or PowerShell.
- Approved software packaging or deployment workflows that install NetSupport Manager through msiexec.exe.
- Managed remote support sessions initiated from browser-based IT portals in environments that officially use NetSupport.

Escalation criteria:
- The binary is running from an unexpected path, especially a user-writable directory, and the parent is Office, script, or browser activity not associated with IT support.
- Outbound connections are observed to unknown external IPs or characteristic NetSupport ports without a known corporate management server.
- Multiple hosts show the same pattern, or the host also shows persistence, credential access, or additional malware activity.
- The user or endpoint owner denies any approved remote support activity.

Containment actions:
- If malicious use is likely, isolate the host from the network using endpoint containment.
- Terminate the NetSupport process and any clearly related child processes after preserving evidence.
- Block the remote IPs observed in the alert if they are not known corporate support infrastructure.
- Disable or reset the user account if there is evidence of unauthorized interactive use or lateral movement.

Closure criteria:
- Confirmed approved NetSupport deployment or helpdesk session with matching account, host, path, and remote infrastructure.
- No suspicious parent process, no external C2 activity, and the binary resides in an expected managed installation path.
- No additional malicious process tree, persistence, or follow-on activity is found on the host.
- Document the approved support server IPs or paths for future allowlisting if validated by the environment owner.

---

## Detection 2: NetSupport RAT Outbound C2 Communication on Known Ports

### Detection Opportunity

NetSupport RAT binary initiating outbound connections to external IP addresses on ports associated with NetSupport Manager C2 protocol

### Intelligence Context

- SANS ISC: Unidentified RAT pushes NetSupport RAT, (Mon, Jun 1st) — [https://isc.sans.edu/diary/rss/33034](https://isc.sans.edu/diary/rss/33034)
  - Context: NetSupport RAT deployed by an unidentified staging RAT communicates outbound to C2 infrastructure. NetSupport RAT uses known binary names and characteristic ports, making outbound connections from client32.exe to external IPs a high-confidence detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071
- Products: Not specified
- Platforms: Windows
- Malware: NetSupport RAT
- Tools: Not specified
- Search tags: NetSupport RAT, Windows, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: command and control: T1071 Application Layer Protocol (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceNetworkEvents

### KQL

```kql
let NetSupportBinaries = dynamic(["client32.exe", "nsm.exe", "nscm.exe", "pcicl32.exe", "remcmdstub.exe"]);
let PrivateRanges = dynamic(["10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254."]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (NetSupportBinaries)
| where ActionType == "ConnectionSuccess"
| where not(RemoteIP has_any (PrivateRanges))
| where RemotePort in (5950, 80, 443, 5901)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    RemoteIP,
    RemotePort,
    RemoteUrl
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate NetSupport Manager deployments where client32.exe connects to corporate management servers on port 5950 or 443.
- IT remote support sessions initiated by helpdesk staff using licensed NetSupport Manager.
- Environments where NetSupport Manager is used as an approved remote access tool will generate high volumes of matches without IP-based exclusions.

Tuning notes:
- Add known corporate NetSupport Manager server IPs to a dynamic exclusion variable and apply a 'not(RemoteIP has_any(...))' filter to suppress legitimate management traffic.
- If port 80 and 443 generate excessive noise, consider removing them and relying on port 5950 and 5901 as primary C2 indicators, supplemented by the parent process detection.
- Consider adding an InitiatingProcessFolderPath filter to flag binaries running outside of expected installation paths such as C:\Program Files\NetSupport\.

Risks / caveats:
- Attackers using alternate ports for NetSupport C2 will evade this detection; port 5950 is the default but is not guaranteed.
- Port 80 and 443 matches will generate false positives in environments where NetSupport Manager uses HTTPS for legitimate management; IP-based exclusions are essential before scheduling.
- InitiatingProcessFolderPath is available in DeviceNetworkEvents in Defender XDR but population depends on the endpoint agent version; validate field availability in the tenant.

### Triage Runbook

First 15 minutes:
- Identify the initiating process path and command line to determine whether the NetSupport binary is running from an expected installation directory.
- Check the remote IP, remote port, and remote URL to see whether the destination matches a known corporate support server or an unknown external host.
- Review the account and device context to determine whether the activity aligns with a helpdesk session or an end-user workstation.
- Look for repeated connections, beaconing behavior, or multiple affected hosts using the same remote infrastructure.

Evidence to collect:
- Device name, account name, initiating process file name, command line, and folder path.
- Remote IP, remote port, remote URL, and whether the destination is internal, approved, or external.
- Connection timestamps and frequency to assess whether the traffic is interactive support or periodic beaconing.
- Any related process tree or file creation events around the same time.

Pivot points:
- DeviceNetworkEvents for the same DeviceName or DeviceId to enumerate all connections from the NetSupport binary.
- DeviceProcessEvents to confirm the parent process and whether the binary was launched by a suspicious script, Office app, or browser.
- DeviceFileEvents to check for installer drops, persistence, or staging artifacts on the host.
- If available, identity and helpdesk ticketing records to validate whether the session was authorized.

Benign explanations:
- Approved NetSupport Manager use by IT staff on a managed endpoint.
- Corporate support traffic to a known internal or vendor-managed NetSupport server.
- Software deployment or remote assistance workflows that legitimately use NetSupport on ports 5950, 443, or 5901.

Escalation criteria:
- The destination IP or URL is unknown, external, and not part of approved support infrastructure.
- The binary is not in an expected installation path or is launched by an unexpected parent process.
- The host shows repeated outbound connections consistent with beaconing or multiple NetSupport-related alerts.
- The user denies any support session and there is no corresponding helpdesk record.

Containment actions:
- Isolate the host if the connection is to an unknown external destination and the process is not approved.
- Block the remote IP or URL if confirmed malicious and not required for business operations.
- Terminate the NetSupport process if it is clearly unauthorized and preserve the command line and network evidence first.
- Escalate to endpoint response for full host scoping if additional suspicious activity is present.

Closure criteria:
- Destination is confirmed as an approved corporate support endpoint and the activity matches an authorized session.
- Process path, parent process, and account all align with documented remote support procedures.
- No additional suspicious network destinations or follow-on malware behavior are observed.
- Allowlist guidance is documented for known support infrastructure if needed.

---

## Detection 3: macOS Browser Spawning Shell Interpreter or Unsigned Binary - FlutterShell Dropper Chain

### Detection Opportunity

macOS browser process spawning a shell interpreter or unexpected child process consistent with malvertising-delivered dropper activity linked to FlutterShell backdoor campaign

### Intelligence Context

- Unit 42: Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor — [https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/)
  - Context: Operation FlutterBridge used malvertising to deliver the FlutterShell backdoor to macOS users. The delivery chain involves a browser process spawning unexpected child processes acting as droppers, which is the initial execution stage before backdoor installation and persistence.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1543.001, T1543.004, T1543
- Products: Not specified
- Platforms: macOS
- Malware: FlutterShell
- Tools: Not specified
- Search tags: FlutterShell, macOS, T1543.001, T1543.004, T1543

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: persistence: T1543 Create or Modify System Process/ T1543.001 Launch Agent (high); persistence: T1543 Create or Modify System Process/ T1543.004 Launch Daemon (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let BrowserBinaries = dynamic(["safari", "google chrome", "firefox", "microsoft edge", "chromium", "chrome", "msedge"]);
let ShellInterpreters = dynamic(["bash", "zsh", "sh", "python", "python3", "osascript", "perl", "ruby"]);
let SuspiciousStagingPaths = dynamic(["/tmp/", "/var/folders/", "/private/tmp/"]);
DeviceProcessEvents
| where OSPlatform == "macOS"
| where tolower(InitiatingProcessFileName) has_any (BrowserBinaries)
| where (
    tolower(FileName) in (ShellInterpreters)
    or FolderPath has_any (SuspiciousStagingPaths)
)
| where not(ProcessCommandLine has_any (
    "--type=renderer",
    "--type=gpu-process",
    "--type=utility",
    "NativeMessagingHost",
    "--type=crashpad-handler",
    "--type=broker"
))
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    FileName,
    ProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Browser extensions that invoke shell scripts for legitimate functionality.
- Developer workflows where browsers launch terminal or script processes as part of web development tooling.
- macOS applications that use osascript for legitimate AppleScript automation triggered via browser interaction.
- Software update mechanisms that use browsers as launchers for shell-based update scripts.

Tuning notes:
- Run the query without the SuspiciousStagingPaths filter first to understand the volume of shell spawns from browsers in the environment before adding path-based conditions.
- Add known legitimate browser helper binary names to the ProcessCommandLine exclusion list based on observed results.
- Consider adding a FolderPath exclusion for known browser application bundle paths such as /Applications/Google Chrome.app/ to reduce noise from browser-internal processes.
- Promote to scheduled_rule only after baselining false positive volume and adding environment-specific exclusions.

Risks / caveats:
- OSPlatform field population in DeviceProcessEvents for macOS endpoints requires Defender for Endpoint macOS agent onboarding; if macOS endpoints are not onboarded, this query will return no results.
- The OSPlatform value 'macOS' must be validated in the tenant as the exact string used by the Defender for Endpoint macOS agent, as alternate values such as 'Mac' or 'Darwin' may be present depending on agent version.
- The OSPlatform string value 'macOS' must be confirmed in the tenant before this query will return results; run a baseline query against DeviceProcessEvents filtering on OSPlatform to validate.
- Browser binary names in DeviceProcessEvents on macOS may differ from display names; validate that 'chrome', 'safari', and 'msedge' match the FileName values recorded by the Defender for Endpoint macOS agent in the environment.

### Triage Runbook

First 15 minutes:
- Inspect the browser parent process, child process name, command line, and folder path for evidence of a downloaded or staged payload.
- Check whether the child process is a shell interpreter or a process running from /tmp, /var/folders, or another writable staging location.
- Review the initiating process command line for browser type, download context, or suspicious arguments that indicate a malvertising or drive-by chain.
- Look for additional child processes, archive extraction, or script execution immediately after the alert.

Evidence to collect:
- Device name, account name, browser process name, child process name, command lines, and folder paths.
- Timestamp of the browser spawn and any subsequent process chain activity.
- Any file names or paths indicating downloaded payloads, temporary staging, or unsigned binaries.
- Whether the browser was interacting with a known developer tool, automation workflow, or a suspicious website.

Pivot points:
- DeviceProcessEvents on the same DeviceName to reconstruct the full process tree before and after the alert.
- DeviceFileEvents to identify downloaded files, archive extraction, or newly created executables in temporary paths.
- DeviceNetworkEvents to identify the source URL or remote host associated with the browser activity if available.
- If available, browser or proxy telemetry to determine the site visited immediately before the spawn.

Benign explanations:
- Legitimate browser-driven automation such as AppleScript, developer tooling, or local web app workflows.
- Browser extensions or native messaging hosts that invoke shell commands for approved functionality.
- Software update or installer workflows that temporarily launch shell interpreters from browser activity.

Escalation criteria:
- The child process is a shell interpreter or unsigned binary launched from a browser and runs from a temporary or user-writable path.
- The command line shows download, decode, execution, or staging behavior consistent with a dropper.
- The host shows additional suspicious activity such as persistence creation, credential access, or outbound C2.
- The user cannot explain the browser activity or the site is known to be malicious.

Containment actions:
- Isolate the macOS host if the browser spawn appears to be a malicious dropper chain.
- Terminate the suspicious child process and any related descendants after preserving evidence.
- Quarantine or remove any downloaded payloads identified in the staging path.
- Block the source domain or URL if confirmed malicious and not business-required.

Closure criteria:
- The browser-to-child process relationship is explained by a legitimate application, extension, or approved automation.
- No suspicious staging path, unsigned binary, or follow-on persistence is found.
- No additional malicious process tree or network activity is present.
- Document any legitimate browser helper patterns for future tuning if validated.

---

## Detection 4: macOS LaunchAgent or LaunchDaemon Plist Written by Non-System Process - FlutterShell Persistence

### Detection Opportunity

Persistence established on macOS host via plist file creation in LaunchAgents or LaunchDaemons directories by a non-system process, consistent with FlutterShell backdoor installation

### Intelligence Context

- Unit 42: Operation FlutterBridge: macOS Malvertising Campaign Spreads New FlutterShell Backdoor — [https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/](https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/)
  - Context: The FlutterShell backdoor delivered via Operation FlutterBridge establishes persistence on macOS hosts. macOS persistence via LaunchAgent or LaunchDaemon plist writes by untrusted or unexpected processes is a strong indicator of backdoor installation following the malvertising delivery chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1543.001, T1543.004, T1543
- Products: Not specified
- Platforms: macOS
- Malware: FlutterShell
- Tools: Not specified
- Search tags: FlutterShell, macOS, T1543.001, T1543.004, T1543

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: persistence: T1543 Create or Modify System Process/ T1543.001 Launch Agent (high); persistence: T1543 Create or Modify System Process/ T1543.004 Launch Daemon (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
let PersistencePaths = dynamic(["/Library/LaunchAgents/", "/Library/LaunchDaemons/"]);
let SystemInstallers = dynamic(["installer", "softwareupdate", "mdmclient", "jamf", "munki", "puppet", "chef"]);
DeviceFileEvents
| where OSPlatform == "macOS"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (PersistencePaths)
| where FileName endswith ".plist"
| where not(tolower(InitiatingProcessFileName) in (SystemInstallers))
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    ActionType,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- MDM-managed software deployments writing LaunchAgent plists for legitimate applications.
- Application installers that write their own LaunchAgent plists during installation.
- Developer tools such as Homebrew services that write LaunchAgent plists for background services.
- Endpoint security agents that write their own persistence plists during installation or update.

Tuning notes:
- Run a baseline query against DeviceFileEvents filtering on FolderPath containing '/Library/LaunchAgents/' to confirm telemetry availability and identify the volume of legitimate plist writes before scheduling.
- Expand SystemInstallers with all endpoint management and deployment tool binary names observed in the environment.
- Consider adding a separate detection or extending this query to cover user-level LaunchAgent paths by adding a FolderPath pattern matching '/Users/' and '/Library/LaunchAgents/' in combination.
- Add InitiatingProcessFolderPath filters to flag processes writing plists from staging directories such as /tmp/ or /var/folders/ as higher confidence indicators.

Risks / caveats:
- OSPlatform field availability in DeviceFileEvents for macOS endpoints must be confirmed; macOS file event telemetry requires Defender for Endpoint macOS agent with file monitoring enabled, which is not enabled by default in all configurations.
- The OSPlatform string value 'macOS' must be validated in the tenant as the exact value recorded by the agent; alternate values may exist depending on agent version.
- DeviceFileEvents ActionType values 'FileCreated' and 'FileModified' must be confirmed as supported on macOS endpoints in the tenant; file event ActionType coverage on macOS may differ from Windows.
- The SystemInstallers exclusion list must be expanded with all MDM, endpoint management, and software deployment tool binary names used in the environment before scheduling to avoid suppressing legitimate activity.

### Triage Runbook

First 15 minutes:
- Review the written plist path, file name, and initiating process to determine whether the write targets LaunchAgents or LaunchDaemons.
- Check whether the writing process is a known installer, MDM tool, or endpoint management agent from an approved path.
- Inspect the plist contents if available to identify the program path, arguments, and run-at-login or keep-alive settings.
- Look for matching process execution, downloads, or network activity that would indicate the plist was written as part of malware installation.

Evidence to collect:
- Device name, account name, file name, folder path, action type, and SHA256 if present.
- Initiating process file name, command line, and folder path.
- The exact LaunchAgents or LaunchDaemons path and whether it is user-level or system-level.
- Any related binaries, scripts, or network connections created around the same time.

Pivot points:
- DeviceFileEvents for the same host to find other plist writes, executable drops, or modifications near the alert time.
- DeviceProcessEvents to identify the process tree that led to the plist creation.
- DeviceNetworkEvents to see whether the writing process or dropped binary contacted external infrastructure.
- If available, endpoint management logs to confirm whether the action came from Jamf, Munki, MDM, or another approved tool.

Benign explanations:
- Legitimate software installation or update activity by MDM, Jamf, Munki, or another approved deployment system.
- Homebrew services or developer tools that create LaunchAgent plists for background services.
- Endpoint security or productivity software that installs its own persistence mechanism during setup or upgrade.

Escalation criteria:
- The plist is written by a non-system process from a user-writable or temporary path.
- The plist points to an unexpected executable, script, or command line, especially one in /tmp, /var/folders, or a hidden directory.
- The host also shows browser-delivered payloads, shell execution, or outbound C2 activity.
- The writing process is not an approved installer or management agent and the user cannot justify the change.

Containment actions:
- Isolate the host if the plist appears to establish unauthorized persistence.
- Remove or quarantine the malicious plist and associated payload after preserving a copy for analysis.
- Terminate the associated process tree if it is still active.
- Coordinate with endpoint engineering before removing any file if there is uncertainty about legitimate management software.

Closure criteria:
- The plist write is confirmed as part of an approved installer, MDM action, or known software update.
- The plist contents and target binary are consistent with legitimate business software.
- No suspicious companion files, scripts, or network activity are found.
- Environment-specific management tools are documented for future allowlisting if needed.

---

## Detection 5: Anomalous Azure Key Vault or Kubernetes Secret Access by Unexpected Identity in Container Environment

### Detection Opportunity

Bulk or anomalous reads of cloud secrets from Azure Key Vault or Kubernetes secret stores by non-standard service principals, pods, or identities in containerized environments

### Intelligence Context

- Securelist: Containers on fire: from container escapes to supply chain attacks — [https://securelist.com/container-attack-vectors/120010/](https://securelist.com/container-attack-vectors/120010/)
  - Context: Securelist identified exposed secrets as a primary attack vector in containerized environments. Attackers access or exfiltrate secrets from cloud secret stores and Kubernetes environments as part of container compromise chains including privilege escalation and lateral movement.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552.001, T1526, T1552
- Products: Not specified
- Platforms: containers, cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: containers, cloud, T1552.001, T1526, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: credential access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low); discovery: T1526 Cloud Service Discovery (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- AuditLogs connector for Entra ID must be configured in Sentinel; if not connected, the AuditLogs table will be absent or empty.

Required telemetry:
- AzureActivity, AuditLogs

### KQL

```kql
let LookbackWindow = 1h;
let SecretOps = dynamic(["SecretGet", "SecretList", "VaultGet", "KeyGet", "CertificateGet", "secrets/read", "keys/read", "certificates/read"]);
let AuditOps = dynamic(["Add service principal", "Update service principal", "Add member to role"]);
let SecretActivity = AzureActivity
| where TimeGenerated >= ago(LookbackWindow)
| where OperationName has_any (SecretOps)
| where ActivityStatus == "Succeeded"
| summarize
    SecretAccessCount = count(),
    DistinctResources = dcount(ResourceId),
    CallerIPs = make_set(CallerIpAddress, 20),
    Resources = make_set(ResourceId, 20)
    by Caller, bin(TimeGenerated, 10m)
| where SecretAccessCount > 10 or DistinctResources > 5;
let RecentAuditEvents = AuditLogs
| where TimeGenerated >= ago(LookbackWindow)
| where OperationName has_any (AuditOps)
| extend AuditInitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend AuditInitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend AuditInitiatedBy = iff(isnotempty(AuditInitiatedByUser), AuditInitiatedByUser, AuditInitiatedByApp)
| project AuditTimestamp = TimeGenerated, AuditOperation = OperationName, AuditInitiatedBy;
SecretActivity
| join kind=leftouter (
    RecentAuditEvents
) on $left.Caller == $right.AuditInitiatedBy
| project
    TimeGenerated,
    Caller,
    SecretAccessCount,
    DistinctResources,
    CallerIPs,
    Resources,
    AuditOperation,
    AuditInitiatedBy
| order by SecretAccessCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- CI/CD pipelines that read multiple secrets at deployment time will exceed the volume threshold.
- Application initialization sequences that bulk-read configuration secrets from Key Vault on startup.
- Automated rotation scripts that enumerate and update secrets across multiple vaults.
- Monitoring or compliance tools that periodically enumerate Key Vault contents.

Tuning notes:
- Add known CI/CD service principal names or object IDs to a Caller exclusion list to suppress expected pipeline secret reads.
- Adjust SecretAccessCount and DistinctResources thresholds after running the query in hunting mode to establish a baseline for the environment.
- To extend coverage to Kubernetes secret access, add a separate query branch against ContainerLog or KubeAudit tables if those data sources are connected to Sentinel.
- Consider splitting the detection into two separate rules: one for high-volume secret reads and one for secret reads by newly created or recently modified service principals, to improve signal clarity.

Risks / caveats:
- Azure Key Vault diagnostic logging must be explicitly enabled per vault and forwarded to the Log Analytics workspace backing Sentinel; without this configuration, AzureActivity will not contain SecretGet or SecretList operations and the query will return no results.
- AuditLogs connector for Entra ID must be configured in Sentinel; if not connected, the AuditLogs table will be absent or empty.
- The AuditLogs InitiatedBy field is a dynamic JSON object in Sentinel; direct string comparison using tostring(InitiatedBy) may not reliably extract the UPN or service principal ID needed to match against AzureActivity.Caller. The correct extraction is tostring(InitiatedBy.user.userPrincipalName) or tostring(InitiatedBy.app.servicePrincipalId) depending on the initiator type.
- AzureActivity OperationName values for Key Vault operations may appear as 'Microsoft.KeyVault/vaults/secrets/read' rather than 'SecretGet' depending on the diagnostic log schema version; the has_any filter on short names must be validated against actual OperationName values in the tenant.

### Triage Runbook

First 15 minutes:
- Identify the caller, resource IDs, access count, and distinct resource count to understand whether the activity is bulk enumeration or normal application startup.
- Check whether the identity is a known CI/CD service principal, workload identity, or application that routinely reads secrets.
- Review the time window and source IPs to see whether the access came from an expected cluster, pipeline, or management network.
- Look for recent identity changes, role assignments, or service principal modifications that could explain the access pattern.

Evidence to collect:
- Caller, caller IPs, accessed resources, access count, distinct resource count, and time window.
- Audit operation and audit initiated-by identity details for recent changes to the same principal.
- Resource group, subscription, vault names, and any associated Kubernetes cluster or workload identity information.
- Whether the access pattern aligns with deployment, rotation, or application initialization activity.

Pivot points:
- AzureActivity to review all secret-related operations by the same caller over a longer lookback window.
- AuditLogs to identify recent service principal, role assignment, or application changes tied to the caller.
- If available, Kubernetes audit or container telemetry to validate whether the identity maps to a pod or workload.
- Key Vault diagnostic logs or resource logs to confirm the exact secret operations and source IPs.

Benign explanations:
- CI/CD pipelines that read multiple secrets during deployment or application startup.
- Automated secret rotation or configuration refresh jobs.
- Monitoring, compliance, or inventory tools that enumerate vault contents on a schedule.

Escalation criteria:
- The caller is not a known workload identity, service principal, or approved automation account.
- Secret access is high-volume, spans many resources, or occurs from an unexpected IP or environment.
- Recent identity changes suggest the principal was newly created, modified, or granted elevated access.
- There is evidence of follow-on misuse such as token abuse, privilege escalation, or data exfiltration.

Containment actions:
- Disable or revoke the suspicious service principal, managed identity, or user if unauthorized access is confirmed.
- Rotate exposed secrets if the access is not clearly legitimate or if sensitive vaults were touched.
- Restrict Key Vault access policies or role assignments for the affected identity pending investigation.
- If a container workload is implicated, isolate the cluster workload or scale down the affected deployment as appropriate.

Closure criteria:
- The caller is confirmed as an approved application, pipeline, or workload with documented secret access needs.
- Access volume and resource breadth are consistent with normal baseline behavior.
- No suspicious identity changes, unauthorized IPs, or follow-on activity are found.
- Any necessary allowlist or threshold tuning is documented for the environment.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- macOS Browser Spawning Shell Interpreter or Unsigned Binary - FlutterShell Dropper Chain: Do not schedule yet; validate as an analyst-led hunt first.
- Anomalous Azure Key Vault or Kubernetes Secret Access by Unexpected Identity in Container Environment: Do not schedule yet; validate as an analyst-led hunt first.

Other deployment dependency:
- macOS LaunchAgent or LaunchDaemon Plist Written by Non-System Process - FlutterShell Persistence: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Telemetry availability:
- Anomalous Azure Key Vault or Kubernetes Secret Access by Unexpected Identity in Container Environment: AuditLogs connector for Entra ID must be configured in Sentinel; if not connected, the AuditLogs table will be absent or empty.

Shared-table notes:
- DeviceProcessEvents: shared by NetSupport RAT Binary Spawned by Suspicious Parent Process; macOS Browser Spawning Shell Interpreter or Unsigned Binary - FlutterShell Dropper Chain
- DeviceNetworkEvents: shared by NetSupport RAT Binary Spawned by Suspicious Parent Process; NetSupport RAT Outbound C2 Communication on Known Ports

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: NetSupport RAT Binary Spawned by Suspicious Parent Process; NetSupport RAT Outbound C2 Communication on Known Ports.
2. Resolve environment-mapping detections next: macOS LaunchAgent or LaunchDaemon Plist Written by Non-System Process - FlutterShell Persistence.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: macOS Browser Spawning Shell Interpreter or Unsigned Binary - FlutterShell Dropper Chain; Anomalous Azure Key Vault or Kubernetes Secret Access by Unexpected Identity in Container Environment.

### Hunting Agenda and Promotion Criteria

- macOS Browser Spawning Shell Interpreter or Unsigned Binary - FlutterShell Dropper Chain: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Anomalous Azure Key Vault or Kubernetes Secret Access by Unexpected Identity in Container Environment: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- macOS LaunchAgent or LaunchDaemon Plist Written by Non-System Process - FlutterShell Persistence: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
