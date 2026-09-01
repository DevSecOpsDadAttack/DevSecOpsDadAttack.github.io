---
layout: post
title: "Detection Engineering Brief - Tuesday, September 1, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-01
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Microsoft Defender XDR
  - Microsoft 365
  - Windows
  - ValleyRAT
  - Microsoft Teams
  - Active Directory
  - T1090
  - T1090.001
  - T1204
  - T1204.002
  - T1036
  - T1071
  - T1071.001
  - T1078
  - T1016
  - T1087
  - T1087.002
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Microsoft Defender XDR, Microsoft 365, Windows, ValleyRAT, Microsoft Teams, Active Directory, T1090, T1090.001, T1204, T1204.002, T1036, T1071, T1071.001, T1078, T1016, T1087, T1087.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: TerminalFix - DLL Sideloading via Unsigned DLL in User-Writable Path; TerminalFix - Reverse Tunnel Outbound Connection from Unexpected Process; ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound; Spring Ring - Unusual Interactive Logon to Domain Controller Followed by Reconnaissance Commands.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: TerminalFix - DLL Sideloading via Unsigned DLL in User-Writable Path

### Detection Opportunity

DLL sideloading using unsigned DLLs loaded from user-writable directories alongside legitimate executables during multistage intrusion

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign explicitly performs DLL sideloading as part of its multistage intrusion chain. Unsigned DLLs loaded from user-writable paths alongside legitimate executables are the primary artifact of this technique.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090, T1090.001
- Products: Microsoft Defender XDR, Microsoft 365
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Defender XDR, Microsoft 365, Windows, T1090, T1090.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- DeviceImageLoadEvents, DeviceProcessEvents

### KQL

```kql
let suspiciousPaths = dynamic(['\\temp\\', '\\appdata\\', '\\downloads\\', '\\programdata\\', '\\users\\public\\']);
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where (isnull(Signer) or Signer == '') and (isnull(SignatureStatus) or SignatureStatus != 'Valid')
| where FolderPath has_any (suspiciousPaths)
| where FolderPath !has 'system32'
    and FolderPath !has 'syswow64'
    and FolderPath !has 'winsxs'
    and FolderPath !has 'program files'
| project
    LoadTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    LoadingProcess = InitiatingProcessFileName,
    LoadingProcessId = InitiatingProcessId,
    LoadedDLL = FileName,
    DLLPath = FolderPath,
    DLLSHA256 = SHA256
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | project
        DeviceId,
        ProcessId,
        ProcessFileName = FileName,
        ProcessCommandLine
) on DeviceId, $left.LoadingProcessId == $right.ProcessId
| project
    LoadTimestamp,
    DeviceName,
    LoadingProcess,
    LoadedDLL,
    DLLPath,
    DLLSHA256,
    ProcessCommandLine
| summarize
    DLLsLoaded = make_set(LoadedDLL),
    Paths = make_set(DLLPath),
    Hashes = make_set(DLLSHA256),
    Commands = make_set(ProcessCommandLine)
    by DeviceName, LoadingProcess, bin(LoadTimestamp, 1h)
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software that ships unsigned DLLs into AppData or ProgramData during installation or update cycles.
- Developer workstations where locally compiled DLLs are loaded from user-writable paths.
- Portable application bundles that extract unsigned components into Temp directories at runtime.

**Tuning notes:**
- Extend suspiciousPaths with any additional environment-specific user-writable directories.
- Add known legitimate loading processes (e.g., specific vendor updaters) to an exclusion list once baseline is established.
- Consider adding a minimum file age filter using FileCreationTime if available to focus on recently dropped DLLs.

**Risks / caveats:**
- Signer and SignatureStatus fields in DeviceImageLoadEvents are only populated when Microsoft Defender for Endpoint is operating in full telemetry mode; sparse population will cause the unsigned-DLL filter to drop legitimate sideloading events.
- DeviceImageLoadEvents requires Microsoft Defender for Endpoint P2 licensing and may not be available in all M365 Defender tenants.
- Signer and SignatureStatus field population depends on Defender for Endpoint telemetry completeness; sparse data will reduce detection coverage.
- The 7-day lookback may produce large result sets in environments with high software deployment activity; consider reducing to 1-2 days during initial baselining.

### Triage Runbook

**First 15 minutes:**
- Confirm the loading process name, command line, and parent process to see whether the DLL load is tied to a known installer, updater, or portable app.
- Check whether the DLL path is in AppData, Temp, Downloads, ProgramData, or Public and whether the file was recently created or modified.
- Review the DLL hash and any related file reputation in Defender XDR to see if the file is known, unsigned, or previously observed on other hosts.
- Look for nearby process creation, network connections, or additional DLL loads from the same host within the same hour to identify a multistage intrusion pattern.

**Evidence to collect:**
- DeviceName, LoadingProcess, LoadingProcessId, ProcessCommandLine, and LoadTimestamp
- LoadedDLL, DLLPath, DLLSHA256, Signer, and SignatureStatus if available
- Any parent process chain leading to the loading process
- Recent DeviceProcessEvents and DeviceNetworkEvents for the same host around the alert time

**Pivot points:**
- DeviceImageLoadEvents for the same DeviceName and DLLSHA256 to find other hosts loading the same DLL
- DeviceProcessEvents for the LoadingProcessId and parent process chain
- DeviceNetworkEvents for the same DeviceId to look for outbound connections after the DLL load
- DeviceFileEvents for recent creation or modification of the DLL or adjacent files in the same directory

**Benign explanations:**
- Legitimate software installers or updaters that stage unsigned DLLs in AppData or ProgramData during installation.
- Developer workstations loading locally built DLLs from user-writable directories.
- Portable applications that extract unsigned components into Temp or Downloads at runtime.

**Escalation criteria:**
- The DLL is unsigned, newly dropped, and loaded by an unexpected or suspicious process with no business justification.
- The same host shows follow-on outbound connections, additional payload drops, or other intrusion behavior after the DLL load.
- The DLL hash or loading process is seen on multiple hosts outside of approved software deployment activity.
- The process chain includes suspicious parents such as script hosts, rundll32, regsvr32, or mshta.

**Containment actions:**
- If the DLL load appears malicious, isolate the host in Defender XDR to stop further execution and lateral movement.
- Block or quarantine the suspicious DLL and any associated dropped files if Defender identifies them as malicious.
- Disable or reset the user account if the activity aligns with active compromise and the account is not a known installer/service account.

**Closure criteria:**
- The DLL is confirmed to belong to a sanctioned installer, updater, or portable application and the path is expected.
- No suspicious follow-on process or network activity is found on the host within the surrounding time window.
- The DLL hash is validated as benign by software inventory, vendor documentation, or internal allowlisting.
- A documented exception or allowlist entry exists for the loading process and DLL path.

<br/>
---
<br/>

## Detection 2: TerminalFix - Reverse Tunnel Outbound Connection from Unexpected Process

### Detection Opportunity

Non-browser process establishing persistent outbound network connections consistent with reverse tunnel deployment following multistage intrusion

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign deploys a reverse tunnel as a core capability. Reverse tunnels produce persistent outbound connections from unexpected non-browser processes, often on common tunnel ports, providing a behavioral network signal detectable without specific IOCs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090, T1090.001
- Products: Microsoft Defender XDR, Microsoft 365
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Defender XDR, Microsoft 365, Windows, T1090, T1090.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let tunnelPorts = dynamic([22, 80, 443, 4443, 8080, 8443, 2222, 1080]);
let excludedProcesses = dynamic(['chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe', 'svchost.exe', 'lsass.exe', 'services.exe', 'MsMpEng.exe', 'onedrive.exe', 'teams.exe', 'ms-teams.exe']);
let suspiciousParents = dynamic(['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe']);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == 'ConnectionSuccess'
| where RemotePort in (tunnelPorts)
| where InitiatingProcessFileName !in~ (excludedProcesses)
| where RemoteIP !startswith '10.'
    and RemoteIP !startswith '192.168.'
    and RemoteIP !startswith '172.16.'
    and RemoteIP !startswith '172.17.'
    and RemoteIP !startswith '172.18.'
    and RemoteIP !startswith '172.19.'
    and RemoteIP !startswith '172.20.'
    and RemoteIP !startswith '172.21.'
    and RemoteIP !startswith '172.22.'
    and RemoteIP !startswith '172.23.'
    and RemoteIP !startswith '172.24.'
    and RemoteIP !startswith '172.25.'
    and RemoteIP !startswith '172.26.'
    and RemoteIP !startswith '172.27.'
    and RemoteIP !startswith '172.28.'
    and RemoteIP !startswith '172.29.'
    and RemoteIP !startswith '172.30.'
    and RemoteIP !startswith '172.31.'
    and RemoteIP !startswith '127.'
    and RemoteIP !startswith '169.254.'
| where InitiatingProcessParentFileName in~ (suspiciousParents)
| summarize
    ConnectionCount = count(),
    RemoteIPs = make_set(RemoteIP),
    Ports = make_set(RemotePort),
    WindowStart = min(Timestamp)
    by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, bin(Timestamp, 1h)
| where ConnectionCount >= 10
| project
    WindowStart,
    DeviceName,
    TunnelProcess = InitiatingProcessFileName,
    TunnelCommandLine = InitiatingProcessCommandLine,
    ParentProcess = InitiatingProcessParentFileName,
    ConnectionCount,
    RemoteIPs,
    Ports
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote management tools such as SSH clients, VPN clients, or monitoring agents making frequent outbound connections on tunnel-associated ports.
- Software update services making repeated connections to CDN endpoints on port 443 or 80.
- Development tools or CI/CD agents connecting to build infrastructure on non-standard ports.

**Tuning notes:**
- Add any additional internal IP prefixes specific to the environment to the RemoteIP exclusion block.
- Adjust ConnectionCount threshold based on observed baseline after running in hunting mode for 7 days.
- Expand excludedProcesses with any approved remote management tools identified during baselining.

**Risks / caveats:**
- DeviceNetworkEvents ActionType value 'ConnectionSuccess' must be confirmed as a valid value in the target tenant; some environments may only see 'ConnectionAttempt' or 'InboundConnectionAccepted'.
- The 172.16/12 exclusion is approximated using individual /24 startswith checks; a small number of 172.16-172.31 addresses with unusual third octets may not be excluded.
- ConnectionCount threshold of 10 per hour requires baselining against environment-specific outbound connection rates for non-browser processes before scheduling.
- Legitimate SSH or VPN clients spawned from shell scripts will match the suspiciousParents filter and require allowlisting.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, its parent, and the full command line to determine whether the connection came from a browser, admin tool, or suspicious launcher.
- Review the remote IPs and ports to see whether the traffic is to known internal services, approved VPN endpoints, or unusual external infrastructure.
- Check connection frequency and duration to confirm whether the process is making persistent, repeated connections consistent with tunneling.
- Look for recent process creation, script execution, or DLL sideloading on the same host that could explain the network behavior.

**Evidence to collect:**
- DeviceName, TunnelProcess, TunnelCommandLine, ParentProcess, and ConnectionCount
- RemoteIPs, Ports, and the first/last timestamps in the alert window
- Any related DeviceProcessEvents for the initiating process and its parent
- Any DeviceNetworkEvents showing repeated success to the same destination or port

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and InitiatingProcessId to map all remote destinations
- DeviceProcessEvents for the initiating process and parent process chain
- DeviceImageLoadEvents for the same host if the process appears to have been sideloaded or tampered with
- DeviceFileEvents for recent drops in user-writable paths tied to the same process tree

**Benign explanations:**
- Approved SSH, VPN, remote support, or monitoring tools that make frequent outbound connections.
- Software update agents or CI/CD tooling connecting repeatedly to external services.
- Administrative scripts that launch tunnel-capable tools from shell processes during maintenance.

**Escalation criteria:**
- The process is not an approved remote management tool and the command line indicates tunneling, proxying, or port forwarding.
- The host shows repeated outbound connections to unusual external IPs or ports with no business justification.
- The process parent is a script host, command shell, or other suspicious launcher and the activity is new for the host.
- The alert coincides with other intrusion indicators such as unsigned DLL loads or suspicious file drops.

**Containment actions:**
- Isolate the host if the process is confirmed or strongly suspected to be a reverse tunnel or proxy used for C2.
- Terminate the suspicious process and block the remote IPs if they are clearly malicious and not business-critical.
- Disable the associated account if the activity is tied to unauthorized access or post-compromise tunneling.

**Closure criteria:**
- The process is identified as an approved remote management, VPN, or monitoring tool with a documented purpose.
- The remote endpoints are confirmed as sanctioned infrastructure and the connection pattern matches baseline behavior.
- No additional suspicious process, file, or authentication activity is found on the host.
- An allowlist or exception is created for the approved process and destination pattern.

<br/>
---
<br/>

## Detection 3: ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound

### Detection Opportunity

Malicious installer spawning unsigned child processes dropping payloads into temp or AppData directories followed by outbound C2 network connections consistent with ValleyRAT delivery

### Intelligence Context

- Securelist: ValleyRAT masquerading as adware — [https://securelist.com/valleyrat-backdoor-adware/121175/](https://securelist.com/valleyrat-backdoor-adware/121175/)
  - Context: ValleyRAT is distributed disguised as adware via a malicious installer. The infection chain progresses from installer execution to payload drop and C2 beaconing. Combining installer-spawned child process drops into user-writable paths with subsequent outbound connections provides a compound behavioral signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1204.002, T1036, T1071, T1071.001
- Products: Not specified
- Platforms: Windows
- Malware: ValleyRAT
- Tools: Not specified
- Search tags: ValleyRAT, Windows, T1204, T1204.002, T1036, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Defense Evasion: T1036 Masquerading (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let writablePaths = dynamic(['\\temp\\', '\\appdata\\local\\temp\\', '\\appdata\\roaming\\', '\\users\\public\\']);
let installerPatterns = dynamic(['setup', 'install', 'update', 'patch', 'deploy']);
let suspiciousDrops =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType in ('FileCreated', 'FileModified')
    | where FolderPath has_any (writablePaths)
    | where FileName endswith '.exe' or FileName endswith '.dll'
    | where InitiatingProcessFileName has_any (installerPatterns)
    | project
        DropTime = Timestamp,
        DeviceId,
        DeviceName,
        DroppedFile = FileName,
        DropPath = FolderPath,
        InstallerProcess = InitiatingProcessFileName,
        InstallerProcessId = InitiatingProcessId,
        DropSHA256 = SHA256;
let childExec =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FolderPath has_any (writablePaths)
    | where InitiatingProcessFileName has_any (installerPatterns)
    | project
        ExecTime = Timestamp,
        DeviceId,
        ChildProcess = FileName,
        ChildCommandLine = ProcessCommandLine,
        ParentInstaller = InitiatingProcessFileName,
        ParentInstallerProcessId = InitiatingProcessId,
        ChildProcessId = ProcessId;
let c2Connections =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType == 'ConnectionSuccess'
    | where RemoteIP !startswith '10.'
        and RemoteIP !startswith '192.168.'
        and RemoteIP !startswith '172.16.'
        and RemoteIP !startswith '172.17.'
        and RemoteIP !startswith '172.18.'
        and RemoteIP !startswith '172.19.'
        and RemoteIP !startswith '172.20.'
        and RemoteIP !startswith '172.21.'
        and RemoteIP !startswith '172.22.'
        and RemoteIP !startswith '172.23.'
        and RemoteIP !startswith '172.24.'
        and RemoteIP !startswith '172.25.'
        and RemoteIP !startswith '172.26.'
        and RemoteIP !startswith '172.27.'
        and RemoteIP !startswith '172.28.'
        and RemoteIP !startswith '172.29.'
        and RemoteIP !startswith '172.30.'
        and RemoteIP !startswith '172.31.'
        and RemoteIP !startswith '127.'
        and RemoteIP !startswith '169.254.'
    | project
        NetTime = Timestamp,
        DeviceId,
        NetProcessId = InitiatingProcessId,
        ConnProcess = InitiatingProcessFileName,
        RemoteIP,
        RemotePort;
suspiciousDrops
| join kind=inner childExec on DeviceId, $left.InstallerProcessId == $right.ParentInstallerProcessId
| where abs(datetime_diff('minute', DropTime, ExecTime)) < 10
| join kind=inner c2Connections on DeviceId, $left.ChildProcessId == $right.NetProcessId
| where abs(datetime_diff('minute', ExecTime, NetTime)) < 30
| project
    DeviceName,
    InstallerProcess,
    DroppedFile,
    DropPath,
    DropSHA256,
    ChildProcess,
    ChildCommandLine,
    RemoteIP,
    RemotePort,
    DropTime,
    ExecTime,
    NetTime
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that drop executables into AppData or Temp as part of normal installation workflows.
- Auto-update mechanisms for browsers, productivity tools, or security software that match installer name patterns.
- Software packaging tools used by IT departments that spawn child processes into writable directories.

**Tuning notes:**
- Extend installerPatterns with additional naming conventions observed for adware or third-party installer tooling in the environment.
- Reduce ExecTime and NetTime windows if the environment has low baseline installer activity to tighten the correlation.
- Add known legitimate installer process names to an exclusion list after reviewing initial results.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileCreated' and 'FileModified' must be confirmed as valid in the target tenant; some Defender for Endpoint configurations may use different ActionType strings.
- DeviceNetworkEvents ActionType value 'ConnectionSuccess' must be confirmed as valid in the target tenant.
- Generic installer name patterns will still match legitimate software deployment tools; allowlisting by InstallerProcess name is required after baselining.
- The process-ID join assumes the dropped file is executed by the same installer process that dropped it; indirect execution chains will not be captured.

### Triage Runbook

**First 15 minutes:**
- Validate the installer name, parent process, and command line to determine whether it is a known software deployment tool or a suspicious masquerade.
- Inspect the dropped file names, paths, and hashes to see whether executables or DLLs were written into Temp, AppData, or Public.
- Confirm the child process execution chain and whether the child process initiated outbound network connections shortly after execution.
- Check whether the remote IPs are external and whether the connection pattern is consistent with beaconing or staged payload retrieval.

**Evidence to collect:**
- DeviceName, InstallerProcess, InstallerProcessId, DropTime, DroppedFile, DropPath, and DropSHA256
- ChildProcess, ChildCommandLine, ChildProcessId, ExecTime, RemoteIP, RemotePort, and NetTime
- Any related DeviceFileEvents showing additional files dropped by the same installer
- Any related DeviceNetworkEvents showing repeated outbound connections from the child process

**Pivot points:**
- DeviceFileEvents for the same InstallerProcessId to identify all dropped files and paths
- DeviceProcessEvents for the child process and any descendants
- DeviceNetworkEvents for the child process ID to map all external communications
- DeviceImageLoadEvents for the child process if DLL sideloading or module loading is suspected

**Benign explanations:**
- Legitimate software installers that unpack executables or DLLs into user-writable directories during setup.
- Auto-update mechanisms for browsers, productivity tools, or security software.
- IT packaging or deployment tools that spawn child processes as part of normal installation workflows.

**Escalation criteria:**
- The installer is unsigned, unfamiliar, or masquerading as adware or another benign product.
- Dropped files are executable or script payloads in writable paths and the child process makes external connections soon after.
- The same host shows multiple suspicious stages such as file drop, execution, and outbound beaconing.
- The activity is observed on more than one host or the hash matches known malicious samples.

**Containment actions:**
- Isolate the host if the installer chain is confirmed or strongly suspected to be malicious.
- Quarantine the dropped files and terminate the child process and any descendants.
- Block the remote IPs or domains if they are clearly malicious and not shared business infrastructure.
- Reset the user account if the execution appears to have been triggered through user interaction or phishing.

**Closure criteria:**
- The installer is verified as a sanctioned deployment package or vendor updater.
- Dropped files and outbound connections are consistent with documented installation behavior.
- No suspicious descendants, persistence, or additional C2 activity are present.
- The installer or file path is added to an approved exception after validation.

<br/>
---
<br/>

## Detection 4: Spring Ring - Teams Client Spawning Unexpected Child Process Post-Vishing

### Detection Opportunity

Microsoft Teams client process spawning unexpected child processes or dropping unsigned executables into user-writable directories following social engineering via voice phishing

### Intelligence Context

- Unit 42: Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams — [https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/)
  - Context: The Spring Ring campaign abuses Microsoft Teams voice phishing to socially engineer victims into executing malware. Post-social-engineering malware deployment via Teams will manifest as the Teams client process spawning unexpected child processes or dropping unsigned executables, a high-fidelity behavioral signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078, T1016, T1087, T1087.002
- Products: Microsoft Teams
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Teams, Windows, Active Directory, T1078, T1016, T1087, T1087.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1078 Valid Accounts (low); Discovery: T1016 System Network Configuration Discovery (high); Discovery: T1087 Account Discovery/ T1087.002 Domain Account (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let teamsProcesses = dynamic(['teams.exe', 'ms-teams.exe']);
let allowedChildren = dynamic(['teams.exe', 'ms-teams.exe', 'msedgewebview2.exe', 'crashpad_handler.exe', 'squirrel.exe']);
let writablePaths = dynamic(['\\temp\\', '\\appdata\\', '\\downloads\\', '\\users\\public\\']);
let suspiciousChildProcs =
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where InitiatingProcessFileName in~ (teamsProcesses)
    | where FileName !in~ (allowedChildren)
    | project
        EventTime = Timestamp,
        DeviceId,
        DeviceName,
        AccountName,
        DetectionType = 'UnexpectedChildProcess',
        File = FileName,
        Detail = ProcessCommandLine;
let suspiciousFileDrops =
    DeviceFileEvents
    | where Timestamp > ago(1d)
    | where InitiatingProcessFileName in~ (teamsProcesses)
    | where FolderPath has_any (writablePaths)
    | where FileName endswith '.exe'
        or FileName endswith '.dll'
        or FileName endswith '.ps1'
        or FileName endswith '.bat'
    | project
        EventTime = Timestamp,
        DeviceId,
        DeviceName,
        AccountName = '',
        DetectionType = 'ExecutableDropFromTeams',
        File = FileName,
        Detail = strcat(FolderPath, FileName);
union suspiciousChildProcs, suspiciousFileDrops
| summarize
    DetectionTypes = make_set(DetectionType),
    Files = make_set(File),
    Details = make_set(Detail),
    Accounts = make_set(AccountName)
    by DeviceId, DeviceName, bin(EventTime, 1h)
| project
    EventTime,
    DeviceName,
    DeviceId,
    DetectionTypes,
    Files,
    Details,
    Accounts
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Teams integrations or plugins that legitimately spawn helper processes not included in the allowedChildren list.
- Teams-based file sharing workflows where users receive and open script files through Teams chat.
- Custom Teams deployment wrappers that use non-standard executable names.

**Tuning notes:**
- Expand allowedChildren with any additional legitimate Teams helper processes observed in the environment after initial deployment.
- Narrow the file extension filter in suspiciousFileDrops if Teams-based sharing of .ps1 or .bat files is common and legitimate in the environment.
- Consider adding an AccountName exclusion for service accounts used by Teams automation workflows.

**Risks / caveats:**
- AccountName is available in DeviceProcessEvents but not in DeviceFileEvents; the union projection must handle this field asymmetry explicitly to avoid null propagation errors.
- The allowedChildren list reflects common Teams helper processes as of the time of writing; Teams updates may introduce new legitimate child process names that require addition to the list.
- Teams-based file sharing of legitimate scripts will generate false positives that require allowlisting by file name or path.
- The 1-day lookback requires the scheduled rule to run at least daily to avoid coverage gaps.

### Triage Runbook

**First 15 minutes:**
- Identify the Teams process, child process name, and command line to determine whether the child is a known Teams helper or an unexpected executable/script.
- Review any file drops from Teams into user-writable directories and confirm whether the files are executable, script-based, or otherwise suspicious.
- Check the associated account and recent Teams activity to see whether the user was engaged in a voice phishing or social engineering event.
- Look for follow-on process execution or network activity from the child process on the same host.

**Evidence to collect:**
- DeviceName, AccountName, DetectionTypes, Files, Details, and EventTime
- Child process names and command lines from DeviceProcessEvents
- Dropped file names, paths, and hashes from DeviceFileEvents
- Any recent Teams-related sign-in, chat, or call context available to the SOC

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and AccountName to enumerate all Teams child processes
- DeviceFileEvents for the same DeviceId to inspect file drops from Teams
- DeviceNetworkEvents for the child process if it executed and connected externally
- Microsoft Teams audit or sign-in data if available in the tenant for user context

**Benign explanations:**
- Legitimate Teams helper processes such as WebView2, crash handlers, or update components.
- Users receiving and opening legitimate scripts or files through Teams chat.
- Custom Teams deployment wrappers or enterprise integrations that spawn non-standard helper processes.

**Escalation criteria:**
- Teams spawns an unexpected executable or script that is not in the approved helper list.
- Teams drops a new executable, DLL, or script into Temp, AppData, Downloads, or Public.
- The user reports a suspicious call, file transfer, or prompt in Teams that preceded the alert.
- The child process performs additional suspicious actions such as persistence, credential access, or outbound C2.

**Containment actions:**
- If the child process is confirmed malicious, isolate the host and terminate the process tree.
- Quarantine any dropped executable or script files associated with the alert.
- Disable or reset the user account if the event is tied to successful social engineering and unauthorized execution.

**Closure criteria:**
- The child process is a known Teams component or approved enterprise integration.
- The file drop is a legitimate document or script handled by an approved workflow and no execution occurred.
- No suspicious network, persistence, or privilege activity follows the Teams event.
- The process name or file path is added to an allowlist after validation.

<br/>
---
<br/>

## Detection 5: Spring Ring - Unusual Interactive Logon to Domain Controller Followed by Reconnaissance Commands

### Detection Opportunity

Unusual interactive or remote logon to a domain controller followed by execution of reconnaissance commands consistent with post-vishing lateral movement targeting enterprise domain controllers

### Intelligence Context

- Unit 42: Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams — [https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/)
  - Context: The Spring Ring campaign explicitly targets enterprise domain controllers as a post-exploitation objective following Teams-based voice phishing. Unusual logons to domain controllers combined with reconnaissance command execution represent a high-fidelity compound signal for this campaign's lateral movement phase.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078, T1016, T1087, T1087.002
- Products: Microsoft Teams
- Platforms: Windows, Active Directory
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Teams, Windows, Active Directory, T1078, T1016, T1087, T1087.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1078 Valid Accounts (low); Discovery: T1016 System Network Configuration Discovery (high); Discovery: T1087 Account Discovery/ T1087.002 Domain Account (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceLogonEvents, DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceLogonEvents, DeviceProcessEvents

### KQL

```kql
let reconTools = dynamic(['net.exe', 'net1.exe', 'nltest.exe', 'whoami.exe', 'dsquery.exe', 'ipconfig.exe', 'arp.exe', 'nslookup.exe', 'ping.exe', 'quser.exe']);
let dcNamePatterns = dynamic(['dc', 'domaincontroller', 'addc', 'pdc', 'bdc']);
let dcLogons =
    DeviceLogonEvents
    | where Timestamp > ago(1d)
    | where LogonType in ('Interactive', 'RemoteInteractive', 'Network')
    | where DeviceName has_any (dcNamePatterns)
    | where AccountName !endswith '$'
    | project
        LogonTime = Timestamp,
        DeviceId,
        DeviceName,
        AccountName,
        LogonType,
        RemoteIP;
let dcRecon =
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where DeviceName has_any (dcNamePatterns)
    | where FileName in~ (reconTools)
    | project
        ReconTime = Timestamp,
        DeviceId,
        DeviceName,
        AccountName,
        ReconProcess = FileName,
        ReconCommandLine = ProcessCommandLine;
dcLogons
| join kind=inner dcRecon on DeviceId, AccountName
| where ReconTime > LogonTime
    and datetime_diff('minute', ReconTime, LogonTime) <= 30
| summarize
    ReconCommands = make_set(ReconCommandLine),
    Processes = make_set(ReconProcess)
    by DeviceName, AccountName, LogonType, RemoteIP, LogonTime
| project
    LogonTime,
    DeviceName,
    AccountName,
    LogonType,
    RemoteIP,
    ReconCommands,
    Processes
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate domain administrators who routinely log on interactively to DCs and run network diagnostic tools as part of standard operations.
- Monitoring or backup agents that log on to DCs and execute enumeration-style commands.
- Automated scripts that run net.exe or ipconfig.exe on DCs as part of scheduled maintenance.

**Tuning notes:**
- Replace dcNamePatterns with the exact device name substrings or full names used for domain controllers in the environment, or replace the has_any filter with a watchlist lookup if a DC inventory watchlist exists.
- Add known administrative account names to an AccountName exclusion filter after reviewing initial results.
- Consider extending reconTools with any additional enumeration utilities observed in the environment.

**Risks / caveats:**
- DeviceLogonEvents LogonType field uses string values ('Interactive', 'RemoteInteractive', 'Network'); these must be confirmed as valid string representations in the target tenant as some schemas use numeric logon type codes.
- Domain controller devices must be enrolled in Microsoft Defender for Endpoint and actively sending DeviceLogonEvents and DeviceProcessEvents telemetry; DCs not onboarded to MDE will produce no results.
- The dcNamePatterns list is a placeholder approximation; the actual DC naming convention must be supplied before this query produces reliable results.
- The dcNamePatterns list must be replaced with the actual DC naming convention used in the environment before this query produces reliable results; the current values are approximations only.

### Triage Runbook

**First 15 minutes:**
- Verify whether the account is an approved domain admin or service account and whether the logon type and source IP are expected for that user.
- Review the recon command line and process names to confirm whether the activity is standard troubleshooting or enumeration behavior.
- Check whether the logon occurred on a known domain controller and whether the device name matches the environment's DC inventory.
- Look for additional activity from the same account on other hosts, especially privilege changes, lateral movement, or repeated recon commands.

**Evidence to collect:**
- DeviceName, AccountName, LogonType, RemoteIP, and LogonTime
- ReconCommands, Processes, and ReconTime
- Any AccountDomain or related identity context available in Defender XDR
- Any subsequent DeviceProcessEvents or DeviceNetworkEvents from the same account or host

**Pivot points:**
- DeviceLogonEvents for the same AccountName to identify other logons and source IPs
- DeviceProcessEvents on the domain controller for additional enumeration or admin tools
- DeviceNetworkEvents for the same host to identify remote connections after logon
- Identity or directory audit data to check for privilege changes, group membership changes, or account anomalies

**Benign explanations:**
- Legitimate domain administrators performing interactive maintenance on a domain controller.
- Monitoring, backup, or management agents that log on and run diagnostic commands.
- Scheduled maintenance scripts that execute recon-style tools such as ipconfig or nltest.

**Escalation criteria:**
- The account is not authorized for interactive DC access or the source IP is unfamiliar.
- Recon commands are executed by a non-admin account or immediately after a suspicious logon.
- The activity is followed by privilege escalation, lateral movement, or additional suspicious process execution.
- The domain controller naming or inventory check confirms the device is a real DC and the behavior is outside normal admin practice.

**Containment actions:**
- Disable or reset the account if the logon is unauthorized or clearly compromised.
- Isolate the domain controller only if there is evidence of active malicious execution or broader compromise and containment will not disrupt critical services without approval.
- Block the source IP or session if it is clearly malicious and the environment supports safe network containment.

**Closure criteria:**
- The account is confirmed as an authorized administrator and the activity matches an approved maintenance window.
- The recon commands are consistent with documented troubleshooting or inventory tasks.
- No additional suspicious logons, process activity, or privilege changes are found.
- The device is confirmed to be a domain controller and the event is documented as benign administrative activity.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- TerminalFix - DLL Sideloading via Unsigned DLL in User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.
- TerminalFix - Reverse Tunnel Outbound Connection from Unexpected Process: Do not schedule yet; validate as an analyst-led hunt first.
- ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Telemetry availability:**
- Spring Ring - Unusual Interactive Logon to Domain Controller Followed by Reconnaissance Commands: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceLogonEvents, DeviceProcessEvents before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by TerminalFix - DLL Sideloading via Unsigned DLL in User-Writable Path; TerminalFix - Reverse Tunnel Outbound Connection from Unexpected Process; ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound; Spring Ring - Teams Client Spawning Unexpected Child Process Post-Vishing; Spring Ring - Unusual Interactive Logon to Domain Controller Followed by Reconnaissance Commands
- DeviceNetworkEvents: shared by TerminalFix - Reverse Tunnel Outbound Connection from Unexpected Process; ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound
- DeviceFileEvents: shared by ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound; Spring Ring - Teams Client Spawning Unexpected Child Process Post-Vishing

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Spring Ring - Teams Client Spawning Unexpected Child Process Post-Vishing.
2. Resolve environment-mapping detections next: Spring Ring - Unusual Interactive Logon to Domain Controller Followed by Reconnaissance Commands.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: TerminalFix - DLL Sideloading via Unsigned DLL in User-Writable Path; TerminalFix - Reverse Tunnel Outbound Connection from Unexpected Process; ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound.

### Hunting Agenda and Promotion Criteria

- TerminalFix - DLL Sideloading via Unsigned DLL in User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- TerminalFix - Reverse Tunnel Outbound Connection from Unexpected Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- ValleyRAT - Installer Spawning Unsigned Child Process into User-Writable Directory with C2 Outbound: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Spring Ring - Unusual Interactive Logon to Domain Controller Followed by Reconnaissance Commands: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceLogonEvents, DeviceProcessEvents before scheduling..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
