---
layout: post
title: "Detection Engineering Brief - Saturday, October 24, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-24
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - LiteLLM
  - Python
  - T1059
  - CVE-2026-93680
  - CVE-2026-0768
  - CVE-2026-0769
  - CVE-2026-10134
  - CVE-2026-7873
  - CVE-2026-93674
  - T1190
  - Langflow
  - Metasploit
  - OpenCTI
  - MongoDB
  - Apache Solr
  - T1071
  - T1071.001
  - T1041
  - T1095
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 3 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: LiteLLM, Python, T1059, CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, T1190, Langflow, Metasploit, OpenCTI, MongoDB, Apache Solr, T1071, T1071.001, T1041, T1095.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Python Startup Hook File Write - Potential Supply Chain Persistence; Python Process Outbound Network Connection Following Package Import - Credential Exfiltration Pattern; Unauthenticated RCE Exploitation Against Langflow - Child Process Spawn from Web Application; Pre-Authentication RCE Exploitation Against OpenCTI - Anomalous Child Process from Web Application Host; Metasploit Post-Exploitation Staging Behavior - Reverse Shell or Meterpreter Stager from Application Host.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Python Startup Hook File Write - Potential Supply Chain Persistence

### Detection Opportunity

Compromised Python package writes sitecustomize.py or usercustomize.py to Python site-packages directories, establishing startup hook persistence executed at every interpreter launch.

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The LiteLLM 1.107.0 supply chain compromise used Python startup hooks (sitecustomize.py or usercustomize.py) to execute malicious code at every Python interpreter launch, enabling credential theft during normal package use.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1071, T1071.001, T1041
- Products: LiteLLM, Python
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1059, T1071, T1071.001, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Exfiltration: T1041 Exfiltration Over C2 Channel (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 7d;
let correlationWindow = 5min;
let hookWrites = DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("sitecustomize.py", "usercustomize.py")
| where FolderPath has_any ("site-packages", "dist-packages")
| where ActionType in ("FileCreated", "FileModified")
| project
    HookTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    FolderPath,
    FileName,
    HookInitiatingProcess = InitiatingProcessFileName,
    HookCommandLine = InitiatingProcessCommandLine,
    HookParentProcess = InitiatingProcessParentFileName,
    HookProcessId = InitiatingProcessId;
let pythonNet = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has_any ("python", "python3", "python.exe")
| where RemoteIP !startswith "127."
    and RemoteIP !startswith "10."
    and not (RemoteIP startswith "192.168.")
    and not (RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.") 
| project
    NetTimestamp = Timestamp,
    DeviceId,
    RemoteIP,
    RemoteUrl,
    NetInitiatingProcess = InitiatingProcessFileName,
    NetCommandLine = InitiatingProcessCommandLine;
hookWrites
| join kind=inner pythonNet on DeviceId
| where (NetTimestamp - HookTimestamp) between (0min .. correlationWindow)
| where HookInitiatingProcess !in~ ("pip", "pip3", "conda", "poetry", "uv", "pip.exe")
| summarize
    arg_min(HookTimestamp, *),
    OutboundConnections = count(),
    RemoteIPs = make_set(RemoteIP, 20)
    by DeviceId, DeviceName, FolderPath, FileName, HookInitiatingProcess, HookCommandLine, HookParentProcess
| project
    HookTimestamp,
    DeviceName,
    FolderPath,
    FileName,
    HookInitiatingProcess,
    HookCommandLine,
    HookParentProcess,
    NetInitiatingProcess,
    NetCommandLine,
    RemoteIP,
    RemoteUrl,
    OutboundConnections,
    RemoteIPs
| sort by HookTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate pip or conda package installations that write sitecustomize.py as part of package setup, followed by routine Python network activity within the correlation window.
- Development environments where developers frequently install packages and run Python scripts with outbound connectivity in rapid succession.
- CI/CD pipeline hosts where package installation and test execution with network calls occur within minutes of each other.

**Tuning notes:**
- Start with the hookWrites subquery alone to confirm file event telemetry is populated before enabling the network join.
- Add FolderPath exclusions for known virtual environment base paths if venv-scoped writes are acceptable in the environment.
- Reduce correlationWindow to 2min in environments where Python startup-to-first-network-call latency is well understood and short.
- Consider promoting to scheduled_rule after baselining if the hookWrites signal alone (without network join) proves low-noise.

**Risks / caveats:**
- DeviceFileEvents file telemetry for Python site-packages directories requires Defender for Endpoint with file event collection enabled; environments without this may return no results for the hook file write signal.
- RemoteUrl is not consistently populated in DeviceNetworkEvents across all OS platforms and DfE sensor versions; RemoteIP is the more reliable correlation field.
- The device-level join without a process ID anchor means the correlating Python network connection may originate from a different Python process than the one that wrote the hook file; process-level correlation requires InitiatingProcessId matching which is only possible if the hook-writing process also makes the network call directly.
- The 5-minute correlation window may miss slow-starting Python environments or catch unrelated Python network activity in busy environments; baseline the window against environment-specific Python startup latency.

### Triage Runbook

**First 15 minutes:**
- Confirm the file write target is in a Python site-packages or dist-packages path and note the exact file name, timestamp, and initiating process.
- Check whether the writer was a known package manager or installer such as pip, pip3, conda, poetry, or uv, and whether the command line shows a normal install workflow.
- Review the parent process and surrounding process tree to see if the write came from a developer workstation, CI/CD host, or production server.
- Look for any outbound Python network activity within minutes of the write, especially to external IPs or unusual URLs.

**Evidence to collect:**
- File path, file name, action type, timestamp, initiating process name, command line, and parent process name for the hook file write.
- Any DeviceNetworkEvents from the same host around the same time, including remote IP, remote URL, remote port, and initiating process command line.
- The package or repository context if visible in the command line, such as install, upgrade, wheel build, or editable install activity.
- Host role and user context: developer workstation, build agent, container host, or production application server.

**Pivot points:**
- DeviceFileEvents for additional writes to sitecustomize.py, usercustomize.py, or other files in site-packages/dist-packages on the same host.
- DeviceNetworkEvents for Python processes on the same host in the 5-minute window before and after the file write.
- DeviceProcessEvents for the initiating process and its parent to identify package installation or script execution chains.
- If available, pivot on DeviceId and InitiatingProcessId to separate the hook writer from unrelated Python activity.

**Benign explanations:**
- A legitimate pip, conda, poetry, or uv installation that writes startup hook files as part of package setup.
- Developer or CI/CD activity where package installation and routine Python network access happen close together.
- A sanctioned internal package or plugin that uses startup hooks for environment initialization.

**Escalation criteria:**
- The hook file was written by a non-package-manager process or by an unexpected parent process.
- The command line or process ancestry suggests post-install tampering, script execution, or a non-interactive service account.
- The host shows suspicious outbound Python connections to external IPs or unknown URLs shortly after the write.
- The file contents or subsequent activity indicate credential theft, environment variable access, or persistence beyond normal package behavior.

**Containment actions:**
- If the write is not clearly benign, isolate the host to stop further Python execution and potential credential theft.
- Preserve the suspicious file and related package artifacts before remediation.
- Disable or rotate credentials used on the host if there is evidence of token or environment-variable theft.
- Block the suspicious package source or internal package version if the compromise appears supply-chain related.

**Closure criteria:**
- The write is confirmed to be from a trusted package manager during an approved installation or update.
- No suspicious outbound Python network activity is found in the correlation window.
- The file contents match expected package behavior and no additional persistence or credential-theft indicators are present.
- The host role and user activity align with normal development or CI/CD package installation patterns.

<br/>
---
<br/>

## Detection 2: Python Process Outbound Network Connection Following Package Import - Credential Exfiltration Pattern

### Detection Opportunity

Python interpreter makes outbound network connections shortly after package execution, consistent with credential theft via environment variable access and exfiltration observed in the LiteLLM supply chain compromise.

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The LiteLLM compromise performed credential theft during package execution, likely by reading environment variables and exfiltrating them via outbound HTTP connections initiated by the Python interpreter as part of startup hook execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1071, T1071.001, T1041
- Products: LiteLLM, Python
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1059, T1071, T1071.001, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Exfiltration: T1041 Exfiltration Over C2 Channel (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 7d;
let correlationWindow = 3min;
let pythonProcs = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName has_any ("python", "python3", "python.exe")
| where ProcessCommandLine has "litellm"
    or ProcessCommandLine has_any ("sitecustomize", "usercustomize")
    or ProcessCommandLine has_any ("exec(", "eval(", "__import__(", "urllib.request", "urllib.urlopen")
| project
    ProcTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    ProcProcessId = ProcessId;
let outboundNet = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has_any ("python", "python3", "python.exe")
| where RemoteIP !startswith "127."
    and RemoteIP !startswith "10."
    and not (RemoteIP startswith "192.168.")
    and not (RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.")
| project
    NetTimestamp = Timestamp,
    DeviceId,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    NetInitiatingProcessId = InitiatingProcessId;
pythonProcs
| join kind=inner outboundNet on DeviceId
| where (NetTimestamp - ProcTimestamp) between (0min .. correlationWindow)
| summarize
    arg_min(ProcTimestamp, *),
    UniqueRemoteIPs = dcount(RemoteIP),
    RemoteIPList = make_set(RemoteIP, 10),
    RemotePortList = make_set(RemotePort, 10)
    by DeviceId, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| project
    ProcTimestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    UniqueRemoteIPs,
    RemoteIPList,
    RemotePortList
| sort by ProcTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Python scripts that legitimately use urllib or requests for API calls in development or data science environments.
- Automated testing frameworks that invoke Python with eval or exec patterns as part of test harnesses.
- Python-based monitoring agents that make outbound connections shortly after startup.
- Any Python process invoking __import__ dynamically as part of plugin or extension loading.

**Tuning notes:**
- Run the pythonProcs subquery alone first to assess volume and ProcessCommandLine population quality in the environment.
- Consider splitting into two separate queries: one LiteLLM-specific (high confidence) and one generic suspicious-pattern (lower confidence, higher noise).
- Add AccountName exclusions for known service accounts running Python workloads with legitimate outbound connectivity.
- Adjust correlationWindow based on observed Python startup-to-first-network-call latency measured in the environment.

**Risks / caveats:**
- ProcessCommandLine for Python processes may be truncated or partially populated on Linux hosts depending on DfE sensor version and process argument length; detections relying on command-line substring matching may miss invocations with long argument lists.
- DeviceProcessEvents may not capture all Python subprocess invocations if the process is forked rather than exec'd, depending on OS and sensor configuration.
- The assumption that LiteLLM appears in the Python command line may not hold when LiteLLM is imported as a library within a larger application; in that case the command line may only show the application entry point.
- The 3-minute correlation window is arbitrary; environments with slow Python startup or deferred network calls may miss the exfiltration event.

### Triage Runbook

**First 15 minutes:**
- Identify the exact Python command line, account, and host role associated with the process that made the outbound connection.
- Check whether the process command line references LiteLLM, sitecustomize, usercustomize, exec, eval, urllib, or dynamic imports.
- Review the remote IP, URL, and port to determine whether the destination is external, unusual, or associated with a known service.
- Correlate the process start time with any recent package installation, import, or startup-hook file write on the same host.

**Evidence to collect:**
- Process command line, file name, account name, timestamp, and process ID for the Python process.
- Remote IP, remote URL, remote port, and network timestamp for each outbound connection.
- Any preceding DeviceFileEvents showing startup-hook creation or modification on the same host.
- Host classification and user context, including whether the system is a developer workstation, build agent, or production server.

**Pivot points:**
- DeviceProcessEvents for Python processes on the host before and after the alert time.
- DeviceNetworkEvents for all outbound connections from Python on the same host, including repeated destinations.
- DeviceFileEvents for sitecustomize.py and usercustomize.py writes on the same host.
- If available, pivot on AccountName to see whether the same user has other suspicious Python executions across hosts.

**Benign explanations:**
- A legitimate Python application or script making normal API calls after startup.
- Automated tests or CI/CD jobs that use urllib, requests, exec, eval, or dynamic imports as part of framework behavior.
- A monitoring agent or internal tool that legitimately contacts external services from Python.

**Escalation criteria:**
- The destination is an unknown external IP, suspicious domain, or non-business URL and the process is not an approved application.
- The Python command line or ancestry suggests package compromise, startup-hook execution, or credential harvesting.
- There is evidence of environment-variable access, token access, or repeated outbound connections consistent with exfiltration.
- The same host also shows suspicious hook file writes or other persistence indicators.

**Containment actions:**
- If the activity is not clearly benign, isolate the host to prevent further exfiltration.
- Revoke or rotate credentials, API keys, and tokens used on the host.
- Preserve process, file, and network evidence before cleanup.
- Block the suspicious destination if it is confirmed malicious.

**Closure criteria:**
- The Python process is tied to an approved application, test harness, or service account with expected outbound behavior.
- No suspicious hook file writes or other persistence indicators are found on the host.
- The remote destination is known and business-justified, and the timing matches normal application behavior.
- No evidence of credential theft, token access, or unusual data transfer is present.

<br/>
---
<br/>

## Detection 3: Unauthenticated RCE Exploitation Against Langflow - Child Process Spawn from Web Application

### Detection Opportunity

Langflow web application host spawns unexpected child processes following inbound HTTP requests, consistent with unauthenticated remote code execution via public Metasploit modules targeting CVE-2026-93680 and related CVEs.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Langflow, MongoDB, and More — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more)
  - Context: Rapid7 published six Metasploit modules targeting Langflow, covering three unauthenticated RCE paths and two authenticated code execution flaws. Public exploit availability significantly lowers the bar for exploitation and makes process-spawn-based detection on Langflow hosts operationally valuable.

### Search Metadata

- CVEs: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095, T1059
- Products: Langflow
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, T1190, Langflow, Metasploit, T1095, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (low); Execution: T1059 Command and Scripting Interpreter (medium); Initial Access: T1190 Exploit Public-Facing Application (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 1d;
let correlationWindow = 2min;
let suspiciousChildProcs = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has_any ("langflow", "python", "python3", "uvicorn", "gunicorn")
| where FileName has_any ("sh", "bash", "zsh", "dash", "cmd.exe", "powershell.exe", "whoami", "id", "curl", "wget", "nc", "ncat", "nmap")
    or ProcessCommandLine has_any ("/bin/sh", "/bin/bash", "cmd /c", "powershell", "base64", "chmod +x", "curl ", "wget ")
| project
    SpawnTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine;
let inboundConns = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where RemoteIP !startswith "10."
    and not (RemoteIP startswith "192.168.")
    and not (RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.") 
    and RemoteIP !startswith "127."
| project
    ConnTimestamp = Timestamp,
    DeviceId,
    RemoteIP,
    RemotePort;
suspiciousChildProcs
| join kind=leftouter inboundConns on DeviceId
| where isnull(ConnTimestamp)
    or (SpawnTimestamp - ConnTimestamp) between (0min .. correlationWindow)
| summarize
    arg_min(SpawnTimestamp, *),
    InboundSourceIPs = make_set(RemoteIP, 10),
    InboundPorts = make_set(RemotePort, 10)
    by DeviceId, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, FileName, ProcessCommandLine
| project
    SpawnTimestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine,
    InboundSourceIPs,
    InboundPorts
| sort by SpawnTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Langflow legitimately spawning subprocess workers or health check processes during startup or under load.
- Administrative shell access to the Langflow host via SSH or remote management tools that appear as shell child processes of the application user.
- Automated deployment or configuration management tools running as the same user account as Langflow.

**Tuning notes:**
- Run the suspiciousChildProcs subquery alone first to confirm Langflow process names appear in InitiatingProcessFileName and to identify any legitimate subprocess spawns that need exclusion.
- Confirm ActionType 'InboundConnectionAccepted' is populated in DeviceNetworkEvents for the Langflow host before relying on the inbound IP correlation.
- Consider adding DeviceId or DeviceName filters scoped to known Langflow host identifiers to prevent the rule from matching Python/uvicorn processes on non-Langflow hosts.
- After baselining, convert from leftouter to inner join if inbound connection telemetry is confirmed reliable, to reduce analyst review burden.

**Risks / caveats:**
- The InitiatingProcessFileName value 'langflow' may not match the actual process name on monitored hosts if Langflow is invoked via a wrapper script, Docker entrypoint, or systemd unit that presents a different process name; the exact process name must be confirmed in DeviceProcessEvents before the rule will fire.
- DeviceNetworkEvents ActionType 'InboundConnectionAccepted' requires DfE network inspection to be enabled for inbound connections on the Langflow host; if not enabled, the inbound correlation branch will return no results and the leftouter join will still surface child process spawns without attacker IP context.
- The InitiatingProcessFileName filter must be validated against actual Langflow process names in DeviceProcessEvents before scheduling; if Langflow runs under a generic Python process name without 'langflow' in the filename, the filter will match all Python-parented shell spawns on the host, not just Langflow-specific ones.
- The leftouter join means child process spawns with no matching inbound connection will still appear in results; analysts must distinguish these from confirmed exploitation chains.

### Triage Runbook

**First 15 minutes:**
- Identify the spawned child process, its command line, parent process, and whether it is a shell, downloader, or reconnaissance utility.
- Check the inbound connection context for the source IP, port, and timing relative to the process spawn.
- Verify whether the host is actually running Langflow and whether the process name matches the expected deployment method.
- Look for immediate follow-on activity such as reverse shells, file downloads, or additional child processes.

**Evidence to collect:**
- Spawn timestamp, process name, command line, parent process name, and account name for the child process.
- Inbound connection timestamp, source IP, and remote port from DeviceNetworkEvents.
- Host deployment details: container, systemd service, wrapper script, or direct Python invocation.
- Any subsequent process or network activity from the same host after the spawn.

**Pivot points:**
- DeviceProcessEvents for the same host to identify the full process tree around the spawn time.
- DeviceNetworkEvents for inbound connections to the host in the minutes before the spawn.
- CommonSecurityLog or WAF logs if available to validate the source IP and request path.
- DeviceFileEvents for any new files, scripts, or dropped payloads created after the spawn.

**Benign explanations:**
- Legitimate Langflow worker, health check, or maintenance subprocesses.
- Administrative shell access or automation running under the same service account.
- Deployment or configuration management activity that spawns helper processes on the host.

**Escalation criteria:**
- The spawned process is a shell, downloader, or reconnaissance tool not expected for Langflow.
- The inbound source IP is external or otherwise suspicious and aligns with exploit timing.
- There is evidence of command execution, reverse connection setup, or payload staging.
- The host shows repeated suspicious spawns or additional exploitation indicators.

**Containment actions:**
- If exploitation is likely, isolate the host from the network.
- Preserve volatile evidence and process details before restarting or remediating.
- Block the source IP if it is confirmed malicious and operationally safe to do so.
- Patch or disable the exposed Langflow service until the environment is validated.

**Closure criteria:**
- The child process is confirmed to be a legitimate Langflow subprocess or approved administrative action.
- The inbound connection is from a trusted internal source or scanner and matches expected behavior.
- No additional suspicious child processes, downloads, or reverse connections are present.
- The host deployment and process ancestry explain the event without evidence of exploitation.

<br/>
---
<br/>

## Detection 4: Pre-Authentication RCE Exploitation Against OpenCTI - Anomalous Child Process from Web Application Host

### Detection Opportunity

OpenCTI application host spawns unexpected shell or interpreter child processes following unauthenticated inbound HTTP requests, consistent with the pre-auth RCE chain covered by Metasploit modules.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Langflow, MongoDB, and More — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more)
  - Context: Rapid7 documented a pre-authentication RCE chain against OpenCTI with a corresponding Metasploit module, making OpenCTI hosts an active exploitation target. Detection focuses on the post-exploitation artifact of unexpected child process creation from the OpenCTI application process.

### Search Metadata

- CVEs: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095, T1059
- Products: OpenCTI
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, T1190, OpenCTI, Metasploit, T1095, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (low); Execution: T1059 Command and Scripting Interpreter (medium); Initial Access: T1190 Exploit Public-Facing Application (low)

### Deployment Gates

- CommonSecurityLog must be populated by a WAF, reverse proxy, or network security device forwarding OpenCTI HTTP traffic to Sentinel; if no such connector is configured, the openctiWebHits subquery returns no results and the inner join produces no output.

**Required telemetry:**
- DeviceProcessEvents, CommonSecurityLog

### KQL

```kql
let lookback = 7d;
let correlationWindow = 3min;
let openctiSpawns = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has_any ("node", "python", "python3", "opencti")
| where FileName has_any ("sh", "bash", "zsh", "dash", "cmd.exe", "powershell.exe", "curl", "wget", "nc", "whoami", "id", "uname")
    or ProcessCommandLine has_any ("/bin/sh", "/bin/bash", "base64", "chmod ", "curl ", "wget ")
| project
    SpawnTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine;
let openctiWebHits = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestURL has_any ("/graphql", "/auth")
| project
    WebTimestamp = TimeGenerated,
    SourceIP,
    RequestURL,
    DeviceName;
openctiSpawns
| join kind=leftouter openctiWebHits on DeviceName
| where isnull(WebTimestamp)
    or (SpawnTimestamp - WebTimestamp) between (0min .. correlationWindow)
| summarize
    arg_min(SpawnTimestamp, *),
    WebRequestCount = countif(isnotnull(WebTimestamp)),
    SourceIPs = make_set(SourceIP, 10),
    RequestURLs = make_set(RequestURL, 10)
    by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessParentFileName, FileName, ProcessCommandLine
| project
    SpawnTimestamp,
    WebTimestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine,
    WebRequestCount,
    SourceIPs,
    RequestURLs
| sort by SpawnTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Node.js or Python processes spawning shell commands as part of legitimate OpenCTI plugin execution or background job processing.
- Administrative access to the OpenCTI host via the same service account that runs the application.
- Security scanning tools probing /graphql or /auth endpoints generating CommonSecurityLog entries that correlate with unrelated process spawns.

**Tuning notes:**
- Run the openctiSpawns subquery alone first to confirm OpenCTI process names appear in InitiatingProcessFileName on target hosts.
- Run the openctiWebHits subquery alone to confirm CommonSecurityLog is populated with OpenCTI HTTP traffic and that DeviceName matches the format used in DeviceProcessEvents.
- Consider adding a DeviceName or DeviceId allowlist scoped to known OpenCTI host identifiers to prevent matching Node.js or Python processes on unrelated hosts.
- If CommonSecurityLog is unavailable, the process spawn signal alone from openctiSpawns is still valuable as a standalone hunting query.

**Risks / caveats:**
- CommonSecurityLog must be populated by a WAF, reverse proxy, or network security device forwarding OpenCTI HTTP traffic to Sentinel; if no such connector is configured, the openctiWebHits subquery returns no results and the inner join produces no output.
- The DeviceName join key between DeviceProcessEvents and CommonSecurityLog is not guaranteed to be consistent; DeviceProcessEvents uses the DfE-registered hostname while CommonSecurityLog DeviceName reflects the log source device name, which may differ for OpenCTI hosts behind load balancers or with FQDN mismatches.
- CommonSecurityLog.RequestURL field population depends on the specific log source device type and its CEF mapping; not all WAF or proxy products populate RequestURL with application-layer paths in the CEF format ingested by Sentinel.
- The DeviceName join between DeviceProcessEvents and CommonSecurityLog is the primary reliability risk; if hostnames differ between the two data sources, the web hit correlation will silently fail and all results will appear as uncorrelated spawns.

### Triage Runbook

**First 15 minutes:**
- Identify the child process, its command line, and whether it is a shell, interpreter, downloader, or recon tool.
- Review the correlated web request details, including source IP and request URL, for exploit-like paths such as /graphql or /auth.
- Confirm the OpenCTI host identity and whether the application is behind a load balancer or proxy that could affect log correlation.
- Check for immediate post-spawn activity such as outbound connections, file creation, or additional process launches.

**Evidence to collect:**
- Spawn timestamp, process name, command line, parent process name, and account name.
- Web timestamp, source IP, request URL, and any available WAF or proxy disposition.
- Host role and deployment details for the OpenCTI service.
- Any related DeviceNetworkEvents or DeviceFileEvents occurring after the spawn.

**Pivot points:**
- DeviceProcessEvents for the OpenCTI host to reconstruct the process tree around the alert.
- CommonSecurityLog for additional requests from the same source IP or to the same URL paths.
- DeviceNetworkEvents for outbound connections from the host after the suspicious spawn.
- DeviceFileEvents for dropped scripts, temporary files, or new binaries created after the event.

**Benign explanations:**
- Legitimate OpenCTI plugin execution or background job processing that spawns helper processes.
- Administrative shell access or automation using the same service account as OpenCTI.
- Security scanning or testing activity that hit OpenCTI endpoints and coincided with unrelated process activity.

**Escalation criteria:**
- The spawned process is an unexpected shell or interpreter and not part of normal OpenCTI operation.
- The request path and source IP look exploit-like and align with the process spawn timing.
- There is evidence of payload staging, reverse connections, or additional suspicious child processes.
- The OpenCTI host shows repeated anomalous spawns or signs of broader compromise.

**Containment actions:**
- If exploitation is suspected, isolate the OpenCTI host or remove it from service.
- Preserve process, web, and network evidence before remediation.
- Block the source IP if it is malicious and blocking will not disrupt critical operations.
- Patch or disable the vulnerable OpenCTI exposure until validated.

**Closure criteria:**
- The child process is explained by approved OpenCTI functionality or maintenance activity.
- The correlated web request is from a trusted source or known scanner and does not indicate exploitation.
- No follow-on suspicious network, file, or process activity is present.
- The host’s deployment and application behavior account for the event.

<br/>
---
<br/>

## Detection 5: Metasploit Post-Exploitation Staging Behavior - Reverse Shell or Meterpreter Stager from Application Host

### Detection Opportunity

Application host processes initiate outbound reverse connections on non-standard ports following exploitation, consistent with Metasploit meterpreter or shell stager behavior observed after successful RCE against Langflow or related products.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Langflow, MongoDB, and More — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more)
  - Context: Rapid7 published Metasploit modules for multiple CVEs across Langflow and related products. Post-exploitation staging via meterpreter or reverse shells is the expected follow-on behavior after successful exploitation, producing recognizable outbound connection patterns from the compromised application host.

### Search Metadata

- CVEs: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674
- Threat actors: Not specified
- ATT&CK tags: T1190, T1095, T1059
- Products: Langflow, MongoDB, OpenCTI, Apache Solr
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, T1190, Langflow, MongoDB, OpenCTI, Apache Solr, Metasploit, T1095, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (low); Execution: T1059 Command and Scripting Interpreter (medium); Initial Access: T1190 Exploit Public-Facing Application (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let lookback = 7d;
let correlationWindow = 5min;
let knownMsfPorts = dynamic([4444, 4445, 5555, 8080, 8443, 9001, 1234, 6666]);
let suspiciousSpawns = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has_any ("python", "python3", "node", "java", "langflow", "uvicorn", "gunicorn", "solr")
| where FileName has_any ("sh", "bash", "zsh", "dash", "cmd.exe", "powershell.exe", "curl", "wget", "nc", "ncat")
| project
    SpawnTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    SpawnProcessId = ProcessId;
let reverseConns = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName has_any ("python", "python3", "node", "java", "sh", "bash", "dash", "nc", "ncat")
| where RemotePort in (knownMsfPorts)
    or (RemotePort >= 40000 and RemotePort <= 65535)
| where RemoteIP !startswith "127."
    and RemoteIP !startswith "10."
    and not (RemoteIP startswith "192.168.")
    and not (RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.") 
| project
    ConnTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    RemoteIP,
    RemotePort,
    ConnInitiatingProcess = InitiatingProcessFileName,
    ConnInitiatingProcessId = InitiatingProcessId;
suspiciousSpawns
| join kind=inner reverseConns on DeviceId
| where (ConnTimestamp - SpawnTimestamp) between (0min .. correlationWindow)
| summarize
    arg_min(SpawnTimestamp, *),
    UniqueRemoteIPs = dcount(RemoteIP),
    RemoteIPList = make_set(RemoteIP, 10),
    RemotePorts = make_set(RemotePort, 10),
    ConnectionCount = count()
    by DeviceId, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| project
    SpawnTimestamp,
    ConnTimestamp,
    DeviceName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    ConnInitiatingProcess,
    RemoteIP,
    RemotePort,
    UniqueRemoteIPs,
    RemoteIPList,
    RemotePorts,
    ConnectionCount
| sort by SpawnTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Application servers making legitimate outbound connections on high ephemeral ports to databases, message queues, or microservices.
- Python or Node.js processes connecting to cloud APIs or monitoring endpoints on ports in the 8080 or 8443 range.
- Network scanners or security tools running on the same host that initiate connections on Metasploit default ports as part of scanning activity.
- Legitimate use of netcat (nc) for debugging or health checks in containerized environments.

**Tuning notes:**
- Run the reverseConns subquery alone filtered to only knownMsfPorts (removing the ephemeral range) as a first pass to assess signal quality before adding the high-port range.
- Add DeviceName or DeviceId filters scoped to known application server host identifiers to reduce matching on unrelated hosts.
- Validate ActionType values for outbound connections in the environment by running DeviceNetworkEvents → where InitiatingProcessFileName == 'python' → summarize count() by ActionType to confirm 'ConnectionSuccess' is populated.
- Consider splitting into two separate queries: one for known Metasploit ports (higher confidence, schedulable after baselining) and one for the ephemeral port range (lower confidence, hunting only).

**Risks / caveats:**
- DeviceNetworkEvents ActionType 'ConnectionSuccess' must be confirmed as the correct value for outbound TCP connections in the environment; some DfE sensor versions use different ActionType values for outbound connections.
- The high ephemeral port range (40000-65535) filter will produce very high false positive volume in environments with active microservice or database traffic; this range should be removed or significantly narrowed before any scheduled deployment.
- The high ephemeral port range (40000-65535) will generate substantial false positives in environments with active microservice, database, or cloud API traffic; consider removing this range and relying solely on known Metasploit default ports for a lower-noise variant.
- The device-level join without process ID linkage means the reverse connection may originate from a different process than the spawned shell; process-level correlation via InitiatingProcessId matching the spawned process's ProcessId would require the shell itself to make the connection, which is the expected Metasploit behavior but cannot be enforced without a process ID join.

### Triage Runbook

**First 15 minutes:**
- Identify the outbound connection details: remote IP, remote port, initiating process, and the exact timing relative to the suspicious spawn.
- Check whether the process is a shell, netcat, Python, Node.js, Java, or another process commonly used for staging.
- Review the process tree to see whether the connection followed a suspicious child process from Langflow, OpenCTI, MongoDB, or Solr.
- Look for repeated connections to the same destination or multiple high-risk ports that suggest interactive control.

**Evidence to collect:**
- Spawn timestamp, connection timestamp, process name, command line, and process IDs for the suspected staging chain.
- Remote IP, remote port, and any repeated destination list from the alert.
- Host role and application context to determine whether the process is expected on that server.
- Any evidence of downloaded payloads, dropped binaries, or shell command execution after the connection.

**Pivot points:**
- DeviceNetworkEvents for all outbound connections from the host around the alert time, especially to the same remote IP or port.
- DeviceProcessEvents for the host to identify the process tree and any shell or downloader children.
- DeviceFileEvents for newly created executables, scripts, or temporary files on the host.
- If available, firewall or proxy logs to confirm whether the connection was allowed and whether it was interactive.

**Benign explanations:**
- Legitimate application traffic on high ports from microservices, databases, or cloud APIs.
- Debugging or administrative use of netcat or shell utilities in containerized environments.
- Security testing or scanning activity performed by authorized teams.
- Known service-to-service communication from the application host to internal infrastructure.

**Escalation criteria:**
- The outbound connection is to an unknown external IP or a port commonly used for reverse shells or handlers.
- The initiating process is an unexpected shell, downloader, or interpreter spawned by the application.
- There is evidence of interactive command execution, payload staging, or repeated beaconing.
- The host also shows suspicious inbound exploitation or other compromise indicators.

**Containment actions:**
- Isolate the host if the connection appears to be a reverse shell or meterpreter session.
- Preserve memory, process, and network evidence before remediation.
- Block the remote IP or port if confirmed malicious and operationally safe.
- Rotate credentials and tokens used on the host if compromise is confirmed.

**Closure criteria:**
- The outbound connection is tied to approved application behavior or known internal service communication.
- The process tree does not show suspicious shell or staging activity.
- No additional indicators of compromise are present on the host.
- The remote destination and port are expected for the application or environment.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Python Startup Hook File Write - Potential Supply Chain Persistence: Do not schedule yet; validate as an analyst-led hunt first.
- Python Process Outbound Network Connection Following Package Import - Credential Exfiltration Pattern: Do not schedule yet; validate as an analyst-led hunt first.
- Metasploit Post-Exploitation Staging Behavior - Reverse Shell or Meterpreter Stager from Application Host: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Unauthenticated RCE Exploitation Against Langflow - Child Process Spawn from Web Application: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.
- Pre-Authentication RCE Exploitation Against OpenCTI - Anomalous Child Process from Web Application Host: CommonSecurityLog must be populated by a WAF, reverse proxy, or network security device forwarding OpenCTI HTTP traffic to Sentinel; if no such connector is configured, the openctiWebHits subquery returns no results and the inner join produces no output.

**Shared-table notes:**
- DeviceNetworkEvents: shared by Python Startup Hook File Write - Potential Supply Chain Persistence; Python Process Outbound Network Connection Following Package Import - Credential Exfiltration Pattern; Unauthenticated RCE Exploitation Against Langflow - Child Process Spawn from Web Application; Metasploit Post-Exploitation Staging Behavior - Reverse Shell or Meterpreter Stager from Application Host
- DeviceProcessEvents: shared by Python Process Outbound Network Connection Following Package Import - Credential Exfiltration Pattern; Unauthenticated RCE Exploitation Against Langflow - Child Process Spawn from Web Application; Pre-Authentication RCE Exploitation Against OpenCTI - Anomalous Child Process from Web Application Host; Metasploit Post-Exploitation Staging Behavior - Reverse Shell or Meterpreter Stager from Application Host

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Unauthenticated RCE Exploitation Against Langflow - Child Process Spawn from Web Application; Pre-Authentication RCE Exploitation Against OpenCTI - Anomalous Child Process from Web Application Host.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Python Startup Hook File Write - Potential Supply Chain Persistence; Python Process Outbound Network Connection Following Package Import - Credential Exfiltration Pattern; Metasploit Post-Exploitation Staging Behavior - Reverse Shell or Meterpreter Stager from Application Host.

### Hunting Agenda and Promotion Criteria

- Python Startup Hook File Write - Potential Supply Chain Persistence: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Python Process Outbound Network Connection Following Package Import - Credential Exfiltration Pattern: Do not schedule yet; validate as an analyst-led hunt first..
- Metasploit Post-Exploitation Staging Behavior - Reverse Shell or Meterpreter Stager from Application Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Unauthenticated RCE Exploitation Against Langflow - Child Process Spawn from Web Application: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.; prove correlation keys join correctly on real tenant telemetry.
- Pre-Authentication RCE Exploitation Against OpenCTI - Anomalous Child Process from Web Application Host: CommonSecurityLog must be populated by a WAF, reverse proxy, or network security device forwarding OpenCTI HTTP traffic to Sentinel; if no such connector is configured, the openctiWebHits subquery returns no results and the inner join produces no output.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
