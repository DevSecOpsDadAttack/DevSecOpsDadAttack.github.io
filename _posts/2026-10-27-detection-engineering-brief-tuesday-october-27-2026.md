---
layout: post
title: "Detection Engineering Brief - Tuesday, October 27, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-27
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - LiteLLM
  - Python
  - CVE-2026-111497
  - Node.js
  - nodezlib
  - Brotli decoder
  - Linux
  - Windows
  - macOS
  - CVE-2026-93680
  - CVE-2026-0768
  - CVE-2026-0769
  - CVE-2026-10134
  - CVE-2026-7873
  - CVE-2026-93674
  - Langflow
  - MongoDB
  - OpenCTI
  - Apache Solr
  - Metasploit
  - T1071
  - T1041
  - T1203
  - T1105
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 4 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: LiteLLM, Python, CVE-2026-111497, Node.js, node:zlib, Brotli decoder, Linux, Windows, macOS, CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, Langflow, MongoDB, OpenCTI, Apache Solr, Metasploit, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: LiteLLM Supply Chain - Python Startup Hook File Written to Site-Packages; LiteLLM Supply Chain - Python Interpreter Outbound Connection After Package Install; CVE-2026-111497 - Vulnerable Node.js Version Inventory for Patch Gap Detection.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: LiteLLM Supply Chain - Python Startup Hook File Written to Site-Packages

### Detection Opportunity

Credential theft via Python startup hooks (usercustomize.py or sitecustomize.py written to Python site-packages directory)

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The LiteLLM 1.107.0 package was compromised to write malicious Python startup hook files (sitecustomize.py or usercustomize.py) into site-packages directories, enabling credential theft on every subsequent Python interpreter invocation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1041
- Products: LiteLLM
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1071, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Exfiltration: T1041 Exfiltration Over C2 Channel (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let lookback = 24h;
let pipInstalls = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where ProcessCommandLine has_any ("pip install", "pip3 install")
| project DeviceName, PipTime = TimeGenerated, PipCommandLine = ProcessCommandLine;
let hookWrites = DeviceFileEvents
| where TimeGenerated >= ago(lookback)
| where ActionType in ("FileCreated", "FileModified")
| where FileName in~ ("sitecustomize.py", "usercustomize.py")
| where FolderPath has "site-packages"
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, ReportId;
hookWrites
| join kind=leftouter (
    pipInstalls
) on DeviceName
| where isempty(PipTime) or (TimeGenerated >= PipTime and TimeGenerated <= PipTime + 10m)
| summarize
    arg_max(TimeGenerated, *),
    PipCommandLines = make_set(PipCommandLine, 10)
    by DeviceName, AccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, ReportId
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ActionType,
    InitiatingProcessFileName,
    PipCommandLines,
    ReportId
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Python package installations that include a sitecustomize.py or usercustomize.py as part of their distribution.
- Virtual environment setup tools writing these files during environment initialization.
- Developer workstations where custom sitecustomize.py files are intentionally maintained.

**Tuning notes:**
- Add FolderPath exclusions for known virtual environment roots if noise from venv creation is high.
- Adjust the 10-minute post-install window based on observed pip installation durations in the environment.
- Consider promoting to scheduled_rule once FP baseline is established and exclusions are tuned.

**Risks / caveats:**
- DeviceFileEvents.ReportId is available in Defender XDR but confirm it is populated for FileCreated and FileModified ActionTypes in the tenant before relying on it for deduplication.
- InitiatingProcessFileName in DeviceFileEvents reflects the direct parent process; pip may spawn child processes (python.exe) that perform the actual write, so InitiatingProcessFileName may not read 'pip' even during a pip install.
- The 10-minute pip-to-hook correlation window may miss slow installations or flag unrelated hook writes that happen to follow a pip install on the same device.
- InitiatingProcessFileName may show python.exe rather than pip.exe because pip delegates file writes to Python subprocesses; the pip correlation via DeviceProcessEvents join is the more reliable signal for install context.

### Triage Runbook

**First 15 minutes:**
- Confirm the file write is to sitecustomize.py or usercustomize.py under a Python site-packages path and note the exact FolderPath and AccountName.
- Check whether the write occurred shortly after a pip install or other package installation activity on the same host.
- Review the initiating process lineage to determine whether pip, python, an installer, or a developer tool created the file.
- Look for immediate follow-on Python execution or outbound network activity from the same host after the file write.

**Evidence to collect:**
- DeviceFileEvents for the hook file creation/modification, including FileName, FolderPath, ActionType, InitiatingProcessFileName, AccountName, TimeGenerated, and ReportId.
- DeviceProcessEvents around the same time for pip install, python -m pip, virtual environment creation, or package update commands.
- Any DeviceNetworkEvents from the host after the hook write to identify outbound destinations, ports, and timing.
- Endpoint context showing whether the path is system-wide site-packages or a developer virtual environment.

**Pivot points:**
- DeviceFileEvents filtered on sitecustomize.py and usercustomize.py in site-packages paths.
- DeviceProcessEvents filtered on pip install, python -m pip install, venv, virtualenv, conda, or package manager activity.
- DeviceNetworkEvents for the same DeviceName within 30 minutes after the file write.
- If available, related sign-in or credential use telemetry for the AccountName on the same host.

**Benign explanations:**
- Legitimate virtual environment creation or package initialization writing sitecustomize.py in a venv or conda environment.
- Developer-maintained custom startup hooks intentionally deployed on workstations.
- Legitimate package installation that includes a startup hook as part of the distribution, especially in test or build environments.

**Escalation criteria:**
- The hook file is written outside an approved virtual environment or developer-controlled path.
- The host shows outbound connections or suspicious Python execution after the hook write.
- The same account or host also shows other compromise indicators such as unusual logons, token use, or additional malicious file writes.
- The package install matches LiteLLM 1.107.0 or another confirmed compromised installation path.

**Containment actions:**
- Isolate the host if the hook write is in a production or user workstation context and cannot be explained by approved software deployment.
- Disable or reset the affected user account if there is evidence of credential theft or suspicious authentication activity.
- Remove the malicious startup hook file only after preserving evidence and confirming the scope of impact.
- Block further package installation from untrusted sources on the affected host until the investigation is complete.

**Closure criteria:**
- The file write is confirmed to be from an approved virtual environment or sanctioned developer activity.
- No suspicious follow-on Python execution, outbound connections, or credential misuse is found.
- The package source and install context are validated as benign and documented.
- Any malicious hook file has been removed and the host is returned to normal monitoring with no additional indicators.

<br/>
---
<br/>

## Detection 2: LiteLLM Supply Chain - Compromised Package Version Installation Detected

### Detection Opportunity

Installation of the specific compromised LiteLLM 1.107.0 package via pip

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The supply chain compromise was introduced in LiteLLM version 1.107.0 specifically. Detecting installation of this exact version via pip provides a low-FP, actionable signal for identifying exposed hosts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1041
- Products: LiteLLM
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1071, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Exfiltration: T1041 Exfiltration Over C2 Channel (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 24h;
let installEvents = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where ProcessCommandLine has_any ("pip install", "pip3 install", "python -m pip install", "python3 -m pip install")
| where ProcessCommandLine has "litellm"
| where ProcessCommandLine has_any ("1.107.0", "litellm==1.107.0")
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName = InitiatingProcessFileName;
installEvents
| join kind=leftouter (
    DeviceFileEvents
    | where TimeGenerated >= ago(lookback)
    | where ActionType in ("FileCreated", "FileModified")
    | where FileName in~ ("sitecustomize.py", "usercustomize.py")
    | where FolderPath has "site-packages"
    | project DeviceName, HookFile = FileName, HookPath = FolderPath, HookTime = TimeGenerated
) on DeviceName
| extend HookWrittenWithinWindow = iff(
    isnotempty(HookFile) and HookTime >= TimeGenerated and HookTime <= TimeGenerated + 15m,
    true,
    false
)
| where isempty(HookFile) or HookWrittenWithinWindow == true
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    HookFile,
    HookPath,
    HookTime,
    HookWrittenWithinWindow
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security researchers or malware analysts intentionally installing the compromised package in isolated analysis environments.
- Automated dependency resolution that pins to 1.107.0 in a requirements file where the version string does not appear in ProcessCommandLine.

**Tuning notes:**
- Add 'python -m pip' variants to the has_any filter if the environment uses module-style pip invocations.
- Consider adding a separate detection branch that monitors for litellm==1.107.0 in DeviceFileEvents for requirements.txt writes as a complementary signal.
- Set alert suppression per DeviceName with a 1-hour window to avoid duplicate alerts from pip retry attempts.

**Risks / caveats:**
- ProcessCommandLine may not capture the full pip command if the version is specified via a requirements file (e.g., requirements.txt) rather than inline; in that case the string '1.107.0' will not appear in ProcessCommandLine and the detection will not fire.
- On some Linux distributions, pip may be invoked as a Python module (python -m pip install litellm==1.107.0); the has_any filter for 'pip install' and 'pip3 install' will not match this invocation pattern.
- pip invocations via requirements files will not be detected because the version string will not appear in ProcessCommandLine.
- The 15-minute hook correlation window is a heuristic; installations on slow systems or with many dependencies may take longer before the hook file is written.

### Triage Runbook

**First 15 minutes:**
- Verify the command line shows installation of litellm==1.107.0 or an equivalent pip invocation on the host.
- Identify the user or automation account that performed the install and whether it was expected for that device.
- Check for immediate file writes to sitecustomize.py or usercustomize.py in site-packages after the install.
- Look for subsequent Python execution and outbound network activity from the same device within the next 15 minutes.

**Evidence to collect:**
- DeviceProcessEvents showing the full pip command line, account, device, and time of install.
- DeviceFileEvents for any hook file creation or modification after the install event.
- DeviceNetworkEvents from the same host after installation to identify suspicious remote connections.
- Any package management logs, CI/CD job context, or software deployment records that explain the install.

**Pivot points:**
- DeviceProcessEvents filtered for pip install, pip3 install, python -m pip install, and litellm==1.107.0.
- DeviceFileEvents for sitecustomize.py and usercustomize.py in site-packages on the same DeviceName.
- DeviceNetworkEvents for the same DeviceName within 15 minutes after the install.
- If available, software deployment or build pipeline telemetry tied to the AccountName.

**Benign explanations:**
- A developer or researcher intentionally installing the compromised version in a sandbox or test environment.
- An automated dependency pin in requirements.txt that legitimately references 1.107.0 for testing or reproducibility.
- A package install that did not result in malicious hook creation because the host was isolated or the install was blocked.

**Escalation criteria:**
- The install occurred on a production host, user workstation, or server without an approved test purpose.
- Hook files were created or modified after the install, especially outside an approved virtual environment.
- The host shows suspicious outbound connections, credential use, or additional compromise indicators after installation.
- The install was performed by an unexpected account or from an untrusted source repository.

**Containment actions:**
- Isolate the host if the install occurred on a production or user endpoint and cannot be clearly justified.
- Quarantine or remove the compromised package from the environment and prevent further installs from the same source.
- Reset credentials for the account used to perform the install if there is any sign of credential theft.
- Block or restrict the affected package source in enterprise package controls until the scope is understood.

**Closure criteria:**
- The installation is confirmed to be in an approved sandbox, lab, or developer test environment.
- No malicious hook file creation or suspicious post-install activity is observed.
- The package source, purpose, and device context are documented as authorized.
- Any affected host has been remediated or is confirmed not to have executed the malicious startup hook.

<br/>
---
<br/>

## Detection 3: LiteLLM Supply Chain - Python Interpreter Outbound Connection After Package Install

### Detection Opportunity

Remote code loading by Python interpreter making outbound network connections shortly after package installation

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: After the LiteLLM 1.107.0 supply chain compromise, remote code loading was observed. The malicious startup hook triggers outbound connections from the Python interpreter to retrieve or exfiltrate data, providing a behavioral network signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1041
- Products: LiteLLM
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1071, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Exfiltration: T1041 Exfiltration Over C2 Channel (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let postInstallWindow = 10m;
let installEvents = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where ProcessCommandLine has_any ("pip install", "pip3 install", "python -m pip install", "python3 -m pip install")
| where ProcessCommandLine has "litellm"
| where ProcessCommandLine has_any ("1.107.0", "litellm==1.107.0")
| project DeviceName, InstallTime = TimeGenerated;
DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where InitiatingProcessFileName in~ (
    "python.exe", "python3", "python", "python3.exe",
    "python3.9", "python3.10", "python3.11", "python3.12",
    "python3.9.exe", "python3.10.exe", "python3.11.exe", "python3.12.exe"
  )
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| join kind=inner (installEvents) on DeviceName
| where TimeGenerated >= InstallTime and TimeGenerated <= InstallTime + postInstallWindow
| extend MinutesAfterInstall = datetime_diff('minute', TimeGenerated, InstallTime)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    RemoteUrl = iff(isnotempty(RemoteUrl), RemoteUrl, ""),
    InstallTime,
    MinutesAfterInstall
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Python applications making outbound API calls within 10 minutes of a pip install on the same device.
- pip itself spawning Python subprocesses that connect to PyPI or CDN endpoints during package resolution.
- Monitoring agents, telemetry collectors, and CI/CD pipelines running Python with frequent outbound connections.

**Tuning notes:**
- Add known PyPI CDN IP ranges or ASNs to an exclusion list to reduce noise from legitimate package downloads.
- Extend the Python binary name list to include environment-specific interpreter names if Conda or pyenv is used.
- Consider adding a RemotePort filter (e.g., exclude 443 to known package registries) as an additional noise reduction layer.
- Promote to scheduled_rule only after establishing a baseline of expected Python outbound connections in the environment.

**Risks / caveats:**
- RemoteUrl may be empty in DeviceNetworkEvents for direct IP connections; the query should not rely on RemoteUrl being populated for all connection events.
- InitiatingProcessFileName in DeviceNetworkEvents reflects the process that opened the socket; on Linux, python3 binary names vary by distribution and may include version suffixes (e.g., python3.11) that are not covered by the current in~ filter.
- ipv4_is_private() does not handle IPv6 private ranges; if RemoteIP contains IPv6 addresses, additional filtering is needed.
- The 10-minute post-install window may miss delayed hook execution if the Python interpreter is not invoked immediately after installation.

### Triage Runbook

**First 15 minutes:**
- Confirm the outbound connection occurred after the package install on the same host and note the time delta.
- Identify the remote IP, URL, and port and determine whether the destination is expected for package downloads or application traffic.
- Check whether the Python process is a normal application, a build agent, or an interpreter launched by the compromised package.
- Look for additional signs of compromise on the host, including hook file writes, unusual child processes, or credential access activity.

**Evidence to collect:**
- DeviceNetworkEvents for the remote IP, RemoteUrl, RemotePort, and connection timing relative to the install.
- DeviceProcessEvents showing the Python interpreter command line and parent process lineage.
- DeviceFileEvents for sitecustomize.py or usercustomize.py writes on the same host.
- Any proxy, DNS, or firewall logs that identify the destination reputation and protocol.

**Pivot points:**
- DeviceNetworkEvents filtered to the same DeviceName and a short window after the install time.
- DeviceProcessEvents for python, python3, python3.x, or python.exe on the same host.
- DeviceFileEvents for hook file creation in site-packages on the same device.
- Proxy or DNS telemetry for the RemoteIP or RemoteUrl if available.

**Benign explanations:**
- Legitimate Python applications making API calls shortly after a package install.
- pip or package resolution traffic to PyPI, CDN, or internal package mirrors.
- CI/CD, telemetry, or monitoring agents that use Python and routinely connect outbound.

**Escalation criteria:**
- The destination is untrusted, newly observed, or inconsistent with normal package or application traffic.
- The connection is followed by hook file creation, suspicious child processes, or credential-related activity.
- The Python process is running on a production server or user workstation where the install was not expected.
- Multiple hosts show the same pattern, suggesting broader exposure to the compromised package.

**Containment actions:**
- Isolate the host if the outbound connection is to a suspicious destination and the install context is not clearly benign.
- Block the remote IP or domain at the network edge if it is confirmed malicious or part of an active campaign.
- Suspend or reset the account if there is evidence of credential theft or unauthorized access.
- Preserve process, network, and file evidence before cleanup or reimaging.

**Closure criteria:**
- The outbound connection is attributed to approved package download or legitimate application behavior.
- No malicious hook file, suspicious child process, or credential misuse is found.
- The remote destination is validated as benign and documented.
- The host is either remediated or confirmed not to have executed malicious code after the install.

<br/>
---
<br/>

## Detection 4: CVE-2026-111497 - Vulnerable Node.js Version Inventory for Patch Gap Detection

### Detection Opportunity

Execution of unpatched Node.js versions vulnerable to CVE-2026-111497 (critical out-of-bounds write in Brotli decoder)

### Intelligence Context

- Rapid7: CVE-2026-111497: Critical out-of-bounds write in the Node.js Brotli decoder — [https://www.rapid7.com/blog/post/etr-cve-2026-111497-critical-out-of-bounds-write-in-the-node-js-brotli-decoder](https://www.rapid7.com/blog/post/etr-cve-2026-111497-critical-out-of-bounds-write-in-the-node-js-brotli-decoder)
  - Context: CVE-2026-111497 is a critical out-of-bounds write in the Node.js Brotli decoder that can lead to process crashes, memory disclosure, or remote code execution. Identifying unpatched Node.js instances running in the environment enables patch prioritization before exploitation occurs.

### Search Metadata

- CVEs: CVE-2026-111497
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: Node.js, node:zlib, Brotli decoder
- Platforms: Linux, Windows, macOS
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-111497, Node.js, node:zlib, Brotli decoder, Linux, Windows, macOS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: inventory
- Severity recommendation: informational
- MITRE ATT&CK: Not mapped

### Deployment Gates

- ProcessVersionInfoProductVersion is a Windows PE metadata field and is typically not populated for ELF binaries on Linux or Mach-O binaries on macOS; the inventory will be incomplete for non-Windows Node.js deployments.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookback = 7d;
DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where FileName in~ ("node.exe", "node")
| where isnotempty(ProcessVersionInfoProductVersion)
| summarize
    LastSeen = max(TimeGenerated),
    DeviceCount = dcount(DeviceName),
    DeviceNames = make_set(DeviceName, 20)
    by ProcessVersionInfoProductVersion, FileName
| extend PatchStatus = "Cross-reference against Node.js security advisory for CVE-2026-111497 to determine if this version is patched"
| project
    ProcessVersionInfoProductVersion,
    FileName,
    DeviceCount,
    DeviceNames,
    LastSeen,
    PatchStatus
| sort by DeviceCount desc, LastSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Patched Node.js versions will appear in the inventory until fixed version strings are added as exclusion filters; all results require manual cross-reference against the Node.js security advisory.

**Tuning notes:**
- Once fixed version strings are confirmed from the Node.js security advisory, add them as exclusion filters: → where ProcessVersionInfoProductVersion !in ('18.x.y', '20.x.y', '22.x.y') where x.y are the patched minor/patch versions.
- For Linux and macOS coverage, supplement this query with DeviceTvmSoftwareInventory where SoftwareName has 'node' to leverage vulnerability management telemetry which does not depend on PE version metadata.
- Scope to specific DeviceGroups if Node.js is only deployed in a subset of the environment to reduce query cost.

**Risks / caveats:**
- ProcessVersionInfoProductVersion is a Windows PE metadata field and is typically not populated for ELF binaries on Linux or Mach-O binaries on macOS; the inventory will be incomplete for non-Windows Node.js deployments.
- The fixed version strings for CVE-2026-111497 are not included in the query; without them, the PatchStatus logic cannot distinguish vulnerable from patched instances and the query produces an undifferentiated inventory.
- ProcessVersionInfoProductVersion is not reliably populated for node binaries on Linux and macOS; a significant portion of the Node.js estate may be invisible to this query.
- Fixed version strings for CVE-2026-111497 must be obtained from the official Node.js security advisory and added as explicit exclusion filters before this query can distinguish vulnerable from patched instances.

### Triage Runbook

**First 15 minutes:**
- Review the listed Node.js versions and device names to identify systems that need patch validation.
- Confirm whether the inventory includes only Windows hosts or whether Linux/macOS coverage is incomplete.
- Compare the observed versions against the official Node.js advisory to determine which devices are actually vulnerable.
- Prioritize internet-facing, production, and developer systems that run Node.js services or build pipelines.

**Evidence to collect:**
- DeviceProcessEvents showing node or node.exe version strings and last-seen timestamps.
- Asset inventory or software management records that confirm the installed Node.js version on each device.
- OS platform information for each device to determine whether version metadata is reliable.
- Patch management or configuration management records showing whether the fixed version has been deployed.

**Pivot points:**
- DeviceProcessEvents for node and node.exe with ProcessVersionInfoProductVersion.
- DeviceTvmSoftwareInventory or equivalent software inventory telemetry for Node.js presence.
- DeviceInfo or asset inventory to map OS platform and ownership.
- Patch management records or deployment logs for Node.js updates.

**Benign explanations:**
- The device may already be patched, but the query cannot distinguish patched from unpatched without fixed version mapping.
- Linux and macOS systems may be undercounted because version metadata is not always populated.
- Some results may reflect non-production developer systems or ephemeral build agents.

**Escalation criteria:**
- A production or internet-facing host is running a version confirmed vulnerable by the advisory.
- Multiple critical systems share the same vulnerable version and have not been patched.
- The environment lacks reliable coverage for Linux/macOS Node.js instances and patch status cannot be verified.
- Node.js is used in exposed services or CI/CD systems that increase exploitation risk.

**Containment actions:**
- No immediate containment is required unless exploitation evidence exists; this is a patch-gap finding.
- Accelerate patching or upgrade scheduling for confirmed vulnerable hosts.
- Temporarily restrict exposure of vulnerable Node.js services if patching cannot be completed quickly.
- Increase monitoring on exposed Node.js systems until patching is verified.

**Closure criteria:**
- Each listed host has been cross-referenced against the advisory and marked patched or scheduled for remediation.
- Linux/macOS inventory gaps are addressed through alternate software inventory sources.
- High-risk hosts have an owner, remediation date, and tracking ticket.
- No exploitation indicators are present on the affected systems.

<br/>
---
<br/>

## Detection 5: Metasploit Framework Execution on Host - Potential Langflow Exploitation Activity

### Detection Opportunity

Metasploit framework binaries executed on a host, consistent with active exploitation tooling targeting Langflow CVEs

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Langflow, MongoDB, and More — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more)
  - Context: Rapid7 published Metasploit modules targeting multiple Langflow CVEs including authentication bypass and unauthenticated RCE. Detection of Metasploit binary execution on production hosts, particularly those running Langflow, indicates active exploitation tooling in use.

### Search Metadata

- CVEs: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674
- Threat actors: Not specified
- ATT&CK tags: T1203, T1105
- Products: Langflow, MongoDB, OpenCTI, Apache Solr, Metasploit
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, Langflow, MongoDB, OpenCTI, Apache Solr, Metasploit, T1203, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1203 Exploitation for Client Execution (medium); Command and Control: T1105 Ingress Tool Transfer (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let postExecWindow = 5m;
let msfExec = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where FileName in~ ("msfconsole", "msfvenom", "msfdb", "msfrpc", "msfconsole.bat", "msfvenom.bat")
    or ProcessCommandLine has_any ("msfconsole", "msfvenom", "msf5", "msf6")
| project
    DeviceName,
    AccountName,
    MsfTime = TimeGenerated,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName;
let postExecNet = DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| project
    DeviceName,
    NetTime = TimeGenerated,
    RemoteIP,
    RemotePort,
    RemoteUrl = iff(isnotempty(RemoteUrl), RemoteUrl, "");
msfExec
| join kind=leftouter (postExecNet) on DeviceName
| where isempty(NetTime) or (NetTime >= MsfTime and NetTime <= MsfTime + postExecWindow)
| project
    MsfTime,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    NetTime,
    RemoteIP,
    RemotePort,
    RemoteUrl
| sort by MsfTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized penetration testing activities on designated red team infrastructure.
- Security research workstations with Metasploit installed for defensive analysis.
- Vulnerability scanners or security platforms that invoke Metasploit as a backend component.

**Tuning notes:**
- Add a device group or device tag exclusion for authorized penetration testing infrastructure to suppress red team false positives.
- Extend the post-execution network window beyond 5 minutes if Metasploit session establishment in the environment takes longer.
- Consider adding FolderPath filters for known Metasploit installation paths (e.g., /usr/share/metasploit-framework, /opt/metasploit-framework) to increase specificity.
- Add a summarize step before the final project if deduplication per device per Metasploit execution event is needed to reduce alert volume.

**Risks / caveats:**
- On Linux, Metasploit binaries are typically Ruby scripts invoked via the ruby interpreter; FileName in DeviceProcessEvents may show 'ruby' rather than 'msfconsole', reducing detection coverage for script-based invocations.
- ProcessCommandLine capture completeness for long Metasploit command lines should be validated in the tenant, as truncation can occur.
- On Linux, Metasploit is commonly invoked as a Ruby script; FileName will show the Ruby interpreter rather than msfconsole, and the ProcessCommandLine match on 'msfconsole' may not fire if the script path is abbreviated.
- The 5-minute post-execution network window may miss delayed C2 connections if Metasploit session establishment takes longer in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the process name and command line match Metasploit binaries or known Metasploit arguments.
- Identify the user, host role, and whether the device is part of an approved red team or security testing environment.
- Check for outbound connections, payload staging, or suspicious child processes shortly after Metasploit execution.
- Determine whether the host runs Langflow or another exposed service targeted by the referenced CVEs.

**Evidence to collect:**
- DeviceProcessEvents showing the Metasploit process, command line, parent process, account, and folder path.
- DeviceNetworkEvents within minutes of execution to identify remote IPs, ports, and any suspicious outbound traffic.
- Host role and application inventory to confirm whether Langflow or related services are present.
- Any change-management, red-team authorization, or vulnerability testing records for the device.

**Pivot points:**
- DeviceProcessEvents filtered for msfconsole, msfvenom, msfdb, msfrpc, or command lines containing msf5/msf6.
- DeviceNetworkEvents for the same DeviceName within the post-execution window.
- DeviceFileEvents or process creation telemetry for payload drops, script execution, or archive extraction on the host.
- Asset inventory or service inventory to confirm whether Langflow is installed or exposed.

**Benign explanations:**
- Authorized penetration testing or red team activity on designated infrastructure.
- Security research or lab systems where Metasploit is intentionally installed and used.
- A vulnerability scanner or security platform that invokes Metasploit as part of a controlled assessment.

**Escalation criteria:**
- The host is not in an approved testing environment and Metasploit execution is unexpected.
- There is evidence of exploitation success, payload delivery, or suspicious network staging after execution.
- The device runs Langflow or another exposed service and is internet-facing or production critical.
- Multiple hosts show similar Metasploit activity without an approved testing window.

**Containment actions:**
- Isolate the host if Metasploit execution is unauthorized or accompanied by suspicious post-execution activity.
- Block suspicious outbound destinations observed after execution if they are confirmed malicious.
- Preserve memory, process, and network evidence before remediation or reimaging.
- Disable or review accounts used to launch the tool if unauthorized access is suspected.

**Closure criteria:**
- The activity is confirmed as authorized testing on approved infrastructure.
- No evidence of exploitation, payload staging, or unauthorized access is found.
- The device is documented with the testing authorization or red team exception.
- Any suspicious artifacts are removed and the host returns to normal monitoring.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- LiteLLM Supply Chain - Python Startup Hook File Written to Site-Packages: Do not schedule yet; validate as an analyst-led hunt first.
- LiteLLM Supply Chain - Python Interpreter Outbound Connection After Package Install: Do not schedule yet; validate as an analyst-led hunt first.

**Environment scope / baselines:**
- CVE-2026-111497 - Vulnerable Node.js Version Inventory for Patch Gap Detection: ProcessVersionInfoProductVersion is a Windows PE metadata field and is typically not populated for ELF binaries on Linux or Mach-O binaries on macOS; the inventory will be incomplete for non-Windows Node.js deployments.

**Shared-table notes:**
- DeviceFileEvents: shared by LiteLLM Supply Chain - Python Startup Hook File Written to Site-Packages; LiteLLM Supply Chain - Compromised Package Version Installation Detected
- DeviceProcessEvents: shared by LiteLLM Supply Chain - Python Startup Hook File Written to Site-Packages; LiteLLM Supply Chain - Compromised Package Version Installation Detected; LiteLLM Supply Chain - Python Interpreter Outbound Connection After Package Install; CVE-2026-111497 - Vulnerable Node.js Version Inventory for Patch Gap Detection; Metasploit Framework Execution on Host - Potential Langflow Exploitation Activity
- DeviceNetworkEvents: shared by LiteLLM Supply Chain - Python Interpreter Outbound Connection After Package Install; Metasploit Framework Execution on Host - Potential Langflow Exploitation Activity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: LiteLLM Supply Chain - Compromised Package Version Installation Detected; Metasploit Framework Execution on Host - Potential Langflow Exploitation Activity.
2. Resolve environment-mapping detections next: CVE-2026-111497 - Vulnerable Node.js Version Inventory for Patch Gap Detection.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: LiteLLM Supply Chain - Python Startup Hook File Written to Site-Packages; LiteLLM Supply Chain - Python Interpreter Outbound Connection After Package Install.

### Hunting Agenda and Promotion Criteria

- LiteLLM Supply Chain - Python Startup Hook File Written to Site-Packages: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- LiteLLM Supply Chain - Python Interpreter Outbound Connection After Package Install: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-111497 - Vulnerable Node.js Version Inventory for Patch Gap Detection: ProcessVersionInfoProductVersion is a Windows PE metadata field and is typically not populated for ELF binaries on Linux or Mach-O binaries on macOS; the inventory will be incomplete for non-Windows Node.js deployments..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
