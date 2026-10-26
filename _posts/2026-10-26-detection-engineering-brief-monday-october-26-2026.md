---
layout: post
title: "Detection Engineering Brief - Monday, October 26, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-26
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - LiteLLM
  - Python
  - CVE-2026-93674
  - OpenCTI
  - T1190
  - Metasploit
  - CVE-2026-109618
  - CVE-2026-109619
  - PHP
  - T1195.001
  - T1195
  - T1059
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: LiteLLM, Python, CVE-2026-93674, OpenCTI, T1190, Metasploit, CVE-2026-109618, CVE-2026-109619, PHP, T1195.001, T1195, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Outbound Network Connection from Python Interpreter Shortly After pip Install; Unexpected Child Process Spawned by OpenCTI Service Following Pre-Auth RCE Exploitation.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Python Startup Hook File Written by pip or Python Process

### Detection Opportunity

Malicious code injected into Python startup hooks (sitecustomize.py or usercustomize.py) to execute at interpreter startup following supply chain compromise

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The LiteLLM 1.107.0 package was compromised to write malicious code into Python startup hook files (sitecustomize.py or usercustomize.py), causing the malicious payload to execute automatically on every Python interpreter invocation on developer systems.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1195.001, T1195
- Products: LiteLLM
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1195.001, T1195

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1195 Supply Chain Compromise/ T1195.001 Compromise Software Dependencies and Development Tools (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FileName in~ ("sitecustomize.py", "usercustomize.py")
| where FolderPath has_any ("site-packages", "lib/python", "Lib\\site-packages")
| where InitiatingProcessFileName in~ ("pip", "pip3", "pip.exe", "pip3.exe", "python", "python3", "python.exe")
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName,
    ReportId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Python package developers who intentionally maintain or test sitecustomize.py in their own environments.
- Automated CI/CD pipelines that install packages and legitimately write these files as part of environment setup.
- Virtual environment creation tools that scaffold site-packages directories including these files.

**Tuning notes:**
- Add conda.exe, poetry, uv, or other package manager binary names to the InitiatingProcessFileName filter if those tools are used in your environment.
- Add additional FolderPath patterns matching your Python installation roots (e.g., '/home/', '/opt/', 'C:\\Python', 'C:\\Users') if standard path fragments are insufficient.
- Consider adding an allowlist exclusion for known-good package names in InitiatingProcessCommandLine if specific packages legitimately write these files in your environment.

**Risks / caveats:**
- DeviceFileEvents requires Defender for Endpoint Plan 2 or Microsoft 365 Defender licensing with MDE onboarding on the monitored hosts. If Python developer workstations are not onboarded, the query will produce no results.
- Python installations using non-standard paths (e.g., conda environments, pyenv, custom virtualenv roots) may not contain 'site-packages' or 'lib/python' in the FolderPath and will not be detected. Review FolderPath values in your environment.
- Installs performed via package managers other than pip (e.g., conda, poetry, uv) will not match the InitiatingProcessFileName filter and require additional entries.
- The detection does not fire if the compromised package writes the startup hook file via a subprocess spawned by pip rather than pip directly.

### Triage Runbook

**First 15 minutes:**
- Identify the host, user account, timestamp, and exact file path from the alert; confirm whether the write was to sitecustomize.py or usercustomize.py in a Python site-packages or lib/python path.
- Review the initiating process command line to determine whether the write came from a normal pip install, a CI/CD job, or an unexpected package install command.
- Check whether the same host or user also triggered outbound Python network activity, suspicious child processes, or additional file writes shortly after the alert time.
- If the host is a developer workstation, verify with the user whether they recently installed or updated LiteLLM or another Python package and whether the activity was expected.

**Evidence to collect:**
- DeviceFileEvents for the file creation or modification event, including FolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, and ReportId.
- DeviceProcessEvents around the same timestamp to identify the pip/python parent process chain and any subsequent Python execution.
- DeviceNetworkEvents from the same host and user within a short window after the file write to look for remote connections from python.exe or python.
- Any package management logs, virtual environment setup logs, or CI/CD job records that explain the file write.

**Pivot points:**
- DeviceFileEvents filtered to the same DeviceName, FileName, and InitiatingProcessAccountName for a 24-hour window.
- DeviceProcessEvents for the same DeviceName and InitiatingProcessAccountName to find pip, python, or related package manager activity before and after the alert.
- DeviceNetworkEvents for the same DeviceName to identify outbound connections from python processes after the file modification.
- If available, endpoint timeline or investigation graph pivots from the ReportId to related process and network events.

**Benign explanations:**
- A developer intentionally created or edited sitecustomize.py or usercustomize.py for local environment customization.
- A CI/CD pipeline or build script legitimately wrote the file as part of environment provisioning or test setup.
- A virtual environment or package installation tool created the file as part of normal Python environment scaffolding.

**Escalation criteria:**
- The file write was performed by pip or python in a context that the user cannot explain or that does not match normal development activity.
- The same host shows outbound network activity, credential access behavior, or additional suspicious process execution shortly after the file write.
- The affected host is a developer workstation or build server that should not be modifying Python startup hooks outside approved workflows.
- Multiple hosts show the same pattern, suggesting a broader supply chain exposure rather than a one-off developer action.

**Containment actions:**
- Isolate the host if the file write is unexplained or if follow-on malicious activity is observed.
- Suspend or disable the user account if there is evidence the account was used to trigger the malicious install and the activity is not expected.
- Remove or quarantine the modified startup hook file only after preserving evidence and confirming the malicious content.
- Block the compromised package version or source in package management controls if the organization uses centralized dependency controls.

**Closure criteria:**
- The file write is confirmed to be part of an approved developer, CI/CD, or environment setup workflow.
- No suspicious follow-on process execution or outbound network activity is found on the host.
- The modified file is validated as benign and the package installation source is trusted and expected.
- The alert is documented with the responsible user, approved workflow, and any tuning needed for known-good paths or tools.

<br/>
---
<br/>

## Detection 2: Outbound Network Connection from Python Interpreter Shortly After pip Install

### Detection Opportunity

Remote code loading executed on developer systems following installation of a compromised Python package, with Python initiating outbound network connections

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: Following installation of the compromised LiteLLM package, malicious startup hook code caused the Python interpreter to load remote code, resulting in outbound network connections from the Python process on developer systems.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1195.001, T1195
- Products: LiteLLM
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1195.001, T1195

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1195 Supply Chain Compromise/ T1195.001 Compromise Software Dependencies and Development Tools (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let pip_installs = DeviceProcessEvents
| where (InitiatingProcessFileName in~ ("pip", "pip3", "pip.exe", "pip3.exe")
    or ProcessCommandLine has_any ("pip install", "pip3 install"))
| where ProcessCommandLine has "install"
| project
    DeviceName,
    PipTime = Timestamp,
    PipCommandLine = ProcessCommandLine,
    PipAccountName = InitiatingProcessAccountName;
let python_net = DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("python", "python3", "python.exe")
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(RemoteIP matches regex @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fd)")
| where ipv4_is_private(RemoteIP) == false
| project
    DeviceName,
    NetTime = Timestamp,
    RemoteIP,
    RemoteUrl,
    PythonProcessFileName = InitiatingProcessFileName,
    PythonAccountName = InitiatingProcessAccountName,
    NetReportId = ReportId;
pip_installs
| join kind=inner python_net on DeviceName
| where NetTime between (PipTime .. (PipTime + 5m))
| project
    DeviceName,
    PipTime,
    PipCommandLine,
    PipAccountName,
    NetTime,
    RemoteIP,
    RemoteUrl,
    PythonProcessFileName,
    PythonAccountName,
    NetReportId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Python applications that legitimately make outbound API calls immediately after a pip install in the same session (e.g., post-install scripts that call home for telemetry or license validation).
- Developer workflows where pip install is followed immediately by running a Python script that makes legitimate outbound connections.
- CI/CD pipelines that install packages and then immediately run tests or scripts that connect to external services.

**Tuning notes:**
- Narrow PipCommandLine to contain 'litellm' to scope specifically to the compromised package and dramatically reduce volume.
- Extend the time window beyond 5 minutes if your environment shows deferred startup hook execution patterns.
- Add known-good external IP ranges or domains (e.g., PyPI, package CDNs) to an exclusion list to reduce noise from legitimate post-install network activity.
- Consider running this as a 30-day lookback hunt before scheduling to understand baseline frequency in your environment.

**Risks / caveats:**
- RemoteUrl is not always populated in DeviceNetworkEvents; it depends on whether DNS resolution and HTTP inspection are available for the connection. Queries relying on RemoteUrl may return empty values for many rows.
- ipv4_is_private() does not handle IPv6 addresses; if Python connects via IPv6, those connections will not be filtered and may cause errors or unexpected results. The query should guard against non-IPv4 RemoteIP values.
- The 5-minute correlation window is a heuristic; deferred startup hook execution or slow package installs may fall outside this window and be missed.
- The regex-based private IP filter is a belt-and-suspenders guard alongside ipv4_is_private(); if RemoteIP contains an IPv6 address, ipv4_is_private() will still error. Consider pre-filtering to IPv4-only addresses using a stricter regex if IPv6 is common in your environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the pip install command, installed package name, and user account from the alert; verify whether the install included LiteLLM or another suspicious dependency.
- Review the destination IP and URL to determine whether the connection was to a known package repository, a corporate service, or an unknown external host.
- Check whether the Python process spawned additional child processes, accessed sensitive files, or made repeated outbound connections after the install.
- Compare the timing of the pip install and the network event to confirm the connection occurred in the expected post-install window.

**Evidence to collect:**
- DeviceProcessEvents for the pip install command line, parent process, and user context.
- DeviceNetworkEvents for the Python process, including RemoteIP, RemoteUrl, ActionType, and ReportId.
- DeviceFileEvents for any startup hook file writes on the same host around the same time.
- Any shell history, terminal logs, or CI job logs that show what was installed and what ran immediately afterward.

**Pivot points:**
- DeviceProcessEvents on the same DeviceName and InitiatingProcessAccountName to find pip install activity and subsequent python.exe execution.
- DeviceNetworkEvents on the same DeviceName to identify all outbound connections from python.exe in the same time window.
- DeviceFileEvents on the same DeviceName for sitecustomize.py or usercustomize.py writes.
- If available, proxy or firewall logs to validate the destination and payload pattern of the outbound connection.

**Benign explanations:**
- A legitimate Python application made an API call immediately after installation or first run.
- A developer installed a package and then launched a script that normally connects to external services.
- A CI/CD pipeline installed dependencies and then ran tests that legitimately contacted external endpoints.

**Escalation criteria:**
- The destination is unknown, suspicious, or unrelated to normal development activity.
- The Python process connects externally without a clear user action or expected application behavior.
- The same host also shows startup hook file modification, credential access, or other suspicious post-install behavior.
- Multiple developer hosts show the same install-to-network pattern, suggesting a broader compromise.

**Containment actions:**
- Isolate the host if the outbound connection is unexplained or points to a suspicious external destination.
- Block the destination IP or domain if it is confirmed malicious and not required for business use.
- Disable or suspend the user session if the activity appears tied to a malicious install or execution chain.
- Preserve process, network, and file evidence before remediation to support root cause analysis.

**Closure criteria:**
- The outbound connection is confirmed to be expected for the installed package or the user’s workflow.
- No malicious file writes, child processes, or repeated suspicious connections are found.
- The destination is validated as a trusted service or internal dependency endpoint.
- The event is documented as benign with supporting evidence from process, network, and user validation.

<br/>
---
<br/>

## Detection 3: pip Installation of Compromised LiteLLM Version 1.107.0

### Detection Opportunity

Credential theft via malicious code injected into the LiteLLM Python package supply chain, specifically version 1.107.0

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The specific version LiteLLM 1.107.0 was confirmed compromised and used to steal credentials via malicious code injected into the package. Detecting installation of this exact version provides a high-confidence anchor for identifying exposed systems.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1195.001, T1195
- Products: LiteLLM
- Platforms: Python
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, T1195.001, T1195

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1195 Supply Chain Compromise/ T1195.001 Compromise Software Dependencies and Development Tools (high)

### Deployment Gates

- Installs performed inside Docker build layers or other containerized environments may not surface in DeviceProcessEvents if the container host is not onboarded or if container process telemetry is not collected.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where ProcessCommandLine has "litellm"
    and ProcessCommandLine has "1.107.0"
    and (
        InitiatingProcessFileName in~ ("pip", "pip3", "pip.exe", "pip3.exe")
        or ProcessCommandLine has "pip install"
        or ProcessCommandLine has "pip3 install"
    )
| project
    Timestamp,
    DeviceName,
    ProcessCommandLine,
    FileName,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    InitiatingProcessParentFileName,
    InitiatingProcessParentCommandLine,
    ReportId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security researchers or analysts intentionally installing the compromised version in isolated test environments.
- Automated vulnerability scanning tools that enumerate installed package versions and log them in a way that surfaces in process telemetry.

**Tuning notes:**
- Run a historical search over 30-90 days to identify systems that already installed this version before the rule was deployed.
- Consider adding a broader variant that alerts on any litellm install (removing the version filter) to inventory all litellm deployments for version auditing.
- If your environment uses requirements.txt or pyproject.toml, consider supplementing this detection with a file content search for '1.107.0' in dependency files if that telemetry is available.

**Risks / caveats:**
- DeviceProcessEvents requires Defender for Endpoint onboarding on monitored hosts. If developer workstations are not onboarded, the query will produce no results.
- pip installs triggered indirectly by build tools (e.g., tox, poetry, uv, Docker build steps) may not surface the version string in ProcessCommandLine if the tool resolves and installs without passing the version explicitly on the command line.
- Installs performed without explicit version pinning (e.g., 'pip install litellm' resolving to 1.107.0 from PyPI cache) will not match because the version string will not appear in ProcessCommandLine.
- Requirements file-driven installs (pip install -r requirements.txt) will not match unless the version string is echoed into the command line by the calling tool.

### Triage Runbook

**First 15 minutes:**
- Verify the exact command line, host, user account, and timestamp to confirm the installation of LiteLLM 1.107.0.
- Determine whether the install occurred on a developer workstation, build server, or container host and whether that system handles sensitive credentials or tokens.
- Check for immediate follow-on activity such as Python startup hook file writes, outbound Python network connections, or credential access behavior.
- Identify whether the install was intentional, such as a pinned dependency in a requirements file, or whether it was an unexpected manual install.

**Evidence to collect:**
- DeviceProcessEvents showing the pip command, parent process, and user context.
- DeviceFileEvents for sitecustomize.py or usercustomize.py writes on the same host.
- DeviceNetworkEvents for python.exe outbound connections after the install.
- Any dependency manifests, build logs, or package lock files that show why LiteLLM 1.107.0 was installed.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessAccountName to find all pip activity involving litellm.
- DeviceFileEvents for the same host to look for startup hook modifications after the install.
- DeviceNetworkEvents for the same host to identify suspicious outbound connections from python processes.
- If available, identity and sign-in logs for the user account to determine whether credentials may have been exposed or reused.

**Benign explanations:**
- A security researcher or analyst intentionally installed the compromised version in a lab or isolated test environment.
- A build or dependency lock file pinned the version and caused an expected installation.
- A vulnerability assessment or software inventory process logged the version string during normal operations.

**Escalation criteria:**
- The installation occurred on a production, developer, or build system without a clear business justification.
- The host also shows startup hook modification, suspicious Python network activity, or credential-related behavior.
- The user account has access to secrets, tokens, or source code repositories and the install was unexpected.
- The same version appears on multiple hosts, indicating broader exposure to the compromised package.

**Containment actions:**
- Isolate the host if the install is unauthorized or if follow-on malicious behavior is observed.
- Revoke or rotate credentials used on the host if there is any indication of credential theft or token exposure.
- Block or remove the compromised package version from approved repositories and dependency sources.
- Preserve the host state and package evidence before cleanup to support incident investigation.

**Closure criteria:**
- The install is confirmed to be intentional, isolated, and performed in a controlled environment.
- No evidence of malicious execution, credential theft, or suspicious network activity is found.
- The affected system is not exposed to sensitive credentials or the credentials have been rotated if needed.
- The event is documented with the approved use case and any required tuning or exception handling.

<br/>
---
<br/>

## Detection 4: Unexpected Child Process Spawned by OpenCTI Service Following Pre-Auth RCE Exploitation

### Detection Opportunity

Pre-authentication RCE chain exploited against OpenCTI resulting in unexpected child processes spawned from the OpenCTI service process

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Langflow, MongoDB, and More — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more)
  - Context: A pre-authentication RCE chain against OpenCTI was added to Metasploit, enabling unauthenticated attackers to achieve code execution on OpenCTI hosts. Post-exploitation process spawning from the OpenCTI service is the primary detectable artifact.

### Search Metadata

- CVEs: CVE-2026-93674
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: OpenCTI
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-93674, OpenCTI, T1190, Metasploit, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("node", "opencti", "java")
| where FileName in~ ("bash", "sh", "dash", "zsh", "ksh", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe", "python", "python3", "perl", "ruby")
| where not(ProcessCommandLine has_any ("--version", "-version", "-V"))
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    ReportId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Other Node.js applications on the same host fleet that legitimately spawn shell processes (e.g., build tools, test runners, shell-out operations in Express apps).
- Java-based services co-located on the same host that spawn shells for legitimate administrative tasks.
- OpenCTI plugins or connectors that legitimately invoke shell commands as part of their operation.

**Tuning notes:**
- Add a DeviceName filter scoped to the hostname(s) of your OpenCTI deployment before scheduling as a production rule. This is required to prevent fleet-wide false positives.
- Confirm the exact process binary name used by your OpenCTI installation (e.g., 'node', 'node18', 'nodejs') and update InitiatingProcessFileName accordingly.
- Baseline child processes of the OpenCTI node process in your environment over 7-14 days before enabling as a scheduled alert to identify legitimate shell invocations to exclude.
- If OpenCTI runs in a container, verify that the container host is onboarded to MDE and that container process telemetry is collected.

**Risks / caveats:**
- The query will match any Node.js or Java application on the monitored host fleet that spawns a shell, not only OpenCTI. Without a DeviceName restriction to the OpenCTI host(s), this will produce false positives from other services. The OpenCTI host name(s) must be known and added to the query before scheduling.
- DeviceProcessEvents requires Defender for Endpoint onboarding on the OpenCTI host. If OpenCTI runs in a container or on a host not onboarded to MDE, the query will produce no results.
- Without a DeviceName restriction to the OpenCTI host(s), this query will alert on any Node.js or Java application across the entire monitored fleet that spawns a shell. This is the primary deployment blocker.
- OpenCTI connectors or workers that run as separate processes may use different parent process names not covered by the current filter.

### Triage Runbook

**First 15 minutes:**
- Confirm the OpenCTI host, service account, parent process, child process name, and command line from the alert.
- Check whether the child process is a shell, interpreter, or utility that is not normally spawned by OpenCTI on this host.
- Review recent inbound traffic, authentication logs, and application logs for signs of exploitation around the alert time.
- Determine whether the host is internet-facing and whether the alert aligns with known exploitation attempts or unusual requests.

**Evidence to collect:**
- DeviceProcessEvents showing the OpenCTI parent process, spawned child process, and full command line.
- Application and web server logs for OpenCTI around the same timestamp, including request paths and source IPs if available.
- DeviceNetworkEvents and firewall logs to identify inbound connections and any outbound activity from the host after the spawn.
- Any service logs, container logs, or orchestration events if OpenCTI runs in a containerized environment.

**Pivot points:**
- DeviceProcessEvents on the OpenCTI host for all child processes spawned by the OpenCTI service account in the same time window.
- DeviceNetworkEvents for the same host to identify suspicious outbound connections after the child process spawn.
- Web server, reverse proxy, and application logs to correlate inbound requests with the process event.
- If available, EDR timeline or investigation graph pivots from the ReportId to related process and network activity.

**Benign explanations:**
- A legitimate OpenCTI connector or plugin spawned a shell or interpreter as part of normal operation.
- An administrator performed a maintenance task that caused the service to launch a helper process.
- A health check or startup script triggered a benign shell invocation from the service context.

**Escalation criteria:**
- The child process is an unexpected shell, interpreter, or utility with no approved operational explanation.
- There is evidence of inbound exploitation attempts, suspicious requests, or post-exploitation outbound connections.
- The OpenCTI host is internet-facing and the process activity aligns with unauthorized access or command execution.
- Additional suspicious processes, persistence changes, or credential access are observed on the host.

**Containment actions:**
- Isolate the OpenCTI host if exploitation is suspected or if the child process is clearly malicious.
- Disable external access to the OpenCTI service until the host is validated and patched.
- Preserve logs, process evidence, and container or VM state before remediation.
- Rotate any credentials, API keys, or tokens used by the OpenCTI service if compromise is confirmed.

**Closure criteria:**
- The child process is confirmed to be part of an approved OpenCTI connector, plugin, or maintenance workflow.
- No evidence of unauthorized inbound access or post-exploitation activity is found.
- The host is patched or otherwise protected against the identified vulnerability exposure.
- The event is documented with the approved process chain and any required exclusions or scoping changes.

<br/>
---
<br/>

## Detection 5: PHP-FPM or Web Server Spawning Unexpected Shell Child Process - CVE-2026-109618 and CVE-2026-109619

### Detection Opportunity

Exploitation of critical PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619 resulting in the PHP-FPM or web server process spawning an interactive shell, indicating successful remote code execution

### Intelligence Context

- Unit 42: Threat Brief: Critical Vulnerabilities in PHP: CVE-2026-109618, CVE-2026-109619 (Updated October 25) — [https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/)
  - Context: Unit 42 reported critical PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619 enabling remote code execution. The primary post-exploitation signal is the PHP-FPM or web server process spawning unexpected shell or interpreter children, which is not expected in normal PHP application operation.

### Search Metadata

- CVEs: CVE-2026-109618, CVE-2026-109619
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: PHP
- Platforms: PHP
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-109618, CVE-2026-109619, PHP, T1190, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "php-fpm", "php", "php8", "php7",
    "php8.0", "php8.1", "php8.2", "php8.3",
    "apache2", "httpd", "nginx", "lighttpd"
)
| where FileName in~ (
    "bash", "sh", "dash", "zsh", "ksh",
    "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe",
    "python", "python3", "perl", "ruby",
    "nc", "ncat", "curl", "wget"
)
| where not(ProcessCommandLine has_any ("--version", "-version", "-v", "logrotate"))
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    ReportId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- PHP applications that legitimately shell out to system commands (e.g., image processing via ImageMagick, PDF generation via wkhtmltopdf invoked through shell_exec).
- Web server maintenance scripts that run under the web server process context and invoke bash or sh.
- Monitoring agents or health check scripts that run as children of the web server process.
- Legitimate use of curl or wget by PHP applications for outbound HTTP requests if those are spawned as child processes rather than using PHP's native HTTP functions.

**Tuning notes:**
- Add the specific PHP binary name matching your installed version to the InitiatingProcessFileName filter if it is not already covered (e.g., php8.4).
- Baseline child processes of php-fpm and web server processes in your environment over 7-14 days before enabling as a production scheduled rule to identify legitimate shell-out patterns to exclude.
- Add known-good command line patterns for legitimate shell-outs (e.g., specific ImageMagick or wkhtmltopdf invocations) to the not() exclusion filter.
- Consider adding a DeviceName filter scoped to known web server hosts to reduce noise from developer workstations running local PHP environments.

**Risks / caveats:**
- DeviceProcessEvents requires Defender for Endpoint onboarding on the Linux or Windows hosts running PHP-FPM or the web server. If web servers are not onboarded, the query will produce no results.
- PHP applications that legitimately use shell_exec, exec, or system() PHP functions will generate false positives. Baselining is required to identify and exclude these patterns.
- Versioned PHP binary names beyond those listed (e.g., php8.4, php7.4, php5.6) will not match the InitiatingProcessFileName filter if they differ from the hardcoded list.
- The -v exclusion may suppress some legitimate exploitation attempts if an attacker uses a shell invocation that happens to include '-v' in its arguments.

### Triage Runbook

**First 15 minutes:**
- Confirm the host, parent process, child process, and command line from the alert; verify whether the parent is php-fpm, php, apache2, httpd, nginx, or lighttpd.
- Check whether the child process is a shell, interpreter, or network utility that is unusual for the application and host role.
- Review web access logs, reverse proxy logs, and application logs for suspicious requests or exploitation patterns around the alert time.
- Determine whether the host is internet-facing and whether the process activity coincides with inbound traffic from an external source.

**Evidence to collect:**
- DeviceProcessEvents showing the parent PHP or web server process and the spawned child process with full command line.
- Web server, application, and reverse proxy logs for the same timestamp to identify the triggering request and source IP.
- DeviceNetworkEvents for outbound connections from the host after the child process spawn.
- Host patch level, service configuration, and any recent changes to PHP or web server deployment.

**Pivot points:**
- DeviceProcessEvents on the same DeviceName for all child processes spawned by the PHP or web server process in the alert window.
- DeviceNetworkEvents for the same host to identify suspicious outbound connections after the process spawn.
- Web server and application logs to correlate request paths, user agents, and source IPs with the process event.
- If available, firewall or WAF logs to confirm whether the request was blocked, allowed, or followed by exploitation.

**Benign explanations:**
- A legitimate PHP application invoked a shell or helper utility for image processing, PDF generation, or system maintenance.
- A scheduled maintenance or log rotation task ran under the web server context.
- A monitoring or health-check script spawned a helper process as part of normal operations.

**Escalation criteria:**
- The child process is an unexpected shell or interpreter with no approved application use case.
- The host is internet-facing and logs show suspicious requests consistent with exploitation.
- There is evidence of outbound connections, file modification, or additional process spawning after the event.
- Multiple web servers or PHP hosts show the same pattern, suggesting active exploitation at scale.

**Containment actions:**
- Isolate the host if exploitation is suspected or if the spawned process is clearly malicious.
- Temporarily remove the service from exposure or place it behind a WAF or maintenance page until validated.
- Preserve logs and process evidence before restarting or rebuilding the host.
- Rotate credentials, secrets, or tokens accessible to the web application if compromise is confirmed.

**Closure criteria:**
- The process spawn is confirmed to be a legitimate application or maintenance action.
- No suspicious inbound requests, outbound connections, or follow-on execution are found.
- The host is patched or otherwise protected against the identified PHP vulnerability exposure.
- The event is documented with the approved workflow and any tuning required for known-good shell-outs.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- Python Startup Hook File Written by pip or Python Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- Outbound Network Connection from Python Interpreter Shortly After pip Install: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- pip Installation of Compromised LiteLLM Version 1.107.0: Installs performed inside Docker build layers or other containerized environments may not surface in DeviceProcessEvents if the container host is not onboarded or if container process telemetry is not collected.
- Unexpected Child Process Spawned by OpenCTI Service Following Pre-Auth RCE Exploitation: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by Outbound Network Connection from Python Interpreter Shortly After pip Install; pip Installation of Compromised LiteLLM Version 1.107.0; Unexpected Child Process Spawned by OpenCTI Service Following Pre-Auth RCE Exploitation; PHP-FPM or Web Server Spawning Unexpected Shell Child Process - CVE-2026-109618 and CVE-2026-109619

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Python Startup Hook File Written by pip or Python Process; pip Installation of Compromised LiteLLM Version 1.107.0; PHP-FPM or Web Server Spawning Unexpected Shell Child Process - CVE-2026-109618 and CVE-2026-109619.
2. Resolve environment-mapping detections next: Unexpected Child Process Spawned by OpenCTI Service Following Pre-Auth RCE Exploitation.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Outbound Network Connection from Python Interpreter Shortly After pip Install.

### Hunting Agenda and Promotion Criteria

- Outbound Network Connection from Python Interpreter Shortly After pip Install: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Unexpected Child Process Spawned by OpenCTI Service Following Pre-Auth RCE Exploitation: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
