---
layout: post
title: "Detection Engineering Brief - Sunday, October 25, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-25
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - LiteLLM
  - Python
  - Windows
  - Linux
  - CVE-2026-93680
  - CVE-2026-0768
  - CVE-2026-0769
  - CVE-2026-10134
  - CVE-2026-7873
  - CVE-2026-93674
  - Langflow
  - Metasploit
  - MongoDB
  - OpenCTI
  - Apache Solr
  - APT41
  - CVE-2022-21894
  - UEFI
  - BlackLotus
  - BlackX
  - T1105
  - T1095
  - T1542.001
  - T1068
  - T1542
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: LiteLLM, Python, Windows, Linux, CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, Langflow, Metasploit, MongoDB, OpenCTI, Apache Solr, APT41, CVE-2022-21894, UEFI, BlackLotus, BlackX, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Python Startup Hook File Write - Potential Supply Chain Credential Theft; Python Process Outbound Connection During Package Import - Remote Code Loading; Metasploit Staging Behavior - Unexpected Outbound Connection from Web Service Process; Unexpected Write to EFI System Partition by Non-System Process - BlackX Bootkit Staging.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Python Startup Hook File Write - Potential Supply Chain Credential Theft

### Detection Opportunity

Malicious modification of Python startup hook files (sitecustomize.py or usercustomize.py) to enable persistent credential theft following LiteLLM supply chain compromise

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The compromised LiteLLM 1.107.0 package wrote malicious code into Python startup hook files (sitecustomize.py or usercustomize.py) to execute credential theft logic automatically on every Python interpreter invocation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1105
- Products: LiteLLM
- Platforms: Python, Windows, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, Windows, Linux, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let HookWrites = DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sitecustomize.py", "usercustomize.py")
| where FolderPath has_any ("site-packages", "lib\\python", "lib/python", "Lib\\")
| where InitiatingProcessFileName in~ ("pip", "pip3", "python", "python3", "python.exe", "python3.exe", "pip.exe", "pip3.exe")
| where ActionType in ("FileCreated", "FileModified")
| project HookTimestamp = Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessSHA256;
let PostHookNetwork = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("python", "python3", "python.exe", "python3.exe")
| where not(ipv4_is_private(RemoteIP))
| where RemoteIP != "127.0.0.1"
| project NetTimestamp = Timestamp, DeviceName, RemoteIP, RemotePort, NetInitiatingProcess = InitiatingProcessFileName;
HookWrites
| join kind=inner PostHookNetwork on DeviceName
| where NetTimestamp between (HookTimestamp .. (HookTimestamp + 10m))
| project HookTimestamp, NetTimestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, RemoteIP, RemotePort, NetInitiatingProcess
| order by HookTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate pip installs that include post-install scripts making outbound calls (e.g., telemetry, license checks) on non-standard ports.
- CI/CD pipeline agents that run pip install followed immediately by package validation scripts that make network calls.
- Development environments where sitecustomize.py is legitimately managed by tooling such as conda or pyenv.

**Tuning notes:**
- Add FolderPath exclusions for known-safe virtual environment base paths used by internal tooling.
- Narrow the network leg to specific suspicious ports if the environment has a known baseline of Python outbound traffic patterns.
- Consider adding a SHA256 allowlist for known-good pip and python binaries to reduce noise from trusted package managers.

**Risks / caveats:**
- DeviceFileEvents may not capture writes to Python lib directories inside containers or virtual environments if the Defender for Endpoint sensor is not deployed at the host OS level.
- FolderPath population for file events inside Python virtual environments varies by sensor version; paths may differ from the has_any patterns used.
- The 10-minute correlation window may produce false positives in environments where pip installs are followed by automated test suites that make outbound calls.
- ipv4_is_private() does not handle IPv6 addresses; if RemoteIP contains IPv6 loopback or link-local addresses, add explicit exclusions.

### Triage Runbook

**First 15 minutes:**
- Confirm the affected host, user, and exact hook path; verify whether the file is sitecustomize.py or usercustomize.py under a Python site-packages or virtual environment path.
- Check whether the initiating process is a known package manager, build agent, or developer workflow versus an unexpected pip/python invocation.
- Review the file modification time and the subsequent outbound Python connection timing; determine whether the network activity occurred within minutes of the hook write.
- Identify the remote IP and port and assess whether the destination is external, unusual for the environment, or associated with package installation, telemetry, or proxy infrastructure.
- If the host is a developer workstation or CI runner, contact the owner to confirm whether a package install or environment bootstrap was expected at that time.

**Evidence to collect:**
- DeviceFileEvents record for the hook write, including FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessSHA256, and timestamp.
- DeviceNetworkEvents record for the outbound connection, including RemoteIP, RemotePort, InitiatingProcessFileName, ActionType, and timestamp.
- Any related DeviceProcessEvents showing the parent pip/python command line and the package being installed or executed.
- File contents or hash of the modified hook file if available from endpoint response or file collection.
- User context for the initiating process and whether the device is a workstation, build agent, or shared development host.

**Pivot points:**
- DeviceFileEvents for other writes to sitecustomize.py or usercustomize.py on the same device or by the same initiating process hash.
- DeviceNetworkEvents for additional outbound connections from python.exe or python3.exe around the same timestamp.
- DeviceProcessEvents to pivot from InitiatingProcessId or SHA256 into the full pip/python command line and child processes.
- DeviceEvents or Advanced Hunting process lineage to determine whether the activity came from a package install, script, or interactive session.

**Benign explanations:**
- A legitimate pip install or environment bootstrap that writes a startup hook as part of tooling such as conda, pyenv, or internal developer automation.
- A CI/CD agent running package validation or post-install checks that make outbound calls to internal services or package mirrors.
- A developer-managed virtual environment where sitecustomize.py is intentionally maintained by local tooling.

**Escalation criteria:**
- The hook file was written by an unexpected or unsigned Python/pip binary, or by a process not associated with normal software installation.
- The outbound connection is to an unfamiliar public IP, especially on a non-standard port, and is not attributable to a known package registry or proxy.
- The hook file content or hash indicates injected credential theft logic, obfuscation, or references to secrets, tokens, or environment variables.
- Multiple hosts show the same hook write pattern or the same initiating process hash, suggesting broader supply-chain impact.

**Containment actions:**
- Isolate the host if the hook file content is suspicious or if the outbound destination is clearly malicious and the device is not a shared build system.
- Quarantine or block the identified remote IP/domain at the network boundary if confirmed malicious.
- Disable or remove the modified hook file only after preserving evidence and confirming the change is not part of a legitimate deployment.
- Reset exposed credentials for the affected user or service account if the hook is confirmed to have harvested secrets.

**Closure criteria:**
- The file write is confirmed to be a legitimate package-management or developer-tool action and the outbound connection is attributable to approved infrastructure.
- The hook file content is reviewed and found benign, with no evidence of credential theft logic or persistence.
- No additional suspicious Python activity, credential access, or related host/network indicators are found after pivoting.
- The event is documented as an approved software installation or environment management activity and any allowlist updates are completed.

<br/>
---
<br/>

## Detection 2: Python Process Outbound Connection During Package Import - Remote Code Loading

### Detection Opportunity

Python interpreter initiating outbound network connections to external infrastructure during package execution, consistent with remote code loading behavior observed in the LiteLLM supply chain compromise

### Intelligence Context

- Microsoft Security Blog: Inside the LiteLLM 1.107.0 supply chain compromise: Credential theft through Python startup hooks — [https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
  - Context: The compromised LiteLLM package loaded remote code during execution, causing Python processes to make unexpected outbound connections to attacker-controlled infrastructure as part of the credential theft chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1105
- Products: LiteLLM
- Platforms: Python, Windows, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: LiteLLM, Python, Windows, Linux, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("python", "python3", "python.exe", "python3.exe")
| where InitiatingProcessParentFileName in~ ("pip", "pip3", "pip.exe", "pip3.exe", "python", "python3", "python.exe", "python3.exe")
| where RemotePort !in (80, 443, 8080, 8443)
| where not(ipv4_is_private(RemoteIP))
| where RemoteIP != "127.0.0.1"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    RemoteIP,
    RemotePort
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Python packages that legitimately phone home on non-standard ports during installation (e.g., license servers, internal artifact registries on custom ports).
- Data science tooling (Jupyter, Dask, Ray) that opens non-standard ports for inter-process communication.
- Internal package mirrors or proxy servers using non-standard ports that are not RFC1918 addresses.

**Tuning notes:**
- Add RemotePort exclusions for any internal artifact repositories or license servers using non-standard ports.
- If hunting for the specific LiteLLM compromise, add InitiatingProcessCommandLine has 'litellm' as an additional filter to narrow scope.
- Consider adding InitiatingProcessSHA256 to the projection to enable hash-based allowlisting of known-good Python binaries.

**Risks / caveats:**
- InitiatingProcessParentFileName is referenced in required_fields but not used in the original KQL; it is available in DeviceNetworkEvents and has been incorporated in the improved query.
- DeviceNetworkEvents may not populate InitiatingProcessFileName for all Python subprocess chains depending on sensor version and OS.
- Removing the DeviceProcessEvents join simplifies the query but loses ProcessCommandLine context from the spawning pip invocation; analysts should pivot to DeviceProcessEvents on InitiatingProcessId for full command-line context.
- ipv4_is_private() does not handle IPv6; add explicit IPv6 loopback/link-local exclusions if your environment uses dual-stack.

### Triage Runbook

**First 15 minutes:**
- Identify the Python process, parent process, and command line that preceded the connection; confirm whether it was launched by pip, a build script, or an interactive session.
- Review the destination IP and port and determine whether it is a known internal service, package mirror, or an unexpected public endpoint.
- Check whether the connection occurred on a non-standard port and whether the same host has other recent Python network activity.
- Correlate the event with package installation timestamps, especially around newly installed or upgraded Python packages.
- If the host is a developer workstation or CI runner, verify whether the activity aligns with an approved install, test, or deployment job.

**Evidence to collect:**
- DeviceNetworkEvents entry with RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, and timestamp.
- DeviceProcessEvents for the Python process and its parent to capture the full command line and process lineage.
- Package installation logs, shell history, or CI job logs showing what package or script was executed.
- Any related file writes or module loads around the same time that indicate package tampering or post-install execution.
- Host identity and role, including whether it is a developer endpoint, build agent, or production server.

**Pivot points:**
- DeviceProcessEvents for the same InitiatingProcessId to reconstruct the full Python execution chain.
- DeviceNetworkEvents for all connections from python.exe/python3.exe on the same device within the same time window.
- DeviceFileEvents for recent writes under Python library, site-packages, or virtual environment paths.
- DeviceEvents or audit logs for package installation, script execution, or archive extraction around the alert time.

**Benign explanations:**
- A legitimate package install or post-install script that contacts a license server, telemetry endpoint, or internal artifact service.
- Data science or automation tooling that uses Python to communicate with internal services on non-standard ports.
- A build or test pipeline that runs package validation immediately after installation and opens outbound connections as part of the workflow.

**Escalation criteria:**
- The destination is an unknown public IP or suspicious infrastructure and cannot be tied to approved package management or internal services.
- The Python process was spawned by an unexpected parent or from a path inconsistent with the approved runtime.
- The command line or related files show evidence of remote code retrieval, obfuscation, or execution of downloaded content.
- Multiple endpoints show the same package or process behavior, indicating possible broader compromise.

**Containment actions:**
- Isolate the host if the connection is to suspicious external infrastructure and the activity is not attributable to approved software installation.
- Block the remote IP/domain if confirmed malicious and not required for business operations.
- Suspend the affected build or deployment job until the package source and integrity are validated.
- Preserve the package, environment, and process artifacts before remediation if compromise is suspected.

**Closure criteria:**
- The connection is confirmed to be part of an approved package install, internal service call, or expected test workflow.
- No suspicious follow-on process creation, file writes, or additional outbound connections are observed.
- The package source and integrity are validated and match approved software supply-chain controls.
- The event is documented as benign and any necessary allowlist or tuning updates are completed.

<br/>
---
<br/>

## Detection 3: Langflow Service Spawning Unexpected Child Process - Unauthenticated RCE via Metasploit Module

### Detection Opportunity

Langflow web service process spawning unexpected child processes on Linux or Windows hosts, consistent with unauthenticated remote code execution exploitation via Metasploit modules targeting CVE-2026-0768, CVE-2026-0769, or CVE-2026-10134

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Langflow, MongoDB, and More — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more)
  - Context: Rapid7 added Metasploit modules exploiting three unauthenticated RCE paths and two authenticated code execution flaws in Langflow. Successful exploitation causes the Langflow service process to spawn attacker-controlled child processes.

### Search Metadata

- CVEs: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674
- Threat actors: Not specified
- ATT&CK tags: T1105, T1095
- Products: Langflow
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, Langflow, Metasploit, T1105, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1105 Ingress Tool Transfer (medium); Command and Control: T1095 Non-Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let LangflowInbound = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName has_any ("langflow", "uvicorn", "gunicorn")
| project InboundTime = Timestamp, DeviceName, RemoteIP, RemotePort;
let SuspiciousChildren = DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName has_any ("langflow", "uvicorn", "gunicorn", "python", "python3", "python.exe", "python3.exe")
| where FileName in~ ("sh", "bash", "zsh", "dash", "ash", "ksh", "tcsh", "cmd.exe", "powershell.exe", "pwsh.exe", "curl", "wget", "nc", "ncat", "perl", "ruby", "xterm")
| project SpawnTime = Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId;
LangflowInbound
| join kind=inner SuspiciousChildren on DeviceName
| where SpawnTime between (InboundTime .. (InboundTime + 2m))
| project
    InboundTime,
    SpawnTime,
    DeviceName,
    RemoteIP,
    RemotePort,
    SpawnedProcess = FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessId
| order by InboundTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Langflow deployments that legitimately invoke shell commands as part of workflow execution (e.g., custom nodes that run subprocess calls).
- Python-based Langflow components that spawn python3 subprocesses for sandboxed code execution.
- Automated health check scripts that run curl or wget against the Langflow service from the same host.

**Tuning notes:**
- Add the Langflow service listening port as a RemotePort filter on the inbound leg if other services share the host and generate noise.
- Add ProcessCommandLine exclusions for known-legitimate Langflow subprocess patterns identified during baselining.
- Extend the correlation window to 5 minutes if delayed exploitation payloads are observed in your environment.

**Risks / caveats:**
- ActionType value 'InboundConnectionAccepted' must be verified as populated in the target environment's DeviceNetworkEvents schema; some sensor configurations only emit 'ConnectionSuccess' for outbound events and may not record inbound accepted connections.
- Langflow deployments inside containers without a host-level Defender for Endpoint sensor will produce no telemetry in DeviceProcessEvents or DeviceNetworkEvents.
- The 2-minute correlation window may miss delayed subprocess spawning if Langflow defers execution after accepting the connection.
- If multiple inbound connections arrive within the window, the join may produce duplicate alert rows for the same spawn event; consider deduplication by InitiatingProcessId if alert volume is high.

### Triage Runbook

**First 15 minutes:**
- Confirm the Langflow host, listening service, and inbound source IP; determine whether the inbound connection was expected or from an unknown external address.
- Review the spawned child process name and command line to see whether it is a shell, interpreter, downloader, or reverse-shell utility.
- Check whether the child process was launched shortly after the inbound connection and whether the timing matches the alert window.
- Identify whether the host is internet-facing and whether Langflow is exposed without compensating controls such as authentication or network restrictions.
- Look for immediate post-exploitation behavior such as additional child processes, file writes, or outbound connections from the spawned process.

**Evidence to collect:**
- DeviceNetworkEvents showing the inbound connection, source IP, destination port, and timestamp.
- DeviceProcessEvents for the spawned child process, including FileName, ProcessCommandLine, InitiatingProcessFileName, and InitiatingProcessId.
- Any process tree or lineage showing the Langflow service process and subsequent child execution.
- Web server, application, or reverse proxy logs for the same timestamp and source IP.
- Host telemetry for additional suspicious activity such as credential access, file creation, or outbound staging connections.

**Pivot points:**
- DeviceProcessEvents for child processes spawned by the Langflow service process on the same host.
- DeviceNetworkEvents for additional inbound attempts or outbound connections from the same device around the alert time.
- DeviceFileEvents for new files, scripts, or dropped payloads created after the inbound connection.
- Application logs for Langflow, uvicorn, or gunicorn to identify the request path and any error or execution traces.

**Benign explanations:**
- A legitimate Langflow workflow or custom node that intentionally spawns shell or Python subprocesses.
- Administrative activity or health checks that trigger a service restart or helper process creation.
- A local automation script or container orchestration action that coincides with the inbound connection but is unrelated to exploitation.

**Escalation criteria:**
- The child process is an unexpected shell, downloader, or interpreter and there is no approved workflow that explains it.
- The inbound source is external, untrusted, or associated with scanning or exploitation activity.
- The host is internet-facing and shows additional signs of compromise such as reverse shells, credential access, or persistence.
- Multiple suspicious child processes or repeated inbound-to-child patterns occur on the same host.

**Containment actions:**
- Isolate the host if the child process is clearly malicious or if exploitation is strongly suspected.
- Block the source IP at the perimeter if it is confirmed hostile and not part of authorized testing.
- Disable external access to Langflow until the service is patched, authenticated, or otherwise protected.
- Preserve process, network, and application logs before restarting or rebuilding the service.

**Closure criteria:**
- The child process is confirmed to be part of an approved Langflow workflow or administrative action.
- No additional suspicious processes, network connections, or file changes are found on the host.
- The inbound source is validated as authorized testing or a known internal client.
- The service is patched or hardened and the event is documented as benign.

<br/>
---
<br/>

## Detection 4: Metasploit Staging Behavior - Unexpected Outbound Connection from Web Service Process

### Detection Opportunity

Web service processes (Langflow, MongoDB, OpenCTI, Apache Solr) initiating outbound connections to external IPs on Metasploit default staging ports following inbound exploitation attempts

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Langflow, MongoDB, and More — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more)
  - Context: Metasploit modules were added for multiple CVEs across Langflow, MongoDB, OpenCTI, and Apache Solr. Post-exploitation Metasploit staging typically causes the exploited service process to initiate a reverse connection to attacker infrastructure on common Metasploit handler ports.

### Search Metadata

- CVEs: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674
- Threat actors: Not specified
- ATT&CK tags: T1105, T1095
- Products: Langflow, MongoDB, OpenCTI, Apache Solr
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-93680, CVE-2026-0768, CVE-2026-0769, CVE-2026-10134, CVE-2026-7873, CVE-2026-93674, Langflow, MongoDB, OpenCTI, Apache Solr, Metasploit, T1105, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1105 Ingress Tool Transfer (medium); Command and Control: T1095 Non-Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let MetasploitPorts = dynamic([4444, 4445, 5555, 8888, 9999, 1234]);
let ServiceProcesses = dynamic(["langflow", "uvicorn", "gunicorn", "mongod", "mongos", "solr", "java", "opencti"]);
let InboundToService = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName has_any (ServiceProcesses)
| project InboundTime = Timestamp, DeviceName, ServiceProcess = InitiatingProcessFileName;
let OutboundStaging = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName has_any (ServiceProcesses)
| where RemotePort in (MetasploitPorts)
| where not(ipv4_is_private(RemoteIP))
| where RemoteIP != "127.0.0.1"
| project OutboundTime = Timestamp, DeviceName, RemoteIP, RemotePort, OutboundInitiatingProcess = InitiatingProcessFileName;
InboundToService
| join kind=inner OutboundStaging on DeviceName
| where OutboundTime between (InboundTime .. (InboundTime + 5m))
| project
    InboundTime,
    OutboundTime,
    DeviceName,
    ServiceProcess,
    RemoteIP,
    RemotePort,
    OutboundInitiatingProcess
| order by InboundTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Java-based services (Elasticsearch, Kafka, Spark) running on the same host as Solr or OpenCTI that make outbound connections on ports in the Metasploit port list.
- Development or testing environments where port 8888 is used for Jupyter notebooks or port 5555 for Android Debug Bridge.
- Legitimate MongoDB replication or sharding traffic on non-standard ports.

**Tuning notes:**
- Replace 'java' in ServiceProcesses with the specific process name used by your Solr or OpenCTI deployment to reduce false positives.
- Add known internal penetration testing source IPs to a RemoteIP exclusion list to suppress authorized red team activity.
- Consider splitting this query into per-product variants (one for Langflow/Python, one for MongoDB, one for Java-based services) to enable independent tuning.

**Risks / caveats:**
- ActionType value 'InboundConnectionAccepted' must be verified as populated in the target environment's DeviceNetworkEvents schema.
- ActionType value 'ConnectionSuccess' must be verified as the correct value for outbound established connections in the target environment's schema.
- The 'java' process name will match any JVM-based application on the host, not only Solr or OpenCTI; this is the primary source of expected false positives.
- Sophisticated Metasploit operators using custom listener ports outside the MetasploitPorts list will not be detected.

### Triage Runbook

**First 15 minutes:**
- Confirm the service process name and whether it is one of the expected web services on the host, such as Langflow, MongoDB, OpenCTI, or Solr.
- Review the outbound destination IP and port and determine whether it matches a known Metasploit handler port or an unexpected public endpoint.
- Check for a preceding inbound connection or exploit attempt on the same host within the alert window.
- Inspect the process command line and parent context to determine whether the outbound connection originated from a service process or a spawned child.
- Look for additional signs of staging or post-exploitation activity, including shell launches, file drops, or repeated connections.

**Evidence to collect:**
- DeviceNetworkEvents for both the inbound and outbound connections, including timestamps, RemoteIP, RemotePort, and initiating process names.
- DeviceProcessEvents for the service process and any child processes spawned around the same time.
- Application and reverse proxy logs to correlate inbound requests with the outbound staging event.
- Host telemetry showing whether the service process executed commands, downloaded files, or spawned shells.
- Any available network flow or firewall logs confirming the external destination and connection pattern.

**Pivot points:**
- DeviceNetworkEvents for all outbound connections from the same service process on the host.
- DeviceProcessEvents for child processes spawned by the service process before and after the outbound connection.
- DeviceFileEvents for dropped payloads or modified service files around the same time.
- Web application logs for the service to identify the inbound request that may have triggered exploitation.

**Benign explanations:**
- A legitimate service health check, replication, or plugin action that happens to use a port overlapping with the Metasploit list.
- A development or test environment where the service shares a host with tools that use common staging ports.
- Authorized penetration testing activity that is not yet documented in the SOC workflow.

**Escalation criteria:**
- The outbound connection is to an unknown public IP on a suspicious handler port and follows an inbound request to the service.
- The service process spawns shells, interpreters, or downloaders after the outbound connection.
- The host is production-facing and the behavior is not explained by a known application workflow or maintenance task.
- Multiple hosts or services show the same staging pattern, suggesting coordinated exploitation.

**Containment actions:**
- Isolate the host if the outbound staging behavior is confirmed malicious or strongly suspicious.
- Block the destination IP/port pair if it is not required for business operations and is associated with attacker infrastructure.
- Temporarily disable external access to the affected service until the vulnerability is assessed and patched.
- Preserve logs and memory or process artifacts before remediation if active exploitation is suspected.

**Closure criteria:**
- The outbound connection is tied to approved testing, a known service workflow, or a documented internal dependency.
- No additional suspicious child processes or follow-on connections are observed.
- The destination is validated as legitimate infrastructure and the port use is expected for the service.
- The event is documented and any necessary tuning or allowlisting is completed.

<br/>
---
<br/>

## Detection 5: Unexpected Write to EFI System Partition by Non-System Process - BlackX Bootkit Staging

### Detection Opportunity

Non-system processes writing files to the EFI system partition on Windows endpoints, consistent with CVE-2022-21894 exploitation used by APT41 to stage the BlackX UEFI bootkit

### Intelligence Context

- Securelist: How APT41 revived the BlackLotus bootkit to attack diplomatic organizations in Central Asia — [https://securelist.com/uefi-bootkit-blackx/121539/](https://securelist.com/uefi-bootkit-blackx/121539/)
  - Context: APT41 exploited CVE-2022-21894 (Baton Drop) to bypass Secure Boot and write the BlackX UEFI bootkit to the EFI system partition. File writes to EFI partition paths by non-system processes are a detectable artifact of this staging activity.

### Search Metadata

- CVEs: CVE-2022-21894
- Threat actors: APT41
- ATT&CK tags: T1542.001, T1068, T1542
- Products: Not specified
- Platforms: Windows, UEFI
- Malware: BlackLotus, BlackX
- Tools: Not specified
- Search tags: APT41, CVE-2022-21894, Windows, UEFI, BlackLotus, BlackX, T1542.001, T1068, T1542

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1542 Pre-OS Boot/ T1542.001 System Firmware (high); Privilege Escalation: T1068 Exploitation for Privilege Escalation (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let LegitimateEFIWriters = dynamic([
    "MoUsoCoreWorker.exe",
    "TrustedInstaller.exe",
    "svchost.exe",
    "bootmgr",
    "bcdboot.exe",
    "reagentc.exe",
    "dismhost.exe"
]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has_any (
    "\\EFI\\",
    "\\Boot\\",
    "EFI\\Microsoft",
    "EFI\\Boot"
)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not(InitiatingProcessFileName has_any (LegitimateEFIWriters))
| project
    Timestamp,
    DeviceName,
    FolderPath,
    FileName,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    InitiatingProcessAccountName
| summarize
    EFIWriteCount = count(),
    Files = make_set(FileName),
    Paths = make_set(FolderPath),
    Actions = make_set(ActionType),
    SHA256s = make_set(InitiatingProcessSHA256),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by EFIWriteCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Firmware update utilities from hardware vendors (Dell Command Update, HP Support Assistant, Lenovo System Update) that write to the EFI partition during legitimate firmware updates.
- Windows Feature Updates that use processes not in the LegitimateEFIWriters list to stage bootloader changes.
- Third-party disk management or encryption tools that interact with the EFI partition.

**Tuning notes:**
- Add firmware vendor update process names specific to your hardware fleet (e.g., DellCommandUpdate.exe, HPFirmwareUpdRec.exe, LenovoSystemUpdateAddin.exe) to the LegitimateEFIWriters list.
- Cross-reference any matches against DeviceEvents for Secure Boot state changes on the same device and timestamp to increase confidence.
- Reduce the lookback window from 14 days to 24 hours when running as a near-real-time hunt to reduce result volume and improve signal-to-noise ratio.

**Risks / caveats:**
- DeviceFileEvents may not capture file writes to the EFI system partition if the partition is not mounted at the OS level or if the Defender for Endpoint sensor does not monitor that mount point; this must be confirmed by checking for any existing EFI-path events in the environment before relying on this query.
- The join between DeviceFileEvents and DeviceProcessEvents on DeviceName and InitiatingProcessFileName without a ProcessId key is a many-to-many join that can produce a very large intermediate result set on active hosts, potentially causing query timeouts or misleading correlations.
- Whether DeviceFileEvents captures EFI partition writes in the target environment must be confirmed before this query can be trusted; absence of results may indicate a telemetry gap rather than absence of activity.
- The LegitimateEFIWriters list does not include firmware vendor update utilities; these must be added based on the hardware fleet in the environment to avoid false positives.

### Triage Runbook

**First 15 minutes:**
- Confirm the device, writing process, and exact EFI or Boot path involved; verify whether the process is a known Windows update or firmware utility.
- Review the initiating process command line, account, and hash to determine whether the writer is expected and signed.
- Check whether the write coincides with a firmware update, OS upgrade, disk repair, or boot configuration change.
- Look for related indicators such as Secure Boot changes, boot configuration modifications, or additional writes to EFI paths.
- Assess whether the endpoint is a high-value target or has signs of privilege escalation preceding the write.

**Evidence to collect:**
- DeviceFileEvents for the EFI path write, including FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, and account name.
- Any DeviceEvents or security logs showing Secure Boot, boot configuration, or firmware-related changes on the same device.
- DeviceProcessEvents or related telemetry for the initiating process lineage and any parent process context.
- System and vendor update logs that could explain a legitimate firmware or bootloader modification.
- If available, a copy or hash of the written EFI file for offline analysis.

**Pivot points:**
- DeviceFileEvents for other EFI or Boot partition writes on the same host and by the same process hash.
- DeviceEvents for Secure Boot state changes, boot configuration changes, or firmware update activity.
- DeviceProcessEvents for the initiating process and any parent processes around the same timestamp.
- Endpoint or OS logs for Windows Update, bcdboot, reagentc, or vendor firmware tools.

**Benign explanations:**
- A legitimate Windows update, recovery operation, or bootloader repair performed by trusted system utilities.
- A hardware vendor firmware update tool writing to the EFI partition during a scheduled maintenance window.
- A disk encryption, recovery, or boot management product that legitimately modifies EFI files.

**Escalation criteria:**
- The writing process is not a trusted system utility, firmware updater, or approved maintenance tool.
- The EFI write is accompanied by privilege escalation, suspicious command-line arguments, or other boot-related tampering.
- There are multiple EFI writes, Secure Boot changes, or boot configuration modifications without a valid change record.
- The host is a sensitive system and the activity cannot be explained by approved maintenance.

**Containment actions:**
- Isolate the host if the EFI write is suspicious and not attributable to a trusted maintenance process.
- Suspend further reboot or firmware activity until the device is assessed, if operationally safe to do so.
- Preserve the EFI-related files and logs before remediation or rebooting the system.
- Escalate to endpoint engineering or incident response for boot integrity validation and recovery planning.

**Closure criteria:**
- The EFI write is confirmed to be part of a legitimate, approved firmware or boot maintenance activity.
- The initiating process, account, and file hash match trusted vendor or Microsoft update behavior.
- No additional EFI tampering, Secure Boot changes, or suspicious boot artifacts are found.
- The event is documented and any required allowlist or hardware-vendor exclusions are added.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Python Startup Hook File Write - Potential Supply Chain Credential Theft: Do not schedule yet; validate as an analyst-led hunt first.
- Python Process Outbound Connection During Package Import - Remote Code Loading: Do not schedule yet; validate as an analyst-led hunt first.
- Metasploit Staging Behavior - Unexpected Outbound Connection from Web Service Process: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- Unexpected Write to EFI System Partition by Non-System Process - BlackX Bootkit Staging: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceFileEvents: shared by Python Startup Hook File Write - Potential Supply Chain Credential Theft; Unexpected Write to EFI System Partition by Non-System Process - BlackX Bootkit Staging
- DeviceNetworkEvents: shared by Python Startup Hook File Write - Potential Supply Chain Credential Theft; Python Process Outbound Connection During Package Import - Remote Code Loading; Langflow Service Spawning Unexpected Child Process - Unauthenticated RCE via Metasploit Module; Metasploit Staging Behavior - Unexpected Outbound Connection from Web Service Process
- DeviceProcessEvents: shared by Python Process Outbound Connection During Package Import - Remote Code Loading; Langflow Service Spawning Unexpected Child Process - Unauthenticated RCE via Metasploit Module; Unexpected Write to EFI System Partition by Non-System Process - BlackX Bootkit Staging

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Langflow Service Spawning Unexpected Child Process - Unauthenticated RCE via Metasploit Module.
2. Resolve environment-mapping detections next: Unexpected Write to EFI System Partition by Non-System Process - BlackX Bootkit Staging.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Python Startup Hook File Write - Potential Supply Chain Credential Theft; Python Process Outbound Connection During Package Import - Remote Code Loading; Metasploit Staging Behavior - Unexpected Outbound Connection from Web Service Process.

### Hunting Agenda and Promotion Criteria

- Python Startup Hook File Write - Potential Supply Chain Credential Theft: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Python Process Outbound Connection During Package Import - Remote Code Loading: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Metasploit Staging Behavior - Unexpected Outbound Connection from Web Service Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Unexpected Write to EFI System Partition by Non-System Process - BlackX Bootkit Staging: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
