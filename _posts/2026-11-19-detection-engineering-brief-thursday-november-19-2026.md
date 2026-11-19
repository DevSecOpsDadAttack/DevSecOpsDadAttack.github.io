---
layout: post
title: "Detection Engineering Brief - Thursday, November 19, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-19
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-114938
  - T1190
  - OpenJDK
  - Oracle Java SE
  - Oracle GraalVM
  - Java 17
  - JVM
  - CVE-2026-123007
  - nginx
  - HTTP/2
  - vendor scripts
  - websites
  - T1059
  - T1071
  - T1505.003
  - T1036
  - T1505
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 2 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-114938, T1190, OpenJDK, Oracle Java SE, Oracle GraalVM, Java 17, JVM, CVE-2026-123007, nginx, HTTP/2, vendor scripts, websites, T1059, T1071, T1505.003, T1036, T1505.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-114938 - Unexpected Child Process Spawned by Java Process on Internet-Facing Host; CVE-2026-123007 - Shell or Interpreter Spawned by nginx Worker Process After HTTP/2 Request Burst; CVE-2026-123007 - nginx Error Log Memory Corruption Events Correlated with External Source IPs; OPTIMJACK - Unexpected Script File Modification in Web Root by Non-Deployment Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-114938 - Unexpected Child Process Spawned by Java Process on Internet-Facing Host

### Detection Opportunity

Unauthenticated remote attacker executes code in the Java process, resulting in unexpected child process spawning from java.exe or javaw.exe

### Intelligence Context

- Rapid7: CVE-2026-114938: Reported Critical Pre-authentication Remote Code Execution in Java 17 — [https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17](https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17)
  - Context: Rapid7 reported that an unauthenticated remote attacker can exploit a vulnerable Base64 decoder in Java 17 to crash the JVM or execute code with the privileges of the Java process. Post-exploitation would manifest as unexpected child processes spawned from java.exe or javaw.exe, or anomalous outbound connections from the JVM host.

### Search Metadata

- CVEs: CVE-2026-114938
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: OpenJDK, Oracle Java SE, Oracle GraalVM
- Platforms: Java 17, JVM
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-114938, T1190, OpenJDK, Oracle Java SE, Oracle GraalVM, Java 17, JVM, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 30m;
let suspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "sh", "bash", "dash", "python", "python3", "perl", "ruby", "wget", "curl", "nc", "ncat", "whoami", "id", "uname"]);
let javaSpawns = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe", "java")
| where FileName in~ (suspiciousChildren)
| project SpawnTime = Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, InitiatingProcessId;
let inboundConns = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where not(ipv4_is_private(RemoteIP)) and RemoteIP != "127.0.0.1"
| project ConnTime = Timestamp, DeviceId, RemoteIP, RemotePort;
javaSpawns
| join kind=inner inboundConns on DeviceId
| where SpawnTime between (ConnTime .. (ConnTime + 5m))
| summarize
    ConnTime = min(ConnTime),
    RemoteIPs = make_set(RemoteIP, 10),
    RemotePorts = make_set(RemotePort, 10)
    by SpawnTime, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| project SpawnTime, ConnTime, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIPs, RemotePorts
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Java application servers that legitimately spawn shell scripts as part of application logic (e.g., Tomcat running shell-based health checks).
- Build or CI agents running on Java that invoke shell commands as part of pipeline steps.
- Monitoring agents that use curl or wget and are launched by Java-based orchestration tools.

**Tuning notes:**
- Expand or restrict the suspiciousChildren list based on the specific Java application stack deployed in the environment.
- Adjust the 5-minute correlation window between inbound connection and child process spawn based on observed application latency patterns.
- Consider adding a DeviceName or DeviceId allowlist to scope the query to known internet-facing Java hosts only.

**Risks / caveats:**
- ActionType value 'InboundConnectionAccepted' must be confirmed as available in the target environment's DeviceNetworkEvents telemetry; some MDE sensor configurations on Linux do not populate inbound connection events.
- On Linux hosts, InitiatingProcessFileName for JVM processes may be 'java' without the .exe extension; the query handles this but Linux MDE sensor coverage must be confirmed.
- The 5-minute correlation window may link unrelated inbound connections to a child process spawn on busy Java application servers; consider tightening to 2 minutes after baselining.
- ipv4_is_private() does not handle IPv6 private ranges; if the environment uses IPv6 for inbound connections, additional filtering is needed.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is actually internet-facing and running a vulnerable Java 17/OpenJDK/Oracle Java SE/GraalVM service at the alert time.
- Review the parent Java command line and child process command line to determine whether the child is a known application helper or an attacker-style shell/interpreter.
- Check whether the child process launched shortly after an inbound external connection and whether the source IP is unfamiliar or associated with scanning.
- Look for immediate follow-on behavior from the same host such as outbound connections, new processes, or suspicious file writes.

**Evidence to collect:**
- DeviceName, DeviceId, SpawnTime, ConnTime, RemoteIPs, RemotePorts
- InitiatingProcessFileName and InitiatingProcessCommandLine for the Java process
- FileName and ProcessCommandLine for the spawned child process
- Any nearby DeviceNetworkEvents showing outbound connections from the same host
- Any additional DeviceProcessEvents showing a process tree beyond the initial child

**Pivot points:**
- DeviceProcessEvents for the same DeviceId around the alert window to reconstruct the full process tree
- DeviceNetworkEvents for the same DeviceId to identify inbound source IPs and any outbound callback traffic
- DeviceFileEvents for the same DeviceId to check for web shell drops, script changes, or staging activity
- If available, host telemetry or application logs for the Java service to identify the request that preceded execution

**Benign explanations:**
- A legitimate Java application server may spawn shell scripts for health checks, maintenance, or application startup tasks.
- Build, CI, or automation agents running on Java may invoke interpreters or command-line utilities as part of normal workflows.
- Monitoring or orchestration tools launched by Java may use curl, wget, or similar utilities for routine operations.

**Escalation criteria:**
- The child process is a shell, scripting interpreter, or recon utility not normally used by the application.
- The Java process was exposed to the internet and the child spawn closely follows an external inbound connection.
- There is evidence of outbound callback traffic, credential access, file modification, or additional suspicious child processes.
- The Java command line or service context suggests a vulnerable public-facing application rather than a controlled admin action.

**Containment actions:**
- If exploitation is plausible, isolate the host from the network while preserving evidence.
- Block or restrict the external source IP if it is clearly malicious and not a shared service or scanner.
- Suspend the affected Java service only if business impact is acceptable and the host cannot be safely monitored in place.
- Preserve process, network, and application logs before rebooting or making major changes.

**Closure criteria:**
- The child process is confirmed as a documented and expected Java application action.
- No suspicious outbound activity, file changes, or additional process execution is found on the host.
- The inbound connection is attributable to approved testing, monitoring, or a known benign source.
- The Java service is patched or otherwise not vulnerable, and the alert matches a known benign pattern after review.

<br/>
---
<br/>

## Detection 2: CVE-2026-123007 - Shell or Interpreter Spawned by nginx Worker Process After HTTP/2 Request Burst

### Detection Opportunity

nginx worker process spawns a shell or interpreter following exploitation of the HTTP/2 integer underflow vulnerability, indicating post-exploitation code execution

### Intelligence Context

- Rapid7: CVE-2026-123007: Critical NGINX HTTP/2 Integer Underflow Leads to RCE (FIXED) — [https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed)
  - Context: Rapid7 reported that a remote unauthenticated client can exploit an integer underflow in nginx HTTP/2 handling by cancelling queued response data, causing memory corruption in the nginx worker process. Successful exploitation can result in code execution with nginx worker permissions, which would manifest as unexpected child processes such as shells or interpreters spawned from the nginx worker.

### Search Metadata

- CVEs: CVE-2026-123007
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071
- Products: nginx, HTTP/2
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123007, T1190, nginx, HTTP/2, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 30m;
let suspiciousChildren = dynamic(["sh", "bash", "dash", "python", "python3", "perl", "ruby", "wget", "curl", "nc", "ncat", "whoami", "id", "uname", "cmd.exe", "powershell.exe"]);
let nginxSpawns = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName has "nginx"
| where FileName in~ (suspiciousChildren)
| project SpawnTime = Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine;
let inboundHTTP2 = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "InboundConnectionAccepted"
| where RemotePort in (80, 443)
| where not(ipv4_is_private(RemoteIP)) and RemoteIP != "127.0.0.1"
| project ConnTime = Timestamp, DeviceId, RemoteIP, RemotePort;
nginxSpawns
| join kind=inner inboundHTTP2 on DeviceId
| where SpawnTime between (ConnTime .. (ConnTime + 5m))
| summarize
    ConnTime = min(ConnTime),
    RemoteIPs = make_set(RemoteIP, 10),
    RemotePorts = make_set(RemotePort, 10)
    by SpawnTime, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| project SpawnTime, ConnTime, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIPs, RemotePorts
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- nginx configurations that use FastCGI or CGI wrappers may legitimately spawn shell or interpreter processes.
- Monitoring or health-check scripts invoked via nginx exec modules.
- Environments where nginx is used as a reverse proxy and upstream health checks invoke shell utilities.

**Tuning notes:**
- Add non-standard HTTP/2 listener ports to the RemotePort filter if nginx is configured on ports other than 80 and 443.
- Narrow the InitiatingProcessFileName filter to the exact nginx binary name if multiple nginx variants exist in the environment.
- Baseline legitimate nginx child processes before scheduling to refine the suspiciousChildren list.

**Risks / caveats:**
- ActionType value 'InboundConnectionAccepted' availability on Linux MDE sensors must be confirmed; some sensor configurations do not emit inbound connection events.
- InitiatingProcessFileName for nginx worker processes on Linux may be reported as 'nginx: worker process' or the full binary path depending on MDE sensor version; the has 'nginx' filter handles this but should be validated.
- The has 'nginx' filter on InitiatingProcessFileName will match any process whose name contains the string 'nginx'; validate that no unrelated processes match in the environment.
- The 5-minute correlation window may link unrelated inbound connections to child process spawns on high-traffic nginx hosts; consider tightening after baselining.

### Triage Runbook

**First 15 minutes:**
- Confirm the nginx host is internet-facing and serving HTTP/2 traffic on the affected listener.
- Review the nginx worker parent process and spawned child process to determine whether the child is a legitimate helper or an attacker-style shell/interpreter.
- Check the timing of the child spawn against inbound HTTP/2 traffic and look for a burst of requests or unusual client behavior.
- Look for immediate signs of post-exploitation activity such as outbound connections, new processes, or file changes on the same host.

**Evidence to collect:**
- DeviceName, DeviceId, SpawnTime, ConnTime, RemoteIPs, RemotePorts
- InitiatingProcessFileName and InitiatingProcessCommandLine for the nginx worker
- FileName and ProcessCommandLine for the spawned child process
- Any DeviceNetworkEvents showing inbound HTTP/2 traffic and subsequent outbound connections
- Any DeviceProcessEvents showing additional child processes from the same nginx worker

**Pivot points:**
- DeviceProcessEvents for the same DeviceId to reconstruct the nginx process tree
- DeviceNetworkEvents for inbound and outbound activity around the alert window
- DeviceFileEvents for the same host to check for dropped scripts or modified web content
- Host or application logs for nginx error messages, worker restarts, or request anomalies

**Benign explanations:**
- Some nginx deployments legitimately spawn helper scripts or interpreters for FastCGI, CGI, or custom integration logic.
- Health-check, maintenance, or monitoring scripts may be invoked by nginx in certain environments.
- Reverse proxy or application gateway configurations may use shell utilities as part of normal operational workflows.

**Escalation criteria:**
- The child process is a shell, scripting interpreter, or recon utility not normally used by nginx.
- The child spawn is tightly correlated with suspicious external HTTP/2 traffic and is not explained by known application behavior.
- There is evidence of outbound callback traffic, web root modification, or additional suspicious execution on the host.
- The nginx worker command line or service context indicates a public-facing service with no approved reason to spawn the child process.

**Containment actions:**
- If exploitation is plausible, isolate the host or remove it from the load balancer while preserving evidence.
- Block the malicious source IP or temporarily restrict access to the affected listener if operationally feasible.
- Restart or recycle nginx only after evidence collection if the service is unstable and containment is required.
- Preserve logs from nginx, the host, and any upstream WAF or firewall before remediation.

**Closure criteria:**
- The spawned process is confirmed as a documented nginx helper or application workflow.
- No suspicious outbound traffic, file modification, or additional process activity is found.
- The inbound HTTP/2 traffic is attributable to approved testing, monitoring, or a known benign client.
- The host is patched or otherwise not vulnerable, and the alert matches a known benign operational pattern.

<br/>
---
<br/>

## Detection 3: CVE-2026-123007 - nginx Error Log Memory Corruption Events Correlated with External Source IPs

### Detection Opportunity

nginx worker process logs memory corruption or invalid length errors in Syslog following HTTP/2 RST_STREAM abuse from an external client

### Intelligence Context

- Rapid7: CVE-2026-123007: Critical NGINX HTTP/2 Integer Underflow Leads to RCE (FIXED) — [https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed)
  - Context: Rapid7 described that the exploit mechanism involves a client cancelling queued HTTP/2 response data, causing nginx to use an invalid length value leading to memory corruption. This would produce error log entries in nginx reflecting invalid memory operations, which are forwarded to Syslog in Linux environments and can be correlated with the external source IP that triggered the condition.

### Search Metadata

- CVEs: CVE-2026-123007
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071
- Products: nginx, HTTP/2
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123007, T1190, nginx, HTTP/2, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Syslog ProcessName field population depends on the rsyslog or syslog-ng forwarding configuration on the nginx host; if ProcessName is not populated, the nginx filter will not match.

**Required telemetry:**
- Syslog, CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let nginxErrors = Syslog
| where TimeGenerated > ago(lookback)
| where ProcessName has "nginx"
| where SyslogMessage has_any ("invalid length", "memory corruption", "segfault", "heap", "use after free", "invalid pointer", "worker process exited")
| project ErrorTime = TimeGenerated, Computer, SyslogMessage;
let externalConns = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where DestinationPort in (80, 443)
| where not(ipv4_is_private(SourceIP)) and SourceIP != "127.0.0.1"
| project ConnTime = TimeGenerated, DeviceAddress, SourceIP, DestinationPort;
nginxErrors
| join kind=inner (externalConns) on $left.Computer == $right.DeviceAddress
| where ErrorTime between (ConnTime .. (ConnTime + 2m))
| project ErrorTime, ConnTime, Computer, SyslogMessage, SourceIP, DestinationPort
| order by ErrorTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate nginx worker crashes from non-exploit causes (OOM, misconfiguration) will produce matching Syslog entries.
- Security scanners from external IPs performing HTTP/2 probing may coincide with unrelated nginx errors.
- High-traffic nginx hosts may produce frequent worker process exit messages unrelated to exploitation.

**Tuning notes:**
- Extend the 2-minute correlation window if network log timestamps lag behind Syslog timestamps in the environment.
- Add additional nginx error message patterns specific to the deployed nginx version if memory corruption manifests with different log text.
- Confirm that CommonSecurityLog DeviceAddress values match the Computer field in Syslog for the nginx hosts in scope before scheduling.

**Risks / caveats:**
- CommonSecurityLog requires a CEF-compatible connector (WAF, firewall, or network device) to be configured and ingesting data into the Sentinel workspace; this table may not exist or may be empty without that connector.
- The join on Syslog.Computer == CommonSecurityLog.DeviceAddress will produce no results if the nginx host hostname in Syslog does not match the DeviceAddress value emitted by the network device in CommonSecurityLog; this field alignment is environment-specific.
- Syslog ProcessName field population depends on the rsyslog or syslog-ng forwarding configuration on the nginx host; if ProcessName is not populated, the nginx filter will not match.
- The 2-minute correlation window may be too tight if network device log timestamps lag behind Syslog timestamps; extend to 5 minutes if misses are observed.

### Triage Runbook

**First 15 minutes:**
- Review the exact Syslog message to confirm it reflects memory corruption, invalid length, segfault, or worker exit behavior rather than a generic nginx error.
- Confirm the nginx host is the same system referenced by the network device log and that the external source IP is not a known scanner or approved tester.
- Check whether the error occurred during or immediately after inbound HTTP/2 traffic to the affected port.
- Look for signs of service instability, worker restarts, crashes, or follow-on suspicious activity on the host.

**Evidence to collect:**
- ErrorTime, ConnTime, Computer, SyslogMessage, SourceIP, DestinationPort
- Additional nginx Syslog entries before and after the alert window
- Any related CommonSecurityLog entries showing the same source IP and destination port pattern
- Host telemetry showing process restarts, crashes, or new child processes on the nginx host
- Any outbound connections or file changes from the same host after the error

**Pivot points:**
- Syslog for the same Computer to gather surrounding nginx error and restart messages
- CommonSecurityLog for the same SourceIP and destination port to understand the request pattern
- DeviceNetworkEvents or equivalent host telemetry if available to validate follow-on outbound activity
- DeviceProcessEvents or host process logs to check for worker crashes or unexpected child processes

**Benign explanations:**
- nginx can emit similar errors from non-exploit causes such as misconfiguration, resource exhaustion, or routine worker failures.
- External security scanners may trigger error conditions without successful exploitation.
- High-traffic or unstable nginx deployments may produce worker exit or memory-related messages unrelated to an attack.

**Escalation criteria:**
- The error text strongly indicates memory corruption or invalid length behavior and aligns with suspicious external HTTP/2 traffic.
- There are repeated errors, worker crashes, or service instability tied to the same source IP or request pattern.
- The host shows additional signs of compromise such as outbound connections, new processes, or web content changes.
- The source IP is clearly malicious or part of a broader attack campaign against the environment.

**Containment actions:**
- If exploitation is plausible, isolate the host or remove it from service while preserving logs and crash evidence.
- Block the source IP at the firewall or WAF if it is confirmed malicious and not a shared service.
- Fail over traffic to a clean instance if available and operationally appropriate.
- Preserve nginx, Syslog, and network device logs before restarting services or applying fixes.

**Closure criteria:**
- The error is explained by a known benign condition such as misconfiguration, resource exhaustion, or a documented crash cause.
- No corroborating evidence of exploitation, outbound callback traffic, or suspicious process activity is found.
- The source IP is confirmed as approved testing, monitoring, or a benign scanner.
- The host is patched or otherwise not vulnerable, and the log pattern is consistent with normal operational noise.

<br/>
---
<br/>

## Detection 4: CVE-2026-123007 - Anomalous Outbound Connection from nginx Worker Process After Inbound HTTP/2 Traffic

### Detection Opportunity

nginx worker process initiates unexpected outbound network connection following exploitation, indicating post-exploitation callback or data exfiltration

### Intelligence Context

- Rapid7: CVE-2026-123007: Critical NGINX HTTP/2 Integer Underflow Leads to RCE (FIXED) — [https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed)
  - Context: Rapid7 reported that successful exploitation of CVE-2026-123007 allows code execution with nginx worker process permissions. Post-exploitation activity would include the nginx worker initiating outbound connections to attacker-controlled infrastructure, which is anomalous since nginx workers do not typically initiate outbound connections to arbitrary external IPs.

### Search Metadata

- CVEs: CVE-2026-123007
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071
- Products: nginx, HTTP/2
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123007, T1190, nginx, HTTP/2, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName has "nginx"
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where not(ipv4_is_private(RemoteIP)) and RemoteIP != "127.0.0.1"
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, RemoteIP, RemotePort, LocalPort, ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- nginx configured as a reverse proxy with external upstream backends (CDN, SaaS APIs) will generate matches; known upstream IP ranges should be added to an exclusion list.
- nginx health-check or OCSP stapling connections to external certificate authorities.
- nginx modules that perform outbound HTTP requests as part of application logic (e.g., auth_request to external IdP).

**Tuning notes:**
- Add known legitimate nginx upstream proxy, CDN, or external API IP ranges to an exclusion list using a let statement to reduce false positives from reverse proxy configurations.
- Restrict the query to specific high-value nginx hosts using a DeviceName or DeviceId filter if the rule generates noise across a large fleet.
- Consider adding a RemotePort exclusion for well-known upstream ports (80, 443) only after confirming that post-exploitation callbacks in the environment use non-standard ports; otherwise keep all ports in scope.

**Risks / caveats:**
- InitiatingProcessFileName population for nginx worker processes on Linux MDE sensors must be confirmed; some sensor versions may not populate this field for non-PE processes.
- The has 'nginx' filter on InitiatingProcessFileName will match any process whose name contains the string 'nginx'; validate that no unrelated processes match in the environment.
- ipv4_is_private() does not handle IPv6 addresses; if RemoteIP contains IPv6 values, additional filtering is needed.
- nginx reverse proxy configurations with external upstream backends will generate false positives until known upstream IP ranges are added to an exclusion list.

### Triage Runbook

**First 15 minutes:**
- Confirm the outbound destination is not a known upstream backend, CDN, OCSP, or approved external service used by nginx.
- Review the nginx worker command line and process ID to understand which listener or service instance generated the connection.
- Check whether the outbound connection followed suspicious inbound HTTP/2 traffic or other signs of exploitation on the same host.
- Look for additional suspicious activity from the host, including new processes, file changes, or repeated outbound connections.

**Evidence to collect:**
- Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId
- RemoteIP, RemotePort, LocalPort, ActionType for the outbound connection
- Any nearby inbound connection events to the same host and listener
- Any DeviceProcessEvents showing child processes or process tree anomalies
- Any DeviceFileEvents showing web root changes or dropped artifacts

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId to identify all outbound destinations and timing
- DeviceProcessEvents for the same DeviceId to check for shells, interpreters, or recon tools spawned by nginx
- DeviceFileEvents for the same host to look for web shell placement or tampering
- If available, WAF or firewall logs to correlate the outbound event with the inbound HTTP/2 request pattern

**Benign explanations:**
- nginx reverse proxy deployments may legitimately connect to external upstreams, SaaS APIs, or CDN services.
- OCSP stapling, certificate validation, or health-check logic can create outbound traffic from nginx-related processes.
- Some application architectures use nginx modules or scripts that make outbound requests as part of normal operation.

**Escalation criteria:**
- The destination IP is not a documented upstream or approved external dependency.
- The outbound connection is followed by suspicious child processes, file modifications, or repeated callback behavior.
- The connection occurs after suspicious inbound HTTP/2 traffic and there is no operational explanation.
- The host shows multiple indicators of compromise or the same pattern appears across several nginx servers.

**Containment actions:**
- If the destination is suspicious and exploitation is plausible, isolate the host or remove it from service.
- Block the destination IP or domain if it is confirmed malicious and not a legitimate dependency.
- If needed, disable the affected nginx instance or route traffic away from it while preserving evidence.
- Capture process, network, and web logs before restarting or rebuilding the host.

**Closure criteria:**
- The outbound destination is confirmed as a legitimate upstream, CDN, or approved external dependency.
- No suspicious process tree, file modification, or additional malicious network activity is found.
- The inbound traffic pattern is explained by normal application behavior or approved testing.
- The host is patched or otherwise not vulnerable, and the connection matches a documented benign workflow.

<br/>
---
<br/>

## Detection 5: OPTIMJACK - Unexpected Script File Modification in Web Root by Non-Deployment Process

### Detection Opportunity

Compromised vendor script or supply chain modification alters web root script files via a process outside known deployment tooling

### Intelligence Context

- Unit 42: Borrowed Code, Real Consequences: What OPTIMJACK Teaches Us — [https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/](https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/)
  - Context: Unit 42 reported that the OPTIMJACK supply chain attack involved a compromised vendor script that exposed websites. The attack relied on trusted web assets being altered unexpectedly, highlighting the need for strict segmentation and monitoring of web root file modifications by processes outside normal deployment pipelines.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1505.003, T1036, T1505
- Products: vendor scripts
- Platforms: websites
- Malware: Not specified
- Tools: Not specified
- Search tags: vendor scripts, websites, T1505.003, T1036, T1505

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: watchlist
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (medium); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let webRootPaths = dynamic(["/var/www", "/usr/share/nginx", "/srv/www", "\\inetpub\\wwwroot", "\\wwwroot"]);
let knownDeployProcs = dynamic(["git", "npm", "yarn", "rsync", "deploy", "ansible", "chef", "puppet", "terraform"]);
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".js" or FileName endswith ".html" or FileName endswith ".php" or FileName endswith ".htm"
| where FolderPath has_any (webRootPaths)
| where not(InitiatingProcessFileName has_any (knownDeployProcs))
| project Timestamp, DeviceName, DeviceId, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Any deployment process not included in the knownDeployProcs list will generate false positives until the list is fully baselined.
- Web application frameworks that self-update or write compiled assets to the web root at runtime.
- CMS platforms (WordPress, Drupal) that write plugin or theme files to the web root as part of normal operation.
- Backup or archival processes that copy web root files.

**Tuning notes:**
- Extend the webRootPaths list to include environment-specific web root directories not covered by the defaults.
- Add additional deployment tool process names to knownDeployProcs to reduce false positives from legitimate CI/CD pipelines.
- Consider adding a time-of-day filter to flag modifications outside business hours as a higher-confidence signal after baselining normal deployment windows.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileCreated' and 'FileModified' must be confirmed as available in the MDE sensor version deployed; some sensor configurations report file events with different ActionType labels.
- FolderPath population for Linux file events in DeviceFileEvents depends on MDE Linux sensor coverage; confirm that file write events in web root directories are captured on the target Linux hosts.
- The webRootPaths list must be extended with environment-specific web root directories before the query will detect modifications in non-standard paths.
- The knownDeployProcs list must be validated against the actual deployment toolchain to avoid both false positives from unlisted legitimate processes and false negatives from attacker processes that mimic deployment tool names.

### Triage Runbook

**First 15 minutes:**
- Confirm the modified file is in a real web root and identify whether the change was expected from a deployment or maintenance activity.
- Review the initiating process name, command line, and hash to determine whether it belongs to approved deployment tooling.
- Inspect the file contents or version history to see whether the change introduces suspicious code, redirects, obfuscation, or external references.
- Check whether the same host shows other file changes, suspicious process activity, or signs of web compromise.

**Evidence to collect:**
- Timestamp, DeviceName, DeviceId, FolderPath, FileName, ActionType
- InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
- File version history or backup copy of the modified script
- Any related DeviceProcessEvents from the same host around the modification time
- Any web server access logs showing requests to the modified file before or after the change

**Pivot points:**
- DeviceFileEvents for the same DeviceId to find other file changes in the web root
- DeviceProcessEvents to identify the parent process and any related deployment or scripting activity
- Web server access logs to determine whether the modified file was accessed or executed
- If available, source control or CI/CD logs to verify whether the change came from an approved pipeline

**Benign explanations:**
- A legitimate deployment process not included in the allowlist may have modified the file.
- CMS platforms or web frameworks may update plugin, theme, or generated assets in the web root during normal operation.
- Backup, restore, or archival jobs may copy files into the web root as part of maintenance.

**Escalation criteria:**
- The modifying process is not an approved deployment tool and has no clear business justification.
- The file contents show suspicious code, obfuscation, web shell behavior, or unauthorized redirects.
- There are multiple unexpected file changes in the web root or evidence of broader compromise on the host.
- The modification occurred outside normal deployment windows and cannot be explained by a change record.

**Containment actions:**
- If malicious modification is plausible, isolate the host or remove it from service to prevent further web exposure.
- Restore the affected file from a known-good source after preserving the malicious version for analysis.
- Disable or block the process or account responsible if it is confirmed unauthorized and still active.
- Preserve file hashes, timestamps, and web logs before remediation.

**Closure criteria:**
- The modification is confirmed as part of an approved deployment or maintenance workflow.
- The file contents are verified as benign and match a known-good version or change record.
- No additional suspicious file changes, process activity, or web compromise indicators are found.
- The deployment tooling is added to the allowlist or watchlist is updated to reflect the approved process.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- CVE-2026-114938 - Unexpected Child Process Spawned by Java Process on Internet-Facing Host: Do not schedule yet; validate as an analyst-led hunt first.
- CVE-2026-123007 - Shell or Interpreter Spawned by nginx Worker Process After HTTP/2 Request Burst: Do not schedule yet; validate as an analyst-led hunt first.

**Environment scope / baselines:**
- CVE-2026-123007 - nginx Error Log Memory Corruption Events Correlated with External Source IPs: Syslog ProcessName field population depends on the rsyslog or syslog-ng forwarding configuration on the nginx host; if ProcessName is not populated, the nginx filter will not match.

**Other deployment dependency:**
- OPTIMJACK - Unexpected Script File Modification in Web Root by Non-Deployment Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceProcessEvents: shared by CVE-2026-114938 - Unexpected Child Process Spawned by Java Process on Internet-Facing Host; CVE-2026-123007 - Shell or Interpreter Spawned by nginx Worker Process After HTTP/2 Request Burst
- DeviceNetworkEvents: shared by CVE-2026-114938 - Unexpected Child Process Spawned by Java Process on Internet-Facing Host; CVE-2026-123007 - Shell or Interpreter Spawned by nginx Worker Process After HTTP/2 Request Burst; CVE-2026-123007 - Anomalous Outbound Connection from nginx Worker Process After Inbound HTTP/2 Traffic

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: CVE-2026-123007 - Anomalous Outbound Connection from nginx Worker Process After Inbound HTTP/2 Traffic.
2. Resolve environment-mapping detections next: CVE-2026-123007 - nginx Error Log Memory Corruption Events Correlated with External Source IPs; OPTIMJACK - Unexpected Script File Modification in Web Root by Non-Deployment Process.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: CVE-2026-114938 - Unexpected Child Process Spawned by Java Process on Internet-Facing Host; CVE-2026-123007 - Shell or Interpreter Spawned by nginx Worker Process After HTTP/2 Request Burst.

### Hunting Agenda and Promotion Criteria

- CVE-2026-114938 - Unexpected Child Process Spawned by Java Process on Internet-Facing Host: Do not schedule yet; validate as an analyst-led hunt first..
- CVE-2026-123007 - Shell or Interpreter Spawned by nginx Worker Process After HTTP/2 Request Burst: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-123007 - nginx Error Log Memory Corruption Events Correlated with External Source IPs: Syslog ProcessName field population depends on the rsyslog or syslog-ng forwarding configuration on the nginx host; if ProcessName is not populated, the nginx filter will not match.; prove correlation keys join correctly on real tenant telemetry.
- OPTIMJACK - Unexpected Script File Modification in Web Root by Non-Deployment Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
