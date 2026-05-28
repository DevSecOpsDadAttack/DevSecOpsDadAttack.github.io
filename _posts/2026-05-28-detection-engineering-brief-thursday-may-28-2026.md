---
layout: post
title: "Detection Engineering Brief - Thursday, May 28, 2026"
subtitle: "Machine-speed threat intelligence translated into detection engineering action."
date: 2026-05-28
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - MITRE ATT&CK
  - Gogs
  - Linux
  - Storm-2697
  - Windows
  - The Gentlemen
  - Akira
  - T1059
  - T1059.004
  - T1021
  - T1021.002
  - T1016
  - T1082
  - T1490
---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Gogs, Linux, Storm-2697, Windows, The Gentlemen, Akira, T1059, T1059.004, T1021, T1021.002, T1016, T1082, T1490.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Gogs Git Rebase Argument Injection via --exec Flag; Unexpected Child Process Spawned by Gogs Service Following Git Rebase; Gentlemen Ransomware Lateral Movement: Concurrent Remote Logons from Single Account to Multiple Hosts; Akira Pre-Encryption Activity: Perimeter Allow Followed by Internal Reconnaissance and Shadow Copy Deletion.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Gogs Git Rebase Argument Injection via --exec Flag

### Detection Opportunity

Branch name injects the --exec flag into git rebase during merge, enabling RCE on the Gogs server.

### Intelligence Context

- Rapid7: Authenticated RCE via Argument Injection in Gogs (NOT FIXED) — [https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed)
  - Context: An authenticated Gogs user crafts a malicious branch name that injects the --exec flag into a git rebase command executed server-side during a 'Rebase before merging' merge operation, achieving RCE on the Gogs host.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004
- Products: Gogs
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: Gogs, Linux, T1059, T1059.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where FileName =~ "git" or FileName endswith "/git"
| where ProcessCommandLine has_all ("rebase", "--exec")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer workstations performing interactive git rebase --exec operations.
- CI/CD pipeline agents using git rebase --exec for automated testing hooks.

Tuning notes:
- Add '| where DeviceName in~ ("<gogs-host-1>", "<gogs-host-2>")' after the FileName filter once Gogs server hostnames are known.
- Add '| where AccountName =~ "<gogs-service-account>"' to restrict to the Gogs service identity once confirmed.
- Consider extending the projection with InitiatingProcessParentFileName if deeper process ancestry is available.

Risks / caveats:
- DeviceProcessEvents is only available when Microsoft Defender for Endpoint is deployed on the Linux host running Gogs. If MDE Linux coverage is absent, this query returns no results.
- ProcessCommandLine capture fidelity on Linux depends on MDE agent version; argument injection via branch names may appear as a single concatenated string that does not always preserve --exec as a discrete token.
- Without scoping DeviceName to known Gogs server hostnames, developer workstations will generate significant noise.
- The --exec token may be embedded within a quoted branch name string rather than appearing as a standalone argument, depending on how the Gogs process constructs the git command line.

### Triage Runbook

First 15 minutes:
- Confirm the alerting host is a Gogs server and not a developer workstation or CI runner.
- Review InitiatingProcessFileName, InitiatingProcessCommandLine, and InitiatingProcessAccountName to verify the process chain is consistent with the Gogs service.
- Inspect ProcessCommandLine for evidence that --exec was injected through a branch name or other unexpected argument content.
- Check whether the event time aligns with a user-initiated merge/rebase action in Gogs audit or application logs.

Evidence to collect:
- DeviceName, AccountName, InitiatingProcessAccountName, and full ProcessCommandLine from the alerting event.
- Any Gogs application logs, access logs, or audit records covering the same timestamp and repository.
- Parent and child process details around the git invocation, including any shell spawned immediately after the rebase.
- Recent repository branch names or merge requests associated with the affected user or repository.

Pivot points:
- DeviceProcessEvents for the same DeviceName and a narrow time window around the alert to find related git, shell, curl, wget, python, or perl activity.
- DeviceProcessEvents filtered to the Gogs service account or Gogs host to identify repeated git rebase --exec executions.
- Gogs server logs or Linux auth logs to confirm the user session and service context.
- If available, file and network telemetry from the same host to look for post-exploitation activity after the git command.

Benign explanations:
- A developer workstation or CI job legitimately using git rebase --exec for testing or workflow automation.
- A Gogs repository hook or maintenance script that intentionally invokes git rebase with exec behavior.
- A non-Gogs Linux host where a developer manually ran the command for local development.

Escalation criteria:
- The event occurred on a confirmed Gogs server and the initiating context is the Gogs service account or daemon.
- The command line contains suspicious branch-name content or an unexpected shell is spawned immediately after the rebase.
- There is any evidence of follow-on activity such as file creation, outbound connections, or additional command execution on the host.

Containment actions:
- If confirmed on a production Gogs server, isolate the host from the network to prevent further command execution and data access.
- Disable or suspend the affected Gogs account and revoke active sessions if the malicious user identity is known.
- Preserve volatile evidence before rebooting or reimaging, including process tree, open network connections, and relevant logs.

Closure criteria:
- The host is verified as a non-Gogs system or a known-good developer/CI workflow.
- Gogs logs confirm the command was generated by an approved repository hook or maintenance task.
- No suspicious child processes, network activity, or file changes are found after review of the surrounding telemetry.

---

## Detection 2: Unexpected Child Process Spawned by Gogs Service Following Git Rebase

### Detection Opportunity

Remote code execution on the Gogs server manifests as unexpected processes spawned by the Gogs service process after argument injection via git rebase.

### Intelligence Context

- Rapid7: Authenticated RCE via Argument Injection in Gogs (NOT FIXED) — [https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed)
  - Context: Successful exploitation of the Gogs argument injection vulnerability results in arbitrary command execution on the server. This surfaces as shell interpreters, curl, wget, or other unexpected binaries spawned as children of the Gogs process.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004
- Products: Gogs
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: Gogs, Linux, T1059, T1059.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName has_any ("gogs", "gogs-server")
| where FileName in~ ("bash", "sh", "dash", "zsh", "curl", "wget", "python", "python3", "perl", "ruby", "php", "awk", "nc", "ncat", "netcat")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate Gogs repository hooks that invoke shell scripts or scripting runtimes as part of configured CI/CD workflows.
- Gogs administrative maintenance scripts that use curl or wget for update checks.

Tuning notes:
- Scope DeviceName to known Gogs server hostnames once confirmed to avoid matching unrelated Linux hosts.
- Exclude ProcessCommandLine values matching known legitimate hook patterns specific to the environment.
- Consider chaining this query with the git rebase --exec detection using a time-windowed join on DeviceName to create a higher-confidence compound signal.

Risks / caveats:
- DeviceProcessEvents is only available when Microsoft Defender for Endpoint is deployed on the Linux host running Gogs. If MDE Linux coverage is absent, this query returns no results.
- InitiatingProcessFileName on Linux reflects only the binary filename without path; if the Gogs binary is renamed or installed under a non-standard name, the filter will not match.
- Gogs repository hooks that legitimately invoke shell interpreters will match; a baseline of known-good hook invocations should be established before scheduling.
- If the Gogs binary is renamed or deployed under a path-qualified name that MDE reports differently, the InitiatingProcessFileName filter will not match.

### Triage Runbook

First 15 minutes:
- Verify the parent process is the Gogs service or a renamed Gogs binary on a Linux host running Gogs.
- Review the child process name and command line to decide whether it is expected for repository hooks or clearly post-exploitation behavior.
- Check whether the child process is a shell, downloader, scripting runtime, or network utility such as bash, sh, curl, wget, python, perl, ruby, or php.
- Look for a preceding git rebase --exec event on the same host and timestamp to strengthen the exploitation chain.

Evidence to collect:
- Full process tree for the alerting event, including parent, child, and any grandchild processes.
- ProcessCommandLine and InitiatingProcessCommandLine for both the Gogs process and the spawned child.
- Gogs application logs and Linux auth logs around the same time window.
- Any file creation, outbound network connections, or privilege changes associated with the spawned child process.

Pivot points:
- DeviceProcessEvents on the same DeviceName for the preceding and following 30 minutes to identify additional spawned processes.
- DeviceNetworkEvents from the same host to identify downloads, callbacks, or lateral movement after the child process started.
- DeviceFileEvents if available to look for dropped scripts, binaries, or modified repository content.
- Gogs logs to correlate the child process with a specific repository action or user session.

Benign explanations:
- A legitimate Gogs repository hook that intentionally runs shell scripts or automation tooling.
- Administrative maintenance scripts that use curl or wget for updates or health checks.
- A known CI/CD integration that executes scripting runtimes as part of repository workflows.

Escalation criteria:
- The child process is a shell, downloader, or scripting runtime not documented as part of the Gogs deployment.
- The child process initiates outbound network connections, writes files, or spawns additional suspicious processes.
- The event is correlated with the git rebase --exec detection or other evidence of malicious repository manipulation.

Containment actions:
- Isolate the Gogs host if the child process is clearly unauthorized or shows active post-exploitation behavior.
- Stop the Gogs service only if needed to prevent further execution and after preserving evidence.
- Block any observed malicious outbound destinations if the child process is attempting to retrieve payloads or beacon.

Closure criteria:
- The child process is confirmed as an approved hook, maintenance task, or documented automation.
- No additional suspicious processes, file changes, or network activity are observed on the host.
- The Gogs service account and process lineage match the expected deployment pattern.

---

## Detection 3: Gentlemen Ransomware Self-Propagation: Rapid Fan-Out SMB Connections from Single Host

### Detection Opportunity

Self-propagation module deploys malware across the network via rapid sequential outbound connections from a single infected host to multiple internal targets.

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware, attributed to Storm-2697, includes an aggressive self-propagation module that deploys itself across an entire network using simultaneous lateral movement techniques, generating rapid fan-out network connections from a single compromised host to many internal peers.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1021, T1021.002
- Products: Not specified
- Platforms: Windows
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, Windows, The Gentlemen, T1021, T1021.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemotePort in (445, 135, 139)
| where ipv4_is_private(RemoteIP)
| summarize
    DistinctTargets = dcount(RemoteIP),
    Targets = make_set(RemoteIP, 50)
    by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 5m)
| where DistinctTargets > 10
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    DistinctTargets,
    Targets
| order by DistinctTargets desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- SCCM or WSUS distribution points pushing updates to many endpoints simultaneously.
- Enterprise backup agents performing parallel SMB-based backup jobs.
- Network scanning or asset inventory tools run by IT operations.

Tuning notes:
- Adjust DistinctTargets threshold from 10 based on observed legitimate administrative fan-out volume in the environment.
- Add '| where AccountName !in~ ("sccm-service", "backup-agent")' with environment-specific service account names to reduce false positives.
- Consider adding InitiatingProcessSHA256 to the projection if available to enable hash-based threat intelligence lookups on the propagating binary.

Risks / caveats:
- ActionType value 'ConnectionSuccess' must be present in the DeviceNetworkEvents data for the monitored Windows endpoints; environments where only 'ConnectionAttempt' is logged will return no results.
- RemoteIP regex matching in KQL uses matches regex which is case-sensitive and computationally expensive at scale; confirm the operator is supported in the target workspace tier.
- The threshold of 10 distinct internal SMB targets within 5 minutes may fire on legitimate administrative tools in environments with large-scale patch or backup operations; baseline against 30 days of historical data before setting the alert threshold.
- ipv4_is_private() does not cover all non-routable ranges such as 100.64.0.0/10 (CGNAT); if the environment uses CGNAT internally, supplement with an additional filter.

### Triage Runbook

First 15 minutes:
- Identify the source host and initiating process responsible for the SMB fan-out.
- Check whether the process is a known management, backup, patching, or inventory tool.
- Review the list of target hosts to see whether the pattern is broad, unusual, and concentrated in a short time window.
- Look for concurrent signs of ransomware activity on the source host such as file renaming, encryption, or suspicious process launches.

Evidence to collect:
- DeviceName, InitiatingProcessFileName, AccountName, DistinctTargets, and the Targets list from the alert.
- DeviceNetworkEvents for the same host and time window to confirm SMB, RPC, or admin-share activity.
- DeviceProcessEvents on the source host to identify the binary initiating the connections.
- Any endpoint alerts on the target hosts for file modification, service creation, or remote execution.

Pivot points:
- DeviceNetworkEvents for the source host to see whether the same process is contacting many internal IPs on ports 445, 135, or 139.
- DeviceProcessEvents on the source host to identify suspicious parent-child chains or known ransomware tooling.
- DeviceLogonEvents for the source account to determine whether the account is being used across multiple systems unusually.
- If available, file telemetry on the source host to look for encryption or mass file changes.

Benign explanations:
- SCCM, WSUS, Tanium, or similar enterprise management tools performing legitimate fan-out operations.
- Backup agents writing to multiple hosts in parallel.
- IT inventory or vulnerability scanning tools using SMB for discovery or validation.

Escalation criteria:
- The initiating process is not a known management, backup, or scanning tool.
- The source host also shows encryption behavior, suspicious child processes, or other ransomware indicators.
- The target list includes many business-critical hosts and the activity is continuing or expanding.

Containment actions:
- Isolate the source host immediately if the process is unknown or ransomware behavior is confirmed.
- Disable the associated account if it is not a sanctioned service account and appears compromised.
- Notify infrastructure teams to monitor or protect the listed target hosts for follow-on activity.

Closure criteria:
- The initiating process is verified as a legitimate management, backup, or scanning tool.
- The account is an approved service identity and the target pattern matches documented behavior.
- No corroborating ransomware indicators are present on the source or target hosts.

---

## Detection 4: Gentlemen Ransomware Lateral Movement: Concurrent Remote Logons from Single Account to Multiple Hosts

### Detection Opportunity

Simultaneous lateral movement techniques generate concurrent remote logon events from the same source account to multiple distinct hosts within a short time window.

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware uses a series of simultaneous lateral movement techniques per target, which produces correlated remote logon events from the same compromised account authenticating to multiple hosts concurrently within a short time window.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1021, T1021.002
- Products: Not specified
- Platforms: Windows
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, Windows, The Gentlemen, T1021, T1021.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceLogonEvents, DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 5m;
let LateralLogons =
    DeviceLogonEvents
    | where LogonType == "Network"
    | where ActionType == "LogonSuccess"
    | summarize
        DistinctHosts = dcount(DeviceName),
        HostList = make_set(DeviceName, 20),
        RemoteIPList = make_set(RemoteIP, 20),
        WindowStart = min(Timestamp)
        by AccountName, AccountDomain, bin(Timestamp, LookbackWindow)
    | where DistinctHosts > 5;
let RemoteExec =
    DeviceProcessEvents
    | where InitiatingProcessFileName in~ ("wmic.exe", "psexec.exe", "mmc.exe", "schtasks.exe", "at.exe", "powershell.exe")
    | summarize
        ExecCount = count(),
        ExecProcesses = make_set(strcat(InitiatingProcessFileName, " -> ", FileName), 10)
        by AccountName, AccountDomain, bin(Timestamp, LookbackWindow);
LateralLogons
| join kind=inner RemoteExec on AccountName, AccountDomain, Timestamp
| project
    Timestamp,
    AccountName,
    AccountDomain,
    DistinctHosts,
    HostList,
    RemoteIPList,
    ExecCount,
    ExecProcesses
| order by DistinctHosts desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- IT automation service accounts performing simultaneous remote management across many hosts.
- Domain join or Group Policy processing accounts authenticating to multiple endpoints concurrently.
- Vulnerability scanners using domain credentials to authenticate to many hosts in rapid succession.

Tuning notes:
- Adjust DistinctHosts threshold from 5 based on observed legitimate service account behavior in the environment.
- Add '| where AccountName !in~ ("svc-backup", "svc-mgmt")' with environment-specific service account names to reduce false positives.
- Consider adding a DeviceLogonEvents filter on RemoteIP to exclude logons originating from known management jump hosts.

Risks / caveats:
- LogonType in DeviceLogonEvents is a string field ('Network') not an integer; the original query correctly uses the string value but this must be confirmed against the workspace schema.
- AccountName population in DeviceProcessEvents reflects the account running the process on the destination host, not the source account performing the logon; the join on AccountName across these two tables may not correctly correlate the same identity if the ransomware runs under a different local account on the destination.
- Bin boundary misalignment between the two summarize operations can cause missed joins when logon and process events straddle a 5-minute bin boundary; consider extending the bin to 10 minutes or using a time-range join approach if this becomes a coverage gap.
- AccountName join across DeviceLogonEvents and DeviceProcessEvents may fail to correlate when the ransomware runs under a local account on the destination that differs from the source domain account; this is a known limitation of the table join approach.

### Triage Runbook

First 15 minutes:
- Identify the account, domain, and host list involved in the concurrent logons.
- Determine whether the account is a service account, admin account, or a normal user account.
- Review the associated remote execution processes to see whether tools like psexec, wmic, schtasks, powershell, or mmc were used.
- Check whether the logons originated from a known management jump host or from an unusual source IP.

Evidence to collect:
- AccountName, AccountDomain, DistinctHosts, HostList, RemoteIPList, ExecCount, and ExecProcesses from the alert.
- DeviceLogonEvents for the same account and time window to validate the concurrent logon pattern.
- DeviceProcessEvents on the destination hosts to identify remote execution tooling or suspicious commands.
- Any authentication logs or VPN logs that identify the source system or source IP for the account activity.

Pivot points:
- DeviceLogonEvents filtered to the account and surrounding time window to see all hosts authenticated to.
- DeviceProcessEvents on the destination hosts for psexec, wmic, schtasks, powershell, or mmc activity.
- DeviceNetworkEvents from the source host or source IP to identify SMB, WinRM, or RPC connections.
- If available, identity logs to determine whether the account password was recently changed or abused.

Benign explanations:
- An IT automation or service account performing legitimate remote administration across many hosts.
- Group Policy, domain management, or software deployment activity from a management server.
- A vulnerability scanner or inventory tool authenticating to multiple systems in a short period.

Escalation criteria:
- The account is a standard user or an admin account not normally used for broad remote access.
- The destination hosts are unrelated business systems and the activity is not tied to a known management workflow.
- Remote execution tooling or additional suspicious commands are observed on the destination hosts.

Containment actions:
- Disable or reset the account if it is confirmed or strongly suspected to be compromised.
- Isolate the source system if the logons are originating from an endpoint rather than a sanctioned management server.
- Coordinate with endpoint teams to monitor or isolate destination hosts showing remote execution activity.

Closure criteria:
- The account is verified as an approved service identity with documented multi-host remote access behavior.
- The source IP or jump host is a known management system and the commands are expected.
- No suspicious remote execution, privilege escalation, or ransomware indicators are present.

---

## Detection 5: Akira Pre-Encryption Activity: Perimeter Allow Followed by Internal Reconnaissance and Shadow Copy Deletion

### Detection Opportunity

Pre-impact activity before ransomware execution, correlating inbound perimeter firewall allow events with subsequent internal reconnaissance commands and shadow copy deletion on Windows hosts.

### Intelligence Context

- SANS ISC: Reconstructing an Akira Ransomware Kill Chain from Perimeter and Endpoint Logs, (Wed, May 27th) — [https://isc.sans.edu/diary/rss/33024](https://isc.sans.edu/diary/rss/33024)
  - Context: The SANS ISC analysis of an Akira ransomware kill chain highlights that critical pre-encryption behaviors are captured by joining perimeter firewall logs with Windows event logs. Correlating an inbound allow event from an external IP with subsequent reconnaissance commands and shadow copy deletion on internal hosts reconstructs the intrusion chain before the ransomware binary fires.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1016, T1082, T1490
- Products: Not specified
- Platforms: Windows
- Malware: Akira
- Tools: Not specified
- Search tags: Windows, Akira, T1016, T1082, T1490

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Discovery: T1016 System Network Configuration Discovery (high); Discovery: T1082 System Information Discovery (high); Impact: T1490 Inhibit System Recovery (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, DeviceProcessEvents before scheduling.

Required telemetry:
- CommonSecurityLog, DeviceProcessEvents

### KQL

```kql
let PerimeterAllows =
    CommonSecurityLog
    | where DeviceAction =~ "allow" or DeviceAction =~ "permit"
    | where not(SourceIP matches regex @"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
    | where DestinationPort in (22, 3389, 443, 80, 8080, 8443)
    | project AllowTime = TimeGenerated, SourceIP, DestinationIP, DeviceVendor, DeviceProduct;
let PreRansomExec =
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("nltest", "whoami", "ipconfig")
        or ProcessCommandLine has_any ("net user", "net group")
        or (ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete")
        or (ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    | project ExecTime = Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FileName;
PerimeterAllows
| join kind=inner (PreRansomExec) on $left.DestinationIP == $right.DeviceName
| where ExecTime between (AllowTime .. (AllowTime + 2h))
| project
    AllowTime,
    ExecTime,
    SourceIP,
    DestinationIP,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FileName,
    DeviceVendor,
    DeviceProduct
| order by AllowTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate external administrative access followed by routine system commands on the destination host.
- Backup software invoking vssadmin or wmic shadowcopy as part of scheduled snapshot operations.
- Security scanning tools that enumerate system information using whoami, ipconfig, or net commands after authenticating remotely.

Tuning notes:
- Implement an asset inventory watchlist in Sentinel that maps internal IP addresses to DeviceName values, then replace the direct join condition with a lookup against that watchlist.
- Validate DeviceAction values in CommonSecurityLog by running 'CommonSecurityLog | summarize count() by DeviceAction | order by count_ desc' against the workspace before deploying.
- Restrict DestinationPort to the specific ports used by externally exposed services in the environment to reduce noise from internal traffic misclassified as external.
- Consider splitting the detection into two separate analytics: one for shadow copy deletion alone (higher confidence, lower noise) and one for the full correlation chain.

Risks / caveats:
- CommonSecurityLog DeviceAction values are firewall-vendor-specific; 'allow' and 'permit' are common but not universal. The deployed firewall vendor's CEF normalization must be confirmed to use these exact strings before the query returns results.
- The join on DestinationIP == DeviceName requires that DeviceName in DeviceProcessEvents contains an IP address string rather than a hostname, which is not the default MDE behavior. An asset inventory table mapping IP addresses to hostnames is required for this join to function.
- CommonSecurityLog requires a CEF-compatible firewall connector to be configured in the Sentinel workspace. If no perimeter firewall is forwarding CEF logs, the table will be empty.
- DeviceProcessEvents in a Sentinel workspace requires the Microsoft Defender for Endpoint connector to be enabled and data to be flowing via the MDE-Sentinel integration.

### Triage Runbook

First 15 minutes:
- Validate the external source IP, destination host, and allowed service to determine whether the perimeter event is expected.
- Review the endpoint command line for reconnaissance commands such as whoami, ipconfig, nltest, or net user/group and for shadow copy deletion commands.
- Check whether the destination host is a server or workstation and whether the activity occurred shortly after the inbound allow event.
- Look for additional signs of compromise on the same host, including suspicious logons, new services, scheduled tasks, or outbound connections.

Evidence to collect:
- AllowTime, ExecTime, SourceIP, DestinationIP, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FileName, DeviceVendor, and DeviceProduct.
- Firewall logs showing the original inbound allow event and the exact service/port that was permitted.
- DeviceProcessEvents on the destination host for the surrounding time window to identify follow-on discovery or destructive actions.
- Any file, logon, or network telemetry that indicates the host was used for staging or lateral movement.

Pivot points:
- CommonSecurityLog for the same SourceIP or DestinationIP to see whether the external host has repeated access attempts or other allowed sessions.
- DeviceProcessEvents on the destination host to find additional discovery, privilege, or recovery-inhibition commands.
- DeviceLogonEvents to identify whether the account used on the host is local, domain, or remote-admin related.
- DeviceNetworkEvents to look for outbound beaconing or lateral movement after the initial access.

Benign explanations:
- A legitimate external administrative session followed by routine commands such as whoami or ipconfig.
- Backup or maintenance software invoking vssadmin or shadow copy commands as part of scheduled operations.
- Security or IT scanning tools performing host discovery after remote access.

Escalation criteria:
- The inbound allow is from an unrecognized external IP and the host immediately runs discovery and shadow copy deletion commands.
- The host shows additional ransomware indicators such as mass file changes, new services, or suspicious remote access.
- The activity is on a critical server or multiple hosts show the same pattern.

Containment actions:
- Isolate the affected host if the chain is confirmed or strongly suspected to be malicious.
- Block the external source IP at the perimeter if it is not a legitimate business source.
- Disable the account used on the host if it appears compromised and preserve evidence before remediation.

Closure criteria:
- The perimeter allow is tied to a known administrative source and the commands are documented maintenance actions.
- No additional suspicious activity is found on the host or adjacent systems.
- The shadow copy deletion match is explained by approved backup or recovery tooling.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- Gogs Git Rebase Argument Injection via --exec Flag: Do not schedule yet; validate as an analyst-led hunt first.
- Unexpected Child Process Spawned by Gogs Service Following Git Rebase: Do not schedule yet; validate as an analyst-led hunt first.
- Gentlemen Ransomware Lateral Movement: Concurrent Remote Logons from Single Account to Multiple Hosts: Do not schedule yet; validate as an analyst-led hunt first.

Telemetry availability:
- Akira Pre-Encryption Activity: Perimeter Allow Followed by Internal Reconnaissance and Shadow Copy Deletion: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, DeviceProcessEvents before scheduling.

Shared-table notes:
- DeviceProcessEvents: shared by Gogs Git Rebase Argument Injection via --exec Flag; Unexpected Child Process Spawned by Gogs Service Following Git Rebase; Gentlemen Ransomware Lateral Movement: Concurrent Remote Logons from Single Account to Multiple Hosts; Akira Pre-Encryption Activity: Perimeter Allow Followed by Internal Reconnaissance and Shadow Copy Deletion

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Gentlemen Ransomware Self-Propagation: Rapid Fan-Out SMB Connections from Single Host.
2. Resolve environment-mapping detections next: Akira Pre-Encryption Activity: Perimeter Allow Followed by Internal Reconnaissance and Shadow Copy Deletion.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Gogs Git Rebase Argument Injection via --exec Flag; Unexpected Child Process Spawned by Gogs Service Following Git Rebase; Gentlemen Ransomware Lateral Movement: Concurrent Remote Logons from Single Account to Multiple Hosts.

### Hunting Agenda and Promotion Criteria

- Gogs Git Rebase Argument Injection via --exec Flag: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Unexpected Child Process Spawned by Gogs Service Following Git Rebase: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Gentlemen Ransomware Lateral Movement: Concurrent Remote Logons from Single Account to Multiple Hosts: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Akira Pre-Encryption Activity: Perimeter Allow Followed by Internal Reconnaissance and Shadow Copy Deletion: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
