---
layout: post
title: "Detection Engineering Brief - Friday, October 30, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-30
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Windows
  - T1059
  - T1059.001
  - T1059.003
---

## Detection Engineering Summary

This brief produced 1 detection candidate.

0 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

1 detection include KQL. 1 include ATT&CK mappings. 1 include triage guidance.

Search metadata extracted for this run includes: Windows, T1059, T1059.001, T1059.003.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: ClickFix - Browser-Spawned Script Interpreter Execution.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: ClickFix - Browser-Spawned Script Interpreter Execution

### Detection Opportunity

ClickFix-style social engineering triggers user-initiated execution of script interpreters spawned directly from browser processes

### Intelligence Context

- SANS ISC: Yet Another ClickFix Campaign, (Wed, Oct 28th) — [https://isc.sans.edu/diary/rss/33466](https://isc.sans.edu/diary/rss/33466)
  - Context: The reporting describes a ClickFix campaign in which users are socially engineered into manually triggering malicious command execution. The established ClickFix pattern involves a browser process spawning cmd.exe, powershell.exe, mshta.exe, or wscript.exe, often with encoded or obfuscated command lines, as the user is instructed to paste or run a command.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001, T1059.003
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, T1059, T1059.001, T1059.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (high); execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); execution: T1059 Command and Scripting Interpreter/ T1059.003 Windows Command Shell (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackWindow = 7d;
let NetworkCorrelationWindow = 5m;
let BrowserProcesses = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"]);
let ScriptInterpreters = dynamic(["cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe"]);
let ObfuscationKeywords = dynamic(["-enc", "-EncodedCommand", "FromBase64", "IEX", "Invoke-Expression", "DownloadString", "DownloadFile"]);
let UrlKeywords = dynamic(["mshta", "http", "https"]);
let SuspiciousChildProcs = DeviceProcessEvents
| where Timestamp >= ago(LookbackWindow)
| where InitiatingProcessFileName has_any (BrowserProcesses)
| where FileName has_any (ScriptInterpreters)
| where ProcessCommandLine has_any (ObfuscationKeywords)
    or ProcessCommandLine has_any (UrlKeywords)
| project
    ProcessTime = Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    ProcessId;
let NetworkFollowOn = DeviceNetworkEvents
| where Timestamp >= ago(LookbackWindow)
| where InitiatingProcessFileName has_any (ScriptInterpreters)
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| where RemoteIP !startswith "127."
    and RemoteIP !startswith "::1"
    and RemoteIP !startswith "169.254."
    and RemoteIP !startswith "10."
    and RemoteIP !startswith "192.168."
    and not (RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.") 
| project
    NetworkTime = Timestamp,
    DeviceId,
    NetInitiatingProcessFileName = InitiatingProcessFileName,
    RemoteUrl,
    RemoteIP,
    RemotePort;
SuspiciousChildProcs
| join kind=leftouter (
    NetworkFollowOn
) on DeviceId
| where isempty(NetworkTime) or (NetworkTime >= ProcessTime and NetworkTime <= ProcessTime + NetworkCorrelationWindow)
| where isnotempty(RemoteUrl)
    or isnotempty(RemoteIP)
    or ProcessCommandLine has_any (ObfuscationKeywords)
| project
    ProcessTime,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    NetworkTime,
    RemoteUrl,
    RemoteIP,
    RemotePort
| order by ProcessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise web portals or IT self-service tools that legitimately invoke PowerShell or cmd.exe via browser-based automation.
- Developer environments where browsers launch script interpreters as part of build or test workflows.
- Browser extensions or enterprise management agents that spawn cmd.exe or PowerShell for configuration tasks.
- Password managers or SSO tools that use mshta.exe or wscript.exe for credential bridging.

**Tuning notes:**
- Add known-safe InitiatingProcessCommandLine values to an exclusion list to suppress enterprise automation false positives.
- If the environment uses Chromium-based enterprise browsers with custom executable names, add those names to BrowserProcesses.
- Consider splitting into two separate queries: one for high-confidence encoded-command-line matches (schedule as alert) and one for URL-keyword-only matches (keep as hunting).
- The private IP exclusion for RFC1918 ranges can be removed if the threat model includes lateral movement via internal attacker infrastructure.

**Risks / caveats:**
- RemoteUrl is not always populated in DeviceNetworkEvents; environments where DNS-only or IP-only telemetry is collected may see empty RemoteUrl for legitimate outbound callbacks, reducing correlation fidelity.
- InitiatingProcessFileName in DeviceNetworkEvents reflects the direct parent of the network event, not the original browser grandparent; if the script interpreter spawns a child that makes the connection, the join will miss it.
- The 7-day lookback is appropriate for hunting but should be reduced to 1 day or less if converted to a scheduled rule to avoid repeated alerting on the same events.
- The 5-minute network correlation window may miss slow-beacon or delayed callback patterns; analysts should pivot manually on DeviceId and ProcessId for extended follow-on activity.

### Triage Runbook

**First 15 minutes:**
- Confirm the exact parent-child chain: identify the browser process, the spawned interpreter (cmd.exe, powershell.exe, mshta.exe, wscript.exe, or cscript.exe), and the account that initiated it.
- Review the full command line for encoded content, obfuscation, download cradles, script execution flags, or references to remote content.
- Check whether the event occurred immediately after a user browsing session, helpdesk interaction, or prompt to paste/run a command from a website.
- Look for any network follow-on from the interpreter within a few minutes, especially external RemoteUrl/RemoteIP activity or unusual ports.
- Assess whether the host shows additional suspicious activity such as new child processes, persistence changes, or repeated interpreter launches.

**Evidence to collect:**
- DeviceName, DeviceId, Timestamp, AccountName, and AccountDomain for the triggering event.
- InitiatingProcessFileName, FileName, ProcessCommandLine, and InitiatingProcessCommandLine to reconstruct the execution chain.
- NetworkTime, RemoteUrl, RemoteIP, and RemotePort for any correlated outbound activity.
- Any additional process tree entries on the same host around the same time, including subsequent child processes spawned by the interpreter.
- User-reported context if available: website visited, prompt shown, file downloaded, or instructions followed.

**Pivot points:**
- DeviceProcessEvents: pivot on the same DeviceId and AccountName to find prior and subsequent browser launches, interpreter executions, and child processes.
- DeviceNetworkEvents: pivot on the same DeviceId and time window to identify outbound connections from the interpreter or its children.
- DeviceFileEvents: check for dropped scripts, downloaded files, or newly created executables in the user profile or temp directories.
- DeviceRegistryEvents: look for persistence-related changes if the interpreter executed a payload or script.
- DeviceLogonEvents: validate whether the account activity aligns with the user’s normal login pattern and workstation usage.

**Benign explanations:**
- Legitimate enterprise web portals or self-service tools that launch PowerShell or cmd.exe for automation.
- Developer or IT workflows where a browser starts a local script interpreter for testing, build, or admin tasks.
- Password managers, SSO tools, or browser extensions that use mshta.exe or wscript.exe for integration or credential bridging.
- Known internal automation pages or remote support tools that are expected to invoke command shells.

**Escalation criteria:**
- The command line is encoded, obfuscated, or contains download-and-execute behavior.
- The interpreter makes an external network connection to an unfamiliar domain, IP, or non-standard port.
- The host shows additional suspicious activity such as persistence, credential access, or multiple staged child processes.
- The user denies intentionally running a command or visiting a site that would explain the execution.
- The same pattern appears on multiple hosts or accounts, suggesting a broader campaign.

**Containment actions:**
- If the command line or follow-on activity is clearly malicious, isolate the host from the network.
- Suspend or reset the affected user account if there is evidence of active attacker control or repeated malicious execution.
- Block identified malicious domains, URLs, or IPs at the proxy or DNS layer if they are confirmed malicious.
- Preserve volatile evidence before rebooting or cleaning the system if incident response support is available.

**Closure criteria:**
- The execution is confirmed as approved administrative or developer activity and matches an established allowlist or documented workflow.
- No suspicious network follow-on, persistence, or additional malicious process activity is found after review.
- The user confirms the action was intentional and the command line aligns with a legitimate internal tool or portal.
- Any suspicious indicators are explained by benign automation and documented for future allowlisting.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- ClickFix - Browser-Spawned Script Interpreter Execution: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ClickFix - Browser-Spawned Script Interpreter Execution.

### Hunting Agenda and Promotion Criteria

- ClickFix - Browser-Spawned Script Interpreter Execution: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
