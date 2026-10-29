---
layout: post
title: "Detection Engineering Brief - Thursday, October 29, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-29
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - NetamLoader
  - Windows 10
  - T1204
  - T1106
---

## Detection Engineering Summary

This brief produced 1 detection candidate.

0 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

1 detection include KQL. 1 include ATT&CK mappings. 1 include triage guidance.

Search metadata extracted for this run includes: NetamLoader, Windows 10, T1204, T1106.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: NetamLoader - Suspicious Loader Process Chain on Windows 10.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: NetamLoader - Suspicious Loader Process Chain on Windows 10

### Detection Opportunity

NetamLoader execution observed as part of a targeted attack against government Windows 10 endpoints, manifesting as unusual loader process chains or unsigned executables spawning child processes.

### Intelligence Context

- Securelist: Unknown APT uses NetamLoader to attack a Win10 OS customized for governments in Asia — [https://securelist.com/netamloader/121676/](https://securelist.com/netamloader/121676/)
  - Context: An unknown APT deployed NetamLoader against a customized government Windows 10 OS in Asia. The loader was used as the initial execution stage, making process chain and image load telemetry the primary detection surface in the absence of published file hashes.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1106
- Products: Not specified
- Platforms: Windows 10
- Malware: NetamLoader
- Tools: Not specified
- Search tags: NetamLoader, Windows 10, T1204, T1106

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: execution: T1204 User Execution (low); execution: T1106 Native API (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceImageLoadEvents

### KQL

```kql
let LookbackWindow = 7d;
let ChainWindowSeconds = 120;
let TrustedParents = dynamic([
    "explorer.exe", "svchost.exe", "services.exe",
    "wininit.exe", "winlogon.exe", "lsass.exe",
    "msiexec.exe", "taskhostw.exe", "sihost.exe",
    "runtimebroker.exe", "searchhost.exe"
]);
let TrustedPathPrefixes = dynamic([
    @"c:\windows\\",
    @"c:\program files\\",
    @"c:\program files (x86)\\"
]);
let SuspiciousLoaderProcesses =
    DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where ProcessIntegrityLevel in~ ("low", "medium", "untrusted")
    | where not(
        FolderPath has_any (TrustedPathPrefixes)
      )
    | where not(
        InitiatingProcessFileName in~ (TrustedParents)
      )
    | summarize
        arg_min(Timestamp, *)
        by DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
    | project
        DeviceName,
        ParentProcess          = InitiatingProcessFileName,
        ParentCmdLine          = InitiatingProcessCommandLine,
        ChildProcess           = FileName,
        ChildCmdLine           = ProcessCommandLine,
        ChildFolderPath        = FolderPath,
        ChildSHA256            = SHA256,
        ProcessIntegrityLevel,
        Timestamp;
let UnsignedImageLoads =
    DeviceImageLoadEvents
    | where Timestamp > ago(LookbackWindow)
    | where IsSigned != true
    | where not(
        FolderPath has_any (TrustedPathPrefixes)
      )
    | project
        DeviceName,
        LoadedImage            = FileName,
        ImageFolderPath        = FolderPath,
        ImageSHA256            = SHA256,
        InitiatingProcessFileName,
        ImageTimestamp         = Timestamp;
SuspiciousLoaderProcesses
| join kind=inner UnsignedImageLoads
    on DeviceName,
       $left.ChildProcess == $right.InitiatingProcessFileName
| where datetime_diff('second', ImageTimestamp, Timestamp) between (0 .. ChainWindowSeconds)
| project
    Timestamp,
    DeviceName,
    ParentProcess,
    ParentCmdLine,
    ChildProcess,
    ChildCmdLine,
    ChildFolderPath,
    ChildSHA256,
    ProcessIntegrityLevel,
    LoadedImage,
    ImageFolderPath,
    ImageSHA256,
    ImageTimestamp
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers and update agents running from temp or user-profile directories with medium integrity that load unsigned helper DLLs.
- Developer tools, scripting runtimes, and build agents executing unsigned binaries from non-standard paths.
- Third-party security or monitoring agents that load unsigned kernel or user-mode components.
- Custom government OS components installed outside standard Program Files paths that are unsigned by design.

**Tuning notes:**
- To scope to Windows 10 devices only, add: → join kind=inner (DeviceInfo → where OSPlatform == 'Windows10' → distinct DeviceName) on DeviceName after the SuspiciousLoaderProcesses let block.
- Narrow ProcessIntegrityLevel to only 'low' or 'untrusted' if medium-integrity false positives dominate after initial review.
- Add environment-specific trusted path prefixes to TrustedPathPrefixes (e.g., software deployment cache paths, VDI base image paths) to reduce noise.
- Add environment-specific trusted parent process names to TrustedParents for any custom government OS shell or session manager processes.

**Risks / caveats:**
- DeviceImageLoadEvents.IsSigned and DeviceImageLoadEvents.IsCodeSigningCert require Microsoft Defender for Endpoint Plan 2 with image load telemetry enabled; these fields may be absent or null if the MDE sensor is not configured to collect image load events.
- DeviceProcessEvents.ProcessIntegrityLevel is populated only when the MDE sensor collects process integrity metadata; verify field is non-null in the target tenant before relying on it as a filter.
- OSVersion is not a standard field in DeviceProcessEvents in Defender XDR; the original filter on OSVersion has been replaced with a join-time DeviceName scope or removed to avoid producing zero results.
- The 7-day lookback window combined with a broad join may produce large intermediate result sets in active tenants; consider reducing to 1-2 days for initial runs.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is in scope for the government Windows 10 population and note whether the alert came from a known software deployment, VDI, or custom OS build.
- Review the parent process, child process, command lines, folder paths, and integrity level to see whether execution originated from a user-writable or unusual directory.
- Check whether the child process is unsigned or unexpectedly unsigned for that software family, and whether it spawned additional child processes or loaded unsigned images.
- Look for signs of user interaction immediately before execution, such as a download, document open, installer launch, or archive extraction.
- Assess whether the process chain is isolated to one host or repeated across multiple hosts with the same binary or path.

**Evidence to collect:**
- Device name, timestamp, parent process name, parent command line, child process name, child command line, child folder path, and process integrity level.
- Loaded image name, image folder path, image SHA256, and whether the image is signed or code-signing certified.
- Any available file reputation, first-seen, or certificate metadata for the child binary and loaded image.
- Recent DeviceProcessEvents and DeviceImageLoadEvents around the alert time to reconstruct the full chain and identify additional spawned processes.
- User context and recent activity on the endpoint, including logon session, downloads, email attachments, browser activity, or software installation events if available.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and ChildSHA256 to find repeated executions, parent variations, and additional child processes.
- DeviceImageLoadEvents for the same DeviceName and ImageSHA256 to identify other hosts loading the same unsigned image.
- DeviceInfo to confirm OS platform, device group, and whether the host is a government-build Windows 10 endpoint.
- DeviceFileEvents or file telemetry, if available, to determine file creation time, origin path, and whether the binary was dropped recently.
- Sign-in and user activity telemetry to correlate the process start with a user session or suspicious interactive activity.

**Benign explanations:**
- Legitimate software installers or update agents running from temp or user-profile directories and loading unsigned helper components.
- Custom government OS components or internally developed utilities that are unsigned by design and execute from non-standard paths.
- Developer tools, scripting runtimes, or build agents that spawn helper processes and load unsigned modules during normal operation.
- Third-party security, monitoring, or endpoint management software that uses unsigned helper binaries or side-loaded components.

**Escalation criteria:**
- The child process is unsigned, runs from a user-writable or unusual path, and spawns additional suspicious processes or loads unsigned images.
- The same binary or image appears on multiple hosts, especially if those hosts are in the same government Windows 10 group.
- The command line, parent chain, or file path suggests staged execution, masquerading, or execution from a temporary or hidden location.
- There is no credible business justification, software deployment record, or known-good allowlist entry for the binary or path.
- Additional telemetry shows follow-on activity such as credential access, persistence, lateral movement, or outbound connections from the host.

**Containment actions:**
- If the process chain appears malicious or there is strong corroborating evidence, isolate the host from the network using endpoint containment.
- Preserve the suspicious binary and loaded image for forensic collection before remediation if operationally feasible.
- Block the file hash or path only after confirming it is not a sanctioned internal component or required government build artifact.
- Disable or suspend the affected user session if the execution is tied to an active interactive compromise and business impact is acceptable.

**Closure criteria:**
- The binary and loaded image are confirmed as approved internal software or a documented government OS component.
- The execution is explained by a known software deployment, update process, or approved administrative activity.
- No additional suspicious process creation, unsigned image loading, or related host activity is found after pivoting.
- The file path, parent process, and certificate metadata match a validated benign pattern and the host is not showing broader compromise indicators.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- NetamLoader - Suspicious Loader Process Chain on Windows 10: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: NetamLoader - Suspicious Loader Process Chain on Windows 10.

### Hunting Agenda and Promotion Criteria

- NetamLoader - Suspicious Loader Process Chain on Windows 10: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
