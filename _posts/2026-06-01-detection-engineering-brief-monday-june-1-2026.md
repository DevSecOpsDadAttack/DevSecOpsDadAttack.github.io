---
layout: post
title: "Detection Engineering Brief - Monday, June 1, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-01
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - npm
  - Windows
  - macOS
  - Linux
  - CVE-2026-0257
  - T1190
  - PAN-OS
  - Prisma Access
  - GlobalProtect
  - NetSupport RAT
  - T1059.007
  - T1041
  - T1059
  - T1071.001
  - T1095
  - T1071
---

## Executive Signal

This brief produced 4 detection candidates.

1 production candidate, 2 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: npm, Windows, macOS, Linux, CVE-2026-0257, T1190, PAN-OS, Prisma Access, GlobalProtect, NetSupport RAT, T1059.007, T1041, T1059, T1071.001, T1095, T1071.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: NPM Post-Install Script Spawning Reconnaissance Commands; NPM Install Followed by Outbound Network Connection to External Host; GlobalProtect VPN Session Established Without Prior Authentication Event (CVE-2026-0257).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: NPM Post-Install Script Spawning Reconnaissance Commands

### Detection Opportunity

Malicious npm packages executing reconnaissance commands via post-install scripts after dependency confusion installation

### Intelligence Context

- Microsoft Security Blog: Malicious npm packages abuse dependency confusion to profile developer environments — [https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)
  - Context: 33 malicious npm packages used dependency confusion to trigger post-install scripts that collected reconnaissance data from developer and build environments, profiling the host after installation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059.007, T1041, T1059
- Products: npm
- Platforms: Windows, macOS, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, Windows, macOS, Linux, T1059.007, T1041, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (medium); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ReconProcs = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "npm", "node")
| where FileName in~ ("whoami.exe", "hostname.exe", "systeminfo.exe", "ipconfig.exe", "ifconfig", "uname", "env", "printenv", "id")
| project ReconTime = Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ReconProcess = FileName, ReconFolderPath = FolderPath,
          ProcessCommandLine;
let PostReconNet = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "npm", "node")
| where isnotempty(RemoteIP)
| project NetTime = Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, RemotePort;
ReconProcs
| join kind=leftouter PostReconNet on DeviceName, AccountName
| where isnotempty(RemoteIP)
| where (NetTime - ReconTime) between (0min .. 2min)
| project ReconTime, NetTime, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ReconProcess, ReconFolderPath, ProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort
| sort by ReconTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- node-gyp and native addon build scripts routinely invoke system binaries such as uname, env, and hostname during compilation.
- CI/CD pipeline agents running npm install as a service account will generate high volumes of matches; these should be scoped out by DeviceName or AccountName.
- Monorepo tooling (nx, turborepo, lerna) may spawn multiple node processes that make outbound connections to internal registries within the correlation window.

Tuning notes:
- Baseline legitimate npm postinstall recon invocations by running the ReconProcs subquery alone for 7 days and reviewing InitiatingProcessCommandLine values; add known-good patterns to an exclusion filter.
- For CI/CD environments, consider scoping the query to DeviceName values not in a known build-agent list.
- Add internal IP ranges to a RemoteIP exclusion to suppress connections to internal package registries or artifact stores.
- Extend the lookback to 14 days during initial hunting; reduce to 1 day if promoted to a scheduled rule.

Risks / caveats:
- ipv4_is_private() does not evaluate IPv6 addresses; devices with IPv6-only egress will not be filtered correctly.
- On macOS and Linux endpoints onboarded to Defender for Endpoint, InitiatingProcessFileName may be 'node' rather than 'node.exe' and FileName values for shell built-ins such as 'env' and 'printenv' may not appear as discrete process events depending on the shell execution model — verify telemetry coverage for non-Windows platforms before relying on this query cross-platform.
- The 2-minute correlation window may need widening for slow build pipelines or narrowing to reduce noise in high-throughput CI environments.
- Joining on AccountName as well as DeviceName can cause missed matches when npm runs under a different account than the node process making the outbound connection (e.g., sudo or runas scenarios).

### Triage Runbook

First 15 minutes:
- Confirm the host role: developer workstation, CI/CD runner, build server, or general user endpoint.
- Review the full InitiatingProcessCommandLine and ProcessCommandLine to identify the package name, install source, and whether the command was part of a known build step.
- Check whether the recon binary and folder path are expected for this environment (for example node-gyp, native addon builds, or monorepo tooling).
- Inspect the correlated RemoteIP/RemoteUrl/RemotePort to determine whether the connection is to an internal registry/artifact store or an external destination.
- Look for additional npm-related process activity on the same host and account in the same time window, including repeated installs or multiple recon commands.

Evidence to collect:
- DeviceName and AccountName to determine whether this is a developer, service, or build account.
- InitiatingProcessCommandLine and ProcessCommandLine to capture the exact npm invocation and spawned recon command.
- ReconProcess and ReconFolderPath to identify the binary executed and whether it ran from an unusual path.
- RemoteIP, RemoteUrl, and RemotePort to assess whether the outbound connection is external or expected internal infrastructure.
- Any preceding or subsequent DeviceProcessEvents and DeviceNetworkEvents on the same host within 30 minutes to establish scope.

Pivot points:
- DeviceProcessEvents for the same DeviceName and AccountName to enumerate all npm, node, and recon command activity.
- DeviceNetworkEvents for the same DeviceName and AccountName to identify other outbound destinations from node or npm.
- DeviceFileEvents if available to check for package extraction, temporary directories, or suspicious script artifacts.
- DeviceLogonEvents to determine whether the account is interactive, service-based, or a CI runner.
- Package management or source control logs outside Defender XDR to confirm whether the install was initiated by a legitimate pipeline or developer action.

Benign explanations:
- node-gyp or native addon builds commonly spawn uname, env, hostname, ipconfig, or systeminfo during installation.
- CI/CD agents often run npm install under shared service accounts and generate correlated recon plus network activity.
- Monorepo tooling such as nx, turborepo, or lerna can create multiple node processes and internal registry connections.
- A known internal package may legitimately perform environment checks during post-install for compatibility or telemetry.

Escalation criteria:
- The package name, install source, or script path is unknown or does not match approved software supply chain sources.
- The outbound destination is external and not a known registry, artifact store, CDN, or approved telemetry endpoint.
- The recon commands are unusual for the environment, such as whoami, systeminfo, ipconfig, or uname on a developer workstation with no build context.
- Multiple hosts or accounts show the same pattern, suggesting a broader dependency confusion campaign.
- Evidence indicates credential harvesting, environment profiling, or data staging beyond a normal build script.

Containment actions:
- If the package or script is unapproved, isolate the host or stop the build job to prevent further execution.
- Remove or quarantine the suspicious npm package from the affected project or artifact cache.
- Block the external destination if it is confirmed malicious and not required for business use.
- Reset credentials for the affected developer or service account if there is evidence of token exposure or suspicious authentication activity.
- Preserve the host state and relevant logs before remediation if compromise is suspected.

Closure criteria:
- The npm package and install source are verified as approved and the recon commands match documented build behavior.
- The outbound destination is confirmed to be a legitimate internal registry, artifact store, or approved service.
- No additional suspicious process, network, or credential activity is found on the host or related accounts.
- Any required exclusions are documented with the exact package/script and destination patterns.
- The analyst records why the event is benign and whether tuning is needed for the environment.

---

## Detection 2: NPM Install Followed by Outbound Network Connection to External Host

### Detection Opportunity

npm post-install script initiating outbound network connection to external infrastructure to exfiltrate developer environment reconnaissance data

### Intelligence Context

- Microsoft Security Blog: Malicious npm packages abuse dependency confusion to profile developer environments — [https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)
  - Context: Malicious npm packages collected reconnaissance data from developer and build environments and transmitted it outbound, consistent with dependency confusion supply chain profiling activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059.007, T1041, T1059
- Products: npm
- Platforms: Windows, macOS, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, Windows, macOS, Linux, T1059.007, T1041, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (medium); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let NpmInstalls = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("npm.cmd", "npm") and ProcessCommandLine has "install"
| project InstallTime = Timestamp, DeviceName, AccountName, InstallCommandLine = ProcessCommandLine;
let NodeOutbound = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where RemotePort !in (80, 443, 8080, 8443)
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| where not(RemoteUrl has_any ("registry.npmjs.org", "registry.yarnpkg.com"))
| project NetTime = Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, RemotePort;
NpmInstalls
| join kind=inner NodeOutbound on DeviceName, AccountName
| where (NetTime - InstallTime) between (0min .. 5min)
| project InstallTime, NetTime, DeviceName, AccountName, InstallCommandLine, RemoteIP, RemoteUrl, RemotePort
| sort by InstallTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- npm packages that include telemetry or analytics scripts making outbound calls on non-standard ports.
- Packages that download binary assets from CDN endpoints not covered by the registry exclusion list.
- CI/CD agents running npm install as a shared service account will generate correlated events for every build.
- Electron or desktop app builds that invoke node.exe for asset bundling and make outbound calls during the build process.

Tuning notes:
- Add private npm registry hostnames to the has_any exclusion in the NodeOutbound filter.
- Consider adding common CDN hostnames used by npm package binary downloads to the exclusion list after baselining.
- For CI/CD environments, scope the query to DeviceName values not in a known build-agent list to reduce volume.
- Adjust the 5-minute window based on observed build pipeline timing in the environment.

Risks / caveats:
- ipv4_is_private() does not evaluate IPv6 addresses; IPv6 egress to external hosts will not be detected.
- On macOS and Linux, the npm process FileName may be 'npm' without the .cmd extension and node may appear as 'node' rather than 'node.exe'; both variants are included in the query but telemetry availability for non-Windows platforms should be confirmed.
- RemoteUrl may be empty in DeviceNetworkEvents for connections where DNS resolution did not occur or was not captured; detections relying on RemoteUrl exclusions will not filter those events.
- The 5-minute post-install window may be too wide for high-frequency build environments and too narrow for slow dependency resolution pipelines.

### Triage Runbook

First 15 minutes:
- Confirm whether the host is a developer machine, build agent, or production endpoint and whether npm install is expected there.
- Review InstallCommandLine to identify the package, repository, and whether the install was interactive, scripted, or part of a pipeline.
- Check RemoteIP, RemoteUrl, and RemotePort to determine if the destination is a public registry, private artifact store, CDN, or unknown external host.
- Correlate the timing between InstallTime and NetTime to see whether the connection occurred immediately after install or later as part of normal application behavior.
- Look for repeated node outbound connections or additional suspicious child processes from the same install session.

Evidence to collect:
- DeviceName and AccountName to identify the affected system and whether the account is a service or developer identity.
- InstallCommandLine to capture the exact npm command and package context.
- RemoteIP, RemoteUrl, and RemotePort to characterize the destination and whether it is expected.
- NetTime relative to InstallTime to understand whether the connection aligns with post-install execution.
- Any related DeviceProcessEvents showing node, npm, shell, or recon commands around the same timestamp.

Pivot points:
- DeviceProcessEvents filtered to the same DeviceName and AccountName for npm, node, powershell, cmd, bash, sh, or recon utilities.
- DeviceNetworkEvents for the same host to identify all external destinations contacted by node or npm in the last 24 hours.
- DeviceFileEvents to look for package extraction, temporary script files, or dropped binaries.
- DeviceLogonEvents to determine whether the account is a build service account or an interactive user.
- Proxy, firewall, or DNS logs to validate whether the destination is a known registry, CDN, or suspicious external host.

Benign explanations:
- Legitimate npm packages may contact CDNs, telemetry services, or package mirrors during install.
- Private registries such as Artifactory, Nexus, or Azure Artifacts can appear as external destinations if not allowlisted.
- CI/CD agents often generate many install-and-connect events under shared service accounts.
- Electron or desktop app builds may invoke node during packaging and reach out to dependency or asset endpoints.

Escalation criteria:
- The destination is not a known registry, CDN, or approved internal service and the package is not recognized.
- The install command references an unexpected package name, dependency confusion source, or unapproved repository.
- The host is a non-development endpoint where npm install should not normally occur.
- There is evidence of credential theft, environment enumeration, or repeated outbound connections to the same unknown host.
- Multiple endpoints or accounts show the same install-to-external-connection pattern.

Containment actions:
- If the package or destination is suspicious, stop the build or isolate the host to prevent further execution.
- Remove the package from the project and clear any cached artifacts or lockfile entries if malicious dependency confusion is suspected.
- Block the external destination at proxy or firewall if confirmed malicious.
- Rotate any exposed developer, CI, or package registry credentials if the install may have accessed secrets.
- Preserve logs and package metadata before cleanup if the event may be part of a broader supply chain incident.

Closure criteria:
- The install and outbound connection are matched to an approved package and expected destination.
- The destination is documented as a legitimate registry, CDN, or internal artifact service.
- No additional suspicious child processes, exfiltration indicators, or repeated connections are observed.
- Any needed allowlist entries are added for the exact hostnames or package patterns.
- The analyst documents the benign workflow and any environment-specific tuning required.

---

## Detection 3: GlobalProtect VPN Session Established Without Prior Authentication Event (CVE-2026-0257)

### Detection Opportunity

Unauthenticated remote attacker establishing a VPN session through PAN-OS GlobalProtect gateway by exploiting authentication bypass vulnerability CVE-2026-0257

### Intelligence Context

- Rapid7: Rapid7 Observed Exploitation of PAN-OS GlobalProtect Authentication Bypass Vulnerability (CVE-2026-0257) — [https://www.rapid7.com/blog/post/etr-rapid7-observed-exploitation-of-pan-os-globalprotect-authentication-bypass-vulnerability-cve-2026-0257](https://www.rapid7.com/blog/post/etr-rapid7-observed-exploitation-of-pan-os-globalprotect-authentication-bypass-vulnerability-cve-2026-0257)
  - Context: Rapid7 MDR identified successful exploitation of CVE-2026-0257 across multiple customers, where remote unauthenticated attackers established VPN connections through affected GlobalProtect gateways without completing a normal authentication flow.

### Search Metadata

- CVEs: CVE-2026-0257
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: PAN-OS, Prisma Access, GlobalProtect
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-0257, T1190, PAN-OS, Prisma Access, GlobalProtect

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog must be populated by a PAN-OS CEF/Syslog connector with DeviceVendor set to 'Palo Alto Networks'; if logs are ingested via a different connector or table (e.g., a custom table or Palo Alto Networks via the dedicated data connector), this query will return no results.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let AuthEvents = CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor =~ "Palo Alto Networks"
| where DeviceProduct has_any ("GlobalProtect", "PAN-OS")
| where Activity has_any ("login", "authenticate", "auth-success", "prelogin")
    or Message has_any ("login", "authenticate", "prelogin")
| project AuthTime = TimeGenerated, SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor =~ "Palo Alto Networks"
| where DeviceProduct has_any ("GlobalProtect", "PAN-OS")
| where Activity has_any ("connected", "tunnel-established", "gateway-connected")
    or Message has_any ("connected", "tunnel established")
| where not(ipv4_is_private(SourceIP))
| project SessionTime = TimeGenerated, SourceIP, DeviceProduct, Activity, DeviceAction, Message, LogSeverity, DestinationIP
| join kind=leftanti (
    AuthEvents
) on SourceIP
    , $left.SessionTime - 5m <= $right.AuthTime
    , $right.AuthTime <= $left.SessionTime
| sort by SessionTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- VPN clients that use certificate-based or SAML authentication may not produce an Activity event matching the auth keyword list, causing legitimate sessions to appear as bypasses.
- Split-tunnel or reconnect scenarios where the session-established event is logged without a new authentication event because the session token is reused.
- Internal gateway health-check or keepalive sessions from RFC1918 addresses are excluded by the SourceIP filter but non-RFC1918 monitoring infrastructure may still generate matches.

Tuning notes:
- Run distinct Activity and Message value queries against CommonSecurityLog filtered to DeviceVendor 'Palo Alto Networks' to enumerate all actual event type strings before deploying.
- Add known VPN gateway or concentrator internal IPs to a SourceIP exclusion if internal health-check sessions generate false positives.
- If the leftanti with inequality join predicates is not supported in the target Sentinel workspace version, restructure using: join the session events to a summarized auth lookup table and filter where no auth record falls within the 5-minute pre-session window.
- Adjust the 5-minute pre-session auth window based on observed authentication flow timing in the environment.

Risks / caveats:
- CommonSecurityLog must be populated by a PAN-OS CEF/Syslog connector with DeviceVendor set to 'Palo Alto Networks'; if logs are ingested via a different connector or table (e.g., a custom table or Palo Alto Networks via the dedicated data connector), this query will return no results.
- The Activity and Message field values for GlobalProtect session-established and authentication events vary by PAN-OS firmware version and log verbosity configuration; the keyword lists in this query must be validated against actual ingested log samples before deployment.
- The leftanti join as written suppresses any session alert if a matching SourceIP auth event exists anywhere in the 1-day lookback window, not within a bounded window relative to the session event — this means a morning auth event will suppress an afternoon bypass session from the same IP, producing false negatives.
- The Activity and Message keyword lists for both session and auth events must be validated against actual PAN-OS log samples in the environment before this rule produces reliable results; incomplete auth keyword coverage will cause false positives.

### Triage Runbook

First 15 minutes:
- Confirm the affected gateway, device product, and whether the session source IP is external and unexpected.
- Review the raw Activity, Message, DeviceAction, and LogSeverity fields to verify that the event is truly a session establishment and not a different GlobalProtect message.
- Check whether a corresponding authentication event exists within the five minutes before the session from the same SourceIP.
- Validate whether the source IP is associated with a known user, VPN concentrator, or monitoring system.
- Determine whether other sessions from the same SourceIP or to the same gateway occurred around the same time.

Evidence to collect:
- SessionTime, SourceIP, DestinationIP, DeviceProduct, Activity, DeviceAction, Message, and LogSeverity from the alert.
- Any authentication-related CommonSecurityLog entries from the same SourceIP in the five minutes before the session.
- Gateway hostname or IP and the PAN-OS firmware/version if available from asset inventory.
- User identity or certificate/SAML context if present in adjacent logs.
- Other security logs showing failed logins, repeated session attempts, or unusual geolocation for the SourceIP.

Pivot points:
- CommonSecurityLog for the same SourceIP, DestinationIP, and DeviceProduct over the last 24 hours.
- CommonSecurityLog for authentication-related Activity and Message values to confirm the environment’s actual log strings.
- Firewall, VPN, and identity logs to correlate the session with user authentication or certificate issuance.
- Asset inventory or CMDB to identify the gateway version and exposure status.
- Threat intelligence or geolocation lookups for the SourceIP if it is external and not recognized.

Benign explanations:
- Certificate-based or SAML-based VPN flows may not emit an auth keyword that matches the rule.
- Session reuse or reconnect behavior can produce a session-established event without a fresh authentication event.
- Logging gaps, connector misconfiguration, or incomplete keyword mapping can make legitimate sessions appear unauthenticated.
- Internal health-check or monitoring traffic may be misclassified if the source is not RFC1918 but still trusted.

Escalation criteria:
- The session is from an unknown external IP and no valid authentication event exists in the expected pre-session window.
- Multiple session-established events occur from the same source without corresponding authentication, suggesting active exploitation.
- The gateway is internet-facing and known to be vulnerable or unpatched for CVE-2026-0257.
- There are signs of post-authentication abuse such as unusual VPN activity, lateral movement, or access to internal resources.
- The same source IP targets multiple gateways or customers, indicating broad exploitation activity.

Containment actions:
- If exploitation is likely, disable or restrict the affected gateway or apply vendor mitigation guidance immediately.
- Block the source IP at the perimeter if it is clearly malicious and not a legitimate user or service.
- Force reauthentication or revoke active VPN sessions associated with the suspicious source if supported by the platform.
- Accelerate patching or configuration changes for the affected PAN-OS/GlobalProtect environment.
- Preserve logs and configuration state before making changes if incident response or legal review is expected.

Closure criteria:
- A valid authentication event is found within the expected window and the session is confirmed legitimate.
- The event is explained by known logging behavior, certificate/SAML flow, or connector keyword mismatch.
- No additional suspicious sessions or follow-on activity are observed from the source IP.
- The environment mapping issue is documented and the detection is tuned or corrected.
- If the session was malicious, containment and remediation steps are completed and tracked.

---

## Detection 4: NetSupport RAT Process Execution with Outbound C2 Beaconing

### Detection Opportunity

NetSupport RAT client process executing on a Windows endpoint and establishing outbound network connections consistent with C2 beaconing

### Intelligence Context

- SANS ISC: Unidentified RAT pushes NetSupport RAT, (Mon, Jun 1st) — [https://isc.sans.edu/diary/rss/33034](https://isc.sans.edu/diary/rss/33034)
  - Context: An unidentified threat actor delivered NetSupport RAT to Windows endpoints. NetSupport RAT uses the legitimate NetSupport Manager client binary (client32.exe) repurposed for unauthorized remote access and C2 communication.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071.001, T1095, T1071
- Products: Not specified
- Platforms: Windows
- Malware: NetSupport RAT
- Tools: Not specified
- Search tags: Windows, NetSupport RAT, T1071.001, T1095, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Command and Control: T1095 Non-Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let NetSupportExec = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "client32.exe"
| where FolderPath !startswith @"C:\Program Files\NetSupport"
| where FolderPath !startswith @"C:\Program Files (x86)\NetSupport"
| project ExecTime = Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine;
let NetSupportNet = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "client32.exe"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project NetTime = Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, RemotePort;
NetSupportExec
| join kind=leftouter NetSupportNet on DeviceName, AccountName
| where isnotempty(RemoteIP)
| where (NetTime - ExecTime) between (0min .. 10min)
| project ExecTime, NetTime, DeviceName, AccountName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort
| sort by ExecTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Environments where NetSupport Manager is legitimately deployed to non-standard paths (e.g., user profile directories or custom enterprise paths) will generate false positives until those paths are added to the FolderPath exclusion.
- Penetration testing or red team exercises using NetSupport Manager as a legitimate remote access tool.
- Software packaging or repackaging workflows that extract client32.exe to a temp directory before installation.

Tuning notes:
- Run a baseline query for all client32.exe FolderPath values in DeviceProcessEvents before scheduling to identify legitimate deployment paths and add them to the exclusion list.
- Consider restricting the query to device groups known to not have authorized NetSupport Manager deployments to reduce volume.
- Adjust the 10-minute correlation window based on observed NetSupport RAT beaconing intervals if threat intelligence becomes available.
- If promoting to a scheduled rule, reduce the lookback from 7 days to 1 day and set the rule frequency to match.

Risks / caveats:
- ipv4_is_private() does not evaluate IPv6 addresses; C2 connections over IPv6 will not be filtered or detected by the RemoteIP check.
- DeviceNetworkEvents attributes network connections to the process that opened the socket; if client32.exe uses a helper process or injects into another process for network activity, the InitiatingProcessFileName filter will not match.
- The 10-minute correlation window between process execution and outbound connection may miss slow-beaconing C2 configurations or catch unrelated node.exe connections in busy environments.
- The FolderPath exclusion covers only the two default NetSupport Manager installation paths; environments with custom deployment paths will generate false positives until those paths are added.

### Triage Runbook

First 15 minutes:
- Verify the host role and whether NetSupport Manager is officially deployed on the endpoint or device group.
- Review FolderPath and ProcessCommandLine to determine whether client32.exe is running from a standard installation path or an unusual location.
- Inspect RemoteIP, RemoteUrl, and RemotePort to see whether the connection is external and whether the port is consistent with remote access tooling.
- Check whether the process was launched by a user, installer, service, or another suspicious parent process.
- Look for additional signs of remote control activity such as repeated beaconing, persistence, or other suspicious child processes.

Evidence to collect:
- ExecTime, NetTime, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, and InitiatingProcessCommandLine.
- RemoteIP, RemoteUrl, and RemotePort for the outbound connection.
- Any other DeviceProcessEvents showing client32.exe execution history on the same host.
- Any DeviceNetworkEvents showing repeated connections from client32.exe or related processes.
- Endpoint inventory or software deployment records confirming whether NetSupport is authorized on the device.

Pivot points:
- DeviceProcessEvents for client32.exe across the environment to identify other affected hosts and paths.
- DeviceNetworkEvents for client32.exe to identify all external destinations and beaconing patterns.
- DeviceLogonEvents to determine whether the account is interactive, privileged, or service-based.
- DeviceFileEvents to look for dropped installers, persistence artifacts, or renamed copies of client32.exe.
- Proxy, firewall, or DNS logs to validate whether the destination is a known remote support server or suspicious external host.

Benign explanations:
- NetSupport Manager may be legitimately installed for remote administration in some environments.
- Authorized remote support tools can generate outbound connections that resemble beaconing.
- Software packaging or repackaging workflows may temporarily execute client32.exe from a staging directory.
- Penetration testing or red team exercises may intentionally use NetSupport Manager.

Escalation criteria:
- client32.exe is running from a non-standard path or on a host where NetSupport is not approved.
- The outbound destination is external and not a known corporate remote support server.
- There are signs of persistence, repeated beaconing, or additional suspicious activity on the host.
- Multiple endpoints show the same pattern, suggesting a broader intrusion or unauthorized remote access tool deployment.
- The process is associated with user activity that does not align with approved remote support operations.

Containment actions:
- If unauthorized, isolate the host to stop remote access and preserve evidence.
- Terminate the suspicious client32.exe process if containment is required and approved by incident response.
- Block the external IP or domain if it is confirmed malicious and not a legitimate support endpoint.
- Remove unauthorized NetSupport artifacts and investigate persistence locations after evidence capture.
- Reset credentials or revoke sessions if the tool may have been used for unauthorized access.

Closure criteria:
- NetSupport is confirmed as an approved tool on the host and the path, parent process, and destination are legitimate.
- The outbound destination is verified as a sanctioned remote support server.
- No persistence, unauthorized access, or additional affected hosts are found.
- Any non-standard but approved deployment paths are documented and added to tuning.
- The analyst records the rationale for closure and any follow-up monitoring needed.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- NPM Post-Install Script Spawning Reconnaissance Commands: Do not schedule yet; validate as an analyst-led hunt first.
- NPM Install Followed by Outbound Network Connection to External Host: Do not schedule yet; validate as an analyst-led hunt first.

Telemetry availability:
- GlobalProtect VPN Session Established Without Prior Authentication Event (CVE-2026-0257): CommonSecurityLog must be populated by a PAN-OS CEF/Syslog connector with DeviceVendor set to 'Palo Alto Networks'; if logs are ingested via a different connector or table (e.g., a custom table or Palo Alto Networks via the dedicated data connector), this query will return no results.

Shared-table notes:
- DeviceProcessEvents: shared by NPM Post-Install Script Spawning Reconnaissance Commands; NPM Install Followed by Outbound Network Connection to External Host; NetSupport RAT Process Execution with Outbound C2 Beaconing
- DeviceNetworkEvents: shared by NPM Post-Install Script Spawning Reconnaissance Commands; NPM Install Followed by Outbound Network Connection to External Host; NetSupport RAT Process Execution with Outbound C2 Beaconing

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: NetSupport RAT Process Execution with Outbound C2 Beaconing.
2. Resolve environment-mapping detections next: GlobalProtect VPN Session Established Without Prior Authentication Event (CVE-2026-0257).
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: NPM Post-Install Script Spawning Reconnaissance Commands; NPM Install Followed by Outbound Network Connection to External Host.

### Hunting Agenda and Promotion Criteria

- NPM Post-Install Script Spawning Reconnaissance Commands: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- NPM Install Followed by Outbound Network Connection to External Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- GlobalProtect VPN Session Established Without Prior Authentication Event (CVE-2026-0257): CommonSecurityLog must be populated by a PAN-OS CEF/Syslog connector with DeviceVendor set to 'Palo Alto Networks'; if logs are ingested via a different connector or table (e.g., a custom table or Palo Alto Networks via the dedicated data connector), this query will return no results.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
