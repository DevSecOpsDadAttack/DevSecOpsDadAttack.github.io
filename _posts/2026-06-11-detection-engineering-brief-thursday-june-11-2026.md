---
layout: post
title: "Detection Engineering Brief - Thursday, June 11, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-11
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-10523
  - T1190
  - Ivanti Sentry
  - MobileIron Sentry
  - CVE-2026-10520
  - T1059
  - cloud
  - T1136
  - T1136.001
  - T1562
  - T1562.008
---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-10523, T1190, Ivanti Sentry, MobileIron Sentry, CVE-2026-10520, T1059, cloud, T1136, T1136.001, T1562, T1562.008.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Ivanti Sentry - Unauthenticated Admin Account Creation via CVE-2026-10523; Ivanti Sentry - Root-Level Command Execution Following Unauthenticated Request via CVE-2026-10520; Ivanti Sentry - Compound: Admin Account Creation Followed by Root Command Execution; Azure - Diagnostic Settings or Log Profile Deleted Outside Change Window Correlated with Subsequent Resource Access.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Ivanti Sentry - Unauthenticated Admin Account Creation via CVE-2026-10523

### Detection Opportunity

Remote unauthenticated attacker creates arbitrary administrative accounts on Ivanti Sentry via authentication bypass.

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: CVE-2026-10523 is an authentication bypass allowing a remote unauthenticated attacker to create arbitrary administrative accounts on Ivanti Sentry, granting full administrative access without prior credentials.

### Search Metadata

- CVEs: CVE-2026-10523
- Threat actors: Not specified
- ATT&CK tags: T1190, T1136, T1136.001, T1059
- Products: Ivanti Sentry, MobileIron Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10523, T1190, Ivanti Sentry, MobileIron Sentry, T1136, T1136.001, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Persistence: T1136 Create Account/ T1136.001 Local Account (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

Required telemetry:
- Syslog

### KQL

```kql
let lookback = 1h;
let accountCreationKeywords = dynamic(["account created", "admin account", "user added", "useradd", "adduser", "new administrative"]);
let authKeywords = dynamic(["authenticated", "login success", "session opened"]);
let creationEvents = Syslog
    | where TimeGenerated > ago(lookback)
    | where HostName has_any ("sentry", "mobileiron")
    | where SyslogMessage has_any (accountCreationKeywords)
    | extend SourceIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage);
let authEvents = Syslog
    | where TimeGenerated > ago(lookback)
    | where HostName has_any ("sentry", "mobileiron")
    | where SyslogMessage has_any (authKeywords)
    | extend SourceIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
    | where isnotempty(SourceIP)
    | project HostName, SourceIP;
creationEvents
| join kind=leftanti authEvents on HostName, SourceIP
| project TimeGenerated, HostName, ProcessName, SyslogMessage, SourceIP
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate administrative account provisioning performed by an admin who authenticated via a path not captured in Syslog (e.g., console, SSH key) will appear as unauthenticated.
- Automated provisioning scripts that create accounts without a preceding Syslog authentication event will trigger the rule.
- Any Linux host whose hostname contains 'sentry' or 'mobileiron' that runs useradd or adduser for routine OS operations will match.

Tuning notes:
- Replace the has_any HostName filter with an explicit list of known Sentry appliance hostnames once the environment naming convention is confirmed.
- Validate the exact SyslogMessage strings emitted by the deployed firmware version and update the accountCreationKeywords list accordingly.
- If source IPs are not embedded in Syslog messages, remove the leftanti join and rely solely on keyword matching, accepting higher false positive rates.

Risks / caveats:
- Syslog table requires the Linux Syslog connector or a custom log forwarder configured on Ivanti Sentry appliances; if not deployed, the table will contain no relevant rows.
- SyslogMessage content for admin account creation events is firmware-version-specific; the keyword list may produce zero matches if the appliance uses different log strings.
- SourceIP is extracted via regex from free-text SyslogMessage; if Sentry does not embed source IPs in account creation log lines, the leftanti join will silently exclude all events, producing no results.
- The 1-hour lookback window may miss slow-burn attacks where authentication and account creation are separated by more than an hour.

### Triage Runbook

First 15 minutes:
- Confirm the alerting host is a real Ivanti Sentry or MobileIron Sentry appliance, not a generic Linux host with a matching hostname.
- Review the SyslogMessage for the exact account creation text, created username, source IP if present, and any preceding authentication or admin activity.
- Check whether the account is expected, recently approved, or created during a maintenance window; validate with the platform owner or change records.
- Look for additional Sentry alerts or logs around the same time indicating login, privilege use, configuration changes, or command execution.

Evidence to collect:
- TimeGenerated, HostName, ProcessName, SyslogMessage, and extracted SourceIP from the alert.
- Any nearby Syslog entries showing authentication, session start, admin login, or account management actions on the same host.
- The created account name, role/privilege level, and whether it is local to the appliance.
- Any correlated management-plane or network logs showing access to the appliance from the same source IP or from unusual geographies.

Pivot points:
- Syslog for the same HostName over the last 24 hours to find account creation, authentication, and command execution activity.
- Azure/identity or VPN logs if the appliance is managed through a jump host or admin network to identify the operator behind the source IP.
- Firewall/proxy logs for inbound connections to the appliance during the alert window.
- Any EDR or host telemetry available for the appliance if it forwards process or audit logs beyond Syslog.

Benign explanations:
- Planned administrative provisioning of a new local account by an authorized operator.
- Automated onboarding or configuration scripts that create accounts without a preceding Syslog authentication event.
- Firmware-specific logging gaps that make a legitimate authenticated action appear unauthenticated in Syslog.

Escalation criteria:
- The created account is unknown, unapproved, or has administrative privileges.
- There is no matching authorized change record and the source IP is external or otherwise suspicious.
- You find follow-on activity such as root command execution, configuration tampering, or additional new accounts on the same appliance.
- The appliance is internet-facing and the event occurred outside a maintenance window.

Containment actions:
- Disable or remove the newly created account if it is unauthorized and you have confirmed it is not needed for recovery.
- Isolate the appliance from external access where feasible, or restrict management access to trusted admin networks while preserving evidence.
- Force credential rotation for any accounts that may have been exposed through the appliance, especially privileged local accounts.
- Preserve Syslog and appliance configuration backups before making changes.

Closure criteria:
- The account is verified as legitimate and tied to an approved change or maintenance activity.
- No follow-on suspicious activity is found on the appliance or related admin infrastructure.
- The appliance owner confirms the event matches expected provisioning behavior and the logs support that conclusion.
- Any unauthorized account has been removed and the incident has been handed off for remediation if needed.

---

## Detection 2: Ivanti Sentry - Root-Level Command Execution Following Unauthenticated Request via CVE-2026-10520

### Detection Opportunity

Remote unauthenticated command injection on Ivanti Sentry results in root-level process execution spawned from the web service process.

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: CVE-2026-10520 is an OS command injection vulnerability allowing a remote unauthenticated attacker to achieve remote code execution with root privileges on Ivanti Sentry. Exploitation would manifest as unexpected shell or system commands spawned from the Sentry web service process.

### Search Metadata

- CVEs: CVE-2026-10520
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1136, T1136.001
- Products: Ivanti Sentry, MobileIron Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10520, T1190, T1059, Ivanti Sentry, MobileIron Sentry, T1136, T1136.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Persistence: T1136 Create Account/ T1136.001 Local Account (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

Required telemetry:
- Syslog

### KQL

```kql
let lookback = 1h;
let suspiciousProcesses = dynamic(["sh", "bash", "python", "python3", "curl", "wget", "chmod", "nc", "ncat", "perl", "ruby", "base64"]);
let sentryProcesses = dynamic(["mics", "tomcat", "java", "httpd", "nginx", "sentry"]);
Syslog
| where TimeGenerated > ago(lookback)
| where HostName has_any ("sentry", "mobileiron")
| where ProcessName has_any (sentryProcesses) or SyslogMessage has_any (sentryProcesses)
| where SyslogMessage has_any (suspiciousProcesses)
| extend ExtractedCommand = coalesce(
    extract(@"\b(sh|bash|python3?|curl|wget|chmod|nc|ncat|perl|ruby|base64)\b", 1, SyslogMessage),
    ""
  )
| project TimeGenerated, HostName, ProcessName, SyslogMessage, ExtractedCommand
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate administrative shell sessions on the Sentry appliance by authorized administrators will match if the session is logged via syslog.
- Routine cron jobs or health-check scripts invoking curl, wget, or bash on the appliance will trigger the rule.
- Any Linux host whose hostname contains 'sentry' or 'mobileiron' running standard shell utilities will match.

Tuning notes:
- Query the Syslog table for the target Sentry host and review distinct ProcessName values before deploying to confirm which process names are actually emitted.
- If the appliance does not log child process names, consider enabling auditd or equivalent OS-level logging on the Sentry appliance and forwarding those logs.
- Replace the HostName has_any filter with an explicit hostname list once Sentry appliance names are confirmed.

Risks / caveats:
- Syslog table requires the Linux Syslog connector or a custom log forwarder configured on Ivanti Sentry appliances; if not deployed, the table will contain no relevant rows.
- Ivanti Sentry may not emit Syslog messages containing child process execution context from the web service; if process-level logging is not enabled on the appliance, this query will produce no results.
- The sentryProcesses list (mics, tomcat, java, httpd, nginx, sentry) is assumed; the actual ProcessName values in Syslog depend on the firmware version and must be confirmed.
- Short process names like 'sh', 'nc', and 'perl' are common substrings in legitimate log messages; the has_any filter may produce false positives even with word-boundary regex on ExtractedCommand.

### Triage Runbook

First 15 minutes:
- Validate the host is a real Ivanti Sentry or MobileIron Sentry appliance and not an unrelated Linux system.
- Inspect the SyslogMessage and ExtractedCommand for the exact command, parent process context, and any signs of shell spawning or download activity.
- Check whether the command is expected for appliance maintenance, patching, or health checks; confirm with the platform owner if needed.
- Search for nearby signs of post-exploitation such as new accounts, outbound connections, file changes, or repeated command execution.

Evidence to collect:
- TimeGenerated, HostName, ProcessName, SyslogMessage, and ExtractedCommand from the alert.
- Any adjacent Syslog entries showing web-service activity, authentication bypass indicators, or repeated command execution.
- Process lineage or audit details if available from the appliance, especially the web service process that spawned the command.
- Network telemetry showing outbound connections from the appliance to unusual IPs, domains, or ports around the alert time.

Pivot points:
- Syslog on the same HostName for the prior and subsequent 24 hours to identify command sequences and account changes.
- Firewall, proxy, or DNS logs for outbound traffic from the appliance after the alert time.
- Any appliance-specific audit or process logs that can confirm child process creation from the web service.
- Change-management records to verify whether the command matches a planned administrative action.

Benign explanations:
- Authorized administrative shell activity or vendor-supported maintenance on the appliance.
- Routine cron, health-check, or update scripts invoking shell utilities.
- Logging artifacts from normal appliance operations that resemble command execution but are not attacker-driven.

Escalation criteria:
- The command is clearly malicious, such as downloading tools, spawning a shell, changing permissions, or creating persistence.
- You observe outbound connections, file drops, or additional suspicious commands after the initial event.
- The command was executed outside a maintenance window and no approved change explains it.
- There is evidence the web service process spawned the command without an authenticated admin session.

Containment actions:
- If compromise is likely, isolate the appliance from the network or restrict inbound management access while preserving logs.
- Block suspicious outbound destinations observed from the appliance.
- Rotate credentials and revoke sessions for any accounts that may have been used on or through the appliance.
- Preserve volatile evidence and coordinate with the appliance owner before rebooting or patching.

Closure criteria:
- The command is confirmed as legitimate maintenance or vendor activity.
- No additional suspicious process, network, or account activity is found on the appliance.
- The alert is attributable to expected appliance behavior or a known false-positive pattern.
- Any required remediation has been completed and the appliance is monitored for recurrence.

---

## Detection 3: Ivanti Sentry - Compound: Admin Account Creation Followed by Root Command Execution

### Detection Opportunity

Chained exploitation of Ivanti Sentry: unauthenticated admin account creation (CVE-2026-10523) followed by root-level command execution (CVE-2026-10520) on the same host within a short time window.

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: Rapid7 disclosed two critical vulnerabilities affecting Ivanti Sentry: CVE-2026-10523 enables unauthenticated admin account creation and CVE-2026-10520 enables unauthenticated OS command injection for root RCE. An attacker chaining both on the same appliance within a short window represents full compromise.

### Search Metadata

- CVEs: CVE-2026-10520, CVE-2026-10523
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1136, T1136.001
- Products: Ivanti Sentry, MobileIron Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10520, CVE-2026-10523, T1190, T1059, Ivanti Sentry, MobileIron Sentry, T1136, T1136.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Persistence: T1136 Create Account/ T1136.001 Local Account (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Both account creation and command execution Syslog message formats are firmware-specific; if either pattern does not match actual log output, the correlation produces no results.
- Both underlying signal patterns share the same firmware-specific log format dependency; if either is misconfigured, the correlation silently produces no results.

Required telemetry:
- Syslog

### KQL

```kql
let lookback = 2h;
let correlationWindow = 30m;
let accountCreationKeywords = dynamic(["account created", "admin account", "user added", "useradd", "adduser", "new administrative"]);
let cmdKeywords = dynamic(["sh", "bash", "python", "curl", "wget", "chmod", "nc", "perl"]);
let accountCreation = Syslog
    | where TimeGenerated > ago(lookback)
    | where isnotempty(HostName)
    | where HostName has_any ("sentry", "mobileiron")
    | where SyslogMessage has_any (accountCreationKeywords)
    | project CreationTime = TimeGenerated, HostName, CreationMsg = SyslogMessage;
let cmdExecution = Syslog
    | where TimeGenerated > ago(lookback)
    | where isnotempty(HostName)
    | where HostName has_any ("sentry", "mobileiron")
    | where SyslogMessage has_any (cmdKeywords)
    | project ExecTime = TimeGenerated, HostName, ExecMsg = SyslogMessage, ProcessName;
accountCreation
| join kind=inner cmdExecution on HostName
| where ExecTime >= CreationTime and ExecTime <= CreationTime + correlationWindow
| extend TimeDeltaMinutes = datetime_diff('minute', ExecTime, CreationTime)
| project CreationTime, ExecTime, TimeDeltaMinutes, HostName, ProcessName, CreationMsg, ExecMsg
| order by CreationTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate admin provisioning of a new account followed by a routine shell script execution on the same appliance within 30 minutes will trigger the rule.
- Automated configuration management tools that create accounts and then run shell commands as part of a deployment pipeline will match.

Tuning notes:
- Validate each subquery independently against live Syslog data before enabling the full correlation.
- Replace HostName has_any with an explicit list of confirmed Sentry appliance hostnames to eliminate noise from unrelated Linux hosts.
- Adjust correlationWindow based on observed attacker tempo once the individual detections are validated.

Risks / caveats:
- Syslog table requires the Linux Syslog connector or a custom log forwarder configured on Ivanti Sentry appliances; if not deployed, both subqueries return empty results.
- Both account creation and command execution Syslog message formats are firmware-specific; if either pattern does not match actual log output, the correlation produces no results.
- The between operator on TimeGenerated in a join context requires CreationTime to precede ExecTime; if timestamps are out of order due to ingestion delay, valid attack chains may be missed.
- Ingestion delay between the two Syslog events could cause the time-window join to miss valid attack chains if one event is delayed beyond the correlation window.

### Triage Runbook

First 15 minutes:
- Treat the alert as a likely compromise and verify both stages occurred on the same appliance within the stated time window.
- Review CreationMsg and ExecMsg to identify the created account, the executed command, and whether the sequence is consistent with exploitation.
- Check whether the account creation and command execution came from the same source IP or external network and whether either event is expected.
- Look for immediate post-compromise behavior such as additional logins, configuration changes, outbound connections, or new accounts.

Evidence to collect:
- CreationTime, ExecTime, TimeDeltaMinutes, HostName, ProcessName, CreationMsg, and ExecMsg.
- The created account name, privilege level, and whether it was used after creation.
- Any source IPs, session identifiers, or adjacent authentication events tied to the same host.
- Network and DNS telemetry showing outbound activity from the appliance after the command execution.

Pivot points:
- Syslog for the same HostName over at least 24 hours to reconstruct the full sequence of account creation, login, and command execution.
- Firewall, proxy, and DNS logs for outbound connections from the appliance after the first event.
- Any available appliance audit logs or management logs that show configuration changes or admin session activity.
- Identity or jump-host logs if administrators normally access the appliance through a bastion or VPN.

Benign explanations:
- A legitimate admin created an account and then ran a maintenance command within the same window.
- Automation or configuration management created an account and executed a shell command as part of deployment.
- Log format or ingestion delay caused unrelated events to appear correlated when they were not.

Escalation criteria:
- Both events are confirmed and no approved change explains them.
- The created account is unknown, privileged, or used for further activity.
- The executed command is malicious or indicates persistence, tool staging, or system tampering.
- There is any evidence of external attacker access, especially from an internet-facing appliance.

Containment actions:
- Isolate the appliance or severely restrict access if compromise is plausible.
- Disable the unauthorized account and revoke any related sessions or credentials.
- Block suspicious outbound traffic and preserve logs before any reboot or patching.
- Coordinate emergency response with the appliance owner and infrastructure team because this may indicate full appliance compromise.

Closure criteria:
- Both events are explained by an approved change, vendor action, or known automation.
- No additional suspicious activity is found on the appliance or related admin infrastructure.
- The created account and command are validated as legitimate and documented.
- Any unauthorized access has been contained and remediated.

---

## Detection 4: Azure - Logging Configuration Disabled or Deleted by Non-Automated Identity

### Detection Opportunity

Adversary manipulates Azure logging configuration by deleting or disabling diagnostic settings or log profiles to reduce defender visibility.

### Intelligence Context

- Unit 42: Blinding the Watchmen: Abusing Cloud Logging Services for Defense Evasion and Visibility — [https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/](https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/)
  - Context: Unit 42 research describes adversaries targeting cloud logging services to achieve defense evasion by manipulating logging configuration, disrupting log delivery, and reducing defender visibility. In Azure, this manifests as deletion or disabling of diagnostic settings, log analytics workspaces, or audit log policies.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1562, T1562.008
- Products: Not specified
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud, T1562, T1562.008

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Defense Evasion: T1562 Impair Defenses/ T1562.008 Disable or Modify Cloud Logs (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- AzureActivity

### KQL

```kql
let lookback = 1d;
let loggingOperations = dynamic([
    "microsoft.insights/diagnosticsettings/delete",
    "microsoft.insights/logprofiles/delete",
    "microsoft.operationalinsights/workspaces/delete",
    "microsoft.insights/diagnosticsettings/write",
    "microsoft.operationalinsights/workspaces/write",
    "microsoft.insights/logprofiles/write"
]);
let guidPattern = @"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$";
AzureActivity
| where TimeGenerated > ago(lookback)
| where tolower(OperationName) in (loggingOperations)
| where ActivityStatus in ("Succeeded", "Success")
| where not(Caller matches regex guidPattern)
| project TimeGenerated, OperationName, Caller, CallerIpAddress, ResourceId, ResourceGroup, ActivityStatus
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate infrastructure engineers deleting and recreating diagnostic settings during planned maintenance or IaC deployments will trigger the rule.
- Log Analytics workspace deletions performed by authorized cloud administrators during decommissioning will match.
- Write operations on diagnostic settings that represent updates rather than disablement will appear in results.

Tuning notes:
- Build an allowlist of known automation service principal display names or UPNs used by IaC pipelines and add a 'where Caller !in (allowlist)' clause after deployment.
- To reduce false positives from write operations, parse the Properties field for indicators that a diagnostic setting was set to 'disabled' or had all log categories removed, if the Properties column is populated in the environment.
- Consider splitting delete and write operations into separate rules with different severities: delete operations are higher confidence than write operations.

Risks / caveats:
- AzureActivity requires the Azure Activity diagnostic connector to be enabled and connected to the Sentinel workspace; if not configured, the table will be empty.
- Write operations on diagnostic settings include both disablement and legitimate reconfiguration; without parsing the Properties field to confirm a setting was disabled, write-based alerts will have higher false positive rates.
- Service principals using certificate-based authentication may appear with non-GUID Caller values (e.g., app display names), causing them to pass the GUID exclusion filter.
- The 1-day lookback window means the rule runs once per day by default; for near-real-time detection, reduce the lookback and schedule frequency accordingly.

### Triage Runbook

First 15 minutes:
- Identify the caller and confirm whether it is a human user, not a service principal or automation identity.
- Review the exact operation name, target resource, and activity status to see whether logging was deleted, disabled, or merely updated.
- Check for a matching change ticket, deployment window, or approved infrastructure-as-code activity.
- Look for other suspicious AzureActivity events from the same caller around the same time, especially privilege changes or resource access.

Evidence to collect:
- TimeGenerated, OperationName, Caller, CallerIpAddress, ResourceId, ResourceGroup, and ActivityStatus.
- Any Properties or related activity details that show whether diagnostic settings, log profiles, or workspace links were removed or disabled.
- The caller’s identity type, associated subscription, and whether the IP is expected for that user or automation.
- Nearby AzureActivity events from the same caller showing role changes, resource enumeration, or access to sensitive resources.

Pivot points:
- AzureActivity for the same Caller over the last 24 hours to identify related changes and access patterns.
- Azure AD sign-in logs for the Caller to validate the session origin, device, and MFA status.
- Resource-specific activity or control-plane logs for the affected subscription or resource group.
- Change-management or IaC pipeline records to confirm whether the action was authorized.

Benign explanations:
- Planned maintenance, decommissioning, or logging reconfiguration by a cloud administrator.
- Infrastructure-as-code deployment that recreated or updated diagnostic settings.
- Authorized cleanup of obsolete log profiles or workspaces.

Escalation criteria:
- The caller is unknown, unexpected, or operating from an unusual IP or location.
- The logging change was not approved and appears intended to reduce visibility.
- The action is followed by other suspicious Azure control-plane activity from the same identity.
- Multiple logging-related resources were disabled or deleted in a short period.

Containment actions:
- If unauthorized, disable the caller account or revoke its sessions and tokens.
- Restore logging configuration as soon as evidence is preserved and the change is confirmed malicious.
- Increase monitoring on the affected subscription or resource group until the incident is resolved.
- Preserve AzureActivity and sign-in logs before making corrective changes.

Closure criteria:
- A valid change record or automation explains the logging modification.
- The caller is confirmed as an authorized identity and the action matches expected maintenance.
- No additional suspicious activity is found from the same identity or IP.
- Logging has been restored or the change is otherwise documented and accepted by the owner.

---

## Detection 5: Azure - Diagnostic Settings or Log Profile Deleted Outside Change Window Correlated with Subsequent Resource Access

### Detection Opportunity

Suspicious deletion or disruption of Azure logging configuration followed by resource access activity, consistent with an attacker blinding defenders before further action.

### Intelligence Context

- Unit 42: Blinding the Watchmen: Abusing Cloud Logging Services for Defense Evasion and Visibility — [https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/](https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/)
  - Context: Unit 42 describes adversaries disrupting cloud log delivery as a precursor to further malicious activity, specifically to reduce defender visibility before conducting follow-on actions. Detecting the logging disruption correlated with subsequent resource operations by the same caller strengthens the signal beyond a standalone config change.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1562, T1562.008
- Products: Not specified
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud, T1562, T1562.008

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1562 Impair Defenses/ T1562.008 Disable or Modify Cloud Logs (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- AzureActivity

### KQL

```kql
let lookback = 4h;
let followOnWindow = 60m;
let deletionOps = dynamic([
    "microsoft.insights/diagnosticsettings/delete",
    "microsoft.insights/logprofiles/delete",
    "microsoft.operationalinsights/workspaces/delete"
]);
let loggingDeletions = AzureActivity
    | where TimeGenerated > ago(lookback)
    | where tolower(OperationName) in (deletionOps)
    | where ActivityStatus in ("Succeeded", "Success")
    | project DeletionTime = TimeGenerated, Caller, DeletedResource = ResourceId, CallerIpAddress;
let followOnActivity = AzureActivity
    | where TimeGenerated > ago(lookback)
    | where ActivityStatus in ("Succeeded", "Success")
    | where tolower(OperationName) !in (deletionOps)
    | summarize FollowOnTime = min(TimeGenerated), FollowOnOperation = take_any(OperationName), FollowOnResource = take_any(ResourceId) by Caller, bin(TimeGenerated, 1m)
    | project FollowOnTime, Caller, FollowOnResource, FollowOnOperation;
loggingDeletions
| join kind=inner followOnActivity on Caller
| where FollowOnTime >= DeletionTime and FollowOnTime <= DeletionTime + followOnWindow
| where FollowOnResource != DeletedResource
| extend TimeDeltaMinutes = datetime_diff('minute', FollowOnTime, DeletionTime)
| project DeletionTime, FollowOnTime, TimeDeltaMinutes, Caller, CallerIpAddress, DeletedResource, FollowOnResource, FollowOnOperation
| order by DeletionTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Any active Azure administrator who deletes a diagnostic setting during routine maintenance and then performs any other Azure operation within 60 minutes will trigger the rule.
- IaC deployment pipelines that delete and recreate diagnostic settings as part of a deployment sequence will match.
- Automated remediation scripts that delete misconfigured logging resources and then access other resources will match.

Tuning notes:
- Shorten followOnWindow to 15 minutes to reduce coincidental matches from routine admin activity.
- Add a Caller exclusion list for known IaC service principals and automation accounts that legitimately delete and recreate diagnostic settings.
- Consider adding a CallerIpAddress consistency check (require the same IP for both events) to strengthen the signal that the same session performed both actions.
- This query is best used as a hunting query run on-demand or on a long schedule (e.g., daily) rather than as a high-frequency scheduled alert until baselining is complete.

Risks / caveats:
- AzureActivity requires the Azure Activity diagnostic connector to be enabled and connected to the Sentinel workspace; if not configured, the table will be empty.
- The join on Caller alone without additional context (e.g., same session, same IP) means any coincidental activity by the same identity within 60 minutes will match, producing high false positive volume in active environments.
- The summarize in followOnActivity reduces row explosion but may collapse multiple distinct follow-on operations into one, reducing analyst visibility into the full activity chain.
- Ingestion delay in AzureActivity (typically 5-15 minutes) may cause the follow-on event to appear before the deletion event in the workspace, causing missed correlations near the window boundary.

### Triage Runbook

First 15 minutes:
- Treat the deletion plus follow-on activity as suspicious until you confirm a legitimate change window.
- Review DeletedResource, FollowOnResource, and FollowOnOperation to understand what was accessed after logging was removed.
- Check whether the same caller and IP are consistent with an approved admin session or automation pipeline.
- Look for additional control-plane actions from the same caller, especially privilege changes, role assignments, or access to sensitive resources.

Evidence to collect:
- DeletionTime, FollowOnTime, TimeDeltaMinutes, Caller, CallerIpAddress, DeletedResource, FollowOnResource, and FollowOnOperation.
- Any AzureActivity details showing whether the deleted logging resource was restored or modified again.
- Azure AD sign-in context for the caller, including MFA, device, location, and session risk if available.
- Resource-specific logs for the follow-on target to determine what was done after logging disruption.

Pivot points:
- AzureActivity for the same Caller and subscription over the prior and subsequent 24 hours.
- Azure AD sign-in logs for the Caller to validate whether the session is expected.
- Activity logs for DeletedResource and FollowOnResource to reconstruct the sequence of actions.
- Any available resource-level logs or Defender for Cloud alerts tied to the follow-on resource.

Benign explanations:
- An administrator deleted a logging resource during planned maintenance and then performed unrelated work in the same session.
- An IaC pipeline or remediation script deleted and recreated logging resources as part of deployment.
- A legitimate cleanup action was followed by normal administrative activity within the same hour.

Escalation criteria:
- The caller is not a known administrator or automation identity.
- The follow-on activity targets sensitive resources or includes privilege escalation, data access, or further defense evasion.
- There is no approved change window or the activity occurred from an unusual IP or location.
- Multiple logging-related deletions or repeated follow-on actions occur in a short period.

Containment actions:
- Revoke the caller’s active sessions or disable the account if malicious intent is likely.
- Restore logging configuration after preserving evidence, and increase monitoring on the affected scope.
- Block or investigate the source IP if it is external or unexpected.
- Escalate to cloud incident response because this pattern can indicate an attacker blinding defenders before deeper compromise.

Closure criteria:
- The deletion and follow-on activity are fully explained by an approved change or automation.
- The caller is confirmed as authorized and the follow-on action is benign.
- No additional suspicious AzureActivity or sign-in behavior is found.
- Logging has been restored or the owner has accepted the documented change.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Ivanti Sentry - Unauthenticated Admin Account Creation via CVE-2026-10523: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.
- Ivanti Sentry - Root-Level Command Execution Following Unauthenticated Request via CVE-2026-10520: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

Other deployment dependency:
- Ivanti Sentry - Compound: Admin Account Creation Followed by Root Command Execution: Both account creation and command execution Syslog message formats are firmware-specific; if either pattern does not match actual log output, the correlation produces no results.
- Ivanti Sentry - Compound: Admin Account Creation Followed by Root Command Execution: Both underlying signal patterns share the same firmware-specific log format dependency; if either is misconfigured, the correlation silently produces no results.

Schema / correlation keys:
- Azure - Diagnostic Settings or Log Profile Deleted Outside Change Window Correlated with Subsequent Resource Access: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- Syslog: shared by Ivanti Sentry - Unauthenticated Admin Account Creation via CVE-2026-10523; Ivanti Sentry - Root-Level Command Execution Following Unauthenticated Request via CVE-2026-10520; Ivanti Sentry - Compound: Admin Account Creation Followed by Root Command Execution
- AzureActivity: shared by Azure - Logging Configuration Disabled or Deleted by Non-Automated Identity; Azure - Diagnostic Settings or Log Profile Deleted Outside Change Window Correlated with Subsequent Resource Access

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Azure - Logging Configuration Disabled or Deleted by Non-Automated Identity.
2. Resolve environment-mapping detections next: Ivanti Sentry - Unauthenticated Admin Account Creation via CVE-2026-10523; Ivanti Sentry - Root-Level Command Execution Following Unauthenticated Request via CVE-2026-10520; Ivanti Sentry - Compound: Admin Account Creation Followed by Root Command Execution.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Azure - Diagnostic Settings or Log Profile Deleted Outside Change Window Correlated with Subsequent Resource Access.

### Hunting Agenda and Promotion Criteria

- Azure - Diagnostic Settings or Log Profile Deleted Outside Change Window Correlated with Subsequent Resource Access: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Ivanti Sentry - Unauthenticated Admin Account Creation via CVE-2026-10523: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Ivanti Sentry - Root-Level Command Execution Following Unauthenticated Request via CVE-2026-10520: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Ivanti Sentry - Compound: Admin Account Creation Followed by Root Command Execution: Both account creation and command execution Syslog message formats are firmware-specific; if either pattern does not match actual log output, the correlation produces no results.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
