---
layout: post
title: "Detection Engineering Brief - Wednesday, June 10, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-10
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-10520
  - CVE-2026-10523
  - T1059
  - Ivanti Sentry
  - MobileIron Sentry
  - T1136
  - T1562.008
  - cloud
  - CVE-2026-0257
  - T1190
  - PAN-OS
  - T1562
---

## Executive Signal

This brief produced 5 detection candidates.

3 production candidates, 0 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-10520, CVE-2026-10523, T1059, Ivanti Sentry, MobileIron Sentry, T1136, T1562.008, cloud, CVE-2026-0257, T1190, PAN-OS, T1562.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Ivanti Sentry - Suspicious Process Spawned from Web Service (CVE-2026-10520 RCE); Ivanti Sentry - Unauthorized Administrative Account Creation (CVE-2026-10523).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Ivanti Sentry - Suspicious Process Spawned from Web Service (CVE-2026-10520 RCE)

### Detection Opportunity

Remote unauthenticated attacker achieves root code execution on Ivanti Sentry appliance via CVE-2026-10520

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: Rapid7 confirmed CVE-2026-10520 allows a remote unauthenticated attacker to achieve RCE with root privileges on Ivanti Sentry. Detection targets anomalous child processes spawned from Sentry web service processes as surfaced via Syslog forwarding from the appliance.

### Search Metadata

- CVEs: CVE-2026-10520, CVE-2026-10523
- Threat actors: Not specified
- ATT&CK tags: T1059, T1136
- Products: Ivanti Sentry, MobileIron Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10520, CVE-2026-10523, T1059, Ivanti Sentry, MobileIron Sentry, T1136

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1136 Create Account (high)

### Deployment Gates

- Syslog connector must be configured to receive forwarded logs from Ivanti Sentry appliances; if not deployed, the table will contain no matching records.

Required telemetry:
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(7d)
| where HostName has_any ("sentry", "mobileiron")
| extend HasWebServiceToken = SyslogMessage has_any ("mics", "tomcat", "java", "httpd", "nginx")
| extend HasShellToken = SyslogMessage has_any ("sh", "bash", "python", "perl", "curl", "wget", "chmod", "useradd", "adduser")
| where HasWebServiceToken == true and HasShellToken == true
| project TimeGenerated, HostName, ProcessName, SyslogMessage, HasWebServiceToken, HasShellToken
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Routine Sentry service startup log lines may contain both web service names and shell interpreter references in informational messages.
- Scheduled maintenance scripts executed by administrators on the appliance will match the shell/interpreter keyword list.
- Log rotation or cron-driven tasks running under the Sentry service account may generate matching syslog entries.

Tuning notes:
- After confirming the syslog message format from Sentry appliances, consider parsing SyslogMessage with extract() or parse_command_line() if structured fields are available.
- If Sentry emits audit events as separate lines per process, consider using a time-window join on HostName to correlate parent and child process log lines instead of single-line co-occurrence.

Risks / caveats:
- Ivanti Sentry syslog format may not emit process-spawn events in a single SyslogMessage line containing both the parent web service name and the child shell/interpreter name simultaneously; if process execution is logged as separate audit records, the co-occurrence filter will produce no results.
- Syslog connector must be configured to receive forwarded logs from Ivanti Sentry appliances; if not deployed, the table will contain no matching records.
- HostName substring filter ('sentry', 'mobileiron') must be replaced with exact appliance hostnames after environment inventory to avoid missing appliances with non-standard naming and to avoid matching unrelated hosts.
- The 7-day lookback is appropriate for hunting but should be reduced to 1 day if promoted to a scheduled rule.

### Triage Runbook

First 15 minutes:
- Confirm the alerted HostName is an actual Ivanti Sentry or MobileIron Sentry appliance in your inventory.
- Review SyslogMessage and ProcessName for a web-service parent spawning a shell, interpreter, downloader, or account-management utility.
- Check whether the timestamp aligns with patching, maintenance, backup, or admin activity on the appliance.
- Look for multiple alerts on the same host or repeated process-spawn patterns within a short window.

Evidence to collect:
- Exact HostName, TimeGenerated, ProcessName, and SyslogMessage from the alert.
- Any nearby syslog entries showing authentication, configuration changes, or new account creation on the same host.
- Appliance version/build and whether CVE-2026-10520/CVE-2026-10523 remediation has been applied.
- Any external source IPs, management access logs, or VPN/admin session records associated with the same time window.

Pivot points:
- Syslog on the same HostName for 24 hours before and after the alert time.
- CommonSecurityLog or appliance management logs for admin logins, config changes, or account creation around the alert.
- Change management or maintenance records for the appliance during the alert window.
- If available, EDR or host telemetry from any management jump host used to administer the appliance.

Benign explanations:
- Planned maintenance or troubleshooting by an administrator on the appliance.
- Routine startup or health-check logging that includes both web-service and shell keywords.
- Log rotation, backup, or cron-driven tasks executed under the appliance service account.

Escalation criteria:
- Any evidence of a shell, downloader, or account-management command executed outside an approved maintenance window.
- Multiple suspicious child processes from the same Sentry web service process or repeated alerts over a short period.
- Any concurrent sign of unauthorized account creation, configuration tampering, or outbound connections from the appliance.
- The appliance is internet-facing and no legitimate explanation is quickly confirmed.

Containment actions:
- If compromise is plausible, isolate the appliance from external access while preserving management connectivity for responders.
- Disable or restrict administrative access paths to the appliance until root cause is understood.
- Preserve syslog, configuration, and appliance state evidence before rebooting or applying disruptive changes.
- Coordinate emergency patching or vendor guidance if exploitation is confirmed or strongly suspected.

Closure criteria:
- The process-spawn event is matched to approved maintenance or a known-good appliance task.
- No additional suspicious syslog activity, account changes, or outbound connections are found in the surrounding window.
- The appliance owner confirms the activity and provides a valid change record.
- The host is verified as non-Sentry or the hostname match is a known benign substring collision.

---

## Detection 2: Ivanti Sentry - Unauthorized Administrative Account Creation (CVE-2026-10523)

### Detection Opportunity

Remote unauthenticated attacker creates arbitrary administrative accounts on Ivanti Sentry via CVE-2026-10523

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: Rapid7 confirmed CVE-2026-10523 allows a remote unauthenticated attacker to create arbitrary administrative accounts on Ivanti Sentry. This is a discrete auditable event detectable via Syslog or CommonSecurityLog forwarded from the appliance.

### Search Metadata

- CVEs: CVE-2026-10520, CVE-2026-10523
- Threat actors: Not specified
- ATT&CK tags: T1136
- Products: Ivanti Sentry, MobileIron Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10520, CVE-2026-10523, T1136, Ivanti Sentry, MobileIron Sentry

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1136 Create Account (high)

### Deployment Gates

- Syslog connector and CEF/CommonSecurityLog connector must both be deployed and receiving data from Sentry appliances for the union to be meaningful.

Required telemetry:
- Syslog, CommonSecurityLog

### KQL

```kql
let SentryAccountCreation_Syslog =
    Syslog
    | where TimeGenerated > ago(1d)
    | where HostName has_any ("sentry", "mobileiron")
    | where SyslogMessage has_any ("useradd", "adduser", "account created", "admin account", "new user")
    | project TimeGenerated, Source="Syslog", HostName, ProcessName, SyslogMessage, SourceIP=tostring("");
let SentryAccountCreation_CSL =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceVendor has_any ("Ivanti", "MobileIron")
    | where DeviceProduct has_any ("Sentry", "MobileIron Sentry")
    | where Activity has_any ("useradd", "adduser", "account created", "admin account", "new user")
    | project TimeGenerated, Source="CommonSecurityLog", HostName=tostring(DeviceName), ProcessName=tostring(""), SyslogMessage=tostring(Activity), SourceIP=tostring(SourceIP);
union SentryAccountCreation_Syslog, SentryAccountCreation_CSL
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate administrator-initiated account provisioning during onboarding or maintenance windows.
- Automated provisioning pipelines that create service accounts on Sentry appliances.
- Syslog lines from non-Sentry hosts whose hostnames happen to contain 'sentry' or 'mobileiron' as substrings.

Tuning notes:
- After confirming the exact audit log message format from Ivanti Sentry, replace broad has_any keyword matching with exact string matches or regex patterns for higher fidelity.
- If Sentry emits structured CEF fields for account creation (e.g., a specific DeviceEventClassID), add that filter to the CommonSecurityLog branch for precision.

Risks / caveats:
- CommonSecurityLog DeviceVendor string must exactly match 'Ivanti' or 'MobileIron' as configured in the CEF forwarder; if the vendor string differs, the CSL branch will return no results.
- Syslog connector and CEF/CommonSecurityLog connector must both be deployed and receiving data from Sentry appliances for the union to be meaningful.
- The Activity field in CommonSecurityLog may not contain free-text account creation strings; Ivanti Sentry CEF mappings must be verified to confirm Activity carries audit event descriptions.
- HostName substring filter must be replaced with exact appliance hostnames to avoid false positives from unrelated hosts and false negatives from appliances with non-standard naming.

### Triage Runbook

First 15 minutes:
- Confirm the alerted host or device is a real Ivanti Sentry or MobileIron Sentry appliance.
- Review the account name, creator context, and exact message text to determine whether the account is administrative and newly created.
- Check whether the creation occurred during an approved onboarding, break-glass, or maintenance activity.
- Look for any nearby signs of exploitation, such as suspicious process execution or configuration changes on the same appliance.

Evidence to collect:
- Alerted TimeGenerated, Source, HostName/DeviceName, SyslogMessage or Activity, and SourceIP if present.
- The new account name, role/privilege level, and whether it is enabled or active.
- Any preceding authentication, admin session, or configuration events on the same appliance.
- Appliance version and patch status for CVE-2026-10523 and related advisories.

Pivot points:
- Syslog and CommonSecurityLog for the same appliance over 24-72 hours to find other admin actions.
- Authentication or admin audit logs for the appliance to identify who, if anyone, created the account.
- Change management records and identity logs for the named account or creator identity.
- If available, VPN, firewall, or reverse proxy logs for source IP correlation.

Benign explanations:
- Authorized administrator provisioning a new account during onboarding or support.
- Automated provisioning workflow creating a service account as part of a managed process.
- A test or lab appliance where account creation is expected and documented.

Escalation criteria:
- The account is privileged, unexpected, or created outside a documented change window.
- No legitimate creator or change record can be found quickly.
- The account appears designed for persistence, such as a generic admin name or unusual role assignment.
- Other compromise indicators are present on the same appliance, including suspicious process execution or external access.

Containment actions:
- Disable or remove the unauthorized account if the appliance owner confirms it is not legitimate.
- Reset credentials for any accounts that may have been exposed or reused on the appliance.
- Restrict administrative access to the appliance and preserve logs before making disruptive changes.
- Escalate to incident response if the account is confirmed unauthorized or if additional compromise indicators exist.

Closure criteria:
- A valid change record or approved provisioning workflow explains the account creation.
- The account is verified as legitimate and matches expected naming, role, and timing.
- No other suspicious activity is found on the appliance in the surrounding time window.
- The alert is determined to be a hostname or vendor-string false positive after validation.

---

## Detection 3: Azure - Cloud Logging Diagnostic Settings Disabled or Deleted (T1562.008)

### Detection Opportunity

Adversary disables or deletes Azure diagnostic settings or Log Analytics workspace configurations to reduce defender visibility

### Intelligence Context

- Unit 42: Blinding the Watchmen: Abusing Cloud Logging Services for Defense Evasion and Visibility — [https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/](https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/)
  - Context: Unit 42 research documents adversary abuse of cloud logging services to suppress defender visibility. The detection targets the discrete control-plane action of deleting or disabling Azure diagnostic settings, which is the primary mechanism for blinding Azure-native logging pipelines.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1562.008, T1562
- Products: Not specified
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: T1562.008, cloud, T1562

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1562 Impair Defenses/ T1562.008 Disable or Modify Cloud Logs (high)

### Deployment Gates

- AzureActivity connector must be enabled and connected for the relevant Azure subscriptions; if not deployed, the table will be empty.

Required telemetry:
- AzureActivity

### KQL

```kql
AzureActivity
| where TimeGenerated > ago(1d)
| where tolower(OperationName) has_any (
    "microsoft.insights/diagnosticsettings/delete",
    "microsoft.insights/diagnosticsettings/write",
    "microsoft.operationalinsights/workspaces/delete",
    "microsoft.operationalinsights/workspaces/write"
  )
| where ActivityStatusValue =~ "Success" or ActivityStatus =~ "Succeeded"
| extend InitiatorUPN = tostring(parse_json(tostring(parse_json(InitiatedBy).user)).userPrincipalName)
| extend InitiatorApp = tostring(parse_json(tostring(parse_json(InitiatedBy).app)).displayName)
| extend ActorType = case(
    isnotempty(InitiatorUPN), "User",
    isnotempty(InitiatorApp), "ServicePrincipal",
    "Unknown"
  )
| project TimeGenerated, OperationName, ActivityStatus, CallerIpAddress, ResourceId, ResourceGroup, SubscriptionId, InitiatorUPN, InitiatorApp, ActorType
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Infrastructure-as-code pipeline runs that delete and recreate diagnostic settings as part of idempotent deployments.
- Authorized administrators performing subscription cleanup or resource decommissioning.
- Log Analytics workspace retention policy changes made by authorized capacity management processes.

Tuning notes:
- Consider splitting into two rules: one for delete operations (higher severity, lower FP rate) and one for write operations (medium severity, requires allowlisting).
- ActivityStatusValue is the newer normalized field in AzureActivity; ActivityStatus is retained as a fallback for older ingestion pipelines. Validate which field is populated in the environment.
- Add a where ActorType == 'User' filter if service principal activity is separately monitored or generates excessive noise.

Risks / caveats:
- AzureActivity connector must be enabled and connected for the relevant Azure subscriptions; if not deployed, the table will be empty.
- The write operation filter on diagnostic settings and workspaces will match legitimate configuration changes; allowlisting authorized actors is required to reduce false positive volume before this rule generates actionable alerts at scale.
- AzureActivity ingestion latency can be up to 15 minutes; near-real-time detection of active logging suppression may lag behind the adversary action.
- In environments with many subscriptions, the query should be scoped or the alert volume assessed before enabling at full scale.

### Triage Runbook

First 15 minutes:
- Identify the exact resource affected, the operation performed, and whether it was a delete or write action.
- Check the InitiatorUPN or InitiatorApp to see whether the actor is a known admin, automation identity, or unknown principal.
- Verify whether the change occurred during an approved infrastructure or logging maintenance window.
- Assess whether the affected resource is critical and whether other logging paths remain intact.

Evidence to collect:
- TimeGenerated, OperationName, ActivityStatus, CallerIpAddress, ResourceId, ResourceGroup, SubscriptionId, InitiatorUPN, and InitiatorApp.
- The before/after state of the diagnostic setting, workspace, or export configuration if available.
- Change management ticket, deployment pipeline run, or approval record tied to the actor.
- Any concurrent suspicious AzureActivity events from the same actor or IP.

Pivot points:
- AzureActivity for the same actor, subscription, and resource group over the last 24-72 hours.
- AzureActivity for other diagnostic setting, workspace, or export changes by the same InitiatorUPN or InitiatorApp.
- Identity logs for the initiating user or service principal, including sign-in risk and MFA status if available.
- Resource-specific logs to confirm whether telemetry stopped after the change.

Benign explanations:
- Authorized infrastructure-as-code deployment updating logging configuration.
- Planned decommissioning or cleanup of a resource or subscription.
- A service principal performing a legitimate configuration rollout or migration.

Escalation criteria:
- The actor is unknown, unexpected, or not tied to a valid change record.
- Logging was deleted or disabled on a high-value subscription, workspace, or critical resource.
- Multiple logging-related changes occur in a short period or from an unusual source IP.
- Other suspicious Azure control-plane activity is present, suggesting defense evasion.

Containment actions:
- Re-enable diagnostic settings or restore logging configuration if the change is confirmed unauthorized and operationally safe.
- Disable or revoke the initiating identity if it is compromised and not required for immediate operations.
- Preserve AzureActivity and related logs before making further changes.
- Escalate to cloud incident response if logging suppression appears malicious or coordinated.

Closure criteria:
- The change is matched to a valid, approved maintenance or deployment activity.
- The affected logging configuration is restored or confirmed intentionally modified.
- No additional suspicious control-plane activity is found from the same actor.
- The actor is a known automation identity and the action is consistent with expected behavior.

---

## Detection 4: Azure - Log Retention or Export Policy Modified to Suppress Evidence (T1562.008)

### Detection Opportunity

Adversary modifies log retention or export policy on Azure storage accounts or Log Analytics workspaces to suppress forensic evidence

### Intelligence Context

- Unit 42: Blinding the Watchmen: Abusing Cloud Logging Services for Defense Evasion and Visibility — [https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/](https://unit42.paloaltonetworks.com/cloud-logging-defense-evasion/)
  - Context: Unit 42 research identifies manipulation of log retention and export configurations as a technique adversaries use to suppress evidence in cloud environments. This detection targets AzureActivity operations that reduce or eliminate retention on log storage resources.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1562.008, T1562
- Products: Not specified
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: T1562.008, cloud, T1562

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1562 Impair Defenses/ T1562.008 Disable or Modify Cloud Logs (high)

### Deployment Gates

- AzureActivity connector must be enabled and connected for the relevant Azure subscriptions; if not deployed, the table will be empty.

Required telemetry:
- AzureActivity

### KQL

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where tolower(OperationName) has_any (
    "microsoft.operationalinsights/workspaces/dataexports/delete",
    "microsoft.operationalinsights/workspaces/dataexports/write",
    "microsoft.storage/storageaccounts/managementpolicies/write",
    "microsoft.storage/storageaccounts/managementpolicies/delete",
    "microsoft.operationalinsights/workspaces/write"
  )
| where ActivityStatusValue =~ "Success" or ActivityStatus =~ "Succeeded"
| extend InitiatorUPN = tostring(parse_json(tostring(parse_json(InitiatedBy).user)).userPrincipalName)
| extend InitiatorApp = tostring(parse_json(tostring(parse_json(InitiatedBy).app)).displayName)
| extend ActorType = case(
    isnotempty(InitiatorUPN), "User",
    isnotempty(InitiatorApp), "ServicePrincipal",
    "Unknown"
  )
| project TimeGenerated, OperationName, ActivityStatus, CallerIpAddress, ResourceId, ResourceGroup, SubscriptionId, InitiatorUPN, InitiatorApp, ActorType
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Authorized infrastructure-as-code pipelines that manage storage lifecycle policies as part of cost optimization.
- Log Analytics workspace retention changes made by authorized administrators during capacity planning.
- Data export rule modifications made by authorized SIEM integration pipelines.

Tuning notes:
- To promote to a scheduled rule, reduce lookback to 1 day and add where ActorType == 'User' to focus on human-initiated changes, or maintain both actor types with separate severity assignments.
- ActivityStatusValue is the newer normalized field; ActivityStatus is retained as fallback. Validate which is populated in the environment.
- Consider parsing the Properties field with parse_json() to extract the specific retention value being set, enabling a filter for retention reductions below a defined threshold.

Risks / caveats:
- AzureActivity connector must be enabled and connected for the relevant Azure subscriptions; if not deployed, the table will be empty.
- The workspace write operation filter is broad and will match any successful workspace configuration change, not only retention reductions; analyst review of Properties content is required to confirm retention was actually reduced.
- Storage management policy writes include lifecycle rules unrelated to log retention; results require analyst triage to identify log-relevant storage accounts.
- Promoting to a scheduled rule requires establishing a baseline of authorized automation activity and implementing an allowlist before alert volume is manageable.

### Triage Runbook

First 15 minutes:
- Identify which resource was modified and whether the change affects retention, export, or lifecycle policy.
- Check whether the actor is a known administrator or automation identity and whether the timing matches a change window.
- Determine if the change reduces retention below policy minimums or disables export to a security destination.
- Look for related AzureActivity events from the same actor that indicate broader tampering.

Evidence to collect:
- TimeGenerated, OperationName, ActivityStatus, CallerIpAddress, ResourceId, ResourceGroup, SubscriptionId, InitiatorUPN, InitiatorApp, and ActorType.
- The specific retention or export values before and after the change if available.
- Change ticket, deployment record, or approval for the policy modification.
- Any other AzureActivity events from the same actor around the same time.

Pivot points:
- AzureActivity for the same InitiatorUPN or InitiatorApp across the last 7 days.
- AzureActivity for storage account management policy or Log Analytics workspace changes in the same subscription.
- Resource logs or workspace configuration history to verify whether retention/export actually changed.
- Identity logs for the initiating user or service principal to validate legitimacy.

Benign explanations:
- Authorized cost-optimization or lifecycle-policy update by cloud operations.
- Planned workspace retention adjustment during a migration or compliance change.
- A legitimate SIEM integration or data export rule update by an approved automation identity.

Escalation criteria:
- Retention was reduced below policy minimums or export was disabled without approval.
- The actor is unknown, compromised, or not tied to a valid change record.
- Multiple evidence-suppressing changes occur across resources or subscriptions.
- The change is accompanied by other suspicious cloud control-plane activity.

Containment actions:
- Restore the prior retention or export configuration if the change is unauthorized and safe to revert.
- Disable or revoke the initiating identity if compromise is suspected.
- Preserve AzureActivity and any affected resource configuration history before further remediation.
- Escalate to cloud incident response if evidence suppression is confirmed.

Closure criteria:
- A valid change record explains the policy modification and the values remain within approved bounds.
- The configuration is verified as intended and does not reduce required logging retention.
- No other suspicious activity is associated with the actor or resource.
- The event is confirmed to be routine automation or a planned migration.

---

## Detection 5: PAN-OS - CVE-2026-0257 Exploitation Attempt Detected via CommonSecurityLog

### Detection Opportunity

Active exploitation of CVE-2026-0257 against internet-exposed PAN-OS devices as confirmed by Unit 42 threat intelligence

### Intelligence Context

- Unit 42: Threat Brief: Active Exploitation of PAN-OS CVE-2026-0257 — [https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/](https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/)
  - Context: Unit 42 confirmed active in-the-wild exploitation of CVE-2026-0257 affecting PAN-OS. PAN-OS forwards threat events to Sentinel via CommonSecurityLog, enabling detection of CVE-specific threat log entries and anomalous management-plane access from external source IPs.

### Search Metadata

- CVEs: CVE-2026-0257
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: PAN-OS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-0257, T1190, PAN-OS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CEF/CommonSecurityLog connector must be configured on PAN-OS devices to forward threat logs to Microsoft Sentinel; if not deployed, the table will contain no PAN-OS records.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor =~ "Palo Alto Networks"
| where tolower(DeviceProduct) has_any ("pan-os", "panos", "firewall")
| extend IsCVEStringMatch = (Activity has "CVE-2026-0257" or Message has "CVE-2026-0257")
| extend IsBehavioralMatch = (
    tolower(DeviceAction) !in ("allow")
    and DestinationPort in (443, 4443, 8443)
    and isnotempty(SourceIP)
    and ipv4_is_private(SourceIP) == false
  )
| where IsCVEStringMatch == true or IsBehavioralMatch == true
| extend SignalType = case(
    IsCVEStringMatch == true and IsBehavioralMatch == true, "CVE-String+Behavioral",
    IsCVEStringMatch == true, "CVE-String",
    "Behavioral-Heuristic"
  )
| project TimeGenerated, DeviceVendor, DeviceProduct, Activity, SourceIP, DestinationIP, DestinationPort, DeviceAction, Message, SignalType, IsCVEStringMatch, IsBehavioralMatch
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Blocked external connection attempts to PAN-OS GlobalProtect portal on port 443 from internet scanners.
- Legitimate remote administrator access to PAN-OS management interface from external IPs that is blocked by policy.
- Vulnerability scanner activity generating non-allow events against management ports.

Tuning notes:
- Once Palo Alto publishes the specific threat signature ID for CVE-2026-0257, add a filter on the signature ID field (typically mapped to DeviceEventClassID or AdditionalExtensions in CommonSecurityLog) for higher-fidelity alerting and consider disabling the behavioral heuristic branch.
- Consider splitting into two separate rules: one for CVE-string matches (high severity, low FP) and one for the behavioral heuristic (medium severity, requires tuning).
- If PAN-OS management interfaces are on dedicated IPs, add a DestinationIP filter to the behavioral branch to reduce noise from GlobalProtect or other external-facing services on the same ports.

Risks / caveats:
- CEF/CommonSecurityLog connector must be configured on PAN-OS devices to forward threat logs to Microsoft Sentinel; if not deployed, the table will contain no PAN-OS records.
- The CVE string 'CVE-2026-0257' will only appear in Activity or Message fields after Palo Alto Networks publishes and deploys a threat content update containing the corresponding signature; until that update is applied on the PAN-OS device, the CVE string branch will return no results.
- The CVE string match branch will produce no results until Palo Alto Networks releases a threat content update with a signature referencing CVE-2026-0257 and that update is applied to the forwarding PAN-OS device.
- The behavioral heuristic branch is broad; it will generate alerts for any blocked external connection to ports 443/4443/8443 on PAN-OS devices, which may be high volume in internet-exposed environments.

### Triage Runbook

First 15 minutes:
- Confirm the device is a PAN-OS firewall and identify whether the alert is a CVE-string match or a behavioral heuristic match.
- Review SourceIP, DestinationIP, DestinationPort, DeviceAction, Activity, and Message to understand whether traffic was blocked or allowed.
- Check whether the destination is an internet-facing management interface or a legitimate external service such as GlobalProtect.
- Look for repeated attempts from the same source or multiple sources against the same device.

Evidence to collect:
- TimeGenerated, DeviceVendor, DeviceProduct, Activity, SourceIP, DestinationIP, DestinationPort, DeviceAction, Message, and SignalType.
- Whether the event was a threat log, traffic log, or management-plane access event.
- Any related PAN-OS logs showing successful logins, configuration changes, or subsequent threat activity.
- Device version, content update status, and whether the CVE signature is present on the firewall.

Pivot points:
- CommonSecurityLog for the same SourceIP, DestinationIP, or DeviceProduct over the last 24-72 hours.
- PAN-OS threat, traffic, and system logs for the same device and time window.
- Firewall or upstream network logs to determine whether the source is scanning broadly or targeting this device specifically.
- If available, identity and admin logs for any management-plane access around the same time.

Benign explanations:
- Internet scanner or vulnerability assessment activity blocked by the firewall.
- Legitimate remote administration attempts that were denied by policy.
- A threat-intelligence signature match that does not indicate successful exploitation.

Escalation criteria:
- The event is a CVE-string match and the device is internet-exposed or otherwise high value.
- Multiple attempts or multiple source IPs target the same PAN-OS device in a short period.
- There is any evidence of successful management-plane access, configuration change, or follow-on suspicious activity.
- The device is missing the relevant security content update and exploitation cannot be ruled out.

Containment actions:
- If exploitation is plausible, restrict external access to the affected management interface or device while preserving business-critical connectivity.
- Increase monitoring on the device and adjacent network segments for follow-on activity.
- Apply the vendor-recommended content update or patch as soon as operationally feasible.
- Escalate to network/security incident response if there are signs of successful compromise.

Closure criteria:
- The event is confirmed to be a blocked scan, benign admin attempt, or non-exploitable signature hit.
- No follow-on suspicious activity is found on the device or adjacent logs.
- The device is patched or the relevant threat content is confirmed current.
- The source is identified as an approved scanner or testing activity with a valid change record.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Ivanti Sentry - Suspicious Process Spawned from Web Service (CVE-2026-10520 RCE): Syslog connector must be configured to receive forwarded logs from Ivanti Sentry appliances; if not deployed, the table will contain no matching records.
- Ivanti Sentry - Unauthorized Administrative Account Creation (CVE-2026-10523): Syslog connector and CEF/CommonSecurityLog connector must both be deployed and receiving data from Sentry appliances for the union to be meaningful.
- Azure - Cloud Logging Diagnostic Settings Disabled or Deleted (T1562.008): AzureActivity connector must be enabled and connected for the relevant Azure subscriptions; if not deployed, the table will be empty.
- Azure - Log Retention or Export Policy Modified to Suppress Evidence (T1562.008): AzureActivity connector must be enabled and connected for the relevant Azure subscriptions; if not deployed, the table will be empty.

Shared-table notes:
- Syslog: shared by Ivanti Sentry - Suspicious Process Spawned from Web Service (CVE-2026-10520 RCE); Ivanti Sentry - Unauthorized Administrative Account Creation (CVE-2026-10523)
- CommonSecurityLog: shared by Ivanti Sentry - Unauthorized Administrative Account Creation (CVE-2026-10523); PAN-OS - CVE-2026-0257 Exploitation Attempt Detected via CommonSecurityLog
- AzureActivity: shared by Azure - Cloud Logging Diagnostic Settings Disabled or Deleted (T1562.008); Azure - Log Retention or Export Policy Modified to Suppress Evidence (T1562.008)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Azure - Cloud Logging Diagnostic Settings Disabled or Deleted (T1562.008); Azure - Log Retention or Export Policy Modified to Suppress Evidence (T1562.008); PAN-OS - CVE-2026-0257 Exploitation Attempt Detected via CommonSecurityLog.
2. Resolve environment-mapping detections next: Ivanti Sentry - Suspicious Process Spawned from Web Service (CVE-2026-10520 RCE); Ivanti Sentry - Unauthorized Administrative Account Creation (CVE-2026-10523).

### Hunting Agenda and Promotion Criteria

- Ivanti Sentry - Suspicious Process Spawned from Web Service (CVE-2026-10520 RCE): Syslog connector must be configured to receive forwarded logs from Ivanti Sentry appliances; if not deployed, the table will contain no matching records.; prove correlation keys join correctly on real tenant telemetry.
- Ivanti Sentry - Unauthorized Administrative Account Creation (CVE-2026-10523): Syslog connector and CEF/CommonSecurityLog connector must both be deployed and receiving data from Sentry appliances for the union to be meaningful.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
