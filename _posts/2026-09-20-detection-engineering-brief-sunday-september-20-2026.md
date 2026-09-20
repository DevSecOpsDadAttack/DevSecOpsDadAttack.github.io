---
layout: post
title: "Detection Engineering Brief - Sunday, September 20, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-20
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - email
  - endpoint
  - AWS AgentCore Harness
  - AWS
  - MovieReaper
  - web
  - T1566
  - T1566.001
  - T1552.001
  - T1041
  - T1552
  - T1071.001
  - T1071
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 0 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: email, endpoint, AWS AgentCore Harness, AWS, MovieReaper, web, T1566, T1566.001, T1552.001, T1041, T1552, T1071.001, T1071.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: AWS AgentCore - Anomalous Credential Access from Agent Workload Identity; AWS AgentCore - Credential Access Followed by High-Volume Outbound Network Activity.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Malspam Quarantine - Attachment Blocked by Mail Gateway

### Detection Opportunity

Malspam delivering a malicious attachment was caught and quarantined by the mail gateway, with the email blocked before delivery.

### Intelligence Context

- SANS ISC: LausivLoader analysis, or how to pass data between malware stages, (Thu, Sep 17th) — [https://isc.sans.edu/diary/rss/33348](https://isc.sans.edu/diary/rss/33348)
  - Context: A malspam message impersonating a legitimate company employee was caught in mail gateway quarantine. The email carried a malicious attachment themed as a price quotation request for a fiber optic system. The attachment type was not specified in the reporting.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1566.001
- Products: Not specified
- Platforms: email, endpoint
- Malware: Not specified
- Tools: Not specified
- Search tags: email, endpoint, T1566, T1566.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: low
- MITRE ATT&CK: initial-access: T1566 Phishing/ T1566.001 Spearphishing Attachment (high)

### Deployment Gates

- Requires Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing; EmailEvents and EmailAttachmentInfo are not available without it.

**Required telemetry:**
- EmailEvents, EmailAttachmentInfo

### KQL

```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Blocked", "Quarantined")
| where ThreatTypes has_any ("Malware", "Phish")
| where AttachmentCount > 0
| extend SenderFromDomain = tostring(split(SenderMailFromAddress, "@")[1])
| project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromDomain, SenderIPv4, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction, AttachmentCount
| join kind=leftouter (
    EmailAttachmentInfo
    | where Timestamp > ago(7d)
    | project NetworkMessageId, FileName, FileType, SHA256
) on NetworkMessageId
| project Timestamp, SenderMailFromAddress, SenderFromDomain, SenderIPv4, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction, FileName, FileType, SHA256
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate bulk mail or marketing platforms occasionally quarantined as phish due to link reputation; review SenderIPv4 and SenderMailFromAddress against known bulk senders.
- Internal relay or forwarding services with external sender addresses may appear if EmailDirection classification is inconsistent.

**Tuning notes:**
- Restrict ThreatTypes further to 'Malware' only if phish-quarantine volume is too high for analyst review capacity.
- Add SenderFromDomain exclusions for known trusted partner relay domains to reduce recurring false positives.
- Consider summarizing by SenderIPv4 to identify bulk malspam campaigns sending from a single source.

**Risks / caveats:**
- Requires Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing; EmailEvents and EmailAttachmentInfo are not available without it.
- EmailAttachmentInfo.Timestamp must be within the same lookback window as EmailEvents for the join to return results; if attachment metadata is delayed or missing, FileName and SHA256 will be null for matched rows.
- ThreatTypes is a dynamic/string field; has_any behavior against multi-value strings should be validated in the environment to confirm 'Malware' and 'Phish' tokens match exactly.
- Lookback window of 7 days may surface high result volumes in environments with active phishing campaigns; consider reducing to 1-2 days for scheduled rule use.

### Triage Runbook

**First 15 minutes:**
- Verify the email was not delivered to any mailbox and that DeliveryAction is Blocked or Quarantined for all matching events.
- Review SenderMailFromAddress, SenderIPv4, SenderFromDomain, Subject, and RecipientEmailAddress for signs of a campaign affecting multiple users.
- Check whether the attachment SHA256 is known malicious in threat intelligence or has appeared in other alerts.
- Identify whether the recipient reported any related user interaction, forwarding, or alternate delivery path such as mobile mail clients or external forwarding rules.

**Evidence to collect:**
- Timestamp, sender address, sender domain, sender IP, recipient, subject, ThreatTypes, DeliveryAction, FileName, FileType, and SHA256.
- Any additional matching messages with the same sender, subject, or attachment hash across the last 7 days.
- Mail gateway quarantine details, including whether the message was blocked before delivery or held for review.
- User report or helpdesk notes indicating whether the recipient saw a preview, notification, or related message on another device.

**Pivot points:**
- EmailEvents filtered by SenderMailFromAddress, SenderIPv4, Subject, and RecipientEmailAddress.
- EmailAttachmentInfo for the same NetworkMessageId and SHA256 to identify other recipients of the same attachment.
- Mail gateway or Defender email quarantine search for the same sender domain and attachment hash.
- Threat intelligence lookup for SHA256, sender domain, and sender IP reputation.

**Benign explanations:**
- Legitimate bulk mail or marketing platforms can be quarantined as phish due to poor reputation or URL content.
- Internal relay or forwarding services may make an external sender appear suspicious if EmailDirection is inconsistent.
- A user may receive a legitimate quotation or invoice request that is malformed enough to trigger malware/phish classification without actual malicious intent.

**Escalation criteria:**
- Escalate if the same sender, subject, or attachment hash appears across multiple recipients or multiple quarantine events.
- Escalate if the attachment hash is known malicious or the sender domain/IP has strong phishing reputation.
- Escalate if any evidence shows the message was delivered, opened, or forwarded outside quarantine.
- Escalate if the recipient reports credential entry, macro execution, or any follow-on suspicious activity after the email was received.

**Containment actions:**
- Keep the message quarantined and ensure it is not released to any mailbox.
- Block the sender domain and sender IP at the mail gateway if campaign activity is confirmed.
- Search and purge any matching messages from other mailboxes if the same attachment or subject is found.
- Notify the recipient and adjacent recipients not to open similar messages and to report related emails immediately.

**Closure criteria:**
- Confirmed quarantined or blocked with no delivery to any mailbox.
- No evidence of user interaction, forwarding, or secondary delivery path.
- Attachment hash and sender reputation reviewed with no additional indicators of compromise.
- Any related campaign activity has been searched and no additional affected users were found.

<br/>
---
<br/>

## Detection 2: AWS AgentCore - Anomalous Credential Access from Agent Workload Identity

### Detection Opportunity

Prompt injection in AWS AgentCore Harness workloads triggers unexpected IAM credential access events such as GetSecretValue or AssumeRole from agent service principals.

### Intelligence Context

- Unit 42: A Vault with a Heap-View: The Uncomfortable Space Between AgentCore Harness and Identity — [https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/](https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/)
  - Context: Unit 42 research identified that default configurations in AWS AgentCore Harness allow prompt injection attacks to trigger credential access, enabling exfiltration of IAM credentials from agent workloads via GetSecretValue or AssumeRole API calls.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552.001, T1041, T1552
- Products: AWS AgentCore Harness
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS AgentCore Harness, AWS, T1552.001, T1041, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low); exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail before scheduling.

**Required telemetry:**
- AWSCloudTrail

### KQL

```kql
let CredentialAccessEvents = AWSCloudTrail
| where TimeGenerated > ago(1d)
| where eventName in ("GetSecretValue", "AssumeRole", "GetSessionToken")
| where userAgent has_any ("agentcore", "bedrock-agent")
| extend AgentRoleArn = tostring(parse_json(tostring(sessionContext)).sessionIssuer.arn)
| project CredentialAccessTime=TimeGenerated, eventName, sourceIPAddress, userAgent, AgentRoleArn, recipientAccountId, requestParameters, errorCode;
let SubsequentAccess = AWSCloudTrail
| where TimeGenerated > ago(1d)
| where eventName !in ("GetSecretValue", "AssumeRole", "GetSessionToken")
| project FollowOnTime=TimeGenerated, sourceIPAddress, FollowOnEvent=eventName, FollowOnParams=requestParameters;
CredentialAccessEvents
| join kind=inner (
    SubsequentAccess
) on sourceIPAddress
| where FollowOnTime > CredentialAccessTime and FollowOnTime <= CredentialAccessTime + 15m
| project CredentialAccessTime, FollowOnTime, eventName, FollowOnEvent, sourceIPAddress, userAgent, AgentRoleArn, recipientAccountId, errorCode
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate AgentCore workflows that perform GetSecretValue as part of normal secret retrieval followed by other API calls will match; baseline normal agent API call sequences before alerting.
- Shared source IPs such as NAT gateways used by multiple workloads will cause the sourceIPAddress join to correlate unrelated workloads.

**Tuning notes:**
- Validate userAgent values by running: AWSCloudTrail → where eventName in ('GetSecretValue','AssumeRole') → summarize count() by userAgent → order by count_ desc — then update the has_any filter with confirmed AgentCore strings.
- Consider filtering on sessionContext to match only AgentCore-specific IAM role name patterns rather than relying solely on userAgent.
- Add recipientAccountId scoping if the environment has multiple AWS accounts to reduce cross-account noise.

**Risks / caveats:**
- AWSCloudTrail table requires the AWS CloudTrail data connector to be configured and actively ingesting into the Sentinel workspace; absence of this connector means the table will not exist.
- The userAgent field in AWSCloudTrail may be a JSON string or structured object depending on connector version; has_any string matching may not parse nested JSON correctly.
- sessionContext is a dynamic/JSON field in AWSCloudTrail; direct projection without parsing may return opaque JSON blobs that are not analyst-readable.
- The userAgent filter strings 'agentcore' and 'bedrock-agent' must be validated against actual CloudTrail logs in the environment before this query is meaningful; incorrect strings will produce zero results or over-broad matches.

### Triage Runbook

**First 15 minutes:**
- Identify the exact eventName sequence and confirm whether GetSecretValue, AssumeRole, or GetSessionToken occurred from the expected AgentCore service principal.
- Review the extracted AgentRoleArn, sourceIPAddress, recipientAccountId, and userAgent to determine whether the activity matches the known workload identity and environment.
- Check for follow-on API calls from the same sourceIPAddress within 15 minutes, especially unusual IAM, S3, STS, or data access actions.
- Validate whether the secret or role accessed is required by the workload's normal function and whether the timing aligns with a recent prompt or job execution.

**Evidence to collect:**
- CloudTrail event timestamps, event names, source IP, user agent, role ARN, requestParameters, and errorCode.
- The specific secret name, role ARN, or session token target involved in the access event.
- Any subsequent API calls from the same sourceIPAddress or principal, including denied attempts.
- AgentCore workload logs, prompt history, and orchestration logs around the same time window.

**Pivot points:**
- AWSCloudTrail for the same sourceIPAddress, recipientAccountId, and AgentRoleArn over the prior 24 hours.
- AWSCloudTrail for unusual IAM, STS, Secrets Manager, S3, or KMS activity following the credential access event.
- AgentCore application logs or harness telemetry for prompt injection indicators, unexpected tool calls, or abnormal task execution.
- Identity and access management records for the role trust policy and recent changes to the workload permissions.

**Benign explanations:**
- The workload may legitimately retrieve secrets at startup or during a scheduled task.
- Shared NAT or VPC endpoint IPs can make unrelated workloads appear correlated in CloudTrail.
- A denied AssumeRole or GetSecretValue attempt may reflect a misconfiguration or expired permission rather than malicious activity.

**Escalation criteria:**
- Escalate if the accessed secret or role is not expected for the workload or is outside the normal execution pattern.
- Escalate if there are unusual follow-on actions such as privilege escalation, new role assumptions, or access to sensitive data stores.
- Escalate if prompt injection indicators, unexpected tool invocation, or suspicious user input are present in the workload logs.
- Escalate if multiple AgentCore workloads or accounts show the same pattern from the same source IP or role family.

**Containment actions:**
- Disable or rotate the affected secret if unauthorized access is suspected.
- Temporarily restrict the workload role permissions or trust policy if the role is being abused.
- Pause the affected AgentCore workload or harness instance if it is actively making unexpected credential requests.
- Preserve CloudTrail and workload logs before making changes that could destroy evidence.

**Closure criteria:**
- The credential access was confirmed as expected behavior for the workload and no suspicious follow-on activity was found.
- No unauthorized role assumption, secret retrieval, or data access occurred beyond the expected workflow.
- Prompt injection or workload abuse indicators were not present in the associated logs.
- Any required tuning or allowlisting has been documented for the known-good workload pattern.

<br/>
---
<br/>

## Detection 3: AWS AgentCore - Credential Access Followed by High-Volume Outbound Network Activity

### Detection Opportunity

Following IAM credential access events in AWS AgentCore workloads, outbound data exfiltration is attempted from the same workload identity, correlating credential theft with network egress.

### Intelligence Context

- Unit 42: A Vault with a Heap-View: The Uncomfortable Space Between AgentCore Harness and Identity — [https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/](https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/)
  - Context: Unit 42 identified that after prompt injection triggers credential access in AgentCore Harness, the stolen credentials can be used to exfiltrate data outbound. Detecting the chain of credential access followed by anomalous outbound network volume from the same workload provides a compound exfiltration signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552.001, T1041, T1552
- Products: AWS AgentCore Harness
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS AgentCore Harness, AWS, T1552.001, T1041, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low); exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail, CommonSecurityLog before scheduling.

**Required telemetry:**
- AWSCloudTrail, CommonSecurityLog

### KQL

```kql
let AgentCredAccess = AWSCloudTrail
| where TimeGenerated > ago(1d)
| where eventName in ("GetSecretValue", "AssumeRole", "GetSessionToken")
| where userAgent has_any ("agentcore", "bedrock-agent")
| summarize CredAccessTime=min(TimeGenerated) by sourceIPAddress;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where isnotempty(SourceIP)
| where SentBytes > 500000
| join kind=inner AgentCredAccess on $left.SourceIP == $right.sourceIPAddress
| where TimeGenerated > CredAccessTime and TimeGenerated <= CredAccessTime + 30m
| project TimeGenerated, CredAccessTime, SourceIP, DestinationIP, SentBytes, ApplicationProtocol, DeviceVendor, DeviceProduct
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- AgentCore workloads that legitimately transfer large payloads (model outputs, dataset responses) after credential retrieval will match.
- Shared NAT gateway IPs will correlate unrelated workloads' network egress with AgentCore credential access events.
- Any Lambda function sharing the NAT IP with an AgentCore workload will be correlated if it transfers large volumes.

**Tuning notes:**
- Baseline AgentCore egress volumes by running: CommonSecurityLog → where SourceIP in (AgentCore IP list) → summarize percentiles(SentBytes, 50, 90, 99) by bin(TimeGenerated, 1h) — then set the threshold above the 99th percentile of normal.
- If NAT is in use, consider correlating on VPC flow log data or AWS GuardDuty findings instead of CommonSecurityLog SourceIP.
- Validate userAgent values in CloudTrail before relying on the has_any filter.

**Risks / caveats:**
- AWSCloudTrail table requires the AWS CloudTrail data connector to be configured and actively ingesting into the Sentinel workspace.
- CommonSecurityLog requires a CEF-compatible network appliance connector to be configured; SentBytes field population is appliance-dependent and may be null or zero for many CEF sources.
- SourceIP in CommonSecurityLog may reflect a NAT gateway or VPC endpoint rather than the AgentCore workload's internal IP, making the join to AWSCloudTrail sourceIPAddress unreliable without network topology knowledge.
- The userAgent filter strings 'agentcore' and 'bedrock-agent' must be confirmed against actual CloudTrail logs in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the credential access event occurred before the outbound traffic and that the same sourceIPAddress or workload identity is involved.
- Review DestinationIP, SentBytes, ApplicationProtocol, DeviceVendor, and DeviceProduct to identify where the data was sent and through which network control point.
- Check whether the destination is a known AWS service, internal endpoint, or an external internet host that is unusual for the workload.
- Compare the volume and timing against normal AgentCore egress patterns to see whether the threshold is exceeded by routine workload behavior.

**Evidence to collect:**
- CloudTrail credential access details including eventName, sourceIPAddress, userAgent, and AgentRoleArn.
- Network telemetry showing DestinationIP, SentBytes, protocol, and the network appliance that observed the traffic.
- Any related S3, STS, Secrets Manager, or application logs showing what data was accessed before the egress.
- Historical baseline of normal egress volume for the same workload or source IP.

**Pivot points:**
- AWSCloudTrail for the same sourceIPAddress and recipientAccountId around the credential access time.
- CommonSecurityLog or equivalent network telemetry for the same SourceIP and DestinationIP over the prior 24 hours.
- AWS service logs for S3, STS, Secrets Manager, or application-specific data access tied to the workload role.
- VPC flow logs or firewall logs if NAT or endpoint translation makes SourceIP correlation unreliable.

**Benign explanations:**
- The workload may legitimately transfer large model outputs, datasets, or logs after retrieving credentials.
- Shared NAT gateways can cause unrelated traffic to appear tied to the same source IP.
- A burst of outbound traffic may reflect normal batch processing, synchronization, or backup activity rather than exfiltration.

**Escalation criteria:**
- Escalate if the destination is external and not part of the workload's approved service list.
- Escalate if the outbound volume is materially above baseline and follows credential access with no clear business justification.
- Escalate if the same pattern repeats across multiple time windows or multiple AgentCore identities.
- Escalate if the accessed credentials are privileged or the traffic includes sensitive data stores, archives, or unusual protocols.

**Containment actions:**
- If exfiltration is plausible, isolate the workload or revoke the role session to stop further outbound activity.
- Block the suspicious destination IP or domain at the network control point if it is clearly malicious or unauthorized.
- Rotate or disable the accessed credentials if compromise is confirmed or strongly suspected.
- Preserve network and CloudTrail evidence before making disruptive changes.

**Closure criteria:**
- The outbound traffic was explained by a documented workload process and matched baseline behavior.
- No unauthorized destination, data store, or protocol was identified.
- Credential access was expected and no suspicious follow-on activity was found.
- Any false-positive tuning for the workload's normal egress volume has been recorded.

<br/>
---
<br/>

## Detection 4: MovieReaper - Executable Dropped and Launched from User-Writable Directory

### Detection Opportunity

Multi-stage trojan drops a secondary payload executable into a user-writable directory such as Temp or AppData and immediately executes it, consistent with MovieReaper dropper behavior observed after torrent file delivery.

### Intelligence Context

- Securelist: The Odyssey and trojans again: MovieReaper attacks users in multiple countries via compromised torrents — [https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/](https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/)
  - Context: MovieReaper is a multi-stage trojan distributed via compromised movie torrents. After initial execution, the dropper stage writes secondary payload executables to user-writable directories and immediately executes them. This write-then-execute pattern in Temp or AppData directories is a reliable behavioral indicator of the dropper stage.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071.001, T1071
- Products: Not specified
- Platforms: endpoint, web
- Malware: MovieReaper
- Tools: Not specified
- Search tags: MovieReaper, endpoint, web, T1071.001, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: command-and-control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let ExcludedDroppers = dynamic(["msiexec.exe", "wuauclt.exe", "svchost.exe", "setup.exe", "installer.exe"]);
let DroppedFiles = DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr"
| where InitiatingProcessFileName !in~ (ExcludedDroppers)
| project FileCreatedTime=Timestamp, DeviceName, DroppedFile=FileName, DroppedPath=FolderPath, DroppingProcess=InitiatingProcessFileName, DroppingProcessCommandLine=InitiatingProcessCommandLine, SHA256;
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\")
| join kind=inner DroppedFiles on DeviceName, $left.FileName == $right.DroppedFile
| where Timestamp > FileCreatedTime and Timestamp <= FileCreatedTime + 1m
| where FolderPath startswith DroppedPath or DroppedPath startswith FolderPath
| project FileCreatedTime, ExecutionTime=Timestamp, DeviceName, AccountName, DroppedFile, DroppedPath, DroppingProcess, DroppingProcessCommandLine, ProcessCommandLine, SHA256
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that extract and immediately execute components from Temp directories will match; tune InitiatingProcessFileName exclusions based on observed software deployment tooling.
- Self-extracting archives (SFX) that write and execute payloads from AppData will match.
- Browser-based download managers that save and auto-execute files may match if the browser process is not excluded.

**Tuning notes:**
- Run the query in hunting mode for 7 days before promoting to a scheduled rule to establish a false positive baseline.
- Add InitiatingProcessFileName exclusions for any software deployment or update agents observed in results that are confirmed legitimate.
- If MovieReaper SHA256 hashes become available from threat intelligence, add a SHA256 allowlist inversion to prioritize confirmed malicious hashes in triage.

**Risks / caveats:**
- Requires Microsoft Defender for Endpoint to be deployed on monitored endpoints; DeviceFileEvents and DeviceProcessEvents will not be populated without MDE.
- DeviceProcessEvents.FolderPath reflects the process image path, not the working directory; the has_any filter on FolderPath in DeviceProcessEvents correctly matches the executable's location but this must be confirmed against actual schema behavior in the environment.
- The FolderPath startswith cross-check between DeviceFileEvents and DeviceProcessEvents may not match exactly if path casing or trailing slash conventions differ between the two tables; validate path format consistency in the environment.
- The 1-minute execution window may miss dropper variants that delay execution; extend to 5 minutes if validated MovieReaper samples show longer staging delays.

### Triage Runbook

**First 15 minutes:**
- Confirm the file was created in Temp, AppData, or another user-writable directory and executed within the expected short time window.
- Review the dropping process, its command line, the dropped file hash, and the user account context to identify the initial execution chain.
- Check whether the file hash is known malicious and whether the process tree shows a browser, torrent client, archive utility, or script-based launcher.
- Look for additional suspicious files, persistence, or child processes on the same host around the same time.

**Evidence to collect:**
- FileCreatedTime, ExecutionTime, DeviceName, AccountName, DroppedFile, DroppedPath, DroppingProcess, DroppingProcessCommandLine, ProcessCommandLine, and SHA256.
- Process tree for the dropped executable, including parent and child processes.
- Any persistence artifacts such as scheduled tasks, Run keys, services, or startup folder entries.
- Threat intelligence results for the dropped SHA256 and any related filenames or paths.

**Pivot points:**
- DeviceFileEvents for the same DeviceName, DroppedPath, and SHA256 over the prior 24 hours.
- DeviceProcessEvents for the same host to identify child processes, command lines, and persistence behavior.
- DeviceNetworkEvents for the same host to see whether the dropped executable made outbound connections.
- Defender threat intelligence or sandbox results for the file hash and file name.

**Benign explanations:**
- Legitimate installers and self-extracting archives often write to Temp or AppData and execute immediately.
- Browser download managers or software updaters may create similar write-then-execute patterns.
- Some enterprise software deployment tools can mimic dropper behavior if not excluded by policy.

**Escalation criteria:**
- Escalate immediately if the hash is malicious, unsigned in an unexpected context, or associated with known malware.
- Escalate if the process tree shows persistence, credential access, or additional payloads after execution.
- Escalate if the host shows outbound connections, lateral movement, or multiple suspicious files in the same directory.
- Escalate if the user reports opening a torrent, archive, or installer immediately before the alert and the file is not an approved package.

**Containment actions:**
- Isolate the endpoint if the file is confirmed malicious or the host shows active post-execution behavior.
- Terminate the suspicious process tree and quarantine the dropped file through endpoint response actions.
- Block the file hash and related filenames in endpoint protection and email/web controls if applicable.
- Preserve volatile evidence and collect the process tree before rebooting or cleaning the host.

**Closure criteria:**
- The dropped file was confirmed benign, signed, and associated with an approved installer or updater.
- No persistence, malicious child processes, or suspicious network activity were found.
- The file hash was reviewed and not associated with known malware.
- Any required exclusions for legitimate software deployment tools have been documented.

<br/>
---
<br/>

## Detection 5: MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints

### Detection Opportunity

MovieReaper malware communicates with C2 infrastructure hosted on the Solana blockchain by making outbound connections to Solana RPC API endpoints from non-browser processes, following torrent-delivered trojan execution.

### Intelligence Context

- Securelist: The Odyssey and trojans again: MovieReaper attacks users in multiple countries via compromised torrents — [https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/](https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/)
  - Context: MovieReaper uses the Solana blockchain to host its C2 infrastructure, making outbound connections to Solana RPC nodes from the infected endpoint. Connections to Solana RPC endpoints from non-browser, non-crypto-wallet processes are anomalous and indicative of blockchain-based C2 communication.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071.001, T1071
- Products: Not specified
- Platforms: endpoint, web
- Malware: MovieReaper
- Tools: Not specified
- Search tags: MovieReaper, endpoint, web, T1071.001, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: command-and-control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- DeviceNetworkEvents.RemoteUrl is not populated for all connection types in Defender for Endpoint; HTTPS connections may only populate RemoteIP and RemotePort, causing domain-based filtering to miss connections where DNS resolution is not captured. Port 8899 filter provides a fallback but Solana RPC over HTTPS uses port 443 in most public deployments.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let SolanaRpcDomains = dynamic(["api.mainnet-beta.solana.com", "api.devnet.solana.com", "api.testnet.solana.com", "solana-api.projectserum.com", "rpc.ankr.com"]);
let KnownBrowsers = dynamic(["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe", "iexplore.exe", "safari.exe", "vivaldi.exe", "waterfox.exe"]);
let KnownCryptoWallets = dynamic(["phantom.exe", "solflare.exe", "backpack.exe", "exodus.exe", "atomic.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where (RemoteUrl has_any (SolanaRpcDomains)) or (RemotePort in (8899, 8900) and isnotempty(RemoteIP))
| where InitiatingProcessFileName !in~ (KnownBrowsers)
| where InitiatingProcessFileName !in~ (KnownCryptoWallets)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate cryptocurrency wallet applications (Phantom, Solflare, Backpack) installed on endpoints will connect to Solana RPC endpoints and will match if not excluded.
- Blockchain development tools and Solana CLI utilities installed by developers will match.
- Electron-based crypto applications may use process names not in the browser exclusion list.

**Tuning notes:**
- Validate RemoteUrl field population in the environment by running: DeviceNetworkEvents → where isnotempty(RemoteUrl) → summarize count() by bin(Timestamp, 1h) — if RemoteUrl is sparsely populated, consider supplementing with DNS query logs from DeviceEvents where ActionType == 'DnsQueryResponse'.
- Expand SolanaRpcDomains with additional third-party RPC providers observed in network telemetry.
- Add any legitimate blockchain or crypto wallet process names observed in results to KnownCryptoWallets before scheduling as a recurring hunt.

**Risks / caveats:**
- DeviceNetworkEvents.RemoteUrl is not populated for all connection types in Defender for Endpoint; HTTPS connections may only populate RemoteIP and RemotePort, causing domain-based filtering to miss connections where DNS resolution is not captured. Port 8899 filter provides a fallback but Solana RPC over HTTPS uses port 443 in most public deployments.
- Requires Microsoft Defender for Endpoint to be deployed on monitored endpoints.
- RemoteUrl may not be populated for HTTPS connections in all MDE configurations; connections to Solana RPC over port 443 will only be caught by the port filter if RemoteIP is populated, and port 443 alone is too broad to include as a filter without domain confirmation.
- The Solana RPC domain list covers major public endpoints but third-party or private RPC providers used by MovieReaper variants will not be caught by domain filtering.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process is not a known browser, wallet, or approved blockchain tool and review its folder path and command line.
- Check whether the remote destination is a known Solana RPC domain or validator port and whether the connection was successful.
- Review the user context and process tree to see whether the process originated from a user-writable directory or from a recent suspicious download.
- Look for related file creation, execution, or persistence events on the same host around the connection time.

**Evidence to collect:**
- Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, and Protocol.
- Process tree and parent process for the network-initiating binary.
- Any recent file creation or execution events for the same binary or related payloads.
- Threat intelligence or reputation data for the remote domain, IP, and the initiating process hash if available.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and RemoteUrl/RemoteIP over the prior 24 hours.
- DeviceProcessEvents for the initiating process name, folder path, and parent process.
- DeviceFileEvents for recent writes to the same folder path or executable name.
- DNS or proxy logs if RemoteUrl is not consistently populated in endpoint telemetry.

**Benign explanations:**
- Legitimate crypto wallet applications or Solana development tools may connect to RPC endpoints.
- Some Electron-based applications may use non-browser process names while still being benign.
- Developer workstations may legitimately access Solana RPC services for testing or blockchain development.

**Escalation criteria:**
- Escalate if the process is not an approved browser, wallet, or developer tool and the connection is to a Solana RPC endpoint.
- Escalate if the process runs from a user-writable directory or follows a recent suspicious download or execution event.
- Escalate if the same host also shows persistence, additional payloads, or other malware-like behavior.
- Escalate if multiple endpoints show the same non-browser Solana RPC pattern and the software is not approved.

**Containment actions:**
- Isolate the endpoint if the process is unapproved and the connection pattern is consistent with malware C2.
- Terminate the suspicious process and block the remote domain or IP if it is confirmed malicious or unauthorized.
- Remove or disable the suspicious binary if it is not a sanctioned application.
- Preserve process and network evidence before remediation if compromise is likely.

**Closure criteria:**
- The process was identified as an approved browser, wallet, or developer tool with a documented business purpose.
- No additional malicious behavior, persistence, or suspicious file activity was found on the host.
- The remote destination and process lineage were validated as benign.
- Any required allowlist or exclusion updates have been recorded for future tuning.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Licensing / identity risk fields:**
- Malspam Quarantine - Attachment Blocked by Mail Gateway: Requires Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing; EmailEvents and EmailAttachmentInfo are not available without it.

**Telemetry availability:**
- AWS AgentCore - Anomalous Credential Access from Agent Workload Identity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail before scheduling.
- AWS AgentCore - Credential Access Followed by High-Volume Outbound Network Activity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail, CommonSecurityLog before scheduling.

**Schema / correlation keys:**
- MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints: DeviceNetworkEvents.RemoteUrl is not populated for all connection types in Defender for Endpoint; HTTPS connections may only populate RemoteIP and RemotePort, causing domain-based filtering to miss connections where DNS resolution is not captured. Port 8899 filter provides a fallback but Solana RPC over HTTPS uses port 443 in most public deployments.

**Shared-table notes:**
- AWSCloudTrail: shared by AWS AgentCore - Anomalous Credential Access from Agent Workload Identity; AWS AgentCore - Credential Access Followed by High-Volume Outbound Network Activity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Malspam Quarantine - Attachment Blocked by Mail Gateway; MovieReaper - Executable Dropped and Launched from User-Writable Directory; MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints.
2. Resolve environment-mapping detections next: AWS AgentCore - Anomalous Credential Access from Agent Workload Identity; AWS AgentCore - Credential Access Followed by High-Volume Outbound Network Activity.

### Hunting Agenda and Promotion Criteria

- AWS AgentCore - Anomalous Credential Access from Agent Workload Identity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail before scheduling..
- AWS AgentCore - Credential Access Followed by High-Volume Outbound Network Activity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AWSCloudTrail, CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
