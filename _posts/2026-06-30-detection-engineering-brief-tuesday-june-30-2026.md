---
layout: post
title: "Detection Engineering Brief - Tuesday, June 30, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-30
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - ToddyCat
  - Gmail
  - Google Workspace
  - OAuth
  - Umbrij
  - T1190
  - LiteLLM
  - Metasploit Framework
  - Next.js
  - Dalfox
  - Perplexity AI
  - Chromium-based browsers
  - Windows
  - T1098.003
  - T1098
  - T1176
---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: ToddyCat, Gmail, Google Workspace, OAuth, Umbrij, T1190, LiteLLM, Metasploit Framework, Next.js, Dalfox, Perplexity AI, Chromium-based browsers, Windows, T1098.003, T1098, T1176.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Metasploit - LiteLLM Proxy SQL Injection Probe via WAF Logs; Metasploit - Next.js Middleware Authorization Bypass Probe; Metasploit - Dalfox Deserialization RCE: Unexpected Child Process Spawned by Web Service; Malicious Chromium Extension Installation with Outbound Search Redirect Behavior.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: ToddyCat - Suspicious OAuth2 Permission Grant Targeting Google Services

### Detection Opportunity

OAuth authorization tokens granted to external Google service applications from corporate identities, consistent with ToddyCat Umbrij tooling access pattern.

### Intelligence Context

- Securelist: ToddyCat: your hidden email assistant. Part 2 — [https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/](https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/)
  - Context: ToddyCat used the Umbrij tool to target OAuth authorization tokens, enabling persistent access to Google Workspace and Gmail on behalf of compromised corporate identities.

### Search Metadata

- CVEs: Not specified
- Threat actors: ToddyCat
- ATT&CK tags: T1098.003, T1098
- Products: Gmail, Google Workspace, OAuth
- Platforms: Not specified
- Malware: Not specified
- Tools: Umbrij
- Search tags: ToddyCat, Gmail, Google Workspace, OAuth, Umbrij, T1098.003, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Credentials (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- AuditLogs, SigninLogs

### KQL

```kql
let lookback = 1d;
let googleKeywords = dynamic(["google", "gmail", "googleapis", "workspace"]);
let oauthGrants = AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName =~ "Add delegated permission grant" or OperationName =~ "Consent to application"
| extend TargetResource = tostring(TargetResources[0].displayName)
| extend TargetResourceId = tostring(TargetResources[0].id)
| extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| where isnotempty(InitiatedByUPN)
| where TargetResource has_any (googleKeywords)
    or TargetResourceId has_any (googleKeywords)
    or tostring(AdditionalDetails) has_any (googleKeywords)
| project GrantTime = TimeGenerated, InitiatedByUPN, InitiatedByIP, TargetResource, TargetResourceId, OperationName, CorrelationId;
let recentSignins = SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ConditionalAccessStatus;
oauthGrants
| join kind=inner recentSignins
    on $left.InitiatedByUPN == $right.UserPrincipalName
| where SigninTime <= GrantTime and GrantTime <= SigninTime + 30m
| project GrantTime, SigninTime, InitiatedByUPN, InitiatedByIP, TargetResource, TargetResourceId, OperationName, AppDisplayName, ConditionalAccessStatus, CorrelationId
| order by GrantTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Administrators legitimately consenting to Google Workspace connector applications (e.g., Google Calendar sync, Google Drive connectors) will trigger this rule.
- Users who authenticate and then immediately authorize a Google API integration tool (e.g., Zapier, Make) within the 30-minute window will produce matches.

Tuning notes:
- Build an allowlist of approved Google application display names or client IDs and add a 'not in' filter on TargetResource to suppress known-good consent events.
- Consider adding a watchlist of privileged or sensitive UPNs to elevate severity for those accounts.
- Extend googleKeywords with specific Google API client IDs observed in the tenant if display names are inconsistent.

Risks / caveats:
- AuditLogs.TargetResources is a dynamic array; tostring(TargetResources[0].displayName) will return empty string if the array is empty or the schema differs across Entra ID audit event categories. Validate that 'Add delegated permission grant' and 'Consent to application' events populate TargetResources[0].displayName in the tenant.
- InitiatedBy.user.userPrincipalName and InitiatedBy.user.ipAddress are nested dynamic fields that may be null for service-principal-initiated grants; the query will silently drop those rows from the join.
- The 30-minute correlation window between sign-in and grant may need adjustment based on observed authentication patterns; a very short window reduces FPs but may miss delayed consent flows.
- If the tenant has high volumes of Google API consent events (e.g., a Google Workspace-integrated environment), alert volume will be high until an exclusion list for approved applications is built.

### Triage Runbook

First 15 minutes:
- Confirm the grant event details: InitiatedByUPN, TargetResource/TargetResourceId, AppDisplayName, CorrelationId, and GrantTime.
- Check whether the user recently signed in from the same IP or an unusual IP/geo and whether ConditionalAccessStatus indicates a bypass or failure.
- Identify whether the granted app is approved, expected, or tied to a known Google Workspace integration; if not, treat as suspicious.
- Review the account’s recent activity for mailbox access, token use, consent changes, forwarding rules, or other post-consent abuse.
- If the account is privileged or sensitive, immediately notify the incident lead and identity team for parallel review.

Evidence to collect:
- AuditLogs entries for the consent/grant event and any related consent modifications around the same time.
- SigninLogs for the user covering at least 24 hours before and after the grant, including IPAddress, AppDisplayName, and ConditionalAccessStatus.
- The exact OAuth client/application name, client ID if available, and requested scopes/permissions.
- Any mailbox or Workspace activity after the grant, including unusual access patterns, forwarding, or delegated access changes.
- User context: whether the user reported the consent, was phished, or was performing a legitimate Google integration setup.

Pivot points:
- AuditLogs filtered on the same InitiatedByUPN, CorrelationId, TargetResourceId, or AppDisplayName.
- SigninLogs for the same user and source IPs to identify preceding sign-in and subsequent token use.
- Google Workspace/Gmail audit logs if available to confirm token use, mailbox access, or admin actions.
- Identity protection or Entra ID risk events for the same account.
- Watchlists or allowlists of approved Google applications and service accounts.

Benign explanations:
- A user or admin legitimately connected an approved Google Workspace app such as calendar, drive, or mail sync.
- A sanctioned automation platform such as Zapier or Make was newly authorized by the user.
- A break-glass or service account performed a planned integration or migration task.
- A helpdesk or admin action created a consent event during onboarding or troubleshooting.

Escalation criteria:
- The app is unapproved, unknown, or impersonates a Google service.
- The consent was followed by unusual sign-ins, impossible travel, MFA fatigue, or other identity risk indicators.
- The account is privileged, handles sensitive mail, or belongs to an executive or admin.
- There is evidence of mailbox access, forwarding rule creation, or token abuse after the grant.

Containment actions:
- Revoke the suspicious OAuth grant and invalidate related refresh tokens if the app is not approved.
- Reset the user’s password and force reauthentication if there are signs of compromise.
- Disable the account temporarily if privileged access or active abuse is confirmed.
- Block the application/client ID tenant-wide if it is malicious or clearly unauthorized.

Closure criteria:
- The application is confirmed approved and the grant matches a documented business need.
- No suspicious sign-ins, token use, mailbox activity, or follow-on abuse is found.
- The event is attributable to a known integration or migration with supporting change records.
- Allowlist or tuning has been updated for the approved app or service account.

---

## Detection 2: Metasploit - LiteLLM Proxy SQL Injection Probe via WAF Logs

### Detection Opportunity

HTTP requests to LiteLLM Proxy endpoints containing SQL injection payload patterns, consistent with exploitation attempts using the public Metasploit module.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: A new Metasploit module for SQL injection against LiteLLM Proxy was released, raising the likelihood of opportunistic exploitation attempts against exposed LiteLLM instances.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: LiteLLM
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit Framework
- Search tags: T1190, LiteLLM, Metasploit Framework

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let lookback = 1d;
let sqliPatterns = dynamic(["' OR ", "1=1", "UNION SELECT", "xp_", "SLEEP(", "WAITFOR", "BENCHMARK(", "' AND ", "OR 1=", "AND 1="]);
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where RequestURL has "litellm" or DestinationHostName has "litellm"
| where RequestURL has_any (sqliPatterns)
    or AdditionalExtensions has_any (sqliPatterns)
| summarize
    RequestCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Methods = make_set(RequestMethod),
    ResponseCodes = make_set(ResponseCode),
    SampleURLs = make_set(RequestURL, 5)
    by SourceIP, bin(TimeGenerated, 10m)
| where RequestCount >= 3
| project-away TimeGenerated
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Internal penetration testing or vulnerability scanning tools targeting LiteLLM endpoints will match.
- URL-encoded query parameters in legitimate LiteLLM API calls that contain substrings like '--' or '1=1' in model names or prompt content may match.

Tuning notes:
- If LiteLLM is deployed with a non-default hostname, add that hostname to the DestinationHostName filter.
- Consider adding specific LiteLLM API path segments (e.g., '/v1/completions', '/health') to the URL filter to reduce matching against unrelated traffic on the same host.
- Raise RequestCount threshold to 10 or higher if the environment has high-frequency automated clients.

Risks / caveats:
- CommonSecurityLog requires an active CEF/Syslog connector from a WAF or network appliance. If no such connector is configured, the table will be empty or absent.
- RequestURL field population is vendor-dependent; some CEF sources do not populate RequestURL and instead embed the URL in AdditionalExtensions or Message. The query may return no results if the WAF vendor does not map URLs to the RequestURL field.
- LiteLLM traffic must be routable through the WAF and the hostname or path must contain the string 'litellm'. Deployments using IP-based routing or non-default hostnames will not match.
- The threshold of 3 requests per 10-minute bin may need upward adjustment in environments with automated API clients that send bursts of legitimate requests to LiteLLM.

### Triage Runbook

First 15 minutes:
- Identify the source IP, request volume, methods, response codes, and sample URLs from the alert.
- Check whether the source IP belongs to an internal scanner, penetration test, monitoring system, or known security team asset.
- Confirm whether the targeted host is an exposed LiteLLM Proxy instance and whether the requests hit sensitive endpoints.
- Look for a burst of similar requests, repeated payload patterns, or follow-on requests from the same source IP.
- If the source is external and not recognized, notify the application owner and network team for validation.

Evidence to collect:
- WAF/CommonSecurityLog entries for the source IP, request paths, methods, response codes, and timestamps.
- Any reverse proxy or application logs showing the same requests and whether they reached the backend.
- LiteLLM application logs for errors, SQL exceptions, or abnormal authentication/session behavior.
- Asset inventory details for the destination host, including whether it is internet-facing and what version is deployed.
- Any change records or approved testing windows that explain the traffic.

Pivot points:
- CommonSecurityLog for the same SourceIP across a wider time window to identify broader scanning.
- Web server or reverse proxy logs for the destination host and adjacent endpoints.
- Application logs from LiteLLM for SQL errors, stack traces, or unusual admin actions.
- Firewall or proxy logs to determine whether the source IP is external, internal, or VPN-originated.
- Threat intel or internal scanner allowlists for the source IP.

Benign explanations:
- An internal vulnerability scanner or penetration test generated the requests.
- A monitoring or health-check tool sent malformed query strings that resemble SQL injection patterns.
- A legitimate API client produced URL-encoded content that partially matched the pattern set.
- A developer or tester was validating the application in a non-production environment.

Escalation criteria:
- Requests are coming from an external IP not on an approved testing list.
- The same source shows repeated probes across multiple endpoints or hosts.
- The application logs show SQL errors, crashes, or signs of backend impact.
- There is evidence of successful exploitation, authentication bypass, or data access after the probe.

Containment actions:
- Block or rate-limit the source IP at the WAF or edge if the activity is clearly malicious and external.
- Place the LiteLLM service behind stricter access controls if it is exposed unnecessarily.
- Engage the application owner to patch, harden, or temporarily restrict the endpoint if exploitation is suspected.
- Preserve logs before making changes that could erase evidence.

Closure criteria:
- The source is confirmed as an approved scanner, tester, or monitoring system.
- No application errors, backend impact, or follow-on exploitation are observed.
- The traffic is explained by a known test window or benign client behavior.
- Allowlist or tuning has been updated for the approved source or endpoint pattern.

---

## Detection 3: Metasploit - Next.js Middleware Authorization Bypass Probe

### Detection Opportunity

HTTP requests targeting Next.js middleware paths with authorization bypass characteristics, consistent with scanning activity using the public Metasploit module.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: A Metasploit scanner module for Next.js Middleware Authorization Bypass was released, enabling automated probing of Next.js applications for middleware-level authentication weaknesses.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Next.js
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit Framework
- Search tags: T1190, Next.js, Metasploit Framework

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

Required telemetry:
- CommonSecurityLog

### KQL

```kql
let lookback = 1d;
let nextjsPaths = dynamic(["/_next/", "/__nextjs", "/api/"]);
let bypassHeaders = dynamic(["x-middleware-subrequest", "x-invoke-path", "x-nextjs-data"]);
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where RequestURL has_any (nextjsPaths)
| where ResponseCode == 200
| where AdditionalExtensions has_any (bypassHeaders)
    or RequestURL matches regex @"/_next/(?!static)[^.]+$"
| summarize
    HitCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DistinctPaths = dcount(RequestURL),
    SamplePaths = make_set(RequestURL, 5),
    DestinationHosts = make_set(DestinationHostName, 5)
    by SourceIP, bin(TimeGenerated, 5m)
| where HitCount >= 5 or DistinctPaths >= 3
| project-away TimeGenerated
| order by HitCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- CDN prefetch and cache-warming requests to /_next/ static asset paths will match the path filter and may exceed the HitCount threshold.
- Legitimate API clients making multiple requests to /api/ endpoints within a 5-minute window will match the summarize threshold.

Tuning notes:
- Scope DestinationHostName to the specific hostnames of Next.js applications in the environment to reduce cross-application noise.
- If the WAF vendor does not populate AdditionalExtensions with headers, consider removing the header branch and relying solely on the URL regex branch.
- Increase HitCount threshold to 15-20 for high-traffic environments.

Risks / caveats:
- CommonSecurityLog requires an active CEF/Syslog connector from a WAF or reverse proxy. If no such connector is configured, the table will be empty or absent.
- AdditionalExtensions field content is entirely vendor-dependent. HTTP request headers such as x-middleware-subrequest are not a standard CEF field and may not appear in AdditionalExtensions for all WAF vendors. The header-based detection branch may produce zero results.
- Next.js applications must be routed through the WAF feeding CommonSecurityLog. Direct-to-origin traffic will not be visible.
- The header-based detection branch (AdditionalExtensions has_any bypassHeaders) will produce no results if the WAF vendor does not include HTTP request headers in AdditionalExtensions.

### Triage Runbook

First 15 minutes:
- Identify the source IP, destination host, request paths, and whether the bypass-related headers are present.
- Confirm whether the destination is a production Next.js application and whether the paths are dynamic application routes rather than static assets.
- Check if the source is a known CDN, health checker, QA tool, or internal scanner.
- Look for repeated requests to multiple paths or a pattern of 200 responses that suggest successful probing.
- Notify the application owner if the host is production-facing and the source is not recognized.

Evidence to collect:
- CommonSecurityLog entries for the source IP, destination host, request paths, response codes, and any header data in AdditionalExtensions.
- Reverse proxy or application logs showing whether the requests reached the app and whether middleware was bypassed.
- Application authentication logs for unusual 200 responses on protected routes.
- Asset inventory or routing configuration showing which hostnames are Next.js applications.
- Approved scanner or CDN source lists for comparison.

Pivot points:
- CommonSecurityLog for the same SourceIP and DestinationHostName over a broader window.
- Web application logs for protected routes, login endpoints, and middleware decisions.
- Identity/authentication logs for successful access to protected content from the same source IP.
- CDN or load balancer logs to determine whether the traffic was edge-generated or external.
- Change records for recent Next.js deployments or middleware changes.

Benign explanations:
- A CDN, cache warmer, or synthetic monitor requested dynamic routes.
- An internal QA or security test exercised middleware behavior intentionally.
- A legitimate API client repeatedly accessed /api/ endpoints within the alert window.
- The WAF or proxy logged header content that resembles bypass indicators without actual exploitation.

Escalation criteria:
- The source is external and not on an approved testing list.
- Protected routes returned 200 responses unexpectedly or middleware behavior appears bypassed.
- There are multiple distinct paths or hosts being probed in a short period.
- The application owner confirms the middleware should have blocked the requests but did not.

Containment actions:
- Block or rate-limit the source IP if the activity is malicious and external.
- Temporarily restrict access to the affected application if bypass is confirmed and exposure is high.
- Coordinate with the app owner to patch or reconfigure middleware and validate access controls.
- Preserve logs and request samples before making changes.

Closure criteria:
- The source is confirmed as an approved scanner, CDN, or internal test system.
- No evidence of successful bypass or unauthorized access is found.
- The alert is attributable to expected application traffic or a known test.
- Tuning has been applied for approved sources or known benign paths.

---

## Detection 4: Metasploit - Dalfox Deserialization RCE: Unexpected Child Process Spawned by Web Service

### Detection Opportunity

Unexpected child processes spawned by a web server or Dalfox service process following inbound HTTP requests, consistent with successful deserialization RCE exploitation via the public Metasploit module.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for Audiobookshelf, LiteLLM, Next.js, Dalfox and more — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-modules-for-audiobookshelf-litellm-next-js-dalfox-and-more)
  - Context: A Metasploit module for deserialization RCE against Dalfox was released. Successful exploitation would result in arbitrary command execution, observable as unexpected child processes spawned by the Dalfox or web server process.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Dalfox
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit Framework
- Search tags: T1190, Dalfox, Metasploit Framework

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let lookback = 1d;
let webParents = dynamic(["dalfox", "nginx", "apache2", "httpd", "node", "java", "tomcat", "gunicorn", "uvicorn"]);
let suspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "sh", "bash", "wget", "curl", "nc", "ncat", "perl", "ruby", "mshta.exe", "wscript.exe", "cscript.exe"]);
DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where InitiatingProcessFileName has_any (webParents)
| where FileName has_any (suspiciousChildren)
    or ProcessCommandLine has_any (["/bin/sh", "/bin/bash", "cmd /c", "powershell -", "wget http", "curl http", "base64 -d"])
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName, AccountDomain
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Web servers that legitimately spawn shell scripts for log rotation, certificate renewal, or health checks will match the bash/sh child process filter.
- Python-based web frameworks (gunicorn, uvicorn) that spawn worker processes or management commands will generate matches on the python child process pattern.

Tuning notes:
- Scope DeviceName to the specific host(s) running Dalfox or the web service being protected to reduce cross-environment noise.
- Add FileName exclusions for known legitimate child processes (e.g., 'logrotate', 'certbot') that the web server spawns in the environment.
- If the environment does not run Dalfox as a service, remove 'dalfox' from webParents and retain only the web server process names relevant to the deployment.

Risks / caveats:
- Dalfox is a security research/scanning tool and is unlikely to be a production service on monitored endpoints. The 'dalfox' entry in webParents will match zero events in most environments unless Dalfox is explicitly deployed as a service.
- DeviceProcessEvents requires Defender for Endpoint (MDE) onboarding on the host running Dalfox or the associated web server. If the host is not MDE-enrolled, no telemetry will be available.
- On Linux hosts, process names in InitiatingProcessFileName may appear without file extensions (e.g., 'python' not 'python.exe'); the has_any operator handles this correctly, but Linux MDE onboarding must be confirmed.
- The webParents list uses substring matching via has_any, which means a process named 'node_exporter' would match 'node'. Consider using more precise matching if the environment has processes with overlapping name substrings.

### Triage Runbook

First 15 minutes:
- Identify the host, parent process, child process, command line, and account involved in the alert.
- Confirm whether the parent process is a legitimate web service on that host and whether Dalfox is expected to run there.
- Check whether the child process is a shell, scripting interpreter, downloader, or other high-risk utility.
- Review the timing of inbound requests around the process spawn to see if the execution followed web traffic.
- If the child process is suspicious and the host is internet-facing, escalate immediately to incident response.

Evidence to collect:
- DeviceProcessEvents for the parent and child process chain, including command lines and timestamps.
- Any web server, application, or container logs showing inbound requests immediately before the process spawn.
- Network telemetry from the host for outbound connections, downloads, or command-and-control indicators after the spawn.
- Host inventory and service configuration showing whether Dalfox or the web service is expected on the device.
- User and account context for the process owner, including whether the account is a service account.

Pivot points:
- DeviceProcessEvents for the same DeviceName and parent process over a wider time window.
- DeviceNetworkEvents for the host to identify outbound connections after the suspicious spawn.
- DeviceFileEvents for dropped files, scripts, or binaries created around the same time.
- Web server logs for the same host to correlate inbound requests with process creation.
- Defender XDR alerts for the same device or account to identify related activity.

Benign explanations:
- A web server legitimately spawned a maintenance script, log rotation job, or certificate renewal task.
- A development or test environment is running Dalfox or a similar security tool intentionally.
- A Python or Node-based web framework spawned worker processes or management commands as part of normal operation.
- An administrator performed a planned troubleshooting action from the web service account.

Escalation criteria:
- The child process is a shell, downloader, or command interpreter not normally used by the service.
- There are outbound connections, file drops, or additional suspicious processes after the spawn.
- The host is production or internet-facing and the process chain is not expected.
- The application owner cannot explain the process chain as legitimate.

Containment actions:
- Isolate the host if there is evidence of active exploitation or post-exploitation activity.
- Stop the affected service only if necessary to prevent further execution and after preserving evidence.
- Block suspicious outbound destinations if command-and-control or payload retrieval is observed.
- Preserve process, network, and web logs before remediation.

Closure criteria:
- The process chain is confirmed as a documented maintenance or service action.
- No suspicious outbound activity, file drops, or additional child processes are found.
- The host is confirmed to be a sanctioned test or security tool environment.
- The alert is tuned out for known benign child processes or approved hosts.

---

## Detection 5: Malicious Chromium Extension Installation with Outbound Search Redirect Behavior

### Detection Opportunity

New browser extension files written to Chrome profile extension directories on Windows endpoints, correlated with outbound network connections to unexpected search or redirect destinations, consistent with a malicious MV3 extension spoofing AI branding.

### Intelligence Context

- Microsoft Security Blog: Chromium extension uses AI-related branding to redirect browser search — [https://www.microsoft.com/en-us/security/blog/2026/06/29/chromium-extension-uses-airelated-branding-redirect-browser-search/](https://www.microsoft.com/en-us/security/blog/2026/06/29/chromium-extension-uses-airelated-branding-redirect-browser-search/)
  - Context: A malicious Chromium extension spoofing Perplexity AI branding used MV3 APIs and intermediary infrastructure to redirect browser search traffic. The extension installs into standard Chrome profile extension paths and establishes outbound connections to redirect destinations.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1176
- Products: Perplexity AI
- Platforms: Chromium-based browsers, Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Perplexity AI, Chromium-based browsers, Windows, T1176

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1176 Browser Session Hijacking (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- DeviceNetworkEvents.RemoteUrl is not consistently populated for Chrome browser connections in Defender for Endpoint telemetry. Many outbound connections from chrome.exe appear with RemoteIP and RemotePort only, with RemoteUrl empty. The redirect detection branch may return no results if RemoteUrl is not populated.

Required telemetry:
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 2d;
let knownSearchEngines = dynamic(["google.com", "bing.com", "duckduckgo.com", "yahoo.com", "ecosia.org", "brave.com", "googleapis.com", "gstatic.com", "chrome.google.com"]);
let extensionWrites = DeviceFileEvents
| where TimeGenerated >= ago(lookback)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath matches regex @"(?i)\\AppData\\Local\\Google\\Chrome\\User Data\\[^\\]+\\Extensions\\[a-z]{32}\\"
| where FileName in~ ("manifest.json", "background.js", "content.js", "service_worker.js")
| project WriteTime = TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName;
let redirectConnections = DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where InitiatingProcessFileName =~ "chrome.exe"
| where isnotempty(RemoteUrl)
| where not(RemoteUrl has_any (knownSearchEngines))
| where RemoteUrl has_any (["search", "query", "q=", "redirect"])
| project ConnTime = TimeGenerated, DeviceName, RemoteUrl, RemoteIP = tostring(RemoteIP), RemotePort, InitiatingProcessFileName;
extensionWrites
| join kind=inner redirectConnections on DeviceName
| where ConnTime between (WriteTime .. (WriteTime + 1h))
| project WriteTime, ConnTime, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, RemoteUrl, RemoteIP, RemotePort
| order by WriteTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate extension installations from the Chrome Web Store followed by the extension making API calls to search-related services will match.
- Enterprise-deployed extensions that use search or query parameters in their backend API calls will match the RemoteUrl filter.
- Chrome's own update mechanism writing manifest.json files during extension updates will match the file write filter.

Tuning notes:
- Add googleapis.com, gstatic.com, and chrome.google.com to knownSearchEngines to suppress Chrome's own extension update and sync traffic.
- To cover Microsoft Edge, add a second extensionWrites branch with the Edge AppData path: AppData\Local\Microsoft\Edge\User Data\[^\\]+\\Extensions\\.
- Consider reducing the correlation window to 15 minutes to reduce cross-activity false positives in high-user-density environments.
- If RemoteUrl is not populated in the environment, pivot to RemoteIP-based detection by correlating extension writes with connections to RemoteIPs not in a known-good IP allowlist.

Risks / caveats:
- DeviceNetworkEvents.RemoteUrl is not consistently populated for Chrome browser connections in Defender for Endpoint telemetry. Many outbound connections from chrome.exe appear with RemoteIP and RemotePort only, with RemoteUrl empty. The redirect detection branch may return no results if RemoteUrl is not populated.
- DeviceFileEvents may not capture all extension file writes if the Chrome process writes files through a mechanism that bypasses MDE file monitoring (e.g., Chrome's internal update mechanism writing directly via the browser process).
- RemoteUrl is sparsely populated in DeviceNetworkEvents for Chrome processes; the join will produce few or no results in environments where MDE does not capture Chrome URL-level telemetry. Analyst should validate RemoteUrl population before relying on this detection.
- The 1-hour correlation window between extension write and redirect connection may be too wide in environments with many concurrent Chrome users, generating cross-user false positive joins if DeviceName is shared (e.g., VDI).

### Triage Runbook

First 15 minutes:
- Identify the affected device, user account, extension folder path, and the timing of the file write and network connection.
- Confirm whether the extension ID or folder path matches an approved enterprise extension.
- Check whether the outbound destination is a known search engine, corporate proxy, or an unexpected redirect domain.
- Review browser-related process activity on the host for additional extension writes, downloads, or suspicious child processes.
- If the extension is unapproved or the redirect destination is suspicious, escalate and begin containment.

Evidence to collect:
- DeviceFileEvents showing the extension file creation or modification, including FolderPath, FileName, and initiating process details.
- DeviceNetworkEvents for the same device and time window, including RemoteUrl, RemoteIP, RemotePort, and initiating process.
- Browser profile and extension inventory from the endpoint to confirm installed extensions and permissions.
- User logon context and whether the browser profile belongs to a single user or a shared/VDI session.
- Any proxy, DNS, or web logs showing search redirection or intermediary infrastructure.

Pivot points:
- DeviceFileEvents for the same DeviceName and extension path to identify other files in the extension directory.
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessFileName to find additional suspicious destinations.
- DeviceProcessEvents for chrome.exe and related browser processes to identify downloads or script execution.
- Defender XDR alerts for browser hijacking, credential theft, or suspicious downloads on the same device.
- Proxy/DNS logs for the user or device to identify repeated redirects or search-domain anomalies.

Benign explanations:
- A legitimate Chrome or enterprise extension was installed or updated by the user or IT.
- Chrome auto-updated an extension and wrote manifest or service worker files.
- The browser made normal search-related requests to approved search engines or corporate proxy infrastructure.
- A managed browser policy deployed an extension as part of enterprise configuration.

Escalation criteria:
- The extension is not approved, is newly installed, or uses suspicious permissions or branding.
- The redirect destination is unknown, intermediary, or inconsistent with normal search behavior.
- There is evidence of multiple extension writes, unusual browser activity, or additional suspicious network connections.
- The affected user is privileged, handles sensitive data, or reports browser hijacking symptoms.

Containment actions:
- Remove or disable the suspicious browser extension and preserve the extension files for analysis.
- Isolate the endpoint if there are signs of broader compromise or credential theft.
- Reset browser sync/session state and force sign-out if the extension may have accessed user data.
- Block known malicious redirect domains or IPs at the proxy if confirmed.

Closure criteria:
- The extension is confirmed as approved, managed, or part of a documented deployment.
- The outbound traffic is explained by normal browser or enterprise extension behavior.
- No additional suspicious browser activity, redirects, or credential abuse is found.
- The endpoint is cleaned or the extension is removed and the user confirms normal browser behavior.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Metasploit - LiteLLM Proxy SQL Injection Probe via WAF Logs: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Metasploit - Next.js Middleware Authorization Bypass Probe: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Metasploit - Dalfox Deserialization RCE: Unexpected Child Process Spawned by Web Service: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.
- Malicious Chromium Extension Installation with Outbound Search Redirect Behavior: DeviceNetworkEvents.RemoteUrl is not consistently populated for Chrome browser connections in Defender for Endpoint telemetry. Many outbound connections from chrome.exe appear with RemoteIP and RemotePort only, with RemoteUrl empty. The redirect detection branch may return no results if RemoteUrl is not populated.

Schema / correlation keys:
- Malicious Chromium Extension Installation with Outbound Search Redirect Behavior: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- CommonSecurityLog: shared by Metasploit - LiteLLM Proxy SQL Injection Probe via WAF Logs; Metasploit - Next.js Middleware Authorization Bypass Probe

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: ToddyCat - Suspicious OAuth2 Permission Grant Targeting Google Services.
2. Resolve environment-mapping detections next: Metasploit - LiteLLM Proxy SQL Injection Probe via WAF Logs; Metasploit - Next.js Middleware Authorization Bypass Probe; Metasploit - Dalfox Deserialization RCE: Unexpected Child Process Spawned by Web Service.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Malicious Chromium Extension Installation with Outbound Search Redirect Behavior.

### Hunting Agenda and Promotion Criteria

- Malicious Chromium Extension Installation with Outbound Search Redirect Behavior: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Metasploit - LiteLLM Proxy SQL Injection Probe via WAF Logs: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Metasploit - Next.js Middleware Authorization Bypass Probe: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Metasploit - Dalfox Deserialization RCE: Unexpected Child Process Spawned by Web Service: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
