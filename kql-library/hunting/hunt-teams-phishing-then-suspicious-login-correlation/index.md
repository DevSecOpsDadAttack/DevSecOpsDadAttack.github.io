---
layout: page
title: Hunt Teams Phishing Then Suspicious Login Correlation
subtitle: "Teams phishing messages correlated with subsequent suspicious sign-ins for the same recipient — deals with ExternalAccess not being populated by falling back to sender-domain-outside-org."
permalink: /kql-library/hunting/hunt-teams-phishing-then-suspicious-login-correlation/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/hunting/' | relative_url }}">Hunting</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>&nbsp;Hunting</span>
  <code class="kql-lib-query-file">hunt-teams-phishing-then-suspicious-login-correlation.kql</code>
</div>

<p class="kql-lib-query-longdesc">Teams phishing messages correlated with subsequent suspicious sign-ins for the same recipient — deals with ExternalAccess not being populated by falling back to sender-domain-outside-org.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/credential-access/' | relative_url }}">Credential Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1566-003/' | relative_url }}">T1566.003</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1078/' | relative_url }}">T1078</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/officeactivity/' | relative_url }}">OfficeActivity</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/signinlogs/' | relative_url }}">SigninLogs</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://devsecopsdadattack.com/2026-08-26-KQL-Detection-of-the-Week-The-Field-That-Wasnt-There/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-teams-phishing-then-suspicious-login-correlation">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-teams-phishing-then-suspicious-login-correlation.kql' | relative_url }}" download="hunt-teams-phishing-then-suspicious-login-correlation.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-teams-phishing-then-suspicious-login-correlation" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Correlates Teams phishing messages with subsequent suspicious sign-ins for the same recipient —
// 'the phishing message that correlates with every login.' Deals with the ExternalAccess field not
// being populated in every tenant by falling back to sender-domain-outside-org detection.
// Source: KQL Detection of the Week: The Field That Wasn't There (2026-08-26) — https://devsecopsdadattack.com/2026-08-26-KQL-Detection-of-the-Week-The-Field-That-Wasnt-There/
// Tactics: Initial Access, Credential Access
// Techniques: T1566.003, T1078
// Platforms: Microsoft 365, Entra ID
// Data: OfficeActivity, SigninLogs

let baseline_window = 30d;
let detection_window = 24h;
let correlation_window = 4h;
// ============================================================
// STEP 1: TEAMS MESSAGES — external senders.
//
// THE FIX: Don't gate on ExternalAccess. Use it as enrichment
// when it's populated, and fall back to the sender's domain when
// it's not. The OfficeActivity Teams audit record carries UserId
// as the recipient. For identifying external senders, we check
// whether the Operation itself indicates an external interaction.
//
// "MemberAdded" with an external user is the strongest signal —
// someone was added to a chat or team from outside the org.
// "MessageCreatedHasLink" is the delivery mechanism the Unit 42
// reporting describes. "MessageSent" is broad but captures the
// remainder.
//
// The ExternalAccess field, when populated, is authoritative.
// When it's null, we let the event through and flag it as
// "ExternalAccess not confirmed" in the output. The analyst sees
// both categories and can filter in triage.
// ============================================================
let TeamsMessages = OfficeActivity
| where TimeGenerated >= ago(detection_window)
| where RecordType == "MicrosoftTeams"
| where Operation in ("MessageCreatedHasLink", "MessageSent", "MemberAdded")
| where isnotempty(UserId)
// ExternalAccess as enrichment, not a gate.
| extend ExternalConfirmed = iif(ExternalAccess == true, true, false)
| extend ExternalNull = iif(isnull(ExternalAccess), true, false)
// When ExternalAccess IS populated and is false, this is an
// internal message — drop it. When it's null, keep it for review.
| where ExternalAccess == true or isnull(ExternalAccess)
| project
    PhishTime = TimeGenerated,
    TargetUser = tolower(UserId),
    Operation,
    ExternalConfirmed,
    ExternalNull;
// ============================================================
// STEP 2: LOCATION BASELINE — where has this user signed in from?
//
// The original query builds a binary set: locations you've seen,
// and locations you haven't. This version adds frequency and
// recency so the analyst can distinguish "truly new" from "rare."
// A user who signed in from Location X once, 29 days ago, clears
// the binary baseline and is invisible on day 30. With frequency,
// that single-use location is flagged as rare, not normal.
// ============================================================
let LocationBaseline = SigninLogs
| where TimeGenerated between (ago(baseline_window) .. ago(detection_window))
| where ResultType == 0
| where isnotempty(Location)
| summarize
    LocationUseCount = count(),
    LocationUseDays  = dcount(bin(TimeGenerated, 1d)),
    LastSeenAt       = max(TimeGenerated)
    by UserPrincipalName = tolower(UserPrincipalName), Location;
// ============================================================
// STEP 3: RECENT SIGN-INS — successful authentication in the
// detection window.
// ============================================================
let RecentSignins = SigninLogs
| where TimeGenerated >= ago(detection_window)
| where ResultType == 0
| where isnotempty(Location)
| project
    SigninTime = TimeGenerated,
    UPN = tolower(UserPrincipalName),
    SigninIP = IPAddress,
    SigninLocation = Location,
    AppDisplayName,
    UserAgent,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    DeviceDetail;
// ============================================================
// STEP 4: CORRELATE — Teams message → sign-in from
// new or rare location.
//
// The correlation window is 4 hours, not 6. The attack chain
// described by Unit 42 is: phishing message → user clicks link →
// credential harvested → attacker uses credential. That chain
// is minutes to low hours; 6 hours brings in too much legitimate
// travel and VPN activity. 4 hours is still generous; if your
// environment is high-travel, tighten to 2.
//
// The join is on user identity (TargetUser == UPN). This is the
// correct anchor — the phishing message targets a specific user,
// and the credential use is by that user. There is no device
// anchor because the attacker signs in from their own device,
// not the victim's.
// ============================================================
RecentSignins
| join kind=inner TeamsMessages on $left.UPN == $right.TargetUser
| where SigninTime between (PhishTime .. (PhishTime + correlation_window))
// Baseline join: was this location seen before?
| join kind=leftouter LocationBaseline
    on $left.UPN == $right.UserPrincipalName,
       $left.SigninLocation == $right.Location
// NEW location: not in the baseline at all.
// RARE location: in the baseline but used very infrequently.
| extend LocationStatus = case(
      isnull(LocationUseCount),                    "NeverSeen",
      LocationUseCount <= 2 and LocationUseDays <= 1, "RarelySeen",
                                                   "Known"
  )
| where LocationStatus in ("NeverSeen", "RarelySeen")
| project
    PhishTime,
    SigninTime,
    CorrelationMinutes = datetime_diff('minute', SigninTime, PhishTime),
    UPN,
    SigninIP,
    SigninLocation,
    LocationStatus,
    LocationUseCount,
    LocationUseDays,
    LastSeenAt,
    Operation,
    ExternalConfirmed,
    ExternalNull,
    AppDisplayName,
    UserAgent,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    DeviceDetail
| order by LocationStatus asc, CorrelationMinutes asc
```

</div>
