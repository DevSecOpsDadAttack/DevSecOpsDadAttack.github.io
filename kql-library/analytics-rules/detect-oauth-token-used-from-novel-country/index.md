---
layout: page
title: Detect Oauth Token Used From Novel Country
subtitle: "OAuth token used from a country the user has never signed in from — ToddyCat/Umbrij downstream shape where the token itself is the payload."
permalink: /kql-library/analytics-rules/detect-oauth-token-used-from-novel-country/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/analytics-rules/' | relative_url }}">Analytics Rules</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-shield-halved" aria-hidden="true"></i>&nbsp;Analytics Rules</span>
  <code class="kql-lib-query-file">detect-oauth-token-used-from-novel-country.kql</code>
</div>

<p class="kql-lib-query-longdesc">OAuth token used from a country the user has never signed in from — ToddyCat/Umbrij downstream shape where the token itself is the payload.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/credential-access/' | relative_url }}">Credential Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1550-001/' | relative_url }}">T1550.001</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1528/' | relative_url }}">T1528</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Actors</span>
    <a class="kql-lib-tag kql-lib-tag-actor" href="{{ '/kql-library/tag/toddycat/' | relative_url }}">ToddyCat</a>
    <a class="kql-lib-tag kql-lib-tag-actor" href="{{ '/kql-library/tag/umbrij/' | relative_url }}">Umbrij</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/signinlogs/' | relative_url }}">SigninLogs</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/aadnoninteractiveusersigninlogs/' | relative_url }}">AADNonInteractiveUserSignInLogs</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-oauth-token-used-from-novel-country">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-oauth-token-used-from-novel-country.kql' | relative_url }}" download="detect-oauth-token-used-from-novel-country.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-oauth-token-used-from-novel-country" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects an OAuth token being used from a country the user has never signed in from — the
// downstream half of the ToddyCat/Umbrij shape where the token itself is the payload. Correlates
// SigninLogs and AADServicePrincipalSignInLogs against a rolling per-user country baseline.
// Source: KQL Detection of the Week: The Login Was Never the Point (2026-07-06) — https://devsecopsdadattack.com/2026-07-06-KQL-Detection-of-the-Week_-The-Login-Was-Never-the-Point/
// Tactics: Defense Evasion, Credential Access
// Techniques: T1550.001, T1528
// Actors: ToddyCat, Umbrij
// Platforms: Entra ID, Microsoft 365
// Data: SigninLogs, AADNonInteractiveUserSignInLogs

let baselineStart = ago(30d);
let baselineEnd = ago(1d);
let alertWindow = 1d;
let baseline = SigninLogs
| where TimeGenerated between (baselineStart .. baselineEnd)
| where AppDisplayName has_any ("Google", "Gmail", "Google Workspace")
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize BaselineCountries = make_set(Country) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(alertWindow)
| where AppDisplayName has_any ("Google", "Gmail", "Google Workspace")
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| join kind=inner baseline on UserPrincipalName
| where not(Country in (BaselineCountries))
| extend RiskSignal = case(
    RiskLevelDuringSignIn in ("medium", "high"), "ElevatedRisk",
    ConditionalAccessStatus == "failure", "CAFailure",
    "NoRiskSignal"
)
| where RiskLevelDuringSignIn in ("medium", "high")
    or ConditionalAccessStatus == "failure"
| project
    TimeGenerated, UserPrincipalName, IPAddress, Country, BaselineCountries,
    AppDisplayName, RiskLevelDuringSignIn, ConditionalAccessStatus, RiskSignal,
    DeviceDetail, CorrelationId
| sort by TimeGenerated desc
```

</div>
