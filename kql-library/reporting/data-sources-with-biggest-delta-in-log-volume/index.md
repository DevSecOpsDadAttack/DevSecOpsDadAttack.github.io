---
layout: page
title: Data Sources With Biggest Delta In Log Volume
subtitle: "Data sources with the biggest log-volume delta between comparison periods — configurable tunables at the top of the query."
permalink: /kql-library/reporting/data-sources-with-biggest-delta-in-log-volume/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/reporting/' | relative_url }}">Reporting</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-chart-line" aria-hidden="true"></i>&nbsp;Reporting</span>
  <code class="kql-lib-query-file">data-sources-with-biggest-delta-in-log-volume.kql</code>
</div>

<p class="kql-lib-query-longdesc">Data sources with the biggest log-volume delta between comparison periods — configurable tunables at the top of the query.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/usage/' | relative_url }}">Usage</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-data-sources-with-biggest-delta-in-log-volume">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/reporting/data-sources-with-biggest-delta-in-log-volume.kql' | relative_url }}" download="data-sources-with-biggest-delta-in-log-volume.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-data-sources-with-biggest-delta-in-log-volume" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// -------------------------------
// Configuration / Tunables
// -------------------------------
// Cost per GB for Microsoft Sentinel ingest
// (Update this to match your region’s pricing)
// Platforms: Microsoft Sentinel
// Data: Usage
let CostPerGB = 4.30;
// Define the end of the current reporting window (now)
let CurrentEnd = now();
// Define the start of the current 30-day window
let CurrentStart = CurrentEnd - 30d;
// Define the start of the prior 30-day window
let PriorStart = CurrentEnd - 60d;
// Define the end of the prior window (exactly where current begins)
let PriorEnd = CurrentStart;
// -------------------------------
// Prior 30-Day Usage (Days -60 → -30)
// -------------------------------
let PriorData =
    Usage                                   // Query the Usage (billing) table
    | where IsBillable == true              // Only include billable ingest
    | where TimeGenerated >= PriorStart     // Start of prior 30-day window
          and TimeGenerated < PriorEnd      // End of prior window (exclusive)
    | summarize                             // Aggregate ingest volume
        PriorGB = round(
            todouble(sum(Quantity)) / 1024, // Convert MB → GB
            2                               // Round to 2 decimal places
        )
        by DataType;                        // Group by log table / data source
// -------------------------------
// Current 30-Day Usage (Days -30 → Now)
// -------------------------------
let CurrentData =
    Usage                                   // Query the Usage (billing) table
    | where IsBillable == true              // Only include billable ingest
    | where TimeGenerated >= CurrentStart   // Start of current 30-day window
          and TimeGenerated <= CurrentEnd   // End of window (now)
    | summarize                             // Aggregate ingest volume
        CurrentGB = round(
            todouble(sum(Quantity)) / 1024, // Convert MB → GB
            2                               // Round to 2 decimal places
        )
        by DataType;                        // Group by log table / data source
// -------------------------------
// Comparison & Delta Analysis
// -------------------------------
PriorData
| join kind=fullouter                      // Keep all data sources from both periods
    CurrentData
    on DataType                            // Join on table / data source name
| extend
    PriorGB   = coalesce(PriorGB, 0.0),    // Treat missing prior data as 0 GB
    CurrentGB = coalesce(CurrentGB, 0.0),  // Treat missing current data as 0 GB
    ChangeGB  = CurrentGB - PriorGB        // Calculate absolute GB change
| project
    ['Data Source']           = DataType,  // Friendly column name for output
    ['Previous 30 Days (GB)'] = PriorGB,   // Prior window ingest
    ['Current 30 Days (GB)']  = CurrentGB, // Current window ingest
    ['Change (GB)']           = round(     // Net change in GB
        ChangeGB,
        2
    ),
    ['Change %'] =
        iif(                               
            PriorGB > 0,                   // Only calculate % if prior data exists
            round(
                (ChangeGB / PriorGB) * 100,// Percentage change
                1
            ),
            real(null)                     // Avoid misleading % when prior = 0
        ),
    ['Change $'] =
        strcat(
            '$',
            round(
                ChangeGB * CostPerGB,      // Convert GB delta → estimated cost delta
                2
            )
        )
| where                                   // Remove rows with no activity in either period
    ['Current 30 Days (GB)'] > 0
    or ['Previous 30 Days (GB)'] > 0
| top 10                                  // Focus on the biggest movers
    by abs(['Change (GB)']) desc           // Rank by absolute GB change
```

</div>
