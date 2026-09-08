---
layout: page
title: Log Sources With Greatest Delta
subtitle: "Which data sources moved the most between the previous 30 days and the current 30 days — the 'who suddenly got loud' query."
permalink: /kql-library/cost-and-ingest/log-sources-with-greatest-delta/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/cost-and-ingest/' | relative_url }}">Cost &amp; Ingest</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-coins" aria-hidden="true"></i>&nbsp;Cost &amp; Ingest</span>
  <span class="attack-badge attack-badge-sub">Ingest Trends</span>
  <code class="kql-lib-query-file">log-sources-with-greatest-delta.kql</code>
</div>

<p class="kql-lib-query-longdesc">Which data sources moved the most between the previous 30 days and the current 30 days — the "who suddenly got loud" query.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-log-sources-with-greatest-delta">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/ingest-trends/log-sources-with-greatest-delta.kql' | relative_url }}" download="log-sources-with-greatest-delta.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-log-sources-with-greatest-delta" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com

//This query:
//-->Finds the exact time ranges for comparison periods (previous 30 days vs current 30 days)
//-->Calculates total GB for each data source in both periods
//-->Joins the results to show the comparison
//-->Calculates both absolute and percentage changes
//-->Shows top 5 sources with biggest absolute changes
//-->Handles cases where sources might be new or discontinued

//The results include:
//-->Data Source name
//-->Volume for previous 30 days in GB
//-->Volume for current 30 days in GB
//-->Absolute change in GB
//-->Percentage change

// Capture the exact end of the "current" period by finding the latest
// billable Usage record in the workspace
let CurrentPeriod = toscalar(
    Usage                              // Query the Usage (billing) table
    | where IsBillable == true         // Only include billable ingestion
    | summarize max(TimeGenerated)     // Find the most recent billable record timestamp
);
// Define the start of the current 30-day comparison window
let CurrentStart = CurrentPeriod - 30d;   // Current window = last 30 days of data
// Define the start of the prior 30-day window
let PriorStart   = CurrentPeriod - 60d;   // Prior window starts 60 days before CurrentPeriod
// Define the end of the prior window so the two windows are perfectly adjacent
let PriorEnd     = CurrentStart;           // Prior window ends exactly where current begins
// Summarize total billable volume (GB) per data source for the prior period
let PriorData =
    Usage
    | where IsBillable == true                                 // Only billable ingestion
    | where TimeGenerated between (PriorStart .. PriorEnd)    // Filter to prior 30-day window
    | summarize PriorGB = round(todouble(sum(Quantity)) / 1024, 2)
        by DataType;                                          // Aggregate by data source (table)
// Summarize total billable volume (GB) per data source for the current period
let CurrentData =
    Usage
    | where IsBillable == true                                 // Only billable ingestion
    | where TimeGenerated between (CurrentStart .. CurrentPeriod) // Filter to current 30-day window
    | summarize CurrentGB = round(todouble(sum(Quantity)) / 1024, 2)
        by DataType;                                          // Aggregate by data source (table)
// Join prior and current datasets so we can compare changes
PriorData
| join kind=fullouter CurrentData on DataType                 // Include new and discontinued sources
| extend
    DataType  = coalesce(DataType, DataType1),                // Normalize DataType name after join
    PriorGB   = coalesce(PriorGB, 0.0),                        // Treat missing prior data as 0 GB
    CurrentGB = coalesce(CurrentGB, 0.0)                       // Treat missing current data as 0 GB
| project
    ['Data Source']            = DataType,                    // Friendly column name
    ['Previous 30 Days (GB)']  = PriorGB,                     // Prior period volume
    ['Current 30 Days (GB)']   = CurrentGB,                   // Current period volume
    ['Change (GB)']            = round(CurrentGB - PriorGB, 2), // Absolute volume change
    ['Change %']               =
        iif(
            PriorGB > 0,
            round(((CurrentGB - PriorGB) / PriorGB) * 100, 1), // Percent change when baseline exists
            100.0                                              // Fallback for brand-new sources
        )
| where
    ['Current 30 Days (GB)'] > 0
    or ['Previous 30 Days (GB)'] > 0                           // Remove rows with no activity at all
| top 5 by abs(['Change (GB)']) desc                           // Show the biggest movers (up or down)

```

</div>
