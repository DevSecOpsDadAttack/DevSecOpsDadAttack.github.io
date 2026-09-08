---
layout: page
title: Efficiency Exercise
subtitle: "Teaching walkthrough of the 'average daily ingest' question written four ways, from a slow `search *` to an efficient `Usage`-scoped version with cost. Read this before writing your own daily-average query."
permalink: /kql-library/cost-and-ingest/efficiency-exercise/
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
  <span class="attack-badge attack-badge-sub">Billable Volume</span>
  <code class="kql-lib-query-file">efficiency-exercise.kql</code>
</div>

<p class="kql-lib-query-longdesc">Teaching walkthrough of the "average daily ingest" question written four ways, from a slow `search *` to an efficient `Usage`-scoped version with cost. Read this before writing your own daily-average query.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-efficiency-exercise">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/billable-volume/efficiency-exercise.kql' | relative_url }}" download="efficiency-exercise.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-efficiency-exercise" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// This query doesn't just output the total average across the last 30 days' worth of data, this query breaks the data up into GB per day and takes the average from that.
// This step is crucial to get the most accurate and meaningful results. 
// Check out the evolution of this query; different iterations of this query from oldest to newest are listed from top to bottom below:

//Original Query (this one takes forever and is not efficient):

search *                                                                                     //<-- Query Everything
| where TimeGenerated > startofday(ago(30d)) and TimeGenerated < startofday(now())           //<-- Check the past 30 days
| where _IsBillable == True                                                                  //<-- Only include billable ingest volume
| summarize TotalGB = round(sum(_BilledSize/1000/1000/1000)) by bin(TimeGenerated, 1d)       //<-- Summarize billable volume in GB using the _BilledSize table column
| summarize avg(TotalGB)                                                                     //<-- Summarize and return the daily average

// You can swap the below line into above query if you’re a stickler for Gibibytes versus Gigabytes: 
| summarize GB=sum(_BilledSize)/1024/1024/1024

===================================================

Usage
|where TimeGenerated > ago(30d)
|where IsBillable == true
|summarize GB= sum(Quantity)/1000 by bin(TimeGenerated,1d)
|extend Cost=GB*DATAVALUE_PRICE_PER_GB
| summarize AvgCostPerDay=percentiles(Cost,50),AvgGBPerDay=percentiles(GB,50)
| project AvgGBPerDay=strcat(round(AvgGBPerDay,2), ' GB/Day (Past 31 Days)')
| extend Title = 'Avg Daily Consumption'

=================================================

//Improved/More Efficient Query: 

Usage                                                                  //<-- Query the USAGE table (instead of "search *" to query everything)
| where TimeGenerated > ago(30d)                                       //<-- Check the past 30 days
| where IsBillable == true                                             //<-- Only include billable ingest volume
| summarize GB= sum(Quantity)/1000 by bin(TimeGenerated,1d)            //<-- Summarize in GBs by Day
| summarize AvgGBPerDay=avg(GB)                                        //<-- Take the average 
| project AvgGBPerDay=strcat(round(AvgGBPerDay,2), ' GB/Day')          //<-- Convert to string and append "GB/Day"

=================================================

//Improved/More Efficient AND Includes Cost Calculation: 

let rate = 4.30;                                                       //<-- Effective $ per GB rate for East US
Usage                                                                  //<-- Query the USAGE table (instead of "search *" to query everything)
| where TimeGenerated > ago(30d)                                       //<-- Check the past 30 days
| where IsBillable == true                                             //<-- Only include billable ingest volume
| summarize GB= sum(Quantity)/1000 by bin(TimeGenerated,1d)            //<-- break it up into GB/Day
| summarize AvgGBPerDay=avg(GB)                                        //<-- take the Average
| extend Cost=AvgGBPerDay * rate                                       //<-- calculate average cost
| project AvgGBPerDay=strcat(round(AvgGBPerDay,2), ' GB/Day'), AvgCostPerDay=strcat('$', round(Cost,2), ' /Day')    //<-- This line is tricky. I convert everything to string in order to prepend '$' and append ' /Day' to the results
```

</div>
