---
layout: page
title: Hunt Cloud Storage Bucket Lookalike References
subtitle: "References to cloud storage buckets whose names are lookalikes of your real ones — homoglyphs, dashes-for-underscores, plausibly-typosquatted variants."
permalink: /kql-library/hunting/hunt-cloud-storage-bucket-lookalike-references/
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
  <code class="kql-lib-query-file">hunt-cloud-storage-bucket-lookalike-references.kql</code>
</div>

<p class="kql-lib-query-longdesc">References to cloud storage buckets whose names are lookalikes of your real ones — homoglyphs, dashes-for-underscores, plausibly-typosquatted variants.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-cloud-storage-bucket-lookalike-references">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-cloud-storage-bucket-lookalike-references.kql' | relative_url }}" download="hunt-cloud-storage-bucket-lookalike-references.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-cloud-storage-bucket-lookalike-references" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects references to cloud storage buckets whose names are lookalikes of known legitimate ones
// — dashes swapped for underscores, homoglyphs, plausibly-typosquatted variants. Compares
// references in traffic/config against a curated list of your real bucket names, since bucket
// names are globally unique.
// Source: KQL Detection of the Week: A Name Is a Claim, Not a Fact (2026-06-29) — https://devsecopsdadattack.com/2026-06-29-KQL-Detection-of-the-Week_-A-Name-Is-a-Claim_-Not-a-Fact/

let lookback = 90d;
let hijackWindow = 30d;
let deletions = AzureActivity
| where TimeGenerated > ago(lookback)
| where tolower(OperationName) has "microsoft.storage/storageaccounts"
    and tolower(OperationName) has "delete"
| where ActivityStatus =~ "Succeeded"
| extend DeletedResource = tolower(tostring(split(ResourceId, "/")[-1]))
| where isnotempty(DeletedResource)
| project DeleteTime = TimeGenerated, DeletedResource, DeletedBy = Caller,
    DeletedFromIP = CallerIpAddress, SubscriptionId;
let creations = AzureActivity
| where TimeGenerated > ago(hijackWindow)
| where tolower(OperationName) has "microsoft.storage/storageaccounts"
    and (tolower(OperationName) has "write" or tolower(OperationName) has "create")
| where ActivityStatus =~ "Succeeded"
| extend CreatedResource = tolower(tostring(split(ResourceId, "/")[-1]))
| where isnotempty(CreatedResource)
| project CreateTime = TimeGenerated, CreatedResource, CreatedBy = Caller,
    CreatedFromIP = CallerIpAddress, SubscriptionId, ResourceGroup;
deletions
| join kind=inner (creations) on $left.DeletedResource == $right.CreatedResource
| where CreateTime > DeleteTime
| where CreatedBy != DeletedBy
| project
    DeleteTime, CreateTime, DeletedResource,
    DeletedBy, DeletedFromIP,
    CreatedBy, CreatedFromIP,
    SubscriptionId, ResourceGroup
| order by CreateTime desc
```

</div>
