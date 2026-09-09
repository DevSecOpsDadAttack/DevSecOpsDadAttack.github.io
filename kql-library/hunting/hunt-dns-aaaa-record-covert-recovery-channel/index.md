---
layout: page
title: Hunt DNS Aaaa Record Covert Recovery Channel
subtitle: "Project CAV3RN's DNS AAAA-record recovery channel — IPv6 addresses returned in AAAA queries that decode as ASCII or structured config."
permalink: /kql-library/hunting/hunt-dns-aaaa-record-covert-recovery-channel/
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
  <code class="kql-lib-query-file">hunt-dns-aaaa-record-covert-recovery-channel.kql</code>
</div>

<p class="kql-lib-query-longdesc">Project CAV3RN's DNS AAAA-record recovery channel — IPv6 addresses returned in AAAA queries that decode as ASCII or structured config.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/command-and-control/' | relative_url }}">Command and Control</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1071-004/' | relative_url }}">T1071.004</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1132-001/' | relative_url }}">T1132.001</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Actors</span>
    <a class="kql-lib-tag kql-lib-tag-actor" href="{{ '/kql-library/tag/cav3rn/' | relative_url }}">CAV3RN</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/endpoint/' | relative_url }}">Endpoint</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/dnsevents/' | relative_url }}">DnsEvents</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/devicenetworkevents/' | relative_url }}">DeviceNetworkEvents</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-dns-aaaa-record-covert-recovery-channel">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-dns-aaaa-record-covert-recovery-channel.kql' | relative_url }}" download="hunt-dns-aaaa-record-covert-recovery-channel.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-dns-aaaa-record-covert-recovery-channel" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects CAV3RN's DNS AAAA-record recovery channel — the fallback the operator uses when the
// OAuth token request or Graph validation call fails. Looks for IPv6 addresses returned in AAAA
// queries that decode as ASCII text or structured config data.
// Source: KQL Detection of the Week: A Meeting in 2050 (2026-07-27) — https://devsecopsdadattack.com/2026-07-27-KQL-Detection-of-the-Week_-A-Meeting-in-2050-_Detecting-Project-CAV3RN_s-Outlook-Calendar-C2-and-DNS-AAAA-Recovery-Channel_/
// Tactics: Command and Control
// Techniques: T1071.004, T1132.001
// Actors: CAV3RN
// Platforms: Windows, Endpoint
// Data: DnsEvents, DeviceNetworkEvents

let lookback = 7d;
let BootstrapDomains = dynamic(["cloudlanecdn.com"]);
// Single-token prefilter, derived from the registrable label only. A hostname ending
// in ".cloudlanecdn.com" must contain "cloudlanecdn" as a whole indexed term, because
// dots delimit it on both sides -- so this is PROVABLY broader than the boundary test
// below and cannot discard a row the authoritative check would have kept. No
// multi-token adjacency behaviour is relied on anywhere.
let BootstrapTerms   = dynamic(["cloudlanecdn"]);
let FailureSentinel  = "2001:4998:44:3507::8000";
// Shared, cheap base. Nothing expensive happens here.
let AaaaLookups = DnsEvents
| where TimeGenerated > ago(lookback)
| where SubType =~ "LookupQuery"
| where QueryType =~ "AAAA"
| extend QueryName = tolower(trim_end(@"\.", Name));
// Lane 1 — protocol shape. The label-count floor belongs to THIS lane only.
let ShapeLane = AaaaLookups
| where QueryName startswith "d."          // leading-label test, cheap, drops nearly everything
| extend Labels = split(QueryName, ".")
| where array_length(Labels) >= 5
| extend SecondLabel = tostring(Labels[1])
| where strlen(SecondLabel) >= 8 and strlen(SecondLabel) % 2 == 0
| where SecondLabel matches regex @"^[0-9a-f]+$"   // regex last, on the smallest surviving set
| where set_has_element(Labels, "p") or set_has_element(Labels, "q")
| extend
    Lane        = "ProtocolShape",
    MarkerLabel = iff(set_has_element(Labels, "p"), "p", "q")
| project TimeGenerated, ClientIP, Computer, QueryName, Lane, MarkerLabel;
// Lane 2 — bootstrap domain IOC. No label-count floor: the bare domain is two labels.
// Cheap single-token prefilter, then exact apex-or-suffix as the authoritative test.
// Narrow with something cheap, DECIDE with something structured -- same pattern as
// the sentinel lane, and the prefilter is chosen so it can only over-match.
let DomainLane = AaaaLookups
| where QueryName has_any (BootstrapTerms)
| mv-apply Dom = BootstrapDomains to typeof(string) on (
    summarize DomainHits = countif(QueryName == Dom or QueryName endswith strcat(".", Dom))
  )
| where DomainHits > 0
| extend Lane = "BootstrapDomain", MarkerLabel = ""
| project TimeGenerated, ClientIP, Computer, QueryName, Lane, MarkerLabel;
// Lane 3 — failure sentinel in the ANSWER. Cheap lossy prefilter, then authoritative compare.
// IPv6 has no single textual form. 2001:4998:44:3507::8000 and its expanded
// equivalent are the same address and different strings — so narrow on a term,
// decide with ipv6_compare().
let SentinelLane = AaaaLookups
| where IPAddresses has "8000"
| mv-apply AnswerIP = split(tostring(IPAddresses), ",") to typeof(string) on (
    summarize SentinelHits = countif(ipv6_compare(trim(@"\s", AnswerIP), FailureSentinel) == 0)
  )
| where SentinelHits > 0
| extend Lane = "FailureSentinel", MarkerLabel = ""
| project TimeGenerated, ClientIP, Computer, QueryName, Lane, MarkerLabel;
union ShapeLane, DomainLane, SentinelLane
// One lookup can satisfy more than one lane — d.<hex>.<idx>.p.cloudlanecdn.com hits
// both Shape and Domain. EventKey de-duplicates so Queries counts DNS events, not
// union rows. LaneHits counts rows, and the two being different is the point.
| extend EventKey = strcat(tostring(TimeGenerated), "|", QueryName)
// ClientIP is the entity. Computer is the RESOLVER that logged the query, not the
// host that asked — a client talking to two DNS servers would fragment into two rows.
| summarize
    Queries       = dcount(EventKey),
    LaneHits      = count(),
    DistinctNames = dcount(QueryName),
    Resolvers     = make_set(Computer, 5),
    SampleNames   = make_set(QueryName, 10),
    MarkerLabels  = make_set_if(MarkerLabel, isnotempty(MarkerLabel)),
    ShapeCount    = dcountif(EventKey, Lane == "ProtocolShape"),
    DomainCount   = dcountif(EventKey, Lane == "BootstrapDomain"),
    SentinelCount = dcountif(EventKey, Lane == "FailureSentinel"),
    Lanes         = make_set(Lane),
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated)
    by ClientIP
| extend
    ShapeSeen    = ShapeCount > 0,
    SentinelSeen = SentinelCount > 0,
    DomainSeen   = DomainCount > 0,
    LaneCount    = array_length(Lanes)
// Rank by fidelity, not volume — a noisy IOC-only hit must not outrank a single shape hit
| order by ShapeSeen desc, SentinelSeen desc, LaneCount desc, DistinctNames desc
```

</div>
