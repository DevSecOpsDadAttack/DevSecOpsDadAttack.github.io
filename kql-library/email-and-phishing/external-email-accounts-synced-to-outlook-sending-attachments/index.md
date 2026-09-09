---
layout: page
title: External Email Accounts Synced To Outlook Sending Attachments
subtitle: "Employees using Outlook on corporate machines to send email via third-party SMTP servers, with attachments — a common data-exfiltration pattern."
permalink: /kql-library/email-and-phishing/external-email-accounts-synced-to-outlook-sending-attachments/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/email-and-phishing/' | relative_url }}">Email &amp; Phishing</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-envelope-open-text" aria-hidden="true"></i>&nbsp;Email &amp; Phishing</span>
  <code class="kql-lib-query-file">external-email-accounts-synced-to-outlook-sending-attachments.kql</code>
</div>

<p class="kql-lib-query-longdesc">Employees using Outlook on corporate machines to send email via third-party SMTP servers, with attachments — a common data-exfiltration pattern.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/exfiltration/' | relative_url }}">Exfiltration</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1567/' | relative_url }}">T1567</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1048-003/' | relative_url }}">T1048.003</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/emailevents/' | relative_url }}">EmailEvents</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/emailattachmentinfo/' | relative_url }}">EmailAttachmentInfo</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-external-email-accounts-synced-to-outlook-sending-attachments">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/email-and-phishing/external-email-accounts-synced-to-outlook-sending-attachments.kql' | relative_url }}" download="external-email-accounts-synced-to-outlook-sending-attachments.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-external-email-accounts-synced-to-outlook-sending-attachments" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
//
// This query is written in Kusto Query Language (KQL) and is designed to identify employees who are using Outlook on their work machines to
// send emails via third-party SMTP servers, potentially with attachments.
// Tactics: Exfiltration
// Techniques: T1567, T1048.003
// Platforms: Microsoft 365
// Data: EmailEvents, EmailAttachmentInfo

let corpDomains=dynamic(["yourDomain", "subsidiary.org"]); // internal domains
let mailDomains=dynamic(["smtp.gmail.com","smtp.mail.yahoo.com","smtp.zoho.com","smtp.mail.me.com"]); // 3rd-party SMTP
let smtpPorts=dynamic([465,587]); // SMTP ports
let OutlookEmailSends=OfficeActivity
| where TimeGenerated>=ago(90d)
| where RecordType=="Send"
| where Client has "Outlook"
| extend SenderDomain=tolower(split(UserId,"@")[1]) // domain from email
| where SenderDomain !in (corpDomains)
| project OA_Time=TimeGenerated,UserId,SenderDomain,Operation,Client,ClientIP; // email send info
let OutlookSMTP=DeviceNetworkEvents
| where TimeGenerated>=ago(90d)
| where InitiatingProcessFileName=~"OUTLOOK.EXE"
| where RemoteUrl has_any (mailDomains) or RemotePort in (smtpPorts)
| project DN_Time=TimeGenerated,DeviceName,InitiatingProcessAccountName,RemoteUrl,RemotePort,InitiatingProcessCommandLine; // SMTP connection
let OutlookProcess=DeviceProcessEvents
| where TimeGenerated>=ago(90d)
| where FileName=~"OUTLOOK.EXE"
| project DP_Time=TimeGenerated,DeviceName,AccountName,FolderPath,ProcessCommandLine; // outlook running
let RecentFiles=DeviceFileEvents
| where TimeGenerated>=ago(90d)
| where FileName endswith ".pdf" or FileName endswith ".docx" or FileName endswith ".xlsx"
| where InitiatingProcessFileName=~"OUTLOOK.EXE"
| project DF_Time=TimeGenerated,DeviceName,FileName,FolderPath,InitiatingProcessAccountName; // possible attachments
OutlookEmailSends
| join kind=inner (OutlookSMTP) on $left.UserId==$right.InitiatingProcessAccountName
| join kind=inner (OutlookProcess) on DeviceName
| join kind=leftouter (RecentFiles) on $left.DeviceName==$right.DeviceName
| where abs(datetime_diff("minute",OA_Time,DN_Time))<15
| where abs(datetime_diff("minute",OA_Time,DP_Time))<15
| where isnull(DF_Time) or abs(datetime_diff("minute",OA_Time,DF_Time))<10
| project OA_Time,DN_Time,DP_Time,DF_Time,UserId,SenderDomain,DeviceName,RemoteUrl,RemotePort,InitiatingProcessCommandLine,FileName,FolderPath,Client,Operation
| order by OA_Time desc
```

</div>
