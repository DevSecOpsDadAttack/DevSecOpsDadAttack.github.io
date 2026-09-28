---
layout: post
title: "Threat Intelligence Brief - Monday, September 28, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-28
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-35273
  - CVE-2026-88771
  - T1190
  - T1098
  - T1531
  - Lazarus
  - Microsoft-Azure
  - Microsoft
  - Citrix-NetScaler
  - Citrix-NetScaler-ADC
  - Citrix-NetScaler-Gateway
---

## Threat Radar

- **ShinyHunters is actively exploiting Oracle PeopleSoft** (CVE-2026-35273) with a modified exploit in a fresh extortion campaign — PeopleSoft HR and identity systems are in the crosshairs now.

- **CISA confirmed global active exploitation** of two critical Citrix NetScaler ADC and Gateway flaws (CVE-2026-88771, CVSS 9.5) — perimeter access infrastructure is under active attack worldwide.

- **JADEPUFFER (Storm-3168) is conducting destructive Azure operations**, using compromised service principals to delete cloud resources — this is sabotage, not espionage, and the blast radius is operational continuity.

- **Kiteworks issued a precautionary server shutdown advisory** for its Advanced Forms product — the vendor's own response posture signals the flaw is serious even without confirmed exploitation.

- **North Korea's Lazarus Group stole $387.5M from Bitget** — the scale and pace of state-linked crypto theft continues to accelerate, with direct implications for any organization holding or transacting in digital assets.

<br/>
---
<br/>

## Immediate Action Required

- **Oracle PeopleSoft — CVE-2026-35273 | Patch or isolate immediately.** ShinyHunters has modified its exploit and is actively targeting this vulnerability. Vulnerability management and HR system owners should confirm patch status today. If unpatched, restrict external access to PeopleSoft interfaces pending remediation. *Threat actor: ShinyHunters | Technique: T1190*

- **Citrix NetScaler ADC / Gateway — CVE-2026-88771 | CISA KEV — patch now.** CISA's KEV listing confirms active global exploitation of a CVSS 9.5 flaw. Federal agencies face binding remediation deadlines; all enterprises should treat this with equivalent urgency. Network and perimeter teams should validate patch status and review access logs for anomalous activity. *Technique: T1190*

- **Microsoft Azure — JADEPUFFER / Storm-3168 | Audit service principal permissions immediately.** Compromised service principals are being used to delete Azure resources. Cloud and identity teams should audit service principal credential exposure, enforce least-privilege, and review Azure activity logs for unauthorized resource deletion. *Threat actor: JADEPUFFER | Techniques: T1098, T1531*

- **Kiteworks Advanced Forms — Follow vendor shutdown guidance this week.** Kiteworks has recommended precautionary server shutdown. No CVE has been published, but the vendor advisory warrants immediate review by any organization running this product. Confirm with your Kiteworks account team and comply with shutdown guidance until a patch is available.

<br/>
---
<br/>

## High-Impact Developments

### ShinyHunters Actively Exploiting Oracle PeopleSoft (CVE-2026-35273)

- **What happened:** ShinyHunters has modified its exploit tooling and launched a fresh active campaign targeting Oracle PeopleSoft systems via CVE-2026-35273. Google issued a warning about the campaign.

- **Why it matters:** PeopleSoft is widely deployed for enterprise HR, payroll, and identity management. Successful exploitation by an extortion group creates immediate risk of data theft, operational disruption, and ransom demands. The modified exploit suggests active adaptation to defenses or patching efforts — meaning organizations that believed they were protected may not be.

- **Who should care:** Enterprise security teams, HR system owners, vulnerability management leads, and any organization running Oracle PeopleSoft in internet-accessible configurations.

- **Recommended action:** Confirm patch status for CVE-2026-35273 across all PeopleSoft instances. Restrict external access to PeopleSoft interfaces where patching is not yet complete. Engage Oracle support for remediation guidance. Brief leadership on extortion risk.

- **Confidence:** High — active exploitation confirmed, Google warning issued.

- **Search metadata:** CVE-2026-35273, T1190, ShinyHunters, Oracle PeopleSoft, extortion

**Intelligence Context**
- [Google Warns of ShinyHunters' Fresh Oracle PeopleSoft Campaign — SecurityWeek](https://www.securityweek.com/google-warns-of-shinyhunters-fresh-oracle-peoplesoft-campaign/)
  - Context: SecurityWeek reports Google's warning that ShinyHunters has modified its exploit and is running a fresh active campaign against PeopleSoft systems, confirming this is not a theoretical risk.

<br/>
---
<br/>

### CISA Confirms Active Global Exploitation of Critical Citrix NetScaler Flaws

- **What happened:** CISA added two critical Citrix NetScaler ADC and Gateway vulnerabilities — including CVE-2026-88771 (CVSS 9.5) — to its Known Exploited Vulnerabilities catalog following confirmed reports of active global exploitation.

- **Why it matters:** NetScaler ADC and Gateway are primary remote access and load-balancing infrastructure for thousands of enterprises. Exploitation at this severity level enables initial access, credential harvesting, and lateral movement. CISA's KEV listing is a hard signal, not a precaution.

- **Who should care:** Network security teams, perimeter infrastructure owners, SOC leaders monitoring ingress points, and any organization using Citrix NetScaler for remote access or application delivery.

- **Recommended action:** Patch immediately. Validate patch status across all NetScaler ADC and Gateway instances. Review access logs for indicators of exploitation. Federal agencies must comply with KEV remediation timelines; all others should treat this with equivalent urgency.

- **Confidence:** High — CISA KEV listing with confirmed active exploitation globally.

- **Search metadata:** CVE-2026-88771, T1190, Citrix NetScaler ADC, Citrix NetScaler Gateway, CISA KEV

**Intelligence Context**
- [CISA Says Attackers Are Exploiting Two Critical Citrix NetScaler Flaws Globally — The Hacker News](https://thehackernews.com/2026/09/cisa-says-attackers-are-exploiting-two.html)
  - Context: The Hacker News reports CISA's KEV addition of two critical NetScaler flaws, confirming active global exploitation and providing the CVSS 9.5 severity rating for CVE-2026-88771.

<br/>
---
<br/>

### JADEPUFFER Conducts Destructive Azure Resource Deletion via Compromised Service Principals

- **What happened:** JADEPUFFER (tracked by Microsoft as Storm-3168) used compromised Azure service principal credentials to delete cloud resources in targeted destructive attacks. Microsoft characterizes this as an evolution of the group's tradecraft.

- **Why it matters:** This is deliberate destruction of cloud infrastructure, not data theft. Compromised service principals with broad permissions can cause irreversible data loss and operational outages. Recovery from resource deletion is lengthy and costly, particularly where backup and recovery controls are immature. The shift to destructive objectives marks a meaningful escalation in cloud threat actor behavior.

- **Who should care:** Cloud architects, Azure administrators, identity and access management teams, and SOC leaders responsible for cloud environment monitoring. Any organization with Azure service principals carrying delete or contributor-level permissions is a potential target.

- **Recommended action:** Immediately audit Azure service principal permissions and credential exposure. Enforce least-privilege on all service principals. Review Azure Monitor and activity logs for unauthorized resource deletion. Validate that backup and recovery controls are in place and tested. Rotate credentials for any service principals with broad permissions.

- **Confidence:** High — Microsoft tracking confirmed, destructive activity observed.

- **Search metadata:** T1098, T1531, JADEPUFFER, Storm-3168, Microsoft Azure, service principals, destructive attack, credential compromise

**Intelligence Context**
- [JADEPUFFER-Linked Attackers Used Compromised Service Principals to Delete Azure Resources — The Hacker News](https://thehackernews.com/2026/09/jadepuffer-linked-attackers-used.html)
  - Context: The Hacker News reports Microsoft's tracking of JADEPUFFER as Storm-3168, confirming the use of compromised service principals for destructive resource deletion and noting this represents an evolution in the threat actor's tradecraft.

<br/>
---
<br/>

### Kiteworks Advanced Forms Vulnerability Prompts Precautionary Server Shutdown

- **What happened:** Kiteworks discovered a vulnerability in its Advanced Forms product and issued guidance recommending precautionary server shutdown. The company states it has found no evidence of customer or Kiteworks system compromise.

- **Why it matters:** A vendor recommending server shutdown — even as a precaution — signals a high internal severity assessment. Kiteworks is used for secure file sharing and sensitive data workflows; exploitation of this product could expose regulated data. The absence of a published CVE does not reduce operational urgency.

- **Who should care:** Organizations running Kiteworks Advanced Forms, particularly those using it for regulated data workflows, legal document exchange, or compliance-sensitive processes.

- **Recommended action:** Follow Kiteworks' server shutdown guidance immediately. Engage your Kiteworks account team for patch timeline and remediation details. Do not wait for CVE publication before acting.

- **Confidence:** High — vendor-confirmed vulnerability with official shutdown advisory.

- **Search metadata:** Kiteworks Advanced Forms, vulnerability, vendor advisory

**Intelligence Context**
- [Kiteworks Urges Server Shutdown, Finds Advanced Forms Vulnerability — SecurityWeek](https://www.securityweek.com/kiteworks-urges-server-shutdown-finds-advanced-forms-vulnerability/)
  - Context: SecurityWeek reports Kiteworks' discovery of the Advanced Forms vulnerability and the company's precautionary shutdown recommendation, noting no evidence of compromise has been found to date.

<br/>
---
<br/>

## Monitor Only

- Suspected Lazarus Group hackers breached cryptocurrency exchange Bitget, stealing over $387.5M; Bitcoin withdrawals have since resumed. Organizations with digital asset holdings or crypto exchange dependencies should assess counterparty risk and review third-party financial platform security posture. **Source:** [Bitget resumes Bitcoin withdrawals after $387.5 million crypto heist — Bleeping Computer](https://www.bleepingcomputer.com/news/security/bitget-resumes-bitcoin-withdrawals-after-3875-million-crypto-heist/)

- DC Health Agency exposed Medicaid IDs and personal information for approximately 400,000 beneficiaries; exploitation status is unknown. Healthcare and government organizations should review data exposure controls and third-party data handling practices. **Source:** [DC Health Agency Exposes 400,000 Beneficiary Records — SecurityWeek](https://www.securityweek.com/dc-health-agency-exposes-400000-beneficiary-records/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment where attackers are not waiting. ShinyHunters retooled and relaunched against PeopleSoft. JADEPUFFER pivoted from espionage to destruction in Azure. CISA is confirming Citrix exploitation that is already global in scope. All three immediate-action items involve perimeter systems or identity infrastructure — the most reliable initial access vectors, and still the most consistently under-defended. The Kiteworks situation deserves more attention than it will likely receive: vendors do not recommend shutting down servers unless they believe the risk is real, and the absence of a CVE is not reassurance — it is a gap in visibility. Security teams should resist deprioritizing vendor advisories that lack a CVE number. The Lazarus/Bitget theft is a reminder that North Korea's cyber-financial operations are running at industrial scale; organizations with any digital asset exposure should be treating crypto platform risk as a first-class financial risk, not a niche security concern.

<br/>
---
<br/>

## Source Links

- Google Warns of ShinyHunters' Fresh Oracle PeopleSoft Campaign — [https://www.securityweek.com/google-warns-of-shinyhunters-fresh-oracle-peoplesoft-campaign/](https://www.securityweek.com/google-warns-of-shinyhunters-fresh-oracle-peoplesoft-campaign/)

- CISA Says Attackers Are Exploiting Two Critical Citrix NetScaler Flaws Globally — [https://thehackernews.com/2026/09/cisa-says-attackers-are-exploiting-two.html](https://thehackernews.com/2026/09/cisa-says-attackers-are-exploiting-two.html)

- JADEPUFFER-Linked Attackers Used Compromised Service Principals to Delete Azure Resources — [https://thehackernews.com/2026/09/jadepuffer-linked-attackers-used.html](https://thehackernews.com/2026/09/jadepuffer-linked-attackers-used.html)

- Bitget resumes Bitcoin withdrawals after $387.5 million crypto heist — [https://www.bleepingcomputer.com/news/security/bitget-resumes-bitcoin-withdrawals-after-3875-million-crypto-heist/](https://www.bleepingcomputer.com/news/security/bitget-resumes-bitcoin-withdrawals-after-3875-million-crypto-heist/)

- DC Health Agency Exposes 400,000 Beneficiary Records — [https://www.securityweek.com/dc-health-agency-exposes-400000-beneficiary-records/](https://www.securityweek.com/dc-health-agency-exposes-400000-beneficiary-records/)

- Kiteworks Urges Server Shutdown, Finds Advanced Forms Vulnerability — [https://www.securityweek.com/kiteworks-urges-server-shutdown-finds-advanced-forms-vulnerability/](https://www.securityweek.com/kiteworks-urges-server-shutdown-finds-advanced-forms-vulnerability/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
