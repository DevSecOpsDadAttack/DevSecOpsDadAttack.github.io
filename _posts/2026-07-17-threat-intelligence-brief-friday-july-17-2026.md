---
layout: post
title: "Threat Intelligence Brief - Friday, July 17, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-17
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-58644
  - T1187
  - T1056.004
  - T1005
  - T1133
  - T1190
  - Microsoft
  - Microsoft-365
  - Fortinet
  - Windows-Server-2022
  - Windows
---

## Threat Radar

- **SharePoint Server zero-day (CVE-2026-58644) is under active exploitation** — CISA added it to the KEV catalog with a July 19 federal patching deadline. Any organization running on-premises SharePoint Server should treat this as immediate.

- **Fortinet FortiSandbox has two actively exploited vulnerabilities** — CISA issued an emergency directive with a Sunday deadline. Compromise of a security control platform carries compounding risk; validate patch status now.

- **Ransomware is hitting food and beverage manufacturing** — Coca-Cola suspended U.S. Fairlife production and Japanese frozen food manufacturer Nichirei disconnected systems following separate attacks within days of each other, signaling sustained threat actor interest in the sector.

- **ACR Stealer is actively exfiltrating Microsoft 365 credentials and files** — The ClickFix lure tricks users into running malicious commands, resulting in theft of browser passwords, live session tokens, and documents from OneDrive and SharePoint.

- **Microsoft infrastructure faces a compounding threat picture** — A server-side RCE zero-day, an active infostealer campaign targeting M365 credentials, and a CISA KEV addition all converge on Microsoft environments simultaneously.

<br/>
---
<br/>

## Immediate Action Required

- **Patch SharePoint Server now (CVE-2026-58644):** Active exploitation is confirmed. Federal agencies must patch by July 19; all other organizations should treat this with equivalent urgency. Identify all on-premises SharePoint Server instances, apply available patches, and review access logs for anomalous authenticated activity consistent with T1190.

- **Validate FortiSandbox patch status today:** Two actively exploited vulnerabilities in a security control platform represent a high-consequence exposure. Confirm patch status across all FortiSandbox deployments and check for indicators of compromise before assuming a clean state.

- **Review Microsoft 365 session tokens for ACR Stealer / ClickFix exposure:** Stolen live session tokens bypass MFA. Coordinate with IAM teams to assess anomalous token usage and push targeted awareness to high-risk populations — finance, IT, and executives — on ClickFix-style lures.

<br/>
---
<br/>

## High-Impact Developments

### Microsoft SharePoint Server RCE Zero-Day Actively Exploited — CVE-2026-58644

- **What happened:** A critical-severity remote code execution vulnerability in Microsoft SharePoint Server was exploited in the wild shortly after public disclosure. CISA added CVE-2026-58644 to the Known Exploited Vulnerabilities catalog and mandated federal civilian agencies apply patches by July 19, 2026.

- **Why it matters:** Authenticated RCE on SharePoint Server enables full server compromise. SharePoint is a high-value target given the sensitive documents and internal data it hosts. The speed of exploitation after disclosure compresses the patching window to near-zero.

- **Who should care:** Vulnerability management leads, security architects, and SOC leaders at any organization running on-premises SharePoint Server. Microsoft 365 cloud-only tenants should confirm they have no hybrid or on-premises SharePoint exposure.

- **Recommended action:** Apply Microsoft's patch immediately. Inventory all SharePoint Server instances including hybrid configurations. Review authentication logs for anomalous activity. Confirm CISA KEV tracking is integrated into your vulnerability prioritization workflow.

- **Confidence:** High — CISA KEV addition with confirmed active exploitation reported by two independent sources.

- **Search metadata:** CVE-2026-58644, T1190, SharePoint Server, Microsoft

**Intelligence Context**
- [CISA Adds Exploited SharePoint RCE Zero-Day CVE-2026-58644 to KEV — The Hacker News](https://thehackernews.com/2026/07/cisa-adds-exploited-sharepoint-rce-zero.html)
  - Context: Confirms CISA's formal KEV addition and the July 19 federal patching deadline, establishing regulatory urgency beyond voluntary guidance.

- [Fresh SharePoint Vulnerability Exploited Soon After Disclosure — SecurityWeek](https://www.securityweek.com/fresh-sharepoint-vulnerability-exploited-soon-after-disclosure/)
  - Context: Corroborates active exploitation in the wild and characterizes the vulnerability as critical-severity, enabling authenticated remote code execution on the server.

<br/>
---
<br/>

### CISA Emergency Directive: Fortinet FortiSandbox Actively Exploited Flaws

- **What happened:** CISA ordered federal agencies to patch two actively exploited vulnerabilities in Fortinet's FortiSandbox threat detection platform, with a Sunday deadline. Specific CVEs were not disclosed in available reporting.

- **Why it matters:** FortiSandbox is a security control — compromise of threat detection infrastructure is particularly damaging because it blinds defenders while attackers operate freely. Active exploitation confirmed by CISA means this is not theoretical.

- **Who should care:** Security architects and SOC leaders running Fortinet FortiSandbox in any environment, not just federal. CISA KEV additions consistently precede broader exploitation waves.

- **Recommended action:** Immediately verify patch status on all FortiSandbox deployments. Check Fortinet's advisory for specific CVE details and affected versions. Do not assume unpatched systems are uncompromised — validate integrity before and after patching.

- **Confidence:** High — CISA directive with confirmed active exploitation.

- **Search metadata:** FortiSandbox, Fortinet, CISA, active exploitation

**Intelligence Context**
- [CISA urges immediate action on actively exploited Fortinet flaws — Bleeping Computer](https://www.bleepingcomputer.com/news/security/cisa-warns-feds-to-patch-exploited-fortinet-fortisandbox-flaws-by-sunday/)
  - Context: Reports the CISA emergency directive, confirms active exploitation of two FortiSandbox vulnerabilities, and establishes the Sunday patching deadline for federal agencies.

<br/>
---
<br/>

### ACR Stealer ClickFix Campaign Targeting Microsoft 365 Credentials and Files

- **What happened:** ACR Stealer, an infostealer active since 2024, is being distributed via ClickFix social engineering lures that trick users into pasting malicious commands into the Windows Run dialog. Once executed, the malware exfiltrates saved browser passwords, live session tokens, PDFs, and Microsoft 365 documents including files synced from OneDrive and SharePoint.

- **Why it matters:** Live session token theft bypasses MFA entirely. Exfiltration of M365 documents from OneDrive and SharePoint can produce significant data loss without triggering traditional endpoint alerts. The attack vector — user-initiated command execution — is difficult to block through technical controls alone.

- **Who should care:** SOC leaders, IAM teams, and security architects responsible for Microsoft 365 environments. Any enterprise with a large user population is a viable target given the social engineering delivery mechanism.

- **Recommended action:** Reinforce user awareness specifically around ClickFix-style lures — prompts asking users to paste commands. Review conditional access policies and anomalous token usage. Consider restricting or monitoring Windows Run dialog execution in managed environments. Assess whether endpoint controls would catch command injection from user-initiated processes.

- **Confidence:** High — active campaign with confirmed exfiltration behavior documented.

- **Search metadata:** ACR Stealer, ClickFix, T1187, T1056.004, T1005, Microsoft 365, OneDrive, SharePoint

**Intelligence Context**
- [ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files — The Hacker News](https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html)
  - Context: Details the ClickFix delivery mechanism, the specific data types targeted (session tokens, M365 documents, browser credentials), and confirms the campaign has been active since 2024 with ongoing enterprise targeting.

<br/>
---
<br/>

### Ransomware Disrupts Food and Beverage Manufacturing: Coca-Cola and Nichirei

- **What happened:** Coca-Cola suspended U.S. Fairlife production following a ransomware attack, with full scope still under assessment. Separately, Japanese frozen food manufacturer Nichirei disconnected its systems on July 13 following a cyberattack and is in gradual recovery.

- **Why it matters:** Two major food manufacturers hit within days of each other indicates either coordinated sector targeting or opportunistic exploitation of shared vulnerabilities in the industry. Production halts translate directly to revenue loss, supply chain disruption, and potential regulatory scrutiny.

- **Who should care:** Executive leadership, operations, and supply chain teams at any manufacturing organization. Security leaders in adjacent sectors — logistics, retail, food distribution — should assess third-party dependencies on affected organizations.

- **Recommended action:** Manufacturing sector organizations should review OT/IT segmentation, ransomware resilience posture, and incident response playbooks for production environment scenarios. Assess supply chain dependencies on Fairlife or Nichirei products where applicable.

- **Confidence:** High for Coca-Cola (ransomware confirmed); Medium for Nichirei (cyberattack confirmed, ransomware not confirmed).

- **Search metadata:** Ransomware, operational disruption, food and beverage manufacturing, Coca-Cola, Nichirei

**Intelligence Context**
- [Coca-Cola Suspends US Fairlife Production Due to Ransomware Attack — SecurityWeek](https://www.securityweek.com/coca-cola-suspends-us-fairlife-production-due-to-ransomware-attack/)
  - Context: Confirms ransomware as the cause of production suspension at Fairlife and notes the full scope of the incident remains under investigation.

- [Cyberattack Disrupts Operations of Japanese Frozen Food Giant Nichirei — SecurityWeek](https://www.securityweek.com/cyberattack-disrupts-operations-of-japanese-frozen-food-giant-nichirei/)
  - Context: Reports system disconnection at Nichirei on July 13 and gradual recovery, establishing a concurrent incident in the same sector within the same reporting window.

<br/>
---
<br/>

## Monitor Only

- Nichirei's recovery is ongoing with limited technical detail available; attack type and attribution remain unconfirmed — monitor for further disclosure that may reveal shared TTPs with the Coca-Cola ransomware incident. **Source:** Cyberattack Disrupts Operations of Japanese Frozen Food Giant Nichirei — [https://www.securityweek.com/cyberattack-disrupts-operations-of-japanese-frozen-food-giant-nichirei/](https://www.securityweek.com/cyberattack-disrupts-operations-of-japanese-frozen-food-giant-nichirei/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment compressing response timelines to near-zero. The SharePoint zero-day moved from disclosure to active exploitation to CISA KEV addition within a single news cycle — organizations running weekly or monthly patching cadences are structurally unable to respond at this tempo. The FortiSandbox situation is arguably more consequential: attackers targeting security tooling are deliberately degrading defenders' detection capability before executing follow-on activity. The ACR Stealer campaign is a reminder that sophisticated technical controls can be bypassed by a user who pastes one command into a Run box. The food manufacturing incidents, taken together, suggest either coordinated sector targeting or that ransomware operators have identified manufacturing OT/IT environments as high-leverage, low-resilience targets. Security leaders in any operational technology environment should be asking whether their incident response plans account for production shutdown scenarios — not just data breach scenarios.

<br/>
---
<br/>

## Source Links

- Fresh SharePoint Vulnerability Exploited Soon After Disclosure — [https://www.securityweek.com/fresh-sharepoint-vulnerability-exploited-soon-after-disclosure/](https://www.securityweek.com/fresh-sharepoint-vulnerability-exploited-soon-after-disclosure/)

- CISA Adds Exploited SharePoint RCE Zero-Day CVE-2026-58644 to KEV — [https://thehackernews.com/2026/07/cisa-adds-exploited-sharepoint-rce-zero.html](https://thehackernews.com/2026/07/cisa-adds-exploited-sharepoint-rce-zero.html)

- CISA urges immediate action on actively exploited Fortinet flaws — [https://www.bleepingcomputer.com/news/security/cisa-warns-feds-to-patch-exploited-fortinet-fortisandbox-flaws-by-sunday/](https://www.bleepingcomputer.com/news/security/cisa-warns-feds-to-patch-exploited-fortinet-fortisandbox-flaws-by-sunday/)

- Coca-Cola Suspends US Fairlife Production Due to Ransomware Attack — [https://www.securityweek.com/coca-cola-suspends-us-fairlife-production-due-to-ransomware-attack/](https://www.securityweek.com/coca-cola-suspends-us-fairlife-production-due-to-ransomware-attack/)

- ACR Stealer Uses ClickFix Lures to Steal Browser Tokens and Microsoft 365 Files — [https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html](https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html)

- Cyberattack Disrupts Operations of Japanese Frozen Food Giant Nichirei — [https://www.securityweek.com/cyberattack-disrupts-operations-of-japanese-frozen-food-giant-nichirei/](https://www.securityweek.com/cyberattack-disrupts-operations-of-japanese-frozen-food-giant-nichirei/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
