---
layout: post
title: "Threat Intelligence Brief - Sunday, September 27, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-27
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-65660
  - CVE-2026-35273
  - T1190
  - T1059
  - T1036
  - T1555
  - T1562
  - T1195
  - T1041
  - T1547
  - Microsoft
---

## Threat Radar

- **CISA KEV deadline today:** Microsoft SharePoint CVE-2026-65660 is under active exploitation with a federal patching deadline of September 28 — all SharePoint operators should treat this as overdue.

- **No patch available:** Two Citrix NetScaler ADC and Gateway zero-days enabling remote code execution are actively exploited with no vendor fix published; compensating controls are the only current option.

- **WAF bypass in the wild:** ShinyHunters is using a URL-encoding technique to circumvent WAF mitigations for Oracle PeopleSoft CVE-2026-35273, invalidating a common compensating control and resuming widespread exploitation.

- **CI/CD supply chain exposure:** Two GitHub Actions compromised in the Mini Shai-Hulud campaign were re-enabled by their maintainer and remained live with malicious payloads for over a week — any pipeline consuming these actions may be affected.

- **Credential theft MaaS active:** The Lunex platform is distributing Psychedelic Stealer via compromised websites, using an AMD driver to blind endpoint security tools before harvesting browser credentials on Windows systems.

- **AI-assisted botnet emerging:** The x47.c Windows botnet uses xAI Grok to dynamically select persistence actions, increasing evasion complexity and raising the operational bar for defenders.

<br/>
---
<br/>

## Immediate Action Required

- **SharePoint — Patch Now (CVE-2026-65660):** Active exploitation is confirmed and the CISA KEV deadline is today (September 28). Federal agencies are mandated; all enterprise SharePoint operators should treat this with equivalent urgency. Validate patch status across all SharePoint instances immediately.

- **Citrix NetScaler ADC / Gateway — No Patch Exists:** Two unpatched RCE zero-days are actively exploited. Citrix has not confirmed the flaws or released fixes. Restrict management interface exposure, enforce network segmentation around NetScaler appliances, and monitor for anomalous process execution. Brief leadership on the unpatched status.

- **Oracle PeopleSoft — WAF Mitigation Is Insufficient (CVE-2026-35273):** ShinyHunters has demonstrated a URL-encoding bypass that defeats WAF rules protecting this flaw. Any team relying solely on WAF mitigations is exposed. Apply the vendor patch immediately; WAF rules are not an adequate substitute.

- **GitHub Actions — Audit CI/CD Pipelines:** Any pipeline consuming the two affected GitHub Actions from the Mini Shai-Hulud campaign may have ingested malicious code. Audit all third-party GitHub Actions in use, pin actions to verified commit SHAs, and review recent build artifacts for signs of tampering.

<br/>
---
<br/>

## High-Impact Developments

### Microsoft SharePoint CVE-2026-65660 Actively Exploited — CISA KEV Deadline Today

- **What happened:** CISA added CVE-2026-65660 to its Known Exploited Vulnerabilities catalog with a federal patching deadline of September 28. Active exploitation of Microsoft SharePoint is confirmed in the wild.

- **Why it matters:** A KEV listing combined with confirmed active exploitation means this vulnerability is being weaponized against real targets now. The deadline creates compliance exposure for federal agencies, but the operational risk applies equally to any enterprise running SharePoint.

- **Who should care:** SharePoint administrators, vulnerability management leads, federal agency security teams, IT security leadership.

- **Recommended action:** Validate patch status across all SharePoint deployments immediately. Escalate any unpatched instances to leadership. Federal agencies are past the compliance deadline.

- **Confidence:** High — CISA KEV listing and confirmed exploitation reported by SecurityWeek.

- **Search metadata:** CVE-2026-65660, T1190, SharePoint, Microsoft, CISA KEV

**Intelligence Context**
- [Microsoft SharePoint Flaw CVE-2026-65660 Now Exploited in Attacks — SecurityWeek](https://www.securityweek.com/microsoft-sharepoint-flaw-cve-2026-65660-now-exploited-in-attacks/)
  - Context: SecurityWeek reported CISA's KEV addition and the September 28 federal patching deadline, confirming active exploitation of the SharePoint flaw in ongoing attacks.

<br/>
---
<br/>

### Citrix NetScaler Unpatched RCE Zero-Days Under Active Exploitation

- **What happened:** Security firm watchTowr disclosed two unpatched zero-day vulnerabilities in Citrix NetScaler ADC and NetScaler Gateway that enable remote code execution. Both are actively exploited in the wild. Citrix has not confirmed the flaws or released a fix.

- **Why it matters:** Edge devices with no available patch and confirmed active exploitation represent the highest-risk scenario in vulnerability management. Attackers can achieve RCE on network perimeter appliances before defenders have any vendor-sanctioned remediation path.

- **Who should care:** Citrix administrators, network security teams, SOC leaders, security architects managing perimeter infrastructure.

- **Recommended action:** Restrict management interface access immediately, enforce network segmentation around NetScaler appliances, and increase monitoring for anomalous process execution. Monitor Citrix advisories for patch availability. Brief leadership on the unpatched status.

- **Confidence:** High — exploitation confirmed by watchTowr; vendor has not disputed the findings.

- **Search metadata:** T1190, T1059, Citrix NetScaler ADC, Citrix NetScaler Gateway, Zero-Day, RCE

**Intelligence Context**
- [Warning: Two Unpatched Citrix NetScaler RCE Zero-Days Under Active Exploitation — The Hacker News](https://thehackernews.com/2026/09/warning-two-unpatched-citrix-netscaler.html)
  - Context: The Hacker News reported watchTowr's September 26 disclosure of two actively exploited RCE zero-days in Citrix NetScaler ADC and Gateway, noting Citrix has not published fixes or formally confirmed the vulnerabilities.

<br/>
---
<br/>

### ShinyHunters Bypasses WAF to Exploit Oracle PeopleSoft CVE-2026-35273

- **What happened:** The ShinyHunters extortion group developed a URL-encoding technique that bypasses WAF rules commonly deployed to mitigate CVE-2026-35273 in Oracle PeopleSoft, resuming widespread exploitation of vulnerable servers.

- **Why it matters:** This directly invalidates a compensating control many teams may have accepted in place of patching. ShinyHunters is an established extortion actor with a track record of large-scale data theft. PeopleSoft is widely deployed as an HR and ERP platform, making successful exploitation a high-consequence event.

- **Who should care:** Oracle PeopleSoft administrators, application security teams, vulnerability management leads, security architects who approved WAF-only mitigations.

- **Recommended action:** Apply the Oracle patch for CVE-2026-35273 immediately. WAF rules are not a sufficient control for this vulnerability. Review WAF configurations for URL-encoding normalization gaps as a broader defensive measure.

- **Confidence:** High — active exploitation by a named threat actor with a specific bypass technique reported by Bleeping Computer.

- **Search metadata:** CVE-2026-35273, T1190, T1036, ShinyHunters, Oracle PeopleSoft, WAF bypass, Defense Evasion

**Intelligence Context**
- [ShinyHunters uses WAF bypass trick in Oracle PeopleSoft attacks — Bleeping Computer](https://www.bleepingcomputer.com/news/security/shinyhunters-uses-waf-bypass-trick-in-oracle-peoplesoft-attacks/)
  - Context: Bleeping Computer reported that ShinyHunters is using a URL-encoding trick to bypass WAF mitigations for CVE-2026-35273, allowing the group to resume widespread exploitation of unpatched PeopleSoft servers.

<br/>
---
<br/>

### Compromised GitHub Actions Reactivated with Mini Shai-Hulud Malicious Payload

- **What happened:** Two GitHub Actions previously compromised in the Mini Shai-Hulud supply chain campaign were re-enabled by their maintainer and remained publicly accessible with malicious code active for more than a week.

- **Why it matters:** Malicious code injected at the build stage propagates into every downstream artifact, container, or deployment produced during the exposure window. The re-enablement by the maintainer indicates either account compromise or insider risk. A week-long window represents significant potential exposure for any consuming pipeline.

- **Who should care:** DevOps teams, security engineers, software engineering leads, anyone responsible for CI/CD pipeline integrity.

- **Recommended action:** Audit all third-party GitHub Actions currently in use. Pin actions to specific commit SHAs rather than mutable tags. Review build artifacts produced during the exposure window for signs of tampering. Verify maintainer account integrity for any third-party actions in your pipelines.

- **Confidence:** High — confirmed by Bleeping Computer with specific campaign attribution to Mini Shai-Hulud.

- **Search metadata:** T1195, GitHub Actions, Mini Shai-Hulud, Supply Chain, Malicious Code

**Intelligence Context**
- [GitHub Actions re-enabled with Mini Shai-Hulud payload still active — Bleeping Computer](https://www.bleepingcomputer.com/news/security/github-actions-re-enabled-with-mini-shai-hulud-payload-still-active/)
  - Context: Bleeping Computer reported that two GitHub Actions compromised in the Mini Shai-Hulud campaign were re-enabled by their maintainer and remained accessible with active malicious payloads for over a week, creating downstream supply chain risk for any consuming pipeline.

<br/>
---
<br/>

## Monitor Only

- **Lunex MaaS / Psychedelic Stealer:** A four-stage credential-stealing campaign abuses an AMD driver to disable endpoint security monitoring before harvesting browser credentials on Windows systems; SOC and endpoint teams should validate EDR coverage against driver-based security disablement techniques. **Source:** [Lunex Stealer Abuses AMD Driver to Disable Security Monitoring and Steal Browser Credentials — The Hacker News](https://thehackernews.com/2026/09/lunex-stealer-abuses-amd-driver-to.html)

- **x47.c Windows Botnet / xAI Grok abuse:** A novel Windows botnet uses the xAI Grok API to dynamically select persistence actions, increasing detection complexity; threat hunting teams on Windows environments should be aware of this AI-assisted persistence technique as an emerging pattern. **Source:** [New x47.c Windows Botnet Weaponizes xAI Grok, AI API Draining — SecurityWeek](https://www.securityweek.com/new-x47-c-windows-botnet-weaponizes-xai-grok-ai-api-draining/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment where the patching problem is compounding faster than most organizations can absorb it: a KEV-listed SharePoint flaw with a same-day deadline, two Citrix zero-days with no patch at all, and a named extortion actor actively defeating a compensating control that security teams may have signed off as sufficient for PeopleSoft. The Citrix situation is the most operationally dangerous — no CVE, no vendor fix, confirmed exploitation — and it sits on the network perimeter where compromise is immediate and lateral movement is trivial. The GitHub Actions re-enablement is a quiet but serious signal about the fragility of third-party CI/CD dependencies; the week-long exposure window means any team that didn't catch this independently may have already ingested malicious build artifacts. The AI-assisted botnet is worth tracking as a trend, but it should not distract from the three items that require action today.

<br/>
---
<br/>

## Source Links

- Microsoft SharePoint Flaw CVE-2026-65660 Now Exploited in Attacks — [https://www.securityweek.com/microsoft-sharepoint-flaw-cve-2026-65660-now-exploited-in-attacks/](https://www.securityweek.com/microsoft-sharepoint-flaw-cve-2026-65660-now-exploited-in-attacks/)

- Warning: Two Unpatched Citrix NetScaler RCE Zero-Days Under Active Exploitation — [https://thehackernews.com/2026/09/warning-two-unpatched-citrix-netscaler.html](https://thehackernews.com/2026/09/warning-two-unpatched-citrix-netscaler.html)

- ShinyHunters uses WAF bypass trick in Oracle PeopleSoft attacks — [https://www.bleepingcomputer.com/news/security/shinyhunters-uses-waf-bypass-trick-in-oracle-peoplesoft-attacks/](https://www.bleepingcomputer.com/news/security/shinyhunters-uses-waf-bypass-trick-in-oracle-peoplesoft-attacks/)

- Lunex Stealer Abuses AMD Driver to Disable Security Monitoring and Steal Browser Credentials — [https://thehackernews.com/2026/09/lunex-stealer-abuses-amd-driver-to.html](https://thehackernews.com/2026/09/lunex-stealer-abuses-amd-driver-to.html)

- GitHub Actions re-enabled with Mini Shai-Hulud payload still active — [https://www.bleepingcomputer.com/news/security/github-actions-re-enabled-with-mini-shai-hulud-payload-still-active/](https://www.bleepingcomputer.com/news/security/github-actions-re-enabled-with-mini-shai-hulud-payload-still-active/)

- New x47.c Windows Botnet Weaponizes xAI Grok, AI API Draining — [https://www.securityweek.com/new-x47-c-windows-botnet-weaponizes-xai-grok-ai-api-draining/](https://www.securityweek.com/new-x47-c-windows-botnet-weaponizes-xai-grok-ai-api-draining/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
