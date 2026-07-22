---
layout: post
title: "Threat Intelligence Brief - Wednesday, July 22, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-22
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1486
  - T1020
  - T1110.004
  - T1566.002
  - T1621
  - T1195.001
  - T1548
  - T1550
  - Microsoft
  - Microsoft-365
  - Exchange-2016
---

## Threat Radar

- **Anubis ransomware** has confirmed data theft from Coca-Cola subsidiary Fairlife, claiming 1 TB exfiltrated and threatening public release — active extortion pressure is in play now.

- **Food and beverage sector** is under simultaneous pressure from ransomware (Fairlife) and credential stuffing (Chick-fil-A), signaling targeted or opportunistic focus on consumer brands with large customer data footprints.

- **Microsoft identity and DevOps infrastructure** faces a two-front threat: the Kratos phishing kit was actively bypassing M365 MFA at scale before takedown, and a new Azure DevOps MCP flaw enables AI agent hijacking via invisible pull request comments.

- **NuGet supply chain compromise** confirmed — a trojanized package typosquatting Newtonsoft.Json was found in the wild with an active malicious payload, directly threatening .NET build pipelines.

- **Exchange 2016/2019 end-of-support** arrives in October — organizations still running these versions have a shrinking window to migrate before mail infrastructure becomes permanently unpatched.

<br/>
---
<br/>

## Immediate Action Required

- **Anubis / Fairlife ransomware:** If your organization has any relationship with Fairlife or the Coca-Cola supply chain, assess data-sharing exposure and initiate a third-party breach review. Engage legal and communications now — the leak threat is active. | T1486, T1020

- **Chick-fil-A credential stuffing:** Consumer-facing platforms with customer login portals should validate rate limiting, bot detection, and account lockout controls. Determine whether your customer credential exposure overlaps with known breach datasets. | T1110.004

- **Trojanized NuGet package (Newtonsoftt.Json.Net):** Engineering and DevOps teams using .NET should audit NuGet dependencies immediately for this package name and any near-matches to Newtonsoft.Json. Verify package integrity via hash and publisher verification. | T1195.001

- **Azure DevOps MCP AI agent hijacking:** Teams running AI-assisted code review agents integrated with Azure DevOps MCP should treat this as an active risk. Restrict AI agent permissions to least-privilege and audit recent PR review activity for anomalous cross-project access. | T1548, T1550

<br/>
---
<br/>

## High-Impact Developments

### Anubis Ransomware Claims 1 TB Theft from Coca-Cola's Fairlife

- **What happened:** The Anubis ransomware group claims to have exfiltrated 1 TB of confidential data from Fairlife, a Coca-Cola subsidiary, and is threatening public release if demands are not met.

- **Why it matters:** This is a confirmed double-extortion scenario — data is already out, and the clock is running on public disclosure. Regulatory notification obligations, reputational damage, and operational disruption are all live risks. Consumer brand subsidiaries are high-value targets: they typically carry large volumes of customer PII and financial data, often with less mature security programs than their parent companies.

- **Who should care:** Executive leadership, legal, IR teams, communications, and any organization in the food and beverage sector or with shared infrastructure with Fairlife.

- **Recommended action:** Confirm whether any data-sharing or third-party connectivity exists with Fairlife. Activate third-party breach response protocols. Engage your IR retainer if needed. Brief legal on regulatory notification timelines now.

- **Confidence:** High — confirmed claim by a threat actor with known operational history; exploitation confirmed.

- **Search metadata:** T1486, T1020 | Threat actor: Anubis | Sector: Food and Beverage

**Intelligence Context**
- [Ransomware Group Threatening to Leak Data Stolen From Coca-Cola's Fairlife](https://www.securityweek.com/ransomware-group-threatening-to-leak-data-stolen-from-coca-colas-fairlife/) — SecurityWeek reporting confirms the Anubis group's claim of 1 TB exfiltration from Fairlife and the active threat to publish the data, establishing this as a live extortion situation requiring immediate organizational awareness.

<br/>
---
<br/>

### Chick-fil-A Discloses Data Breach from Credential Stuffing

- **What happened:** Chick-fil-A is notifying customers of a data breach resulting from credential stuffing attacks that compromised customer accounts at scale.

- **Why it matters:** Credential stuffing is industrialized — attackers automate login attempts using previously breached username/password pairs to take over accounts across consumer platforms. The breach indicates that account protection controls failed to stop automated login abuse. Affected customers face fraud and privacy exposure. This is the second food and beverage sector breach reported on the same day as Fairlife.

- **Who should care:** Security, IAM, customer support, and legal teams — particularly at organizations operating consumer-facing login portals.

- **Recommended action:** Audit bot detection and rate limiting on all customer-facing authentication endpoints. Confirm MFA is available and actively promoted to customers. Cross-reference your platform's credential exposure against known breach datasets.

- **Confidence:** High — breach confirmed, customer notifications issued.

- **Search metadata:** T1110.004 | Sector: Food and Beverage

**Intelligence Context**
- [Chick-fil-A discloses data breach after credential stuffing attacks](https://www.bleepingcomputer.com/news/security/chick-fil-a-discloses-data-breach-after-credential-stuffing-attacks/) — Bleeping Computer confirms Chick-fil-A is actively notifying customers following credential stuffing attacks that resulted in confirmed account compromises and data exposure.

<br/>
---
<br/>

### Trojanized NuGet Package Targets .NET Developers via Typosquatting

- **What happened:** Researchers identified a malicious NuGet package named "Newtonsoftt.Json.Net" — a deliberate typosquat of the widely used Newtonsoft.Json library — containing hidden game-rigging code targeting the Digitain platform. The package functions as a working library, making detection harder.

- **Why it matters:** The package's operational camouflage — it works as advertised while executing malicious logic — reflects a maturation of supply chain attack tradecraft. Any .NET project that inadvertently pulled this dependency could have introduced compromised code into production builds. Typosquatting attacks against high-download packages like Newtonsoft.Json expose a massive developer population.

- **Who should care:** Security architects, software engineering leads, DevOps, and supply chain risk owners in organizations with .NET development pipelines.

- **Recommended action:** Audit NuGet package manifests across all .NET projects for "Newtonsoftt.Json.Net" or similar near-matches. Enforce package allowlisting or verified publisher policies in your build pipeline. Integrate software composition analysis tooling if not already in place.

- **Confidence:** High — confirmed malicious package; active exploitation confirmed.

- **Search metadata:** T1195.001 | Products: Newtonsoft.Json, NuGet | Platforms: .NET

**Intelligence Context**
- [Trojanized Newtonsoft.Json Fork Hides Game-Rigging Code in a Working Library](https://thehackernews.com/2026/07/trojanized-newtonsoftjson-fork-hides.html) — The Hacker News details the discovery of the typosquatted NuGet package, its functional disguise as a legitimate library, and its targeted malicious payload, confirming active supply chain risk for .NET ecosystems.

<br/>
---
<br/>

### Microsoft Identity and DevOps Under Dual Threat: Kratos Takedown and Azure DevOps MCP Flaw

- **What happened:** German and US law enforcement dismantled the Kratos phishing kit — one of the most widely used criminal phishing kits globally — which was purpose-built to steal Microsoft 365 session tokens and bypass MFA. Separately, a vulnerability in Microsoft's official Azure DevOps MCP server allows an attacker to embed invisible commands in pull request comments that hijack AI code review agents, enabling unauthorized cross-project access and data exfiltration.

- **Why it matters:** The Kratos takedown confirms the kit was in active, widespread use against M365 environments — session token theft at scale was occurring. The infrastructure is down, but copycat kits and residual compromised sessions remain a concern. The Azure DevOps MCP flaw is a novel AI-era attack surface: as organizations adopt AI coding agents, those agents inherit trust that can be weaponized through prompt injection via PR comments, bypassing normal access controls entirely.

- **Who should care:** IAM and M365 administrators (Kratos); DevOps, cloud engineering, and AI governance teams (Azure DevOps MCP). Security architects evaluating AI-assisted development tooling should treat this as a reference case.

- **Recommended action:** For Kratos: review M365 sign-in logs for anomalous session activity, particularly token reuse from unexpected locations, and enforce Conditional Access policies that bind sessions to device compliance. For Azure DevOps MCP: restrict AI agent permissions to the minimum required scope, audit recent AI-assisted PR reviews for unexpected cross-project actions, and monitor for Microsoft guidance or patches on the MCP server flaw.

- **Confidence:** High (Kratos — confirmed active exploitation, takedown complete); Medium (Azure DevOps MCP — exploitation status unconfirmed, vulnerability confirmed by researchers).

- **Search metadata:** T1566.002, T1621, T1548, T1550 | Products: Microsoft 365, Azure DevOps, Azure DevOps MCP | Malware: Kratos | Platform: Azure

**Intelligence Context**
- [Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and Bypass MFA](https://thehackernews.com/2026/07/police-dismantle-kratos-phishing-kit.html) — The Hacker News reports the joint German/US law enforcement action dismantling Kratos infrastructure and the arrest of its Indonesian developer, confirming the kit's scale and active use against M365 MFA controls.

- [Microsoft Azure DevOps MCP Flaw Lets Hidden PR Comments Hijack AI Review Agents](https://thehackernews.com/2026/07/microsoft-azure-devops-mcp-flaw-lets.html) — The Hacker News details the technical mechanism by which invisible PR comments can redirect AI review agents to access unauthorized projects and exfiltrate data, establishing this as a concrete and novel AI pipeline risk.

<br/>
---
<br/>

### Microsoft Exchange 2016/2019 End of Security Support in October

- **What happened:** Microsoft has confirmed that Extended Security Updates for Exchange 2016 and 2019 will cease in October, ending all security patch delivery for these on-premises versions.

- **Why it matters:** On-premises Exchange has historically been one of the most exploited enterprise mail platforms. Once ESU ends, any new vulnerabilities discovered will remain permanently unpatched. Organizations that have not migrated face a permanently expanding attack surface on a high-value target that sits at the network edge.

- **Who should care:** IT infrastructure, security, and vulnerability management teams responsible for on-premises mail infrastructure.

- **Recommended action:** Inventory Exchange 2016/2019 deployments now. If migration to Exchange Online or a supported on-premises version is not already in progress, escalate to leadership and start planning immediately. Procurement, testing, and cutover timelines cannot wait until September.

- **Confidence:** High — confirmed Microsoft announcement.

- **Search metadata:** Products: Exchange 2016, Exchange 2019 | Vendor: Microsoft | Platform: Windows

**Intelligence Context**
- [Microsoft to stop Exchange 2016 / 2019 security updates in October](https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-2016-and-2019-esu-program-ends-in-october/) — Bleeping Computer confirms Microsoft's official reminder that ESU coverage for Exchange 2016 and 2019 ends in October, leaving organizations on these versions without any further security patch coverage.

<br/>
---
<br/>

## Monitor Only

- The Kratos phishing kit takedown is a positive law enforcement outcome, but residual Kratos-derived kits and stolen M365 session tokens from prior campaigns may still be in circulation — M365 administrators should treat this as a prompt to review active session hygiene, not a resolved threat. **Source:** Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and Bypass MFA — [https://thehackernews.com/2026/07/police-dismantle-kratos-phishing-kit.html](https://thehackernews.com/2026/07/police-dismantle-kratos-phishing-kit.html)

<br/>
---
<br/>

## Analyst Observation

Two confirmed breaches in the food and beverage sector on the same day — one ransomware, one credential stuffing — is not coincidence. Consumer brand subsidiaries and franchise operators remain soft targets with high data value, and the Fairlife and Chick-fil-A incidents together reinforce that pattern. The Azure DevOps MCP flaw deserves particular attention from security architects: AI coding agents are being granted meaningful access to source code and project infrastructure, and the security model governing what those agents can be instructed to do is immature. This is a concrete exploitation path that will be replicated across other AI-integrated DevOps tooling. AI development assistants require the same least-privilege and input validation discipline applied to any privileged service account — that discipline is not yet standard practice. The Exchange end-of-support deadline is the kind of item that gets deferred until it becomes a crisis. October is closer than it looks.

<br/>
---
<br/>

## Source Links

- Ransomware Group Threatening to Leak Data Stolen From Coca-Cola's Fairlife — [https://www.securityweek.com/ransomware-group-threatening-to-leak-data-stolen-from-coca-colas-fairlife/](https://www.securityweek.com/ransomware-group-threatening-to-leak-data-stolen-from-coca-colas-fairlife/)

- Chick-fil-A discloses data breach after credential stuffing attacks — [https://www.bleepingcomputer.com/news/security/chick-fil-a-discloses-data-breach-after-credential-stuffing-attacks/](https://www.bleepingcomputer.com/news/security/chick-fil-a-discloses-data-breach-after-credential-stuffing-attacks/)

- Trojanized Newtonsoft.Json Fork Hides Game-Rigging Code in a Working Library — [https://thehackernews.com/2026/07/trojanized-newtonsoftjson-fork-hides.html](https://thehackernews.com/2026/07/trojanized-newtonsoftjson-fork-hides.html)

- Microsoft Azure DevOps MCP Flaw Lets Hidden PR Comments Hijack AI Review Agents — [https://thehackernews.com/2026/07/microsoft-azure-devops-mcp-flaw-lets.html](https://thehackernews.com/2026/07/microsoft-azure-devops-mcp-flaw-lets.html)

- Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and Bypass MFA — [https://thehackernews.com/2026/07/police-dismantle-kratos-phishing-kit.html](https://thehackernews.com/2026/07/police-dismantle-kratos-phishing-kit.html)

- Microsoft to stop Exchange 2016 / 2019 security updates in October — [https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-2016-and-2019-esu-program-ends-in-october/](https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-2016-and-2019-esu-program-ends-in-october/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
