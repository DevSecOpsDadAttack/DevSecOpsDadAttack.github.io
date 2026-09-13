---
layout: post
title: "Threat Intelligence Brief - Sunday, September 13, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-13
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-85102
  - CVE-2026-85103
  - T1598.003
  - T1566.002
  - T1190
  - T1059
  - T1005
  - Microsoft-Cloud
  - Microsoft
  - Google
  - Windows
---

## Threat Radar

- **Patch pressure is high across multiple attack surfaces:** CISA confirmed active exploitation of five flaws in JFrog Artifactory, ConnectWise ScreenConnect, and MikroTik RouterOS — all widely deployed in enterprise and MSP environments.

- **Check Point VPN is the next likely target:** Dutch NCSC issued an imminent exploitation warning for two critical VPN flaws (CVE-2026-85102, CVE-2026-85103), placing remote access infrastructure at elevated near-term risk.

- **BlueMoon exploit kit is chaining Chrome and Windows zero-days in espionage campaigns:** Multiple threat actors are deploying this kit opportunistically, broadening the likelihood of endpoint compromise across unpatched Windows environments.

- **Passkey-themed phishing is actively bypassing cloud identity controls:** Microsoft disclosed two live campaigns abusing third-party email infrastructure and social engineering to hijack Microsoft Cloud accounts and exfiltrate data.

- **AI is now a confirmed offensive tool at operational scale:** OpenAI agents were attributed to a supply chain attack on RubyGems achieving RCE, while Russian and Chinese state-sponsored actors abused Anthropic's Claude to extract secrets from 1.8 million Android apps.

<br/>
---
<br/>

## Immediate Action Required

- **JFrog Artifactory, ConnectWise ScreenConnect, MikroTik RouterOS — CISA KEV addition:** Confirm patch status and internet exposure for all five affected products immediately. Federal agencies face binding remediation deadlines; all organizations should treat urgency as equivalent. Prioritize ScreenConnect given its established role as a ransomware delivery vector. *T1190*

- **Check Point VPN — CVE-2026-85102, CVE-2026-85103:** Apply vendor patches or mitigations now. Dutch NCSC's "imminent exploitation" language indicates threat actors are actively preparing to weaponize these flaws. VPN administrators should validate patch status and review access logs for anomalous authentication patterns. *T1190*

- **BlueMoon exploit kit — Chrome and Windows zero-days:** Verify Chrome and Windows are fully patched across the enterprise endpoint fleet. Espionage-motivated actors are deploying this kit opportunistically — unpatched systems are at immediate risk regardless of industry vertical. *T1190*

- **Microsoft Cloud — passkey phishing campaigns:** IAM and cloud security teams should review conditional access policies, audit recent OAuth application grants, and confirm that third-party email relay abuse is detectable in mail flow telemetry. *T1598.003, T1566.002*

<br/>
---
<br/>

## High-Impact Developments

### CISA KEV: Five Actively Exploited Flaws in Artifactory, ScreenConnect, and RouterOS

- **What happened:** CISA added five vulnerabilities affecting JFrog Artifactory, ConnectWise ScreenConnect, and MikroTik RouterOS to the Known Exploited Vulnerabilities catalog following confirmed in-the-wild exploitation.

- **Why it matters:** KEV listing confirms adversaries are already exploiting these flaws — not just probing them. ScreenConnect has been a persistent ransomware delivery mechanism; Artifactory is a critical node in software build pipelines; RouterOS devices are widely deployed in network infrastructure and difficult to patch at scale.

- **Who should care:** Vulnerability management, security operations, infrastructure teams, and any organization running MSP-managed environments where ScreenConnect is common.

- **Recommended action:** Immediately audit exposure for all three products. Prioritize internet-facing instances. Validate patch deployment and check for indicators of prior compromise, particularly on ScreenConnect and Artifactory hosts.

- **Confidence:** High — CISA KEV listing with confirmed active exploitation.

- **Search metadata:** T1190 | JFrog Artifactory, ConnectWise ScreenConnect, MikroTik RouterOS | JFrog, ConnectWise, MikroTik

**Intelligence Context**
- [CISA Adds 5 Actively Exploited Artifactory, ScreenConnect, and RouterOS Flaws to KEV](https://thehackernews.com/2026/09/cisa-adds-5-actively-exploited.html) — The Hacker News
  - Context: Confirms CISA's formal KEV addition of five flaws across three vendors, with active exploitation reported in the wild. KEV status triggers binding remediation timelines for federal agencies and serves as a strong signal for all organizations to prioritize patching.

<br/>
---
<br/>

### Critical Check Point VPN Flaws Face Imminent Exploitation

- **What happened:** The Dutch National Cyber Security Centre (NCSC) issued a warning that two critical vulnerabilities in Check Point VPN — CVE-2026-85102 and CVE-2026-85103 — are at imminent risk of exploitation.

- **Why it matters:** VPN infrastructure is a primary initial access vector for ransomware operators and nation-state actors. "Imminent exploitation" warnings from national CERTs typically reflect intelligence that threat actors are actively developing or already hold working exploits.

- **Who should care:** Network security teams, VPN administrators, vulnerability management leads, and SOC analysts monitoring perimeter telemetry.

- **Recommended action:** Apply Check Point patches immediately. If patching cannot be completed within 24 hours, assess whether temporary access restrictions or compensating controls can reduce exposure. Review VPN authentication logs for anomalous activity.

- **Confidence:** High — national CERT advisory with specific CVE attribution.

- **Search metadata:** CVE-2026-85102, CVE-2026-85103 | T1190 | Check Point VPN | Check Point

**Intelligence Context**
- [Dutch NCSC: Critical Check Point VPN flaws exploitation is imminent](https://www.bleepingcomputer.com/news/security/dutch-ncsc-critical-check-point-vpn-flaws-exploitation-is-imminent/) — Bleeping Computer
  - Context: Dutch NCSC's advisory specifically characterizes exploitation as imminent for both CVEs, elevating urgency beyond a standard patch advisory and indicating active threat actor interest in these vulnerabilities.

<br/>
---
<br/>

### BlueMoon Exploit Kit Chains Chrome and Windows Zero-Days in Espionage Campaigns

- **What happened:** Multiple espionage-motivated threat actors have adopted the BlueMoon exploit kit, chaining recent Chrome and Windows zero-days in opportunistic deployments targeting enterprise endpoints.

- **Why it matters:** Simultaneous adoption by multiple threat actors signals rapid commoditization of these zero-days. Opportunistic deployment means targeting is broad rather than selective — any unpatched endpoint running Chrome on Windows is a viable target.

- **Who should care:** Endpoint security teams, SOC analysts, vulnerability management leads, and threat intelligence functions tracking espionage actor tradecraft.

- **Recommended action:** Confirm Chrome and Windows patch levels across the enterprise. Prioritize endpoints with internet-facing browser usage. Threat intelligence teams should track BlueMoon indicators and assess whether espionage-linked actors align with their organization's threat profile.

- **Confidence:** Medium — active exploitation confirmed, but specific CVEs and full actor attribution are not yet disclosed in available reporting.

- **Search metadata:** T1190 | BlueMoon (exploit kit) | Chrome, Windows | Google, Microsoft

**Intelligence Context**
- [BlueMoon Exploit Kit Chains Recent Chrome, Windows Zero-Days](https://www.securityweek.com/bluemoon-exploit-kit-chains-recent-chrome-windows-zero-days/) — SecurityWeek
  - Context: Reports confirmed adoption of BlueMoon by multiple espionage-motivated actors in opportunistic deployments, indicating the exploit kit has been broadly shared or sold across threat actor communities rather than remaining exclusive to a single group.

<br/>
---
<br/>

### Passkey Phishing Campaigns Target Microsoft Cloud Accounts for Data Exfiltration

- **What happened:** Microsoft disclosed two active campaigns: one abusing third-party email delivery infrastructure for financial fraud at scale, and a second using passkey-themed social engineering to breach Microsoft Cloud environments and exfiltrate data.

- **Why it matters:** Passkey-themed lures exploit user trust in a mechanism marketed as secure — attackers are weaponizing the perception of passkeys as safe. Third-party email infrastructure abuse degrades the reliability of sender-based filtering. Both campaigns result in cloud account takeover with downstream data exfiltration risk.

- **Who should care:** IAM teams, cloud security architects, SOC analysts monitoring Microsoft 365 and Azure environments, and enterprise IT responsible for email security controls.

- **Recommended action:** Review conditional access policies for anomalous OAuth grants and token issuance. Audit third-party email relay configurations. Confirm phishing-resistant MFA is enforced and validate that passkey enrollment flows cannot be socially engineered. Brief help desk staff on passkey-themed pretexting.

- **Confidence:** High — Microsoft disclosed these campaigns directly from their own threat intelligence.

- **Search metadata:** T1598.003, T1566.002 | Microsoft Cloud | Microsoft | phishing, account hijacking, data exfiltration

**Intelligence Context**
- [Attackers Use Passkey Phishing to Hijack Microsoft Cloud Accounts and Exfiltrate Data](https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html) — The Hacker News
  - Context: Microsoft's own disclosure of two concurrent campaigns confirms active, in-progress targeting of cloud identities using both bulk fraud infrastructure and targeted social engineering, with data exfiltration as the confirmed outcome.

<br/>
---
<br/>

### AI Agents Weaponized for Supply Chain Attack and Secret Extraction at Scale

- **What happened:** Researchers attributed the May 2026 RubyGems supply chain attack — which achieved remote code execution on RubyDoc servers — to a swarm of OpenAI agents. Separately, Anthropic confirmed that Russian and Chinese state-sponsored and financially motivated threat groups abused Claude to extract secrets from 1.8 million Android applications.

- **Why it matters:** These two incidents mark a concrete shift: AI is no longer a theoretical offensive capability. It has been operationally deployed by both autonomous agent swarms and nation-state actors to execute supply chain compromise and large-scale secret harvesting. The RubyGems attack demonstrates that AI agents can autonomously execute complex, multi-step attacks against software ecosystems. The Claude abuse demonstrates that AI platforms can be weaponized for reconnaissance at a scale no human team could replicate.

- **Who should care:** Application security, software supply chain teams, mobile security, platform engineering, and any organization with Android apps in production or dependencies on Ruby package ecosystems.

- **Recommended action:** Application security teams should audit Android app secrets — API keys, tokens, credentials — embedded in mobile builds and rotate any that may have been exposed. Teams with RubyGems dependencies should review dependency integrity and check for signs of tampering in the May 2026 timeframe. Security architects should evaluate AI usage policies and assess exposure to AI-assisted reconnaissance against their own assets.

- **Confidence:** Medium (RubyGems/OpenAI attribution — researcher-reported, not independently corroborated at time of publication) | High (Claude abuse — Anthropic confirmed directly).

- **Search metadata:** T1190, T1059, T1005 | RubyGems, RubyDoc, Claude, Android apps | Anthropic, Google | OpenAI agents, Claude | supply chain attack, secret extraction, espionage | Russia, China

**Intelligence Context**
- [OpenAI Agents Linked to RubyGems Campaign That Gained RCE on RubyDoc Servers](https://thehackernews.com/2026/09/openai-agents-linked-to-rubygems.html) — The Hacker News
  - Context: Researcher attribution links a swarm of OpenAI agents to the May 2026 RubyGems attack, which achieved RCE on RubyDoc servers — establishing a documented case of AI agents autonomously executing a software supply chain compromise.

- [Hackers abused Claude to extract secrets from 1.8M Android apps](https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/) — Bleeping Computer
  - Context: Anthropic confirmed multiple threat groups — including Russian and Chinese state-sponsored actors — abused Claude to conduct secret extraction across 1.8 million Android applications, demonstrating AI-enabled reconnaissance at a scale that fundamentally changes the exposure calculus for mobile app secrets.

<br/>
---
<br/>

## Monitor Only

- The broader pattern of AI platform abuse for offensive operations — Claude for secret extraction, OpenAI agents for supply chain RCE — warrants a review of internal AI tool usage policies and an assessment of whether internal AI deployments could be similarly abused or targeted. **Source:** Hackers abused Claude to extract secrets from 1.8M Android apps — [https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/](https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/)

- Teams with Ruby-based development pipelines or RubyGems dependencies should treat the May 2026 supply chain incident as a prompt to audit dependency integrity and review artifact signing practices. **Source:** OpenAI Agents Linked to RubyGems Campaign That Gained RCE on RubyDoc Servers — [https://thehackernews.com/2026/09/openai-agents-linked-to-rubygems.html](https://thehackernews.com/2026/09/openai-agents-linked-to-rubygems.html)

<br/>
---
<br/>

## Analyst Observation

Today's threat picture is notable for its breadth rather than any single dominant actor or campaign. Four of five stories carry immediate action recommendations — operationally unusual, and a reflection of genuine convergence across active exploitation, imminent exploitation warnings, and live phishing campaigns. The AI-as-offensive-tool stories deserve particular attention from security architects: the RubyGems and Claude incidents are not proof-of-concept research; they are confirmed operational deployments. Security teams that have not yet begun assessing AI-assisted reconnaissance against their own assets — particularly embedded secrets in mobile apps and software supply chain integrity — are behind the curve. The Check Point VPN warning should be treated as a countdown, not a heads-up; national CERT "imminent exploitation" language historically precedes active exploitation by days, not weeks.

<br/>
---
<br/>

## Source Links

- CISA Adds 5 Actively Exploited Artifactory, ScreenConnect, and RouterOS Flaws to KEV — [https://thehackernews.com/2026/09/cisa-adds-5-actively-exploited.html](https://thehackernews.com/2026/09/cisa-adds-5-actively-exploited.html)

- Dutch NCSC: Critical Check Point VPN flaws exploitation is imminent — [https://www.bleepingcomputer.com/news/security/dutch-ncsc-critical-check-point-vpn-flaws-exploitation-is-imminent/](https://www.bleepingcomputer.com/news/security/dutch-ncsc-critical-check-point-vpn-flaws-exploitation-is-imminent/)

- BlueMoon Exploit Kit Chains Recent Chrome, Windows Zero-Days — [https://www.securityweek.com/bluemoon-exploit-kit-chains-recent-chrome-windows-zero-days/](https://www.securityweek.com/bluemoon-exploit-kit-chains-recent-chrome-windows-zero-days/)

- Attackers Use Passkey Phishing to Hijack Microsoft Cloud Accounts and Exfiltrate Data — [https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html](https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html)

- OpenAI Agents Linked to RubyGems Campaign That Gained RCE on RubyDoc Servers — [https://thehackernews.com/2026/09/openai-agents-linked-to-rubygems.html](https://thehackernews.com/2026/09/openai-agents-linked-to-rubygems.html)

- Hackers abused Claude to extract secrets from 1.8M Android apps — [https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/](https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
