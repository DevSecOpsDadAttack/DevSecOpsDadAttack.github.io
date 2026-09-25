---
layout: post
title: "Threat Intelligence Brief - Friday, September 25, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-25
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-48842
  - T1592
  - T1589
  - T1040
  - T1190
  - T1021
  - T1566.002
  - T1020
  - T1561
  - T1561.002
  - T1589.001
---

## Threat Radar

- North Korea's Lazarus Group executed a $351.6M heist against Bitget via backend compromise — one of the largest state-linked crypto thefts on record. Financial services and digital asset custodians face elevated targeting risk.

- CVE-2026-48842, a pre-authentication SQL injection in Roundcube Webmail (CVSS 8.1), is actively exploited in the wild with a patch available. Any exposed instance should be treated as potentially compromised.

- Three "SalesBleed" vulnerabilities in Salesforce Agentforce enabled zero-click data exfiltration and AI agent hijacking. Agentforce deployments require immediate configuration review and application of Salesforce mitigations.

- Russia is intensifying hybrid operations against European nations, combining cyber sabotage, disinformation, and drone attacks. Government and critical infrastructure operators with European exposure should reassess resilience posture now.

- This brief covers three operationally urgent and distinct response tracks — state-sponsored financial crime, actively exploited webmail infrastructure, and emerging AI agent attack surfaces — alongside a sustained hybrid threat requiring ongoing monitoring.

<br/>
---
<br/>

## Immediate Action Required

- **Roundcube Webmail — CVE-2026-48842:** Apply the available patch immediately. This pre-auth SQL injection requires no credentials to exploit and is confirmed actively exploited in the wild. Treat any unpatched, internet-exposed instance as a priority remediation. Review mail server logs for anomalous query activity against the virtuser_query plugin.

- **Bitget / Lazarus Group — Crypto Exchange Breach:** Audit hot and warm wallet access controls and review backend authentication posture. Validate lateral movement exposure (T1021). Assess third-party exchange relationships and custodial arrangements for inherited risk.

- **Salesforce Agentforce — SalesBleed:** Review Agentforce agent permission scopes and data access boundaries. Apply available Salesforce mitigations. CRM owners and IAM teams should determine what sensitive data is accessible to Agentforce agents and whether phishing-capable trust relationships exist.

<br/>
---
<br/>

## High-Impact Developments

### Lazarus Group Steals $351.6M from Bitget in State-Linked Crypto Heist

- **What happened:** Cryptocurrency exchange Bitget disclosed that suspected Lazarus Group actors compromised its backend systems and executed unauthorized transfers totaling $351.6 million from hot and warm wallets. The breach was detected at 18:31 UTC on September 24, 2026.

- **Why it matters:** This is a large-scale, state-sponsored financial theft targeting a major exchange's operational wallet infrastructure. Lazarus has a documented pattern of targeting crypto platforms to fund North Korean state programs. The backend compromise vector (T1190, T1021) indicates the attackers achieved privileged access before initiating transfers — not a phishing incident.

- **Who should care:** CISOs at cryptocurrency exchanges, digital asset custodians, fintech platforms, and any organization holding or transacting in digital assets. Financial services firms with crypto exposure should treat this as a sector-wide threat signal.

- **Recommended action:** Audit hot and warm wallet access controls and privileged backend access. Review remote access paths (T1021) for anomalous activity. Confirm whether your exchange or custodial partners have disclosed any related exposure. Engage incident response if any unexplained wallet activity is detected.

- **Confidence:** High — confirmed by Bitget disclosure, corroborated by multiple credible sources.

- **Search metadata:** T1190, T1021, Lazarus, Bitget, cryptocurrency, financial theft

**Intelligence Context**
- [Bitget Says Suspected North Korean Hackers Stole $351.6M After Backend Compromise — The Hacker News](https://thehackernews.com/2026/09/bitget-says-suspected-north-korean.html)
  - Context: Primary disclosure from Bitget confirming the breach timeline, wallet types affected, and attribution to suspected North Korean actors.

- [Hackers steal $351.6 million in Bitget crypto exchange hack — Bleeping Computer](https://www.bleepingcomputer.com/news/security/hackers-steal-3516-million-in-bitget-crypto-exchange-hack/)
  - Context: Corroborating coverage providing additional technical context on the scope of the theft and the hot/warm wallet compromise.

<br/>
---
<br/>

### CVE-2026-48842: Roundcube Webmail Pre-Auth SQL Injection Under Active Exploitation

- **What happened:** CVE-2026-48842, a pre-authentication SQL injection vulnerability (CVSS 8.1) in the virtuser_query plugin of Roundcube Webmail, is being actively exploited in the wild. The Canadian Centre for Cyber Security issued a public warning. A patch is available.

- **Why it matters:** Pre-authentication exploitation means attackers need no valid credentials to compromise exposed instances. Roundcube is widely deployed across government, academic, and enterprise environments. Successful exploitation can yield unauthorized mailbox access and sensitive email data exposure at scale.

- **Who should care:** Vulnerability management leads, IT operations, and email security teams running any version of Roundcube Webmail with the virtuser_query plugin enabled. SOC teams should treat unpatched instances as actively targeted.

- **Recommended action:** Apply the patch for CVE-2026-48842 immediately. Identify all internet-exposed Roundcube instances in your environment. Review mail server access logs for anomalous pre-authentication activity. If patching cannot be completed immediately, restrict external access to Roundcube interfaces in the interim.

- **Confidence:** High — active exploitation confirmed, government advisory issued, patch available.

- **Search metadata:** CVE-2026-48842, T1190, Roundcube Webmail, SQL injection

**Intelligence Context**
- [Roundcube Pre-Auth SQL Injection Flaw Actively Exploited in the Wild — The Hacker News](https://thehackernews.com/2026/09/roundcube-pre-auth-sql-injection-flaw.html)
  - Context: Details the Canadian Centre for Cyber Security advisory, confirms active exploitation, and identifies the virtuser_query plugin as the vulnerable component.

- [Roundcube Webmail Vulnerability in Attackers' Crosshairs — SecurityWeek](https://www.securityweek.com/roundcube-webmail-vulnerability-in-attackers-crosshairs/)
  - Context: Corroborates active exploitation and confirms the unauthenticated nature of the attack vector, reinforcing urgency for immediate patching.

<br/>
---
<br/>

### SalesBleed: Zero-Click Agent Hijacking and Data Exfiltration in Salesforce Agentforce

- **What happened:** Researchers disclosed three vulnerabilities collectively dubbed "SalesBleed" in Salesforce Agentforce. The flaws allowed attackers to hijack trusted AI agents, exfiltrate sensitive business data, and launch phishing attacks without requiring user interaction. Mitigations are available from Salesforce.

- **Why it matters:** AI agent platforms operate with elevated trust and broad data access by design. Hijacking these agents without user interaction (T1020, T1566.002) bypasses user-awareness controls entirely. At enterprise scale, a compromised Agentforce agent could silently exfiltrate CRM data or deliver credible phishing from a trusted system identity — and do so without generating the signals defenders typically look for.

- **Who should care:** Security architects, cloud security teams, CRM owners, and IAM leads at any organization running Salesforce Agentforce. This is also a signal for any organization deploying AI agents with broad SaaS data access — the attack surface class is not unique to Salesforce.

- **Recommended action:** Review Agentforce agent permission scopes and data access boundaries. Apply available Salesforce mitigations. Determine what sensitive data is reachable by Agentforce agents and whether agent-to-user trust relationships could be weaponized for phishing. Engage Salesforce account teams for remediation guidance.

- **Confidence:** High — vulnerabilities confirmed by SecurityWeek reporting; broader campaign scope not confirmed.

- **Search metadata:** T1566.002, T1020, Salesforce Agentforce, SalesBleed, data exfiltration, agent hijacking

**Intelligence Context**
- ['SalesBleed' Flaws in Salesforce Agentforce Enabled Zero-Click Data Exfiltration — SecurityWeek](https://www.securityweek.com/salesbleed-flaws-in-salesforce-agentforce-enabled-zero-click-data-exfiltration/)
  - Context: Primary source detailing the three SalesBleed vulnerabilities, the zero-click exploitation mechanism, and the data exfiltration and phishing capabilities enabled by agent hijacking.

<br/>
---
<br/>

## Monitor Only

- Russia's escalating hybrid operations — combining cyber sabotage (T1561, T1561.002), disinformation, and drone attacks — against European nations supporting Ukraine represent a sustained and broadening threat to government and critical infrastructure operators; European organizations should reassess resilience and physical security posture now. **Source:** Russia's Hybrid Cyber-Physical War in Europe Heats Up — Dark Reading — [https://www.darkreading.com/physical-security/russia-hybrid-cyber-physical-war-europe](https://www.darkreading.com/physical-security/russia-hybrid-cyber-physical-war-europe)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects three distinct but operationally urgent threat tracks running in parallel. The Bitget breach is a reminder that Lazarus doesn't need novel malware — backend access and privileged lateral movement are sufficient to move hundreds of millions in minutes. The Roundcube exploitation is a textbook case of why pre-auth vulnerabilities in internet-facing mail infrastructure demand same-day patching decisions, not next-cycle scheduling. The SalesBleed findings deserve more attention than they'll likely receive: AI agent platforms are being deployed faster than security teams are evaluating their trust boundaries, and zero-click exfiltration from a system users inherently trust is a difficult problem to detect after the fact. The Russian hybrid operations story is real but diffuse — it matters most to organizations with European critical infrastructure exposure, where the physical and cyber threat surfaces are now genuinely converged.

<br/>
---
<br/>

## Source Links

- Bitget Says Suspected North Korean Hackers Stole $351.6M After Backend Compromise — The Hacker News — [https://thehackernews.com/2026/09/bitget-says-suspected-north-korean.html](https://thehackernews.com/2026/09/bitget-says-suspected-north-korean.html)

- Hackers steal $351.6 million in Bitget crypto exchange hack — Bleeping Computer — [https://www.bleepingcomputer.com/news/security/hackers-steal-3516-million-in-bitget-crypto-exchange-hack/](https://www.bleepingcomputer.com/news/security/hackers-steal-3516-million-in-bitget-crypto-exchange-hack/)

- Roundcube Pre-Auth SQL Injection Flaw Actively Exploited in the Wild — The Hacker News — [https://thehackernews.com/2026/09/roundcube-pre-auth-sql-injection-flaw.html](https://thehackernews.com/2026/09/roundcube-pre-auth-sql-injection-flaw.html)

- Roundcube Webmail Vulnerability in Attackers' Crosshairs — SecurityWeek — [https://www.securityweek.com/roundcube-webmail-vulnerability-in-attackers-crosshairs/](https://www.securityweek.com/roundcube-webmail-vulnerability-in-attackers-crosshairs/)

- 'SalesBleed' Flaws in Salesforce Agentforce Enabled Zero-Click Data Exfiltration — SecurityWeek — [https://www.securityweek.com/salesbleed-flaws-in-salesforce-agentforce-enabled-zero-click-data-exfiltration/](https://www.securityweek.com/salesbleed-flaws-in-salesforce-agentforce-enabled-zero-click-data-exfiltration/)

- Russia's Hybrid Cyber-Physical War in Europe Heats Up — Dark Reading — [https://www.darkreading.com/physical-security/russia-hybrid-cyber-physical-war-europe](https://www.darkreading.com/physical-security/russia-hybrid-cyber-physical-war-europe)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
