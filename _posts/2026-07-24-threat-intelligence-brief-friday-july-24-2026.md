---
layout: post
title: "Threat Intelligence Brief - Friday, July 24, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-24
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1190
  - T1195
  - T1566
  - Windows
  - Hermes
  - Thailand
  - Ministry-of-Finance
  - AI-agent
  - post-exploitation
  - Post-Exploitation
  - AI-Driven-Attack
---

## Threat Radar

- **Clop is actively exfiltrating data from internet-exposed PTC Windchill and FlexPLM instances** — organizations running these PLM platforms face immediate extortion risk with no patch as the primary mitigation vector.

- **Russian state actor Laundry Bear is exploiting an unpatched Zimbra zero-day** via "half-click" phishing — victims need only preview a message to trigger compromise, eliminating the usual user-action barrier.

- **Redis shipped seven emergency patches after public RCE proof-of-concept code dropped** for four major versions — authenticated exploit chains are in the wild and patching windows are narrow.

- **Eight high-severity NodeBB vulnerabilities are now public with working exploit code** — admin access and private message exposure are achievable against any instance running below version 4.14.0.

- **Russian threat cluster UAC-0099 is trojanizing Notepad++ plugins** to deliver MATCHBOIL.V2 malware on Windows endpoints, exploiting developer trust in common tooling.

<br/>
---
<br/>

## Immediate Action Required

- **PTC Windchill / FlexPLM — Clop Ransomware Targeting:** Identify all internet-exposed instances immediately. If exposure exists, treat as potentially compromised. Restrict external access, audit egress logs for bulk data movement, and engage incident response if anomalies are found. Brief executive leadership given extortion and legal exposure risk. *(T1190, Clop)*

- **Redis — Patch All Instances Now:** Apply the seven security releases shipped July 23. Prioritize internet-facing and internally accessible Redis instances running versions 6.2.22, 7.4.9, 8.6.4, or 8.8.0. Public RCE PoC code is available; the exploitation window is open. *(T1190, RCE)*

- **NodeBB — Upgrade to 4.14.0 Immediately:** All prior versions are affected by eight high-severity flaws with public exploit code enabling admin access and private chat exposure. Upgrade is the only remediation. *(T1190)*

- **Zimbra — Laundry Bear Zero-Day Exploitation:** If your organization runs Zimbra, assume the zero-day is unpatched and treat email preview as a potential trigger. Engage Zimbra for patch status, disable message preview where operationally feasible, and heighten monitoring on Zimbra infrastructure. Government and critical sector organizations are primary targets. *(T1190, T1566, Laundry Bear)*

<br/>
---
<br/>

## High-Impact Developments

### Clop Ransomware Targets PTC Windchill and FlexPLM in Active Data Theft Campaign

- **What happened:** The Clop ransomware gang is actively targeting internet-exposed PTC Windchill and FlexPLM product lifecycle management instances. The campaign centers on data theft and extortion — Clop exfiltrates sensitive PLM data and threatens public disclosure to coerce payment.

- **Why it matters:** PLM systems hold proprietary product designs, manufacturing data, and supply chain information. Exfiltration carries significant IP loss, regulatory, and legal consequences beyond immediate operational disruption. Clop has a demonstrated history of mass-exploitation campaigns against enterprise software.

- **Who should care:** CISOs and security architects at manufacturing, aerospace, defense, and consumer goods organizations running PTC products; application owners responsible for Windchill and FlexPLM; legal and compliance teams.

- **Recommended action:** Immediately audit internet exposure of Windchill and FlexPLM. Remove external access where not operationally required. Review egress and authentication logs for indicators of bulk data exfiltration. Engage PTC for available mitigations. Brief executive leadership on extortion risk.

- **Confidence:** High

- **Search metadata:** T1190, Clop, Windchill, FlexPLM, PTC, Ransomware, Data Theft

**Intelligence Context**
- [Clop ransomware targets Windchill, FlexPLM in data theft attacks](https://www.bleepingcomputer.com/news/security/clop-ransomware-targets-windchill-flexplm-in-data-theft-attacks/) — Bleeping Computer
  - Context: Confirms active Clop targeting of internet-exposed PTC Windchill and FlexPLM instances in a data theft extortion campaign, with known exploitation underway.

<br/>
---
<br/>

### AI-Discovered Vulnerabilities: Redis RCE Zero-Days and NodeBB Admin Access Flaws

- **What happened:** AI agents discovered critical vulnerabilities in two widely deployed platforms. Kimi K3 agents identified authenticated RCE zero-days across four Redis versions (6.2.22, 7.4.9, 8.6.4, 8.8.0); Redis shipped seven patches on July 23 after public PoC code was released. Separately, Aikido Security's AI pentest agents found eight high-severity flaws in NodeBB during a six-hour source code review — all versions below 4.14.0 are affected, and exploit code is publicly available.

- **Why it matters:** Both disclosures arrived with working exploit code already public, compressing the patching window to near-zero. Redis is ubiquitous in application stacks; RCE against it can pivot into broader infrastructure compromise. NodeBB flaws expose admin credentials and private communications, creating both access and data exposure risk.

- **Who should care:** IT operations and application owners running Redis or NodeBB; SOC teams monitoring for exploitation attempts; vulnerability management leads prioritizing patch sequencing.

- **Recommended action:** Apply all seven Redis security patches immediately across all versions in use. Upgrade NodeBB to 4.14.0 or later without delay. Validate that Redis instances are not unnecessarily internet-exposed. Treat both as emergency patch items given public exploit availability.

- **Confidence:** High

- **Search metadata:** T1190, Redis, NodeBB, RCE, Remote Code Execution, Vulnerability Disclosure

**Intelligence Context**
- [Kimi K3 Agents Found Redis Zero-Days and Built RCE Exploit, Researchers Say](https://thehackernews.com/2026/07/kimi-k3-agents-found-redis-zero-days.html) — The Hacker News
  - Context: Details the AI-discovered authenticated RCE chains across four Redis versions, confirms public PoC availability, and reports Redis's seven-patch emergency release on July 23.

- [NodeBB Patches Eight AI-Found Flaws Exposing Admin Access and Private Chats](https://thehackernews.com/2026/07/nodebb-patches-eight-ai-found-flaws.html) — The Hacker News
  - Context: Reports eight high-severity NodeBB vulnerabilities found by Aikido Security AI agents in six hours, with exploit code now public and all pre-4.14.0 versions affected.

<br/>
---
<br/>

### Russian State Actor Laundry Bear Exploits Zimbra Zero-Day via Half-Click Phishing

- **What happened:** Russian state-sponsored group Laundry Bear is exploiting an unpatched Zimbra zero-day using "half-click" phishing emails — the vulnerability triggers on message open or preview, requiring no further user interaction. Confirmed targets include US and Ukrainian government entities.

- **Why it matters:** The passive trigger mechanism removes the most common phishing defense — user skepticism about clicking links or attachments. Any Zimbra user who previews a malicious email is potentially compromised. State-sponsored attribution and geopolitical targeting suggest intelligence collection and credential theft objectives, but the technique is transferable to broader campaigns.

- **Who should care:** Organizations running Zimbra for email, particularly government agencies, defense contractors, and critical infrastructure operators; SOC and email security teams; security architects evaluating email platform risk.

- **Recommended action:** Immediately assess Zimbra patch status and contact Zimbra for remediation guidance on this zero-day. Evaluate whether message preview can be disabled as a temporary control. Heighten monitoring on Zimbra authentication and access logs. Organizations adjacent to US or Ukrainian government operations should treat this as elevated risk.

- **Confidence:** High

- **Search metadata:** T1190, T1566, Laundry Bear, Zimbra, Zero-Day Exploitation, Phishing

**Intelligence Context**
- [Russian Hackers Exploit Zimbra Zero-Day Against US, Ukraine Targets](https://www.darkreading.com/cyberattacks-data-breaches/russian-hackers-zimbra-zero-day-us-ukraine-targets) — Dark Reading
  - Context: Attributes active Zimbra zero-day exploitation to Laundry Bear, describes the half-click phishing delivery mechanism, and confirms US and Ukrainian government targeting.

<br/>
---
<br/>

### UAC-0099 Distributes MATCHBOIL.V2 via Trojanized Notepad++ Plugin

- **What happened:** Russian threat cluster UAC-0099, flagged by CERT-UA, is distributing a malicious Notepad++ plugin that delivers MATCHBOIL.V2 malware on Windows systems. The campaign exploits user trust in a widely used developer text editor's plugin ecosystem to achieve initial access.

- **Why it matters:** Trojanized developer tools bypass both user suspicion and many endpoint controls — developers routinely install plugins and frequently carry elevated privileges. This technique is consistent with UAC-0099's pattern of targeting Ukrainian-linked organizations.

- **Who should care:** IT operations and endpoint security teams managing Windows developer environments; SOC teams monitoring for lateral movement from developer workstations; organizations with Ukrainian operational ties or contractors.

- **Recommended action:** Audit Notepad++ plugin installations across Windows endpoints, particularly in developer environments. Restrict plugin installation to approved sources. Verify plugin integrity against known-good hashes. Treat any recently installed, unverified Notepad++ plugins as suspect pending investigation.

- **Confidence:** High

- **Search metadata:** T1195, UAC-0099, MATCHBOIL.V2, Notepad++, Windows, Malware Distribution

**Intelligence Context**
- [Fake Notepad++ Plugin Delivers MATCHBOIL.V2 in UAC-0099 Attacks](https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html) — The Hacker News
  - Context: Reports CERT-UA's attribution of the trojanized Notepad++ plugin campaign to UAC-0099 and confirms MATCHBOIL.V2 as the delivered payload on Windows systems.

<br/>
---
<br/>

## Monitor Only

- Origin Energy confirmed a data breach affecting 2 million customers, with attackers threatening to publicly leak stolen data — no attack vector or threat actor has been publicly attributed; energy sector security and privacy teams should monitor leak forums for exfiltrated data and assess whether third-party relationships with Origin create downstream exposure. **Source:** Data Breach Confirmed After Australian Energy Giant Origin Is Hacked — [https://www.securityweek.com/data-breach-confirmed-after-australian-energy-giant-origin-is-hacked/](https://www.securityweek.com/data-breach-confirmed-after-australian-energy-giant-origin-is-hacked/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment where the window between disclosure and active exploitation has effectively closed. Clop is already inside PLM systems. Zimbra is being exploited with a technique that defeats the most basic user-awareness training. Both Redis and NodeBB landed with working exploit code on day one of disclosure. The AI-assisted vulnerability discovery angle is operationally significant — not because AI finding bugs is novel, but because adversaries have access to the same tooling and can compress their own research timelines accordingly. The UAC-0099 Notepad++ campaign is a reminder that developer endpoints remain soft targets: elevated privileges, diverse third-party tooling, and far less scrutiny than production servers. With public exploit code already circulating, patch velocity and exposure reduction are the only levers that matter — compensating controls are not adequate substitutes.

<br/>
---
<br/>

## Source Links

- Clop ransomware targets Windchill, FlexPLM in data theft attacks — [https://www.bleepingcomputer.com/news/security/clop-ransomware-targets-windchill-flexplm-in-data-theft-attacks/](https://www.bleepingcomputer.com/news/security/clop-ransomware-targets-windchill-flexplm-in-data-theft-attacks/)

- Kimi K3 Agents Found Redis Zero-Days and Built RCE Exploit, Researchers Say — [https://thehackernews.com/2026/07/kimi-k3-agents-found-redis-zero-days.html](https://thehackernews.com/2026/07/kimi-k3-agents-found-redis-zero-days.html)

- NodeBB Patches Eight AI-Found Flaws Exposing Admin Access and Private Chats — [https://thehackernews.com/2026/07/nodebb-patches-eight-ai-found-flaws.html](https://thehackernews.com/2026/07/nodebb-patches-eight-ai-found-flaws.html)

- Russian Hackers Exploit Zimbra Zero-Day Against US, Ukraine Targets — [https://www.darkreading.com/cyberattacks-data-breaches/russian-hackers-zimbra-zero-day-us-ukraine-targets](https://www.darkreading.com/cyberattacks-data-breaches/russian-hackers-zimbra-zero-day-us-ukraine-targets)

- Data Breach Confirmed After Australian Energy Giant Origin Is Hacked — [https://www.securityweek.com/data-breach-confirmed-after-australian-energy-giant-origin-is-hacked/](https://www.securityweek.com/data-breach-confirmed-after-australian-energy-giant-origin-is-hacked/)

- Fake Notepad++ Plugin Delivers MATCHBOIL.V2 in UAC-0099 Attacks — [https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html](https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
