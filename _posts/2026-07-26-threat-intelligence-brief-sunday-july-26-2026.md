---
layout: post
title: "Threat Intelligence Brief - Sunday, July 26, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-26
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-16723
  - T1566.002
  - T1027
  - T1190
  - T1059
  - T1110
  - T1526
  - FIN11
  - Windows
  - Linux
  - ClickFix
---

## Threat Radar

- **Fastjson CVE-2026-16723 is being actively exploited with no patch available** — any internet-facing Spring Boot application using Fastjson 1.x is at immediate risk of unauthenticated RCE; compensating controls are the only option right now.

- **A public working exploit for GitLab self-managed 18.11.3 dropped July 24** — any authenticated user can execute commands as `git`; the patch has been available since June 10, making unpatched instances indefensible.

- **Cl0p affiliates (FIN11 / Lace Tempest) are actively extorting organizations via internet-exposed PTC Windchill and FlexPLM** — engineering IP and manufacturing data are the target; this group has a proven track record of mass exploitation campaigns.

- **Two concurrent malvertising campaigns are assembling malware directly in browser memory**, bypassing file-based and download controls — one (SourTrade) abuses the Bun runtime; a second targets users of crypto and trading platforms via fake Solana, Luno, and TradingView pages.

- **Insurance and financial services phishing has shifted from credential harvesting to real-time session hijacking** — the detection window between credential theft and account misuse has effectively collapsed.

<br/>
---
<br/>

## Immediate Action Required

- **Fastjson CVE-2026-16723 — No patch exists.** Identify all internet-facing Java applications using Fastjson 1.x. Apply WAF rules to block malicious JSON deserialization payloads, restrict external access where possible, and escalate to application owners for emergency review. `CVE-2026-16723 · T1190 · Fastjson · Spring Boot · JVM`

- **GitLab self-managed 18.11.3 — Public exploit is live.** Confirm all self-managed GitLab instances are running the June 10 patch. If any remain unpatched, treat as actively compromised: restrict push access, audit recent repository activity, and patch immediately. `T1190 · T1059 · GitLab · Linux`

- **PTC Windchill / FlexPLM — Cl0p affiliate active exploitation.** Audit internet exposure of all PTC PLM systems. If exposed, take offline or place behind authenticated VPN immediately. Engage PTC for available patches or mitigations. Brief executive leadership given extortion risk and potential IP loss. `T1190 · T1526 · Cl0p · FIN11 · Lace Tempest · PTC Windchill · PTC FlexPLM`

<br/>
---
<br/>

## High-Impact Developments

### Fastjson RCE Actively Exploited — No Patch Available (CVE-2026-16723)

- **What happened:** Attackers are actively exploiting a critical unauthenticated RCE vulnerability in Alibaba's Fastjson 1.x library. A crafted JSON request executes arbitrary code with the privileges of the Java process on affected Spring Boot applications. No patch is currently available.

- **Why it matters:** Unauthenticated RCE with confirmed in-the-wild exploitation and no remediation path is as severe as it gets. Organizations cannot patch their way out of this today — compensating controls are the only line of defense while a fix is pending.

- **Who should care:** Application security teams, enterprise IT, and SOC leaders responsible for any Java-based web applications using Fastjson. Vulnerability management leads should prioritize asset discovery immediately.

- **Recommended action:** Inventory all Fastjson 1.x deployments. Apply WAF rules targeting malicious JSON deserialization patterns. Restrict internet exposure of affected applications where operationally feasible. Monitor for anomalous Java process behavior. Track Alibaba's advisory cadence.

- **Confidence:** High — active exploitation confirmed by ThreatBook and Imperva.

- **Search metadata:** `CVE-2026-16723 · T1190 · Fastjson · Spring Boot · Alibaba · Pivotal · JVM`

**Intelligence Context**
- [Fastjson 1.x RCE Vulnerability Targeted in Attacks With No Patched Available — The Hacker News](https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html)
  - Context: ThreatBook and Imperva confirmed active exploitation of CVE-2026-16723, with attackers sending malicious JSON requests to execute code without authentication on Spring Boot applications. No patch is available as of publication.

<br/>
---
<br/>

### GitLab RCE PoC Published — Unpatched Self-Managed Servers at Imminent Risk

- **What happened:** Researchers at depthfirst published a working public exploit on July 24 for a GitLab RCE flaw patched six weeks earlier on June 10. The exploit allows any authenticated user with push access to execute commands as `git` on unpatched self-managed GitLab 18.11.3 instances.

- **Why it matters:** Public exploit availability compresses the exploitation timeline to near-zero. Any unpatched self-managed GitLab instance should be treated as actively targeted. Developer infrastructure compromise can cascade into source code theft, supply chain tampering, and lateral movement.

- **Who should care:** DevOps and platform engineering teams, enterprise IT, and SOC leaders. Security architects should assess blast radius if a GitLab server is compromised.

- **Recommended action:** Verify all self-managed GitLab instances are patched to the version released June 10 or later. For any unpatched instance, restrict access, audit recent activity for anomalous commands, and treat as potentially compromised pending investigation.

- **Confidence:** High — working exploit code is publicly available and confirmed.

- **Search metadata:** `T1190 · T1059 · GitLab · Linux`

**Intelligence Context**
- [Researcher Publishes GitLab RCE PoC Letting Authenticated Users Run Commands as Git — The Hacker News](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)
  - Context: depthfirst published functional exploit code on July 24 targeting the GitLab flaw patched June 10, enabling authenticated users to run arbitrary commands as `git` on unpatched 18.11.3 self-managed servers.

<br/>
---
<br/>

### Cl0p Affiliates Exploit PTC Windchill and FlexPLM for Data Extortion

- **What happened:** Threat actors linked to Cl0p (FIN11 and Lace Tempest) are chaining a pre-authentication information disclosure vulnerability with an RCE flaw in internet-exposed PTC Windchill and FlexPLM deployments. The campaign targets engineering and manufacturing organizations for data theft and extortion.

- **Why it matters:** Cl0p has a documented history of mass exploitation campaigns — MOVEit and GoAnywhere being the clearest precedents — that scale rapidly across industries. PLM systems hold engineering IP, product designs, and supply chain data: high-leverage extortion material. Downstream supply chain partners are also at risk.

- **Who should care:** Executive leadership, security operations, enterprise IT, and supply chain and manufacturing security owners. Any organization in engineering, aerospace, defense, automotive, or industrial manufacturing running PTC products should treat this as a direct threat.

- **Recommended action:** Immediately audit internet exposure of PTC Windchill and FlexPLM instances. Remove direct internet access where possible; place behind authenticated VPN or zero-trust access controls. Contact PTC for available patches and mitigations. Brief executive leadership on extortion risk and confirm incident response playbooks are current.

- **Confidence:** High — active exploitation confirmed with known threat actor attribution.

- **Search metadata:** `T1190 · T1526 · Cl0p · FIN11 · Lace Tempest · PTC Windchill · PTC FlexPLM · PTC`

**Intelligence Context**
- [Cl0p Affiliates Target Internet-Exposed PTC Windchill and FlexPLM with Unauthenticated RCE — The Hacker News](https://thehackernews.com/2026/07/cl0p-affiliates-target-internet-exposed.html)
  - Context: Cl0p-linked actors (FIN11, Lace Tempest) are chaining pre-authentication information disclosure with RCE against internet-exposed PTC Windchill and FlexPLM as part of an active data extortion campaign targeting engineering and manufacturing sectors.

<br/>
---
<br/>

### Browser-Based In-Memory Malware Assembly Bypasses File-Based Controls

- **What happened:** Two concurrent malvertising campaigns use JavaScript to assemble malware directly in browser memory, writing no complete malicious file to disk. The SourTrade campaign abuses the legitimate Bun JavaScript runtime to reconstruct Windows executables from fragmented pieces. A separate campaign serves fake Solana, Luno, and TradingView pages to deliver malware assembled entirely in memory.

- **Why it matters:** Both techniques are built to defeat file-based AV, download scanning, and hash-based detection. Endpoint controls that inspect files at rest or in transit will not catch this. Users visiting convincing imitations of legitimate crypto and trading sites are exposed with no obvious warning.

- **Who should care:** Enterprise IT and SOC leaders responsible for endpoint protection strategy. Security architects evaluating current browser and endpoint control coverage. Any organization with staff active on crypto or financial trading platforms.

- **Recommended action:** Review endpoint protection coverage for in-memory execution and behavioral detection. Assess whether browser isolation or DNS-layer controls reduce exposure. Determine whether Bun runtime usage in the enterprise is expected or anomalous. Raise user awareness around unsolicited crypto and trading platform prompts.

- **Confidence:** High — active campaigns confirmed by Confiant and Bleeping Computer reporting.

- **Search metadata:** `T1566.002 · T1027 · SourTrade · Bun · Windows · malvertising`

**Intelligence Context**
- [Malvertising Sends Malware in Pieces, Then Makes the Browser Build the Executable — The Hacker News](https://thehackernews.com/2026/07/malvertising-sends-malware-in-pieces.html)
  - Context: Confiant detailed the SourTrade campaign, which uses the legitimate Bun runtime to have victims' browsers reconstruct Windows executables from fragmented malware pieces, evading file-based detection.

- [Malicious sites use JavaScript to build malware in browser memory — Bleeping Computer](https://www.bleepingcomputer.com/news/security/malicious-sites-use-javascript-to-build-malware-in-browser-memory/)
  - Context: A separate large-scale malvertising campaign uses fake Solana, Luno, and TradingView pages with malicious JavaScript to instruct browsers to assemble malware directly in memory, targeting crypto and trading audiences.

<br/>
---
<br/>

## Monitor Only

- Insurance and financial services phishing has evolved from delayed credential harvesting to real-time session hijacking, eliminating the detection window between credential theft and account compromise — relevant to any organization in financial services or insurance reviewing phishing defenses and MFA posture. **Source:** [CTM360 Research Reveals How Insurance Phishing Has Evolved Into Real-Time Account Hijacking — The Hacker News](https://thehackernews.com/2026/07/ctm360-research-reveals-how-insurance.html)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment where the exploitation-to-impact timeline is compressing across every category. The Fastjson situation is the most uncomfortable: active exploitation with no patch forces a purely defensive posture relying on controls that may not be tuned for this specific attack pattern. The GitLab PoC is a reminder that six weeks is too long to leave developer infrastructure unpatched — public exploit code turns a known vulnerability into a commodity attack. The Cl0p PTC campaign follows the group's established mass-exploitation playbook; if your organization runs internet-exposed PTC products, assume active scanning is already underway. The browser-in-memory malware trend warrants structural attention: as file-based detection matures, adversaries are moving the assembly point to where defenders have less visibility. Organizations without behavioral endpoint detection and browser isolation are increasingly exposed to this class of technique.

<br/>
---
<br/>

## Source Links

- Fastjson 1.x RCE Vulnerability Targeted in Attacks With No Patched Available — The Hacker News — [https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html](https://thehackernews.com/2026/07/fastjson-1x-rce-vulnerability-targeted.html)

- Cl0p Affiliates Target Internet-Exposed PTC Windchill and FlexPLM with Unauthenticated RCE — The Hacker News — [https://thehackernews.com/2026/07/cl0p-affiliates-target-internet-exposed.html](https://thehackernews.com/2026/07/cl0p-affiliates-target-internet-exposed.html)

- Researcher Publishes GitLab RCE PoC Letting Authenticated Users Run Commands as Git — The Hacker News — [https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)

- CTM360 Research Reveals How Insurance Phishing Has Evolved Into Real-Time Account Hijacking — The Hacker News — [https://thehackernews.com/2026/07/ctm360-research-reveals-how-insurance.html](https://thehackernews.com/2026/07/ctm360-research-reveals-how-insurance.html)

- Malvertising Sends Malware in Pieces, Then Makes the Browser Build the Executable — The Hacker News — [https://thehackernews.com/2026/07/malvertising-sends-malware-in-pieces.html](https://thehackernews.com/2026/07/malvertising-sends-malware-in-pieces.html)

- Malicious sites use JavaScript to build malware in browser memory — Bleeping Computer — [https://www.bleepingcomputer.com/news/security/malicious-sites-use-javascript-to-build-malware-in-browser-memory/](https://www.bleepingcomputer.com/news/security/malicious-sites-use-javascript-to-build-malware-in-browser-memory/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
