---
layout: post
title: "Threat Intelligence Brief - Wednesday, October 28, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-10-28
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-104351
  - CVE-2026-101767
  - T1190
  - T1499
  - T1566.002
  - T1110
  - T1059
  - Adobe-Campaign-Classic
  - code-execution
  - privilege-escalation
  - Adobe
---

## Threat Radar

- **CISA KEV confirmed:** The Brotli library vulnerability (Node2Shell/HTTP2Shell) is under active exploitation — honeypots are logging real attack attempts, not just proof-of-concept activity.

- **Oracle EBS under active probing:** CVE-2026-101767, an unauthenticated SQL injection enabling remote code execution, is being actively scanned. Exploitation typically follows probing within days.

- **Device code phishing campaign live against U.S. organizations:** Skyw4lker abuses legitimate cloud authentication flows, producing fewer detection signals than traditional credential theft — identity teams need to review conditional access and device code flow restrictions now.

- **Adobe Campaign Classic carries a CVSS 9.9 flaw:** Eight critical vulnerabilities patched this week, including CVE-2026-104351. Exploitation status is unknown, but severity and attack surface make this a priority patch cycle item.

- **EPICS Base flaws patched in research facility control software:** Four long-hidden denial-of-service vulnerabilities affect particle accelerators and fusion labs. No active exploitation reported, but process crashes in these environments carry severe operational consequences.

<br/>
---
<br/>

## Immediate Action Required

- **Brotli (Node2Shell) — Patch immediately.** CISA KEV listing plus confirmed honeypot hits means exploitation is active and iterating. Identify all services and applications using Brotli and apply available patches without delay. Treat any unpatched internet-facing Brotli deployment as compromised until verified. *(T1190)*

- **Oracle EBS (CVE-2026-101767) — Patch or isolate immediately.** Unauthenticated SQL injection with RCE capability is being actively probed. ERP systems are high-value targets; a successful compromise risks financial data, operational continuity, and supply chain integrity. Confirm patch status with ERP owners and finance operations today. *(CVE-2026-101767, T1190, T1059)*

- **Skyw4lker device code phishing — Restrict device code authentication flows now.** Determine whether device code OAuth flows are operationally required and disable where they are not. Audit recent device code authentication events for anomalies. Confirm MFA enforcement and tune conditional access policies to flag unusual authentication patterns. *(T1566.002, T1110)*

<br/>
---
<br/>

## High-Impact Developments

### Node2Shell Brotli Vulnerability Actively Exploited — CISA KEV Confirmed

- **What happened:** CISA added the critical Brotli vulnerability — tracked as Node2Shell, Broccoli2Shell, and HTTP2Shell — to the Known Exploited Vulnerabilities catalog. Two independent honeypot operators confirmed real-world exploitation attempts, including at least one using a broken but functional exploit variant, indicating attackers are actively iterating.

- **Why it matters:** Brotli is a widely deployed compression library embedded in web servers, CDNs, and application stacks. Active exploitation of a library-level vulnerability can affect a broad and often poorly inventoried attack surface. The broken exploit variant observed in honeypots signals early-stage exploitation that will mature quickly.

- **Who should care:** IT, security operations, application owners, platform engineering, and anyone responsible for internet-facing services or software supply chain inventory.

- **Recommended action:** Immediately identify all Brotli deployments across your environment, including indirect dependencies. Apply vendor patches. Prioritize internet-facing services. Escalate to leadership if patch timelines exceed 24–48 hours.

- **Confidence:** High — CISA KEV listing and independent honeypot corroboration.

- **Search metadata:** Brotli, Node2Shell, HTTP2Shell, Broccoli2Shell, T1190, CISA KEV, active exploitation

**Intelligence Context**
- [CISA warns of hackers now exploiting critical Node2Shell flaw](https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-now-exploiting-critical-node2shell-flaw/) — Bleeping Computer
  - Context: CISA's official confirmation of active exploitation, establishing the KEV listing and the urgency baseline for this vulnerability.

- [CISA Warns of Node2Shell Exploitation as Honeypots Log Attack Attempts](https://www.securityweek.com/cisa-warns-of-node2shell-exploitation-as-honeypots-log-attack-attempts/) — SecurityWeek
  - Context: Provides honeypot operator corroboration of real-world attack attempts, including observation of a broken exploit variant, confirming active adversary engagement with this vulnerability.

<br/>
---
<br/>

### Oracle EBS SQL Injection Under Active Probing — RCE Risk

- **What happened:** CVE-2026-101767, an unauthenticated SQL injection vulnerability in Oracle E-Business Suite, is under active probing. The flaw is exploitable for remote code execution without authentication, making it a target for opportunistic and targeted attackers alike.

- **Why it matters:** Oracle EBS sits at the core of financial, procurement, and operational workflows for many enterprises. Unauthenticated RCE against an ERP system is a direct path to data theft, financial fraud, and operational disruption. Active probing means the exploitation window is open now.

- **Who should care:** ERP owners, IT, security, and finance operations teams at any organization running Oracle EBS.

- **Recommended action:** Apply Oracle's available patch immediately. If patching cannot be completed within 24 hours, assess whether Oracle EBS can be isolated from internet-facing exposure or access restricted to known IP ranges while remediation proceeds.

- **Confidence:** High — active probing confirmed by SecurityWeek reporting.

- **Search metadata:** CVE-2026-101767, Oracle EBS, Oracle, T1190, T1059, SQL injection, code execution

**Intelligence Context**
- [Hackers Start Probing Fresh Oracle EBS Vulnerability](https://www.securityweek.com/hackers-start-probing-fresh-oracle-ebs-vulnerability/) — SecurityWeek
  - Context: Confirms active probing of CVE-2026-101767 and establishes the unauthenticated SQL injection to RCE attack chain, directly informing the urgency and remediation priority for Oracle EBS operators.

<br/>
---
<br/>

### Skyw4lker Device Code Phishing Campaign Targets American Organizations

- **What happened:** A campaign tracked as Skyw4lker is actively targeting American organizations using device code phishing — a technique that abuses legitimate cloud authentication flows rather than harvesting credentials directly. By exploiting trusted authentication mechanisms, attackers gain access to corporate accounts while generating fewer conventional detection signals.

- **Why it matters:** Device code phishing is effective precisely because it resembles legitimate user behavior to many security controls. Successful account compromise can lead to data access, lateral movement, and downstream business impact. The reduced detection footprint slows post-compromise discovery.

- **Who should care:** Identity and access management teams, SOC analysts, IT, and security leadership at U.S.-based organizations using cloud services with device code authentication enabled.

- **Recommended action:** Audit and restrict device code OAuth flows where not operationally required. Review conditional access policies for anomalous authentication patterns. Reinforce user awareness that legitimate services rarely require device code authentication initiated by unsolicited contact.

- **Confidence:** High — active campaign confirmed.

- **Search metadata:** Skyw4lker, device code phishing, T1566.002, T1110, credential compromise, American organizations

**Intelligence Context**
- [American Organizations Under Attack: Skyw4lker Device Code Phishing Campaign Exposed](https://thehackernews.com/2026/10/american-organizations-under-attack.html) — The Hacker News
  - Context: Details the Skyw4lker campaign's abuse of cloud authentication mechanisms and explains why device code phishing produces fewer detection signals than traditional credential theft, directly informing the identity team response posture.

<br/>
---
<br/>

### Adobe Campaign Classic — Eight Critical Flaws Patched, Including CVSS 9.9

- **What happened:** Adobe released patches for eight critical vulnerabilities in Campaign Classic. The most severe, CVE-2026-104351 (CVSS 9.9), enables arbitrary code execution. Additional flaws support privilege escalation and security feature bypass. Exploitation status is currently unknown.

- **Why it matters:** Campaign Classic is customer-facing infrastructure. Compromise could expose customer data, disrupt marketing operations, and give attackers a foothold into broader enterprise systems. A CVSS 9.9 rating with no known exploitation today does not preclude exploitation once the patch is reverse-engineered.

- **Who should care:** Marketing and customer experience teams, IT, and security — particularly organizations running Campaign Classic in internet-accessible configurations.

- **Recommended action:** Apply Adobe's patches this week. Prioritize if Campaign Classic is internet-facing or handles customer PII. Confirm with marketing and CX teams that the platform is in scope for vulnerability management.

- **Confidence:** High — vendor-confirmed patches with documented CVE severity.

- **Search metadata:** CVE-2026-104351, Adobe Campaign Classic, Adobe, T1190, code execution, privilege escalation, security bypass

**Intelligence Context**
- [Adobe Fixes 8 Critical Campaign Classic Flaws Allowing Code Execution and Security Bypass](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) — The Hacker News
  - Context: Confirms the patch release and documents the vulnerability scope, including the CVSS 9.9 lead CVE and the range of exploit outcomes — code execution, privilege escalation, and security bypass — establishing the remediation priority.

<br/>
---
<br/>

## Monitor Only

- Four denial-of-service vulnerabilities in EPICS Base control software have been patched; no active exploitation reported, but the flaws could allow attackers to crash processes at particle accelerators and fusion labs — relevant to research institutions and national lab operators running EPICS-based OT environments. **Source:** Long-Hidden Flaws Patched in EPICS Research Facility Control Software — [https://www.securityweek.com/long-hidden-flaws-patched-in-epics-research-facility-control-software/](https://www.securityweek.com/long-hidden-flaws-patched-in-epics-research-facility-control-software/)

<br/>
---
<br/>

## Analyst Observation

Three of the five stories in this brief involve active exploitation or active probing — not theoretical risk. The Brotli situation is the clearest example: CISA KEV confirmation plus honeypot-verified attack attempts means the window for orderly patching has already closed for exposed systems. The Oracle EBS probing follows the same trajectory; once scanning begins at scale, exploitation of unpatched instances typically follows within days. Skyw4lker is a reminder that identity remains the softest target in most environments — device code phishing works because organizations haven't restricted authentication flows they don't need. The Adobe and EPICS items are legitimate patch priorities, but they should not compete for the same attention as the three actively exploited items. Triage accordingly.

<br/>
---
<br/>

## Source Links

- CISA warns of hackers now exploiting critical Node2Shell flaw — [https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-now-exploiting-critical-node2shell-flaw/](https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-now-exploiting-critical-node2shell-flaw/)

- CISA Warns of Node2Shell Exploitation as Honeypots Log Attack Attempts — [https://www.securityweek.com/cisa-warns-of-node2shell-exploitation-as-honeypots-log-attack-attempts/](https://www.securityweek.com/cisa-warns-of-node2shell-exploitation-as-honeypots-log-attack-attempts/)

- Hackers Start Probing Fresh Oracle EBS Vulnerability — [https://www.securityweek.com/hackers-start-probing-fresh-oracle-ebs-vulnerability/](https://www.securityweek.com/hackers-start-probing-fresh-oracle-ebs-vulnerability/)

- American Organizations Under Attack: Skyw4lker Device Code Phishing Campaign Exposed — [https://thehackernews.com/2026/10/american-organizations-under-attack.html](https://thehackernews.com/2026/10/american-organizations-under-attack.html)

- Adobe Fixes 8 Critical Campaign Classic Flaws Allowing Code Execution and Security Bypass — [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html)

- Long-Hidden Flaws Patched in EPICS Research Facility Control Software — [https://www.securityweek.com/long-hidden-flaws-patched-in-epics-research-facility-control-software/](https://www.securityweek.com/long-hidden-flaws-patched-in-epics-research-facility-control-software/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
