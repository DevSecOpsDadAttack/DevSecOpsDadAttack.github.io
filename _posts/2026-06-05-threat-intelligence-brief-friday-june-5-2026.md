---
layout: post
title: "Threat Intelligence Brief - Friday, June 5, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-06-05
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-3300
  - CVE-2026-20245
  - T1190
  - T1584
  - T1595
  - T1595.002
  - T1078
  - T1059
  - T1204
  - T1566
  - T1566.001
---

## Executive Signal

- **Cisco Catalyst SD-WAN Manager has an unpatched zero-day (CVE-2026-20245) under active exploitation** — root privilege escalation confirmed, no patch available. Network teams must act on mitigations now.
- **A critical RCE flaw in the Everest Forms Pro WordPress plugin (CVE-2026-3300, CVSS 9.8) is under active exploitation**, enabling full site takeover. Treat any installation as compromised until updated or removed.
- **Five Eyes agencies have formally warned** that Chinese intelligence operatives are running active social engineering campaigns against government and military personnel via fake recruiter personas on professional platforms.
- **Threat actor PCPJack has hijacked 230+ cloud servers across AWS, Azure, and Google Cloud**, converting them into a covert SMTP relay botnet — indicating weak cloud access hygiene across multiple organizations.
- **Google Chrome 149 patches 429 vulnerabilities**, over 100 rated critical or high. Volume warrants accelerated enterprise rollout this week.
- **ShinyHunters leaked 234 GB of DentaQuest data** affecting 2.6 million individuals — healthcare organizations should assess third-party dental benefits administrator exposure and prepare for downstream regulatory scrutiny.

---

## Immediate Action Required

**1. Cisco Catalyst SD-WAN Manager — CVE-2026-20245 (Zero-Day, Active Exploitation)**
Apply Cisco's recommended mitigations immediately. No patch is available. Isolate or restrict access to SD-WAN Manager interfaces until a fix is released. Treat any internet-exposed instance as potentially compromised.

**2. Everest Forms Pro WordPress Plugin — CVE-2026-3300 (Active Exploitation, CVSS 9.8)**
Update or remove the Everest Forms Pro plugin immediately across all managed WordPress environments. Active exploitation is confirmed and leads to full site compromise. Audit hosting environments for unauthorized code execution or webshell deployment.

---

## High-Impact Developments

### Cisco SD-WAN Zero-Day Actively Exploited — No Patch Available
- **What happened:** Cisco disclosed CVE-2026-20245, a zero-day in Catalyst SD-WAN Manager enabling root privilege escalation. Exploitation is confirmed in the wild. No patch is currently available.
- **Why it matters:** Root-level access to SD-WAN Manager gives attackers control over network routing, segmentation, and lateral movement across enterprise WAN infrastructure — a critical chokepoint in enterprise and telecom environments.
- **Who should care:** Network operations, security operations, enterprise and telecom CISOs, and any organization running Cisco Catalyst SD-WAN.
- **Recommended action:** Apply Cisco's interim mitigations immediately. Restrict management plane access. Review logs for anomalous privilege escalation activity. Track Cisco's advisory for patch availability.
- **Confidence:** High — vendor-confirmed, active exploitation reported.
- **Search metadata:** CVE-2026-20245, T1190, T1068, Cisco, Catalyst SD-WAN Manager, Zero-Day Exploitation, Privilege Escalation, Network Device Compromise, Enterprise, Telecommunications

---

### Everest Forms Pro WordPress Plugin — Critical RCE Under Active Exploitation
- **What happened:** CVE-2026-3300 (CVSS 9.8), a remote code execution vulnerability in the Everest Forms Pro WordPress plugin, is being actively exploited to achieve complete site takeover. Approximately 4,000 active installations are at risk.
- **Why it matters:** Full site compromise via a plugin flaw exposes customer data, enables malware hosting, and can pivot into broader hosting infrastructure. Active exploitation at a 9.8 CVSS makes this a drop-everything item for web teams.
- **Who should care:** Application owners, web hosting teams, IT, and security operations managing WordPress environments.
- **Recommended action:** Update or remove Everest Forms Pro immediately. Audit affected sites for unauthorized file modifications or new admin accounts.
- **Confidence:** High — active exploitation confirmed.
- **Search metadata:** CVE-2026-3300, T1190, T1059, T1204, Everest Forms Pro, WordPress, Remote Code Execution, Website Compromise, Plugin Vulnerability

---

### PCPJack Cloud Server Hijacking — Covert SMTP Botnet Across Major Providers
- **What happened:** Threat actor PCPJack has compromised over 230 business cloud servers on AWS, Google Cloud, and Azure, repurposing them as SMTP relay proxies to support covert email operations.
- **Why it matters:** Organizations whose servers are part of this botnet face reputational damage, email domain blacklisting, potential regulatory exposure, and evidence of access control failures. Cross-provider scope points to credential compromise or misconfiguration at scale.
- **Who should care:** Cloud operations, security operations, email security teams, and any organization with significant cloud server footprints.
- **Recommended action:** Audit cloud server inventories for unexpected SMTP activity or outbound relay behavior. Review IAM configurations and access logs for unauthorized access. Enforce least-privilege access and MFA on cloud management consoles.
- **Confidence:** High — active campaign confirmed.
- **Search metadata:** T1078, T1583, T1583.001, PCPJack, AWS, Azure, Google Cloud, Botnet, Server Hijacking, Unauthorized Access, Cloud Provider User

---

### Five Eyes Advisory — Chinese Intelligence Targeting Personnel via Fake Job Offers
- **What happened:** Five Eyes intelligence agencies jointly warned that Chinese intelligence officers are posing as recruiters on professional networking platforms to target government and military personnel with access to classified or privileged information.
- **Why it matters:** This is a confirmed, state-sponsored social engineering campaign designed to elicit sensitive information or establish long-term access to cleared personnel. The threat extends to private sector organizations with government contracts or dual-use technology.
- **Who should care:** Government agencies, defense contractors, organizations with cleared personnel, HR, and executive leadership.
- **Recommended action:** Brief employees — particularly those with security clearances or privileged access — on this specific tactic. Reinforce policies on unsolicited recruiter contact and information sharing on professional platforms. Establish clear HR reporting mechanisms.
- **Confidence:** High — Five Eyes joint advisory.
- **Search metadata:** T1595, T1595.002, T1078, T1566, T1566.001, Five Eyes, Chinese Intelligence, Espionage, Phishing, Social Engineering, Government, Military

---

## Monitor Only

- **ShinyHunters / DentaQuest breach:** 234 GB of healthcare data affecting 2.6 million individuals has been publicly leaked. Healthcare organizations and their benefits administrators should assess third-party exposure. Regulatory and legal teams should monitor for HIPAA implications and fraud activity targeting affected individuals.
- **Google Chrome 149 — 429 vulnerabilities patched:** Over 100 critical/high-severity flaws including use-after-free and input validation issues. No confirmed active exploitation reported at this time. Prioritize enterprise deployment this week through standard patch management.

---

## Analyst Observation

The most dangerous items in this brief are the ones without patches. The Cisco SD-WAN zero-day is the highest-priority item — root access to network management infrastructure with no fix available is a worst-case scenario for enterprise defenders, and the window between disclosure and widespread exploitation is closing. The WordPress plugin exploitation is a recurring reminder that web application attack surface is routinely underinventoried and under-monitored. The PCPJack cloud botnet warrants more attention than it typically receives: 230+ hijacked cloud servers is not a small operation, and the organizations whose infrastructure was abused likely had no visibility into it. Cloud access hygiene — credential management, MFA enforcement, anomalous outbound traffic monitoring — remains a persistent gap that threat actors are reliably exploiting.

---

## Source Links

- Cisco warns of unpatched SD-WAN zero-day exploited in attacks — [https://www.bleepingcomputer.com/news/security/new-cisco-sd-wan-flaw-exploited-in-zero-day-attacks-to-gain-root/](https://www.bleepingcomputer.com/news/security/new-cisco-sd-wan-flaw-exploited-in-zero-day-attacks-to-gain-root/)
- Hackers Exploit Critical Everest Forms Pro WordPress Plugin Flaw to Take Over Sites — [https://thehackernews.com/2026/06/hackers-exploit-critical-everest-forms.html](https://thehackernews.com/2026/06/hackers-exploit-critical-everest-forms.html)
- PCPJack Hijacks 230 AWS, Google Cloud, and Azure Servers for Covert SMTP Relay Network — [https://thehackernews.com/2026/06/pcpjack-hijacks-230-aws-google-cloud.html](https://thehackernews.com/2026/06/pcpjack-hijacks-230-aws-google-cloud.html)
- Five Eyes: Chinese Spies Target Government, Military Staff With Fake Job Opportunities — [https://www.securityweek.com/five-eyes-chinese-spies-target-government-military-staff-with-fake-job-opportunities/](https://www.securityweek.com/five-eyes-chinese-spies-target-government-military-staff-with-fake-job-opportunities/)
- Hackers Leak DentaQuest Information Impacting 2.6 Million — [https://www.securityweek.com/hackers-leak-dentaquest-information-impacting-2-6-million/](https://www.securityweek.com/hackers-leak-dentaquest-information-impacting-2-6-million/)
- Chrome 149 Patches 429 Vulnerabilities — [https://www.securityweek.com/chrome-149-patches-429-vulnerabilities/](https://www.securityweek.com/chrome-149-patches-429-vulnerabilities/)

---

_Generated by DevSecOpsDadAttack cyber threat intelligence._
