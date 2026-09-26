---
layout: post
title: "Threat Intelligence Brief - Saturday, September 26, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-26
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1499
  - T1190
  - T1589
  - T1548
  - Microsoft
  - Elementor
  - CSRF
  - WordPress
  - account-takeover
  - Elementor-Website-Builder
  - Cross-site-request-forgery
---

## Threat Radar

- **CISA KEV update:** Active exploitation confirmed for Microsoft SharePoint and MikroTik RouterOS RCE flaws — federal agencies face mandatory patching deadlines; all enterprises should treat this as urgent.

- **Kiteworks zero-day warning:** Kiteworks received credible federal threat intelligence indicating an imminent cyberattack, potentially involving a zero-day. Customers were directed to take servers offline for a multi-hour window — an extraordinary and operationally disruptive precaution.

- **Elementor CSRF enables full WordPress takeover:** A high-severity cross-site request forgery flaw in the Elementor plugin allows unauthenticated attackers to create rogue admin accounts. No active exploitation confirmed yet, but the attack surface is enormous given Elementor's install base.

- **Telecom data theft sentenced:** A U.S. Army soldier received 70 months for stealing call and text metadata from over 100 million AT&T customers and extorting telecom providers — insider and criminal threats to carrier infrastructure remain material.

- **Secure file-sharing platforms remain high-value targets:** The Kiteworks incident follows a pattern of threat actors prioritizing managed file transfer and secure collaboration platforms — cf. MOVEit, Accellion FTA — for large-scale data theft operations.

<br/>
---
<br/>

## Immediate Action Required

- **SharePoint and MikroTik RouterOS — CISA KEV (Active Exploitation):** Validate patch status across all SharePoint Server instances and MikroTik RouterOS deployments immediately. CISA KEV listing confirms in-the-wild exploitation. Federal agencies have binding remediation deadlines; all organizations should treat this equivalently. Prioritize internet-exposed instances. | *T1190, Microsoft SharePoint, MikroTik RouterOS*

- **Kiteworks — Imminent Zero-Day Threat:** If your organization uses Kiteworks for secure file transfer or managed file sharing, confirm whether the vendor-directed shutdown window has passed and assess current patch and configuration status. Contact Kiteworks directly for updated guidance. Review logs for anomalous access during the exposure window. | *Kiteworks, Zero-day, Imminent threat*

- **Elementor WordPress Plugin — CSRF Admin Takeover:** Inventory all WordPress deployments using the Elementor Website Builder plugin and apply available patches this week. Audit admin account lists for unauthorized additions. Reinforce phishing awareness for site administrators — exploitation requires an admin to interact with a crafted link. | *T1548, T1499, Elementor, WordPress, CSRF*

<br/>
---
<br/>

## High-Impact Developments

### CISA KEV: SharePoint RCE and MikroTik RouterOS Actively Exploited

- **What happened:** CISA added remote code execution vulnerabilities in Microsoft SharePoint and MikroTik RouterOS to its Known Exploited Vulnerabilities catalog, citing confirmed in-the-wild exploitation.

- **Why it matters:** A KEV listing is the clearest available signal that exploitation is occurring at scale. SharePoint is pervasive in enterprise environments; MikroTik RouterOS is widely deployed at the network edge and in ISP infrastructure. RCE on either product can give attackers deep network access or lateral movement capability.

- **Who should care:** Security operations, IT operations, infrastructure and network teams, vulnerability management leads, and any organization running on-premises SharePoint or MikroTik routing hardware.

- **Recommended action:** Verify patch status for both products immediately. Prioritize internet-facing SharePoint instances and externally reachable MikroTik devices. Where patching cannot be completed immediately, implement compensating controls and increase monitoring on affected systems.

- **Confidence:** High — CISA KEV listing with confirmed active exploitation.

- **Search metadata:** T1190, Microsoft SharePoint, MikroTik RouterOS, RCE, CISA-KEV

**Intelligence Context**
- [SharePoint RCE and MikroTik RouterOS Flaws Actively Exploited in the Wild](https://thehackernews.com/2026/09/sharepoint-rce-and-mikrotik-routeros.html) — The Hacker News
  - Context: Reports CISA's addition of both vulnerabilities to the KEV catalog with explicit confirmation of active exploitation, establishing the authoritative basis for immediate action.

<br/>
---
<br/>

### Kiteworks Warns Customers of Imminent Zero-Day Cyberattack

- **What happened:** Kiteworks, a secure file-sharing and managed file transfer platform formerly known as Accellion, received credible threat intelligence from federal authorities warning of an imminent cyberattack potentially involving a zero-day vulnerability. The company directed customers worldwide to shut down their servers for a window of six to nine hours as a precautionary measure.

- **Why it matters:** A vendor directing customers to take production systems offline is an extraordinary step — it signals the threat intelligence was assessed as highly credible. Kiteworks serves enterprises, government agencies, and regulated industries that depend on it for sensitive data transfer. Its predecessor, Accellion FTA, was exploited in a major supply chain attack in 2021, and threat actors have demonstrated sustained interest in this product category.

- **Who should care:** Any organization using Kiteworks for secure file sharing, managed file transfer, or regulated data exchange. Security operations, IT operations, and vendor management teams need situational awareness. Legal and compliance teams should assess data exposure risk.

- **Recommended action:** Confirm whether your Kiteworks environment completed the recommended shutdown window. Engage Kiteworks support for current patch status and any indicators of compromise. Review access logs for the period surrounding the threat window. Assess whether sensitive data transiting Kiteworks during this period requires breach notification evaluation.

- **Confidence:** Medium — threat intelligence sourced from federal authorities and treated as credible by the vendor; no confirmed exploitation disclosed at time of reporting.

- **Search metadata:** Kiteworks, Zero-day, Imminent threat

**Intelligence Context**
- [Kiteworks Urges Customers to Shut Down Systems for 9 Hours Over Possible Cyber Attack](https://thehackernews.com/2026/09/kiteworks-urges-customers-to-shut-down.html) — The Hacker News
  - Context: Reports Kiteworks receiving credible federal threat intelligence and directing customers to shut down systems for nine hours as a precautionary measure against an imminent attack.

- [Kiteworks urges 6-hour server shutdown over potential zero-day attacks](https://www.bleepingcomputer.com/news/security/kiteworks-urges-6-hour-server-shutdown-over-potential-zero-day-attacks/) — Bleeping Computer
  - Context: Corroborates the shutdown directive and specifically characterizes the threat as a potential zero-day, adding technical context to the nature of the risk Kiteworks communicated to customers.

<br/>
---
<br/>

### Elementor WordPress Plugin CSRF Flaw Enables Admin Account Takeover

- **What happened:** A high-severity cross-site request forgery vulnerability in the Elementor Website Builder plugin for WordPress allows unauthenticated attackers to create rogue administrator accounts and achieve full site takeover. Exploitation requires a site administrator to click a crafted malicious link. No active exploitation has been confirmed at time of reporting.

- **Why it matters:** Elementor is one of the most widely installed WordPress plugins globally, making the attack surface exceptionally broad. Full admin account creation gives attackers persistent access — enabling content defacement, malware injection, data exfiltration, or use of the site as an attack staging platform. The social engineering requirement is a low bar given the prevalence of phishing.

- **Who should care:** Website operators, application security teams, IT operations teams managing WordPress infrastructure, and any organization whose web presence depends on WordPress with Elementor installed.

- **Recommended action:** Patch the Elementor plugin immediately across all WordPress deployments. Audit administrator account lists for unauthorized additions. Brief site administrators on the phishing-style delivery mechanism. Verify that WordPress admin accounts use MFA.

- **Confidence:** High — vulnerability details confirmed by two independent sources; exploitation status unconfirmed.

- **Search metadata:** T1499, T1548, Elementor Website Builder, WordPress, CSRF, Account takeover, Privilege escalation

**Intelligence Context**
- [Elementor CSRF Flaw Lets Attackers Take Over Sites After Admin Clicks Crafted Link](https://thehackernews.com/2026/09/elementor-csrf-flaw-lets-attackers-take.html) — The Hacker News
  - Context: Provides technical detail on the CSRF vulnerability, confirming the unauthenticated attack path and the rogue admin account creation capability that enables full site takeover.

- [Elementor WordPress flaw lets attackers create admin accounts](https://www.bleepingcomputer.com/news/security/elementor-wordpress-flaw-lets-attackers-create-admin-accounts/) — Bleeping Computer
  - Context: Independent corroboration of the vulnerability, reinforcing the severity assessment and broadening the reporting basis for organizational awareness and patch prioritization.

<br/>
---
<br/>

## Monitor Only

- A U.S. Army soldier was sentenced to 70 months in federal prison and ordered to pay nearly $300,000 in restitution for hacking AT&T and Verizon, stealing call and text metadata for over 100 million customers in 2024, and conducting extortion — relevant to telecom sector risk awareness, insider threat posture, and privacy exposure assessments. **Source:** U.S. Soldier Gets 70 Months in Prison for AT&T, Verizon Extortions — [https://krebsonsecurity.com/2026/09/u-s-soldier-gets-70-months-in-prison-for-att-verizon-extortions/](https://krebsonsecurity.com/2026/09/u-s-soldier-gets-70-months-in-prison-for-att-verizon-extortions/)

<br/>
---
<br/>

## Analyst Observation

Today's brief is concentrated in widely deployed enterprise infrastructure — SharePoint, network edge devices, and secure file transfer platforms. The Kiteworks situation stands out: a vendor-directed shutdown based on federal threat intelligence is not a routine advisory, and organizations that treated the Accellion FTA compromise as a one-time event should revisit their assumptions about managed file transfer risk. The Elementor flaw is a volume problem — the install base is massive, the exploitation path is straightforward, and the outcome is complete site compromise. Patch it this week; don't wait for active exploitation confirmation. The AT&T/Verizon sentencing is operationally closed, but the scale — 100 million customer records from a single insider — should inform how telecom-dependent organizations assess third-party data exposure and supply chain trust.

<br/>
---
<br/>

## Source Links

- SharePoint RCE and MikroTik RouterOS Flaws Actively Exploited in the Wild — [https://thehackernews.com/2026/09/sharepoint-rce-and-mikrotik-routeros.html](https://thehackernews.com/2026/09/sharepoint-rce-and-mikrotik-routeros.html)

- Kiteworks Urges Customers to Shut Down Systems for 9 Hours Over Possible Cyber Attack — [https://thehackernews.com/2026/09/kiteworks-urges-customers-to-shut-down.html](https://thehackernews.com/2026/09/kiteworks-urges-customers-to-shut-down.html)

- Kiteworks urges 6-hour server shutdown over potential zero-day attacks — [https://www.bleepingcomputer.com/news/security/kiteworks-urges-6-hour-server-shutdown-over-potential-zero-day-attacks/](https://www.bleepingcomputer.com/news/security/kiteworks-urges-6-hour-server-shutdown-over-potential-zero-day-attacks/)

- Elementor CSRF Flaw Lets Attackers Take Over Sites After Admin Clicks Crafted Link — [https://thehackernews.com/2026/09/elementor-csrf-flaw-lets-attackers-take.html](https://thehackernews.com/2026/09/elementor-csrf-flaw-lets-attackers-take.html)

- Elementor WordPress flaw lets attackers create admin accounts — [https://www.bleepingcomputer.com/news/security/elementor-wordpress-flaw-lets-attackers-create-admin-accounts/](https://www.bleepingcomputer.com/news/security/elementor-wordpress-flaw-lets-attackers-create-admin-accounts/)

- U.S. Soldier Gets 70 Months in Prison for AT&T, Verizon Extortions — [https://krebsonsecurity.com/2026/09/u-s-soldier-gets-70-months-in-prison-for-att-verizon-extortions/](https://krebsonsecurity.com/2026/09/u-s-soldier-gets-70-months-in-prison-for-att-verizon-extortions/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
