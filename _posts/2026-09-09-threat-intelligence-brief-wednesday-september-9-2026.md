---
layout: post
title: "Threat Intelligence Brief - Wednesday, September 9, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-09
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1548
  - T1190
  - T1078
  - T1566.002
  - T1598
  - T1592
  - Ivanti
  - Ivanti-Neurons-for-ITSM
  - Ivanti-Sentry
  - Ivanti-EPMM
  - Microsoft
---

## Threat Radar

- **Chrome zero-day #7 of 2026 is actively exploited** — Google Chrome 153 patches a confirmed in-the-wild vulnerability across Windows, macOS, and Linux; enterprise browser fleets require immediate forced updates.

- **ICS Patch Tuesday hits four major OT vendors simultaneously** — Schneider Electric, Siemens, AVEVA, and Rockwell Automation all released critical patches; deferred patching compounds exposure across OT/ICS environments.

- **Ivanti releases critical fixes across three enterprise products** — Six RCE-class vulnerabilities in Neurons for ITSM and authentication bypass flaws in Sentry and EPMM are high-value targets given Ivanti's history of rapid post-disclosure weaponization.

- **Novel phishing technique actively bypasses static controls** — Attackers are abusing trusted Microsoft services and browser blob URLs to render phishing pages client-side, rendering URL-based blocking and reputation filtering ineffective.

- **36,000+ Plex Media Servers remain unpatched and internet-exposed** — Active exploitation is confirmed; any reachable, unpatched Plex instance is a live attack surface and potential lateral movement entry point.

- **Alby Hub critical flaw enables Bitcoin wallet takeover** — Internet-exposed self-hosted Lightning wallets are vulnerable to full account takeover and fund theft; immediate isolation or patch application is required.

<br/>
---
<br/>

## Immediate Action Required

- **Update Google Chrome to version 153 now** — Actively exploited zero-day (seventh of 2026) affects all major desktop platforms. Push forced updates via endpoint management; do not rely on user self-update cycles.

- **Audit and patch Ivanti Neurons for ITSM, Sentry, and EPMM** — Six critical RCE vulnerabilities and authentication bypass flaws in widely deployed enterprise tooling. Ivanti products have been weaponized rapidly after prior disclosures; treat as high-urgency regardless of confirmed exploitation status.

- **Isolate or patch any internet-exposed Alby Hub instances** — If your organization runs self-hosted Lightning wallets reachable from the internet, remove that exposure immediately and apply available patches. Direct financial loss is the risk.

- **Inventory and patch internet-facing Plex Media Servers** — Active exploitation is confirmed against 36,000+ exposed instances. Identify any Plex deployments in your environment, validate patch status, and remove unnecessary internet exposure.

<br/>
---
<br/>

## High-Impact Developments

### Chrome 153: Seventh Actively Exploited Zero-Day of 2026

- **What happened:** Google released Chrome 153 with 230 security fixes, including a patch for a zero-day confirmed to be actively exploited in the wild. This is the seventh Chrome zero-day patched in 2026.

- **Why it matters:** Chrome is the dominant enterprise browser. Active exploitation means threat actors already have working attack code. Seven zero-days in under nine months signals sustained, high-capability targeting of the browser attack surface.

- **Who should care:** Security leadership, endpoint management teams, IT operations.

- **Recommended action:** Force-push Chrome 153 to all managed endpoints immediately. Validate update compliance within 24 hours. Do not rely on auto-update cadence for actively exploited vulnerabilities.

- **Confidence:** High — confirmed active exploitation per vendor advisory.

- **Search metadata:** Google Chrome, Windows, macOS, Linux, zero-day.

**Intelligence Context**
- [Chrome 153 Patches Seventh Zero-Day of 2026 — SecurityWeek](https://www.securityweek.com/chrome-153-patches-seventh-zero-day-of-2026/) — Context: Google confirmed active exploitation and released Chrome 153 with 230 fixes; immediate update is the vendor-recommended action.

<br/>
---
<br/>

### ICS Patch Tuesday: Critical Flaws Across Schneider Electric, Siemens, AVEVA, and Rockwell Automation

- **What happened:** All four major ICS vendors released critical patches simultaneously as part of ICS Patch Tuesday. Exploitation status is currently unknown, but the vulnerabilities affect industrial control system products with direct ties to operational continuity and safety systems.

- **Why it matters:** Critical flaws in OT/ICS environments carry consequences beyond data loss — production downtime, safety system compromise, and physical process disruption are realistic outcomes. Simultaneous multi-vendor patching creates acute prioritization pressure for OT security teams.

- **Who should care:** Security leadership, OT/ICS operations teams, infrastructure owners, plant managers.

- **Recommended action:** Identify affected product versions across all four vendors. Engage OT operations teams to schedule patching within maintenance windows this week. Where immediate patching is not possible, validate network segmentation and monitoring coverage on affected systems.

- **Confidence:** High — vendor-confirmed critical vulnerabilities; exploitation status unknown.

- **Search metadata:** Schneider Electric, Siemens, AVEVA, Rockwell Automation, ICS, critical vulnerability.

**Intelligence Context**
- [ICS Patch Tuesday: Schneider Electric, Siemens Fix Critical Flaws — SecurityWeek](https://www.securityweek.com/ics-patch-tuesday-schneider-electric-siemens-fix-critical-flaws/) — Context: SecurityWeek reports simultaneous critical patch releases from all four major ICS vendors, with AVEVA and Rockwell Automation included alongside Schneider Electric and Siemens.

<br/>
---
<br/>

### Ivanti Critical RCE and Authentication Bypass Across Neurons for ITSM, Sentry, and EPMM

- **What happened:** Ivanti patched six critical vulnerabilities in Neurons for ITSM enabling remote code execution, along with authentication bypass flaws in Sentry and EPMM. Exploitation is not yet confirmed, but Ivanti products have a documented history of rapid post-disclosure weaponization.

- **Why it matters:** Ivanti products sit at sensitive junctions in enterprise environments — ITSM platforms, mobile device management, and network access control. RCE and authentication bypass in these products can enable full system takeover and serve as pivot points into broader infrastructure. Relevant attack paths: T1190 (Exploit Public-Facing Application) and T1078 (Valid Accounts).

- **Who should care:** Security leadership, IT operations, identity and access management teams.

- **Recommended action:** Apply all available Ivanti patches this week. Prioritize Neurons for ITSM given the six critical RCE vulnerabilities. Review Sentry and EPMM authentication logs for anomalies predating the patch release. Confirm these products are not unnecessarily internet-exposed.

- **Confidence:** High — vendor-confirmed critical vulnerabilities; exploitation unconfirmed but historical pattern warrants urgency.

- **Search metadata:** Ivanti Neurons for ITSM, Ivanti Sentry, Ivanti EPMM, T1190, T1078, remote code execution, authentication bypass.

**Intelligence Context**
- [Ivanti Patches Critical Flaws Across Enterprise Security Products — SecurityWeek](https://www.securityweek.com/ivanti-patches-critical-flaws-across-enterprise-security-products/) — Context: SecurityWeek details six critical RCE vulnerabilities in Neurons for ITSM and authentication bypass flaws in Sentry and EPMM, with vendor guidance to apply patches immediately.

<br/>
---
<br/>

### Novel Browser-Based Phishing Abuses Microsoft Services and Blob URLs to Evade Detection

- **What happened:** Attackers are actively using trusted Microsoft services combined with browser blob URLs to generate phishing pages entirely within the victim's browser. Malicious content is rendered client-side and originates from a trusted domain, leaving no static URL to block and no reputation score to flag.

- **Why it matters:** This technique directly undermines URL-based filtering, web proxies, and email link scanning — controls most organizations treat as primary phishing defenses. Active exploitation is confirmed. Attack paths: T1566.002 (Spearphishing Link) and T1598 (Phishing for Information).

- **Who should care:** Security leadership, SOC teams, email security teams, identity and access management teams.

- **Recommended action:** Brief SOC analysts on this technique so they understand why blob URL-based phishing may not generate alerts from existing controls. Reinforce MFA across all user accounts as a compensating control. Increase user awareness messaging around unexpected credential prompts, including those appearing on trusted-looking pages. Assess whether browser isolation capabilities are available and applicable in your environment.

- **Confidence:** High — active exploitation confirmed.

- **Search metadata:** Microsoft services, blob URLs, T1566.002, T1598, phishing, social engineering.

**Intelligence Context**
- [New Phishing Attack Creates Malicious Pages Inside the Victim's Browser — SecurityWeek](https://www.securityweek.com/new-phishing-attack-creates-malicious-pages-inside-the-victims-browser/) — Context: SecurityWeek reports attackers are actively using trusted Microsoft services and blob URLs to render phishing pages client-side, leaving defenders without a static site to block or detect.

<br/>
---
<br/>

## Monitor Only

- **Over 36,000 Plex Media Servers remain internet-exposed and unpatched against actively exploited vulnerabilities; audit for any Plex deployments in your environment and apply patches immediately.** **Source:** Over 36,000 exposed Plex servers vulnerable to recent flaws — [https://www.bleepingcomputer.com/news/security/over-36-000-plex-servers-unpatched-against-recently-disclosed-flaws/](https://www.bleepingcomputer.com/news/security/over-36-000-plex-servers-unpatched-against-recently-disclosed-flaws/)

- **Alby Hub's critical flaw enabling Bitcoin Lightning wallet takeover is relevant to any organization running self-hosted, internet-exposed Alby Hub instances; immediate internet isolation is the primary mitigation.** **Source:** Alby Hub Critical Flaw Could Let Attackers Take Over Internet-Exposed Bitcoin Wallets — [https://thehackernews.com/2026/09/alby-hub-critical-flaw-could-let.html](https://thehackernews.com/2026/09/alby-hub-critical-flaw-could-let.html)

<br/>
---
<br/>

## Analyst Observation

This cycle is patch-heavy with real operational weight behind it. The Chrome zero-day cadence — seven in nine months — is no longer a curiosity; it is sustained pressure against the browser layer that most enterprises have not structurally addressed beyond auto-update policies. Ivanti warrants particular attention not because exploitation is confirmed today, but because the window between Ivanti patch release and weaponization has historically been measured in days. The blob URL phishing technique is the most strategically significant item for defenders: it is active, and it invalidates a control layer most security programs treat as reliable. SOC teams need to understand this gap exists before they are asked to explain why an alert never fired. The ICS Patch Tuesday volume across four vendors simultaneously is operationally demanding for OT teams who cannot patch on IT timelines; prioritization conversations with operations leadership should happen today.

<br/>
---
<br/>

## Source Links

- Chrome 153 Patches Seventh Zero-Day of 2026 — [https://www.securityweek.com/chrome-153-patches-seventh-zero-day-of-2026/](https://www.securityweek.com/chrome-153-patches-seventh-zero-day-of-2026/)

- ICS Patch Tuesday: Schneider Electric, Siemens Fix Critical Flaws — [https://www.securityweek.com/ics-patch-tuesday-schneider-electric-siemens-fix-critical-flaws/](https://www.securityweek.com/ics-patch-tuesday-schneider-electric-siemens-fix-critical-flaws/)

- Alby Hub Critical Flaw Could Let Attackers Take Over Internet-Exposed Bitcoin Wallets — [https://thehackernews.com/2026/09/alby-hub-critical-flaw-could-let.html](https://thehackernews.com/2026/09/alby-hub-critical-flaw-could-let.html)

- Ivanti Patches Critical Flaws Across Enterprise Security Products — [https://www.securityweek.com/ivanti-patches-critical-flaws-across-enterprise-security-products/](https://www.securityweek.com/ivanti-patches-critical-flaws-across-enterprise-security-products/)

- New Phishing Attack Creates Malicious Pages Inside the Victim's Browser — [https://www.securityweek.com/new-phishing-attack-creates-malicious-pages-inside-the-victims-browser/](https://www.securityweek.com/new-phishing-attack-creates-malicious-pages-inside-the-victims-browser/)

- Over 36,000 exposed Plex servers vulnerable to recent flaws — [https://www.bleepingcomputer.com/news/security/over-36-000-plex-servers-unpatched-against-recently-disclosed-flaws/](https://www.bleepingcomputer.com/news/security/over-36-000-plex-servers-unpatched-against-recently-disclosed-flaws/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
