---
layout: post
title: "Threat Intelligence Brief - Wednesday, September 16, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-16
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-58704
  - CVE-2026-87886
  - T1190
  - T1566
  - T1204
  - Google
  - The-Events-Calendar
  - WordPress
  - RCE
  - Remote-Code-Execution
  - Privilege-Escalation
---

## Threat Radar

- ConnectWise ScreenConnect is under active exploitation for remote code execution — CISA has confirmed in-the-wild attacks, making this the highest-priority item today for any organization using ScreenConnect for remote IT management.

- Google Pixel devices are being targeted through a modem-level privilege escalation flaw (CVE-2026-58704, CVSS 8.0) — limited but confirmed targeted exploitation suggests adversaries with specific victim profiles, raising concern for executives and high-value mobile users.

- Acronis Backup's cPanel/WHM plugin is being actively exploited via CVE-2026-87886 — a local privilege escalation through insecure file permissions that can hand attackers root-level access to hosting environments and customer data.

- Over 200,000 WordPress sites running The Events Calendar plugin are exposed to unauthenticated RCE — exploitation is unconfirmed, but the attack surface is large and the barrier to entry is low.

- Today's threat picture is dominated by privilege escalation and remote code execution across remote management, mobile, hosting, and web infrastructure — three of five stories involve confirmed in-the-wild exploitation.

<br/>
---
<br/>

## Immediate Action Required

- **ConnectWise ScreenConnect** — Patch immediately. CISA-confirmed active exploitation of a critical RCE flaw. Treat any unpatched ScreenConnect instance as potentially compromised. Affected teams: IT, Security, Help Desk, Remote Support Operations.

- **Google Pixel Cellular Modem (CVE-2026-58704)** — Push the available patch via MDM to all managed Pixel devices without delay. Prioritize devices used by executives, legal, finance, or anyone handling sensitive corporate data. Affected teams: MDM, Security, IT.

- **Acronis Backup cPanel/WHM Plugin (CVE-2026-87886)** — Apply the Acronis-issued patch immediately. Audit hosting environments for signs of privilege escalation. Affected teams: IT, Security, Hosting Operations.

- **WordPress Events Calendar Plugin** — Update the plugin this week across all managed WordPress instances. Exploitation is unconfirmed, but the unauthenticated RCE attack surface is significant. Affected teams: IT, Security, Web Operations.

<br/>
---
<br/>

## High-Impact Developments

### ConnectWise ScreenConnect Critical RCE Actively Exploited

- **What happened:** CISA confirmed active in-the-wild exploitation of a critical-severity remote code execution vulnerability in ConnectWise ScreenConnect.

- **Why it matters:** ScreenConnect is a widely deployed remote management and support tool. Successful exploitation gives attackers persistent, privileged access across an enterprise — a high-value target for ransomware operators and espionage actors.

- **Who should care:** IT operations, security teams, help desk, and any team relying on ScreenConnect for remote support or endpoint management.

- **Recommended action:** Patch ScreenConnect immediately. Verify patch status across all instances, including those managed by third-party MSPs. Review recent remote session logs for anomalous activity.

- **Confidence:** High — CISA-confirmed active exploitation.

- **Search metadata:** ScreenConnect, ConnectWise, Remote Code Execution, CISA

**Intelligence Context**
- [Critical ScreenConnect flaw now actively exploited in attacks — Bleeping Computer](https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-exploiting-critical-screenconnect-flaw/)
  - Context: Bleeping Computer reports CISA's direct warning of in-the-wild exploitation of a critical ScreenConnect RCE flaw, confirming active attacker activity rather than theoretical risk.

<br/>
---
<br/>

### Google Pixel Modem Privilege Escalation (CVE-2026-58704) Under Targeted Attack

- **What happened:** Google patched CVE-2026-58704 (CVSS 8.0), a privilege escalation flaw in the Pixel Cellular Modem caused by a logic error enabling permission bypass. Limited targeted exploitation has been confirmed in the wild.

- **Why it matters:** Limited targeted exploitation typically signals adversaries pursuing specific high-value targets — executives, journalists, government officials, or corporate decision-makers. A modem-level flaw is difficult to detect through standard endpoint controls.

- **Who should care:** Mobile device management teams, security operations, and anyone responsible for securing executive or privileged-user devices.

- **Recommended action:** Deploy the available Google patch to all managed Pixel devices via MDM immediately. Identify high-value individuals using unmanaged Pixel devices and communicate the risk directly.

- **Confidence:** High — Google-confirmed exploitation with patch available.

- **Search metadata:** CVE-2026-58704, Pixel Cellular Modem, Google, Privilege Escalation

**Intelligence Context**
- [Google Patches Pixel Modem Flaw Amid Signs of Limited Targeted Exploitation — The Hacker News](https://thehackernews.com/2026/09/google-patches-pixel-modem-flaw-amid.html)
  - Context: The Hacker News details the CVE-2026-58704 logic error in the Pixel modem and confirms Google's disclosure of limited targeted in-the-wild exploitation, with a patch now available.

<br/>
---
<br/>

### Acronis cPanel Backup Plugin Exploited — CVE-2026-87886 Patched

- **What happened:** Acronis disclosed and patched CVE-2026-87886 (CVSS 7.8), a local privilege escalation flaw in its Backup plugin for cPanel and Web Host Manager (WHM), caused by insecure file permissions. Targeted exploitation has been confirmed.

- **Why it matters:** Backup and hosting management software sits at the intersection of privileged access and sensitive data. Exploitation can allow attackers to escalate from a limited foothold to full control of hosting environments, potentially impacting multiple customer tenants.

- **Who should care:** IT, security, and hosting operations teams running Acronis Backup with cPanel or WHM integrations.

- **Recommended action:** Apply the Acronis patch immediately. Audit file permission configurations on affected systems. Review hosting environment logs for signs of unauthorized privilege escalation.

- **Confidence:** High — Vendor-confirmed exploitation with patch issued.

- **Search metadata:** CVE-2026-87886, Acronis Backup, cPanel, Web Host Manager, Privilege Escalation

**Intelligence Context**
- [Acronis cPanel Backup Plugin Vulnerability Exploited in Targeted Attacks — The Hacker News](https://thehackernews.com/2026/09/acronis-cpanel-backup-plugin.html)
  - Context: The Hacker News reports Acronis's own warning of targeted exploitation of CVE-2026-87886, describing the insecure file permissions root cause and the privilege escalation impact.

- [Acronis Patches Exploited Vulnerability in cPanel Backup Plugin — SecurityWeek](https://www.securityweek.com/acronis-patches-exploited-vulnerability-in-cpanel-backup-plugin/)
  - Context: SecurityWeek confirms the patch release and characterizes CVE-2026-87886 as a high-severity insecure file permissions flaw enabling local privilege escalation, corroborating active exploitation.

<br/>
---
<br/>

### Unauthenticated RCE in WordPress Events Calendar Plugin Threatens 200,000+ Sites

- **What happened:** Unauthenticated remote code execution vulnerabilities were disclosed in The Events Calendar WordPress plugin, potentially exposing more than 200,000 sites to full takeover. Exploitation in the wild has not been confirmed.

- **Why it matters:** Unauthenticated RCE requires no credentials or prior access — any internet-facing WordPress site running a vulnerable version is a viable target. At this scale, opportunistic mass exploitation is a realistic near-term scenario once proof-of-concept code circulates.

- **Who should care:** IT, security, and web operations teams managing WordPress deployments, particularly those running The Events Calendar plugin.

- **Recommended action:** Update The Events Calendar plugin across all managed WordPress instances this week. Inventory WordPress plugin versions if not already tracked. Consider WAF rules for high-value sites pending patching.

- **Confidence:** Medium — Vulnerability confirmed; exploitation status unknown.

- **Search metadata:** The Events Calendar, WordPress, Remote Code Execution, T1190, Privilege Escalation

**Intelligence Context**
- [Unauthenticated RCE Flaws Could Expose 200,000+ WordPress Sites to Takeover — SecurityWeek](https://www.securityweek.com/unauthenticated-rce-flaws-could-expose-200000-wordpress-sites-to-takeover/)
  - Context: SecurityWeek reports the disclosure of unauthenticated RCE vulnerabilities in The Events Calendar plugin, estimating over 200,000 potentially exposed WordPress sites with no confirmed exploitation at time of publication.

<br/>
---
<br/>

## Monitor Only

- Premier Medical Group disclosed a June 2026 data breach affecting 280,000 patients, exposing names, contact details, diagnosis information, and health insurance data — use this as a benchmark for reviewing your own unauthorized access controls and breach response procedures. **Source:** 280,000 Impacted by Premier Medical Group Data Breach — SecurityWeek — [https://www.securityweek.com/280000-impacted-by-premier-medical-group-data-breach/](https://www.securityweek.com/280000-impacted-by-premier-medical-group-data-breach/)

<br/>
---
<br/>

## Analyst Observation

Today's brief is operationally dense: three confirmed in-the-wild exploitation events across remote management, mobile, and hosting infrastructure arrived simultaneously. That is not coincidence — it reflects sustained attacker focus on privileged-access tooling and the compounding risk of unpatched environments. ScreenConnect is the most urgent; organizations that use MSPs or third-party IT support must verify their vendors' patch status, not just their own. The Pixel modem exploitation pattern — limited and targeted — warrants a direct conversation with your executive protection or VIP device management program, not a routine MDM push. The WordPress Events Calendar issue is the one to watch over the next 48–72 hours: unauthenticated RCE at this scale attracts rapid weaponization once public disclosure lands.

<br/>
---
<br/>

## Source Links

- Critical ScreenConnect flaw now actively exploited in attacks — Bleeping Computer — [https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-exploiting-critical-screenconnect-flaw/](https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-exploiting-critical-screenconnect-flaw/)

- Google Patches Pixel Modem Flaw Amid Signs of Limited Targeted Exploitation — The Hacker News — [https://thehackernews.com/2026/09/google-patches-pixel-modem-flaw-amid.html](https://thehackernews.com/2026/09/google-patches-pixel-modem-flaw-amid.html)

- Acronis cPanel Backup Plugin Vulnerability Exploited in Targeted Attacks — The Hacker News — [https://thehackernews.com/2026/09/acronis-cpanel-backup-plugin.html](https://thehackernews.com/2026/09/acronis-cpanel-backup-plugin.html)

- Acronis Patches Exploited Vulnerability in cPanel Backup Plugin — SecurityWeek — [https://www.securityweek.com/acronis-patches-exploited-vulnerability-in-cpanel-backup-plugin/](https://www.securityweek.com/acronis-patches-exploited-vulnerability-in-cpanel-backup-plugin/)

- 280,000 Impacted by Premier Medical Group Data Breach — SecurityWeek — [https://www.securityweek.com/280000-impacted-by-premier-medical-group-data-breach/](https://www.securityweek.com/280000-impacted-by-premier-medical-group-data-breach/)

- Unauthenticated RCE Flaws Could Expose 200,000+ WordPress Sites to Takeover — SecurityWeek — [https://www.securityweek.com/unauthenticated-rce-flaws-could-expose-200000-wordpress-sites-to-takeover/](https://www.securityweek.com/unauthenticated-rce-flaws-could-expose-200000-wordpress-sites-to-takeover/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
