---
layout: post
title: "Threat Intelligence Brief - Thursday, August 13, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-08-13
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-59310
  - CVE-2026-55040
  - T1078
  - T1190
  - T1059
  - T1548
  - T1005
  - T1056
  - Fortinet
  - VMware
  - Microsoft
---

## Threat Radar

- Three actively exploited vulnerabilities — VMware vCenter (CVE-2026-59310), Microsoft SharePoint (CVE-2026-55040), and the Windows SYSTEM-level zero-day ShieldBreak — are all confirmed in-the-wild simultaneously, creating a compounding patch burden across infrastructure, endpoint, and collaboration stacks.

- ShieldBreak, publicly released by Nightmare Eclipse on Patch Tuesday, requires no elevated starting privileges. Any authenticated user can obtain a SYSTEM shell, making it immediately weaponizable in post-initial-access scenarios across every Windows enterprise environment.

- CVE-2026-55040 reached active exploitation within hours of public PoC release, compressing the effective patch window to near-zero for any internet-facing or internally accessible SharePoint deployment.

- City-Forum has been quietly exfiltrating data from misconfigured Salesforce Experience Cloud and ServiceNow portals since at least March 2025. Affected organizations may have no indication of exposure.

- Belgium's eID browser extension compromise is a signal event for any organization using browser extension-based authentication: the entire trust chain can be undermined at the extension layer, independent of the underlying identity provider.

<br/>
---
<br/>

## Immediate Action Required

- **VMware vCenter — CVE-2026-59310 (RCE, actively exploited):** Apply available patches immediately. If patching cannot be completed within 24 hours, restrict vCenter management plane access to trusted networks and review logs for indicators of compromise. Full virtualization infrastructure is at risk.

- **Microsoft SharePoint — CVE-2026-55040 (Authentication Bypass, CVSS 9.1, actively exploited):** Apply Microsoft's patch immediately. Confirm whether SharePoint instances are internet-facing. Review access logs for anomalous authentication events. Treat credential and session token exposure as likely in unpatched environments.

- **Windows Zero-Day — ShieldBreak (Privilege Escalation, no CVE assigned, public exploit available):** No patch is available. Prioritize endpoint monitoring for SYSTEM-level shell activity spawned from non-privileged processes. Evaluate compensating controls — application allowlisting, privileged access workstations, EDR coverage — while awaiting a Microsoft fix.

- **Salesforce / ServiceNow — City-Forum Campaign (Active Data Theft):** Audit anonymous and guest access permissions on Salesforce Experience Cloud and ServiceNow portals immediately. Disable anonymous access where not operationally required. If misconfiguration existed since March 2025, initiate a data loss assessment covering that full period.

<br/>
---
<br/>

## High-Impact Developments

### VMware vCenter RCE Under Active Exploitation — CVE-2026-59310

- **What happened:** A critical directory traversal vulnerability in VMware vCenter (CVE-2026-59310) is under active exploitation, enabling unauthenticated remote attackers to execute arbitrary code on affected systems.

- **Why it matters:** vCenter is the management plane for virtualized infrastructure. Compromise gives attackers control over all hosted virtual machines and workloads. Lateral movement to every hosted system is trivial post-exploitation.

- **Who should care:** Infrastructure leads, virtualization teams, SOC, and CISOs with on-premises or hybrid VMware environments.

- **Recommended action:** Emergency patch deployment. Isolate vCenter management interfaces from untrusted networks. Validate patch status across all vCenter instances and review logs for exploitation indicators.

- **Confidence:** High — active exploitation confirmed.

- **Search metadata:** CVE-2026-59310, T1190, T1059, VMware, vCenter, directory-traversal, remote-code-execution

**Intelligence Context**
- [Critical VMware vCenter Vulnerability in Attackers' Crosshairs — SecurityWeek](https://www.securityweek.com/critical-vmware-vcenter-vulnerability-in-attackers-crosshairs/)
  - Context: SecurityWeek confirmed active targeting of CVE-2026-59310, describing the directory traversal mechanism that enables remote code execution on vCenter without authentication.

<br/>
---
<br/>

### Windows Zero-Day 'ShieldBreak' — SYSTEM Privileges for Any User

- **What happened:** Threat actor Nightmare Eclipse publicly released ShieldBreak, a working Windows zero-day exploit that allows any local user to spawn a SYSTEM-level shell. The release was timed to Patch Tuesday, maximizing exposure before a fix is available.

- **Why it matters:** A functional, publicly available SYSTEM-level exploit eliminates the privilege escalation barrier for any attacker who achieves initial access — via phishing, credential theft, or any other vector. This directly accelerates ransomware deployment, credential dumping, and lateral movement.

- **Who should care:** SOC leaders, endpoint security teams, vulnerability management, and any organization running Windows — which is nearly universal.

- **Recommended action:** Confirm EDR coverage and alerting for anomalous SYSTEM shell activity spawned from non-privileged processes. Implement compensating controls while awaiting a patch. Treat every unpatched Windows endpoint as a privilege escalation risk from any authenticated user.

- **Confidence:** High — exploit is publicly available and exploitation is confirmed.

- **Search metadata:** T1548, T1059, Nightmare Eclipse, ShieldBreak, Windows, zero-day, privilege-escalation, Microsoft

**Intelligence Context**
- [Nightmare Eclipse Drops Windows Zero-Day Exploit 'ShieldBreak' — SecurityWeek](https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-shieldbreak/)
  - Context: SecurityWeek reported that Nightmare Eclipse released ShieldBreak on Patch Tuesday, confirming the exploit enables any user to obtain a SYSTEM-level shell on Windows systems.

<br/>
---
<br/>

### Microsoft SharePoint Authentication Bypass — CVE-2026-55040

- **What happened:** Active exploitation of CVE-2026-55040, a critical SharePoint authentication bypass (CVSS 9.1), began immediately after public PoC release. Attackers can bypass authentication controls to access internal SharePoint content and credentials without valid credentials.

- **Why it matters:** SharePoint is a core document and collaboration platform across most Microsoft 365 environments. Authentication bypass enables access to sensitive internal content, credential harvesting, and pivoting into connected systems — no valid credentials required.

- **Who should care:** Security architects, identity and access management teams, collaboration platform owners, and SOC analysts monitoring Microsoft 365 environments.

- **Recommended action:** Apply the Microsoft patch immediately. Audit SharePoint exposure, particularly internet-facing instances. Review authentication logs for access patterns consistent with bypass attempts.

- **Confidence:** High — active exploitation confirmed post-PoC release.

- **Search metadata:** CVE-2026-55040, T1078, Microsoft, SharePoint, authentication-bypass

**Intelligence Context**
- [Attackers Exploit SharePoint Authentication Bypass After Public PoC Release — The Hacker News](https://thehackernews.com/2026/08/attackers-exploit-sharepoint.html)
  - Context: The Hacker News reported that threat actors moved to active exploitation of CVE-2026-55040 immediately after public PoC code became available, confirming the compressed exploitation window.

<br/>
---
<br/>

### City-Forum SaaS Data Theft Campaign — Salesforce and ServiceNow

- **What happened:** City-Forum has been running a persistent data theft campaign since at least March 2025, using custom tooling to systematically exfiltrate data from Salesforce Experience Cloud and ServiceNow portals misconfigured to allow anonymous user access.

- **Why it matters:** This is not opportunistic scanning. It is a targeted, long-running campaign with purpose-built tools operating across multiple sectors. Data exposed through anonymous portal access can include customer records, case data, and internal business information — carrying regulatory, fraud, and reputational consequences.

- **Who should care:** Cloud security teams, SaaS platform owners, data governance leads, legal and compliance, and any organization running customer-facing Salesforce or ServiceNow portals.

- **Recommended action:** Audit anonymous and guest access configurations on Salesforce Experience Cloud and ServiceNow portals immediately. Disable unnecessary anonymous access. Conduct a data exposure assessment covering March 2025 forward. Engage platform vendors if misconfiguration is confirmed.

- **Confidence:** High — campaign activity confirmed across multiple reporting sources.

- **Search metadata:** T1190, T1005, City-Forum, Salesforce Experience Cloud, ServiceNow, data-theft, campaign

**Intelligence Context**
- ["City-Forum" data-theft attacks target Salesforce, ServiceNow portals — Bleeping Computer](https://www.bleepingcomputer.com/news/security/city-forum-data-theft-attacks-target-salesforce-servicenow-portals/)
  - Context: Bleeping Computer detailed the use of custom tooling to extract data from portals exposed to anonymous users, confirming the active and ongoing nature of the campaign.

- [Long-running Data Theft Campaign Targeting Salesforce, ServiceNow — Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/long-running-data-theft-campaign-salesforce-servicenow)
  - Context: Dark Reading established the campaign's timeline — active since at least March 2025 — and confirmed multi-sector targeting, indicating broad organizational exposure.

<br/>
---
<br/>

## Monitor Only

- Belgium's eID browser extension vulnerabilities fully compromised the national electronic identity trust framework, enabling RCE on citizen accounts. Direct enterprise impact is limited, but this is a meaningful signal for any organization using browser extension-based authentication: the extension layer itself is a viable attack surface, independent of the underlying identity provider. **Source:** Belgium's eID Authentication Opens Citizen Accounts to RCE — Dark Reading — [https://www.darkreading.com/application-security/belgium-eid-authentication-citizen-accounts-rce](https://www.darkreading.com/application-security/belgium-eid-authentication-citizen-accounts-rce)

<br/>
---
<br/>

## Analyst Observation

This is a genuinely bad Patch Tuesday cycle. Three high-severity, actively exploited vulnerabilities across VMware vCenter, Windows, and SharePoint landed simultaneously — and one of them, ShieldBreak, has no patch. Security teams are triaging all three at once while a long-running SaaS data theft campaign may have been operating undetected in the background for over a year.

City-Forum is the sleeper story. Organizations that haven't audited anonymous access on Salesforce Experience Cloud and ServiceNow portals should treat that as overdue, not optional. The exposure window potentially runs back to March 2025.

The Belgium eID incident is worth tracking as a broader pattern indicator. Compromising the extension layer rather than the identity provider itself is a structurally repeatable attack. It will recur.

<br/>
---
<br/>

## Source Links

- Critical VMware vCenter Vulnerability in Attackers' Crosshairs — SecurityWeek — [https://www.securityweek.com/critical-vmware-vcenter-vulnerability-in-attackers-crosshairs/](https://www.securityweek.com/critical-vmware-vcenter-vulnerability-in-attackers-crosshairs/)

- Nightmare Eclipse Drops Windows Zero-Day Exploit 'ShieldBreak' — SecurityWeek — [https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-shieldbreak/](https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-shieldbreak/)

- Attackers Exploit SharePoint Authentication Bypass After Public PoC Release — The Hacker News — [https://thehackernews.com/2026/08/attackers-exploit-sharepoint.html](https://thehackernews.com/2026/08/attackers-exploit-sharepoint.html)

- Belgium's eID Authentication Opens Citizen Accounts to RCE — Dark Reading — [https://www.darkreading.com/application-security/belgium-eid-authentication-citizen-accounts-rce](https://www.darkreading.com/application-security/belgium-eid-authentication-citizen-accounts-rce)

- "City-Forum" data-theft attacks target Salesforce, ServiceNow portals — Bleeping Computer — [https://www.bleepingcomputer.com/news/security/city-forum-data-theft-attacks-target-salesforce-servicenow-portals/](https://www.bleepingcomputer.com/news/security/city-forum-data-theft-attacks-target-salesforce-servicenow-portals/)

- Long-running Data Theft Campaign Targeting Salesforce, ServiceNow — Dark Reading — [https://www.darkreading.com/cyberattacks-data-breaches/long-running-data-theft-campaign-salesforce-servicenow](https://www.darkreading.com/cyberattacks-data-breaches/long-running-data-theft-campaign-salesforce-servicenow)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
