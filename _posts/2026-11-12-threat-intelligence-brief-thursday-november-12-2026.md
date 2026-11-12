---
layout: post
title: "Threat Intelligence Brief - Thursday, November 12, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-11-12
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-126325
  - T1005
  - T1190
  - T1059
  - T1566.002
  - T1187
  - T1530
  - T1570
  - T1592
  - Microsoft
  - Google-Cloud
---

## Threat Radar

- **Remote management tooling is under active attack on two fronts today:** N-able N-central on-premise deployments face confirmed RCE exploitation that bypasses existing patches via non-default configurations, and ConnectWise ScreenConnect is being actively exploited through a legitimate extension vulnerability to deploy malware.

- **A Google session hijacking campaign running since mid-August 2026 is bypassing MFA** by stealing live session tokens via calendar invite phishing and live proxies — all indicators appeared clean to defenders by design, making this particularly difficult to detect with standard controls.

- **PTC Windchill and FlexPLM carry a CVSS 9.2 RCE vulnerability (CVE-2026-126325)** with patches now available; exploitation status is unknown but the severity and attack surface in engineering and PLM environments warrant urgent patching this week.

- **A breach of AI vendor Fireworks AI exposed Notion workspace chat transcripts**, reinforcing that third-party AI service providers represent a live data confidentiality risk for organizations using SaaS productivity tools with AI integrations.

- **Google Cloud customers running workloads on AMD Turin CPUs face three CPU-level side-channel flaws** that can leak data across VM processes; inter-VM mitigations are in place, but guest OS patches and a full VM stop-and-start are still required per workload.

<br/>
---
<br/>

## Immediate Action Required

- **N-able N-central (on-premise, v2026.4.1 HF2):** Active exploitation confirmed. New vulnerabilities enable root RCE and Windows SYSTEM access via non-default Legacy API configurations, bypassing prior patches. Audit all N-central deployments for non-default Legacy API configurations immediately. Patched status does not equal protected status. *T1190, T1059 | N-able, Windows*

- **ConnectWise ScreenConnect:** Active exploitation confirmed via a vulnerability in a legitimate ScreenConnect extension, enabling authentication bypass and malware deployment. Audit all ScreenConnect instances and installed extensions. Validate that no unauthorized sessions or payloads exist on managed endpoints. *T1190, T1059 | ConnectWise ScreenConnect*

- **Google Workspace — Session Hijacking Campaign:** Active phishing campaign using calendar invites and live proxies to steal live Google sessions, bypassing MFA. Standard link-reputation checks are ineffective against this infrastructure. Engage IAM and SOC teams to review anomalous Google session activity, particularly sessions originating from unexpected geolocations or IP ranges. *T1566.002, T1187 | Google*

<br/>
---
<br/>

## High-Impact Developments

### N-central RCE Exploits Bypass Patched Servers

- **What happened:** N-able disclosed new vulnerabilities in N-central on-premise version 2026.4.1 HF2 that enable root-level RCE and Windows SYSTEM access. The attack path runs through non-default Legacy API configurations and has been confirmed exploited in the wild despite prior patching.

- **Why it matters:** N-central is a privileged management platform administering large endpoint estates. Compromise grants attackers lateral reach across every managed system. Existing patches do not protect non-default configurations, which invalidates patch-based assurance for many deployments.

- **Who should care:** IT operations, endpoint management teams, MSPs, and SOC leaders responsible for N-central infrastructure.

- **Recommended action:** Audit all N-central on-premise deployments for non-default configurations, particularly Legacy API enablement. Treat any instance with non-default configurations as potentially compromised pending N-able's investigation. Apply forthcoming hotfixes without delay.

- **Confidence:** High — exploitation confirmed, vendor investigation ongoing.

- **Search metadata:** T1190, T1059 | N-able N-central | Windows

**Intelligence Context**
- [New N-central Exploits Work Against Patched Servers, Enable Root RCE and Windows SYSTEM Access](https://thehackernews.com/2026/11/new-n-central-exploits-work-against.html) — The Hacker News
  - Context: N-able confirmed it is investigating newly disclosed vulnerabilities in N-central v2026.4.1 HF2 that enable root RCE via non-default Legacy API configurations, with exploitation confirmed in the wild.

<br/>
---
<br/>

### ScreenConnect Extension Exploited for Malware Deployment

- **What happened:** Attackers exploited a vulnerability in a legitimate ConnectWise ScreenConnect extension to bypass authentication and deploy malware across managed endpoints. Active exploitation is confirmed.

- **Why it matters:** Remote support tools carry elevated trust and broad endpoint access by design. Compromising ScreenConnect at the extension layer lets attackers inherit that access and deploy malicious payloads at scale without triggering typical endpoint controls.

- **Who should care:** IT operations, remote support administrators, and SOC teams managing or monitoring ScreenConnect environments.

- **Recommended action:** Audit all ScreenConnect installations and review installed extensions for unauthorized or tampered components. Validate endpoint integrity on systems managed via ScreenConnect. Restrict extension installation to vetted, approved sources and review access logs for anomalous session activity.

- **Confidence:** High — active exploitation confirmed.

- **Search metadata:** T1190, T1059 | ConnectWise ScreenConnect | malware deployment, authentication bypass

**Intelligence Context**
- [Hackers Deploy Malware in Fresh ScreenConnect Campaign](https://www.securityweek.com/hackers-deploy-malware-in-fresh-screenconnect-campaign/) — SecurityWeek
  - Context: Attackers exploited a vulnerability in a legitimate ScreenConnect extension to bypass authentication and deploy malware, with active exploitation confirmed across the campaign.

<br/>
---
<br/>

### Google Session Hijacking Campaign via Calendar Invites and Live Proxies

- **What happened:** A phishing campaign active since mid-August 2026 targets corporate Google users by delivering malicious links via calendar invites. Live proxies steal active Google session tokens in real time, bypassing MFA. Every standard link-reputation indicator returned clean — the evasion was deliberate and engineered.

- **Why it matters:** This campaign renders MFA ineffective because it steals authenticated sessions rather than credentials. Standard email and URL security tooling provides no reliable signal. Compromised Google accounts expose email, Drive, Calendar, and any integrated SaaS applications.

- **Who should care:** IAM teams, SOC analysts, and any organization relying on Google Workspace as a primary productivity platform.

- **Recommended action:** Review Google Workspace audit logs for anomalous session activity — particularly sessions from unexpected IP ranges or geolocations. Confirm whether context-aware access policies and device trust requirements are enforced. Brief security awareness teams on calendar invites as a phishing vector. Evaluate session binding controls where available.

- **Confidence:** High — active campaign confirmed, evasion techniques documented by Material Security threat research.

- **Search metadata:** T1566.002, T1187 | Google Workspace | session hijacking, live proxies, calendar invite phishing

**Intelligence Context**
- [Calendar Invites and Live Proxies: Inside a Google Session Hijacking Campaign](https://thehackernews.com/2026/11/calendar-invites-and-live-proxies.html) — The Hacker News
  - Context: Material Security's threat research team documented the campaign, noting that all standard link-reputation checks returned clean and that the operator deliberately engineered the infrastructure to evade defender tooling.

<br/>
---
<br/>

### Critical RCE Vulnerability in PTC Windchill and FlexPLM (CVE-2026-126325)

- **What happened:** PTC released patches for CVE-2026-126325, a CVSS v4 9.2 remote code execution vulnerability affecting Windchill and FlexPLM. Exploitation status is currently unknown.

- **Why it matters:** Windchill and FlexPLM are widely deployed in engineering, manufacturing, and product lifecycle management environments. Successful exploitation could expose sensitive product design data, cause operational disruption, or enable attackers to pivot from PLM systems into broader enterprise networks.

- **Who should care:** Application owners, vulnerability management leads, and security teams in manufacturing, engineering, or industrial sectors running PTC software.

- **Recommended action:** Apply PTC patches for Windchill and FlexPLM this week. Prioritize internet-exposed or network-accessible instances. Confirm patch deployment with application owners and check application logs for exploitation indicators.

- **Confidence:** High — vendor-confirmed critical vulnerability with patches available; exploitation status unknown.

- **Search metadata:** CVE-2026-126325, T1190 | PTC Windchill, FlexPLM | CVSS 9.2, RCE

**Intelligence Context**
- [PTC Patches Critical Windchill and FlexPLM Flaw That Could Enable Remote Code Execution](https://thehackernews.com/2026/11/ptc-patches-critical-windchill-and.html) — The Hacker News
  - Context: PTC confirmed the vulnerability carries a CVSS v4 score of 9.2 and released patches; no exploitation has been confirmed at time of reporting.

<br/>
---
<br/>

### Fireworks AI Breach Exposes Notion Customer Chat Transcripts

- **What happened:** A breach of Fireworks AI, a third-party AI service provider integrated with Notion, resulted in unauthorized access to chat transcripts from fewer than 1% of Notion workspaces. Most transcripts were described as unattributable.

- **Why it matters:** Organizations using Notion's AI features had workspace content processed and stored by a downstream vendor they may not have explicitly evaluated. The breach confirms that AI integrations extend the data exposure surface beyond the primary SaaS vendor.

- **Who should care:** Legal, privacy, and compliance teams; SaaS administrators managing Notion deployments; security teams responsible for third-party vendor risk.

- **Recommended action:** Determine whether your organization's Notion workspaces used AI chat features during the exposure window. Engage legal and privacy teams to assess notification obligations. Audit third-party AI vendor inventory for similar data-sharing arrangements and validate contractual data handling requirements.

- **Confidence:** High — breach confirmed; scope limited to fewer than 1% of Notion workspaces.

- **Search metadata:** T1530 | Notion, Fireworks AI | data breach, chat transcripts, third-party AI risk

**Intelligence Context**
- [Notion Customer Data Compromised in Fireworks AI Hack](https://www.securityweek.com/notion-customer-data-compromised-in-fireworks-ai-hack/) — SecurityWeek
  - Context: Attackers accessed Notion customer chat transcripts via a breach of Fireworks AI, the third-party AI provider powering Notion's AI features, affecting fewer than 1% of workspaces.

<br/>
---
<br/>

## Monitor Only

- **AMD Turin CPU side-channel flaws in Google Cloud VMs** can leak data across processes within a VM; Google has applied inter-VM mitigations, but guest OS patches and a VM stop-and-start are required per workload — coordinate with cloud and infrastructure teams this week. *T1005 | AMD Turin, Google Cloud* **Source:** [Google Cloud Warns Three AMD Turin CPU Flaws Could Leak Data Across Processes in VMs](https://thehackernews.com/2026/11/google-cloud-warns-three-amd-turin-cpu.html) — The Hacker News

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a pattern practitioners should internalize: the tools organizations trust most — remote management platforms, remote support software, and AI-integrated SaaS — are precisely what attackers are targeting. N-central and ScreenConnect are both under active exploitation, and in both cases the attack surface is the management layer itself, not the endpoints it manages. The Google session hijacking campaign is a reminder that MFA is not a ceiling; it is a floor, and adversaries have already built infrastructure to operate above it. The Fireworks AI breach is the quieter story but arguably the most instructive for leadership: most organizations cannot name every third-party vendor processing their SaaS data, and that gap is now a confirmed liability. Patch urgency this week is real across multiple product lines — prioritize N-central and ScreenConnect above all others given confirmed active exploitation.

<br/>
---
<br/>

## Source Links

- New N-central Exploits Work Against Patched Servers, Enable Root RCE and Windows SYSTEM Access — [https://thehackernews.com/2026/11/new-n-central-exploits-work-against.html](https://thehackernews.com/2026/11/new-n-central-exploits-work-against.html)

- Hackers Deploy Malware in Fresh ScreenConnect Campaign — [https://www.securityweek.com/hackers-deploy-malware-in-fresh-screenconnect-campaign/](https://www.securityweek.com/hackers-deploy-malware-in-fresh-screenconnect-campaign/)

- Calendar Invites and Live Proxies: Inside a Google Session Hijacking Campaign — [https://thehackernews.com/2026/11/calendar-invites-and-live-proxies.html](https://thehackernews.com/2026/11/calendar-invites-and-live-proxies.html)

- PTC Patches Critical Windchill and FlexPLM Flaw That Could Enable Remote Code Execution — [https://thehackernews.com/2026/11/ptc-patches-critical-windchill-and.html](https://thehackernews.com/2026/11/ptc-patches-critical-windchill-and.html)

- Notion Customer Data Compromised in Fireworks AI Hack — [https://www.securityweek.com/notion-customer-data-compromised-in-fireworks-ai-hack/](https://www.securityweek.com/notion-customer-data-compromised-in-fireworks-ai-hack/)

- Google Cloud Warns Three AMD Turin CPU Flaws Could Leak Data Across Processes in VMs — [https://thehackernews.com/2026/11/google-cloud-warns-three-amd-turin-cpu.html](https://thehackernews.com/2026/11/google-cloud-warns-three-amd-turin-cpu.html)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
