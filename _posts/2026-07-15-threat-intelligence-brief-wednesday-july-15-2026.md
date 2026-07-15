---
layout: post
title: "Threat Intelligence Brief - Wednesday, July 15, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-15
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1059
  - T1190
  - T1195.001
  - Microsoft
  - Google
  - Windows
  - Windows-11
  - Cursor
  - code-execution
  - local-privilege-escalation
  - Progress
---

## Threat Radar

- **Active exploitation confirmed:** CISA has confirmed active exploitation of three vulnerabilities in internet-exposed on-premises SharePoint Server instances — patch immediately or take exposed instances offline.

- **Zero-day hits file sharing:** Progress confirmed a zero-day in ShareFile caused a service disruption; a fix is available for Storage Zones Controller customers and must be applied without delay.

- **Supply chain compromise in npm:** Four packages in the @asyncapi namespace were trojanized to deliver a multi-stage botnet loader — any organization with these packages in build pipelines is at risk of downstream malware propagation.

- **Developer tooling risk:** The Cursor AI code editor on Windows silently executes a `git.exe` binary found in a cloned repository's root, exposing SSH keys and cloud tokens with no user prompt — a direct risk for engineering teams cloning untrusted repositories.

- **ICS Patch Tuesday:** Siemens, Schneider Electric, and Rockwell Automation released patches for dozens of vulnerabilities across industrial control system products; OT teams should begin patch prioritization now.

- **Browser critical patches with public exploits:** Chrome 150 and Firefox 152 address critical vulnerabilities; public exploit code exists for Firefox flaws, raising urgency for enterprise browser fleet updates.

<br/>
---
<br/>

## Immediate Action Required

- **SharePoint Server (Microsoft) — Active Exploitation:** CISA has confirmed active exploitation of three vulnerabilities targeting internet-exposed on-premises SharePoint Server. Validate exposure, apply patches immediately, and review logs for indicators consistent with T1190.

- **ShareFile / Storage Zones Controller (Progress) — Zero-Day:** A confirmed zero-day caused a service disruption. On-premises Storage Zones Controller customers must apply the vendor-released fix immediately and assess whether data access or availability was impacted.

- **AsyncAPI npm Packages — Supply Chain Compromise:** Packages `@asyncapi/generator-helpers` and `@asyncapi/generator-components` are confirmed malicious. Engineering and AppSec teams must audit dependency trees, remove affected packages, and scan build artifacts for botnet loader indicators. T1195.001.

<br/>
---
<br/>

## High-Impact Developments

### CISA Warns of Actively Exploited SharePoint Server Vulnerabilities

- **What happened:** CISA issued an alert confirming that three vulnerabilities in internet-exposed on-premises Microsoft SharePoint Server instances are being actively exploited.

- **Why it matters:** Active exploitation means attackers are already scanning for and compromising unpatched systems. SharePoint commonly holds sensitive documents and internal communications, and integrates with identity infrastructure — a foothold here can cascade quickly.

- **Who should care:** IT operations, SOC teams, vulnerability management leads, and identity/access teams responsible for on-premises Microsoft infrastructure.

- **Recommended action:** Identify all internet-exposed SharePoint Server instances immediately. Apply available patches without waiting for a maintenance window. Review access logs for activity consistent with T1190 (Exploit Public-Facing Application). If patching cannot be completed immediately, restrict external access as an interim control.

- **Confidence:** High — CISA advisory with confirmed in-the-wild exploitation.

- **Search metadata:** T1190, SharePoint Server, Microsoft, CISA, active-exploitation

**Intelligence Context**
- [CISA warns admins to patch actively exploited SharePoint flaws — Bleeping Computer](https://www.bleepingcomputer.com/news/security/cisa-warns-admins-to-patch-actively-exploited-sharepoint-flaws/)
  - Context: Bleeping Computer reports CISA's direct warning to administrators, confirming three vulnerabilities are under active exploitation against internet-facing on-premises SharePoint Server deployments.

<br/>
---
<br/>

### Progress ShareFile Zero-Day Causes Confirmed Service Disruption

- **What happened:** Progress confirmed that a zero-day vulnerability in ShareFile was exploited and caused a service disruption. A fix has been released for customers running the on-premises Storage Zones Controller component.

- **Why it matters:** Progress software has been a repeated target — MOVEit being the most prominent example. A confirmed zero-day with active exploitation in another Progress file-transfer product warrants immediate attention, particularly for organizations with on-premises deployments.

- **Who should care:** IT operations and security teams managing on-premises ShareFile deployments, particularly those running Storage Zones Controller.

- **Recommended action:** Apply the vendor-released fix for Storage Zones Controller immediately. Determine whether the disruption resulted in data exposure or unauthorized access. Organizations using cloud-hosted ShareFile should confirm with Progress whether their environment was affected.

- **Confidence:** High — vendor-confirmed zero-day with patch available.

- **Search metadata:** ShareFile, Storage-Zones-Controller, Storage Zones Controller, Progress, zero-day

**Intelligence Context**
- [Progress Confirms Zero-Day Vulnerability Behind ShareFile Disruption — SecurityWeek](https://www.securityweek.com/progress-confirms-zero-day-vulnerability-behind-sharefile-disruption/)
  - Context: SecurityWeek reports Progress's confirmation that a zero-day was the root cause of the ShareFile disruption, with a fix now available for Storage Zones Controller customers who apply it.

<br/>
---
<br/>

### Compromised AsyncAPI npm Packages Distribute Multi-Stage Botnet Malware

- **What happened:** Four packages in the `@asyncapi` npm namespace — including `@asyncapi/generator-helpers` and `@asyncapi/generator-components` — were compromised and are delivering a multi-stage botnet loader. The compromise was identified by multiple security research firms.

- **Why it matters:** Any organization that pulled these packages into CI/CD pipelines, build systems, or developer environments may have already executed malicious code. The multi-stage loader design indicates the attacker is pursuing persistent access, not a one-time payload.

- **Who should care:** Engineering leadership, AppSec teams, software supply chain owners, and SOC teams monitoring build infrastructure.

- **Recommended action:** Audit all projects and pipelines for use of the affected packages. Remove them immediately and treat any system that executed them as potentially compromised. Engage incident response if these packages were present in production build environments. T1195.001.

- **Confidence:** High — confirmed by multiple independent security research organizations.

- **Search metadata:** T1195.001, @asyncapi/generator-helpers, @asyncapi/generator-components, npm, supply-chain, botnet, malware-distribution

**Intelligence Context**
- [Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware — The Hacker News](https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html)
  - Context: The Hacker News reports findings from OX Security, SafeDep, Socket, and StepSecurity identifying four trojanized @asyncapi packages actively distributing a multi-stage botnet loader through the npm ecosystem.

<br/>
---
<br/>

### Cursor AI Editor Silently Executes Binaries from Cloned Repositories on Windows

- **What happened:** A flaw in the Cursor AI code editor on Windows causes it to automatically execute a file named `git.exe` if present in the root of a cloned repository — with no user prompt, approval dialog, or warning. The binary runs with the user's full privileges, including access to SSH keys and cloud tokens.

- **Why it matters:** Developers routinely clone repositories from external or semi-trusted sources. An attacker who can place a crafted repository in front of a Cursor user — via a phishing link, a compromised dependency, or a public repository — achieves silent code execution and credential theft with no user interaction beyond opening the project.

- **Who should care:** Engineering teams using Cursor on Windows, security architects responsible for developer workstation posture, and identity/access teams managing SSH key and cloud token lifecycle.

- **Recommended action:** Assess Cursor usage across developer endpoints. Until a vendor patch is confirmed, instruct developers to avoid cloning repositories from untrusted sources in Cursor on Windows. Evaluate whether SSH keys and cloud tokens on developer machines warrant rotation. T1059.

- **Confidence:** High — behavior is documented and reproducible.

- **Search metadata:** T1059, Cursor, Windows, code-execution

**Intelligence Context**
- [Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution — The Hacker News](https://thehackernews.com/2026/07/cursor-flaw-lets-malicious-cloned.html)
  - Context: The Hacker News details the Cursor flaw, explaining that any `git.exe` binary placed in a repository root is executed automatically when the project is opened, with no user interaction required and full access to the user's credentials.

<br/>
---
<br/>

## Monitor Only

- ICS Patch Tuesday: Siemens, Schneider Electric, and Rockwell Automation released patches for dozens of vulnerabilities across industrial control system products; CISA and VDE CERT issued accompanying advisories — exploitation status is currently unknown, but OT teams should begin patch prioritization this week. **Source:** ICS Patch Tuesday: Vulnerabilities Fixed by Siemens, Schneider, Rockwell — SecurityWeek — [https://www.securityweek.com/ics-patch-tuesday-vulnerabilities-fixed-by-siemens-schneider-rockwell/](https://www.securityweek.com/ics-patch-tuesday-vulnerabilities-fixed-by-siemens-schneider-rockwell/)

- Chrome 150 and Firefox 152 address critical vulnerabilities; public exploit code exists for Firefox flaws but no in-the-wild exploitation has been confirmed — enterprise IT teams should accelerate browser fleet updates given the availability of public exploit code. **Source:** Critical Vulnerabilities Patched With Fresh Chrome 150, Firefox 152 Updates — SecurityWeek — [https://www.securityweek.com/critical-vulnerabilities-patched-with-fresh-chrome-150-firefox-152-updates/](https://www.securityweek.com/critical-vulnerabilities-patched-with-fresh-chrome-150-firefox-152-updates/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a pattern worth internalizing: the attack surface is expanding simultaneously across enterprise collaboration platforms (SharePoint, ShareFile), developer tooling (Cursor, npm), and industrial infrastructure (ICS vendors). Three of today's six stories involve confirmed active exploitation or a confirmed zero-day — an unusually high ratio for a single day, and a signal that threat actors are moving faster than patch cycles. The AsyncAPI supply chain compromise is particularly notable because it targets the build pipeline directly, meaning malware can reach production systems without touching a user's browser or inbox. The Cursor flaw reinforces a broader problem: AI-assisted developer tooling is being adopted faster than security review processes can keep pace. Security architects need to be in procurement conversations before deployment, not after.

<br/>
---
<br/>

## Source Links

- CISA warns admins to patch actively exploited SharePoint flaws — Bleeping Computer — [https://www.bleepingcomputer.com/news/security/cisa-warns-admins-to-patch-actively-exploited-sharepoint-flaws/](https://www.bleepingcomputer.com/news/security/cisa-warns-admins-to-patch-actively-exploited-sharepoint-flaws/)

- Progress Confirms Zero-Day Vulnerability Behind ShareFile Disruption — SecurityWeek — [https://www.securityweek.com/progress-confirms-zero-day-vulnerability-behind-sharefile-disruption/](https://www.securityweek.com/progress-confirms-zero-day-vulnerability-behind-sharefile-disruption/)

- Compromised AsyncAPI npm Packages Deliver Multi-Stage Botnet Malware — The Hacker News — [https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html](https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html)

- Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution — The Hacker News — [https://thehackernews.com/2026/07/cursor-flaw-lets-malicious-cloned.html](https://thehackernews.com/2026/07/cursor-flaw-lets-malicious-cloned.html)

- ICS Patch Tuesday: Vulnerabilities Fixed by Siemens, Schneider, Rockwell — SecurityWeek — [https://www.securityweek.com/ics-patch-tuesday-vulnerabilities-fixed-by-siemens-schneider-rockwell/](https://www.securityweek.com/ics-patch-tuesday-vulnerabilities-fixed-by-siemens-schneider-rockwell/)

- Critical Vulnerabilities Patched With Fresh Chrome 150, Firefox 152 Updates — SecurityWeek — [https://www.securityweek.com/critical-vulnerabilities-patched-with-fresh-chrome-150-firefox-152-updates/](https://www.securityweek.com/critical-vulnerabilities-patched-with-fresh-chrome-150-firefox-152-updates/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
