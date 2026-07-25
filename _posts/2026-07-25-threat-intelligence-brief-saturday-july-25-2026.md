---
layout: post
title: "Threat Intelligence Brief - Saturday, July 25, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-25
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1059
  - T1557.002
  - T1598.003
  - Microsoft-365
  - Microsoft
  - Azure
  - ChatGPT
  - OpenAI
  - outage
  - availability
  - GitLab
---

## Threat Radar

- A working RCE proof-of-concept for GitLab 18.11.3 is now public — any authenticated user can execute commands as `git` on unpatched self-managed instances, making exploitation trivially accessible.

- An active DNS hijacking campaign is targeting travelers at hotels and conference centers, redirecting Microsoft 365 login attempts to credential-harvesting pages; stolen credentials can enable full organizational account compromise.

- Rockwell Automation has patched code execution flaws in Arena simulation software used in industrial environments — exploitation could bridge engineering workstations into adjacent OT networks.

- A threat actor deployed the open-source Hermes AI agent in fully autonomous "YOLO" mode during an alleged breach of Thailand's Ministry of Finance, marking a documented operational use of AI to accelerate post-exploitation at scale.

- Microsoft's own automated maintenance system caused a major global outage of Microsoft 365 and Azure by incorrectly removing IP routes — platform availability risk is not exclusively adversarial.

<br/>
---
<br/>

## Immediate Action Required

**GitLab Self-Managed RCE — Patch or Isolate Now**

A functional exploit is public. Any authenticated user — contractor, developer, or compromised account — can achieve remote code execution on GitLab 18.11.3. Source code repositories, CI/CD pipelines, and secrets stored in GitLab are directly at risk. Patch immediately or restrict access to self-managed instances until patching is complete.

**Microsoft 365 Credential Theft via Hotel Wi-Fi DNS Hijacking**

This is an active campaign. Traveling employees connecting to hotel or conference Wi-Fi are being redirected to fake M365 login pages. Issue traveler advisories now, enforce phishing-resistant MFA (FIDO2/hardware keys), and review sign-in logs for anomalous authentications originating from hospitality-sector IP ranges.

<br/>
---
<br/>

## High-Impact Developments

### GitLab RCE PoC Published — Self-Managed Instances at Immediate Risk

- **What happened:** Security researcher Yuhang Wu published a working proof-of-concept exploit for GitLab 18.11.3. An authenticated user triggers remote code execution by committing two crafted Jupyter notebooks and requesting their diff, executing commands as the `git` system user on the server.

- **Why it matters:** The exploitation bar is extremely low — any authenticated user, including those with minimal privileges, can weaponize this. With a public PoC in circulation, mass exploitation attempts against exposed self-managed instances are a near-term certainty. Source code, CI/CD secrets, deployment keys, and pipeline configurations are all at risk.

- **Who should care:** Security operations, DevOps, and platform engineering teams running self-managed GitLab. Organizations using GitLab for software supply chain workflows face compounded risk.

- **Recommended action:** Identify all self-managed GitLab instances and their version levels immediately. Apply available patches. If patching cannot be completed within hours, restrict instance access to known-good IP ranges or VPN. Audit recent repository activity and CI/CD pipeline executions for anomalies. Rotate secrets stored in GitLab variables.

- **Confidence:** High

- **Search metadata:** T1059, GitLab, RCE, authenticated-access, code-execution

**Intelligence Context**
- Researcher Publishes GitLab RCE PoC Letting Authenticated Users Run Commands as Git — [https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)
  - Context: Researcher Yuhang Wu's working PoC is confirmed functional against GitLab 18.11.3 self-managed servers; the exploit mechanism involves crafted Jupyter notebook diffs, requiring only authenticated access to trigger.

<br/>
---
<br/>

### DNS Hijacking Campaign Harvesting Microsoft 365 Credentials from Travelers

- **What happened:** Attackers are modifying DNS settings on Wi-Fi infrastructure at hotels and conference centers to intercept traffic and redirect Microsoft 365 authentication requests to convincing phishing pages. Credentials are captured in real time.

- **Why it matters:** This is an infrastructure-level attack, not a generic phishing email. Users have no reliable visual indicator that DNS has been tampered with. Stolen M365 credentials provide direct access to email, SharePoint, Teams, and integrated SaaS applications, enabling lateral movement across the organization.

- **Who should care:** Security operations, identity and access management teams, and any organization with employees who travel for business. Executives and senior staff are high-value targets in this scenario.

- **Recommended action:** Issue a travel security advisory now. Require corporate VPN before any cloud authentication on untrusted networks. Enforce phishing-resistant MFA across all M365 accounts. Review Entra ID / Azure AD sign-in logs for authentications originating from hotel or conference IP ranges over the past 30 days. Apply conditional access policies that flag or block authentication from non-corporate network locations.

- **Confidence:** High

- **Search metadata:** T1557.002, T1598.003, Microsoft 365, DNS-hijacking, credential-theft, phishing, hotel-wifi

**Intelligence Context**
- Hackers hijack hotel Wi-Fi DNS to steal Microsoft 365 accounts — [https://www.bleepingcomputer.com/news/security/hackers-hijack-hotel-wi-fi-dns-to-steal-microsoft-365-accounts/](https://www.bleepingcomputer.com/news/security/hackers-hijack-hotel-wi-fi-dns-to-steal-microsoft-365-accounts/)
  - Context: The campaign is confirmed active, with attackers directly modifying DNS configurations on hospitality Wi-Fi devices to intercept and redirect M365 authentication traffic to attacker-controlled credential-harvesting pages.

<br/>
---
<br/>

### Rockwell Arena Simulation Software Patched for Code Execution Flaws

- **What happened:** Rockwell Automation released patches addressing code execution vulnerabilities in Arena simulation software. A researcher demonstrated viable exploitation paths targeting industrial organizations using the software for engineering workflows.

- **Why it matters:** Arena is used in manufacturing and industrial design environments. Exploitation could allow an attacker to execute code on engineering workstations, providing a foothold into networks adjacent to operational technology (OT) systems. Researcher-published exploitation paths lower the barrier for threat actors targeting industrial sectors.

- **Who should care:** Industrial security leads, OT/ICS security architects, and vulnerability management teams at manufacturing, energy, or critical infrastructure organizations using Rockwell products.

- **Recommended action:** Apply Rockwell's patches this week. Confirm that Arena installations are not directly reachable from untrusted networks. Review network segmentation between engineering workstations running Arena and OT/ICS environments.

- **Confidence:** High

- **Search metadata:** T1059, Rockwell Automation, Arena, code-execution, industrial

**Intelligence Context**
- Rockwell Patches Code Execution Flaws in Arena Simulation Software — [https://www.securityweek.com/rockwell-patches-code-execution-flaws-in-arena-simulation-software/](https://www.securityweek.com/rockwell-patches-code-execution-flaws-in-arena-simulation-software/)
  - Context: A researcher detailed how the Arena vulnerabilities could be exploited to target industrial organizations, with patches now available from Rockwell Automation.

<br/>
---
<br/>

### Hermes AI Agent Deployed Autonomously in Government Breach

- **What happened:** A threat actor used the open-source Hermes AI agent configured in unattended "YOLO" mode — fully autonomous operation without human confirmation steps — to conduct post-exploitation activity during an alleged breach of Thailand's Ministry of Finance.

- **Why it matters:** This is a documented operational use of an AI agent to automate attacker tradecraft at speed and scale. Autonomous post-exploitation compresses the window between initial access and data exfiltration or lateral movement. Open-source tooling means the barrier to adoption by other threat actors is low.

- **Who should care:** SOC leaders and security architects who need to recalibrate assumptions about attacker dwell time and operational tempo. Government and financial sector organizations are the most directly relevant targets, but the technique is sector-agnostic.

- **Recommended action:** Stress-test incident response playbooks against faster-moving intrusion timelines. Confirm behavioral detection coverage addresses automated post-exploitation patterns. Reassess whether current mean-time-to-detect assumptions remain valid against AI-accelerated attack cadence.

- **Confidence:** High

- **Search metadata:** T1059, Hermes, Thailand, Finance Ministry, AI-automation, post-exploitation

**Intelligence Context**
- Hermes AI agent used to automate attack on Thai Finance Ministry — [https://www.bleepingcomputer.com/news/security/hermes-ai-agent-used-to-automate-attack-on-thai-finance-ministry/](https://www.bleepingcomputer.com/news/security/hermes-ai-agent-used-to-automate-attack-on-thai-finance-ministry/)
  - Context: The Hermes AI agent was run in fully autonomous YOLO mode during the alleged Ministry of Finance breach, automating post-exploitation tasks without requiring attacker interaction at each step.

<br/>
---
<br/>

## Monitor Only

- **OnTrac data breach:** Logistics company OnTrac notified customers of a corporate network compromise with potential exposure of personal data. Organizations using OnTrac as a shipping partner should review data-sharing agreements and assess downstream privacy obligations. **Source:** OnTrac notifies customers of data breach after network hack — [https://www.bleepingcomputer.com/news/security/ontrac-notifies-customers-of-data-breach-after-network-hack/](https://www.bleepingcomputer.com/news/security/ontrac-notifies-customers-of-data-breach-after-network-hack/)

- **Microsoft 365 and Azure outage:** Microsoft confirmed a major service disruption caused by its own automated maintenance system incorrectly removing IP routes at scale. The incident is resolved, but it reinforces the need for validated business continuity procedures for M365-dependent workflows. **Source:** Microsoft blames massive Microsoft 365 outage on maintenance bug — [https://www.bleepingcomputer.com/news/microsoft/microsoft-blames-massive-microsoft-365-outage-on-maintenance-bug/](https://www.bleepingcomputer.com/news/microsoft/microsoft-blames-massive-microsoft-365-outage-on-maintenance-bug/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment where the attacker's operational advantage is accelerating on multiple fronts simultaneously. The GitLab PoC is the most time-sensitive item — public, functional, and requiring only authenticated access, which means compromised-credential and insider-threat scenarios are now RCE scenarios. The hotel Wi-Fi DNS hijacking campaign is a reminder that physical travel remains an attack surface that identity controls alone cannot fully address, particularly when DNS manipulation occurs below the application layer. The Hermes AI agent story deserves more attention than it will likely receive: autonomous post-exploitation tooling is no longer theoretical, and if your detection strategy assumes a human attacker operating at human speed, that assumption needs revisiting now. The Rockwell patches are straightforward but carry OT adjacency risk that elevates their priority for industrial operators. The Microsoft outage and OnTrac breach are worth tracking but require no immediate defensive action for most organizations.

<br/>
---
<br/>

## Source Links

- Researcher Publishes GitLab RCE PoC Letting Authenticated Users Run Commands as Git — [https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)

- Hackers hijack hotel Wi-Fi DNS to steal Microsoft 365 accounts — [https://www.bleepingcomputer.com/news/security/hackers-hijack-hotel-wi-fi-dns-to-steal-microsoft-365-accounts/](https://www.bleepingcomputer.com/news/security/hackers-hijack-hotel-wi-fi-dns-to-steal-microsoft-365-accounts/)

- Rockwell Patches Code Execution Flaws in Arena Simulation Software — [https://www.securityweek.com/rockwell-patches-code-execution-flaws-in-arena-simulation-software/](https://www.securityweek.com/rockwell-patches-code-execution-flaws-in-arena-simulation-software/)

- Hermes AI agent used to automate attack on Thai Finance Ministry — [https://www.bleepingcomputer.com/news/security/hermes-ai-agent-used-to-automate-attack-on-thai-finance-ministry/](https://www.bleepingcomputer.com/news/security/hermes-ai-agent-used-to-automate-attack-on-thai-finance-ministry/)

- OnTrac notifies customers of data breach after network hack — [https://www.bleepingcomputer.com/news/security/ontrac-notifies-customers-of-data-breach-after-network-hack/](https://www.bleepingcomputer.com/news/security/ontrac-notifies-customers-of-data-breach-after-network-hack/)

- Microsoft blames massive Microsoft 365 outage on maintenance bug — [https://www.bleepingcomputer.com/news/microsoft/microsoft-blames-massive-microsoft-365-outage-on-maintenance-bug/](https://www.bleepingcomputer.com/news/microsoft/microsoft-blames-massive-microsoft-365-outage-on-maintenance-bug/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
