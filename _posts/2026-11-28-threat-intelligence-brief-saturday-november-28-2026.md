---
layout: post
title: "Threat Intelligence Brief - Saturday, November 28, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-11-28
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1110
  - T1621
  - T1190
  - T1059
  - T1548
  - pCloud-Pass
  - pCloud
  - password-manager
  - account-compromise
  - Account-Compromise
  - Credential-Theft
---

## Threat Radar

- **Cacti zero-day with public PoC is actively exploitable today** — unauthenticated RCE on internet-facing instances with no patch available; treat as critical until isolated or remediated.

- **pCloud Pass was compromised with 2FA bypassed** — unknown devices accessed user accounts despite MFA being enabled, signaling credential exposure for any organization whose employees vault enterprise credentials in pCloud Pass.

- **US federal cloud environments are under sustained attack** — the Air Force Cloud One breach follows reported compromises at the FBI, CIA, and Treasury, indicating a coordinated campaign against federal cloud infrastructure.

- **Boston Scientific breach exposes personal and medical data** — breach notifications are active; healthcare-adjacent organizations and partners should assess third-party data-sharing exposure.

- **"God Mode" privilege escalation flaws in national immigration systems** — six countries' visa and border systems are affected; exploitation status unknown but the attack surface is significant for government and travel-sector organizations.

<br/>
---
<br/>

## Immediate Action Required

**Cacti — Unpatched Zero-Day RCE (T1190, T1059)**
Identify all Cacti instances in your environment, particularly internet-facing deployments. No vendor patch is available. Isolate or firewall-restrict access immediately. Monitor for exploitation indicators.

**pCloud Pass — Password Manager Compromise (T1110, T1621)**
If pCloud Pass is in use — by employees or IT teams — treat stored credentials as potentially exposed. Rotate passwords for any enterprise accounts vaulted there. Audit for unauthorized device sessions. Confirmed 2FA bypass means MFA status alone cannot be used as a control indicator.

<br/>
---
<br/>

## High-Impact Developments

### Cacti Network Monitor Zero-Day: Unauthenticated RCE with Public PoC

- **What happened:** A zero-day vulnerability in the Cacti network monitoring platform was publicly disclosed alongside a working proof-of-concept exploit. The flaw allows unauthenticated attackers to execute arbitrary commands on vulnerable servers. Active exploitation has been confirmed and no patch is currently available.

- **Why it matters:** Cacti is widely deployed for network performance monitoring, often on infrastructure-adjacent systems with broad network visibility. An unauthenticated RCE with a public PoC means the barrier to exploitation is near zero. Internet-facing instances are at immediate risk; internal instances are at risk from any attacker with network access.

- **Who should care:** Security leadership, infrastructure and network operations teams, SOC analysts, and vulnerability management leads running Cacti in any capacity.

- **Recommended action:** Audit your asset inventory for Cacti deployments now. Remove internet exposure immediately. Apply compensating controls — network segmentation, authentication proxies — until a vendor patch is released. Escalate to your vulnerability management team for priority tracking.

- **Confidence:** High

- **Search metadata:** T1190, T1059, Cacti, Remote Code Execution, Zero-Day

**Intelligence Context**
- [Unpatched Cacti zero-day with public PoC gives remote code execution](https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/) — Bleeping Computer
  - Context: Confirms the zero-day disclosure, availability of a working public PoC, and active exploitation of unauthenticated RCE against Cacti servers. No patch is available at time of publication.

<br/>
---
<br/>

### pCloud Pass Password Manager Breach: 2FA Bypassed, Credentials at Risk

- **What happened:** pCloud confirmed its pCloud Pass password manager was targeted in a cyberattack. Users reported unknown devices connecting to their accounts despite two-factor authentication being enabled. The attack exposed email addresses and triggered unauthorized login attempts. pCloud states the incident was contained.

- **Why it matters:** A compromised password manager is a high-leverage attack: one breach exposes credentials across every service a user has stored. The confirmed 2FA bypass points to session token theft, MFA fatigue exploitation, or an authentication control failure. "Contained" does not mean stored credentials are safe.

- **Who should care:** Security leadership, IAM teams, and any employee or IT administrator who uses pCloud Pass to store enterprise credentials.

- **Recommended action:** Identify pCloud Pass usage across your organization. Treat all credentials stored in pCloud Pass as compromised until proven otherwise. Rotate passwords for any enterprise accounts vaulted there. Review authentication logs for anomalous device registrations or login attempts. Assess downstream exposure through your IAM team.

- **Confidence:** High

- **Search metadata:** T1110, T1621, pCloud Pass, Account Compromise, Authentication Bypass, Credential Theft

**Intelligence Context**
- [pCloud confirms password manager hack after suspicious login alerts](https://www.bleepingcomputer.com/news/security/pcloud-confirms-password-manager-hack-after-suspicious-login-alerts/) — Bleeping Computer
  - Context: Reports user accounts were accessed by unknown devices despite 2FA being active, and confirms pCloud acknowledged the cyberattack and stated it was contained.

- [pCloud Password Manager Hit by Cyber Attack Involving Email Address Exposure and Login Attempts](https://thehackernews.com/2026/11/pcloud-password-manager-hit-by-cyber.html) — The Hacker News
  - Context: Adds detail on email address exposure and unauthorized login attempts, corroborating the breach scope and pCloud's public acknowledgment.

<br/>
---
<br/>

### US Air Force Cloud One Breach: Federal Cloud Under Sustained Attack

- **What happened:** The US Air Force's Cloud One computing platform was reportedly breached, part of a broader wave of attacks against US government agencies including the FBI, CIA, and Treasury Department. Attack techniques and threat actor attribution have not been publicly confirmed.

- **Why it matters:** Simultaneous federal cloud compromises point to a coordinated campaign rather than isolated incidents. Organizations with federal contracts, shared infrastructure, or data-sharing relationships with affected agencies face elevated supply chain and lateral exposure risk. Cloud-hosted government workloads should be treated as potentially affected until cleared.

- **Who should care:** Security leadership, cloud security teams, government contractors, and organizations operating in or adjacent to federal cloud environments.

- **Recommended action:** Government contractors and federal partners should review shared access, API integrations, and data flows connected to affected agencies. Cloud security teams should validate access controls and audit logs for anomalous activity. Await official CISA or DoD guidance for specific indicators.

- **Confidence:** Medium (breach reported; attribution and full scope unconfirmed)

- **Search metadata:** Cloud One, Cloud, Data Breach, Government Compromise, US Air Force

**Intelligence Context**
- [US Air Force cloud platform reportedly hacked in latest federal breach](https://www.bleepingcomputer.com/news/security/us-air-force-cloud-platform-reportedly-hacked-in-latest-federal-breach/) — Bleeping Computer
  - Context: Reports the Cloud One breach as part of a confirmed wave of attacks on multiple US federal agencies, establishing the pattern of coordinated federal targeting.

<br/>
---
<br/>

## Monitor Only

- **Boston Scientific data breach exposes personal and medical information** — breach notifications are being issued to affected individuals; healthcare-adjacent organizations and third-party partners should assess data-sharing exposure and prepare for potential regulatory inquiries. **Source:** [New Boston Scientific data breach exposes personal, medical info](https://www.bleepingcomputer.com/news/security/new-boston-scientific-data-breach-exposes-personal-medical-info/) — Bleeping Computer

- **"God Mode" privilege escalation flaws disclosed in national visa and immigration systems across Nigeria, Ethiopia, Zambia, Sri Lanka, Fiji, and Ghana** — exploitation status is unknown; direct operational impact for most private-sector organizations is low, but government and travel-sector security teams should note the attack pattern (T1548) and assess analogous systems. **Source:** ['God Mode' Flaws Could Wreak Border-Control Havoc](https://www.darkreading.com/vulnerabilities-threats/god-mode-flaws-wreak-border-control-havoc) — Dark Reading

<br/>
---
<br/>

## Analyst Observation

This brief reflects a threat environment where foundational controls — password managers, MFA, and cloud access governance — are being targeted directly, not circumvented through perimeter exploits. The pCloud Pass incident is a reminder that password managers are high-value targets precisely because they centralize credential access; one compromise multiplies attacker reach across every stored account. The Cacti zero-day compounds this: network monitoring tools occupy privileged network positions and are routinely under-patched because they are treated as operational rather than security infrastructure. The federal cloud breach pattern is the most strategically significant story this week — not for what is confirmed, but for what it implies about adversary access to cloud-hosted government workloads and the downstream risk to contractors and partners. Waiting for official attribution before acting is accepting unnecessary exposure.

<br/>
---
<br/>

## Source Links

- [Unpatched Cacti zero-day with public PoC gives remote code execution](https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/) — Bleeping Computer

- [pCloud confirms password manager hack after suspicious login alerts](https://www.bleepingcomputer.com/news/security/pcloud-confirms-password-manager-hack-after-suspicious-login-alerts/) — Bleeping Computer

- [pCloud Password Manager Hit by Cyber Attack Involving Email Address Exposure and Login Attempts](https://thehackernews.com/2026/11/pcloud-password-manager-hit-by-cyber.html) — The Hacker News

- [US Air Force cloud platform reportedly hacked in latest federal breach](https://www.bleepingcomputer.com/news/security/us-air-force-cloud-platform-reportedly-hacked-in-latest-federal-breach/) — Bleeping Computer

- [New Boston Scientific data breach exposes personal, medical info](https://www.bleepingcomputer.com/news/security/new-boston-scientific-data-breach-exposes-personal-medical-info/) — Bleeping Computer

- ['God Mode' Flaws Could Wreak Border-Control Havoc](https://www.darkreading.com/vulnerabilities-threats/god-mode-flaws-wreak-border-control-havoc) — Dark Reading

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
