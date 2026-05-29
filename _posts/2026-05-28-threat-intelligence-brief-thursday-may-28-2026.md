---
layout: post
title: "Threat Intelligence Brief - Thursday, May 28, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-05-28
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-35616
  - T1566
  - T1190
  - Fortinet
  - Windows
  - Linux
  - AI-Security
  - Anthropic
  - Claude
  - GreyVibe
  - Phishing
---

## Executive Signal

- **Immediate patch required:** CVE-2026-35616 in Fortinet FortiClient EMS is under active exploitation, delivering the EKZ credential stealer. If you run FortiClient EMS, this is a fire drill today.
- **Russia-linked GreyVibe** is using ChatGPT and Gemini to generate phishing lures and malware at scale against government and critical infrastructure targets — a confirmed shift in state-sponsored tradecraft with implications beyond Ukraine.
- **Critical RCE in Gogs** (CVSS 9.4) allows any authenticated user to execute arbitrary code on self-hosted Git instances. Development pipelines and source code repositories are directly at risk. No CVE assigned; exploitation status unknown but disclosure is public.
- **BTMOB**, an Android malware-as-a-service RAT, is actively offered with a custom payload builder — lowering the barrier for targeted mobile phishing against enterprise users.
- AI-assisted lures, credential-focused malware, and developer toolchain vulnerabilities are converging into compounding enterprise risk.

---

## Immediate Action Required

### CVE-2026-35616 — Fortinet FortiClient EMS Authentication Bypass (Active Exploitation)

Attackers are exploiting this authentication bypass in FortiClient EMS to deploy **EKZ**, an undocumented credential stealer. Active exploitation is confirmed. Credential theft from endpoint management infrastructure can cascade rapidly into broader network compromise.

**Action:** Identify all FortiClient EMS deployments. Apply Fortinet patches or mitigations immediately. Audit for EKZ indicators and review credential stores accessible from EMS-managed endpoints. Escalate to security leadership if patching cannot be completed within 24 hours.

> `CVE-2026-35616 · T1190 · FortiClient EMS · Fortinet · EKZ`

---

## High-Impact Developments

### Russia-Linked GreyVibe Uses AI to Scale Phishing and Malware Operations

- **What happened:** GreyVibe, assessed as Russia-linked, is actively targeting Ukrainian government and critical infrastructure using AI-generated phishing lures and custom malware built with ChatGPT and Gemini.
- **Why it matters:** This is a confirmed case of a state-aligned actor integrating mainstream AI into offensive operations. The tradecraft scales lure quality and volume simultaneously, degrading the effectiveness of conventional detection. Researchers assess this reflects how adversary groups will broadly operate going forward.
- **Who should care:** Security leadership, threat intelligence teams, SOC analysts, and any organization with government or critical infrastructure adjacency. The techniques are transferable beyond Ukraine-focused campaigns.
- **Recommended action:** Brief security awareness teams on AI-enhanced phishing characteristics. Validate that email security controls use behavioral and contextual detection, not only signature-based filtering. Ensure threat intelligence feeds are tracking GreyVibe TTPs.
- **Confidence:** High — corroborated by Bleeping Computer and SecurityWeek reporting.
- **Search metadata:** `T1566 · GreyVibe · ChatGPT · Gemini · Windows · State-Sponsored · Phishing · Ukraine · Government · Critical Infrastructure`

---

### Critical RCE Vulnerability in Gogs Self-Hosted Git Service

- **What happened:** A CVSS 9.4 RCE vulnerability has been disclosed in Gogs, a widely used open-source self-hosted Git platform. Any authenticated user can exploit the flaw to execute arbitrary code. No CVE has been assigned. Exploitation status is unknown; the vulnerability is publicly disclosed.
- **Why it matters:** Self-hosted Git platforms sit at the center of development pipelines. Exploitation could expose source code, embedded credentials, CI/CD secrets, and build artifacts. The low privilege bar — any authenticated user — significantly widens the attack surface in multi-user environments.
- **Who should care:** Vulnerability management, DevOps, application security, and SOC teams. Any organization running Gogs should treat this as urgent.
- **Recommended action:** Inventory Gogs deployments. Apply available patches or restrict access to trusted users pending a fix. Review repository access logs for anomalous activity. Assess whether CI/CD pipelines connected to Gogs instances have compensating controls.
- **Confidence:** High — sourced from Rapid7 research via The Hacker News.
- **Search metadata:** `T1190 · Gogs · Remote Code Execution · Linux · Windows · macOS · CVSS 9.4`

---

### BTMOB Android Malware-as-a-Service Enables Custom Phishing Payloads

- **What happened:** BTMOB, an Android remote access trojan, is offered as a service with a builder interface that generates custom phishing payloads. Active use is confirmed.
- **Why it matters:** MaaS builders commoditize sophisticated mobile attacks. Enterprise users accessing corporate resources from Android devices — email, VPN, MFA apps — are viable targets. Credential theft via mobile phishing can bypass desktop-focused controls.
- **Who should care:** Mobile security teams, SOC analysts, and security leadership at organizations with BYOD or Android-heavy mobile fleets.
- **Recommended action:** Validate that MDM policies enforce app allowlisting or restrict sideloading. Confirm mobile threat defense tooling is deployed on Android devices that access corporate resources. Brief helpdesk on BTMOB-style phishing lure patterns.
- **Confidence:** High.
- **Search metadata:** `T1566 · BTMOB · Android · Mobile · Phishing · Fraud`

---

## Monitor Only

- **Dutch law enforcement** seized 800 servers and arrested two operators of **THE.Hosting**, a Russian bulletproof hosting provider. The provider's core IP infrastructure remains intact and operational. Near-term disruption to criminal activity is limited. Threat intelligence teams should monitor for attacker infrastructure shifts associated with this provider. No direct enterprise action is warranted today.

> `THE.Hosting · Russia · Hosting Infrastructure · Disruption`

---

## Analyst Observation

Today's brief reflects where the threat landscape is: AI is a current operational tool for at least one confirmed state-linked actor, and the GreyVibe reporting warrants a realistic reassessment of phishing detection assumptions — not a future-state planning exercise. The Fortinet FortiClient EMS exploitation is the kind of story that breaches organizations still working through change management. The Gogs RCE is the sleeper item — developer tooling rarely receives the same patch urgency as perimeter infrastructure, and that gap is exactly what attackers exploit. If your organization runs Gogs and you don't know it, that's the first problem to solve.

---

## Source Links

- Hackers exploit FortiClient EMS flaw to push infostealer malware — [https://www.bleepingcomputer.com/news/security/hackers-exploit-forticlient-ems-flaw-to-push-infostealer-malware/](https://www.bleepingcomputer.com/news/security/hackers-exploit-forticlient-ems-flaw-to-push-infostealer-malware/)
- Critical Gogs RCE Vulnerability Lets Any Authenticated User Execute Arbitrary Code — [https://thehackernews.com/2026/05/critical-gogs-rce-vulnerability-lets.html](https://thehackernews.com/2026/05/critical-gogs-rce-vulnerability-lets.html)
- GreyVibe hackers use ChatGPT, Gemini to power cyberattacks — [https://www.bleepingcomputer.com/news/security/greyvibe-hackers-use-chatgpt-gemini-to-power-cyberattacks/](https://www.bleepingcomputer.com/news/security/greyvibe-hackers-use-chatgpt-gemini-to-power-cyberattacks/)
- Russia-Linked 'GreyVibe' Attackers Use AI to Supercharge Cyberattacks — [https://www.securityweek.com/russia-linked-greyvibe-attackers-use-ai-to-supercharge-cyberattacks/](https://www.securityweek.com/russia-linked-greyvibe-attackers-use-ai-to-supercharge-cyberattacks/)
- BTMOB Android malware service generates custom phishing payloads — [https://www.bleepingcomputer.com/news/security/btmob-android-malware-service-generates-custom-phishing-payloads/](https://www.bleepingcomputer.com/news/security/btmob-android-malware-service-generates-custom-phishing-payloads/)
- Dutch Raid Fails to Dent Russian Bulletproof Host — [https://www.darkreading.com/cyber-risk/dutch-raid-russian-bulletproof-host](https://www.darkreading.com/cyber-risk/dutch-raid-russian-bulletproof-host)

---

_Generated by DevSecOpsDadAttack cyber threat intelligence._
