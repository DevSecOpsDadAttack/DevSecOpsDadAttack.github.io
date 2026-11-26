---
layout: post
title: "Threat Intelligence Brief - Thursday, November 26, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-11-26
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-136716
  - T1187
  - T1056.004
  - T1190
  - T1078.004
  - T1552.007
  - T1195.001
  - T1566.002
  - Google
  - Microsoft
  - Windows-Presentation-Foundation
---

## Threat Radar

- Mitel MiCollab zero-days were exploited in an AI-assisted extortion campaign before Mitel issued an advisory — CISA has since confirmed active exploitation and added five MiCollab flaws to the KEV catalog alongside vulnerabilities in Juniper, Vates, and Danfoss products.

- Drupal faces a double-barreled crisis: a critical core vulnerability (CVE-2026-136716) enabling full site takeover is under active exploitation, compounded by an incomplete prior patch that left additional sites exposed and is also being actively abused.

- 1Password disclosed a breach in which a compromised employee GitHub account was used to steal customer data and internal source code; password vaults were not accessed, but supply-chain and identity control implications are significant.

- Exploitation is outpacing patch cycles across all three stories: zero-days hit before advisories, patch gaps are weaponized immediately, and developer credential compromise is being used as a supply-chain entry vector.

- Vulnerability management teams should cross-reference asset inventories against this week's CISA KEV additions now: 10 vulnerabilities confirmed exploited across Mitel, Juniper, Vates, and Danfoss products.

<br/>
---
<br/>

## Immediate Action Required

- **Mitel MiCollab** — Validate exposure of all MiCollab instances immediately. Five flaws are CISA KEV-confirmed and were exploited before vendor advisories were published. Patch or isolate now — do not wait for a scheduled maintenance window. *T1190*

- **Drupal** — Apply the latest Drupal core update addressing CVE-2026-136716 and verify that prior installer patches were fully applied. Sites that believed they were patched may still be vulnerable. Treat as unpatched until explicitly confirmed otherwise. *CVE-2026-136716, T1190*

- **1Password enterprise users** — Review all integrations, API tokens, and automation pipelines that depend on 1Password. Audit GitHub access controls for developer accounts across your organization in parallel. *T1078.004, T1552.007*

- **CISA KEV — Juniper, Vates, Danfoss** — If any of these products are in your environment, confirm patch status against this week's KEV additions. Federal agencies face mandatory remediation deadlines; all others should treat KEV listings as high-priority signals requiring immediate triage.

<br/>
---
<br/>

## High-Impact Developments

### Mitel MiCollab Zero-Days Exploited Before Vendor Advisory, CISA Confirms Active Exploitation Across 10 Vulnerabilities

- **What happened:** Accenture reported that threat actors exploited zero-day vulnerabilities in Mitel MiCollab before Mitel issued any advisory, with the attack suspected to be AI-assisted and tied to an extortion campaign. CISA subsequently added five MiCollab vulnerabilities — along with flaws in Juniper, Vates, and Danfoss products — to its Known Exploited Vulnerabilities catalog, bringing the total new KEV additions to 10.

- **Why it matters:** Pre-advisory exploitation eliminates the window organizations rely on to patch before attacks begin. The AI-assistance angle is unconfirmed but consistent with accelerating attacker capability to discover and weaponize vulnerabilities. CISA KEV confirmation across four vendor platforms in a single update signals broad, active threat activity — not isolated incidents.

- **Who should care:** Communications infrastructure owners, enterprise IT, vulnerability management leads, SOC teams, and network operations teams running any of the affected vendor products.

- **Recommended action:** Immediately audit MiCollab deployment exposure and apply all available patches. For Juniper, Vates, and Danfoss, cross-reference KEV additions against your asset inventory and escalate unpatched instances. If MiCollab is internet-facing, restrict access while patching is validated.

- **Confidence:** High — CISA KEV listing and Accenture reporting corroborate active exploitation.

- **Search metadata:** T1190 | Mitel MiCollab, Juniper, Vates, Danfoss | CISA KEV

**Intelligence Context**
- [Mitel MiCollab Zero-Days Exploited in Suspected AI-Assisted Attacks — SecurityWeek](https://www.securityweek.com/mitel-micollab-zero-days-exploited-in-suspected-ai-assisted-attacks/)
  - Context: Accenture's findings detail pre-advisory exploitation of MiCollab zero-days in a suspected AI-assisted extortion campaign, establishing the threat actor's operational tempo ahead of vendor response.

- [Hackers Exploit 10 Vulnerabilities Across Mitel, Juniper, Vates, and Danfoss Products — The Hacker News](https://thehackernews.com/2026/11/hackers-exploit-10-vulnerabilities.html)
  - Context: Confirms CISA's KEV catalog update adding 10 actively exploited vulnerabilities, including the five MiCollab flaws, providing authoritative confirmation of exploitation scope across multiple vendor platforms.

<br/>
---
<br/>

### Drupal Critical Vulnerabilities Under Active Exploitation — Core Flaw and Patch Gap Both Being Abused

- **What happened:** Drupal disclosed two concurrent exploitation incidents. CVE-2026-136716, a highly critical core vulnerability involving improper handling of exceptional conditions, is being actively exploited in the wild and enables full site takeover. Separately, Drupal warned that a prior installer patch was incomplete, leaving a residual vulnerability that attackers are already exploiting independently.

- **Why it matters:** Organizations that applied the previous Drupal patch may have a false sense of security. A new critical core flaw and an exploited patch gap mean Drupal environments face active risk on two fronts simultaneously. Site takeover enables defacement, data theft, malware staging, and persistent footholds.

- **Who should care:** Web operations teams, application security, vulnerability management leads, and any organization running public-facing or internal Drupal-based sites.

- **Recommended action:** Apply the latest Drupal core update immediately. Do not assume prior patching is sufficient — explicitly verify the installer patch gap has been addressed. Review web server logs for indicators of compromise on Drupal instances, particularly anomalous file writes or privilege escalation activity.

- **Confidence:** High — Drupal's own advisories and multiple corroborating sources confirm active exploitation of both issues.

- **Search metadata:** CVE-2026-136716, T1190 | Drupal

**Intelligence Context**
- [Drupal Warns of New Highly Critical Site Takeover Vulnerability Under Active Exploitation — The Hacker News](https://thehackernews.com/2026/11/drupal-warns-of-new-highly-critical.html)
  - Context: Details CVE-2026-136716 as a highly critical Drupal core flaw actively exploited in the wild, rooted in improper exception handling, enabling full site takeover.

- [Drupal Installer Patch Left a Gap Attackers Are Already Exploiting — SecurityWeek](https://www.securityweek.com/drupal-installer-patch-left-a-gap-attackers-are-already-exploiting/)
  - Context: Confirms a separate, concurrent exploitation path where an incomplete prior patch left Drupal sites vulnerable, with attackers already actively targeting the residual gap.

<br/>
---
<br/>

### 1Password Breached via Compromised GitHub Account — Customer Data and Source Code Stolen

- **What happened:** 1Password disclosed that an attacker used a compromised employee GitHub account to push malicious code and exfiltrate customer records and internal source code. Password vaults were not accessed. The breach vector was developer credential compromise leading to unauthorized repository access.

- **Why it matters:** Even without vault access, source code exposure from a password management vendor carries meaningful supply-chain risk — it may reveal architectural details, internal APIs, or security logic that could inform future attacks. Developer identity controls are a critical attack surface, not an IT hygiene afterthought.

- **Who should care:** Security leadership, vendor risk management, IAM teams, and software engineering organizations that use 1Password or rely on GitHub as a development platform.

- **Recommended action:** Audit your organization's GitHub access controls, enforce phishing-resistant MFA on all developer accounts, and review third-party integrations with 1Password. Engage vendor risk processes to assess whether 1Password's source code exposure creates downstream risk for your deployment. Monitor for follow-on 1Password security advisories.

- **Confidence:** High — 1Password disclosed the incident directly; vault compromise is explicitly denied by the vendor.

- **Search metadata:** T1078.004, T1552.007 | 1Password | GitHub

**Intelligence Context**
- [1Password Hacked, Customer Data and Source Code Stolen in GitHub Account Breach — The Hacker News](https://thehackernews.com/2026/11/1password-hacked-customer-data-and.html)
  - Context: 1Password's disclosure confirms unauthorized access to customer information and source code via a compromised GitHub account, with explicit confirmation that password vaults were not accessed.

- [1Password Breach Exposes Customer Data, Internal Source Code — SecurityWeek](https://www.securityweek.com/1password-breach-exposes-customer-data-internal-source-code/)
  - Context: Corroborates the breach mechanism — a compromised employee GitHub account used to push malicious code — and reinforces the supply-chain and developer identity risk dimensions of the incident.

<br/>
---
<br/>

## Monitor Only

- No additional items from today's article set crossed the immediate action or high-impact threshold. All sourced stories are addressed above.

<br/>
---
<br/>

## Analyst Observation

Today's brief exposes a threat environment where the patch-then-protect model is failing in real time. Mitel MiCollab was exploited before Mitel published an advisory — that's not a patch management failure, it's a failure of the entire model. Drupal's situation is arguably worse: organizations that patched in good faith remain exposed because the patch was incomplete. The 1Password breach is a pointed reminder that security vendors are not exempt from the same developer identity risks they help their customers manage. The common thread is that patch status alone is not a reliable indicator of security posture. Teams need visibility into active exploitation activity, and developer credential compromise must be treated as a first-class threat vector.

<br/>
---
<br/>

## Source Links

- Mitel MiCollab Zero-Days Exploited in Suspected AI-Assisted Attacks — SecurityWeek — [https://www.securityweek.com/mitel-micollab-zero-days-exploited-in-suspected-ai-assisted-attacks/](https://www.securityweek.com/mitel-micollab-zero-days-exploited-in-suspected-ai-assisted-attacks/)

- Hackers Exploit 10 Vulnerabilities Across Mitel, Juniper, Vates, and Danfoss Products — The Hacker News — [https://thehackernews.com/2026/11/hackers-exploit-10-vulnerabilities.html](https://thehackernews.com/2026/11/hackers-exploit-10-vulnerabilities.html)

- Drupal Warns of New Highly Critical Site Takeover Vulnerability Under Active Exploitation — The Hacker News — [https://thehackernews.com/2026/11/drupal-warns-of-new-highly-critical.html](https://thehackernews.com/2026/11/drupal-warns-of-new-highly-critical.html)

- Drupal Installer Patch Left a Gap Attackers Are Already Exploiting — SecurityWeek — [https://www.securityweek.com/drupal-installer-patch-left-a-gap-attackers-are-already-exploiting/](https://www.securityweek.com/drupal-installer-patch-left-a-gap-attackers-are-already-exploiting/)

- 1Password Hacked, Customer Data and Source Code Stolen in GitHub Account Breach — The Hacker News — [https://thehackernews.com/2026/11/1password-hacked-customer-data-and.html](https://thehackernews.com/2026/11/1password-hacked-customer-data-and.html)

- 1Password Breach Exposes Customer Data, Internal Source Code — SecurityWeek — [https://www.securityweek.com/1password-breach-exposes-customer-data-internal-source-code/](https://www.securityweek.com/1password-breach-exposes-customer-data-internal-source-code/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
