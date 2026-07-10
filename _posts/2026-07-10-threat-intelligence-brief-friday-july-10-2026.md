---
layout: post
title: "Threat Intelligence Brief - Friday, July 10, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-10
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1110
  - T1190
  - T1059
  - T1059.004
  - T1105
  - T1195.001
  - Microsoft
  - Windows
  - Linux
  - OpenMandriva-Linux
  - Windows-Defender
---

## Threat Radar

- **RoguePlanet** zero-day in Windows Defender is actively exploited with a public PoC in circulation — every Windows enterprise environment is exposed until patched.

- **Ill Bloom** cryptographic flaw in wallet recovery phrase generation has already produced $3.1M in confirmed losses — active exploitation is ongoing, not theoretical.

- **Developer supply chain under coordinated assault**: two simultaneous campaigns weaponize GitHub and npm — one via 200 malicious Go module repositories, one via a compromised Injective Labs SDK — both targeting cryptocurrency credentials.

- **GigaWiper** introduces a hybrid destructive capability combining wiper, ransomware encryption, and multi-pass data destruction — active exploitation is unconfirmed, but the tooling is operationally ready.

- **Insider-enabled ransomware**: a DigitalMint employee facilitated BlackCat attacks against the clients his firm was hired to protect, resulting in a 70-month federal sentence.

<br/>
---
<br/>

## Immediate Action Required

- **RoguePlanet / Windows Defender Zero-Day** — Validate patch status across all Windows endpoints now. A public PoC from researcher Nightmare-Eclipse is available and exploitation is confirmed. Endpoint and vulnerability management teams should treat this as a priority-one patch cycle, not a scheduled update.

- **Ill Bloom / Cryptocurrency Wallet Exposure** — If your organization holds or manages digital assets in software wallets, audit which wallet software is in use and whether affected versions were used during wallet creation. Wallets generated with weak entropy in recovery phrase generation are at direct financial risk. Rotate or migrate affected wallets immediately.

- **GitHub / npm Supply Chain Campaigns** — Audit Go module dependencies and npm packages for recent additions or unexpected updates. Verify the integrity of the Injective Labs SDK if it is in use. Treat any unreviewed third-party package pulled from GitHub or npm as potentially compromised until confirmed clean.

<br/>
---
<br/>

## High-Impact Developments

### RoguePlanet: Windows Defender Zero-Day with Public PoC and Confirmed Exploitation

- **What happened:** Researcher Nightmare-Eclipse published a proof-of-concept exploit for a Windows Defender zero-day dubbed RoguePlanet. The same researcher has previously disclosed multiple Microsoft zero-days. Active exploitation is confirmed.

- **Why it matters:** Windows Defender is the default endpoint protection layer across virtually every enterprise Windows environment. A zero-day that undermines it — with a public PoC accelerating attacker adoption — removes a foundational defensive control at scale.

- **Who should care:** Endpoint security teams, SOC leaders, vulnerability management leads, and CISOs responsible for Windows infrastructure.

- **Recommended action:** Prioritize patching across all Windows endpoints. Confirm whether Microsoft has issued a fix and track patch deployment to completion. Escalate to leadership if patch availability is delayed.

- **Confidence:** High

- **Search metadata:** Windows Defender, Windows, Microsoft, RoguePlanet, zero-day vulnerability

**Intelligence Context**
- [Microsoft Reins in RoguePlanet Zero-Day Threat](https://www.darkreading.com/vulnerabilities-threats/microsoft-rogueplanet-zero-day-threat) — Dark Reading
  - Context: Confirms active exploitation of the RoguePlanet Windows Defender zero-day and identifies Nightmare-Eclipse as the researcher who published the PoC after previously dropping multiple Microsoft zero-days.

<br/>
---
<br/>

### Ill Bloom: Active Exploitation of Cryptographic Weakness Drains $3.1M from Wallets

- **What happened:** Coinspect disclosed a vulnerability called Ill Bloom affecting cryptocurrency wallet software that generates recovery phrases using weak randomness. Attackers can derive wallet credentials from the flawed entropy and drain funds. $3.1M in losses are confirmed.

- **Why it matters:** Funds are being stolen now. The flaw is in the foundational cryptographic operation of wallet creation, meaning any wallet generated with affected software may be permanently compromised regardless of subsequent user behavior.

- **Who should care:** Digital asset teams, security architects responsible for cryptographic implementations, IAM leads, and executive leadership with fiduciary exposure to digital asset holdings.

- **Recommended action:** Identify all wallet software in use across the organization. Determine whether affected versions were used during wallet creation. Migrate assets from potentially compromised wallets to newly generated wallets using verified, cryptographically sound software.

- **Confidence:** High

- **Search metadata:** Ill Bloom, cryptocurrency wallet software, T1110, credential theft, vulnerability

**Intelligence Context**
- [Attackers Exploit 'Ill Bloom' Vulnerability to Drain $3.1 Million From Cryptocurrency Wallets](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html) — The Hacker News
  - Context: Coinspect's disclosure details how weak randomness in recovery phrase generation allows attackers to derive wallet credentials and confirms $3.1M in active losses.

<br/>
---
<br/>

### Coordinated Supply Chain Attacks Weaponize GitHub and npm Against Cryptocurrency Targets

- **What happened:** Two concurrent campaigns are exploiting developer infrastructure. First, a network of 200 GitHub repositories distributes Windows malware via malicious Go modules that load PowerShell to fetch and execute payloads from dead drops. Second, attackers compromised the Injective Labs SDK GitHub repository and published a malicious npm package that harvests cryptocurrency wallet private keys and mnemonic seed phrases from downstream users.

- **Why it matters:** Both campaigns exploit the implicit trust developers place in GitHub and npm. The scale — 200 repositories in one campaign alone — and the consistent targeting of cryptocurrency credentials indicate a deliberate, resource-intensive operation. Any developer or pipeline that consumed affected packages may have already exfiltrated wallet secrets.

- **Who should care:** Software supply chain owners, developers, SOC teams monitoring build pipelines, and digital asset security teams.

- **Recommended action:** Audit Go module and npm dependency trees for unexpected packages or recent version changes. Check specifically for the compromised Injective Labs SDK. Review CI/CD pipeline logs for anomalous PowerShell execution or outbound connections to unfamiliar endpoints. Treat any wallet-related secrets in affected environments as compromised.

- **Confidence:** High

- **Search metadata:** GitHub, npm, Injective SDK, Injective Labs, T1195.001, T1059.004, T1105, PowerShell, Windows, supply chain attack, credential theft

**Intelligence Context**
- [Network of 200 GitHub Repositories Used for Malware Infection](https://www.securityweek.com/network-of-200-github-repositories-used-for-malware-infection/) — SecurityWeek
  - Context: Details the Go module-based distribution network using PowerShell and dead drops to deliver Windows malware across 200 GitHub repositories.

- [Injective SDK on npm infected with cryptocurrency wallet stealer](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/) — Bleeping Computer
  - Context: Confirms the Injective Labs SDK GitHub repository was compromised and used to publish a malicious npm package stealing private keys and seed phrases from downstream users.

<br/>
---
<br/>

## Monitor Only

- **GigaWiper** is a newly identified backdoor combining standalone wiper, ransomware encryption, and multi-pass data destruction — active exploitation is unconfirmed, but the hybrid capability represents a high-consequence threat to business continuity if deployed. Verify offline backup integrity and test recovery procedures. **Source:** GigaWiper Combines Multiple Malware for System-Level Sabotage — [https://www.securityweek.com/gigawiper-combines-multiple-malware-for-system-level-sabotage/](https://www.securityweek.com/gigawiper-combines-multiple-malware-for-system-level-sabotage/)

- A former DigitalMint employee was sentenced to 70 months in federal prison for facilitating BlackCat (ALPHV) ransomware attacks against the firm's own clients — a concrete data point that incident response and negotiation vendors carry insider risk warranting contractual and access controls review. **Source:** Former ransomware negotiator gets 4 years for BlackCat attacks — [https://www.bleepingcomputer.com/news/security/us-ransomware-negotiator-gets-4-years-in-prison-for-blackcat-attacks/](https://www.bleepingcomputer.com/news/security/us-ransomware-negotiator-gets-4-years-in-prison-for-blackcat-attacks/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment where attackers are systematically targeting the trust layers organizations rely on: endpoint protection (RoguePlanet), cryptographic key generation (Ill Bloom), and software dependency infrastructure (GitHub/npm). The cryptocurrency focus across three separate stories is not coincidental — digital asset credentials are high-value, often inadequately protected, and increasingly targeted through both direct exploitation and supply chain poisoning. The GigaWiper disclosure warrants watching precisely because hybrid wiper-ransomware tooling historically precedes targeted destructive campaigns; absence of confirmed exploitation today is not a guarantee of tomorrow. The DigitalMint case is operationally useful as a forcing function: if your organization engages third-party IR or negotiation vendors, review what access those vendors hold and what contractual obligations govern their conduct.

<br/>
---
<br/>

## Source Links

- Attackers Exploit 'Ill Bloom' Vulnerability to Drain $3.1 Million From Cryptocurrency Wallets — [https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)

- Microsoft Reins in RoguePlanet Zero-Day Threat — [https://www.darkreading.com/vulnerabilities-threats/microsoft-rogueplanet-zero-day-threat](https://www.darkreading.com/vulnerabilities-threats/microsoft-rogueplanet-zero-day-threat)

- GigaWiper Combines Multiple Malware for System-Level Sabotage — [https://www.securityweek.com/gigawiper-combines-multiple-malware-for-system-level-sabotage/](https://www.securityweek.com/gigawiper-combines-multiple-malware-for-system-level-sabotage/)

- Network of 200 GitHub Repositories Used for Malware Infection — [https://www.securityweek.com/network-of-200-github-repositories-used-for-malware-infection/](https://www.securityweek.com/network-of-200-github-repositories-used-for-malware-infection/)

- Injective SDK on npm infected with cryptocurrency wallet stealer — [https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/)

- Former ransomware negotiator gets 4 years for BlackCat attacks — [https://www.bleepingcomputer.com/news/security/us-ransomware-negotiator-gets-4-years-in-prison-for-blackcat-attacks/](https://www.bleepingcomputer.com/news/security/us-ransomware-negotiator-gets-4-years-in-prison-for-blackcat-attacks/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
