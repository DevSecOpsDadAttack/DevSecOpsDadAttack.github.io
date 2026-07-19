---
layout: post
title: "Threat Intelligence Brief - Sunday, July 19, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-19
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1190
  - T1555
  - T1187
  - T1499
  - T1548
  - T1195
  - T1219
  - Microsoft
  - LabCentral
  - Linux
  - 7-Zip
---

## Threat Radar

- **Inc ransomware is actively chaining two SonicWall SMA zero-days** to achieve root-level access on edge appliances — confirmed exploitation in the wild makes this the highest-priority item today.

- **WordPress Core "wp2shell" RCE flaws now have public exploits** and are being actively exploited; any internet-facing WordPress installation should be treated as at-risk until patched.

- **ACR Stealer activity is surging against enterprise environments**, targeting browser-stored credentials and authentication tokens — a direct precursor to account takeover and lateral movement.

- **Seven malicious npm packages (ViteVenom/ChainVeil)** are targeting the Vite frontend ecosystem, delivering a RAT via blockchain-based C2 — development and DevOps pipelines are the exposure surface.

- **7-Zip patched an RCE flaw** exploitable via crafted archives; exploitation is unconfirmed but the attack vector is trivially weaponizable in phishing campaigns.

<br/>
---
<br/>

## Immediate Action Required

- **SonicWall SMA — Zero-Day Ransomware Exploitation (Active):** Identify all internet-exposed SonicWall SMA appliances immediately. Apply vendor patches or implement compensating controls. Treat any unpatched SMA device as potentially compromised. Escalate to IT operations and executive leadership. | T1190, T1548

- **WordPress Core — wp2shell RCE (Active Exploitation + Public Exploit):** Patch all WordPress Core installations now. Public exploit availability combined with confirmed in-the-wild exploitation compresses the response window to hours, not days. Validate auto-update status across all managed WordPress properties. | T1190

<br/>
---
<br/>

## High-Impact Developments

### Inc Ransomware Chains Two SonicWall SMA Zero-Days for Root Access

- **What happened:** The Inc ransomware group is exploiting two chained zero-day vulnerabilities in SonicWall Secure Mobile Access (SMA) appliances. Combined, the flaws allow unauthenticated attackers to escalate to root-level access, enabling full network compromise from the edge.

- **Why it matters:** Edge appliance zero-days in active ransomware campaigns represent one of the fastest paths to enterprise-wide encryption and business interruption. There is no patch window when exploitation is already underway.

- **Who should care:** Network security, IT operations, SOC teams, and executive leadership at any organization running SonicWall SMA appliances.

- **Recommended action:** Immediately audit SMA device exposure. Apply SonicWall patches as soon as available; if patches are not yet released, restrict internet-facing access and review recent authentication logs for anomalous root-level activity. Engage incident response resources proactively.

- **Confidence:** High — confirmed active exploitation reported by Dark Reading.

- **Search metadata:** T1190, T1548, SonicWall SMA, Inc ransomware, Ransomware, Privilege Escalation

**Intelligence Context**
- [Inc Ransomware Exploits SonicWall SMA Zero-Days](https://www.darkreading.com/vulnerabilities-threats/inc-ransomware-exploits-sonicwall-sma-zero-days) — Dark Reading
  - Context: Confirms active exploitation of two chained SonicWall SMA zero-days by the Inc ransomware group, with the combined flaw chain enabling root-level access on mobile access appliances.

<br/>
---
<br/>

### WordPress Core "wp2shell" RCE — Public Exploits, Active Exploitation

- **What happened:** Critical remote code execution vulnerabilities in WordPress Core, tracked under the "wp2shell" designation, now have publicly available exploit code and are being actively exploited against internet-facing sites.

- **Why it matters:** A critical RCE with public exploit code and confirmed in-the-wild exploitation means the barrier to attack is near zero. Any unpatched WordPress site is an immediate target.

- **Who should care:** Web operations, IT operations, digital business owners, and security teams managing any WordPress-based web presence.

- **Recommended action:** Patch WordPress Core immediately across all managed instances. Verify auto-update configurations. Review web server logs for indicators of exploitation. Treat unpatched sites as compromised until confirmed otherwise.

- **Confidence:** High — confirmed active exploitation with public exploits reported by Bleeping Computer.

- **Search metadata:** T1190, WordPress Core, wp2shell, Remote Code Execution

**Intelligence Context**
- [WordPress Core "wp2shell" RCE flaws get public exploits, patch now](https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/) — Bleeping Computer
  - Context: Reports that public exploits are now available for the wp2shell RCE vulnerabilities in WordPress Core and that active exploitation is underway, with an explicit recommendation to patch immediately.

<br/>
---
<br/>

### ACR Stealer Surge Targeting Enterprise Credentials and Tokens

- **What happened:** Microsoft has warned of a significant increase in ACR Stealer malware campaigns targeting enterprise customers. The malware harvests browser-stored passwords, authentication tokens, and sensitive documents from infected endpoints.

- **Why it matters:** Stolen authentication tokens bypass MFA and enable direct account takeover without credential reuse. Token theft is a primary enabler of downstream breaches, cloud environment compromise, and lateral movement.

- **Who should care:** IAM teams, SOC analysts, and security operations leads at enterprise organizations — particularly those with Microsoft 365 or Azure environments.

- **Recommended action:** This week: review endpoint protection coverage for stealer-class malware, assess browser credential storage policies, and evaluate token lifetime and conditional access configurations. Investigate anomalous authentication events from any endpoints that may have been exposed.

- **Confidence:** High — Microsoft direct advisory.

- **Search metadata:** T1555, T1187, ACR Stealer, Credential Theft, Information Theft

**Intelligence Context**
- [Microsoft warns of surge in ACR Stealer attacks on customers](https://www.bleepingcomputer.com/news/security/microsoft-warns-of-surge-in-acr-stealer-attacks-on-customers/) — Bleeping Computer
  - Context: Microsoft directly observed and reported the surge in ACR Stealer activity targeting its enterprise customers, with the malware specifically harvesting browser credentials, authentication tokens, and sensitive documents.

<br/>
---
<br/>

### ViteVenom Supply Chain Attack Delivers RAT via Blockchain C2

- **What happened:** Checkmarx researchers identified seven malicious npm packages impersonating legitimate Vite frontend tooling. The packages, part of the ViteVenom campaign — an expansion of the broader ChainVeil operation — deliver a remote access trojan using blockchain infrastructure for command-and-control, making C2 traffic resistant to traditional domain-based blocking.

- **Why it matters:** Developers installing typosquatted or dependency-confused packages introduce persistent RAT access directly into build environments. Blockchain-based C2 complicates detection and blocking. A compromised build pipeline can propagate malicious code into downstream software products.

- **Who should care:** Software development leads, DevOps and DevSecOps teams, and security architects responsible for software supply chain integrity.

- **Recommended action:** This week: audit npm dependencies in projects using Vite for the seven identified malicious packages. Review package integrity controls, enforce lockfiles, and validate dependency sources. Determine whether any affected packages were pulled into CI/CD pipelines or production builds.

- **Confidence:** High — researcher-confirmed, active campaign.

- **Search metadata:** T1195, T1219, ViteVenom, ChainVeil, npm, Vite, Supply Chain Attack, Remote Access Trojan

**Intelligence Context**
- [Seven Malicious Vite npm Packages Use Blockchain C2 to Deliver a RAT](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html) — The Hacker News
  - Context: Details the ViteVenom campaign's seven malicious npm packages targeting the Vite ecosystem, its connection to the ChainVeil operation, and the use of blockchain infrastructure for C2 communications.

<br/>
---
<br/>

### 7-Zip RCE Patched — Update to Version 26.02

- **What happened:** 7-Zip released version 26.02 to address a remote code execution vulnerability triggered when a user opens a specially crafted compressed archive — a natural fit for phishing-based delivery.

- **Why it matters:** 7-Zip is ubiquitous across enterprise endpoints. Active exploitation is unconfirmed, but the attack vector is low-friction and the utility is rarely managed through formal patch channels, meaning deployments frequently lag behind current versions.

- **Who should care:** IT operations and vulnerability management teams responsible for endpoint software inventory.

- **Recommended action:** Deploy 7-Zip version 26.02 across managed endpoints this week. Prioritize systems where users routinely handle externally sourced archive files.

- **Confidence:** High — vendor-confirmed patch; exploitation status unconfirmed.

- **Search metadata:** T1190, 7-Zip, Remote Code Execution

**Intelligence Context**
- [Update now: 7-Zip fixes RCE flaw exploitable with malicious archives](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/) — Bleeping Computer
  - Context: Confirms the release of 7-Zip 26.02 to address an RCE vulnerability exploitable via malicious compressed files, with the source explicitly recommending immediate update.

<br/>
---
<br/>

## Monitor Only

- Abbott Laboratories is investigating two separate cybersecurity incidents — unauthorized access to legacy Exact Sciences systems in its Cancer Diagnostics unit and a claimed breach of its LabCentral portal with data theft — both accompanied by extortion claims. Healthcare sector peers and organizations with shared vendor relationships should monitor for further disclosures. **Source:** Abbott probes two cyber incidents amid extortion claims — [https://www.bleepingcomputer.com/news/security/abbott-laboratories-probes-two-cyber-incidents-amid-extortion-claims/](https://www.bleepingcomputer.com/news/security/abbott-laboratories-probes-two-cyber-incidents-amid-extortion-claims/)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment actively punishing deferred patching on edge infrastructure and developer tooling simultaneously. The SonicWall SMA situation is the clearest operational emergency: ransomware operators with zero-day capability on remote access appliances can move from initial access to full network encryption faster than most incident response cycles can engage. The WordPress and 7-Zip items are textbook examples of why deferring patches on widely deployed, internet-facing or user-adjacent software is not viable — public exploits eliminate the grace period. ViteVenom deserves attention from security architects who may lack visibility into what their development teams are pulling from npm. The ACR Stealer surge is a reminder that endpoint credential hygiene and token lifetime policies are active mitigations against a campaign Microsoft is tracking right now, not theoretical controls.

<br/>
---
<br/>

## Source Links

- Inc Ransomware Exploits SonicWall SMA Zero-Days — [https://www.darkreading.com/vulnerabilities-threats/inc-ransomware-exploits-sonicwall-sma-zero-days](https://www.darkreading.com/vulnerabilities-threats/inc-ransomware-exploits-sonicwall-sma-zero-days)

- WordPress Core "wp2shell" RCE flaws get public exploits, patch now — [https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/](https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/)

- Microsoft warns of surge in ACR Stealer attacks on customers — [https://www.bleepingcomputer.com/news/security/microsoft-warns-of-surge-in-acr-stealer-attacks-on-customers/](https://www.bleepingcomputer.com/news/security/microsoft-warns-of-surge-in-acr-stealer-attacks-on-customers/)

- Seven Malicious Vite npm Packages Use Blockchain C2 to Deliver a RAT — [https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)

- Update now: 7-Zip fixes RCE flaw exploitable with malicious archives — [https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)

- Abbott probes two cyber incidents amid extortion claims — [https://www.bleepingcomputer.com/news/security/abbott-laboratories-probes-two-cyber-incidents-amid-extortion-claims/](https://www.bleepingcomputer.com/news/security/abbott-laboratories-probes-two-cyber-incidents-amid-extortion-claims/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
