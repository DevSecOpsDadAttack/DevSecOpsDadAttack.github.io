---
layout: post
title: "Threat Intelligence Brief - Monday, October 26, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-10-26
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-109618
  - CVE-2026-109619
  - T1190
  - T1111
  - T1056.004
  - T1195.001
  - T1187
  - T1528
  - T1552.007
  - T1021.004
  - T1548
---

## Threat Radar

- **PHP2Shell RCE (CVE-2026-109618, CVE-2026-109619) is being actively exploited** — internet-facing PHP environments require emergency patching and threat hunting now.

- **A Microsoft 365 AitM token-replay campaign has already compromised 97 accounts across 79 organizations**, bypassing MFA — token lifetime controls and session policies require immediate review.

- **Google's Brotli decoder carries an out-of-bounds write flaw** that cascades across Node.js, .NET, PowerShell, and Python on Windows, Linux, and macOS — broad patching urgency across runtimes.

- **Developer supply chains are under simultaneous attack**: Gheist is exfiltrating secrets from GitHub Actions logs using stolen tokens, while a separate prompt-injection campaign is manipulating AI coding agents into installing malicious npm packages.

- **uCreator Android spyware is actively stealing Telegram 2FA credentials and cloning WeChat accounts** via trojanized apps distributed outside official stores — employee mobile devices are a live exposure vector.

<br/>
---
<br/>

## Immediate Action Required

- **PHP2Shell — Patch or mitigate now.** CVE-2026-109618 and CVE-2026-109619 are confirmed exploited in the wild against internet-facing PHP environments. Apply available patches, validate exposure, and initiate threat hunting for signs of compromise. *T1190*

- **Microsoft 365 token-replay — Review session and token controls today.** An AitM relay campaign has successfully bypassed MFA and compromised accounts at scale. Audit token lifetime policies in Entra ID, enforce Continuous Access Evaluation (CAE), and review sign-in logs for anomalous session reuse. *T1187, T1528*

<br/>
---
<br/>

## High-Impact Developments

### PHP2Shell RCE Vulnerabilities Actively Exploited in the Wild

- **What happened:** Two critical remote code execution vulnerabilities — CVE-2026-109618 and CVE-2026-109619, collectively tracked as PHP2Shell — have been confirmed exploited in the wild against internet-facing PHP environments.

- **Why it matters:** Confirmed in-the-wild exploitation removes any grace period. Unpatched PHP-based web applications are an open door to full server compromise, data exfiltration, and lateral movement.

- **Who should care:** Security leadership, vulnerability management, web application owners, incident response teams.

- **Recommended action:** Apply vendor patches immediately. Where patching is not immediately possible, restrict external access to PHP endpoints and initiate threat hunting for indicators of exploitation. Validate patch status across all internet-facing PHP assets.

- **Confidence:** High — confirmed active exploitation reported by Bleeping Computer.

- **Search metadata:** CVE-2026-109618, CVE-2026-109619, T1190, Remote Code Execution, PHP2Shell

**Intelligence Context**
- [PHP2Shell security flaws now successfully exploited in the wild](https://www.bleepingcomputer.com/news/security/php2shell-security-flaws-now-sucessfully-exploited-in-the-wild/) — Bleeping Computer
  - Context: Bleeping Computer confirmed active in-the-wild exploitation of both CVE-2026-109618 and CVE-2026-109619, establishing this as an emergency-tier patching event for any organization running internet-facing PHP.

<br/>
---
<br/>

### Microsoft 365 Token-Replay AitM Campaign Compromises Accounts Across 79 Organizations

- **What happened:** Researchers at Huntress documented an adversary-in-the-middle relay campaign that captured Microsoft 365 sign-in sessions and replayed stolen authentication tokens to access email accounts — compromising 97 accounts across 79 organizations while bypassing MFA entirely.

- **Why it matters:** Token replay is a post-MFA attack. Organizations treating MFA as a complete control against account takeover are exposed. The scale — 79 organizations — indicates an automated, opportunistic campaign with broad targeting.

- **Who should care:** Security leadership, identity and access management teams, SOC, Microsoft 365 administrators.

- **Recommended action:** Audit token lifetime and session policies in Entra ID. Enable Continuous Access Evaluation where not already deployed. Review sign-in logs for token reuse from unexpected locations or devices. Enforce phishing-resistant MFA (FIDO2) for high-value accounts.

- **Confidence:** High — documented by Huntress with specific victim counts.

- **Search metadata:** T1187, T1528, Microsoft 365, AitM, token-replay, Account Compromise

**Intelligence Context**
- [Microsoft 365 Token-Replay Attacks Compromise 97 Accounts at 79 Organizations](https://thehackernews.com/2026/10/microsoft-365-token-replay-attacks.html) — The Hacker News
  - Context: The Hacker News reported Huntress's findings detailing the AitM relay mechanism used to capture and replay session tokens, confirming successful MFA bypass at scale across dozens of organizations.

<br/>
---
<br/>

### Node2Shell: Brotli Decoder Flaw Requires Broad Patching Across Node.js, .NET, Python

- **What happened:** An out-of-bounds write vulnerability in Google's Brotli compression decoder enables code execution and affects Node.js, .NET, PowerShell, and Python packages across Windows, Linux, and macOS. Vendors including Google and Microsoft are issuing patches.

- **Why it matters:** Brotli is embedded across multiple runtimes and platforms. A single library flaw creates a wide, heterogeneous patching surface that is easy to miss in standard patch cycles. Exploitation status is currently unknown, but the code execution potential makes this high priority.

- **Who should care:** Vulnerability management, platform engineering, application owners, security leadership.

- **Recommended action:** Inventory all environments running affected runtimes — Node.js, .NET, PowerShell, Python — across Windows, Linux, and macOS. Prioritize patching this week as vendor updates become available. Monitor exploitation status closely; this flaw has the profile to attract rapid weaponization.

- **Confidence:** High — reported by SecurityWeek; exploitation status unknown.

- **Search metadata:** T1190, Brotli, Node.js, .NET, PowerShell, Python, Windows, Linux, macOS, Code Execution

**Intelligence Context**
- [Node2Shell: Brotli Flaw Triggers Patching Across Microsoft, Node.js, Python Packages](https://www.securityweek.com/node2shell-brotli-flaw-triggers-patching-across-microsoft-node-js-python-packages/) — SecurityWeek
  - Context: SecurityWeek reported the out-of-bounds write flaw in Google's Brotli decoder and confirmed that Microsoft, the Node.js project, and Python package maintainers are all issuing patches, underscoring the cross-platform patching urgency.

<br/>
---
<br/>

### Developer Supply Chain Under Attack: GitHub Secrets Theft and AI Coding Agent Manipulation

- **What happened:** Two concurrent campaigns are targeting developer environments. The Gheist campaign uses stolen GitHub tokens to inject malicious workflows into repositories, causing secrets to be printed into GitHub Actions logs before the attacker downloads and deletes the run — affecting both private repositories and GitHub Enterprise. Separately, a prompt-injection attack placed a malicious instruction file in a developer's Downloads folder directing an AI coding agent to install a known-malicious npm package.

- **Why it matters:** These attacks target the software factory itself. Gheist can expose API keys, cloud credentials, and signing secrets embedded in CI/CD pipelines. The AI coding agent attack confirms that prompt injection has moved from theoretical to operational — adversaries are weaponizing developer AI tooling to introduce malicious dependencies into production code.

- **Who should care:** Security leadership, software engineering, DevOps, supply chain security, AI governance teams.

- **Recommended action:** For Gheist: audit GitHub token permissions, rotate tokens with broad repository access, review Actions log retention settings, and scan recent workflow runs for unauthorized additions. For AI agent manipulation: define and enforce policies governing what AI coding agents are permitted to install, and ensure developer workstations are not inadvertently exposing instruction files to agent context.

- **Confidence:** High — both incidents confirmed as active exploitation events.

- **Search metadata:** T1528, T1552.007, T1195.001, GitHub, GitHub Enterprise, npm, Gheist, AI coding agent, prompt injection, Supply Chain, Credential Theft

**Intelligence Context**
- [Gheist Uses Stolen GitHub Tokens to Steal Private Repository Secrets via Actions Logs](https://thehackernews.com/2026/10/gheist-uses-stolen-github-tokens-to.html) — The Hacker News
  - Context: The Hacker News reported the Gheist campaign's use of stolen tokens to plant and execute malicious GitHub Actions workflows, confirming successful secret exfiltration from private repositories and GitHub Enterprise environments.

- [Malicious File in Downloads Folder Tries to Trick AI Coding Agent Into Installing Malware](https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html) — The Hacker News
  - Context: Security firm Forever Security documented a real-world prompt-injection attempt against a customer's AI coding agent, where a malicious instruction file directed the agent toward a known-malicious npm package — the attempt was caught before execution.

<br/>
---
<br/>

## Monitor Only

- **uCreator Android spyware is actively hijacking Telegram and WeChat accounts** by embedding malicious code in trojanized app copies distributed outside official stores, stealing 2FA credentials and enabling account cloning — reinforce sideloading prohibitions and review mobile threat defense coverage for Android devices used for messaging. *T1111, T1056.004, uCreator, Android* **Source:** uCreator Android Spyware Can Steal Telegram 2FA Passwords and Clone WeChat Accounts — [https://thehackernews.com/2026/10/ucreator-android-spyware-can-steal.html](https://thehackernews.com/2026/10/ucreator-android-spyware-can-steal.html)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a threat environment where attackers are operating across every layer of the enterprise simultaneously — exploiting public-facing PHP applications, bypassing MFA through token replay, draining CI/CD secrets, manipulating AI developer tooling, and harvesting mobile credentials. The Microsoft 365 AitM campaign is the most operationally significant story for most organizations: MFA bypass at this scale should force a hard conversation about whether token lifetime and session controls have kept pace with the threat. The Gheist and AI agent stories together signal that the software development pipeline is now a primary attack surface — security teams without visibility into CI/CD and developer tooling are flying blind. PHP2Shell demands immediate action; the Brotli flaw demands a structured patching sprint this week.

<br/>
---
<br/>

## Source Links

- PHP2Shell security flaws now successfully exploited in the wild — [https://www.bleepingcomputer.com/news/security/php2shell-security-flaws-now-sucessfully-exploited-in-the-wild/](https://www.bleepingcomputer.com/news/security/php2shell-security-flaws-now-sucessfully-exploited-in-the-wild/)

- Microsoft 365 Token-Replay Attacks Compromise 97 Accounts at 79 Organizations — [https://thehackernews.com/2026/10/microsoft-365-token-replay-attacks.html](https://thehackernews.com/2026/10/microsoft-365-token-replay-attacks.html)

- Node2Shell: Brotli Flaw Triggers Patching Across Microsoft, Node.js, Python Packages — [https://www.securityweek.com/node2shell-brotli-flaw-triggers-patching-across-microsoft-node-js-python-packages/](https://www.securityweek.com/node2shell-brotli-flaw-triggers-patching-across-microsoft-node-js-python-packages/)

- Gheist Uses Stolen GitHub Tokens to Steal Private Repository Secrets via Actions Logs — [https://thehackernews.com/2026/10/gheist-uses-stolen-github-tokens-to.html](https://thehackernews.com/2026/10/gheist-uses-stolen-github-tokens-to.html)

- Malicious File in Downloads Folder Tries to Trick AI Coding Agent Into Installing Malware — [https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html](https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html)

- uCreator Android Spyware Can Steal Telegram 2FA Passwords and Clone WeChat Accounts — [https://thehackernews.com/2026/10/ucreator-android-spyware-can-steal.html](https://thehackernews.com/2026/10/ucreator-android-spyware-can-steal.html)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
