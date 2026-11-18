---
layout: post
title: "Threat Intelligence Brief - Wednesday, November 18, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-11-18
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - CVE-2026-114938
  - CVE-2026-115731
  - T1190
  - T1528
  - Atlassian
  - Microsoft
  - Google
  - Microsoft-Perception
  - Azure
  - Azure-DevOps
  - Java4Shell
---

## Threat Radar

- **Java4Shell (CVE-2026-114938)** introduces pre-authentication RCE across Jira, Jenkins, and Keycloak via Java 17.0.6+. Exploitation status is unconfirmed, but the zero-credential attack surface makes this a top-priority exposure to validate now.

- **Perforce Puppet (CVE-2026-115731)** is under active exploitation. Any client holding a CA-signed agent certificate can execute code on the Puppet server — a direct path to infrastructure-wide lateral movement.

- **PyPI supply chain compromise** targeting the `agent-framework` package (versions 1.26.1 and 1.26.2) is actively stealing Azure, Azure DevOps, and GitHub Actions credentials on Python startup. Development pipelines using this package are likely already compromised.

- Today's stories share a common thread: attackers are targeting the infrastructure that builds, deploys, and manages everything else — CI/CD pipelines, configuration management, and identity platforms.

- Organizations running Java 17.0.6+ should treat Java4Shell as broadly applicable, not limited to the three named products.

- Credential theft from CI/CD environments can cascade rapidly — stolen tokens may grant access to production cloud environments, container registries, and downstream repositories.

<br/>
---
<br/>

## Immediate Action Required

- **CVE-2026-114938 (Java4Shell):** Inventory all internet-facing and internal instances of Jira, Jenkins, Keycloak, and any other Java 17.0.6+ applications. Validate patch availability from Atlassian, CloudBees, and Red Hat. Apply patches or implement compensating controls immediately. Do not wait for confirmed exploitation.

- **CVE-2026-115731 (Perforce Puppet):** Active exploitation is confirmed. Patch Puppet servers immediately. Audit CA-signed agent certificates and revoke any that are unrecognized or unnecessary. Treat Puppet-managed infrastructure as potentially compromised pending investigation.

- **PyPI agent-framework supply chain:** Identify any use of `agent-framework` versions 1.26.1 or 1.26.2 across development environments. Remove immediately and rotate all Azure, Azure DevOps, and GitHub Actions credentials and tokens that may have been exposed. Audit pipeline logs for anomalous credential use.

<br/>
---
<br/>

## High-Impact Developments

### Java4Shell (CVE-2026-114938): Pre-Auth RCE Across Core Enterprise Platforms

- **What happened:** Security firm Calif disclosed a critical vulnerability in Java 17.0.6 and later that enables unauthenticated remote code execution. At least six widely used enterprise applications are affected, including Jira, Jenkins, and Keycloak. Exploitation status is currently unknown.

- **Why it matters:** No credentials are required to exploit this flaw. Jira, Jenkins, and Keycloak are foundational to enterprise development workflows and identity management. A successful exploit against any of these could yield full environment compromise, code injection into pipelines, or identity infrastructure takeover.

- **Who should care:** Security leadership, vulnerability management teams, application owners, and infrastructure teams running Java 17.0.6+ environments.

- **Recommended action:** Inventory Java runtime versions across your environment immediately. Prioritize patching of internet-exposed instances. Engage Atlassian, CloudBees, and Red Hat for patch timelines if fixes are not yet available. Implement temporary network-level restrictions on affected services where patching is delayed.

- **Confidence:** High — disclosed by named security research firm with specific version and product scope identified.

- **Search metadata:** CVE-2026-114938, T1190, Jira, Jenkins, Keycloak, Java, Atlassian, CloudBees, Red Hat

**Intelligence Context**
- [Java4Shell Flaw (CVE-2026-114938) Enables Pre-Auth RCE in Jira, Jenkins, Keycloak and More — The Hacker News](https://thehackernews.com/2026/11/java4shell-cve-2026-114938-enables-pre.html)
  - Context: Calif's disclosure details the vulnerability's presence in Java 17.0.6+ and confirms at least six affected enterprise applications, with exploitation status currently unknown.

<br/>
---
<br/>

### Critical Perforce Puppet RCE (CVE-2026-115731) Under Active Exploitation

- **What happened:** A critical RCE vulnerability in Perforce Puppet is being actively exploited. The flaw allows any client possessing a CA-signed agent certificate to execute arbitrary code on the Puppet server, bypassing meaningful authentication controls.

- **Why it matters:** Puppet typically holds privileged access across large numbers of managed systems. Compromise of the Puppet server is effectively compromise of every system it manages. Active exploitation means the window for unpatched exposure is already closing.

- **Who should care:** Security leadership, infrastructure teams, vulnerability management, and platform owners operating Puppet in any capacity.

- **Recommended action:** Patch immediately. Audit all CA-signed agent certificates and revoke any that cannot be positively attributed. Treat Puppet-managed systems as potentially compromised and investigate recent configuration changes and lateral movement indicators.

- **Confidence:** High — active exploitation confirmed per SecurityWeek reporting.

- **Search metadata:** CVE-2026-115731, T1190, Perforce Puppet, Perforce

**Intelligence Context**
- [Critical Perforce Puppet RCE Exploited in Attacks — SecurityWeek](https://www.securityweek.com/critical-perforce-puppet-rce-exploited-in-attacks/)
  - Context: SecurityWeek confirms active exploitation of CVE-2026-115731, with the attack vector requiring only a CA-signed agent certificate to achieve server-side code execution.

<br/>
---
<br/>

### Poisoned PyPI Package Actively Stealing Azure and CI/CD Credentials

- **What happened:** Malicious versions 1.26.1 and 1.26.2 of the `agent-framework` package on PyPI steal Azure, Azure DevOps, and GitHub Actions credentials automatically on Python startup. This is a confirmed active supply chain attack targeting development and cloud environments.

- **Why it matters:** CI/CD credentials typically carry broad permissions across cloud infrastructure, container registries, and source code repositories. Compromise propagates silently. Any environment that installed these versions should be treated as already exfiltrated.

- **Who should care:** Security leadership, DevOps and platform engineering teams, cloud security teams, and anyone responsible for software supply chain integrity.

- **Recommended action:** Audit Python environments and package manifests for `agent-framework` versions 1.26.1 or 1.26.2 immediately. Remove affected versions and rotate all potentially exposed Azure service principal credentials, Azure DevOps PATs, and GitHub Actions secrets. Review pipeline execution logs for anomalous outbound connections or unauthorized API calls.

- **Confidence:** High — active exploitation confirmed, specific malicious versions identified.

- **Search metadata:** T1528, agent-framework, PyPI, Azure, Azure DevOps, GitHub Actions, Python, Microsoft

**Intelligence Context**
- [Microsoft Agent Framework Releases Poisoned With Credential Stealer — SecurityWeek](https://www.securityweek.com/microsoft-agent-framework-releases-poisoned-with-credential-stealer/)
  - Context: SecurityWeek identifies the specific malicious versions (1.26.1 and 1.26.2) and confirms credential theft triggers on Python startup, targeting Azure and CI/CD platform credentials.

<br/>
---
<br/>

## Monitor Only

- No additional lower-priority items from today's source set met the threshold for Monitor Only inclusion; all triaged stories required immediate action.

<br/>
---
<br/>

## Analyst Observation

Today's brief is notable for what it targets rather than how it attacks: every story hits infrastructure that organizations use to build, deploy, and manage everything else. Java4Shell going after Jira, Jenkins, and Keycloak; a Puppet RCE being actively weaponized; a poisoned PyPI package draining CI/CD credentials — this is not opportunistic noise. Whether coordinated or coincidental, the practical effect is the same: development and infrastructure management tooling warrants the same defensive urgency as perimeter systems. The Puppet exploitation is the most immediately dangerous given confirmed active attacks, but the PyPI supply chain compromise deserves equal operational attention — stolen pipeline credentials rarely announce themselves before they're used.

<br/>
---
<br/>

## Source Links

- Java4Shell Flaw (CVE-2026-114938) Enables Pre-Auth RCE in Jira, Jenkins, Keycloak and More — [https://thehackernews.com/2026/11/java4shell-cve-2026-114938-enables-pre.html](https://thehackernews.com/2026/11/java4shell-cve-2026-114938-enables-pre.html)

- Critical Perforce Puppet RCE Exploited in Attacks — [https://www.securityweek.com/critical-perforce-puppet-rce-exploited-in-attacks/](https://www.securityweek.com/critical-perforce-puppet-rce-exploited-in-attacks/)

- Microsoft Agent Framework Releases Poisoned With Credential Stealer — [https://www.securityweek.com/microsoft-agent-framework-releases-poisoned-with-credential-stealer/](https://www.securityweek.com/microsoft-agent-framework-releases-poisoned-with-credential-stealer/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
