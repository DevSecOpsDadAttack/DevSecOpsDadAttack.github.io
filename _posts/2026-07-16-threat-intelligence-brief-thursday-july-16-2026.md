---
layout: post
title: "Threat Intelligence Brief - Thursday, July 16, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-07-16
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1110
  - T1548
  - T1566
  - T1187
  - T1056
  - T1190
  - T1005
  - T1486
  - T1059
  - T1542
  - Cisco
---

## Threat Radar

- **Oracle E-Business Suite is under active exploitation** — CISA has issued an emergency directive requiring federal agencies to patch by Saturday. Enterprise Oracle users face identical risk and should treat this as an immediate priority.

- **Spirals ransomware completed a full corporate compromise in under 24 hours** — initial access through encryption in a single operational day, leaving defenders almost no window to detect and contain.

- **Russian actor UAT-11795 is trojanizing Zoom and WebEx installers** — employees downloading collaboration tools from unofficial sources risk deploying Starland RAT, a credential and cryptocurrency-stealing backdoor.

- **Zoom appears in three separate threat stories today** — active trojanization campaign plus critical unpatched vulnerabilities; validate software sourcing and accelerate patching simultaneously.

- **F5 NGINX and BIG-IP carry unpatched flaws enabling code execution and configuration tampering** — internet-facing deployments represent a high-value initial access target.

- **UEFI shim bootloaders signed by Microsoft can be abused to bypass Secure Boot** — affects both Windows and Linux fleets and undermines firmware-level integrity controls that many endpoint security programs rely on.

<br/>
---
<br/>

## Immediate Action Required

- **Oracle E-Business Suite — Patch Now:** Active exploitation is confirmed. Federal agencies have a Saturday deadline; enterprise Oracle users should treat this with equivalent urgency. Validate patch status across all EBS instances and confirm internet exposure. *Products: Oracle E-Business Suite | Vendor: Oracle*

- **Spirals Ransomware — Validate Perimeter and Backup Posture:** Spirals is completing full intrusions in under 24 hours via public-facing exploitation (T1190). SOC teams should confirm alerting on external-facing systems and verify backup integrity and isolation today. *ATT&CK: T1190, T1005, T1486 | Threat Actor: Spirals*

- **Trojanized Zoom/WebEx — Audit Software Sources and Credential Exposure:** UAT-11795 is distributing malicious installers that deploy Starland RAT for credential and cryptocurrency theft. Verify that all Zoom and WebEx installations came from official vendor sources and review recent credential activity for affected users. *ATT&CK: T1566, T1187, T1056 | Threat Actor: UAT-11795 | Malware: Starland RAT | Products: Zoom, WebEx*

<br/>
---
<br/>

## High-Impact Developments

### Oracle E-Business Suite Actively Exploited — CISA Emergency Patch Order

- **What happened:** CISA added a critical Oracle E-Business Suite vulnerability to its Known Exploited Vulnerabilities catalog and ordered federal agencies to remediate by Saturday. Attacks are ongoing.

- **Why it matters:** Oracle E-Business Suite is a core financial and ERP platform. Active exploitation means attackers are already inside some environments. The compressed remediation window signals CISA assesses real, immediate harm.

- **Who should care:** Federal agencies, finance teams, and any enterprise running Oracle E-Business Suite — particularly those with internet-accessible instances.

- **Recommended action:** Identify all Oracle E-Business Suite deployments, apply available patches immediately, and validate whether any instances are externally accessible. If patching cannot be completed before Saturday, implement compensating controls and escalate to leadership.

- **Confidence:** High — confirmed active exploitation per CISA directive.

- **Search metadata:** Oracle E-Business Suite, Oracle, active exploitation, CISA KEV

**Intelligence Context**
- [CISA orders feds to patch actively exploited Oracle flaw by Saturday](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-oracle-flaw-by-saturday/) — Bleeping Computer
  - Context: Reports CISA's emergency directive mandating federal agency remediation by Saturday, confirming active exploitation of the Oracle E-Business Suite vulnerability is ongoing.

<br/>
---
<br/>

### Spirals Ransomware: Full Network Compromise in Under 24 Hours

- **What happened:** A newly identified ransomware actor called Spirals executed a complete corporate intrusion — initial access, data exfiltration, and network encryption — in less than 24 hours.

- **Why it matters:** The sub-24-hour dwell time eliminates most traditional detection and response windows. By the time many organizations identify the intrusion, data has already been stolen and encryption is underway.

- **Who should care:** All enterprise security operations, IT, and backup/recovery teams. Any organization with internet-facing systems is a potential target.

- **Recommended action:** Confirm detection coverage exists for exploitation of public-facing applications (T1190) and bulk data collection (T1005). Verify that backups are isolated, tested, and not accessible from the production network. Tabletop the sub-24-hour scenario with your incident response team.

- **Confidence:** High — active campaign with confirmed victim.

- **Search metadata:** Spirals, ransomware, T1190, T1005, T1486

**Intelligence Context**
- [New Spirals ransomware encrypts victim network in under 24 hours](https://www.bleepingcomputer.com/news/security/new-spirals-ransomware-encrypts-victim-network-in-under-24-hours/) — Bleeping Computer
  - Context: Details the Spirals actor's attack chain from initial access through data theft to encryption, documenting the sub-24-hour operational timeline that defines the core risk.

<br/>
---
<br/>

### Russian Threat Actor Trojanizes Zoom and WebEx to Deploy Starland RAT

- **What happened:** Russian financially motivated threat actor UAT-11795 is distributing trojanized versions of Zoom and WebEx that install Starland RAT, a backdoor designed to steal credentials and cryptocurrency.

- **Why it matters:** The attack exploits user trust in widely deployed collaboration tools. Employees who download installers from unofficial sources — search engine results, third-party sites, phishing links — may unknowingly install a fully functional RAT. Credential theft from enterprise environments enables follow-on access well beyond the initial victim.

- **Who should care:** IT and security operations teams managing software distribution, all employees using Zoom or WebEx, and organizations with cryptocurrency holdings or high-value credential stores.

- **Recommended action:** Enforce software installation only from official vendor sources or managed deployment channels. Audit existing Zoom and WebEx installations for integrity. Review authentication logs for anomalous credential use. Communicate the risk of unofficial software downloads to end users.

- **Confidence:** High — active campaign with confirmed malware deployment.

- **Search metadata:** UAT-11795, Starland RAT, Zoom, WebEx, T1566, T1187, T1056, trojanized

**Intelligence Context**
- [Russian hackers trojanize WebEx, Zoom apps to push Starland malware](https://www.bleepingcomputer.com/news/security/russian-hackers-trojanize-webex-zoom-apps-to-push-starland-malware/) — Bleeping Computer
  - Context: Attributes the campaign to UAT-11795, describes the trojanized installer delivery mechanism, and identifies Starland RAT as the payload used for credential and cryptocurrency theft.

<br/>
---
<br/>

## Monitor Only

- **Splunk and Zoom have released patches for critical vulnerabilities enabling credential access, account takeover, and privilege escalation** — exploitation status is unknown but the attack surface is broad; patch this week. **Source:** [Splunk, Zoom Patch Critical Vulnerabilities](https://www.securityweek.com/splunk-zoom-patch-critical-vulnerabilities/) — SecurityWeek

- **F5 has patched multiple NGINX and BIG-IP vulnerabilities allowing code execution, configuration modification, and memory leakage** — no confirmed exploitation yet, but F5 infrastructure is a historically attractive target; prioritize patching for internet-facing deployments. **Source:** [F5 Patches Multiple NGINX, BIG-IP Vulnerabilities](https://www.securityweek.com/f5-patches-multiple-nginx-big-ip-vulnerabilities/) — SecurityWeek

- **Outdated UEFI shim bootloaders signed by Microsoft can be used to bypass Secure Boot on Windows and Linux systems** — no active exploitation confirmed; endpoint and infrastructure teams should inventory bootloader versions and assess exposure, particularly in environments where firmware integrity is a compliance requirement. **Source:** [Old UEFI Shims Expose Systems to Secure Boot Bypass](https://www.securityweek.com/old-uefi-shims-expose-systems-to-secure-boot-bypass/) — SecurityWeek

<br/>
---
<br/>

## Analyst Observation

Today's brief is defined by two themes: speed and trust abuse. Spirals ransomware completing a full kill chain in under 24 hours is not an anomaly — it is a capability benchmark that should force every SOC to honestly assess whether detection and escalation workflows can realistically operate within that window. The Zoom/WebEx trojanization campaign by UAT-11795 is a reminder that supply chain risk does not require a sophisticated vendor compromise; it only requires employees downloading software from the wrong place. The concentration of Zoom-related risk today — active trojanization, critical unpatched vulnerabilities, and a CISA-level Oracle directive all landing simultaneously — is operationally significant. Prioritization is clear: actively exploited vulnerabilities first, then credential-theft vectors in widely deployed tools, then internet-facing infrastructure.

<br/>
---
<br/>

## Source Links

- [CISA orders feds to patch actively exploited Oracle flaw by Saturday](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-oracle-flaw-by-saturday/) — Bleeping Computer

- [New Spirals ransomware encrypts victim network in under 24 hours](https://www.bleepingcomputer.com/news/security/new-spirals-ransomware-encrypts-victim-network-in-under-24-hours/) — Bleeping Computer

- [Russian hackers trojanize WebEx, Zoom apps to push Starland malware](https://www.bleepingcomputer.com/news/security/russian-hackers-trojanize-webex-zoom-apps-to-push-starland-malware/) — Bleeping Computer

- [Splunk, Zoom Patch Critical Vulnerabilities](https://www.securityweek.com/splunk-zoom-patch-critical-vulnerabilities/) — SecurityWeek

- [F5 Patches Multiple NGINX, BIG-IP Vulnerabilities](https://www.securityweek.com/f5-patches-multiple-nginx-big-ip-vulnerabilities/) — SecurityWeek

- [Old UEFI Shims Expose Systems to Secure Boot Bypass](https://www.securityweek.com/old-uefi-shims-expose-systems-to-secure-boot-bypass/) — SecurityWeek

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
