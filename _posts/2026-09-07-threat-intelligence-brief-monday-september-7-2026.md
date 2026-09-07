---
layout: post
title: "Threat Intelligence Brief - Monday, September 7, 2026"
subtitle: "Operational threat reporting for defenders who need signal, not noise."
date: 2026-09-07
author: DevSecOpsDad
categories:
  - threat-intelligence
tags:
  - Cyber-Security-News
  - T1570
  - T1059
  - T1190
  - T1021.004
  - T1539
  - T1056
  - T1187
  - Google
  - Google-Authentication
  - N-central
  - ScreenConnect
---

## Threat Radar

- **N-able N-central RCE is actively exploited and requires emergency patching today** — four hotfixes in five weeks signals an unstable patch cycle; every on-premises build below 2026.3.1.14 remains exposed.

- **MikroTik RouterOS is being hijacked at scale** via chained vulnerability exploitation and internet-exposed SSH, with CERT Polska confirming attacks dating to at least early September.

- **JSCeal malware renders MFA ineffective** by stealing session cookies post-authentication, enabling direct cloud and enterprise account access without valid credentials.

- **Backdoored ScreenConnect clients are propagating payloads worm-like** across newly connected clients — a supply-chain-style risk that can spread silently through MSP and enterprise environments.

- **Attackers are deliberately targeting remote management and access tooling** — N-central, ScreenConnect, and MikroTik are all RMM or network-access infrastructure, reflecting a calculated focus on high-leverage pivot points.

<br/>
---
<br/>

## Immediate Action Required

- **N-able N-central (all on-premises builds below 2026.3.1.14):** Apply Hotfix 4 immediately. Active exploitation is confirmed in N-able's own incident notice. Instances patched to Hotfix 3 within the last 24 hours are still vulnerable and must be re-patched. MSPs and MSSPs should treat this as a fleet-wide emergency given the downstream blast radius. | T1190

- **MikroTik RouterOS:** Audit all internet-facing MikroTik devices immediately. Restrict or eliminate SSH exposure to the public internet. Apply available security updates. Any device with internet-exposed SSH that has not been patched should be treated as potentially compromised. | T1190, T1021.004

- **ScreenConnect deployments:** Validate the integrity of all ScreenConnect instances in use. Confirm no unauthorized modifications to client binaries or server configurations. Treat anomalous lateral file transfer activity as a potential indicator of compromise. | T1570, T1059

<br/>
---
<br/>

## High-Impact Developments

### N-able N-central: Maximum-Severity Unauthenticated RCE Under Active Exploitation

- **What happened:** N-able has issued its fourth emergency hotfix in five weeks for a maximum-severity unauthenticated RCE vulnerability in N-central RMM. Every on-premises build below version 2026.3.1.14 is affected — including instances patched to Hotfix 3 just one day prior. N-able's incident notice acknowledges wild exploitation, while release notes describe it as unconfirmed — a discrepancy that should not delay action.

- **Why it matters:** Unauthenticated RCE in an RMM platform is among the highest-risk vulnerability classes that exist. An attacker who compromises N-central gains administrative control over every managed endpoint in the fleet. For MSPs and MSSPs, that translates directly to downstream customer compromise at scale.

- **Who should care:** CISOs and security directors at MSPs, MSSPs, and any enterprise running N-central on-premises. SOC leaders should be monitoring for post-exploitation indicators across managed endpoints.

- **Recommended action:** Update all on-premises N-central instances to version 2026.3.1.14 or apply Hotfix 4 immediately. Do not assume Hotfix 3 is sufficient. Validate patch status across every N-central server in the environment. Escalate to leadership given confirmed active exploitation.

- **Confidence:** High — corroborated by two independent sources; active exploitation acknowledged by the vendor.

- **Search metadata:** T1190 | N-central | N-able | remote-code-execution | authentication-bypass | unauthenticated-access

**Intelligence Context**
- [N-able Issues Fourth N-central Hotfix in Five Weeks for Unauthenticated RCE Flaw — The Hacker News](https://thehackernews.com/2026/09/n-able-issues-fourth-n-central-hotfix.html)
  - Context: Confirms that Hotfix 3 recipients from the prior day still require Hotfix 4, and notes the discrepancy between N-able's incident notice (exploitation confirmed) and release notes (unconfirmed).

- [N-able patches max severity N-central flaw amid ongoing attacks — Bleeping Computer](https://www.bleepingcomputer.com/news/security/n-able-patches-max-severity-n-central-flaw-amid-ongoing-attacks/)
  - Context: Independently confirms active attacks against the maximum-severity RCE flaw and reinforces the emergency patching directive.

<br/>
---
<br/>

### MikroTik RouterOS: Chained Vulnerabilities and Exposed SSH Enabling Full Administrative Takeover

- **What happened:** Attackers are chaining two recently disclosed MikroTik RouterOS vulnerabilities with internet-exposed SSH services to gain full unauthenticated administrative control of routers. CERT Polska issued a formal warning on September 5, with confirmed attacks dating to at least early September. No credentials are required when SSH is reachable from the internet.

- **Why it matters:** Compromised routers sit at the perimeter of enterprise networks. Full administrative control lets an attacker intercept traffic, establish persistent footholds, manipulate routing, and use the device as a pivot point for deeper network compromise. Perimeter trust is fundamentally undermined.

- **Who should care:** Network security architects, SOC leaders, and IT operations teams managing MikroTik infrastructure. Any organization with internet-facing MikroTik devices should treat this as an active threat.

- **Recommended action:** Identify all MikroTik RouterOS devices with SSH exposed to the internet. Restrict SSH access to trusted management networks only. Apply all available security updates. Review router logs for unauthorized access or configuration changes since early September.

- **Confidence:** High — active exploitation confirmed by CERT Polska and corroborated by two independent sources.

- **Search metadata:** T1190, T1021.004 | MikroTik RouterOS | SSH-exposure | authentication-bypass | unauthorized-access

**Intelligence Context**
- [Hackers exploit new MikroTik RouterOS flaws to hijack routers — Bleeping Computer](https://www.bleepingcomputer.com/news/security/hackers-exploit-new-mikrotik-routeros-flaws-to-hijack-routers/)
  - Context: Details the chained vulnerability exploitation path targeting MikroTik devices with internet-exposed SSH services.

- [Attackers Hijack MikroTik Routers Through Internet-Exposed SSH Without Authentication — The Hacker News](https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html)
  - Context: Cites CERT Polska's formal warning and establishes that successful attacks have been occurring since at least early September, providing the earliest confirmed exploitation timeline.

<br/>
---
<br/>

### JSCeal Malware: Session-Cookie Theft Bypasses Google MFA

- **What happened:** Researchers have published a detailed analysis of JSCeal, a compiled V8 JavaScript malware with session-cookie theft, credential harvesting, keylogging, and traffic interception capabilities. Payloads are protected with RC4-encrypted strings and multiple obfuscation layers. By stealing valid session cookies, JSCeal allows attackers to authenticate to Google services as the victim — bypassing MFA entirely.

- **Why it matters:** MFA is widely treated as a reliable control against credential-based attacks. JSCeal demonstrates that post-authentication session theft makes MFA irrelevant. Any organization relying on Google Workspace or Google-authenticated services is exposed if an endpoint is compromised by this malware.

- **Who should care:** Identity and access management teams, SOC leaders monitoring endpoint telemetry, and security architects responsible for cloud access controls. Particularly relevant for organizations with heavy Google Workspace dependency.

- **Recommended action:** Review endpoint security controls for coverage against V8 JavaScript-based malware. Assess whether session token lifetime and revocation policies are appropriately configured. Evaluate whether conditional access policies — device trust, IP restrictions — can reduce the value of stolen session cookies. Confirm endpoint detection tooling is updated to recognize obfuscated JavaScript payloads.

- **Confidence:** Medium — based on researcher analysis; active exploitation confirmed but scope and targeting are not fully characterized.

- **Search metadata:** T1539, T1056, T1187 | JSCeal | Google Authentication | session-cookie-theft | credential-theft | surveillance

**Intelligence Context**
- [JSCeal Malware Can Bypass Google Authentication Using Stolen Session Cookies — The Hacker News](https://thehackernews.com/2026/09/jsceal-malware-can-bypass-google.html)
  - Context: Provides the primary technical analysis of JSCeal's capabilities, including its RC4-obfuscated payload structure, session-cookie theft mechanism, and MFA bypass methodology.

<br/>
---
<br/>

### Backdoored ScreenConnect Clients: Worm-Like Payload Propagation

- **What happened:** Threat actors have modified ScreenConnect remote support clients to function as backdoors, using them to transfer and execute malicious payloads to newly connected clients in a worm-like propagation pattern. The attack abuses the trusted file-transfer functionality built into remote support tools.

- **Why it matters:** Remote support software operates with elevated trust and broad access across managed environments. A backdoored instance can silently spread malware to every client that connects, creating wide-scale downstream exposure that is difficult to contain once established. This is a supply-chain-adjacent risk for MSPs and enterprises alike.

- **Who should care:** MSPs, MSSPs, and enterprises using ScreenConnect for remote support. SOC leaders should review lateral movement and file transfer telemetry. Vendor security and third-party risk teams should assess ScreenConnect deployment integrity.

- **Recommended action:** Audit all ScreenConnect deployments for unauthorized modifications. Verify binary integrity of ScreenConnect client installations. Review file transfer logs for anomalous payload delivery. Confirm that ScreenConnect instances are sourced from official ConnectWise channels and have not been tampered with.

- **Confidence:** High — active campaign confirmed; specific payload details not yet fully disclosed.

- **Search metadata:** T1570, T1059 | ScreenConnect | ConnectWise | backdoor | worm-like-campaign | remote-access-trojan

**Intelligence Context**
- [Modified ScreenConnect Clients Used in Worm-Like Campaign — SecurityWeek](https://www.securityweek.com/modified-screenconnect-clients-used-in-worm-like-campaign/)
  - Context: Reports the active campaign using backdoored ScreenConnect instances to propagate payloads to newly connected clients, establishing the worm-like spread mechanism as the primary attack vector.

<br/>
---
<br/>

## Monitor Only

- JSCeal's use of RC4-encrypted strings and multi-layer JavaScript obfuscation points to continued infostealer tradecraft evolution aimed at defeating static analysis — identity teams should track further research as attribution and delivery mechanisms are clarified. **Source:** JSCeal Malware Can Bypass Google Authentication Using Stolen Session Cookies — [https://thehackernews.com/2026/09/jsceal-malware-can-bypass-google.html](https://thehackernews.com/2026/09/jsceal-malware-can-bypass-google.html)

- CERT Polska's formal advisory on MikroTik exploitation is a signal worth tracking for broader European threat activity; organizations with MikroTik in OT-adjacent or branch office environments face elevated risk given the persistence potential of router-level compromise. **Source:** Attackers Hijack MikroTik Routers Through Internet-Exposed SSH Without Authentication — [https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html](https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html)

<br/>
---
<br/>

## Analyst Observation

Today's brief reflects a consistent and operationally significant pattern: attackers are systematically targeting the tools defenders use to manage and support infrastructure — RMM platforms, remote support clients, and network edge devices. N-central, ScreenConnect, and MikroTik are not peripheral systems; they are high-trust, high-access components that, when compromised, give adversaries the same administrative reach defenders rely on. The N-central situation is particularly concerning not because of the vulnerability itself, but because four hotfixes in five weeks suggests the underlying flaw is either more complex than initially scoped or the vendor is discovering new exploitation variants in response to active attacker activity. Security leaders should treat RMM and remote access tooling as crown-jewel infrastructure — subject to the same scrutiny applied to identity providers and domain controllers — and should be pressing vendors hard on patch cadence and transparency when emergency fixes arrive this frequently.

<br/>
---
<br/>

## Source Links

- N-able Issues Fourth N-central Hotfix in Five Weeks for Unauthenticated RCE Flaw — [https://thehackernews.com/2026/09/n-able-issues-fourth-n-central-hotfix.html](https://thehackernews.com/2026/09/n-able-issues-fourth-n-central-hotfix.html)

- N-able patches max severity N-central flaw amid ongoing attacks — [https://www.bleepingcomputer.com/news/security/n-able-patches-max-severity-n-central-flaw-amid-ongoing-attacks/](https://www.bleepingcomputer.com/news/security/n-able-patches-max-severity-n-central-flaw-amid-ongoing-attacks/)

- Hackers exploit new MikroTik RouterOS flaws to hijack routers — [https://www.bleepingcomputer.com/news/security/hackers-exploit-new-mikrotik-routeros-flaws-to-hijack-routers/](https://www.bleepingcomputer.com/news/security/hackers-exploit-new-mikrotik-routeros-flaws-to-hijack-routers/)

- Attackers Hijack MikroTik Routers Through Internet-Exposed SSH Without Authentication — [https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html](https://thehackernews.com/2026/09/attackers-hijack-mikrotik-routers.html)

- JSCeal Malware Can Bypass Google Authentication Using Stolen Session Cookies — [https://thehackernews.com/2026/09/jsceal-malware-can-bypass-google.html](https://thehackernews.com/2026/09/jsceal-malware-can-bypass-google.html)

- Modified ScreenConnect Clients Used in Worm-Like Campaign — [https://www.securityweek.com/modified-screenconnect-clients-used-in-worm-like-campaign/](https://www.securityweek.com/modified-screenconnect-clients-used-in-worm-like-campaign/)

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack cyber threat intelligence._
