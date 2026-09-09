---
layout: page
title: Detect Unsigned Dll Load Verified Signing State
subtitle: "Unsigned DLL loads, using IsSigned/SigningStatus rather than treating an empty SHA256 as unsigned (the field is documented as usually-populated, not always)."
permalink: /kql-library/analytics-rules/detect-unsigned-dll-load-verified-signing-state/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/analytics-rules/' | relative_url }}">Analytics Rules</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-shield-halved" aria-hidden="true"></i>&nbsp;Analytics Rules</span>
  <code class="kql-lib-query-file">detect-unsigned-dll-load-verified-signing-state.kql</code>
</div>

<p class="kql-lib-query-longdesc">Unsigned DLL loads, using IsSigned/SigningStatus rather than treating an empty SHA256 as unsigned (the field is documented as usually-populated, not always).</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/persistence/' | relative_url }}">Persistence</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1574-002/' | relative_url }}">T1574.002</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1027/' | relative_url }}">T1027</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/deviceimageloadevents/' | relative_url }}">DeviceImageLoadEvents</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://devsecopsdadattack.com/2026-09-01-KQL-Detection-of-the-Week-The-String-Is-Not-The-Thing/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-unsigned-dll-load-verified-signing-state">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-unsigned-dll-load-verified-signing-state.kql' | relative_url }}" download="detect-unsigned-dll-load-verified-signing-state.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-unsigned-dll-load-verified-signing-state" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects unsigned DLL loads — with the correction that an empty SHA256 in DeviceImageLoadEvents
// does NOT mean unsigned (the field is documented as usually-populated but not always). Uses
// IsSigned/SigningStatus fields against the actual verification result rather than treating a null
// hash as evidence of signing state.
// Source: KQL Detection of the Week: The String Is Not the Thing (2026-09-01) — https://devsecopsdadattack.com/2026-09-01-KQL-Detection-of-the-Week-The-String-Is-Not-The-Thing/
// Tactics: Defense Evasion, Persistence
// Techniques: T1574.002, T1027
// Platforms: Windows
// Data: DeviceImageLoadEvents

let lookback = 7d;
let followOnWindow = 5m;
// Paths a normal user can write to without elevation. This is
// the actual sideloading precondition — the attacker needs to
// drop a DLL somewhere the loader will find it.
let UserWritablePaths = dynamic([
    "\\appdata\\", "\\temp\\", "\\downloads\\",
    "\\programdata\\", "\\users\\public\\"
]);
// Loaders excluded because their image loads from these paths
// are overwhelmingly legitimate and high-volume. Every entry is
// a blind spot you are accepting; validate the path, not just
// the name, before adding to this list.
let TrustedLoaders = dynamic([
    "msmpeng.exe", "mpcmdrun.exe",        // Defender AV
    "trustedinstaller.exe", "tiworker.exe", // Servicing stack
    "wuauclt.exe", "usoclient.exe"          // Windows Update
]);
// ============================================================
// STEP 1: IMAGE LOADS FROM USER-WRITABLE PATHS.
//
// THE FIX, PART ONE: note what is NOT in this block. There is
// no isempty(SHA256) and no IsSigned. DeviceImageLoadEvents has
// no signature verdict to filter on, and its SHA256 column is
// documented as usually empty — filtering on either one gives
// you a predicate that means something other than what it
// reads like.
//
// We require SHA1 instead, because it is both the documented
// populated hash for this table and the join key for the table
// that DOES carry a signing verdict.
// ============================================================
let Loads =
    DeviceImageLoadEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "ImageLoaded"
    | where isnotempty(FolderPath) and isnotempty(SHA1)
    | where tolower(FolderPath) has_any (UserWritablePaths)
    | where not(tolower(InitiatingProcessFileName) in~ (TrustedLoaders))
    | project
        LoadTime = Timestamp,
        DeviceId, DeviceName, SHA1,
        DllName = FileName,
        DllPath = FolderPath,
        InitiatingProcessFileName,
        InitiatingProcessFolderPath,
        InitiatingProcessId,
        InitiatingProcessCreationTime,
        InitiatingProcessCommandLine,
        InitiatingProcessAccountName;
// ============================================================
// STEP 2: THE ACTUAL SIGNING VERDICT.
//
// DeviceFileCertificateInfo is populated by certificate
// verification activity on endpoints, which means it is not
// guaranteed to hold a record for every hash you look up. The
// join is therefore leftouter and "no record" is its own
// verdict rather than an assumed negative. An absent
// certificate record is not proof of an unsigned file — it is
// an unknown, and the analyst should see it labelled as one.
// ============================================================
let CertVerdict =
    DeviceFileCertificateInfo
    | where Timestamp >= ago(lookback + 2d)
    | summarize arg_max(Timestamp,
        IsSigned, IsTrusted, IsRootSignerMicrosoft,
        Signer, Issuer, SignatureType)
      by SHA1;
// ============================================================
// STEP 3: GRADE, DON'T GATE.
//
// Five verdicts instead of a boolean. Unsigned is the classic
// sideload. SignedUntrusted is the more interesting one — a
// valid-looking signature that fails WinVerifyTrust means a
// revoked, expired, or self-signed certificate, which is what
// a stolen-cert campaign looks like. NoCertificateRecord is
// the honest label for the rows that Saturday's query was
// silently treating as unsigned.
// ============================================================
Loads
| join kind=leftouter CertVerdict on SHA1
| extend SigningStatus = case(
      isnull(IsSigned),                                    "NoCertificateRecord",
      IsSigned == false,                                   "Unsigned",
      IsSigned == true and IsTrusted == false,             "SignedUntrusted",
      IsSigned == true and IsRootSignerMicrosoft == true,  "SignedMicrosoft",
                                                           "SignedTrusted")
// Microsoft-rooted signatures loading from AppData are almost
// always legitimate servicing activity. This is the one verdict
// worth dropping; everything else stays visible.
| where SigningStatus != "SignedMicrosoft"
// ============================================================
// STEP 4: FOLLOW-ON EXECUTION, ANCHORED TO THE RIGHT PROCESS.
//
// THE FIX, PART TWO: the join is on DeviceId AND
// InitiatingProcessId, so the child process is one spawned by
// the SAME process instance that loaded the DLL. Saturday and
// Sunday both joined on device alone, which correlates a DLL
// load with every unrelated process on the box.
//
// leftouter, not inner: the sideload is the finding. A load
// with no follow-on execution is still a load, and losing it
// because nothing spawned within five minutes is how you miss
// the staged payloads.
// ============================================================
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | project
        ChildTime = Timestamp,
        DeviceId,
        InitiatingProcessId,
        ChildProcess     = FileName,
        ChildFolderPath  = FolderPath,
        ChildCommandLine = ProcessCommandLine,
        ChildAccount     = AccountName
  ) on DeviceId, InitiatingProcessId
| where isnull(ChildTime)
     or (ChildTime between (LoadTime .. (LoadTime + followOnWindow)))
| summarize
    LoadEvents      = count(),
    ChildProcesses  = make_set(ChildProcess, 10),
    ChildCmdLines   = make_set(ChildCommandLine, 5),
    ChildCount      = countif(isnotempty(ChildProcess)),
    FirstSeen       = min(LoadTime),
    LastSeen        = max(LoadTime),
    Devices         = dcount(DeviceId),
    DeviceList      = make_set(DeviceName, 10)
    by SHA1, DllName, DllPath, SigningStatus,
       InitiatingProcessFileName, InitiatingProcessFolderPath,
       Signer, Issuer, SignatureType
// A single DLL hash sideloaded across many devices is a
// campaign; one device is an incident. Both matter, and the
// analyst should be able to tell them apart from the sort order.
| extend SpawnedAnything = ChildCount > 0
| extend Scope = case(
      Devices >= 10, "Widespread",
      Devices >= 3,  "MultiDevice",
                     "Isolated")
| order by SigningStatus asc, Devices desc, LoadEvents desc
```

</div>
