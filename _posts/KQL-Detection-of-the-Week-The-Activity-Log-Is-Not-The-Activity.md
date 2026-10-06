---
layout: post
title: "KQL Detection of the Week: The Activity Log Is Not the Activity"
subtitle: "Why Three of Six Storm-3168 Detections Hunt for Events AzureActivity Never Records, Making BPFDoor Detection Survive a Rename, and Why split(ResourceId, '/')[6] Isn't the Resource Type"
date: 2026-10-05
author: DevSecOpsDad
tags:
  - KQL Detection of the Week
  - kql
---

![The Activity Log Is Not The Activity](/assets/img/TheActivityLogIsNotTheActivity/1.png)

After a couple of weeks away (a KQL Café appearance, among other things — it's good to be back), the [DevSecOpsDadAttack Detection Engineering pipeline](https://devsecopsdadattack.com/detectionengineering/) ([run on a Raspberry Pi](https://www.hanley.cloud/2026-04-28-From-RSS-Noise-to-CISO-Signal-Automating-Cyber-Threat-Intelligence-That-Actually-Matters/)) handed me thirty detections across seven days, and three clusters of six: six for Storm-3168's service principal destruction spree in Azure, six for the BPFDoor/AVERAT staging chain on Linux edge appliances, and six for ScreenConnect abuse. The most interesting cluster is the first one, and it's interesting for an uncomfortable reason. Microsoft's [Storm-3168 write-up](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/) describes the attack as reconnaissance, then destruction, then credential collection. Three of the six detections the pipeline wrote need a reconnaissance stage or a Key Vault secret read to fire — and `AzureActivity`, the table all six touch, records neither. A fourth detects a different attack altogether. **The pipeline modelled the attack correctly. It modelled the log incorrectly.**

That distinction is the whole article. Microsoft saw 300+ successful read operations over fifteen and a half hours because Microsoft has its own telemetry for Azure Resource Manager. Your Sentinel workspace has the Azure Activity Log, which is a record of control-plane *changes and actions* — and, in Microsoft's own documentation, it doesn't typically capture read operations. The ordinary ARM GET requests that make up resource enumeration — "list my VMs", "show me this resource group" — aren't in it. Not filtered, not sampled, not behind a diagnostic setting: they just aren't captured, and those are exactly the reads Storm-3168 used for reconnaissance. A detection whose first stage is "high-volume read operations in AzureActivity" isn't a noisy detection or a fragile detection; it is a detection for an event class the table doesn't record. And the brief's own Unique Blind Spot Callout for both days says no unique blind spot was isolated, which is the pipeline equivalent of a smoke detector reporting that it has never detected smoke.

Act I is the Storm-3168 cluster: what AzureActivity actually records, why filtering to successful operations throws away the most damning evidence in this incident, and a composite query that parses `OperationNameValue` as a grammar instead of searching `OperationName` for English words. Act II is [Saturday](https://devsecopsdadattack.com/2026-10-03-detection-engineering-brief-saturday-october-3-2026/) and [Sunday](https://devsecopsdadattack.com/2026-10-04-detection-engineering-brief-sunday-october-4-2026/)'s BPFDoor detections — six queries keyed on the filenames `ntpdate` and `udevds`, the one thing the operator will change next — and a name-agnostic replacement built on what the staging chain *does*: execute, unlink within seconds, keep running. The honorable mention is a ScreenConnect detection titled "Without Prior Installation Record" that never checks for one. And the bonus round is the array index hiding in Tuesday's queries: `split(ResourceId, "/")[6]` returns the provider namespace, not the resource type — and returns nothing at all for the single most destructive operation in Azure, deleting a whole resource group.

One note before any of the queries: every replacement in this edition has been checked structurally against the documented schemas of the tables it uses, not run against live tenant data. Telemetry population varies by workspace, connector, and agent version. Treat each one as a hunting query until it has passed the validation checks in your own environment, and only then promote it.

<br/>

---

<br/>

## 🥇 Act I: Six Detections, One Log, Zero Reads

![Act I](/assets/img/TheActivityLogIsNotTheActivity/2.png)

Microsoft published the [Storm-3168 blog](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/) on Friday, 25 September, and the pipeline responded on Monday and Tuesday with six detections:

**Monday:**
1. [Detection 1](https://devsecopsdadattack.com/2026-09-28-detection-engineering-brief-monday-september-28-2026/): Service Principal Bulk Azure Resource Deletion (production candidate)
2. [Detection 2](https://devsecopsdadattack.com/2026-09-28-detection-engineering-brief-monday-september-28-2026/): Service Principal Reconnaissance Followed by Destructive Action (hunting-only)
3. [Detection 3](https://devsecopsdadattack.com/2026-09-28-detection-engineering-brief-monday-september-28-2026/): Service Principal Credential Access Activity in Entra ID (requires environment mapping)

**Tuesday:**
1. [Detection 1](https://devsecopsdadattack.com/2026-09-29-detection-engineering-brief-tuesday-september-29-2026/): Service Principal Bulk Resource Deletion Following Reconnaissance (hunting-only)
2. [Detection 2](https://devsecopsdadattack.com/2026-09-29-detection-engineering-brief-tuesday-september-29-2026/): Service Principal Credential Access Followed by Anomalous Resource Operations (requires environment mapping)
3. [Detection 3](https://devsecopsdadattack.com/2026-09-29-detection-engineering-brief-tuesday-september-29-2026/): Service Principal Bulk Resource Deletion Across Multiple Resource Types (production candidate)

Before taking them apart, here is what the attack actually looked like, because the timeline is the test every query has to pass. Microsoft observed two compromised service principals in one tenant. The first enumerated VMs, subscriptions, resource groups, and resources for roughly fifteen and a half hours — 300+ successful reads. About ninety minutes in, the second service principal enumerated VMs and resource groups across two subscriptions in five seconds. Sixteen hours after that, it enumerated App Service configuration (Microsoft's read: hunting for exposed credentials), and seventy seconds later attempted a ListKeys call against a storage account that didn't exist. Less than a second after *that* failure, destruction began: 100+ storage account deletion attempts in about seven minutes, most of them successful — plus a Key Vault, a Function App, and its App Service plan. In parallel it tried to delete Azure SQL databases (every attempt failed — wrong API version) and repeatedly tried to delete Azure Site Recovery and Azure Backup protection locks (also failed). Thirty minutes after the last deletion, it inventoried storage again and sent 30+ *successful* ListKeys requests, including against Site Recovery storage accounts.

Three phases: reconnaissance, destruction with recovery tampering, credential collection. Now, which of those does AzureActivity contain?

The [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log) records control-plane changes and actions — PUT, POST, and DELETE against Azure Resource Manager — and Microsoft's documentation says it doesn't typically capture read operations. The ordinary ARM GETs that make up resource enumeration aren't there. So:

- **Reconnaissance (300+ reads, the five-second sweep):** not in AzureActivity. These are ordinary ARM resource-enumeration GETs, the class of operation the Activity Log doesn't capture.
- **The App Service configuration enumeration:** possibly in AzureActivity, *if* it was done via the `config/list` POST action that returns app settings — which is a credential-returning action, not a read.
- **The failed ListKeys probe:** in AzureActivity, as a `.../LISTKEYS/ACTION` with a failed status.
- **The deletions:** in AzureActivity — successes *and* failures, including the lock-blocked ones.
- **The 30+ ListKeys:** in AzureActivity, as POST actions.

Now hold each detection up against that.

**Monday Detection 2 / Tuesday Detection 1 — Recon followed by destruction:**

```kql
let ReconPrincipals =
    AzureActivity
    | where TimeGenerated >= ago(LookbackWindow)
    | where tolower(OperationName) has_any ("list", "get", "read")
    | where ActivityStatus =~ "Succeeded"
    | where Caller !contains "@"
    | summarize
        ReconOps = count(),
        DistinctReconTypes = dcount(ResourceType),
        ReconStart = min(TimeGenerated)
        by Caller
    | where ReconOps >= ReconMinOps and DistinctReconTypes >= ReconMinTypes;
```

The first stage asks AzureActivity for `list`, `get`, and `read` operations. The resource-enumeration reads it's looking for aren't in AzureActivity to give it. So what *does* that filter match? Display names of POST actions that happen to start with "List" — things like *List Storage Account Keys*. In this incident, the only events that match the "reconnaissance" filter are the credential collection. The query would be counting the attacker's ListKeys calls as recon — and the successful ones happened *thirty minutes after* the destruction, so the `DeleteStart > ReconStart` ordering fails, and they all target one resource type, so the three-type threshold fails too. On the incident it was modelled on, both hunting queries return zero rows, and the reason isn't tuning.

**Tuesday Detection 2 — SP sign-in followed by Key Vault secret access:**

```kql
let CredentialOps =
    AzureActivity
    | where OperationName has_any ("Microsoft.KeyVault/vaults/secrets", ...)
        or OperationName has_any ("GetSecret", "ListSecrets", "GetCertificate", ...)
```

`GetSecret` is a Key Vault *data-plane* operation. Data-plane access never touches the Activity Log; it lives in Key Vault's own [diagnostic logs](https://learn.microsoft.com/en-us/azure/key-vault/general/logging) (`AzureDiagnostics` with `ResourceProvider == "MICROSOFT.KEYVAULT"`, or the resource-specific Key Vault audit table if you've switched collection modes). The brief's tuning notes half-know this — they suggest adding an AzureDiagnostics branch "if Key Vault diagnostic logs are forwarded" there — but it's not an optional branch, it's the only place the event exists. And Storm-3168's actual credential collection wasn't Key Vault at all. It was storage account keys, via an ARM action that *is* in AzureActivity.

**Monday Detection 3 — Service principal credential operations in Entra ID** queries `AuditLogs` for "Add service principal credentials" and friends. That's a real technique and a reasonable detection, but it's the Entra plane, not the ARM plane, and nothing in Microsoft's report describes the actor adding credentials to an app registration. It detects a different attack.

**Monday Detection 1 / Tuesday Detection 3 — Bulk multi-type deletion:** these two are the closest to the incident, because deletions *are* in the log. Tuesday Detection 3 would probably have fired on this exact attack — storage accounts, a Key Vault, and a Function App with its plan are three provider namespaces in a 30-minute bin. (Why "provider namespaces" rather than "resource types" is the bonus round.) Monday Detection 1 depends on a `ResourceType` column that isn't in the documented AzureActivity schema and on the legacy `ActivityStatus` column, so whether it fires depends on what your workspace actually populates. But both share a filter that matters more than any threshold:

```kql
| where ActivityStatusValue == "Success"
```

Here's the scorecard against the reported incident:

| Detection | What it needs | Does AzureActivity have it? | On this incident |
|---|---|---|---|
| Mon 1 — Bulk deletion | Successful deletes, ≥3 `ResourceType` values | Deletes yes; that column, maybe not | Depends on your schema |
| Mon 2 — Recon → destroy | Reads, then deletes | Enumeration reads not captured | No rows |
| Mon 3 — SP credential ops | Entra app credential changes | Different table, different plane | Not this attack |
| Tue 1 — Recon → bulk delete | Reads, then deletes | Enumeration reads not captured | No rows |
| Tue 2 — SP sign-in → Key Vault reads | Key Vault data-plane events | Not in AzureActivity | No rows |
| Tue 3 — Multi-type deletion | Successful deletes, ≥3 namespaces | Yes | Probably fires |

One fires, one maybe. And the one that fires sees the least interesting version of the attack, because of what the success filter removes:

- **Every recovery-tampering attempt.** The Site Recovery and Backup protection lock deletions all *failed* — and an identity trying to delete backup locks thirty seconds into a deletion burst is the single highest-fidelity ransomware-aligned signal in the whole incident. Microsoft maps it to T1490, Inhibit System Recovery. Success-only filters discard it.
- **Every SQL deletion attempt.** The intent to destroy databases is evidence of scope, even though the API version saved them.
- **The deletions that resource locks blocked.** And this is the part that should bother everyone: the better your preventive controls, the less your detection sees. In a tenant with locks on every storage account, Storm-3168's entire destructive sequence fails — and a success-only rule stays silent while an attacker with Contributor works through your estate trying to delete it.
- **The failed ListKeys probe that immediately preceded destruction.** Less than one second separates it from the first delete.

So the problems are three, and they stack: the detections ask for an event class the table doesn't record (resource-enumeration reads), they discard the outcome that carries the intent (failures), and they identify operations by searching English display names (`OperationName has "delete"`, `has_any ("list", "get", "read")`) when the same row carries a machine-readable operation path that already says exactly what happened.

That path is the fix. `OperationNameValue` isn't a sentence, it's a grammar:

```
MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE
MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION
MICROSOFT.AUTHORIZATION/LOCKS/DELETE
MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE
```

`{provider}/{type}[/{child type}...]/{verb}`. The verb is the last segment, and for the administrative operations that matter here the vocabulary is small — overwhelmingly `WRITE`, `DELETE`, and `ACTION`. The resource type is everything before the verb. An action's name is the segment before `ACTION`. Parse it once and every question the six detections asked by string-matching becomes a structural lookup — and the question none of them asked, "is this identity trying to delete the things that would let us recover?", becomes a provider prefix.

<br/>

### The KQL

```kql
let lookback = 2h;
// ── Thresholds: starting positions — baseline before scheduling ──
let DestroyVolumeThreshold    = 10;  // delete attempts by one principal
let DestroyDiversityThreshold = 3;   // distinct ARM resource types deleted
let ResourceGroupThreshold    = 2;   // whole resource groups deleted
let HarvestTargetThreshold    = 10;  // distinct resources whose secrets were requested
// ============================================================
// THE GRAMMAR.
//
// OperationNameValue is a path, not a sentence:
//   {PROVIDER}/{TYPE}[/{CHILD TYPE}...]/{VERB}
//
// The verb is the last segment. The resource type is
// everything before it. Neither depends on display-name
// wording. Administrative verbs are overwhelmingly WRITE,
// DELETE, ACTION. The Activity Log doesn't typically capture
// reads, and the ARM enumeration GETs used for recon aren't
// here to match.
//
// CredentialActions are ARM POST actions whose response body
// contains a secret. Unlike reads, these ARE logged — they are
// the attacker's credential collection, visible on the
// control plane.
// ============================================================
let CredentialActions = dynamic([
    "LISTKEYS", "LISTACCOUNTSAS", "LISTSERVICESAS",
    "LISTCONNECTIONSTRINGS", "LISTCREDENTIALS", "LISTCREDENTIAL",
    "LISTCLUSTERADMINCREDENTIAL", "LISTCLUSTERUSERCREDENTIAL",
    "LISTAUTHKEYS", "REGENERATEKEY", "PUBLISHXML", "BEGINGETACCESS"
]);
let RecoveryProviders = dynamic([
    "MICROSOFT.RECOVERYSERVICES", "MICROSOFT.DATAPROTECTION"
]);
AzureActivity
| where TimeGenerated >= ago(lookback)
| where CategoryValue =~ "Administrative"
// Positive assertion: the caller IS a GUID (a workload
// identity) — not "isn't a UPN", which also admits empty
// callers and platform-generated events.
| where Caller matches regex
    @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
// ============================================================
// TERMINAL OUTCOMES — BOTH OF THEM.
//
// Long-running ARM operations log Started/Accepted and then
// Succeeded or Failed. Counting terminal events only avoids
// triple-counting one delete. Keeping Failed is the point: a
// delete that a resource lock refused is still an attempt.
//
// Status values differ by ingestion path ("Success" vs
// "Succeeded", "Failure" vs "Failed"); a prefix match covers
// both. column_ifexists tolerates workspaces where only the
// legacy ActivityStatus column is populated.
// ============================================================
| extend Status = coalesce(ActivityStatusValue,
                           column_ifexists("ActivityStatus", ""))
| extend Outcome = case(
      Status startswith "Succe", "Succeeded",
      Status startswith "Fail",  "Failed",
                                 "NonTerminal")
| where Outcome != "NonTerminal"
// ── Parse the grammar ──
| extend OpPath     = toupper(OperationNameValue)
| extend Verb       = extract(@"/([^/]+)$", 1, OpPath)
| extend TargetType = extract(@"^(.+)/[^/]+$", 1, OpPath)
| extend Provider   = extract(@"^([^/]+)/", 1, OpPath)
| extend ActionName = iff(Verb == "ACTION",
                          extract(@"/([^/]+)/ACTION$", 1, OpPath), "")
// ============================================================
// CLASSIFY BY MEANING, NOT BY WORDING.
//
// ProtectionTamper is checked first so a lock or backup
// delete is never counted as ordinary destruction. It is
// deliberately broader than recovery infrastructure: ANY
// resource-lock deletion lands here, because a lock is a
// protective control whatever it protects. TamperKind below
// separates lock removals from Recovery Services / Data
// Protection deletes.
// ============================================================
| extend OpClass = case(
      Verb == "DELETE"
        and (OpPath startswith "MICROSOFT.AUTHORIZATION/LOCKS"
             or Provider in (RecoveryProviders)),         "ProtectionTamper",
      Verb == "DELETE",                                    "Destroy",
      Verb == "ACTION"
        and (ActionName in (CredentialActions)
             or OpPath endswith "/CONFIG/LIST/ACTION"),    "CredentialHarvest",
                                                           "Other")
| where OpClass != "Other"
// AppId from the token claims — stable across tables, used to
// pivot into AADServicePrincipalSignInLogs (see below).
// Claims_d is the preferred dynamic column; the string
// Claims column is the fallback for older ingestion paths.
| extend AppId = coalesce(
      tostring(column_ifexists("Claims_d", dynamic({})).appid),
      tostring(parse_json(column_ifexists("Claims", "{}")).appid))
// ============================================================
// ONE ROW PER IDENTITY.
// ============================================================
| summarize
    DestroyAttempts      = countif(OpClass == "Destroy"),
    DestroySucceeded     = countif(OpClass == "Destroy" and Outcome == "Succeeded"),
    DestroyFailed        = countif(OpClass == "Destroy" and Outcome == "Failed"),
    DestroyTypes         = dcountif(TargetType, OpClass == "Destroy"),
    DestroyTypeList      = make_set_if(TargetType, OpClass == "Destroy", 20),
    ResourceGroupDeletes = countif(OpClass == "Destroy"
                             and TargetType == "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS"),
    TamperAttempts       = countif(OpClass == "ProtectionTamper"),
    TamperFailed         = countif(OpClass == "ProtectionTamper" and Outcome == "Failed"),
    LockDeletes          = countif(OpClass == "ProtectionTamper"
                             and OpPath startswith "MICROSOFT.AUTHORIZATION/LOCKS"),
    RecoveryDeletes      = countif(OpClass == "ProtectionTamper"
                             and Provider in (RecoveryProviders)),
    TamperOps            = make_set_if(OperationNameValue, OpClass == "ProtectionTamper", 10),
    HarvestAttempts      = countif(OpClass == "CredentialHarvest"),
    HarvestSucceeded     = countif(OpClass == "CredentialHarvest" and Outcome == "Succeeded"),
    HarvestTargets       = dcountif(ResourceId, OpClass == "CredentialHarvest"),
    HarvestOps           = make_set_if(OperationNameValue, OpClass == "CredentialHarvest", 10),
    FirstDestroy         = minif(TimeGenerated, OpClass == "Destroy"),
    LastDestroy          = maxif(TimeGenerated, OpClass == "Destroy"),
    FirstTamper          = minif(TimeGenerated, OpClass == "ProtectionTamper"),
    FirstHarvest         = minif(TimeGenerated, OpClass == "CredentialHarvest"),
    LastHarvest          = maxif(TimeGenerated, OpClass == "CredentialHarvest"),
    Subscriptions        = make_set(SubscriptionId, 10),
    CallerIPs            = make_set(CallerIpAddress, 10),
    AppId                = take_anyif(AppId, isnotempty(AppId)),
    SampleTargets        = make_set_if(ResourceId, OpClass != "CredentialHarvest", 20)
  by Caller
// ============================================================
// THE VERDICT.
//
// Three independent signals. Destruction is volume OR
// diversity OR whole resource groups — a 100-account storage
// wipe is one resource type and must not slip under a
// diversity-only threshold. Protection tampering fires on ANY
// attempt, successful or not — but a lock removal with
// nothing else around it gets its own, lower verdict, because
// IaC pipelines legitimately manage locks. Harvest needs
// breadth, because one ListKeys is an app starting up; thirty
// is a sweep.
// ============================================================
| extend DestroyWindowMin  = datetime_diff('minute', LastDestroy, FirstDestroy)
| extend DestroysPerMinute = round(todouble(DestroyAttempts)
                                   / max_of(1, DestroyWindowMin), 1)
| extend HasMassDestroy    = DestroyAttempts >= DestroyVolumeThreshold
                          or DestroyTypes >= DestroyDiversityThreshold
                          or ResourceGroupDeletes >= ResourceGroupThreshold
| extend HasProtectionTamper = TamperAttempts > 0
| extend HasHarvestSweep     = HarvestTargets >= HarvestTargetThreshold
| extend BlockedByControls   = (DestroyFailed + TamperFailed) > 0
| extend TamperKind = case(
      LockDeletes > 0 and RecoveryDeletes > 0, "LocksAndRecovery",
      RecoveryDeletes > 0,                     "RecoveryOnly",
      LockDeletes > 0,                         "LocksOnly",
                                               "")
| extend ChainScore = toint(HasMassDestroy)
                    + toint(HasProtectionTamper)
                    + toint(HasHarvestSweep)
| extend Verdict = case(
      HasMassDestroy and HasProtectionTamper and HasHarvestSweep, "FullImpactChain",
      HasMassDestroy and HasProtectionTamper,                      "DestroyAndTamperProtection",
      HasMassDestroy and HasHarvestSweep,                          "DestroyAndHarvest",
      HasMassDestroy,                                              "MassDestruction",
      HasProtectionTamper and RecoveryDeletes > 0,                 "RecoveryTamper",
      HasProtectionTamper and HasHarvestSweep,                     "LockRemovalAndHarvest",
      HasProtectionTamper,                                         "LockRemovalOnly",
                                                                   "CredentialHarvestSweep")
| where ChainScore > 0
| extend OutcomeMix = strcat(
      "destroy ", DestroySucceeded, " ok / ", DestroyFailed, " failed; ",
      "tamper ",  TamperAttempts - TamperFailed, " ok / ", TamperFailed, " failed; ",
      "harvest ", HarvestSucceeded, " ok / ", HarvestAttempts - HarvestSucceeded, " failed")
| project
    Verdict, ChainScore, OutcomeMix, BlockedByControls,
    Caller, AppId, Subscriptions, CallerIPs,
    FirstDestroy, LastDestroy, DestroyAttempts, DestroysPerMinute,
    DestroyTypes, DestroyTypeList, ResourceGroupDeletes,
    FirstTamper, TamperAttempts, TamperKind, LockDeletes, RecoveryDeletes, TamperOps,
    FirstHarvest, LastHarvest, HarvestAttempts, HarvestTargets, HarvestOps,
    SampleTargets
| order by ChainScore desc, DestroyAttempts desc
```

<br/>

![DevSecOpsDadAttack!](/assets/img/TheActivityLogIsNotTheActivity/3.png)

<br/>

### The lines that do the work

Three structural moves.

The first is parsing `OperationNameValue` into `Verb`, `TargetType`, `Provider`, and `ActionName` with four anchored `extract()` calls. Everything downstream is a lookup on those columns, not a substring search on prose. `OperationName has "delete"` matches whatever the display string happens to say; `Verb == "DELETE"` matches what ARM actually did. And because the resource type comes from the operation path rather than from indexing into `ResourceId`, a resource group deletion carries the type `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS` instead of an empty string that a later `isnotempty()` quietly drops (bonus round).

The second is the outcome handling: terminal events only, and *both* terminal outcomes. The output's `OutcomeMix` column and `BlockedByControls` flag turn failure from something the query discards into something the analyst reads. On the Storm-3168 incident, the row would say something like *destroy 100+ ok / a handful failed; tamper 0 ok / several failed; harvest 30+ ok / 1 failed*, with `BlockedByControls = true`. That tells the analyst in one line that locks held, which resources survived because of them, and that the identity's intent included recovery infrastructure — before anyone opens the Activity Log blade.

The third is the three-signal verdict. Destruction is volume *or* diversity *or* whole resource groups, because the most destructive phase of this incident — 100+ storage accounts — is a single resource type and sails under a diversity-only threshold. Protection tampering fires on any attempt, because there's no business reason for a workload identity to try deleting a backup protection lock in the middle of a deletion burst. The class is deliberately broader than recovery: it includes *any* resource-lock deletion, since a lock is a protective control whatever it protects. `TamperKind` tells the analyst which they're looking at, and a lock removal with no destruction or harvest beside it drops to its own `LockRemovalOnly` verdict rather than borrowing the severity of the full chain. Harvest needs breadth (`dcountif(ResourceId, ...)`), because one ListKeys is an app starting up and thirty across your storage estate is a sweep. Storm-3168 lands at `FullImpactChain` with `ChainScore = 3`. A Terraform destroy of a dev environment lands at `MassDestruction` with `ChainScore = 1` — and an allowlist entry, by AppId.

<br/>

### The shadow of the reads

You cannot see the 300+ reads. You *can* see the tokens they were made with. Every time a service principal authenticates to Azure Resource Manager, Entra writes a row to `AADServicePrincipalSignInLogs` — and Microsoft noted five distinct tokens issued to the destructive principal alone. The reconnaissance principal never deleted anything, so the composite above never sees it; this is the closest thing you have to a recon detection on the defender's side of the glass:

```kql
// Service principals obtaining ARM tokens from an IP not seen
// for that app in the prior 30 days. Requires the
// AADServicePrincipalSignInLogs diagnostic category.
let lookback = 1d;
let ArmResourceId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"; // Azure Resource Manager
let Recent =
    AADServicePrincipalSignInLogs
    | where TimeGenerated >= ago(lookback)
    | where ResourceIdentity == ArmResourceId
    // tostring() works whether ResultType is typed as int or
    // string in your workspace — don't bet on the representation.
    | where tostring(ResultType) in ("0", "Success")
    | summarize
        TokenIssuances = count(),
        IPs            = make_set(IPAddress, 20),
        FirstToken     = min(TimeGenerated),
        LastToken      = max(TimeGenerated)
      by AppId, ServicePrincipalName;
let Baseline =
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (ago(30d) .. ago(lookback))
    | where ResourceIdentity == ArmResourceId
    | where tostring(ResultType) in ("0", "Success")
    | summarize BaselineIPs = make_set(IPAddress, 200) by AppId;
Recent
| join kind=leftouter Baseline on AppId
| extend NewIPs = set_difference(IPs, coalesce(BaselineIPs, dynamic([])))
| where array_length(NewIPs) > 0
| extend NeverSeenBefore = isnull(BaselineIPs)
| project FirstToken, LastToken, ServicePrincipalName, AppId,
          TokenIssuances, NewIPs, NeverSeenBefore
| order by FirstToken desc
```

`AppId` is the join key back to the composite's `AppId` column — both come from the token, so there's no guessing whether `Caller` holds an object ID or an application ID. A row here followed by a row in the composite for the same `AppId` is the whole Storm-3168 story, minus the part your logs were never going to show you. If you run Defender for Resource Manager, its alerts in `SecurityAlert` are Microsoft's view of the reads; join them on the same principal and you get the recon stage back.

<br/>

### Validate before you deploy

Three checks, and the second one is the argument of this whole act, run against your own data.

```kql
// 1. Which of the columns these queries depend on does your
//    AzureActivity actually have?
AzureActivity
| getschema
| where ColumnName in ("ActivityStatus", "ActivityStatusValue",
                       "OperationNameValue", "ResourceType",
                       "Claims", "Claims_d")
| project ColumnName, ColumnType
```

```kql
// 2. What verbs does AzureActivity record?
AzureActivity
| where TimeGenerated >= ago(7d)
| where CategoryValue =~ "Administrative"
| extend Verb = extract(@"/([^/]+)$", 1, toupper(OperationNameValue))
| summarize Events = count(), Example = take_any(OperationNameValue) by Verb
| order by Events desc
```

```kql
// 3. What does the original "reconnaissance" filter actually match?
AzureActivity
| where TimeGenerated >= ago(7d)
| where tolower(OperationName) has_any ("list", "get", "read")
| summarize Events = count() by OperationNameValue
| order by Events desc
```

Check one tells you whether Monday Detection 1 can even resolve its `ResourceType` column, and which status column your ingestion path populates. Check two should be dominated by `WRITE`, `DELETE`, and `ACTION`. If a `READ` bucket appears at all, look at its `Example` column — it won't be the VM, resource group, and subscription enumeration Storm-3168 performed. Check three is the uncomfortable one: run it and look at what the "recon" queries have been counting. In most tenants it's a list of `.../LISTKEYS/ACTION` and similar credential-returning actions — the detection's reconnaissance stage is a credential-access detection wearing the wrong label.

<br/>

### Keeping it honest

- **The GUID check on `Caller` is a positive assertion, and it intentionally includes managed identities.** The source queries' caveats treat managed identities as a false-positive source. They aren't — a managed identity token pulled from IMDS on a compromised VM is the same threat model as a leaked client secret, with the same blast radius. If you need to separate them, the token claims distinguish them; don't drop them.
- **Not every failure reaches AzureActivity.** A delete denied by a resource lock is recorded as a failed operation. A request rejected earlier — Storm-3168's SQL deletions failed on an unsupported API version — may never produce a customer-visible event. Microsoft could see those attempts in its own telemetry; you may not. `BlockedByControls` reports what you can see, which is a floor, not the total.
- **Terminal-only counting assumes the terminal event carries `Caller`.** It should, but ingestion paths vary, and I haven't verified it across tenants. Check before scheduling: `AzureActivity | where ActivityStatusValue startswith "Succe" or ActivityStatusValue startswith "Fail" | summarize Total = count(), EmptyCaller = countif(isempty(Caller))`. If `EmptyCaller` is nonzero, recover the identity by joining those rows to the `Started` event on `CorrelationId` before classifying.
- **A lock removal on its own is the noisiest branch.** Because protection tampering fires on any attempt, an IaC pipeline that removes a lock before a planned change will produce a `LockRemovalOnly` row. That's intentional — lock deletions by workload identities are rare enough to be worth seeing — but route `LockRemovalOnly` to a lower severity than anything with `ChainScore >= 2`, or allowlist the pipelines that manage locks by `AppId`.
- **`CredentialActions` is a list — but it's a list of API semantics, not attacker-chosen labels.** After two articles criticising enumeration, I'm aware of the irony. The difference: an attacker can rename a binary, but cannot rename `listKeys`. The list is finite and defined by the Azure REST surface; extend it as you find other secret-returning actions in check three.
- **Terraform is your biggest false positive, in both directions.** The azurerm provider calls ListKeys on storage accounts during refresh, and `terraform destroy` deletes many resource types quickly. Allowlist by `AppId` (stable) via a watchlist, never by display name, and expect pipeline principals to land at `ChainScore = 1`. A pipeline principal at `ChainScore = 2` or `3` is the alert.
- **The two-hour lookback covers the destructive phase, not the whole campaign.** Microsoft's destruction and credential collection spanned about thirty-five minutes, so a two-hour window run every thirty minutes sees them together. The recon phase spanned fifteen-plus hours and was invisible anyway. Deduplicate alerts on `Caller` so overlapping windows don't produce repeat incidents.
- **This query detects the attack in progress, not before it.** The real prevention lives in Microsoft's mitigation list: resource locks and deletion protection (which demonstrably saved storage accounts here), least-privilege roles on workload identities, and treating any secret that ever touched a public repository or issue as compromised.

<br/>

---

<br/>

## 🥈 Act II: The Name Is Not the Binary

![Act II](/assets/img/TheActivityLogIsNotTheActivity/4.png)

Rapid7's [BPFDoor and AVERAT report](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge) describes a staging chain on Linux mail-security appliances: a dropper writes a shell script to the appliance's storage mount and runs it; the script copies two binaries from the appliance's add-on package directory into `/sbin` as `ntpdate` and `udevds`, launches each, and deletes it ten seconds later while the process keeps running. One of those payloads is the dropper re-executing itself as a watchdog; the other is AVERAT, which beacons out over SMTP. Both end up resident with no on-disk image.

The pipeline wrote six detections for this across [Saturday](https://devsecopsdadattack.com/2026-10-03-detection-engineering-brief-saturday-october-3-2026/) and [Sunday](https://devsecopsdadattack.com/2026-10-04-detection-engineering-brief-sunday-october-4-2026/): two "masqueraded binary staged in `/sbin`" rules (production candidates), two "execute-then-delete within 30 seconds" correlations (production candidates), and two "shell script written and executed by a non-interactive process" hunts. Four of them begin the same way:

```kql
| where FolderPath startswith "/sbin"
| where FileName in ("ntpdate", "udevds")
```

Two filenames. The same report notes that the South Korean BPFDoor cluster rotates through *ten* daemon names, that another sample spoofs an Oracle-style process name, and that Rapid7's earlier whitepaper documented variant-specific names. Across every sample, the authors pick names that look unremarkable on the specific appliance they're targeting. A filename in this campaign isn't an indicator, it's a costume — and costumes are the one thing the operator is guaranteed to change, because changing them costs nothing.

Here's the thing, though: Saturday and Sunday's Detection 2 already found the right *shape*. "Process launched from a path, file at that path deleted seconds later" is exactly the behavior that makes this chain distinctive, and it's behavior the operator can't easily drop — the whole point of the chain is to leave nothing to hash or quarantine. The shape was right. The names were the problem. Remove them and the detection gets stronger, not noisier, provided you replace the names with something that discriminates as well as they did.

That something is *survival*. Legitimate execute-then-delete happens constantly on Linux — autoconf's `conftest` binaries, installer stubs in `/tmp`, package maintainer scripts — but in nearly every legitimate case the process *exits* and then the file is removed. The BPFDoor chain does it the other way around: the file is removed while the process is still running. That ordering — unlinked, then still acting — is the attacker's mechanism, not the attacker's costume.

And the hunting queries have a different problem. Saturday Detection 3 and Sunday Detection 3 look for scripts via:

```kql
| where FileName endswith ".sh"
```

The dropper's script in Rapid7's report is named `updIptable.php`. It's a shell script with a shebang and a `.php` extension, executed via `system()`. The brief's own caveats say "if the dropper does not use a `.sh` extension, this detection will not fire." It doesn't, and it won't. The extension was never the type; the shebang is the type, and the extension is another costume.

<br/>

### The KQL

```kql
let lookback       = 1d;
let unlinkWindow   = 60s;   // exec → unlink
let stageWindow    = 5m;    // write → exec
let survivalWindow = 30m;   // unlink → evidence of life
// ============================================================
// LOCATION TIERS, NOT FILENAMES.
//
// Binaries in these directories are installed by a package
// manager and stay on disk. One that is executed and unlinked
// within a minute is anomalous whatever it's called.
// ============================================================
let SystemBinDirs = dynamic([
    "/sbin", "/usr/sbin", "/bin", "/usr/bin",
    "/usr/local/sbin", "/usr/local/bin", "/lib", "/usr/lib"
]);
// ============================================================
// STAGE A: UNLINKS (smaller side of the join — goes left).
//
// FolderPath semantics vary (some events include the file
// name, some don't); normalise to a full path either way.
// ============================================================
let Unlinks =
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "FileDeleted"
    | extend ImagePath = iff(FolderPath endswith strcat("/", FileName),
                             FolderPath,
                             strcat(trim_end("/", FolderPath), "/", FileName))
    | where ImagePath startswith "/"           // Linux paths only
    | project DeleteTime = Timestamp, DeviceId, ImagePath,
              DeleterName = InitiatingProcessFileName,
              DeleterCommandLine = InitiatingProcessCommandLine;
let Execs =
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | extend ImagePath = iff(FolderPath endswith strcat("/", FileName),
                             FolderPath,
                             strcat(trim_end("/", FolderPath), "/", FileName))
    | where ImagePath startswith "/"
    // Semi-join: keep only executions of paths that were
    // deleted on the same device. This is the expensive scan —
    // every Linux process creation in the lookback — and it
    // shrinks to candidates before the time-window join runs.
    | join kind=leftsemi (Unlinks | distinct DeviceId, ImagePath)
        on DeviceId, ImagePath
    | project ExecTime = Timestamp, DeviceId, DeviceName, ImagePath,
              FileName, ProcessId, ProcessCreationTime,
              ProcessCommandLine, SHA256, AccountName,
              ParentName = InitiatingProcessFileName,
              ParentCommandLine = InitiatingProcessCommandLine;
// ============================================================
// THE ANCHOR: executed, then unlinked within the window.
// Correlate → constrain → collapse, one row per process.
// (DeviceId, ProcessId, ProcessCreationTime) identifies a
// process; PIDs alone recycle.
// ============================================================
let ExecThenUnlink =
    Unlinks
    | join kind=inner Execs on DeviceId, ImagePath
    | where DeleteTime between (ExecTime .. (ExecTime + unlinkWindow))
    | summarize arg_min(DeleteTime, *)
        by DeviceId, ProcessId, ProcessCreationTime;
// ============================================================
// ENRICHMENT 1: WHO PUT IT THERE, AND FROM WHERE.
//
// In the reported chain the stager is `cp`, and its command
// line names the SOURCE — the copy still on disk in the
// appliance's package directory. That's the file the
// responder can actually hash and quarantine.
// ============================================================
let Stagings =
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where ActionType in ("FileCreated", "FileRenamed", "FileModified")
    | extend ImagePath = iff(FolderPath endswith strcat("/", FileName),
                             FolderPath,
                             strcat(trim_end("/", FolderPath), "/", FileName))
    | where ImagePath startswith "/"
    | project StageTime = Timestamp, DeviceId, ImagePath,
              StagerName = InitiatingProcessFileName,
              StagerCommandLine = InitiatingProcessCommandLine,
              StagerParent = InitiatingProcessParentFileName;
let CorrelatedStaging =
    ExecThenUnlink
    | project DeviceId, ProcessId, ProcessCreationTime, ImagePath, ExecTime
    | join kind=inner Stagings on DeviceId, ImagePath
    | where StageTime between ((ExecTime - stageWindow) .. ExecTime)
    | summarize arg_max(StageTime, StagerName, StagerCommandLine, StagerParent)
        by DeviceId, ProcessId, ProcessCreationTime
    | extend CopySource = iff(StagerName in~ ("cp", "mv", "install", "busybox"),
          extract(@"\s(/[^\s]+)\s+/[^\s]+\s*$", 1, StagerCommandLine), "");
// ============================================================
// ENRICHMENT 2: DID IT SURVIVE ITS OWN DELETION?
//
// Any network, file, or child-process event initiated by the
// same process AFTER its image was unlinked. This is what
// separates the implant (unlinked while running) from
// conftest (exited, then cleaned up).
//
// Enrichment, not a gate: a passive BPF sniffer may emit
// nothing until it receives a magic packet.
// ============================================================
// PIDs are device-local and recycled, so candidates are
// (DeviceId, ProcessId) pairs, applied as a semi-join — not a
// global PID list, which make_set() can silently truncate.
let CandidateProcs = ExecThenUnlink | distinct DeviceId, ProcessId;
let ProcessActivity =
    union
      (DeviceNetworkEvents
       | where Timestamp >= ago(lookback)
       | project ActTime = Timestamp, DeviceId,
                 ProcessId = InitiatingProcessId,
                 ActCreationTime = InitiatingProcessCreationTime,
                 ActKind = "Network",
                 ActDetail = strcat(RemoteIP, ":", RemotePort)
       | join kind=leftsemi CandidateProcs on DeviceId, ProcessId),
      (DeviceFileEvents
       | where Timestamp >= ago(lookback)
       | project ActTime = Timestamp, DeviceId,
                 ProcessId = InitiatingProcessId,
                 ActCreationTime = InitiatingProcessCreationTime,
                 ActKind = "File", ActDetail = FolderPath
       | join kind=leftsemi CandidateProcs on DeviceId, ProcessId),
      (DeviceProcessEvents
       | where Timestamp >= ago(lookback)
       | project ActTime = Timestamp, DeviceId,
                 ProcessId = InitiatingProcessId,
                 ActCreationTime = InitiatingProcessCreationTime,
                 ActKind = "ChildProcess", ActDetail = ProcessCommandLine
       | join kind=leftsemi CandidateProcs on DeviceId, ProcessId);
let CorrelatedSurvival =
    ExecThenUnlink
    | project DeviceId, ProcessId, ProcessCreationTime, DeleteTime
    | join kind=inner ProcessActivity on DeviceId, ProcessId
    | where abs(datetime_diff('second', ActCreationTime, ProcessCreationTime)) <= 1
    | where ActTime > DeleteTime and ActTime <= DeleteTime + survivalWindow
    | summarize
        PostUnlinkEvents = count(),
        PostUnlinkKinds  = make_set(ActKind),
        FirstPostUnlink  = min(ActTime),
        PostUnlinkSample = make_set(ActDetail, 10)
      by DeviceId, ProcessId, ProcessCreationTime;
// ============================================================
// THE VERDICT.
// ============================================================
ExecThenUnlink
| join kind=leftouter CorrelatedStaging  on DeviceId, ProcessId, ProcessCreationTime
| join kind=leftouter CorrelatedSurvival on DeviceId, ProcessId, ProcessCreationTime
| extend ImageDir       = extract(@"^(.*)/[^/]+$", 1, ImagePath)
| extend LocationTier   = case(
      ImageDir in (SystemBinDirs),                                    "SystemBin",
      ImageDir startswith "/tmp" or ImageDir startswith "/var/tmp"
        or ImageDir startswith "/dev/shm",                            "Temp",
                                                                      "Other")
| extend SurvivedUnlink = coalesce(PostUnlinkEvents, 0) > 0
| extend SecondsToUnlink = datetime_diff('second', DeleteTime, ExecTime)
| extend Verdict = case(
      SurvivedUnlink and LocationTier == "SystemBin", "ResidentFromDeletedSystemImage",
      SurvivedUnlink,                                 "ResidentFromDeletedImage",
      LocationTier == "SystemBin",                    "SystemBinExecThenUnlink",
                                                      "ExecThenUnlink")
// Outside system dirs, require proof of life — this is the
// line that removes conftest and installer noise.
| where LocationTier == "SystemBin" or SurvivedUnlink
| project
    ExecTime, DeleteTime, SecondsToUnlink, Verdict, LocationTier,
    DeviceName, ImagePath, FileName, SHA256, ProcessId,
    ProcessCommandLine, AccountName, ParentName, ParentCommandLine,
    StageTime, StagerName, StagerCommandLine, StagerParent, CopySource,
    DeleterName, DeleterCommandLine,
    SurvivedUnlink, PostUnlinkEvents, PostUnlinkKinds,
    FirstPostUnlink, PostUnlinkSample
| order by SurvivedUnlink desc, ExecTime desc
```

<br/>

### The lines that do the work

The filename list is gone, and three things replaced it.

The anchor is the join of `FileDeleted` to process creation on the *same path*, constrained to sixty seconds — the exact shape Saturday and Sunday's Detection 2 had, minus `FileName in ("ntpdate", "udevds")`. Rename the payloads to `chronyd` or `polkitd` or `ora_ppmond` and this still fires, because it never asked what they were called.

The discriminator is `SurvivedUnlink`: activity from the same process — keyed on device, PID, *and* creation time, because PIDs recycle — after its image was deleted. This is the line that makes dropping the names safe. A `conftest` binary exits before `rm` runs, so it never has post-unlink activity, and the `where LocationTier == "SystemBin" or SurvivedUnlink` filter removes it. AVERAT beacons every ten to eleven minutes, comfortably inside the thirty-minute survival window; the watchdog instance rewrites its marker file when it goes missing. Both are processes doing things after their binaries stopped existing, which is precisely Rapid7's top host-based recommendation — hunt for processes whose executable has been unlinked — expressed in the tables Defender actually gives you.

The responder's column is `CopySource`. In the reported chain, the stager is a plain `cp` whose command line names its source in the appliance's add-on package directory. The file in `/sbin` is gone; the file it was copied *from* isn't. Pulling the source out of the stager's command line hands the analyst the one artifact they can still hash, submit, and quarantine — and, because that directory is likely how the firmware relaunches the implant at boot, the persistence mechanism too.

The candidate filtering is semi-joins all the way down. `Execs` is cut to paths that were actually deleted on the same device before any time-window work happens, and the survival lookup is cut to candidate `(DeviceId, ProcessId)` pairs. An earlier draft of this query built a global PID list with `toscalar(make_set(ProcessId))` and filtered with `in`. That's broader than it looks (PIDs are device-local, so a PID from one host matches unrelated processes on every other host), and `make_set()` has a size cap that truncates silently. A truncated candidate list doesn't error; it just loses survival evidence. That's the exact failure this series keeps writing about, so it went.

Both enrichments follow last edition's rule: **correlate → constrain → collapse** in their own CTEs, then `leftouter` back to the anchor. A staging or survival event outside its window is excluded inside the CTE; it never reaches the outer join, so it can't null out a row that should have been reported at a lower verdict.

<br/>

### And the script was never a `.sh`

The hunting queries' job — catch the dropper writing and running its script — is still worth doing; it's the earliest observable step. It just needs to stop asking what the file is named and start asking how it was used: *a file was written, and within a minute a shell was invoked with that file's path as an argument.*

```kql
let lookback   = 1d;
let execWindow = 60s;
let Shells = dynamic(["sh", "bash", "dash", "ash", "ksh", "zsh", "busybox"]);
// Every absolute path passed to a shell — `sh -c /path`,
// `/bin/sh /path`, or a shebang exec, which surfaces as the
// interpreter with the script path as an argument.
let ShellRuns =
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName in~ (Shells)
    | extend ScriptArgs = extract_all(@"\s(/[^\s'""]+)", ProcessCommandLine)
    | mv-expand WrittenPath = ScriptArgs to typeof(string)
    | project ExecTime = Timestamp, DeviceId, DeviceName, WrittenPath,
              ShellCommandLine = ProcessCommandLine,
              ShellParent = InitiatingProcessFileName;
let Writes =
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where ActionType in ("FileCreated", "FileModified")
    | extend WrittenPath = iff(FolderPath endswith strcat("/", FileName),
                               FolderPath,
                               strcat(trim_end("/", FolderPath), "/", FileName))
    | project WriteTime = Timestamp, DeviceId, WrittenPath,
              WriterName = InitiatingProcessFileName,
              WriterCommandLine = InitiatingProcessCommandLine;
ShellRuns
| join kind=inner Writes on DeviceId, WrittenPath
| where ExecTime between (WriteTime .. (WriteTime + execWindow))
| summarize arg_min(ExecTime, *) by DeviceId, WrittenPath
// The extension is enrichment, not a filter — and a script
// whose extension claims to be something else is a stronger
// signal, not a reason to skip it.
| extend ScriptExt     = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, WrittenPath))
| extend ExtensionLies = isnotempty(ScriptExt) and ScriptExt !in ("sh", "bash")
| extend WriterIsShell = WriterName in~ (Shells)
| project WriteTime, ExecTime, DeviceName, WrittenPath, ScriptExt,
          ExtensionLies, WriterName, WriterIsShell, WriterCommandLine,
          ShellCommandLine, ShellParent
| order by ExtensionLies desc, ExecTime desc
```

A shell script called `updIptable.php`, written by a binary and executed seconds later via `sh -c`, sorts to the top with `ExtensionLies = true`. The same query still catches a dropper that uses `.sh`, or no extension, or `.dat` — because none of those were ever the thing being detected.

<br/>

### Keeping it honest

- **The appliances in Rapid7's report almost certainly don't run Defender for Endpoint.** These are vendor mail-security gateways; you generally can't install an EDR agent on them. All six source queries share this assumption, and so do mine. The logic holds on any Linux host where MDE *is* deployed — and the same chain works against general-purpose servers. For appliances, rebuild the same shape on whatever the device can export: `execve` and `unlink` audit events via syslog, joined on path and time, in exactly this structure.
- **`FileDeleted` coverage on Linux depends on agent version and path.** The source briefs flagged this correctly. Run `DeviceFileEvents | where ActionType == "FileDeleted" | where FolderPath startswith "/usr" | take 10` on a Linux device group before scheduling. If it returns nothing, the anchor is blind.
- **The ±1-second tolerance on process creation time is deliberate.** `ProcessCreationTime` and `InitiatingProcessCreationTime` should be identical for the same process, but representation and rounding differ across tables in some environments. Exact equality silently drops matches; a one-second band costs nothing given the PID also has to match.
- **Package upgrades can look similar — but not inside sixty seconds.** A running daemon whose binary was replaced during an upgrade is the classic false positive for "executable deleted" hunts. It doesn't match here, because the daemon was started days before the delete. The `unlinkWindow` is what separates an implant that unlinks itself from a service that outlived its old binary. Widening it brings that noise back.
- **`CopySource` only works when the stager is a copy utility with a readable command line.** If the dropper writes the payload itself with `fwrite()`, there's no source path to extract — but `StagerName` will then be the dropper binary, which is better.
- **`ImageDir in (SystemBinDirs)` is an exact directory match, not a tree.** A binary in `/usr/lib/<package>/` lands in the `Other` tier and needs survival evidence to surface. That's deliberate — it's a location tier, not a filesystem walk — but add subdirectories you care about explicitly.
- **Passive BPF implants are designed to be silent.** A sniffer waiting for a magic packet may produce no post-unlink events for days. That's why `SurvivedUnlink` raises the verdict rather than gating it, and why a `SystemBinExecThenUnlink` row with no survival evidence still deserves triage. If your agent surfaces the kernel's ` (deleted)` suffix in `InitiatingProcessFolderPath` for later events, that's a cheap confirmation to add.

<br/>

---

<br/>

## 🎖 Honorable Mention: "Without Prior Installation Record" — Without Checking One

![Honorable Mention](/assets/img/TheActivityLogIsNotTheActivity/5.png)

[Sunday's Detection 4](https://devsecopsdadattack.com/2026-10-04-detection-engineering-brief-sunday-october-4-2026/) is titled *ScreenConnect Client Execution on Host Without Prior Installation Record*, drawing on [SANS ISC's reporting on ScreenConnect abuse](https://isc.sans.edu/diary/rss/33388) and arriving the same week as Microsoft's report on [phishing that abused MSP360 to deploy ScreenConnect](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/). The title describes exactly the right detection: the client appearing on a device where it never existed before. The query summarises every ScreenConnect execution and joins network activity — and never compares against a baseline. There is no "prior" anywhere in it. It's a ScreenConnect inventory with a detection's name on it.

And like five other ScreenConnect queries this week, it finds the client by name:

```kql
| where FileName has_any ("ScreenConnect", "screenconnect", "ConnectWise")
    or ProcessCommandLine has_any ("ScreenConnect", "screenconnect", "ConnectWise")
```

The brief's own caveat says rebranded or renamed clients evade this "entirely." ScreenConnect supports white-labelling as a product feature; the name is configurable by whoever runs the server. What isn't configurable is how the client finds its way home. The guest client launches with a query-string argument that tells it which relay to dial and which session to join — `e=<session type>` (`Access` for unattended clients, `Support` for ad hoc sessions), `y=Guest`, `h=<relay host>`, `p=<port>`, `s=<session>`. Rename the binary, rebrand the installer, change the folder: the observed guest-client invocation still carries its connection configuration, relay endpoint included. That's the property to detect, and the relay host it yields is the identity to baseline.

```kql
let lookback = 1d;
let baseline = 30d;
// Your sanctioned ScreenConnect instance(s). Everything else
// is someone else's server.
let ApprovedRelays = dynamic(["instance-yourco-relay.screenconnect.com"]);
DeviceProcessEvents
| where Timestamp >= ago(baseline)
// Guest participant + a relay host. The session type (e=) is
// extracted, not filtered: Access (unattended) and Support
// (ad hoc) are both abused, and the attacker picks which.
| where ProcessCommandLine contains "y=Guest"
| extend RelayHost   = tolower(extract(@"[?&]h=([^&\s""]+)", 1, ProcessCommandLine)),
         RelayPort   = extract(@"[?&]p=(\d+)", 1, ProcessCommandLine),
         SessionType = extract(@"[?&]e=([A-Za-z]+)", 1, ProcessCommandLine)
| where isnotempty(RelayHost)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp),
    Images    = make_set(FileName, 5),
    Paths     = make_set(FolderPath, 5),
    Parents   = make_set(InitiatingProcessFileName, 5),
    SHA256s   = make_set(SHA256, 5),
    SessionTypes = make_set(SessionType, 5)
  by DeviceId, DeviceName, RelayHost, RelayPort
// THE ACTUAL "WITHOUT PRIOR INSTALLATION RECORD":
// this device + relay pair did not exist in the prior 29 days.
| where FirstSeen >= ago(lookback)
| extend Approved      = RelayHost in~ (ApprovedRelays)
| extend RenamedClient = tostring(Images) !contains "screenconnect"
| where not(Approved)
| project FirstSeen, LastSeen, DeviceName, RelayHost, RelayPort,
          SessionTypes, RenamedClient, Images, Paths, Parents, SHA256s
| order by FirstSeen desc
```

Two changes from the source: identify the client by the connection arguments it's launched with instead of the name it's free to change, and make the title true — `FirstSeen >= ago(lookback)` inside a thirty-day baseline is the prior-installation check. Keying the baseline on device *and relay* means your own sanctioned client being present doesn't mask an attacker's second instance pointing somewhere else, which is exactly the redundant-access pattern the MSP360 reporting describes. `RenamedClient` and `SessionTypes` don't filter. One tells the analyst when the binary was trying not to be recognised; the other says whether this is a persistent unattended client or a one-off support session. An earlier draft required `e=Access`, which would have missed every ad hoc support session — narrowing on a value the attacker chooses, which is the exact mistake this article is about. Caveats: the argument grammar is the vendor's, not a standard, so validate it against your own sanctioned clients before scheduling. Installers and installed clients also carry their configuration in the file and on disk, so process-launch arguments are where it's *observable*, not the only place it lives. And thirty days of baseline only proves absence for thirty days.

<br/>

---

<br/>

## 🥊 Bonus Round: `split(ResourceId, "/")[6]` Is the Namespace, and Resource Groups Don't Have an Index 6

![Bonus Round](/assets/img/TheActivityLogIsNotTheActivity/6.png)

Tuesday's Detection 1 and Detection 3 derive the resource type for their "distinct resource types deleted" threshold like this:

```kql
| extend ResourceType = tostring(coalesce(split(ResourceId, "/")[6], ""))
| where isnotempty(ResourceType)
```

It looks like an off-by-something risk, and it is — in two directions at once. Run it against a few real resource IDs:

```kql
datatable(ResourceId: string) [
    "/subscriptions/1111/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm01",
    "/subscriptions/1111/resourceGroups/prod-rg/providers/Microsoft.Compute/disks/vm01-osdisk",
    "/subscriptions/1111/resourceGroups/prod-rg/providers/Microsoft.Network/networkInterfaces/vm01-nic",
    "/subscriptions/1111/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/sql01/databases/db01",
    "/subscriptions/1111/resourceGroups/prod-rg"
]
| extend Parts = split(ResourceId, "/")
| extend PartCount = array_length(Parts),
         First     = tostring(Parts[0]),
         Index6    = tostring(Parts[6])
```

| Resource | PartCount | First | Index6 |
|---|---|---|---|
| Virtual machine | 9 | *(empty)* | `Microsoft.Compute` |
| OS disk | 9 | *(empty)* | `Microsoft.Compute` |
| Network interface | 9 | *(empty)* | `Microsoft.Network` |
| SQL database | 11 | *(empty)* | `Microsoft.Sql` |
| Resource group | 5 | *(empty)* | *(empty)* |

Two things are happening. First, an ARM resource ID begins with its delimiter, so `split()` produces an empty string at index 0 and every position shifts by one. Index 6 isn't the type, it's the provider namespace. A VM, its OS disk, and its NIC — three resource types by any reasonable definition — count as **two**. Every compute-heavy deletion undercounts; every storage-only wipe (Storm-3168's 100+ accounts) counts as **one**.

Second, a resource group's ID has only five parts. Index 6 is out of range, which in KQL returns null rather than an error; `tostring()` makes it an empty string; `isnotempty()` drops the row. The brief's caveat describes short IDs as an edge case that "will produce empty strings that inflate or deflate DistinctResourceTypes counts." It's worse than that. Deleting a resource group removes everything inside it in a single call — it is the most destructive operation an Azure identity can perform in one request — and it is the one operation this expression is guaranteed to discard. An attacker who deletes five resource groups instead of five hundred resources produces zero rows.

Both queries run without error. Both produce a plausible-looking `ResourceType` column full of real strings from the data. That's the pattern from the last three bonus rounds: the expression does exactly what it says, and not what the column name promises, and the column name is what the analyst reads.

The fix in Act I sidesteps `ResourceId` entirely — `OperationNameValue` already carries the type, and a resource group delete reads `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE`. If you do need the type from the resource ID, anchor on the structure rather than the position:

```kql
| extend ResourceType = iff(ResourceId has "/providers/",
      extract(@"/providers/([^/]+/[^/]+)", 1, ResourceId),   // Microsoft.Compute/virtualMachines
      "Microsoft.Resources/resourceGroups")                  // no provider segment: the RG itself
```

The general rule: if a string starts with its delimiter, index 0 is empty, and every hard-coded index is off by one. And any out-of-range index in KQL is a silent null — so if a filter downstream drops empties, test what you're dropping before you trust the count.

<br/>

---

<br/>

## 🪡 The Common Thread

![Common-Thread](/assets/img/TheActivityLogIsNotTheActivity/7.png)

The last few editions have each had a version of the same lesson. Representation versus meaning. Character lists versus codepoint ranges. Stages versus chains. This week it's one level further down: **the label versus the mechanism, and the record versus the reality.**

Every query I took apart this week asked for something by its label. An English word in a display name (`has "delete"`, `has_any ("list", "get", "read")`). A filename (`ntpdate`, `udevds`, `ScreenConnect.ClientService.exe`). A file extension (`.sh`). A status string (`"Success"`). And every replacement asks for the mechanism instead — the parts the attacker can't change without abandoning the technique. The verb segment of an ARM operation path. A file unlinked while its process keeps running. A shell handed the path of a file written seconds ago. The arguments a remote-access client needs to reach its relay. Labels are chosen; mechanisms are required.

The Storm-3168 cluster adds the part that's genuinely new for this series: before you write a stage, ask whether the table records that class of event at all. Every log is a decision somebody made about what to keep. The Azure Activity Log decided to keep control-plane changes and, typically, not reads, which is a perfectly sensible decision for an audit trail and a fatal one for a reconnaissance detection. No amount of KQL fixes an event that was never written — the fix is to move the stage to a table that does record it (sign-in logs for the token, Key Vault diagnostics for secret reads, Defender for Resource Manager for ARM reads) or to admit the stage is invisible and design around it. The composite in Act I does the second: it detects destruction, protection tampering, and credential collection — the three phases AzureActivity can see — and hands off the fourth to a different table.

And the success filter is the same lesson in miniature. `ActivityStatusValue == "Success"` reads like hygiene, and in most detections it is. In a destruction detection it means your rule's sensitivity is inversely proportional to how well your locks work. The attempt is the intent; the outcome is just a measure of your controls.

Which brings me to the pipeline. It generated thirty detections this week, each with ATT&CK mappings, deployment gates, triage runbooks, and a blind-spot callout — and the blind-spot callout for Monday and Tuesday said none was found, on the two days when three of six queries depended on telemetry the table doesn't capture, and a fourth detected a different attack. That's going into the next pipeline revision as a telemetry-contract check: for every stage, name the table, and confirm the table records that class of event. It's the kind of thing that's obvious once a human reads it and invisible until one does — which is exactly what this weekly review is for.

This kind of detection content is published _daily_ — fresh threat intel translated straight into deployable detections, so you spend your time tuning and shipping instead of reading and re-deriving — that's the whole point of the **[Daily Detection Engineering Brief at DevSecOpsDadAttack.com](https://devsecopsdadattack.com/detectionengineering/)**.

<br/>

![Outro](/assets/img/TheActivityLogIsNotTheActivity/8.png)

<br/>

---

<br/>

## Helpful Links and References:

This Week's Detection Engineering Briefs:
- [Monday, 28th September](https://devsecopsdadattack.com/2026-09-28-detection-engineering-brief-monday-september-28-2026/)
- [Tuesday, 29th September](https://devsecopsdadattack.com/2026-09-29-detection-engineering-brief-tuesday-september-29-2026/)
- [Wednesday, 30th September](https://devsecopsdadattack.com/2026-09-30-detection-engineering-brief-wednesday-september-30-2026/)
- [Thursday, 1st October](https://devsecopsdadattack.com/2026-10-01-detection-engineering-brief-thursday-october-1-2026/)
- [Friday, 2nd October](https://devsecopsdadattack.com/2026-10-02-detection-engineering-brief-friday-october-2-2026/)
- [Saturday, 3rd October](https://devsecopsdadattack.com/2026-10-03-detection-engineering-brief-saturday-october-3-2026/)
- [Sunday, 4th October](https://devsecopsdadattack.com/2026-10-04-detection-engineering-brief-sunday-october-4-2026/)

DevSecOpsDadAttack Tags:
- [detection-engineering](https://devsecopsdadattack.com/tags/#detection-engineering)
- [kql](https://devsecopsdadattack.com/tags/#kql)
- [Storm-3168](https://devsecopsdadattack.com/tags/#Storm-3168)
- [Azure](https://devsecopsdadattack.com/tags/#Azure)
- [service principals](https://devsecopsdadattack.com/tags/#service-principals)
- [Microsoft Entra ID](https://devsecopsdadattack.com/tags/#Microsoft-Entra-ID)
- [BPFDoor](https://devsecopsdadattack.com/tags/#BPFDoor)
- [AVERAT](https://devsecopsdadattack.com/tags/#AVERAT)
- [Linux](https://devsecopsdadattack.com/tags/#Linux)
- [ScreenConnect](https://devsecopsdadattack.com/tags/#ScreenConnect)
- [MSP360](https://devsecopsdadattack.com/tags/#MSP360)
- [AzureActivity](https://devsecopsdadattack.com/tags/#AzureActivity)
- [AADServicePrincipalSignInLogs](https://devsecopsdadattack.com/tags/#AADServicePrincipalSignInLogs)
- [DeviceFileEvents](https://devsecopsdadattack.com/tags/#DeviceFileEvents)
- [DeviceProcessEvents](https://devsecopsdadattack.com/tags/#DeviceProcessEvents)
- [Microsoft Sentinel](https://devsecopsdadattack.com/tags/#Microsoft-Sentinel)
- [Defender XDR](https://devsecopsdadattack.com/tags/#Defender-XDR)
- [T1485](https://devsecopsdadattack.com/tags/#T1485)
- [T1490](https://devsecopsdadattack.com/tags/#T1490)
- [T1078.004](https://devsecopsdadattack.com/tags/#T1078.004)
- [T1036](https://devsecopsdadattack.com/tags/#T1036)
- [T1059.004](https://devsecopsdadattack.com/tags/#T1059.004)
- [T1219](https://devsecopsdadattack.com/tags/#T1219)

ATT&CK Coverage in This Article:

**Detected by the queries above:**
- **T1485** — Data Destruction (Act I. Bulk deletion by a workload identity, by volume, diversity, or whole resource groups — successes and failures both counted.)
- **T1490** — Inhibit System Recovery (Act I. Any attempt to delete Recovery Services or Data Protection resources, or the locks protecting them. The `ProtectionTamper` class is deliberately broader than T1490 — it includes every resource-lock deletion, not just recovery-related ones — so check `TamperKind` before applying this mapping to a specific alert. Every one of Storm-3168's attempts against Site Recovery and Backup protection locks failed, which is why the composite counts attempts rather than successes.)
- **T1078.004** — Valid Accounts: Cloud Accounts (Act I, shadow query. A service principal obtaining ARM tokens from an IP never seen for that application.)
- **T1070.004** — Indicator Removal: File Deletion (Act II. The payload image unlinked within seconds of execution.)
- **T1036.005** — Masquerading: Match Legitimate Name or Location (Act II. Detected *without* depending on the name — the location tier and lifecycle carry the signal, so a renamed payload still fires.)
- **T1059.004** — Command and Scripting Interpreter: Unix Shell (Act II. A freshly written file executed by a shell, regardless of extension.)
- **T1219** — Remote Access Software (Honorable mention. A ScreenConnect guest client pointing at a relay never before seen on that device.)

**Present in the activity, not detectable with this telemetry:**
- **T1526** — Cloud Service Discovery. The 300+ reads and the five-second sweep are the reconnaissance stage of Storm-3168, and they are not in AzureActivity. The shadow query sees the tokens, and Defender for Resource Manager sees the reads; the Activity Log does not.
- **ARM credential collection via ListKeys.** The composite detects it as `CredentialHarvestSweep`, but ATT&CK doesn't have a clean mapping for "ask the control plane to return a data-plane secret." T1552 (Unsecured Credentials) is the closest parent. For the record, the Monday briefs tagged the bulk-deletion detection T1552.001, Credentials in Files — which describes neither the detection nor the attack.

**Deliberately unmapped:**
- **The bonus round.** `split()` indexing is a KQL mechanic, not adversary behavior. It's in the article because it changes what Tuesday's queries count, and which deletions they silently drop.

References:
- Microsoft Security Blog. *Storm-3168: Agentic-driven cloud attacks using compromised service principals.* <https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/>
- Rapid7. *SMTP is the key: BPFDoor and AVERAT hitting the network edge.* <https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge>
- SANS ISC. *ScreenConnect Client (Ab)used by Attackers.* <https://isc.sans.edu/diary/rss/33388>
- Microsoft Security Blog. *Phishing Abuses RMM Tools for Persistent Access.* <https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/>
- Microsoft Learn. *Azure Monitor activity log.* <https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log>
- Microsoft Learn. *AzureActivity table reference.* <https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity>
- Microsoft Learn. *AADServicePrincipalSignInLogs table reference.* <https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs>
- Microsoft Learn. *Azure Key Vault logging.* <https://learn.microsoft.com/en-us/azure/key-vault/general/logging>
- Microsoft Learn. *Lock your resources to protect your infrastructure.* <https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources>
- Microsoft Learn. *DeviceFileEvents table in the advanced hunting schema.* <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table>
- Microsoft Learn. *DeviceProcessEvents table in the advanced hunting schema.* <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table>
- Microsoft Learn. *split() function.* <https://learn.microsoft.com/en-us/kusto/query/split-function>
- Microsoft Learn. *extract_all() function.* <https://learn.microsoft.com/en-us/kusto/query/extract-all-function>
- Microsoft Learn. *dcountif() aggregation function.* <https://learn.microsoft.com/en-us/kusto/query/dcountif-aggregation-function>
- Microsoft Learn. *column_ifexists() function.* <https://learn.microsoft.com/en-us/kusto/query/column-ifexists-function>
- MITRE ATT&CK. *Data Destruction (T1485).* <https://attack.mitre.org/techniques/T1485/>
- MITRE ATT&CK. *Inhibit System Recovery (T1490).* <https://attack.mitre.org/techniques/T1490/>
- MITRE ATT&CK. *Valid Accounts: Cloud Accounts (T1078.004).* <https://attack.mitre.org/techniques/T1078/004/>
- MITRE ATT&CK. *Cloud Service Discovery (T1526).* <https://attack.mitre.org/techniques/T1526/>
- MITRE ATT&CK. *Indicator Removal: File Deletion (T1070.004).* <https://attack.mitre.org/techniques/T1070/004/>
- MITRE ATT&CK. *Masquerading: Match Legitimate Name or Location (T1036.005).* <https://attack.mitre.org/techniques/T1036/005/>
- MITRE ATT&CK. *Unix Shell (T1059.004).* <https://attack.mitre.org/techniques/T1059/004/>
- MITRE ATT&CK. *Remote Access Software (T1219).* <https://attack.mitre.org/techniques/T1219/>
- DevSecOpsDad.com. *From RSS Noise to CISO Signal: Automating Cyber Threat Intel.* <https://www.hanley.cloud/2026-04-28-From-RSS-Noise-to-CISO-Signal-Automating-Cyber-Threat-Intelligence-That-Actually-Matters/>
- DevSecOpsDad.com. *Last Edition: The Stage Is Not the Chain.* <https://www.hanley.cloud/2026-09-14-KQL-Detection-of-the-Week-The-Stage-Is-Not-The-Chain/>

<br/>

---

<br/>

# Stay Ahead of Emerging Threats

_Looking for actionable threat intelligence and detection engineering insights?_

DevSecOpsDadAttack publishes daily:

📈 Threat Intelligence Briefs focused on active campaigns, exploitation trends, and operational risk <br/><br/>
🛠️ Detection Engineering Briefs with ATT&CK mappings, telemetry requirements, KQL detections, tuning guidance, and triage workflows <br/><br/>
🔍 Practical analysis designed for SOC teams, threat hunters, detection engineers, and security leaders <br/><br/>

Visit [DevSecOpsDadAttack.com](https://devsecopsdadattack.com) for the latest intelligence and detection content.

<br/><br/>

# 📚 Want to go deeper?

Anyone can aggregate threat intel.
Very few teams can prove why they acted—or why they didn't.

The below books are about closing that gap; turning curated signal into defensible decisions across KQL, PowerShell, and the Microsoft security stack.

<br/><br/>

<div style="text-align:center; margin: 2.5em 0;">
  <a href="https://a.co/d/hZ1TVpO" target="_blank" rel="noopener noreferrer">
    <img 
      src="/assets/img/KQL Toolbox Cover.jpg"
      alt="KQL Toolbox: Turning Logs into Decisions in Microsoft Sentinel"
      style="width: 215px; margin: 0 auto; box-shadow: 0 16px 40px rgba(0,0,0,.45); border-radius: 8px;"
    />
  </a>
  <p style="margin-top: 0.75em; font-size: 0.95em; opacity: 0.85;">
    🛠️ <strong>KQL Toolbox:</strong> Turning Logs into Decisions in Microsoft Sentinel
  </p>
</div>

<br/>

<div style="text-align:center; margin: 2.5em 0;">
  <a href="https://a.co/d/ifIo6eT" target="_blank" rel="noopener noreferrer">
    <img 
      src="/assets/img/PowerShell-Cover.jpg"
      alt="PowerShell Toolbox: Hands-On Automation for Auditing and Defense"
      style="width: 215px; margin: 0 auto; box-shadow: 0 16px 40px rgba(0,0,0,.45); border-radius: 8px;"
    />
  </a>
  <p style="margin-top: 0.75em; font-size: 0.95em; opacity: 0.85;">
    🧰 <strong>PowerShell Toolbox:</strong> Hands-On Automation for Auditing and Defense
  </p>
</div>

<br/>

<div style="text-align:center; margin: 2.5em 0;">
  <a href="https://a.co/d/4vveVCI" target="_blank" rel="noopener noreferrer">
    <img 
      src="/assets/img/Ultimate%20XDR%20for%20Full%20Spectrum%20Cyber%20Defense/cover11.jpg"
      alt="Ultimate Microsoft XDR for Full Spectrum Cyber Defense"
      style="max-width: 340px; box-shadow: 0 16px 40px rgba(0,0,0,.45); border-radius: 8px;"
    />
  </a>
  <p style="margin-top: 0.75em; font-size: 0.95em; opacity: 0.85;">
    📖 <strong>Ultimate Microsoft XDR for Full Spectrum Cyber Defense</strong><br/>
    Real-world detections, Sentinel, Defender XDR, and Entra ID — end to end.
  </p>
</div>

<br/>
