---
layout: post
title: "KQL Detection of the Week: The String Is Not the Thing"
subtitle: "Detecting Metadata SSRF When the Attacker Owns the Hostname, Normalising IP Obfuscation Instead of Enumerating It, and Why an Empty SHA256 Doesn't Mean Unsigned"
date: 2026-08-31
author: DevSecOpsDad
---

![The String Is Not The Thing](/assets/img/TheStringIsNotTheThing/intro.png)

Nineteen detections across five days. Four of them hunt the cloud metadata service. One of those four ships a list of eight literal strings meant to cover every obfuscated form of `169.254.169.254` — there are at least 120 minimal ones, the list contains a form that doesn't decode to the target at all, and the technique the source intelligence was actually reporting isn't a numeric encoding in the first place. Two more detections, on two different days, filter for "unsigned DLL" against a Defender table that carries no signature verdict, using two different fields, one of which doesn't exist in that table and one of which Microsoft documents as usually empty.

Last week the [DevSecOpsDadAttack Detection Engineering pipeline](https://devsecopsdadattack.com/detectionengineering/) ([run on a Raspberry Pi](https://www.hanley.cloud/2026-04-28-From-RSS-Noise-to-CISO-Signal-Automating-Cyber-Threat-Intelligence-That-Actually-Matters/)) shipped detections that depended on fields which might not exist, and the failure mode was silence. This week the fields exist. They are populated. And the queries are asking them the wrong question. **A detection that matches the representation of an indicator instead of its meaning is defeated by the cheapest transformation the attacker has available** — a different number base, a hostname, a dash instead of a dot. That failure doesn't return zero rows. Sometimes it returns every row.

Act I is the metadata-SSRF cluster and the detection layer nobody built: match the DNS *answer*, not the requested name. Act II takes apart the eight-string encoding list and replaces it with a decoder, because you cannot enumerate an infinite set but you can normalise one. The honorable mention is the TerminalFix DLL sideloading detection, where "unsigned" was inferred from an absent hash. Same structural error in all three, and the fix in all three is a KQL operator that already exists.

<br/>

---

<br/>

## 🥇 Act I: Four Detections for the Metadata Service, and the One That Was Missing

![Act I](/assets/img/TheStringIsNotTheThing/ACTI_Metadata.png)

The [SANS ISC diary on obfuscating IP addresses as hostnames](https://isc.sans.edu/diary/33280) landed on Tuesday the 25th and the pipeline responded across [Wednesday](https://devsecopsdadattack.com/2026-08-26-detection-engineering-brief-wednesday-august-26-2026/) and [Thursday](https://devsecopsdadattack.com/2026-08-27-detection-engineering-brief-thursday-august-27-2026/) with four detections in two shapes.

**Shape 1 — endpoint-side, the connection that actually happened:**

```kql
// Wednesday Detection 2 (DeviceNetworkEvents + DeviceProcessEvents)
DeviceNetworkEvents
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName !in~ (knownCloudAgents)
// ...joined to DeviceProcessEvents on DeviceName + InitiatingProcessId

// Thursday Detection 4 (DeviceNetworkEvents only)
DeviceNetworkEvents
| where RemoteIP == "169.254.169.254"
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where InitiatingProcessName !in~ (waagent, cloud-init, amazon-ssm-agent, ...)
```

**Shape 2 — network-side, the request that was submitted:**

```kql
// Thursday Detection 3 (CommonSecurityLog, the encoding list)
CommonSecurityLog
| where RequestURL has_any (
    "169.254.169.254", "2852039166", "0xa9fea9fe", "0xa9fe.0xa9fe",
    "0251.0376.0251.0376", "169.254.169.254%00",
    "[::ffff:169.254.169.254]", "metadata.google.internal")
    or DestinationIP == "169.254.169.254"

// Wednesday Detection 3 (CommonSecurityLog, the path list)
CommonSecurityLog
| where DestinationIP == "169.254.169.254"
    or RequestURL has_any ("/latest/meta-data", "/metadata/instance",
                           "/computeMetadata", "/openstack")
```

Shape 1 is good. It is genuinely good, and I want to say that clearly before I take anything apart. `RemoteIP == "169.254.169.254"` in `DeviceNetworkEvents` is encoding-proof by construction: by the time the endpoint sensor records a connection, the operating system has already resolved whatever the attacker typed into an actual address. Hex, octal, decimal, hostname, DNS rebinding — all of it collapses to the same `RemoteIP` value. Thursday's Detection 4 was marked a production candidate and it deserved to be.

Shape 2 is where the week goes wrong, and it goes wrong in a way that matters, because the WAF layer is the only one that sees the attempt *before* it succeeds.

**First, and most importantly: the source intelligence is not about numeric encodings.** [Johannes Ullrich’s diary](https://isc.sans.edu/diary/33280) is titled "Obfuscating IP Addresses as Hostnames," and the technique it documents is exactly that — attackers replacing the literal IP with a hostname configured to resolve to that address, using services purpose-built for it. The two named in the reporting are `nip.io` and `sslip.io`, where the rest of the hostname *is* the address you want returned, and where the separator can be a dash instead of a dot precisely because dashes defeat filters. The diary also points at the `1u.ms` tool, which lets an attacker mint hostnames on the fly, and notes that the same trick works with plenty of other dynamic hosting services. Ullrich’s closing recommendation is itself a detection instruction: if you retain DNS logs — and you should — check whether any resolution came back with an address like `169.254.169.254`.

Nobody built that. Four detections were generated from this reporting and not one of them looks at a DNS answer. The pipeline read the word "obfuscating," reached for the obfuscation class it knows — decimal, octal, hex encodings of an IPv4 address — and produced a string list for a technique the article never described. Those numeric encodings are real and worth detecting (Act II builds the decoder for them), but they are a different technique, and the one actually being reported in the wild last week is invisible to all four queries.

Here is the concrete gap. An attacker submits this to your vulnerable application:

```
https://app.example.com/fetch?url=http://169-254-169-254.nip.io/latest/meta-data/iam/security-credentials/
```

Thursday's Detection 3 does not fire: `169-254-169-254` is not any of the eight strings, and `nip.io` is not in the list. Wednesday's Detection 3 fires only on the path fragment `/latest/meta-data`, which the attacker can trivially reshape as `/latest/meta%2Ddata` or simply target Azure's `/metadata/instance` instead — and the pipeline put those two path lists in two different queries on two different days, so neither is complete. Meanwhile the *hostname* resolves to `169.254.169.254`, the application makes the request, and Shape 1 catches it — but only after the credentials have already been read.

**Second, the endpoint detections have a real blind spot that the briefs flag and then leave.** Both Wednesday's Detection 2 and Thursday's Detection 4 carry the same caveat: `DeviceNetworkEvents` may not capture link-local traffic on all cloud VM configurations depending on network driver and sensor version. That is a genuine risk, and it means Shape 1 — the strongest layer — is the one most likely to be missing entirely on the workloads you care about. It needs the validation query at the end of this act.

**Third, the exclusion lists disagree with each other.** Wednesday excludes six cloud agents with `.exe` suffixes. Thursday excludes ten, including bare Linux process names (`waagent`, `cloud-init`, `google_guest_agent`). Neither list includes `kubelet` or `containerd`, which both briefs name in their false-positive sections as expected noise on Kubernetes nodes. This is a tuning gap rather than a design flaw, but two detections for one technique across two days should not have two different, both-incomplete allowlists.

The fix for this act is not a better string list. It is the layer the source article asked for and nobody wrote: **detect on the resolved answer, not the requested name.** A DNS response containing a link-local address is abnormal in essentially every environment, it is provider-agnostic, and it is completely indifferent to how the attacker spelled the hostname.

<br/>

### The KQL

```kql
let lookback = 1d;
// ============================================================
// WILDCARD-DNS SERVICES.
//
// These domains exist to resolve an arbitrary hostname to an
// arbitrary address chosen by whoever constructed the name.
// A workload resolving one of these is a finding regardless of
// what came back, because there is no legitimate reason for a
// production application to dereference an attacker-controlled
// name-to-address mapping service.
//
// 1u.ms is the one named in the SANS reporting. nip.io and
// sslip.io are the two Sean observed. The rest are the common
// alternatives; add any others you find in your own DNS data.
// ============================================================
let WildcardDnsSuffixes = dynamic([
    "nip.io", "sslip.io", "1u.ms", "traefik.me",
    "localtest.me", "vcap.me", "xip.io", "lvh.me"
]);
// ============================================================
// PROVIDER METADATA HOSTNAMES.
//
// GCP publishes a real hostname for its metadata service, which
// means "metadata.google.internal" is both a legitimate string
// on GCP workloads and an SSRF payload on everything else.
// Context decides; the query surfaces it either way.
// ============================================================
let ProviderMetadataNames = dynamic([
    "metadata.google.internal", "metadata.goog",
    "instance-data.ec2.internal"
]);
// ============================================================
// SOURCE 1: DeviceEvents / DnsQueryResponse.
//
// The MDE sensor's own DNS telemetry. AdditionalFields carries
// the query string and the response. Key names have varied
// across sensor versions — run VALIDATION 1 below and confirm
// which keys your tenant actually emits before you trust this
// branch. coalesce() covers the two forms I have seen.
// ============================================================
let DnsFromDeviceEvents =
    DeviceEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "DnsQueryResponse"
    | extend AF = todynamic(AdditionalFields)
    | extend
        QueryName  = tostring(coalesce(AF.DnsQueryString, AF.query)),
        AnswerText = tostring(coalesce(AF.DnsQueryResult, AF.answers, AF.DnsQueryResults))
    | project
        Timestamp, DeviceId, DeviceName,
        InitiatingProcessFileName, InitiatingProcessCommandLine,
        InitiatingProcessAccountName, InitiatingProcessFolderPath,
        QueryName, AnswerText,
        TelemetrySource = "DeviceEvents/DnsQueryResponse";
// ============================================================
// SOURCE 2: DeviceNetworkEvents / DnsConnectionInspected.
//
// Network Protection's Zeek-derived DNS inspection. Keys follow
// Zeek's dns.log naming (query, answers, rcode_name). This
// branch requires Network Protection in block or audit mode; if
// you do not run it, this half returns nothing and Source 1
// carries the detection on its own.
// ============================================================
let DnsFromNetworkEvents =
    DeviceNetworkEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "DnsConnectionInspected"
    | extend AF = todynamic(AdditionalFields)
    | extend
        QueryName  = tostring(AF.query),
        AnswerText = tostring(AF.answers)
    | project
        Timestamp, DeviceId, DeviceName,
        InitiatingProcessFileName, InitiatingProcessCommandLine,
        InitiatingProcessAccountName, InitiatingProcessFolderPath,
        QueryName, AnswerText,
        TelemetrySource = "DeviceNetworkEvents/DnsConnectionInspected";
// ============================================================
// STEP 1: UNION AND EXTRACT ANSWERS.
//
// The answer set arrives as a JSON array in some sensor
// versions and a delimited string in others. Rather than branch
// on the shape, stringify it and pull every dotted quad out
// with a regex. Shape-agnostic, and CNAME answers fall out
// naturally because they aren't dotted quads.
// ============================================================
union DnsFromDeviceEvents, DnsFromNetworkEvents
| where isnotempty(QueryName)
| extend AnswerList = extract_all(
    @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", AnswerText)
| extend QueryNameLower = tolower(QueryName)
| extend UsesWildcardDns   = QueryNameLower has_any (WildcardDnsSuffixes)
| extend UsesProviderName  = QueryNameLower has_any (ProviderMetadataNames)
// Keep resolutions with no A record only if the NAME itself is
// interesting; otherwise expand the answers.
| extend AnswerList = iff(array_length(AnswerList) == 0,
                          dynamic([""]), AnswerList)
| mv-expand Answer = AnswerList to typeof(string)
// ============================================================
// STEP 2: THE TEST — on the ANSWER, not the QUERY.
//
// 169.254.0.0/16 rather than a single host: 169.254.170.2 is
// the ECS task metadata endpoint, and any other link-local
// address arriving as a DNS answer is equally abnormal.
// 192.0.0.192 is Oracle Cloud's legacy metadata endpoint.
// 100.100.100.200 is Alibaba Cloud's.
// ============================================================
| extend AnswerIsIPv4 = isnotnull(parse_ipv4(Answer))
| extend IsMetadataAnswer = AnswerIsIPv4 and (
       ipv4_is_in_range(Answer, "169.254.0.0/16")
    or ipv4_is_in_range(Answer, "192.0.0.192/32")
    or ipv4_is_in_range(Answer, "100.100.100.200/32")
  )
| where IsMetadataAnswer or UsesWildcardDns or UsesProviderName
// ============================================================
// STEP 3: CLASSIFY.
//
// Three distinct findings with three different urgencies, and
// the analyst should not have to reconstruct which is which
// from the raw columns.
// ============================================================
| extend Verdict = case(
      IsMetadataAnswer and UsesWildcardDns,  "MetadataViaWildcardDns",
      IsMetadataAnswer and UsesProviderName, "ProviderMetadataName",
      IsMetadataAnswer,                      "MetadataResolution",
      UsesWildcardDns,                       "WildcardDnsNoMetadataAnswer",
                                             "ProviderNameNoAnswer"
  )
// Does the requested NAME carry an encoded address? This is
// enrichment for triage, never a filter — the whole point of
// this query is that it works when the name is unreadable.
| extend NameEmbedsAddress = QueryNameLower matches regex
    @"(\d{1,3}[-.]){3}\d{1,3}|0x[0-9a-f]{8}|\b\d{8,10}\b"
| summarize
    Resolutions     = count(),
    MetadataAnswers = countif(IsMetadataAnswer),
    AnswerSet       = make_set(Answer, 10),
    QueryNames      = make_set(QueryName, 10),
    Processes       = make_set(InitiatingProcessFileName, 10),
    ProcessPaths    = make_set(InitiatingProcessFolderPath, 5),
    SampleCmd       = take_any(InitiatingProcessCommandLine),
    Accounts        = make_set(InitiatingProcessAccountName, 5),
    Sources         = make_set(TelemetrySource, 2),
    FirstSeen       = min(Timestamp),
    LastSeen        = max(Timestamp)
    by DeviceName, DeviceId, Verdict, NameEmbedsAddress
| order by MetadataAnswers desc, Resolutions desc
```

<br/>

![DevSecOpsDadAttack!](/assets/img/TheStringIsNotTheThing/ACTI_AnswerNotQuery.png)

<br/>

### The line that does the work

```kql
| extend IsMetadataAnswer = AnswerIsIPv4 and (
       ipv4_is_in_range(Answer, "169.254.0.0/16")
    or ipv4_is_in_range(Answer, "192.0.0.192/32")
    or ipv4_is_in_range(Answer, "100.100.100.200/32")
  )
```

`Answer`, not `QueryName`. That is the entire idea.

Every detection in this cluster inspects what the attacker *wrote*. This one inspects what DNS *returned*. The attacker controls the first completely — it is a string in a URL they constructed, and they can spell it a hundred and twenty different ways before you even get to hostnames. They do not control the second. If the payload is going to reach the metadata service, something has to resolve to `169.254.169.254`, and that resolution lands in your telemetry as a dotted quad no matter how the name was spelled. `169-254-169-254.nip.io`, `0xa9fea9fe.attacker.com`, a one-off `1u.ms` name, a rebinding record that returns a benign address on the first lookup and the metadata address on the second — all of them produce the same answer, and this query fires on all of them identically.

The second thing worth noticing is `ipv4_is_in_range` instead of `==`. A single-host comparison against `"169.254.169.254"` is still a string comparison wearing an IP costume: it matches one address and misses `169.254.170.2` (ECS task metadata), `169.254.169.253` (AWS VPC DNS on some configurations), and every other link-local address that has no business appearing in a DNS answer. `ipv4_is_in_range` compares the parsed 32-bit value against a CIDR, which is what you actually meant. KQL has had this operator the whole time.

Third, note what `UsesWildcardDns` does and does not do. It is not a fallback for when the answer check fails — both conditions are evaluated, and a resolution can trigger on the name, the answer, or both, with `Verdict` telling the analyst which. `WildcardDnsNoMetadataAnswer` is a genuinely useful row: a workload resolved a `nip.io` name and got back something that isn't the metadata service. That might be an attacker probing a different internal target, or DNS rebinding on its first, benign response. It is not the finding you were hunting, and it is worth a look.

<br/>

### Validate before you deploy

This detection depends on DNS telemetry that many tenants do not have, and the failure would be silent. Two queries, thirty seconds, run them first.

```kql
// VALIDATION 1: Where does your DNS telemetry live, and what
// are the AdditionalFields keys called in YOUR tenant?
// If both branches return nothing, the Act I detection cannot
// work and your only metadata coverage is the endpoint-side
// RemoteIP query.
union
  (DeviceEvents
   | where Timestamp >= ago(7d)
   | where ActionType == "DnsQueryResponse"
   | extend Src = "DeviceEvents/DnsQueryResponse"),
  (DeviceNetworkEvents
   | where Timestamp >= ago(7d)
   | where ActionType == "DnsConnectionInspected"
   | extend Src = "DeviceNetworkEvents/DnsConnectionInspected")
| summarize Events = count(),
            Devices = dcount(DeviceId),
            SampleFields = take_any(AdditionalFields)
  by Src

// VALIDATION 2: Does your MDE sensor record link-local traffic
// on cloud workloads at all? Both briefs raise this and neither
// resolves it. If LinkLocalEvents is 0 across your cloud device
// group, Shape 1 is blind and Act I is your only coverage.
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| summarize
    Total           = count(),
    LinkLocalEvents = countif(ipv4_is_in_range(RemoteIP, "169.254.0.0/16")),
    MetadataEvents  = countif(RemoteIP == "169.254.169.254"),
    Devices         = dcount(DeviceId),
    LinkLocalDevices = dcountif(DeviceId,
        ipv4_is_in_range(RemoteIP, "169.254.0.0/16"))
```

Validation 2 is the more important of the two, and it is the question both briefs asked and neither answered. If `LinkLocalDevices` is materially lower than the number of cloud workloads you have onboarded, the production-candidate detection the pipeline was most confident about is silently covering a fraction of your estate.

<br/>

### Keeping it honest

- **`AdditionalFields` key names are not contractual.** I use `coalesce(AF.DnsQueryString, AF.query)` because I have seen both, but this is exactly the kind of thing that changes with a sensor version and breaks without an error. Validation 1 prints a sample `AdditionalFields` blob; read it, and hard-code the keys your tenant actually emits rather than trusting my coalesce.
- **`DnsConnectionInspected` requires Network Protection.** If you run Network Protection in neither block nor audit mode, that entire branch is empty. This is a licensing-and-configuration gate, not a query problem, and it is worth knowing before you conclude the detection "didn't find anything."
- **DNS rebinding beats the single-lookup view.** A rebinding attack returns a benign address on the first resolution and the metadata address on the second, and if only the first is logged the answer check never fires. The `WildcardDnsNoMetadataAnswer` verdict is the partial mitigation — you at least see that a rebinding-capable name was resolved — but a detection that correlates repeated resolutions of the same name to different answers within a short window would be better, and I have not written it here because the noise profile depends heavily on your CDN usage.
- **GCP workloads will generate `ProviderMetadataName` rows constantly.** `metadata.google.internal` is the legitimate way to reach IMDS on GCP. On GCP device groups this verdict is pure noise and should be suppressed; on AWS and Azure workloads it is a strong signal, because there is no reason for a Windows VM in Azure to be resolving Google's metadata hostname. Scope by device group rather than dropping the check.
- **This does not detect the direct-IP case, deliberately.** An attacker who submits the literal `http://169.254.169.254/` never issues a DNS query, so this query never sees it. That case is covered by Thursday's Detection 4, which is why I said at the top that Shape 1 is good. Act I is the missing layer, not the replacement layer. Run both.
- **Every wildcard-DNS suffix I listed is one I could think of.** The service class is trivially extensible — anyone with a domain and a wildcard record can build one, and the SANS diary makes exactly that point about dynamic hosting services. Treat the list as a starting position and feed it from your own DNS data: any second-level domain whose answers are mostly RFC1918 or link-local addresses belongs on it.

<br/>

---

<br/>

## 🥈 Act II: Eight Strings Out of an Infinite Set

![Act II](/assets/img/TheStringIsNotTheThing/ACTII_Encoding.png)

[Thursday's Detection 3](https://devsecopsdadattack.com/2026-08-27-detection-engineering-brief-thursday-august-27-2026/) is the most interesting query of the week, because it is the only one that tries to solve the obfuscation problem head-on, and because the way it fails is instructive rather than careless. It looks for obfuscated representations of the metadata address in WAF and proxy logs:

```kql
CommonSecurityLog
| where isnotempty(RequestURL)
| where RequestURL has_any (
    "169.254.169.254",
    "2852039166",
    "0xa9fea9fe",
    "0xa9fe.0xa9fe",
    "0251.0376.0251.0376",
    "169.254.169.254%00",
    "[::ffff:169.254.169.254]",
    "metadata.google.internal"
    )
    or DestinationIP == "169.254.169.254"
```

Eight strings. Let us count what they are up against.

An IPv4 address parsed by `inet_aton` — which is what most HTTP clients, most URL parsers, and most of the language runtimes behind your web applications ultimately use — accepts the address as one, two, three, or four dot-separated parts. Leading parts occupy one octet each; the final part absorbs whatever octets remain. Each part independently may be written in decimal, in octal (any leading zero), or in hexadecimal (`0x` prefix). For `169.254.169.254` that gives:

| Form | Parts | Radix combinations | Example |
|---|---|---|---|
| Four-part | `169` `254` `169` `254` | 3⁴ = **81** | `0xa9.254.0251.0376` |
| Three-part | `169` `254` `43518` | 3³ = **27** | `169.0376.0xa9fe` |
| Two-part | `169` `16689662` | 3² = **9** | `0xa9.16689662` |
| One-part | `2852039166` | 3 = **3** | `0xa9fea9fe` |

**One hundred and twenty minimal forms**, before you do anything clever. Allow the dots to be percent-encoded as `%2e` or double-encoded as `%252e` and the four-part shape alone becomes 81 × 27 = **2,187**. Allow octal zero-padding — `0000000251` parses exactly the same as `0251` — and the set is not large, it is *unbounded*. There is no list. There was never going to be a list.

And the eight strings the detection does carry are not eight of the good ones. Three of them (`169.254.169.254`, `169.254.169.254%00`, `[::ffff:169.254.169.254]`) all contain the literal dotted quad, so they collapse to a single substring match — KQL's `has_any` is case-insensitive and term-based, so the `%00` and IPv6-mapped variants add nothing the first entry didn't already cover. `metadata.google.internal` is a hostname, not an encoding. That leaves three genuine numeric encodings out of a space of 120: the decimal dword, the hex dword, and the octal quad.

Except one of the four numeric entries doesn't work at all. **`0xa9fe.0xa9fe` does not decode to `169.254.169.254`.** In the two-part form, the leading part must fit in a single octet; `0xa9fe` is 43518, which does not. `inet_aton` rejects it, and so does every parser that follows the same semantics. The valid two-part forms are `169.16689662` and `0xa9.0xfea9fe`, and neither is in the list. So of eight entries: three are duplicates of each other, one is a hostname, one is invalid, and three are real — covering 2.5% of the minimal encoding space.

This is not a criticism of whoever wrote the list. It is a demonstration that the list approach cannot work. The correct move is the one every parser already makes: **stop comparing strings and start decoding them.** Pull the address-shaped tokens out of the URL, decode each one the way `inet_aton` would, normalise the result to a canonical form, and then ask whether that canonical form is in the range you care about. One hundred and twenty encodings and 2,187 percent-encoded variants all collapse to a single 32-bit integer, and KQL will do the comparison for you.

<br/>

### The KQL

```kql
let lookback = 1d;
// ============================================================
// DIGIT MAP.
//
// KQL has no base-N string parser, so we fold the digits by
// hand: value = sum(digit * radix^position). This dictionary is
// the digit-to-value lookup for bases up to 16. It is the only
// part of this query that looks like a hack, and it is the part
// that makes the rest possible.
// ============================================================
let HexMap = dynamic({
    "0":0, "1":1, "2":2, "3":3, "4":4, "5":5, "6":6, "7":7,
    "8":8, "9":9, "a":10,"b":11,"c":12,"d":13,"e":14,"f":15
});
let WildcardDnsSuffixes = dynamic([
    "nip.io", "sslip.io", "1u.ms", "traefik.me",
    "localtest.me", "vcap.me", "xip.io", "lvh.me"
]);
let ProviderMetadataNames = dynamic([
    "metadata.google.internal", "metadata.goog",
    "instance-data.ec2.internal"
]);
// ============================================================
// STEP 1: BASE SET — one row per logged request, with a stable
// key so we can fold digits and then reassemble.
//
// The percent-decoding is deliberately narrow: dots and slashes
// only, two passes to catch the double-encoded form. This is
// not a general URL decoder and it is not trying to be; it
// covers the separator obfuscation that actually shows up in
// SSRF payloads.
// ============================================================
let Base =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where isnotempty(RequestURL)
    | extend RowKey = strcat(
        tostring(TimeGenerated), "|", SourceIP, "|",
        DeviceProduct, "|", hash_sha256(RequestURL))
    | extend Url = tolower(RequestURL)
    | extend Url = replace_string(replace_string(Url, "%252e", "%2e"), "%2e", ".")
    | extend Url = replace_string(replace_string(Url, "%252f", "%2f"), "%2f", "/")
    | project
        RowKey, TimeGenerated, SourceIP, DestinationIP, RequestURL, Url,
        RequestClientApplication, HttpRequestMethod,
        DeviceVendor, DeviceProduct, DeviceName,
        DeviceAction;
// ============================================================
// STEP 2: CANDIDATE EXTRACTION.
//
// Pull out every token shaped like an inet_aton argument,
// wherever it appears — after a scheme, inside a query
// parameter, after an @ in the userinfo position. We
// deliberately over-generate: a token that isn't an address
// decodes to some number that isn't in a metadata range and
// falls out at STEP 5. Over-generating costs compute; under-
// generating costs detections.
// ============================================================
let Candidates =
    Base
    | extend Tokens = extract_all(
        @"(?:^|[/@=:\[\.,&\?])((?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3})",
        Url)
    | mv-expand Token = Tokens to typeof(string)
    | where strlen(Token) >= 7 and strlen(Token) <= 45
    | extend Parts = split(Token, ".")
    | extend PartCount = array_length(Parts)
    | where PartCount between (1 .. 4)
    | project RowKey, Token, Parts, PartCount;
// ============================================================
// STEP 3: DECODE EACH PART.
//
// Radix detection follows inet_aton exactly: 0x is hex, a
// leading zero is octal, anything else is decimal. Note that
// "0376" is 254 and not 376 — the leading zero is not
// cosmetic, and treating it as decimal is how a naive
// normaliser gets fooled in the opposite direction.
// ============================================================
let PartValues =
    Candidates
    | mv-expand with_itemindex = PartIdx Part = Parts to typeof(string)
    | extend Part = tostring(Part)
    | extend Radix = case(
          Part startswith "0x",              16,
          Part matches regex @"^0[0-7]+$",    8,
          Part matches regex @"^[0-9]+$",    10,
                                              0)
    | where Radix > 0
    | extend Body = iff(Radix == 16, substring(Part, 2), Part)
    | where strlen(Body) between (1 .. 11)
    | mv-expand with_itemindex = DigIdx Digit = extract_all(@"(.)", Body)
        to typeof(string)
    | extend DigitValue = toint(HexMap[tostring(Digit)])
    | where isnotnull(DigitValue) and DigitValue < Radix
    | summarize PartValue = sum(
          tolong(DigitValue) * tolong(pow(Radix, strlen(Body) - DigIdx - 1)))
        by RowKey, Token, PartIdx, PartCount, Radix;
// ============================================================
// STEP 4: REASSEMBLE PER inet_aton SEMANTICS.
//
// Leading parts each take one octet from the top; the final
// part absorbs the remaining (5 - PartCount) octets. This is
// the rule that makes "169.16689662" and "0xa9fea9fe" the same
// address, and it is the rule the eight-string list was trying
// to enumerate by hand.
// ============================================================
let Decoded =
    PartValues
    | extend Shift = iff(PartIdx < PartCount - 1, 8 * (3 - PartIdx), 0)
    | extend PartValid = iff(
          PartIdx < PartCount - 1,
          PartValue <= 255,
          PartValue < tolong(pow(256, 5 - PartCount)))
    | summarize
        DecodedLong  = sum(PartValue * tolong(pow(2, Shift))),
        InvalidParts = countif(not(PartValid)),
        PartsDecoded = count(),
        Radices      = make_set(Radix, 4)
        by RowKey, Token, PartCount
    // A candidate is only an address if EVERY part parsed and
    // every part was in range. This is where "0xa9fe.0xa9fe"
    // gets rejected — exactly as a real parser rejects it.
    | where InvalidParts == 0 and PartsDecoded == PartCount
    | where DecodedLong between (0 .. 4294967295);
// ============================================================
// STEP 5: NORMALISE AND TEST.
//
// format_ipv4() turns the decoded 32-bit value back into a
// canonical dotted quad, and ipv4_is_in_range() does the
// comparison against a CIDR rather than a literal.
// ============================================================
let NumericHits =
    Decoded
    | extend NormalizedIP = format_ipv4(DecodedLong)
    | where isnotempty(NormalizedIP)
    | where ipv4_is_in_range(NormalizedIP, "169.254.0.0/16")
         or ipv4_is_in_range(NormalizedIP, "192.0.0.192/32")
         or ipv4_is_in_range(NormalizedIP, "100.100.100.200/32")
    | extend ObfuscationClass = case(
          Token == NormalizedIP,                              "Literal",
          PartCount == 1,                                     "DwordCollapsed",
          set_has_element(Radices, 16)
              and set_has_element(Radices, 8),                "MixedRadix",
          set_has_element(Radices, 16),                       "Hexadecimal",
          set_has_element(Radices, 8),                        "Octal",
          PartCount < 4,                                      "PartialCollapse",
                                                              "Decimal")
    | project RowKey, Token, NormalizedIP, ObfuscationClass, PartCount;
// ============================================================
// STEP 6: THE HOSTNAME BRANCH.
//
// The decoder cannot see what Act I sees. A request to
// 169-254-169-254.nip.io carries no numeric token the decoder
// recognises, because the address is in a DNS name and the
// dashes are not dots. At the WAF layer the best we can do is
// flag the suffix itself. It is a weaker signal than a DNS
// answer and it belongs in the same result set anyway.
// ============================================================
let HostnameHits =
    Base
    | where Url has_any (WildcardDnsSuffixes)
         or Url has_any (ProviderMetadataNames)
    | extend
        Token            = extract(@"([a-z0-9\-\.]+\.(?:nip\.io|sslip\.io|1u\.ms|traefik\.me|localtest\.me|vcap\.me|xip\.io|lvh\.me|google\.internal|goog|ec2\.internal))", 1, Url),
        NormalizedIP     = "",
        ObfuscationClass = iff(Url has_any (WildcardDnsSuffixes),
                               "WildcardDnsHostname",
                               "ProviderMetadataHostname"),
        PartCount        = int(null)
    | project RowKey, Token, NormalizedIP, ObfuscationClass, PartCount;
// ============================================================
// STEP 7: JOIN BACK FOR CONTEXT AND RANK.
// ============================================================
union NumericHits, HostnameHits
| join kind=inner Base on RowKey
| extend WasBlocked = DeviceAction has_any ("block", "deny", "drop", "reset")
| summarize
    Requests        = count(),
    Tokens          = make_set(Token, 15),
    NormalizedIPs   = make_set(NormalizedIP, 5),
    Classes         = make_set(ObfuscationClass, 6),
    DistinctClasses = dcount(ObfuscationClass),
    SampleUrl       = take_any(RequestURL),
    Methods         = make_set(HttpRequestMethod, 5),
    UserAgents      = make_set(RequestClientApplication, 5),
    Appliances      = make_set(strcat(DeviceVendor, "/", DeviceProduct), 5),
    BlockedCount    = countif(WasBlocked),
    AllowedCount    = countif(not(WasBlocked)),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated)
    by SourceIP
// An attacker cycling through encodings is trying to find the
// one your filter misses. More distinct classes from one source
// is a stronger signal than more requests.
| extend ProbeConfidence = case(
      DistinctClasses >= 3, "High",
      DistinctClasses == 2, "Medium",
                            "Low")
| order by AllowedCount desc, DistinctClasses desc, Requests desc
```

<br/>

![DevSecOpsDadAttack!](/assets/img/TheStringIsNotTheThing/ACTII_Decoder.png)

<br/>

### The line that does the work

```kql
| extend Shift = iff(PartIdx < PartCount - 1, 8 * (3 - PartIdx), 0)
// ...
| extend NormalizedIP = format_ipv4(DecodedLong)
```

Two lines, and the second one is only possible because of the first.

The `Shift` line is `inet_aton` in a single expression. Every part except the last takes one octet, positioned from the top: part 0 shifts left 24 bits, part 1 shifts 16, part 2 shifts 8. The last part shifts zero and absorbs everything below it, which is why a one-part token is a full 32-bit dword, a two-part token is `octet.24-bits`, and a four-part token is the dotted quad everyone recognises. That one rule generates all 120 encodings from a single address. It also *rejects* `0xa9fe.0xa9fe`, because the accompanying `PartValid` check enforces that leading parts fit in an octet — the query is not being lenient to be safe, it is reproducing the parser's actual behaviour, which means it agrees with the application about what will and won't reach the metadata service.

`format_ipv4(DecodedLong)` is the payoff. It takes the 32-bit value and returns the canonical dotted quad, which means every one of those 120 spellings arrives at `ipv4_is_in_range` as the identical string `169.254.169.254`. The detection no longer has an encoding list. It has a decoder and a range, and the range is the thing you actually care about.

Notice what this changes about the output as well. `NormalizedIP` and `ObfuscationClass` are in the result set, so the analyst sees both what the attacker wrote and what it means. A row showing `Token = 0xa9.254.0251.0376`, `NormalizedIP = 169.254.169.254`, `ObfuscationClass = MixedRadix` tells you in one glance that this is not a scanner tripping over a health-check path — nobody constructs a mixed-radix address by accident. And `DistinctClasses` is the highest-value column in the whole query: a source IP that submits the same target in four different encodings is running an evasion sweep against your filter, and that is a materially different finding from a single literal probe.

One more thing the decoder buys you that the list never could. The list matched `169.254.169.254`. The decoder matches the *range*, so a payload targeting `169.254.170.2` — the ECS task metadata endpoint, which holds task role credentials and which nobody's eight-string list contains — fires this query on day one, in any encoding.

<br/>

### Keeping it honest

- **This query is expensive, and I am not going to pretend otherwise.** Two `mv-expand` operations over extracted tokens and then their digits means a single long URL can fan out into hundreds of intermediate rows. On a high-volume WAF feed this will not run cheaply over 30 days. Mitigations, in order of preference: restrict `Base` to the `DeviceProduct` values of your internet-facing appliances; add a cheap pre-filter (`| where Url matches regex @"0x[0-9a-f]{2,8}|\b0[0-7]{3,}\b|\b\d{8,10}\b|169\.254|nip\.io|sslip\.io"`) before the token extraction so only plausible rows enter the fold; and run it hourly over an hour of data rather than daily over a day. The pre-filter is a string match and it is *not* the detection — it is a performance gate that only ever removes rows the decoder would have rejected anyway. Test that claim in your own environment before you trust my word for it.
- **The percent-decoding is not a URL decoder.** I handle `%2e` and `%252e` for dots and `%2f`/`%252f` for slashes, because those are what appear in SSRF payloads. I do not handle unicode fullwidth full stops, overlong UTF-8, or triple encoding. A determined attacker gets past this. The honest framing is that Act II raises the cost of the WAF-layer evasion considerably; Act I and the endpoint `RemoteIP` check are what actually catch the ones who pay it.
- **`CommonSecurityLog.RequestURL` may already be normalised.** Thursday's brief flags this correctly and it applies just as hard to my version: if your WAF decodes and canonicalises the URL before writing CEF, every obfuscated form arrives as the literal address and the decoder has nothing to do. That is not a failure — you are covered by the literal match — but you should know which situation you are in. Submit a test request with a known hex encoding and read the resulting log row. Thirty seconds, and it tells you whether the whole of Act II is load-bearing or decorative in your environment.
- **`DeviceAction` is vendor-specific.** I use `has_any ("block","deny","drop","reset")` to derive `WasBlocked`, which is a guess dressed as a field. Check what your appliance actually writes and replace the list. If `DeviceAction` is empty in your feed, `AllowedCount` becomes meaningless and you should sort on `DistinctClasses` instead.
- **The wildcard-DNS suffix list is the same open-ended problem in a different costume,** and I want to be explicit that I have not solved it here — I have only moved it. Any domain with a wildcard record can play that role. The list is worth having because the named services get used constantly, but the durable detection for that technique is Act I, which does not care what the domain is called.
- **`0xa9fe.0xa9fe` might work against something.** I have checked it against `inet_aton` semantics and it is invalid, which is why the decoder rejects it. There are parsers in the wild with their own ideas — some accept 16-bit parts, some accept trailing garbage — and if you have a specific application stack whose parser is more permissive than `inet_aton`, its rules are the ones that matter for your SSRF risk, not mine. Test your own stack.

<br/>

---

<br/>

## 🎖 Honorable Mention: The Unsigned DLL That Was Never Checked for Signing

![Honorable Mention](/assets/img/TheStringIsNotTheThing/Honorable.png)

The [TerminalFix reporting](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/) landed on Friday and produced DLL sideloading detections on both [Saturday](https://devsecopsdadattack.com/2026-08-29-detection-engineering-brief-saturday-august-29-2026/) and [Sunday](https://devsecopsdadattack.com/2026-08-30-detection-engineering-brief-sunday-august-30-2026/). Same campaign, same technique, same table — and two different, both-broken ways of asking "is this DLL unsigned?"

**Saturday's Detection 1:**

```kql
DeviceImageLoadEvents
| where ActionType == "ImageLoaded"
| where FolderPath has_any (userWritablePaths)
| where (isempty(SHA256) or SHA256 == "") and InitiatingProcessFileName in~ (abusedLegitBinaries)
```

**Sunday's Detection 1:**

```kql
DeviceImageLoadEvents
| where IsSigned == false
| where FolderPath has_any (UserWritablePaths)
| where InitiatingProcessFileName !in~ (ExcludedInitiators)
```

Neither works, and they fail in opposite directions.

**Sunday's fails loudly.** `DeviceImageLoadEvents` has no `IsSigned` column. The table carries `Timestamp`, `DeviceId`, `DeviceName`, `ActionType`, `FileName`, `FolderPath`, `SHA1`, `SHA256`, `MD5`, `FileSize`, and the `InitiatingProcess*` family. There is no signature verdict anywhere in it. Signing information lives in `DeviceFileCertificateInfo`, and Microsoft's own documentation says so explicitly, right down to the recommended join. A query referencing a column that does not exist throws a semantic error rather than returning rows — which, after last week's article about silent failures, is the good kind of broken. You find out in the query editor, before the rule ships.

**Saturday's fails silently, and much worse.** It reads `isempty(SHA256)` as "unsigned." But `SHA256` in `DeviceImageLoadEvents` is documented as *usually not populated* — Microsoft's schema reference for the column says, in as many words, to use `SHA1` instead. The field is empty by design for most rows. So a filter written to mean "this DLL has no signature" actually means "this is a normal image load event," and it matches almost everything in the table.

The brief caught this. Its own caveats say that absent `SHA256` is an imprecise unsigned-DLL signal and may reflect telemetry gaps rather than signing status. That is exactly right, and it is in a section below the KQL, and the rule shipped with the filter in place. This is the recurring shape of the week: the analysis is correct and the query does not act on it.

Consider what actually happens when someone deploys Saturday's rule. The predicate that was meant to narrow the result set to unsigned DLLs narrows it to nearly nothing, so the real selectivity comes from the `abusedLegitBinaries` list and the user-writable path filter. Every legitimate DLL loaded by `svchost.exe` or `rundll32.exe` from `AppData` or `ProgramData` — every Electron native module, every installer helper, every browser plugin — passes the "unsigned" test, because none of them populate `SHA256` either. Then it joins to `DeviceProcessEvents` on `DeviceName` alone with a two-minute window and reports every shell process that happened to start in the meantime. The analyst gets a flood, concludes the rule is too noisy, and turns it off. A detection that fires on everything gets disabled exactly as fast as one that fires on nothing, and it costs a week of triage on the way out.

Sunday's version compounds this with a join problem worth naming separately. Saturday at least restricted the follow-on process to a shell list. Sunday's `RecentProcesses` has no `FileName` filter at all — it takes *every* process creation event on the device, joins on `DeviceId`, and keeps anything within sixty seconds. On a workstation that starts a few hundred processes a minute, one DLL load produces hundreds of output rows. The brief's own caveat says analysts should group by `DllSHA256` during triage, which is a request that the analyst manually undo the query's fan-out after the fact.

The fix is to ask the signing question of the table that can answer it, and to anchor the follow-on execution to the process that actually loaded the DLL.

<br/>

### The KQL

```kql
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

<br/>

### The line that does the work

```kql
| join kind=leftouter CertVerdict on SHA1
| extend SigningStatus = case(
      isnull(IsSigned),                        "NoCertificateRecord",
      IsSigned == false,                       "Unsigned",
      IsSigned == true and IsTrusted == false, "SignedUntrusted",
      ...)
```

The join is the fix and the `case` is what makes the fix usable.

Saturday inferred a signing verdict from the absence of a hash. Sunday asked for a signing verdict from a table that has none. The correct move is to go get the verdict from the table that computes it, which costs one `leftouter` join on `SHA1` — the join Microsoft documents for exactly this purpose.

The `case` matters as much as the join, because the honest answer to "is this DLL signed?" has three values, not two. `Unsigned` means the certificate verification ran and found no signature. `NoCertificateRecord` means verification never produced a record for this hash — which happens, because that table is populated by verification activity rather than by every image load, and a `leftouter` join will hand you nulls. Collapsing those two into "unsigned" is the same error Saturday made, just committed more carefully. Surfacing them separately means the analyst knows whether they are looking at a fact or a gap.

`SignedUntrusted` is the verdict that neither original query could ever have produced, and it may be the most operationally interesting of the set. A DLL with a signature that fails `WinVerifyTrust` — revoked cert, expired cert, self-signed, broken chain — is not what a legitimate application ships. It is what a sideloaded payload signed with a stolen or throwaway certificate looks like. A boolean `IsSigned == false` filter drops that row on the floor, because the file *is* signed. Grading instead of gating is what surfaces it.

And `on DeviceId, InitiatingProcessId` is the quiet fix underneath. Anchoring the child process to the same process instance that loaded the DLL turns a device-wide correlation into a causal one. It is the difference between "something loaded a suspicious DLL and, separately, something started a shell" and "the process that loaded the suspicious DLL started a shell."

<br/>

### Keeping it honest

- **Process IDs are reused, and `InitiatingProcessId` alone is not a unique process identity.** The five-minute window bounds the damage, and `InitiatingProcessCreationTime` is in the projection so the analyst can verify. The rigorous version adds `InitiatingProcessCreationTime` to the join key, which I left out because it makes the join brittle when the two tables record creation time with different precision. If you see cross-process contamination in the output, add it and accept the misses.
- **Removing the signing filter increases volume, substantially.** Saturday's rule was over-matching for the wrong reason; this one deliberately keeps `NoCertificateRecord` and `SignedTrusted` rows in the output. The controls are the `SigningStatus` sort order and the `Scope` classifier, not a `where` clause. If the volume is unmanageable in week one, suppress `SignedTrusted` before you touch anything else — but look at what you are suppressing first, because a trusted signature on a DLL loading from `\Users\Public\` is its own kind of interesting.
- **`DeviceImageLoadEvents` is a licensing gate, and both briefs said so.** Defender for Endpoint Plan 2 with image load telemetry enabled. Confirm the table returns rows before you invest in tuning this.
- **The `TrustedLoaders` list is what I could think of.** Defender, the servicing stack, Windows Update. Your environment has more — the endpoint management agent, the backup client, the software distribution tool. Add them one at a time with the process path confirmed, because `MsMpEng.exe` in `C:\Users\Public\Downloads` is not Defender.
- **This does not detect DLL search-order hijacking where the DLL is signed and trusted.** A sideload using a legitimately signed, legitimately trusted DLL placed in the wrong directory is invisible to a signing-based detection by definition. The path filter is doing that work here, and it is weaker than I would like. The stronger signal for that variant is a mismatch between the DLL's expected and actual load path, which is a baselining problem rather than a filtering one.

<br/>

---

<br/>

## 🧾 The Rest of the Week, Briefly

![Bonus](/assets/img/TheStringIsNotTheThing/Bonus.png)

Four smaller items, three of which are the same error as the acts above in different clothing.

**[Saturday's Detection 4](https://devsecopsdadattack.com/2026-08-29-detection-engineering-brief-saturday-august-29-2026/) — PaperCut auth bypass. The private-range check is a string match.**

```kql
let privateRanges = dynamic(["10.", "172.16.", ..., "192.168.", "127."]);
CommonSecurityLog
| where not(SourceIP has_any (privateRanges))
```

`has_any` is term-based, not prefix-based. The string `"10."` tokenises to the term `10`, which matches an IP with `10` in *any* octet — `203.0.10.99` and `1.2.10.5` are both excluded from the results as though they were RFC1918. This is a detection for external unauthenticated access that silently discards a slice of external addresses, and the slice is not small. KQL has a purpose-built function for this:

```kql
| where not(ipv4_is_private(SourceIP))
| where not(ipv4_is_in_range(SourceIP, "127.0.0.0/8"))
```

One function, no list, correct semantics. Same lesson as Act I and Act II: an IP address is not a string, and the moment you treat it as one you inherit the tokeniser's opinion about where octets begin.

The same detection also carries `coalesce(extract(pattern, 1, AdditionalExtensions), extract(pattern, 1, tostring(AdditionalExtensions)))` — two identical extracts where the second wraps an already-string column in `tostring()`. It is harmless, and it is worth deleting so the next reader doesn't spend five minutes looking for the difference.

**[Saturday's Detection 2](https://devsecopsdadattack.com/2026-08-29-detection-engineering-brief-saturday-august-29-2026/) and [Sunday's Detection 3](https://devsecopsdadattack.com/2026-08-30-detection-engineering-brief-sunday-august-30-2026/) — reverse tunnel detection that excludes the port tunnels use.** Both filter `RemotePort !in (80, 443, 8080, 8443, ...)` on the reasonable theory that C2 hides on uncommon ports. Modern reverse tunnels do the opposite: they run over 443 precisely because 443 is where nobody looks. The detection is structurally sound and its port logic is inverted relative to the tradecraft it is chasing. If you deploy it, keep the uncommon-port version as a low-severity hunt and build the 443 case on process identity instead — an unexpected binary holding a long-lived outbound 443 connection with no browser lineage is the signal, and the port is not.

The Saturday version also joins `DeviceNetworkEvents` to `DeviceProcessEvents` with `FileName =~ InitiatingProcessFileName` and a five-minute spawn-to-connection window. Matching on process *name* rather than `InitiatingProcessId` means any instance of that binary satisfies the join, and the five-minute window means a tunnel established by a process that started an hour ago is invisible. Same fix as the honorable mention: join on `DeviceId` and `InitiatingProcessId`.

**[Monday's Detection 2](https://devsecopsdadattack.com/2026-08-24-detection-engineering-brief-monday-august-24-2026/) — DOUBLECUP PNG loader. A coincidence engine.** Any PNG written to Temp, Downloads, ProgramData, or Public, joined to *any* process creation on the same device within five minutes. On a workstation that is hundreds of processes per PNG, and there is no causal link asserted anywhere in the query. The brief's own tuning notes name the fix — filter the spawned process to executables running from the same directory as the PNG drop — and that one line converts the query from a join over coincidence to a join over evidence:

```kql
| where tolower(SpawnedCommandLine) has tolower(PngPath)
     or tolower(ParentProcess) =~ tolower(LoaderProcess)
```

**[Sunday's Detection 2](https://devsecopsdadattack.com/2026-08-30-detection-engineering-brief-sunday-august-30-2026/) — fake CAPTCHA lure.** The detection shape is excellent: a script interpreter spawned by a browser is a high-fidelity ClickFix artefact and this is the best-constructed query of the weekend. One operator nit — `InitiatingProcessFileName has_any (BrowserProcesses)` should be `in~`. `has_any` on `"chrome.exe"` is term matching and will match names that merely contain those terms; `in~` is the case-insensitive exact comparison that was intended. It is a small thing that becomes a large thing the first time an attacker names a binary `not-chrome.exe`.

<br/>

---

<br/>

## The Common Thread

The common thread this week: **representation versus meaning.**

Every one of these detections is a comparison. A comparison needs two things on either side of it, and the question that decides whether a detection works is what those two things actually are. `RequestURL has_any ("0xa9fea9fe")` compares a string to a string. `SourceIP has_any ("10.")` compares a string to a string. `isempty(SHA256)` compares a string to emptiness. In all three cases the analyst was thinking about something else entirely — an address, a network range, a signature — and reached for the operator that happened to be nearest.

An address is not a string. `169.254.169.254`, `0xa9fea9fe`, `169.16689662`, and `0251.0376.0251.0376` are four strings and one address, and the parser inside the application under attack knows that even if your `where` clause doesn't. A network range is not a set of prefixes. `10.0.0.0/8` is a range of 32-bit integers, and the string `"10."` is not a prefix of the addresses in it in any sense the tokeniser respects. A signature verdict is not a hash. `SHA256` being empty tells you the sensor didn't compute a SHA256, and Microsoft's schema documentation says outright that it usually doesn't.

The pattern in the fixes is identical each time: replace the string comparison with a semantic one, and use the operator that already exists for the job. `ipv4_is_in_range` instead of `==` on an IP. `ipv4_is_private` instead of a list of dotted prefixes. `format_ipv4` and a digit fold instead of an encoding list. A join to `DeviceFileCertificateInfo` instead of inferring signing status from an absent field. KQL has semantic operators for every one of these, and in every case they are shorter than the string list they replace.

And where the semantic operator doesn't exist — there is no `inet_aton()` in KQL — the answer is to write the decoder rather than to enumerate its outputs. Act II is forty lines of `mv-expand` and digit arithmetic to replace eight strings, and that trade looks bad right up until you count the encoding space and find that the eight strings covered 2.5% of it, one of them didn't work, and the set was unbounded anyway.

The failure mode is worth naming precisely, because it is not last week's. Last week the fields were missing and the detections returned zero rows, and zero rows looked like nothing happened. This week the fields are present and populated and the queries are asking them the wrong question, which produces two different disasters: the encoding list matches almost nothing while looking thorough, and the empty-hash filter matches almost everything while looking selective. Both get the rule disabled. **A detection that fires on everything dies exactly as fast as one that fires on nothing, and it takes a week of your analysts' time on the way out.**

The most useful thing in this week's data isn't any of the three queries above. It is Validation 2 in Act I — one `countif(ipv4_is_in_range(RemoteIP, "169.254.0.0/16"))` that tells you whether your cloud workloads report link-local traffic at all. Both briefs raised that question. Neither answered it. If the answer is no, the detection the pipeline was most confident about is covering a fraction of your estate, and none of the rest of this matters until you fix it.

Every one of these came straight out of this week's daily briefs — each detection shipped with ATT&CK mappings, telemetry requirements, deployment gates, triage runbooks, false-positive notes, and an honest readiness call. Nineteen this week across five days, because the pipeline dropped two, and once again the ones worth writing about were the ones that needed a human between the automation and the analyst.

This kind of detection content is published _daily_ — fresh threat intel translated straight into deployable detections, so you spend your time tuning and shipping instead of reading and re-deriving — that's the whole point of the **[Daily Detection Engineering Brief at DevSecOpsDadAttack.com](https://devsecopsdadattack.com/detectionengineering/)**.

<br/>

![Outro](/assets/img/TheStringIsNotTheThing/Outro.png)

<br/>

---

<br/>

## Helpful Links and References:

This Week's Detection Engineering Briefs:
- [Monday, 24th August](https://devsecopsdadattack.com/2026-08-24-detection-engineering-brief-monday-august-24-2026/)
- [Wednesday, 26th August](https://devsecopsdadattack.com/2026-08-26-detection-engineering-brief-wednesday-august-26-2026/)
- [Thursday, 27th August](https://devsecopsdadattack.com/2026-08-27-detection-engineering-brief-thursday-august-27-2026/)
- [Saturday, 29th August](https://devsecopsdadattack.com/2026-08-29-detection-engineering-brief-saturday-august-29-2026/)
- [Sunday, 30th August](https://devsecopsdadattack.com/2026-08-30-detection-engineering-brief-sunday-august-30-2026/)

DevSecOpsDadAttack Tags:
- [detection-engineering](https://devsecopsdadattack.com/tags/#detection-engineering)
- [kql](https://devsecopsdadattack.com/tags/#kql)
- [SSRF](https://devsecopsdadattack.com/tags/#SSRF)
- [Cloud Metadata](https://devsecopsdadattack.com/tags/#Cloud-Metadata)
- [IMDS](https://devsecopsdadattack.com/tags/#IMDS)
- [TerminalFix](https://devsecopsdadattack.com/tags/#TerminalFix)
- [DLL Sideloading](https://devsecopsdadattack.com/tags/#DLL-Sideloading)
- [PaperCut](https://devsecopsdadattack.com/tags/#PaperCut)
- [DOUBLECUP](https://devsecopsdadattack.com/tags/#DOUBLECUP)
- [LiteLLM](https://devsecopsdadattack.com/tags/#LiteLLM)
- [DNS Detection](https://devsecopsdadattack.com/tags/#DNS-Detection)
- [Wildcard DNS](https://devsecopsdadattack.com/tags/#Wildcard-DNS)
- [IP Obfuscation](https://devsecopsdadattack.com/tags/#IP-Obfuscation)
- [Code Signing](https://devsecopsdadattack.com/tags/#Code-Signing)
- [DeviceImageLoadEvents](https://devsecopsdadattack.com/tags/#DeviceImageLoadEvents)
- [DeviceFileCertificateInfo](https://devsecopsdadattack.com/tags/#DeviceFileCertificateInfo)
- [DeviceNetworkEvents](https://devsecopsdadattack.com/tags/#DeviceNetworkEvents)
- [DeviceEvents](https://devsecopsdadattack.com/tags/#DeviceEvents)
- [CommonSecurityLog](https://devsecopsdadattack.com/tags/#CommonSecurityLog)
- [Microsoft Sentinel](https://devsecopsdadattack.com/tags/#Microsoft-Sentinel)
- [Defender XDR](https://devsecopsdadattack.com/tags/#Defender-XDR)
- [T1190](https://devsecopsdadattack.com/tags/#T1190)
- [T1552.005](https://devsecopsdadattack.com/tags/#T1552-005)
- [T1574.002](https://devsecopsdadattack.com/tags/#T1574-002)
- [T1090](https://devsecopsdadattack.com/tags/#T1090)
- [T1027](https://devsecopsdadattack.com/tags/#T1027)

ATT&CK Coverage in This Article:

**Detected by the queries above:**
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API (Acts I and II. This is the technique the whole metadata cluster is actually about — the adversary reaching the IMDS endpoint to retrieve instance role credentials. Act I detects the name resolution that gets them there; Act II detects the request that carries the payload.)
- **T1190** — Exploit Public-Facing Application (Act II. The SSRF payload arriving at an internet-facing application is the exploitation event, and the WAF-layer detection is where it is visible.)
- **T1027** — Obfuscated Files or Information (Act II. The numeric encoding of the target address is obfuscation applied to a network indicator rather than to a file, and `ObfuscationClass` in the output is the direct measurement of it.)
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading (Honorable Mention. An unsigned or untrusted DLL loaded by a legitimate binary from a user-writable path is the definition of the sub-technique.)
- **T1090 / T1090.001** — Proxy / Internal Proxy (Bonus. The TerminalFix reverse tunnel. Discussed rather than fixed, because the port logic needs inverting before the query is worth deploying.)

**Present in the activity, not cleanly mappable:**
- **DNS rebinding and wildcard-DNS abuse.** Act I's `WildcardDnsHostname` verdict detects the use of `nip.io`, `sslip.io`, and `1u.ms`-style services. ATT&CK's closest entries are T1568 (Dynamic Resolution) and T1071.004 (Application Layer Protocol: DNS), and neither describes this well — the adversary is not using DNS for C2 or for resilient infrastructure, they are using it as an encoding layer to smuggle an address past a string filter. I have left it unmapped rather than force it.

**Deliberately unmapped:**
- **Act I's `WildcardDnsNoMetadataAnswer` verdict is a surface measurement, not an adversary technique.** A workload resolving a `nip.io` name that returns something benign might be an attacker probing a different internal target, or a developer testing something. It is worth seeing; it is not a TTP.
- **The honorable mention's `NoCertificateRecord` verdict is a telemetry state, not behaviour.** It records that certificate verification produced no result for a hash. That is a gap in your data, not something an adversary did.

**Discussed as a correction:**
- **T1190 mapped to the endpoint-side metadata detections.** Wednesday's Detection 2 and Thursday's Detection 4 both map to T1190 (Exploit Public-Facing Application). T1190 is the initial access event at the application boundary; a process on a cloud workload connecting to `169.254.169.254` is the *credential access* consequence, which is T1552.005. The distinction matters operationally: a T1190 alert routes to the app-security queue, and a T1552.005 alert routes to whoever can rotate the instance role.
- **T1090 / T1090.001 mapped to the DLL sideloading detections.** Saturday's Detection 1 and Sunday's Detection 1 both map the DLL load to Proxy / Internal Proxy. The proxy technique belongs to the reverse tunnel later in the chain; the DLL load itself is T1574.002 (DLL Side-Loading). Mapping the loader to the tunnel's technique means the ATT&CK coverage heat map shows execution-flow hijacking as uncovered when it is in fact the thing being detected.
- **T1204.001 mapped to the fake CAPTCHA lure.** Sunday's Detection 2 maps the browser-spawns-interpreter pattern to T1204.001 (Malicious Link). The ClickFix pattern — a page instructing the user to paste a command into a terminal or Run dialog — is better described by T1204.004 (Malicious Copy and Paste). Worth checking against the current ATT&CK release before you change your mappings, but T1204.001 is describing the delivery, not the execution artefact the query detects.

External Sources:
- SANS ISC. *Obfuscating IP Addresses as Hostnames.* <https://isc.sans.edu/diary/33280>
- SANS ISC. *DOUBLECUP's PNG Payload.* <https://isc.sans.edu/diary/rss/33274>
- Microsoft Security Blog. *When AI infrastructure becomes the target: Securing gateways and control points.* <https://www.microsoft.com/en-us/security/blog/2026/08/26/when-ai-infrastructure-becomes-target-securing-gateways-control-points/>
- Microsoft Security Blog. *TerminalFix campaign deploys a reverse tunnel through multistage intrusion.* <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- Microsoft Learn. *DeviceImageLoadEvents table in the advanced hunting schema.* <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table>
- Microsoft Learn. *DeviceFileCertificateInfo table in the advanced hunting schema.* <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table>
- Microsoft Learn. *DeviceProcessEvents table in the advanced hunting schema.* <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table>
- Microsoft Learn. *DeviceNetworkEvents table in the advanced hunting schema.* <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table>
- Microsoft Learn. *DeviceEvents table in the advanced hunting schema.* <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table>
- Microsoft Learn. *format_ipv4().* <https://learn.microsoft.com/en-us/kusto/query/format-ipv4-function>
- Microsoft Learn. *parse_ipv4().* <https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/parse-ipv4-function>
- Microsoft Learn. *CommonSecurityLog table in Microsoft Sentinel.* <https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog>
- MITRE ATT&CK. *Unsecured Credentials: Cloud Instance Metadata API (T1552.005).* <https://attack.mitre.org/techniques/T1552/005/>
- MITRE ATT&CK. *Exploit Public-Facing Application (T1190).* <https://attack.mitre.org/techniques/T1190/>
- MITRE ATT&CK. *Hijack Execution Flow: DLL Side-Loading (T1574.002).* <https://attack.mitre.org/techniques/T1574/002/>
- MITRE ATT&CK. *Obfuscated Files or Information (T1027).* <https://attack.mitre.org/techniques/T1027/>
- MITRE ATT&CK. *Proxy (T1090).* <https://attack.mitre.org/techniques/T1090/>
- DevSecOpsDad.com *From RSS Noise to CISO Signal: Automating Cyber Threat Intel.* <https://www.hanley.cloud/2026-04-28-From-RSS-Noise-to-CISO-Signal-Automating-Cyber-Threat-Intelligence-That-Actually-Matters/>
- DevSecOpsDad.com *Identify Your Exposed Internet-Facing Devices Before They Identify You!* <https://www.hanley.cloud/2025-11-25-Identify-Your-Exposed-Internet-Facing-Devices-Before-They-Identify-You/>


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

<br/>

<div style="text-align:center; margin: 2.5em 0;">
  <a href="https://devsecopsdadattack.com" target="_blank" rel="noopener noreferrer">
    <img 
      src="/assets/img/Attack1.png"
      style="width: auto; margin: 0 auto; box-shadow: 0 16px 40px rgba(0,0,0,.45); border-radius: 8px;"
    />
  </a>
</div>

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
