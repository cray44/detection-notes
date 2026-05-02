# WMI Event Subscription Persistence

<!--
Quality bar checklist — complete before committing:
  [x] SPL query is primary — includes performance notes
  [x] Sigma rule exists in sigma-to-spl/rules/ (not embedded here — reference path only)
  [x] Sigma rule expresses full logic, OR has caveat explaining what SPL adds
  [x] test-data/ directory alongside this file with malicious + benign sample logs
  [x] Threat-informed framing — tied to published actor/campaign reporting where possible
  [x] Blind spots are honest and specific
  [x] FP table has real triage guidance
-->

## Goal

Detect creation of WMI event subscriptions using executable consumer types (`CommandLineEventConsumer` or `ActiveScriptEventConsumer`), which allow arbitrary code execution on trigger and persist across reboots without any scheduled task or registry key. WMI persistence is a TTPs staple for APT29, APT41, and ransomware affiliates because it survives most endpoint hardening and produces no obvious artefact for casual responders to stumble across.

## ATT&CK Categorization

- **Tactic:** TA0003 — Persistence
- **Technique:** T1546 — Event Triggered Execution
- **Sub-technique:** T1546.003 — Windows Management Instrumentation Event Subscription

## Threat Context

WMI event subscription persistence appears in both nation-state and criminal tooling, precisely because it requires no file drop in a predictable location and does not touch the registry paths most AV products monitor.

- **APT29 (Cozy Bear)** used WMI subscriptions in the SolarWinds supply-chain follow-on operations documented by Volexity and Mandiant — subscriptions were installed under system accounts with names mimicking legitimate Windows services, triggered on system uptime thresholds to avoid sandbox detection.
- **APT41 (Double Dragon / Winnti Group)** regularly chains WMI persistence with their modular backdoor deployment. CISA AA22-277A (Iranian actors, 2022) documents the same technique used by state-sponsored actors for long-term persistent access.
- **Conti/BlackCat ransomware affiliates** use WMI subscriptions as a fallback persistence mechanism installed immediately after initial access — before deploying the main ransomware payload — so the subscription re-establishes the C2 beacon if the main implant is cleaned.

Tools used: PowerShell `Set-WMIInstance` / `Register-WMIEvent`, SharpWMI, WMI-Persistence.ps1, direct WMIC CLI, and CIM API from compiled C# droppers.

## Strategy Abstract

WMI persistence requires three objects in the WMI repository: an **EventFilter** (defines the trigger — user logon, system uptime interval, process creation), an **EventConsumer** (defines the action — run a command, execute a script), and a **FilterToConsumerBinding** that links them. Only `CommandLineEventConsumer` and `ActiveScriptEventConsumer` can execute arbitrary code; the other consumer types (`LogFileEventConsumer`, `NTEventLogEventConsumer`) write to logs and are generally benign.

Sysmon captures these object creations as Event ID 19 (filter), 20 (consumer), and 21 (binding). Event 20 is the highest-fidelity signal: it records the consumer `Type` and `Destination` fields, which reveal both what kind of consumer was created and — crucially — the command or script content. Scoring the `Destination` field against known-malicious patterns (base64-encoded strings, LOLBins, suspicious filesystem paths) converts a broad category alert into a risk-stratified finding.

A bound subscription is only active after Event 21 fires — correlating Event 20 creation with Event 21 binding on the same host within seconds provides confirmation that the persistence mechanism is fully armed.

## Technical Context

**Data source:** Sysmon Event ID 20 (WmiEventConsumer) and Event ID 21 (WmiEventConsumerToFilter) via Windows Event Forwarding or Splunk Universal Forwarder — sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

**Sysmon configuration requirement:** WMI activity events (19/20/21) must be enabled. In most Sysmon configs this is on by default — check that `WmiEvent` is not explicitly excluded:

```xml
<WmiEvent onmatch="include">
  <Operation condition="is">Created</Operation>
</WmiEvent>
```

**Sigma rule:** [`rules/windows/wmi-event-subscription-persistence.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/windows/wmi-event-subscription-persistence.yml) in sigma-to-spl

> The Sigma rule matches Event 20 on consumer type (`CommandLineEventConsumer` / `ActiveScriptEventConsumer`). The SPL below extends this with destination content scoring — base64 detection, LOLBin matching, and suspicious path patterns — which Sigma's field-matching model cannot express without custom condition blocks. The risk scoring and Event 21 binding correlation are SPL-only additions.

**Key fields:**

| Field | Event ID | Description |
|---|---|---|
| `EventID` | — | 19 = filter created, 20 = consumer created, 21 = binding created |
| `Type` | 20 | Consumer type — `CommandLineEventConsumer` or `ActiveScriptEventConsumer` are the dangerous ones |
| `Name` | 20 | Consumer name — often masquerades as a legitimate service name |
| `Destination` | 20 | For `CommandLineEventConsumer`: the command line to execute. For `ActiveScriptEventConsumer`: the script content. Primary field for intent scoring. |
| `User` | 20/21 | Account that created the subscription — `SYSTEM` is typical for attackers who've already escalated |
| `Consumer` | 21 | Reference to the consumer object: `CommandLineEventConsumer.Name="<name>"` |
| `Filter` | 21 | Reference to the filter object: `__EventFilter.Name="<name>"` |
| `ComputerName` | all | Endpoint where the subscription was created |

**Environment assumptions:**
- Sysmon 13+ installed on endpoints with WmiEvent logging enabled
- Events forwarded to `index=endpoint` via WEF or Splunk UF
- A `wmi_consumer_allowlist.csv` lookup with known-good `Name` and `Destination` patterns for legitimate management tooling
- Sysmon service integrity monitoring in place (separate detection for Sysmon tampering)

## Performance Notes

- **Estimated event volume:** WMI subscription creation events are extremely low volume — single-digit events per day per endpoint in normal operation. At 1,000 endpoints, expect fewer than 100 Event 20/21 events per day before filtering. Volume spikes are themselves anomalous and indicate mass deployment.
- **Indexed fields:** `EventID`, `index`, and `sourcetype` are indexed. `Type` is a Sysmon-extracted field available in `XmlWinEventLog` and searchable efficiently. The destination content scoring (`eval`/`match`) runs only on what survives the EventID + Type filter — very small set.
- **Recommended time range:** `-60m` on a 15-minute schedule. WMI subscription creation is rare enough that a 1-hour window is appropriate; this is not a high-velocity detection.
- **Acceleration:** Not needed. The pre-filter (`EventID=20 Type IN (...)`) reduces to single-digit events before any field extraction.
- **Do not run `stats` before the destination scoring** — that would collapse events before you can evaluate per-event `Destination` content.

## Blind Spots

- **Pre-installed subscriptions:** WMI subscriptions installed before Sysmon was deployed, or installed on a host where Sysmon was briefly disabled, will not appear in the event stream. The subscription lives in the WMI repository (`C:\Windows\System32\wbem\Repository`) and is persistent — it will fire silently until someone queries `Get-WMIObject -Namespace root\subscription`. A hunting query against the MOF repository is a necessary companion.
- **Remote WMI subscription creation:** When an attacker creates the subscription from a remote host using DCOM/RPC (`wmic /node:<target>`), Sysmon Events 19/20/21 fire on the *target* machine, not the attacker's pivot host. The detection works, but attribution of the source is not captured in these events — correlate with network connection events (Sysmon Event 3) to the WMI DCOM port (135/TCP, dynamic RPC).
- **MOF file compilation:** If an attacker delivers a Managed Object Format (`.mof`) file and runs `mofcomp.exe` to compile it into the WMI repository, the resulting subscription objects may not generate Sysmon Events 19/20/21 depending on the Sysmon version and configuration. `mofcomp.exe` execution from a non-standard path is detectable via process creation events (Event 1) as a complementary signal.
- **Consumer type evasion:** `LogFileEventConsumer` is generally benign, but an attacker could use it to write a script to a predictable path that a scheduled task or service then executes. This detection does not cover that chained technique.
- **WMI namespace variation:** Subscriptions are typically created in `root\subscription`, but they can be created in other namespaces (e.g., `root\default`). Sysmon 19/20/21 should capture these regardless of namespace, but untested — verify in your lab.
- **Sysmon service tampering:** Any technique that stops or corrupts the Sysmon driver before creating the WMI subscription evades this detection entirely. Monitor for Sysmon service stop events and driver unload events as a defense-in-depth control.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| SCCM / ConfigMgr client agents | Consumer `Name` typically contains "SCCM" or "CCM". `Destination` points to `C:\Windows\CCM\`. Verify against known deployment and add to `wmi_consumer_allowlist.csv`. |
| HP iLO / Dell OMSA / OEM management agents | `Destination` points to a vendor path under `C:\Program Files\`. Cross-reference server hardware inventory. Only suppress after confirming the host is a managed server, not a workstation. |
| SolarWinds NCM / monitoring agents | Consumer name typically matches the product. `Destination` is a known agent binary. If unexpected on a host type (e.g., a developer workstation), investigate regardless. |
| Windows built-in SCM Event Log Consumer | `Name` = `SCM Event Log Consumer` — filtered by the Sigma rule. Should not alert. |
| Security tooling using WMI for telemetry | Some older AV/EDR products (pre-2020) used WMI subscriptions for process monitoring before kernel callback availability. If `Destination` points to a known security vendor binary path, suppress after vendor confirmation. |
| Lab/dev environments running WMI persistence demos | `User` will be an interactive user account rather than `SYSTEM` or a service account. Low-risk but worth noting — any persistence installation outside a formal change process warrants documentation. |

## Validation

**Test data:** See [`test-data/`](test-data/) alongside this file — includes malicious samples (encoded PS, LOLBin + ProgramData, VBScript via mshta) and benign samples (SCCM consumer, HP SMH consumer, native SCM consumer).

**Lab reproduction using PowerShell (requires admin):**

```powershell
# Option 1: CommandLineEventConsumer — triggers on system uptime > 300s (fires once per boot)
$FilterArgs = @{
    Name = 'TestPersistenceFilter'
    EventNamespace = 'root\CimV2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300 AND TargetInstance.SystemUpTime < 400"
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

$ConsumerArgs = @{
    Name = 'TestPersistenceConsumer'
    CommandLineTemplate = 'C:\Windows\System32\cmd.exe /c echo pwned > C:\Windows\Temp\wmi-test.txt'
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

$BindingArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs
# Expected: Sysmon Event 19 (filter), Event 20 (CommandLineEventConsumer created), Event 21 (binding)
```

```powershell
# Cleanup after testing
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq 'TestPersistenceFilter' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq 'TestPersistenceConsumer' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

```powershell
# Option 2: Verify existing WMI subscriptions on any host (hunting query)
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

Expected Sysmon output: Event 19 (`WmiEventFilter`), Event 20 (`WmiEventConsumer`, `Type=CommandLineEventConsumer`), Event 21 (`WmiEventConsumerToFilter`) in `Microsoft-Windows-Sysmon/Operational`.

**SPL (primary):**

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=20
    Type IN ("CommandLineEventConsumer", "ActiveScriptEventConsumer")
| eval dest_lower=lower(Destination)
| eval has_encode=if(match(dest_lower, "-en[co]"), "true", "false")
| eval has_b64=if(match(Destination, "[A-Za-z0-9+/]{60,}={0,2}"), "true", "false")
| eval has_lolbin=if(
    match(dest_lower, "powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|cmd\.exe"),
    "true", "false")
| eval has_suspect_path=if(
    match(dest_lower, "\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\programdata\\\\"),
    "true", "false")
| lookup wmi_consumer_allowlist.csv Name OUTPUT is_known_good
| where isnull(is_known_good)
| eval risk_score=case(
    has_encode="true",                                     95,
    has_b64="true",                                        95,
    has_lolbin="true" AND has_suspect_path="true",         90,
    has_lolbin="true",                                     75,
    has_suspect_path="true",                               60,
    true(),                                                50)
| eval confidence=case(risk_score>=85,"HIGH", risk_score>=65,"MEDIUM", true(),"LOW")
| table _time, ComputerName, User, Name, Type, Destination,
         has_encode, has_b64, has_lolbin, has_suspect_path, risk_score, confidence
| sort - risk_score
```

> *Performance note:* `EventID=20` and `Type IN (...)` at the top reduce to single-digit results per day before any `eval` runs. The `lookup` against `wmi_consumer_allowlist.csv` suppresses known-good management tooling. Destination content scoring (`match()`) runs only on what survives both filters. Do not move the `lookup` after the risk scoring block — it would score events that should be suppressed.

**Companion SPL — Event 21 binding correlation (confirms persistence is fully armed):**

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=21
| rex field=Consumer "CommandLineEventConsumer\.Name=\"(?<bound_consumer_name>[^\"]+)\""
| eval consumer_type=if(isnotnull(bound_consumer_name), "CommandLineEventConsumer", null())
| rex field=Consumer "ActiveScriptEventConsumer\.Name=\"(?<bound_script_consumer>[^\"]+)\""
| eval consumer_type=coalesce(consumer_type, if(isnotnull(bound_script_consumer), "ActiveScriptEventConsumer", null()))
| where isnotnull(consumer_type)
| table _time, ComputerName, User, Consumer, Filter, consumer_type
```

## Response

1. **Confirm the consumer type and content** — `Type` and `Destination` in the Event 20 tell you what will execute. A LOLBin with a base64 payload is immediate containment; a path to a known management tool is a potential FP requiring verification.
2. **Check if the subscription is bound** — Query Event 21 on the same host within 60 seconds of Event 20 using the consumer `Name`. If bound, the persistence is active and will fire on next trigger condition.
3. **Identify the filter trigger** — Pull Event 19 for the corresponding `__EventFilter` name. The filter's `Query` field tells you when the payload fires: on user logon (`__InstanceCreationEvent` with `Win32_LogonSession`), on system uptime threshold, or on process creation. This tells you how quickly to act.
4. **Trace the creator process** — Correlate `User` and `ComputerName` from Event 20 with process creation events (Sysmon Event 1) in the prior 60 seconds. Identify what process called `Set-WmiInstance` or `wmic.exe` — this is the initial access or lateral movement artefact.
5. **Remove the subscription** — Use `Get-WmiObject -Namespace root\subscription` queries to enumerate and `Remove-WmiObject` to delete. Remove filter, consumer, and binding; deleting only one leaves the others in the repository. Confirm deletion with a second enumeration.
6. **Scope the compromise** — WMI subscription installation implies the attacker had admin on the host. Pull all process creation, network connection, and file creation events for the 24 hours preceding the subscription creation. Assume credential theft occurred; check for lateral movement activity.
7. **Hunt for other subscriptions** — Run the `Get-WmiObject` hunting query across all endpoints via RMM or Splunk lookup to find subscriptions that predate Sysmon deployment or were installed on hosts where Sysmon was briefly down.

## References

- [MITRE ATT&CK T1546.003 — Event Triggered Execution: WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [CISA Advisory AA22-277A — Iranian APT WMI persistence TTPs](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a)
- [Sysmon Event ID 19/20/21 — WMI Activity documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [FireEye/Mandiant — WMI Attack Techniques whitepaper](https://www.mandiant.com/resources/blog/hackerone-disclosure-wmi-persistence)
- [Matt Graeber — Abusing Windows Management Instrumentation (Black Hat USA 2015)](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent-Asynchronous-And-Fileless-Backdoor.pdf)
- [Sigma rule — wmi-event-subscription-persistence.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/windows/wmi-event-subscription-persistence.yml)
