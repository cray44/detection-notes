# LSASS Process Access for Credential Dumping

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

Detect attempts to dump credentials from LSASS (Local Security Authority Subsystem Service) memory by identifying processes opening handles to `lsass.exe` with memory-read access rights. LSASS credential dumping is the single most-used post-compromise technique across ransomware, APT, and red team operations — Mimikatz, ProcDump, and comsvcs.dll MiniDump all rely on the same Windows process access primitive that Sysmon Event 10 captures.

## ATT&CK Categorization

- **Tactic:** TA0006 — Credential Access
- **Technique:** T1003.001 — OS Credential Dumping: LSASS Memory

## Threat Context

LSASS credential dumping appears in virtually every post-compromise intrusion with lateral movement. Mandiant M-Trends 2024 noted credential theft tools in 86% of intrusions they investigated; LSASS access is the most common mechanism. Specific actor examples:

- **ALPHV/BlackCat and LockBit affiliates** routinely use `ProcDump.exe -accepteula -ma lsass.exe` or `comsvcs.dll,MiniDump` as their first post-access credential step before lateral movement via PtH or PtT.
- **Scattered Spider** used `pypykatz` (Python Mimikatz port) in the MGM and Caesars attacks after gaining initial access via helpdesk social engineering — LSASS dump enabled domain-wide credential harvest.
- **APT29 (Cozy Bear)** has used a custom LSASS reader in several campaigns documented by Volexity and Mandiant to avoid dropping Mimikatz on disk.

The Sysmon Event 10 `GrantedAccess` field is the most reliable indicator: `0x1010` (`PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`) is Mimikatz's default; `0x1F1FFF` is ProcDump's full-access request. Both are abnormal for any process that isn't an AV/EDR agent.

## Strategy Abstract

Windows records every inter-process handle open in Sysmon Event ID 10 (ProcessAccess) when configured to do so. The event captures the requesting process (`SourceImage`), the target (`TargetImage`), and the specific access rights mask (`GrantedAccess`) being requested. An attacker reading LSASS memory must request at minimum `PROCESS_VM_READ` (0x0010) — without it, no memory read is possible.

The detection filters to all Event 10 events targeting `lsass.exe`, then classifies the `GrantedAccess` value against known credential-dumping access masks. A scored allowlist of known-good callers (AV/EDR agents, Windows system processes) is applied to suppress the high volume of legitimate LSASS readers that exist in every enterprise. Anything remaining — particularly unknown binaries or living-off-the-land tools requesting high-access masks — is high confidence.

A secondary signal is `CallTrace`: legitimate LSASS readers (AV engines, Windows itself) have call stacks rooted in system DLLs (`ntdll.dll`, `kernelbase.dll`). Malicious access from injected shellcode or reflectively loaded tools often has call trace entries containing addresses that don't resolve to any named module — these appear as bare hexadecimal addresses in the `CallTrace` field.

## Technical Context

**Data source:** Sysmon Event ID 10 (ProcessAccess) via Windows Event Forwarding or Splunk Universal Forwarder — sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

**Sysmon configuration requirement:** Event ID 10 must be enabled with a `TargetImage` filter for `lsass.exe`. A minimal Sysmon config rule:

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

Without this, no Event 10 events for LSASS will be logged regardless of access rights.

**Sigma rule:** [`rules/endpoint/lsass-process-access-credential-dumping.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/endpoint/lsass-process-access-credential-dumping.yml) in sigma-to-spl

> Sigma matches `GrantedAccess` as string substrings against Sysmon's hex representation. The SPL below converts to integer for range-based scoring and adds `CallTrace` analysis (unknown-module detection) not expressible in Sigma.

**Key fields:**

| Field | Description |
|---|---|
| `EventID` | Must be 10 (ProcessAccess) |
| `SourceImage` | Full path of the process opening the handle — the attacker's tool |
| `SourceProcessId` | PID of requesting process — correlate with process creation events |
| `TargetImage` | Must be `C:\Windows\System32\lsass.exe` |
| `GrantedAccess` | Hex access mask — the specific rights requested. Key values below. |
| `CallTrace` | Semicolon-delimited stack frames — bare hex addresses indicate non-resident/injected code |
| `SourceUser` | Account running the requesting process — `SYSTEM` is normal for many tools; interactive user accounts are suspicious |

**GrantedAccess reference:**

| Value | Rights | Tool / Context |
|---|---|---|
| `0x1010` | VM_READ + QUERY_LIMITED_INFO | Mimikatz `sekurlsa::logonpasswords` default |
| `0x1038` | READ_CONTROL + VM_READ + QUERY_INFO + QUERY_LIMITED_INFO | Mimikatz with more capabilities requested |
| `0x1F1FFF` | Full access minus WRITE_DAC | ProcDump default, also some EDR agents |
| `0x1FFFFF` | PROCESS_ALL_ACCESS | Full read/write/execute — rarely legitimate |
| `0x0010` | VM_READ only | Minimal dump read; some custom tools |
| `0x143A` | VM_READ + multiple write/exec bits | Indicative of process injection prior to LSASS read |
| `0x0400` | QUERY_INFORMATION only | Task Manager — benign, no memory read possible |

**Environment assumptions:**
- Sysmon 14+ installed on endpoints with Event 10 enabled for lsass.exe
- Events forwarded via WEF or Splunk UF to `index=endpoint`
- A `lsass_allowlist.csv` lookup exists with known-good `SourceImage` paths for AV/EDR agents in your environment
- Endpoints are running Windows 10/11 or Server 2016+ (LSASS Protected Process Light availability affects access mask requirements)

## Performance Notes

- **Estimated event volume:** With a properly scoped Sysmon config filtering to `lsass.exe`, expect 50–500 Event 10 events per endpoint per day — the majority from AV/EDR agents. At 1,000 endpoints, that is 50,000–500,000 events/day. The allowlist suppresses the bulk before scoring.
- **Indexed fields:** `EventID`, `index`, and `sourcetype` are indexed. `TargetImage` and `SourceImage` are Sysmon-extracted fields — fast on `XmlWinEventLog` because the Add-on extracts them at index time.
- **Recommended time range:** `-15m` on a 5-minute schedule. This is endpoint telemetry where speed matters — a credential dump followed immediately by lateral movement can happen in under 60 seconds.
- **Acceleration:** Not needed at typical enterprise scale. If running across more than 10,000 endpoints, consider a `tstats` pre-filter on `EventID=10` before the full query.
- **Do not alert on `GrantedAccess=0x0400`** (Task Manager's QUERY_INFORMATION only) — this cannot read memory and is benign. Filter it explicitly to reduce noise.

## Blind Spots

- **Kernel-level credential access:** Attackers with kernel driver access (signed/exploited driver) can read LSASS memory without generating a Sysmon Event 10 at all. UEFI-level rootkits and `PPLdump` (exploiting a Windows kernel vulnerability to bypass LSASS PPL protection) leave no process access event.
- **LSASS Protected Process Light (PPL):** On modern Windows with Credential Guard or PPL enabled, many access masks that previously worked are blocked by the kernel. Attackers must use a PPL bypass (e.g., loading a vulnerable signed driver) before the LSASS access — this detection only fires when the access succeeds or is attempted, not on the preceding PPL bypass.
- **DCSync (no LSASS access required):** An attacker with Domain Replication permissions can extract credential hashes via DCSync (`Mimikatz lsadump::dcsync`) without ever touching LSASS on the victim host. DCSync generates AD replication traffic and a Domain Controller event, not a Sysmon Event 10. Requires a separate detection.
- **Remote LSASS dump:** Tools like `Invoke-Mimikatz` executed remotely or LSASS dump via `crackmapexec --lsa` dump on a remote host — the Sysmon Event 10 fires on the *remote* target, not the attacker's host. Detection works, but alerts on the victim machine, not the pivot source.
- **Memory-mapped file access:** Some credential access techniques read the LSASS process token via memory-mapped sections rather than a direct `OpenProcess` call. These may not generate Event 10 depending on the Windows version.
- **Sysmon config gaps:** If the Sysmon ProcessAccess rule has been modified, disabled, or tampered with on an endpoint, this detection has no signal. Monitoring for Sysmon service stop events (`sc stop sysmon`) is a necessary companion.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| AV/EDR agents (CrowdStrike, Defender, SentinelOne, Carbon Black) | `SourceImage` will match a known vendor path. Maintain `lsass_allowlist.csv` per environment. These should be suppressed before scoring. |
| Windows Defender components (`MsMpEng.exe`, `MpCmdRun.exe`) | Same as above — add to allowlist. `GrantedAccess` for Defender is typically `0x1010` or `0x1F1FFF`. |
| Process Monitor or Process Explorer during authorized admin use | `SourceImage` will be a known Sysinternals path. If running on a server outside a scheduled admin window, investigate. |
| Domain controller LSASS activity from legitimate replication | Seen as `SourceImage=lsass.exe` accessing another lsass — process-to-process. The `SourceImage=TargetImage` pattern is its own FP class; filter it. |
| Automated backup agents reading LSASS for VSS snapshot integrity | Add backup agent paths to `lsass_allowlist.csv`. Verify with backup team. |
| `csrss.exe` and `wininit.exe` | System processes with legitimate LSASS handles. Always suppress. |

## Validation

**Test data:** See [`test-data/`](test-data/) alongside this file — includes malicious samples (Mimikatz access mask, ProcDump access mask, unknown-module CallTrace) and benign samples (EDR agent access, system process access).

**Lab reproduction using Sysmon + Mimikatz:**

```powershell
# In a test VM with Sysmon installed — requires admin
# Option 1: Mimikatz (drops binary on disk — noisy, ideal for testing detection)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
# Expected: Sysmon Event 10 with GrantedAccess=0x1010, SourceImage=mimikatz.exe

# Option 2: ProcDump (LOFT technique — legitimate signed binary)
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Expected: Sysmon Event 10 with GrantedAccess=0x1F1FFF, SourceImage=procdump.exe

# Option 3: comsvcs.dll MiniDump (fileless-ish, no extra binary)
# Run from PowerShell as SYSTEM:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id lsass.dmp full
# Expected: Sysmon Event 10, SourceImage=rundll32.exe, GrantedAccess=0x1F1FFF
```

Expected Sysmon output: Event 10 in `Microsoft-Windows-Sysmon/Operational`, TargetImage ending in `lsass.exe`, GrantedAccess matching one of the flagged values.

**SPL (primary):**

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=10
    TargetImage="*\\lsass.exe"
| eval granted_access_lower=lower(GrantedAccess)
| eval is_memory_read=case(
    match(granted_access_lower, "0x1010"),    "mimikatz_default",
    match(granted_access_lower, "0x1038"),    "mimikatz_extended",
    match(granted_access_lower, "0x1f1fff"),  "procdump_full",
    match(granted_access_lower, "0x1fffff"),  "process_all_access",
    match(granted_access_lower, "0x143a"),    "inject_then_read",
    match(granted_access_lower, "0x0040"),    "vm_read_only",
    match(granted_access_lower, "0x0010"),    "vm_read_minimal",
    true(),                                   null())
| where isnotnull(is_memory_read)
| lookup lsass_allowlist.csv SourceImage OUTPUT is_known_good
| where isnull(is_known_good)
| eval has_unknown_module=if(
    match(CallTrace, "[0-9A-Fa-f]{8,16}\|UNKNOWN"),
    "true", "false")
| eval risk_score=case(
    is_memory_read="process_all_access",                          100,
    is_memory_read="inject_then_read",                            90,
    is_memory_read="procdump_full" AND has_unknown_module="true",  90,
    is_memory_read="mimikatz_default",                            85,
    is_memory_read="mimikatz_extended",                           85,
    is_memory_read="procdump_full",                               70,
    is_memory_read="vm_read_only" OR is_memory_read="vm_read_minimal", 50,
    true(),                                                        40)
| eval confidence=case(risk_score>=85,"HIGH", risk_score>=65,"MEDIUM", true(),"LOW")
| table _time, ComputerName, SourceImage, SourceProcessId, SourceUser,
         TargetImage, GrantedAccess, is_memory_read,
         has_unknown_module, CallTrace, risk_score, confidence
| sort - risk_score
```

> *Performance note:* `EventID=10` and `TargetImage="*\\lsass.exe"` at the top are the critical volume reducers — they must appear before any `eval`. The `lookup` against `lsass_allowlist.csv` suppresses the majority of remaining events (AV/EDR agents). `CallTrace` analysis runs only on what survives both filters. Do not move the allowlist lookup after the `eval risk_score` block.

## Response

1. **Identify the source process** — `SourceImage` and `SourceProcessId` tell you what binary opened the handle. Is it a known tool (`mimikatz.exe`, `procdump.exe`, `rundll32.exe`)? Check the process creation event (Sysmon Event 1) for the same PID to see command-line arguments and parent process.
2. **Determine if credentials were successfully read** — A successful Mimikatz dump generates Sysmon Event 10 immediately followed by network activity (to exfil) or process creation events (subsequent tooling). Check for follow-on lateral movement within 5–15 minutes.
3. **Assess scope** — Was this on a single endpoint or multiple? LSASS dumps from multiple hosts in a short window indicate automated credential collection (worm-like lateral movement or an automated attack framework).
4. **Identify what credentials were available** — What accounts were logged in on the compromised host at the time of the dump? Pull Windows Logon events (Event 4624) for the target host in the prior 24 hours. Domain admin sessions are high-value; service account sessions may indicate widespread exposure.
5. **Contain immediately** — If a domain admin or service account credential was likely dumped from any host, treat as full domain compromise and escalate. Isolate the endpoint. Do not wait for confirmation of lateral movement.
6. **Force password resets** — Reset credentials for all accounts that had interactive sessions on the compromised host. Prioritize privileged accounts. If domain-wide exposure is possible, initiate a full Kerberos TGT invalidation (`krbtgt` password reset — twice, 10 hours apart).
7. **Hunt for lateral movement** — Pivot from `ComputerName` to all authentication events (4624, 4625) and SMB/RDP connections in the 30 minutes following the dump event. Look for Pass-the-Hash indicators (NTLM authentication from non-domain-joined hosts or at unusual hours).

## References

- [MITRE ATT&CK T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [Sysmon Event ID 10 — ProcessAccess documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Detecting Credential Dumping — Elastic Security](https://www.elastic.co/blog/how-attackers-dump-active-directory-database-credentials)
- [Threat Hunting: Detecting LSASS Dumping — menasec.net](https://blog.menasec.net/2019/02/threat-hunting-21-detecting-dumping-of.html)
- [Scattered Spider TTPs (credential access) — CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Mandiant M-Trends 2024 — credential theft prevalence](https://www.mandiant.com/resources/m-trends-2024)
- [Sigma rule — lsass-process-access-credential-dumping.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/endpoint/lsass-process-access-credential-dumping.yml)
