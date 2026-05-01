# Kerberoasting via RC4 Encryption Downgrade

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

Detect Kerberoasting attacks by identifying Kerberos service ticket requests (Event 4769) that force RC4-HMAC encryption against user-class service account SPNs. In modern Active Directory environments that negotiate AES by default, an RC4 TGS request for a user-class SPN is anomalous — it is the exact request pattern produced by Rubeus, Impacket GetUserSPNs.py, and PowerView Invoke-Kerberoast, all of which downgrade to RC4 because RC4 hashes are orders of magnitude faster to crack than AES.

## ATT&CK Categorization

- **Tactic:** TA0006 — Credential Access
- **Technique:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

## Threat Context

Kerberoasting is documented across every major threat actor category. CISA Advisory AA22-320A (Iranian government-sponsored APT) explicitly names Kerberoasting as a post-initial-access credential harvesting technique used before lateral movement. Mandiant, CrowdStrike, and Microsoft have attributed the technique to APT29, APT41, Lazarus Group, and dozens of tracked eCrime operators. The leaked Conti playbook instructs affiliates to run Kerberoast immediately after obtaining a foothold to harvest service account hashes for password cracking.

The technique exploits a design property of Kerberos: any domain user can request a service ticket for any SPN in the domain, and the ticket is encrypted with the service account's NTLM hash. The attacker requests the ticket, extracts it from memory, and cracks it offline — no vulnerability, no exploit, no elevated privilege required. The only detection opportunity on the domain controller side is Event 4769.

RC4 (encryption type 0x17) is the attacker's preferred target because RC4 NT hashes crack in minutes on commodity hardware where AES-256 (0x12) would take years. Modern tooling defaults to requesting 0x17 specifically; some operators filter for service accounts with weak password policies before requesting to maximize crack success rate.

## Strategy Abstract

Windows domain controllers log every Kerberos service ticket request as Event 4769. The event records the requesting user, the target SPN, the encryption type negotiated, and the source IP. In an AD environment where Group Policy enforces AES for Kerberos (the default in Server 2008 R2+ domain functional levels), an RC4 TGS request for a user-class SPN is immediately anomalous.

The detection filters Event 4769 on three criteria:
1. **Encryption type 0x17 (RC4-HMAC)** — the downgrade indicator; 0x18 (RC4-HMAC-EXP) is included as a variant
2. **Non-machine-account SPN** — machine accounts (`$`-suffixed) legitimately use RC4 in some Kerberos operations; user-class service accounts should not
3. **Success status (0x0)** — failed requests indicate a misconfigured tool or enumeration attempt, not a successful hash extraction

Volume amplifies confidence: a single RC4 request might be a legacy application compatibility issue; ten or more requests from the same user in a short window is a tool run.

## Technical Context

**Data source:** Windows Security Event Log — Event ID 4769 via Splunk Add-on for Windows — sourcetype `WinEventLog:Security` or `XmlWinEventLog:Security`, index `windows`

**Sigma rule:** [`rules/windows/kerberoasting-rc4-downgrade.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/windows/kerberoasting-rc4-downgrade.yml) in sigma-to-spl

> The Sigma rule covers the structural filter (EventID 4769, TicketEncryptionType 0x17, Status 0x0, non-machine/non-krbtgt SPN). The SPL below adds volume-based confidence scoring (request count and unique SPN count per user per window) and enrichment of the requesting user's group membership to distinguish service account from interactive user Kerberoasting.

**Key fields:**

| Field | Description |
|---|---|
| `EventCode` | `4769` — Kerberos Service Ticket Operations (request) |
| `Status` | `0x0` = success; filter to this to capture completed hash extractions |
| `TicketEncryptionType` | `0x17` = RC4-HMAC (the downgrade); `0x18` = RC4-HMAC-EXP (variant) |
| `TicketOptions` | Bitmask of Kerberos flags; Rubeus default is `0x40810000` but varies by tool and configuration |
| `ServiceName` | The SPN being targeted — format `service/host.domain.com`; machine accounts end in `$` |
| `SubjectUserName` | The domain account making the request — the compromised user or attacker foothold account |
| `SubjectDomainName` | Domain of the requesting user |
| `IpAddress` | Source IP of the TGS request — the workstation or server the attacker is operating from |
| `ComputerName` | The domain controller that processed the request |

**Environment assumptions:**
- Windows Security Audit Policy has `Audit Kerberos Service Ticket Operations` enabled for both success and failure — this is required for Event 4769 to be logged
- Domain functional level is Windows Server 2008 R2 or higher (AES supported by default); RC4 requests for user-class SPNs are anomalous at this level
- Event logs from all domain controllers are forwarded to Splunk — Kerberoasting requests are handled by whichever DC the client contacts; missing one DC means missing events
- A `service_accounts.csv` lookup exists mapping known service account names to their owner, purpose, and whether RC4 is a documented requirement

## Performance Notes

- **Estimated event volume:** Event 4769 volume depends heavily on environment size and Kerberos ticket lifetime. In a 5,000-user environment, expect 50K–500K events/day across all DCs. A Kerberoasting run adds at most a few hundred events. This is low relative volume.
- **Indexed fields:** `EventCode`, `Status`, and `TicketEncryptionType` should be indexed by the Splunk Add-on for Windows. Confirm with `| tstats count WHERE index=windows sourcetype=WinEventLog:Security by EventCode`.
- **DC coverage:** Run `| stats dc(ComputerName) AS dc_count` on Event 4769 data to verify all DCs are forwarding logs. A Kerberoasting run that only appears on two of five DCs indicates a coverage gap.
- **Recommended time range:** `-1h` on a 15-minute schedule. Kerberoasting tool runs complete in seconds; the detection window should be short to minimize analyst delay.
- **Acceleration:** Event 4769 volume can be high in large enterprises. Use `tstats` to pre-filter on EventCode=4769 before pulling raw events for field extraction. At very high volume, a summary index aggregating (user, SPN, enc_type, hour) enables long-term trending for slow Kerberoasting (one request per day per SPN).

## Blind Spots

- **AES Kerberoasting:** Rubeus v2.0+ supports `--enctype aes256` to request AES-encrypted tickets. The resulting hash is crackable but extremely slow. Detection requires monitoring for any RC4 **or AES** TGS requests for user-class SPNs — AES requests are high-volume and noisy to baseline, making this harder to operationalize without prior SPN enumeration telemetry.
- **AS-REP Roasting (T1558.004):** Accounts with "Do not require Kerberos preauthentication" set respond to AS-REQ with an AS-REP encrypted with their hash — no TGS request generated, no Event 4769. Completely separate detection on Event 4768 with `PreAuthType=0`.
- **Service accounts that legitimately require RC4:** In many environments, older service accounts have `msDS-SupportedEncryptionTypes=4` (RC4 only) because the application was configured before AES support was added. These accounts produce Event 4769 with enc_type 0x17 every time any client authenticates — generating persistent noise that must be baselined and suppressed.
- **Slow Kerberoasting:** An operator running one TGS request per hour across dozens of SPNs over days will never exceed volume-based thresholds. The per-request structural filter (enc_type 0x17) still fires, but at "LOW" confidence — which may not page an analyst.
- **DC log forwarding gaps:** If one or more DCs are not forwarding Event 4769, Kerberoasting requests handled by those DCs are invisible. This is a monitoring infrastructure gap, not a technique evasion.
- **Credential stuffing into legitimate service:** An attacker who obtains a service account's plaintext password via other means (LDAP query, password spray, clipboard) does not need to Kerberoast at all — this detection is irrelevant if the password is already known.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| Legacy application requiring RC4 (SQL Server, older Java Kerberos, some Oracle versions) | Check `ServiceName` against `service_accounts.csv` — if the SPN is documented as requiring RC4, suppress by ServiceName. Request count is low (one per authentication), not bursty. |
| Single RC4 request for a service account with `msDS-SupportedEncryptionTypes=4` | One request is a compatibility event; suppress documented RC4-only accounts. If the same SPN appears in a burst, treat as suspicious regardless of account configuration. |
| Security scanner / red team with authorization | Check `IpAddress` against authorized scanner ranges. If a pentest is underway, correlate timing with the engagement window. Authorized testing should be excluded by source IP, not suppressed globally. |
| Domain controller running old OS that defaults to RC4 for certain operations | Check `IpAddress` — if it matches a DC IP, this may be intra-DC Kerberos communication. Verify DC OS version and AES support. |

## Validation

**Test data:** See [`test-data/`](test-data/) — includes malicious samples (Rubeus-style burst of RC4 TGS requests for multiple user-class SPNs) and benign samples (machine account RC4 request, krbtgt filter, and a known legacy-RC4 service account request).

**Lab reproduction:**

```powershell
# Rubeus Kerberoast (Windows domain-joined lab host)
# Requests RC4 TGS for all user-class SPNs in the domain
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Impacket GetUserSPNs.py (Linux/Mac, requires domain credentials)
python3 impacket/examples/GetUserSPNs.py CONTOSO/jsmith:Password123 -dc-ip 10.1.2.10 -request

# PowerView Invoke-Kerberoast (PowerShell)
Import-Module PowerView.ps1
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash
```

Expected Event 4769 on the DC: `TicketEncryptionType=0x17`, `Status=0x0`, `ServiceName` matches user-class SPN, `IpAddress` = attacker workstation. Multiple events in rapid succession for different SPNs = tool run.

Expected Splunk result: `SubjectUserName` appears with `request_count >= 3`, `unique_spns >= 2`, `confidence=MEDIUM` or `HIGH`.

**SPL (primary):**

```spl
index=windows (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security") earliest=-1h latest=now
| where EventCode=4769
| where Status="0x0"
| where TicketEncryptionType IN ("0x17", "0x18", "23", "24")
| where NOT match(ServiceName, "\$$")
| where ServiceName != "krbtgt"
| where NOT IpAddress IN ("::1", "127.0.0.1", "")
| lookup service_accounts.csv service_name AS ServiceName OUTPUT rc4_required
| where isnull(rc4_required) OR rc4_required != "true"
| stats
    count                  AS request_count,
    dc(ServiceName)        AS unique_spns,
    values(ServiceName)    AS spns_targeted,
    values(IpAddress)      AS source_ips,
    values(ComputerName)   AS dcs_queried,
    min(_time)             AS first_seen,
    max(_time)             AS last_seen
    BY SubjectUserName, SubjectDomainName
| eval confidence = case(
    request_count >= 10 OR unique_spns >= 5, "HIGH",
    request_count >= 3  OR unique_spns >= 2, "MEDIUM",
    true(), "LOW")
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen  = strftime(last_seen,  "%Y-%m-%d %H:%M:%S")
| sort - request_count
| table SubjectUserName, SubjectDomainName, source_ips, unique_spns, spns_targeted, request_count, dcs_queried, confidence, first_seen, last_seen
```

> *Performance note:* The `TicketEncryptionType IN (...)` filter includes both hex string and decimal representations because the Splunk Add-on for Windows normalizes this field inconsistently across versions — include all forms defensively. The `service_accounts.csv` suppression lookup runs before `stats`, filtering documented RC4-required accounts before aggregation. The `dcs_queried` field in output is a diagnostic: if only one DC appears for a large request_count, it may indicate sensor coverage gaps on other DCs.

**KQL (community-translated, untested — Microsoft Sentinel `SecurityEvent`):**

```kql
SecurityEvent
| where EventID == 4769
| where Status == "0x0"
| where TicketEncryptionType in ("0x17", "0x18", "23", "24")
| where ServiceName !endswith "$"
| where ServiceName !in ("krbtgt")
| where IpAddress !in ("::1", "127.0.0.1", "")
| summarize
    RequestCount    = count(),
    UniqueSpns      = dcount(ServiceName),
    SpnsTargeted    = make_set(ServiceName),
    SourceIps       = make_set(IpAddress),
    DcsQueried      = make_set(Computer),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated)
    by SubjectUserName, SubjectDomainName
| extend Confidence = case(
    RequestCount >= 10 or UniqueSpns >= 5, "HIGH",
    RequestCount >= 3  or UniqueSpns >= 2, "MEDIUM",
    "LOW")
| where Confidence in ("HIGH", "MEDIUM")
| sort by RequestCount desc
```

## Response

1. **Identify the requesting user and source IP** (`SubjectUserName`, `source_ips`) — determine whether the user account is a human interactive account or a service account. An interactive user account making TGS requests for other services is the primary indicator of credential compromise.
2. **Pivot to authentication logs** — search Event 4624 (logon) for `SubjectUserName` in the same window from the same `IpAddress`. Determine how the attacker authenticated: was there a prior pass-the-hash or password spray?
3. **Enumerate targeted SPNs** — review `spns_targeted`. High-value targets: SQL service accounts (`MSSQLSvc`), IIS app pool accounts (`HTTP/`), backup service accounts. These have higher likelihood of weak passwords and domain admin-equivalent privileges.
4. **Force password rotation on all targeted accounts immediately** — even if hashes have not been cracked yet, assume they will be. Change passwords for every SPN in `spns_targeted` before the attacker gets offline cracking results (minutes to hours depending on password complexity).
5. **Assess SPN account privileges** — check AD group membership for every targeted service account. Any with Domain Admin, local admin on servers, or database owner privileges is a high-priority reset target.
6. **Harden for recurrence** — enforce strong passwords (25+ chars) on all service accounts with SPNs; migrate service accounts to Group Managed Service Accounts (gMSA), which use 120-character auto-rotating passwords that are not Kerberoastable in practice; configure `msDS-SupportedEncryptionTypes=24` (AES-only) on all user-class service accounts.

## References

- [MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [CISA Advisory AA22-320A — Iranian APT Kerberoasting and credential harvesting](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a)
- [Kerberoasting Without Mimikatz — Will Schroeder / Harmj0y (2016)](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [Rubeus — Kerberos toolkit (GhostPack)](https://github.com/GhostPack/Rubeus)
- [Detecting Kerberoasting Activity — Sean Metcalf / ADSecurity](https://adsecurity.org/?p=2784)
- [Impacket GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [Sigma rule — kerberoasting-rc4-downgrade.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/windows/kerberoasting-rc4-downgrade.yml)
