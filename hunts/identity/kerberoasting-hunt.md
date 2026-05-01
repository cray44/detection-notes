# Hunt: Kerberoasting and AS-REP Roasting

## Hypothesis

> "We believe a threat actor has performed Kerberoasting in our Active Directory environment because it is a near-universal post-compromise step — requiring no elevated privileges and producing service tickets that can be cracked offline without generating authentication failures. This would manifest in Windows Security event logs or Zeek kerberos.log as a burst of TGS-REQ requests for service tickets using RC4 encryption (etype 23) from a single host, targeting multiple service accounts in a short time window."

**Structured form:**
- **Actor behavior:** Requesting Kerberos service tickets (TGS) for accounts with SPNs, preferentially requesting RC4-encrypted tickets (etype 23) because they are faster to crack offline than AES tickets
- **Observable signal:** Multiple TGS-REQ events with `etype=23` (RC4-HMAC) targeting different service accounts from a single source IP within a compressed time window — a pattern inconsistent with normal workstation Kerberos activity
- **Data source:** Windows Security Event Log (Event ID 4769) via Splunk UF, OR Zeek kerberos.log via Corelight (`sourcetype=corelight_kerberos`)
- **Confidence:** High for tool-based attacks (Rubeus, Impacket); Medium for manual/slow attacks that spread requests over time

---

## ATT&CK Mapping

- **Tactic:** TA0006 — Credential Access
- **Technique:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
- **Related:** T1558.004 — AS-REP Roasting (covered in Stage 3)

---

## Threat Context

Kerberoasting is documented in virtually every significant intrusion affecting AD environments. CISA AA22-320A (Iranian APT), multiple Conti/BlackCat ransomware intrusion reports, and Mandiant M-Trends consistently show it as a Tier 1 privilege escalation technique — used within hours of initial access.

Key attacker logic: any authenticated domain user can request a service ticket for any SPN. The ticket is encrypted with the service account's NTLM hash. Offline cracking with Hashcat against common wordlists takes minutes for weak passwords and days for strong ones. Attackers therefore immediately Kerberoast all SPNs and crack opportunistically.

Defenders who enforce AES-only encryption (`msDS-SupportedEncryptionTypes`) and use long random passwords for service accounts dramatically reduce risk — but most environments have legacy service accounts that still accept RC4.

AS-REP Roasting targets accounts with `DONT_REQUIRE_PREAUTH` set — rarer, but produces crackable AS-REP hashes without needing any credentials at all.

---

## Data Requirements

| Requirement | Detail |
|---|---|
| **Primary data source** | Windows Security Event Log — Event ID 4769 (Kerberos Service Ticket Operations) via `sourcetype=WinEventLog:Security` |
| **Alternative data source** | Zeek kerberos.log via Corelight — `sourcetype=corelight_kerberos` (network visibility, captures domain-joined and non-joined attackers) |
| **Minimum retention** | 7 days — Kerberoasting attacks are typically completed in minutes, not spread over weeks |
| **Key fields (4769)** | `EventCode`, `Account_Name`, `Service_Name`, `Ticket_Encryption_Type`, `Client_Address`, `Keywords` |
| **Key fields (Zeek)** | `client`, `service`, `request_type`, `cipher`, `id.orig_h`, `id.resp_h` |
| **Environment assumptions** | DC audit policy enables "Audit Kerberos Service Ticket Operations" (Success). For Zeek path: Corelight sensor on DC-facing network segment. |

---

## Hunt Queries

### Stage 1 — Burst TGS-REQ with RC4 encryption (Windows Events)

Finds hosts requesting multiple RC4-encrypted service tickets in a short window. This is the primary Kerberoasting signal.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4769 earliest=-7d
| where Ticket_Encryption_Type="0x17"
| where NOT match(Service_Name, "(?i)\$$")
| where NOT match(Client_Address, "^::1$|^127\.")
| eval src_ip=replace(Client_Address, "::ffff:", "")
| bucket _time span=10m
| stats
    count AS ticket_count,
    dc(Service_Name) AS unique_spns,
    values(Service_Name) AS targeted_spns,
    values(Account_Name) AS requesting_accounts
    BY src_ip _time
| where ticket_count >= 5 AND unique_spns >= 3
| sort - ticket_count
```

> *`Ticket_Encryption_Type=0x17` is RC4-HMAC. Legitimate workstations request maybe 1–2 service tickets per hour (file server, print server). A host requesting 20 unique SPNs in 10 minutes is running a tool. Filter `Service_Name` ending in `$` to exclude machine account tickets.*

---

### Stage 2 — Kerberoasting via Zeek kerberos.log (network path)

Network-based detection catches attackers on jump boxes, attacker-controlled systems, or Linux hosts running Impacket — all of which don't generate Windows event logs on the attacker machine.

```spl
index=network sourcetype=corelight_kerberos earliest=-7d
| where request_type="TGS" AND cipher="rc4-hmac"
| where NOT match(service, "(?i)krbtgt|kadmin|host\.")
| bucket _time span=10m
| stats
    count AS request_count,
    dc(service) AS unique_services,
    values(service) AS targeted_services,
    values(client) AS requesting_clients
    BY id.orig_h _time
| where request_count >= 5 AND unique_services >= 3
| sort - request_count
```

> *Zeek `cipher=rc4-hmac` maps to etype 23. This catches Impacket GetUserSPNs.py from Linux attack boxes — invisible to Windows event logs but visible on the wire.*

---

### Stage 3 — AS-REP Roasting (Event ID 4768, no pre-auth)

Targets accounts with `DONT_REQUIRE_PREAUTH` set. Less common than Kerberoasting but requires zero credentials from the attacker.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4768 earliest=-7d
| where Pre_Authentication_Type="0x0"
| where NOT match(Client_Address, "^::1$|^127\.")
| eval src_ip=replace(Client_Address, "::ffff:", "")
| stats
    count AS request_count,
    values(Account_Name) AS targeted_accounts,
    dc(Account_Name) AS unique_accounts,
    earliest(_time) AS first_seen,
    latest(_time) AS last_seen
    BY src_ip
| where request_count >= 2
| sort - request_count
```

> *`Pre_Authentication_Type=0x0` means the AS-REQ was sent without a pre-authentication timestamp — the account has preauthentication disabled. Even a single such request from an unexpected IP warrants investigation.*

---

## Baseline Criteria

- **Typical volume (4769):** Domain-joined workstations generate 2–10 TGS requests per hour for normal file share, print, and application access. A DC itself generates many more.
- **RC4 baseline:** In modern environments enforcing AES, RC4 ticket requests should be near zero. Any environment that has not enforced `msDS-SupportedEncryptionTypes` will have legitimate RC4 traffic — filter known service accounts that are explicitly configured RC4-only.
- **Threshold guidance:** 5+ unique SPNs in 10 minutes from a single non-DC host is a reliable threshold. Reduce to 3 unique SPNs if environment enforces AES (making any RC4 request unusual).

---

## Analysis Guide

**High confidence indicators (escalate):**
- Burst of 10+ unique SPNs targeted in < 5 minutes from a single source IP, all with RC4 encryption
- AS-REP roasting requests (Event 4768, `Pre_Auth_Type=0x0`) from an IP that is not a known management system
- Kerberoasting from a Linux/non-Windows IP (visible in Zeek but not Windows events) — strong indicator of Impacket
- RC4 ticket requests immediately followed by LDAP queries for SPNs (Event ID 4662 with SPN filter) — enumeration before attack

**Requires investigation:**
- Moderate burst (5–10 SPNs) from a known IT admin workstation — could be legitimate SPN audit or pentest
- RC4 requests from a host that hosts legacy applications known to require RC4 — verify against application inventory
- Single AS-REP request for an account in a test OU — could be misconfigured dev account

**Likely benign (document and close):**
- Service account requesting tickets for its own dependent services (e.g., SQL service requesting tickets for linked servers) — verify the requesting account is a service account, not a user account
- Domain controller requesting TGS on behalf of S4U2Proxy delegation — will appear as high volume but with consistent, limited SPN set

---

## Pivot Queries

### Pivot 1 — LDAP enumeration preceding the Kerberoasting burst

Attackers typically enumerate SPNs via LDAP before requesting tickets. Find Event 4662 or network LDAP traffic from the same host in the 30 minutes before the burst.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4662 earliest=-7d
| where match(Properties, "servicePrincipalName")
| where Subject_Account_Name="<CANDIDATE_ACCOUNT>"
    OR Client_Address="<CANDIDATE_SRC_IP>"
| table _time Subject_Account_Name Client_Address Properties
| sort _time
```

---

### Pivot 2 — Lateral movement from the Kerberoasting host post-attack

If a service account password was cracked, watch for new authentication events using that account.

```spl
index=windows sourcetype=WinEventLog:Security EventCode IN (4624, 4625, 4768, 4769) earliest=-7d
| where Account_Name IN (<LIST_OF_TARGETED_SPNS>)
| where NOT match(Client_Address, "^<KNOWN_GOOD_IPS>")
| table _time EventCode Account_Name Client_Address Logon_Type
| sort _time
```

---

### Pivot 3 — Check if targeted service accounts have weak password indicators

Not a direct hunt query — use LDAP/AD tools to check `pwdLastSet` for targeted service accounts. Old password + SPN = high crack probability.

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4769 earliest=-7d
| where Ticket_Encryption_Type="0x17"
    AND src_ip="<CANDIDATE_SRC_IP>"
| stats values(Service_Name) AS targeted_spns BY src_ip
| mvexpand targeted_spns
| rename targeted_spns AS spn
```

> *Take the `targeted_spns` list and query Active Directory: `Get-ADServiceAccount -Filter {ServicePrincipalName -like "*"} | Where-Object {$_.SamAccountName -in $targeted_list} | Select SamAccountName, PasswordLastSet`. Accounts with `PasswordLastSet` > 1 year old are the highest crack-priority targets.*

---

## Escalation Criteria

- **Escalate immediately if:** Kerberoasting burst occurred AND subsequent authentication events show a targeted service account logging in from a new host or IP — password was likely cracked and used
- **Investigate further before escalating if:** Burst occurred from a known IT admin or security tool host — confirm whether a pentest or AD audit was scheduled
- **Document and close if:** Burst is attributed to a scheduled AD health check script or known SPN auditing tool, with change record verification

---

## Hunt Log

| Date | Analyst | Environment | Findings | Outcome |
|---|---|---|---|---|
| | | | | |

---

## References

- [CISA AA22-320A — Iranian Government-Sponsored APT Actors](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a)
- [Rubeus — Kerberoasting tool](https://github.com/GhostPack/Rubeus)
- [Impacket GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Detecting Kerberoasting — Sean Metcalf / Trimarc](https://www.trimarcsecurity.com/post/detecting-kerberoasting-activity)
- [Related detection writeup — Kerberoasting via RC4 Encryption Downgrade](../../detections/identity/ad/kerberoasting-rc4-downgrade.md)
