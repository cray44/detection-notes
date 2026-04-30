# SMB Lateral Movement via Admin Share Access

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

Detect adversary lateral movement via SMB by identifying connections to administrative shares (C$, ADMIN$) from internal hosts, particularly when a single source connects to multiple unique targets in a short window. PsExec, Impacket smbexec, and Cobalt Strike's `jump psexec` all write payloads to ADMIN$ or execute over C$ to achieve code execution on remote hosts — and all of it is visible in Zeek SMB metadata without EDR on the target.

## ATT&CK Categorization

- **Tactic:** TA0008 — Lateral Movement
- **Technique:** T1021.002 — Remote Services: SMB/Windows Admin Shares

## Threat Context

The leaked Conti ransomware playbook (2021) explicitly instructs affiliates to use PsExec across admin shares for lateral movement after initial credential acquisition. BlackCat/ALPHV and LockBit 3.0 affiliates have used the same technique, documented in CISA advisories and DFIR Report cases. In practice, it is the most common lateral movement technique seen in ransomware intrusions because it requires only local admin credentials on the target — no additional tooling or exploits.

Cobalt Strike's built-in `jump psexec` command drops a randomly named service binary to ADMIN$, creates a temporary Windows service to execute it, then deletes the binary — the full lifecycle is captured in Zeek smb_files.log if enrichment is available. Impacket's `smbexec.py` uses C$ to stage execution. Both leave identical SMB share mapping events.

The network-layer detection perspective is the differentiator here: Zeek logs admin share access regardless of whether the target has EDR, whether EDR has been disabled, or whether the attacker is using a signed Microsoft binary. The SMB handshake and share mapping negotiation are logged even for encrypted SMB3 connections.

## Strategy Abstract

Zeek `smb_mapping.log` records every SMB tree connect — the moment a client mounts a share. When a host maps `C$` or `ADMIN$` on a remote internal system, that event is logged with source IP, destination IP, and the share path. Legitimate admin share access does happen (IT admins, backup agents, SCCM), but it is identifiable by source host and occurs at low frequency with predictable destinations.

The detection is tiered by lateral spread:

| Signal | Risk contribution | Rationale |
|---|---|---|
| Any admin share (C$, ADMIN$) mapping | +40 | Base indicator; unusual for non-admin-class hosts |
| 2–4 unique destination hosts | +20 | Targeted lateral movement; within IT admin norm but elevated |
| 5–9 unique destination hosts | +40 | Aggressive lateral movement; outside typical admin scope |
| ≥ 10 unique destination hosts | +60 | Worm-like spread; no legitimate operational justification |

A single admin share mapping scores 40 (surfaces for review). Ten unique targets in one hour scores 100 — near-zero false positive outside of a major incident response window.

Zeek `smb_files.log` enrichment (response step 2) adds a second layer: if the source wrote an `.exe`, `.dll`, or `.bat` file to any admin share in the same window, that is a high-confidence PsExec or service-drop indicator regardless of spread count.

## Technical Context

**Data sources:**
- Zeek `smb_mapping.log` via Corelight App for Splunk — sourcetype `corelight_smb_mapping` (primary)
- Zeek `smb_files.log` via Corelight App for Splunk — sourcetype `corelight_smb_files` (enrichment)

**Sigma rule:** [`rules/network/smb-lateral-movement-admin-shares.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/smb-lateral-movement-admin-shares.yml) in sigma-to-spl

> Sigma expresses the admin share path filter and internal destination requirement. The lateral spread scoring (unique target count thresholds) and time-windowed aggregation cannot be expressed in base Sigma and are applied in the SPL conversion.

**Key fields:**

| Field | Description |
|---|---|
| `id.orig_h` | Source IP — the host initiating the SMB connection (the potential lateral mover) |
| `id.resp_h` | Destination IP — the target host |
| `id.resp_p` | Destination port — 445 for SMB; 139 for legacy NetBIOS over SMB |
| `path` | UNC path of the mapped share — `\\target\C$`, `\\target\ADMIN$`; Corelight normalizes to the share name in some versions |
| `share_type` | `DISK`, `PIPE`, or `PRINT` — admin shares are DISK; IPC$ is PIPE |
| `uid` | Connection UID — links to smb_files.log and conn.log for the same SMB session |

**smb_files.log enrichment fields:**

| Field | Description |
|---|---|
| `action` | `SMB_FILES_CREATE`, `SMB_FILES_WRITE`, `SMB_FILES_OPEN`, `SMB_FILES_DELETE` |
| `name` | Filename — `.exe`, `.dll`, `.bat`, `.ps1` writes to admin shares are high signal |
| `path` | Directory path within the share |
| `size` | File size in bytes — PsExec service binaries are typically 100–500KB |

**Environment assumptions:**
- Zeek sensor at internal network tap or span port with visibility into east-west traffic, not just north-south egress
- Corelight SMB analysis package enabled; smb_mapping.log and smb_files.log are both indexed
- An asset inventory lookup is available to identify host class (workstation vs. server vs. DC)
- IT admin source IPs are documented in a `trusted_admin_hosts.csv` lookup for suppression

## Performance Notes

- **Estimated event volume:** smb_mapping.log is moderate volume — in a 5,000-endpoint environment, expect 50K–500K events/day. Most are file server and DFS traffic to non-admin shares.
- **Indexed fields:** `id.resp_p`, `share_type` should be indexed. `path` is typically extracted. Confirm with `| tstats count WHERE index=network sourcetype=corelight_smb_mapping by share_type`.
- **Admin share filter cost:** The `path` filter is an extracted-field match, not an indexed-field filter. Pre-filter on `id.resp_p=445` (indexed) first to reduce event volume before the path regex.
- **Recommended time range:** `-1h` on a 15-minute schedule is appropriate for the spread-based alert. For a single admin share mapping alert (score ≥ 40), real-time is viable given the low false positive rate.
- **Acceleration:** If east-west SMB volume is very high, use `tstats` to pre-aggregate mapping counts per (src, dst) pair before pulling raw events for path filtering.
- **smb_files enrichment:** Run as a separate investigation query, not as part of the scheduled alert — joining at query time across two high-volume SMB logs at scale is expensive.

## Blind Spots

- **SMB3 payload encryption:** SMB3 encrypts file content end-to-end, so Zeek cannot see the actual content of files written to admin shares. The `smb_files.log` action and filename metadata are still logged (from the unencrypted SMB3 metadata headers), but file content inspection is not available without decryption.
- **Non-standard admin share names:** Attackers who create custom hidden shares (e.g., `\\target\xfer$`) for staging bypass the path filter entirely. Only C$ and ADMIN$ are detected.
- **Relay attacks (NTLM relay / SMB relay):** An attacker who relays captured NTLM credentials to authenticate to a target's SMB service will appear as the victim host initiating the connection, not the attacker's real IP. The source IP in Zeek logs is the relayed session's apparent origin.
- **Living-off-the-land via legitimate management traffic:** In environments where SCCM, Intune, or similar management platforms heavily use admin shares, the signal-to-noise ratio degrades. The spread scoring partially mitigates this, but single-target admin access from a management server is a structural blind spot.
- **Sensor placement — east-west gap:** If the Zeek sensor is placed only at internet egress (north-south), lateral movement on internal VLANs without traversing the egress point is invisible. Full east-west coverage requires sensors at distribution switches or a Corelight fleet deployment.
- **Kerberos delegation abuse:** If an attacker uses Kerberos constrained or unconstrained delegation to impersonate a privileged user, the SMB mapping event appears under the delegated identity — the source IP is the intermediate host, not the attacker's actual workstation.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| IT admin manually accessing C$ on a server for troubleshooting | Check `id.orig_h` against `trusted_admin_hosts.csv`. Single-target, low frequency, business hours. Confirm with the admin directly for out-of-hours events. |
| Backup agents (Veeam, Veritas, Commvault) using VSS via admin shares | These connect to many targets but at predictable times (nightly backup window). Suppress by source IP (backup server) after confirming with the backup team. |
| SCCM/Tanium/Ansible deploying software via admin shares | High unique-target count during patch cycles. Suppress by source IP (management server) with a time-bounded exclusion for the deployment window. |
| Vulnerability scanners (Nessus, Qualys) enumerating shares | Typically from a known scanner IP range, rapid connections to many hosts. Add scanner IPs to suppression lookup. |
| Incident response tooling (CrowdStrike RTR, remote shell via admin share) | Appears during active IR — the spread may be deliberate and authorized. Confirm IR engagement context before escalating. |

## Validation

**Test data:** See [`test-data/`](test-data/) — includes malicious samples (PsExec-style multi-target admin share access with executable write) and benign samples (file server access to non-admin shares, IPC$ pipe connection).

**Lab reproduction:**

```bash
# PsExec lateral movement (Windows lab) — generates smb_mapping + smb_files events
# Run from an internal host; Zeek must see east-west traffic
PsExec.exe \\10.1.2.100 -s cmd.exe

# Impacket psexec.py (Linux/Mac) — same Zeek footprint
python3 impacket/examples/psexec.py CONTOSO/jsmith:Password123@10.1.2.100
```

Expected in Zeek smb_mapping.log: `path` contains `ADMIN$`, `id.orig_h` = attacker host, `id.resp_h` = target.
Expected in Zeek smb_files.log: `action=SMB_FILES_CREATE`, `name` matches a service binary name, `path` = `\` (root of ADMIN$).

**SPL (primary — smb_mapping lateral spread detection):**

```spl
index=network sourcetype=corelight_smb_mapping earliest=-1h latest=now
| where id.resp_p=445 OR id.resp_p=139
| where match('id.orig_h', "^10\.") OR match('id.orig_h', "^172\.(1[6-9]|2\d|3[01])\.") OR match('id.orig_h', "^192\.168\.")
| where match('id.resp_h', "^10\.") OR match('id.resp_h', "^172\.(1[6-9]|2\d|3[01])\.") OR match('id.resp_h', "^192\.168\.")
| where id.orig_h != id.resp_h
| eval share = upper(mvindex(split(replace(path, "\\\\[^\\\\]+\\\\", ""), "\\"), 0))
| where share IN ("C$", "ADMIN$")
| lookup trusted_admin_hosts.csv ip AS id.orig_h OUTPUT role AS host_role
| where isnull(host_role) OR host_role != "admin"
| stats
    count              AS mapping_count,
    dc(id.resp_h)      AS unique_targets,
    values(id.resp_h)  AS target_hosts,
    values(share)      AS shares_accessed,
    min(_time)         AS first_seen,
    max(_time)         AS last_seen
    BY id.orig_h
| eval risk_score = 40
| eval risk_score = risk_score + case(
    unique_targets >= 10, 60,
    unique_targets >= 5,  40,
    unique_targets >= 2,  20,
    true(), 0)
| eval lateral_spread = case(
    unique_targets >= 10, "HIGH",
    unique_targets >= 5,  "MEDIUM",
    true(), "LOW")
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen  = strftime(last_seen,  "%Y-%m-%d %H:%M:%S")
| sort - risk_score
| table id.orig_h, unique_targets, target_hosts, shares_accessed, mapping_count, risk_score, lateral_spread, first_seen, last_seen
```

> *Performance note:* Filter on `id.resp_p=445` (indexed) before the path extraction — this eliminates non-SMB traffic before the more expensive `eval share` and path parsing. The `trusted_admin_hosts.csv` lookup suppresses known management hosts before aggregation, which is cheaper than suppressing after `stats`. The `share` extraction using `split`+`mvindex` handles both normalized share names (`C$`) and full UNC paths (`\\host\C$`).

**SPL (enrichment — executable writes to admin shares, run as follow-up):**

```spl
index=network sourcetype=corelight_smb_files earliest=-1h latest=now
| where action IN ("SMB_FILES_CREATE", "SMB_FILES_WRITE")
| where match(lower(name), "\.(exe|dll|bat|ps1|vbs|cmd)$")
| where match('id.orig_h', "^10\.") OR match('id.orig_h', "^172\.(1[6-9]|2\d|3[01])\.") OR match('id.orig_h', "^192\.168\.")
| where id.orig_h != id.resp_h
| table _time, id.orig_h, id.resp_h, action, path, name, size
| sort - _time
```

## Response

1. **Identify the source host** (`id.orig_h`) — pull EDR telemetry for the same window. Look for net use, PsExec.exe, impacket tooling, PowerShell Invoke-Command, or service creation events (Windows Event 7045) on the source. Also check parent process chain.
2. **Check smb_files.log for executable writes** — run the enrichment SPL above. A `.exe` or service binary written to ADMIN$ in the same window confirms code execution, not just share enumeration.
3. **Pivot to all target hosts** — for each `id.resp_h` in `target_hosts`, check Event ID 7045 (new service installed) and 4624 (logon type 3) around the same timestamp. Lateral movement leaves logon artifacts even when EDR is absent.
4. **Determine initial access point** — the source host is likely not patient zero. Pull its conn.log history for the prior 24–48 hours. Look for inbound SMB from another internal host, C2 beaconing, or phishing-related process execution.
5. **Scope the blast radius** — map all (src, dst) pairs found in the smb_mapping alert window. This is the adversary's lateral movement graph for that hour. Every target is a potential second-stage host.
6. **Isolate in dependency order** — isolate targets before the source; isolating the source first allows the adversary to pivot further from already-compromised targets.

## References

- [MITRE ATT&CK T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [CISA Advisory AA23-263A — Cobalt Strike and admin share lateral movement](https://www.cisa.gov/sites/default/files/2023-09/aa23-263a-cobalt-strike-cisa_tlp-white.pdf)
- [Conti ransomware playbook analysis — DFIR Report](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [BlackCat/ALPHV — SMB lateral movement TTPs (CISA AA23-061A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a)
- [Impacket psexec.py source — Fortra/SecureAuthCorp](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
- [Sigma rule — smb-lateral-movement-admin-shares.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/smb-lateral-movement-admin-shares.yml)
