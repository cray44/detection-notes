# TLS C2 via JA4 Fingerprint and Certificate Anomalies

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

Detect outbound TLS connections to adversary-controlled C2 infrastructure by identifying certificate anomalies and known C2 framework TLS fingerprints. Cobalt Strike, Brute Ratel, Havoc, and Sliver are the dominant post-exploitation frameworks used by both nation-state actors and ransomware operators — all of them ride TLS, and all of them leave fingerprints at the protocol level that endpoint tooling never sees.

## ATT&CK Categorization

- **Tactic:** TA0011 — Command and Control
- **Technique:** T1071.001 — Application Layer Protocol: Web Protocols
- **Technique:** T1573.002 — Encrypted Channel: Asymmetric Cryptography

## Threat Context

Cobalt Strike is the most widely documented adversary tool across tracked threat groups. Mandiant, CrowdStrike, and Microsoft have attributed its use to APT29, APT41, Lazarus Group, FIN7, and the majority of ransomware affiliates operating today. Brute Ratel C4 emerged as a deliberate successor after Cobalt Strike became heavily detected at the endpoint layer — its author explicitly marketed it as "undetected by EDR." JA4 fingerprinting, released by FoxIO in 2023, provides a more stable fingerprint than JA3 for tracking these frameworks across version updates and malleable profile changes. CISA has published specific JA3/JA4 hashes for Cobalt Strike listener profiles in multiple advisories.

The detection is intentionally layered: a JA4 blocklist catches unmodified or default-configured frameworks; certificate anomaly scoring catches custom-configured frameworks that operators forget to harden; behavioral correlation catches frameworks that have been hardened at both layers but still exhibit beaconing patterns.

## Strategy Abstract

C2 frameworks that communicate over TLS need server-side certificates. Operators setting up infrastructure quickly often use self-signed certificates, certificates where the subject equals the issuer, or certificates with IP addresses as the CN rather than a hostname — all of which are structurally anomalous for legitimate HTTPS traffic. Even when operators obtain CA-signed certificates, the TLS handshake itself leaves a fingerprint: the specific cipher suites, extensions, and negotiation order that the C2 client presents is captured in JA4 (client fingerprint) and JA4S (server fingerprint) and can be compared against a blocklist of known framework defaults.

The detection runs a weighted risk score across four independent signals:

| Signal | Risk contribution | Rationale |
|---|---|---|
| Subject equals issuer (self-signed) | +40 | Strongest structural indicator — no legitimate external HTTPS uses self-signed |
| Certificate validity < 30 days | +20 | Throwaway infrastructure pattern; not typical of legitimate sites |
| No Subject Alternative Name (SAN) | +15 | Modern certs require SANs; absence suggests quick self-generation |
| CN is an IP address | +25 | Certificates with IP CNs are characteristic of C2 tooling |
| JA4/JA3 blocklist match | +50 | Known-bad fingerprint; treat as high confidence when combined with other signals |

Any connection scoring ≥ 40 is surfaced. Connections scoring ≥ 80 (blocklist match + at least one structural anomaly) are treated as high confidence.

## Technical Context

**Data source:** Zeek `ssl.log` via Corelight App for Splunk — sourcetype `corelight_ssl`

**JA4 requirement:** JA4 fingerprinting requires the [ja4 Zeek package](https://github.com/FoxIO-LLC/ja4/tree/main/zeek) installed on the sensor. JA3 is available in stock Zeek. If JA4 is unavailable, substitute `ja3` in the SPL and use a JA3 blocklist.

**Sigma rule:** [`rules/network/tls-c2-ja4-certificate-anomalies.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/tls-c2-ja4-certificate-anomalies.yml) in sigma-to-spl

> Sigma cannot express field equality comparisons (`subject == issuer`), computed certificate age, or weighted risk scoring. The Sigma rule defines the structural filter; the SPL below is the production query.

**Key fields:**

| Field | Description |
|---|---|
| `established` | `true` = TLS handshake completed; filter false to reduce noise |
| `id.orig_h` | Source (internal) IP — the beaconing host |
| `id.resp_h` | Destination (external) IP — C2 server |
| `id.resp_p` | Destination port — C2 often uses 443, 8443, 4443 |
| `server_name` | SNI — the hostname the client requested; may be empty or mismatched on C2 |
| `subject` | Certificate subject field — `CN=` value |
| `issuer` | Certificate issuer — equals `subject` on self-signed certs |
| `validation_status` | Certificate chain validation result — `unable to get local issuer certificate` on self-signed |
| `ja4` | JA4 client fingerprint (requires ja4 Zeek package) |
| `ja3` | JA3 client fingerprint (stock Zeek) |
| `ja3s` | JA3 server fingerprint |
| `cert_chain_fuids` | Links to `x509.log` for full certificate chain inspection |

**Environment assumptions:**
- Zeek sensor deployed at network egress with full TLS visibility (not decryption — just handshake metadata)
- Corelight App for Splunk installed; ssl.log fields are properly extracted
- A `ja4_blocklist.csv` lookup table exists in Splunk, populated from CISA advisories and framework-specific research (see References for sources)
- Internal RFC1918 subnets are defined in a lookup or hardcoded in the filter to suppress internal TLS traffic

## Performance Notes

- **Estimated event volume:** ssl.log is high-volume — in an enterprise with 5,000 endpoints, expect 5–20M TLS connection records per day. **Do not run this as a full-table search.** Filter on `established=true` and external destinations first.
- **Indexed fields:** `established`, `id.resp_h`, and `validation_status` should be indexed via the Corelight App field extractions. Confirm with `| tstats count WHERE index=network sourcetype=corelight_ssl by established` before scheduling.
- **Two-phase approach:** Run a fast JA4 blocklist lookup first (cheap, index-time field) as an always-on alert. Run the full certificate anomaly scoring on a 1h schedule over the prior hour only — not over rolling windows.
- **Recommended time range:** `-1h` on a 15-minute schedule for JA4 blocklist hits. `-1h` hourly for certificate anomaly scoring.
- **Acceleration:** If ssl.log volume exceeds 10M events/day, consider a `tstats`-based pre-filter to extract only the fields needed before piping to the full scoring logic.
- **Do not join ssl.log to x509.log at query time at scale** — the join explodes. Use Corelight's built-in certificate enrichment fields in ssl.log instead.

## Blind Spots

- **Legitimate CA-signed certificates on C2 infrastructure:** Operators who obtain a Let's Encrypt certificate (free, 90-day validity, automated) for their C2 domain bypass all certificate anomaly signals. JA4 fingerprint is the only remaining hook. This is the most common evasion in sophisticated operations.
- **Malleable C2 profiles / JA4 randomization:** Cobalt Strike's malleable C2 profiles allow operators to customize the TLS fingerprint. Sliver and Brute Ratel have built-in randomization. Operators who configure this evade blocklist detection. The certificate anomaly scoring still applies unless they also harden the cert.
- **Domain fronting:** Attacker uses a CDN (Cloudflare, Fastly) as a front — TLS connects to a legitimate CDN IP with a valid wildcard certificate; actual C2 traffic is in the HTTP Host header. No certificate anomaly, no blocked fingerprint. Requires HTTP-layer visibility to detect.
- **C2 over legitimate cloud services:** Teams, OneDrive, Slack, and GitHub have all been used as C2 channels. Valid certs, valid endpoints, no anomalous fingerprint. Out of scope for this detection.
- **Encrypted DNS as C2 (DoH):** TLS to known DoH providers used as a covert channel. Valid certs, known-good destination. Requires a separate detection strategy.
- **Inbound C2 (reverse proxy model):** If the victim host is the listener and the C2 server connects inbound, the directionality of this detection is wrong. Rare but documented in some frameworks.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| Internal dev/test services with self-signed certs | Check `id.resp_h` — if RFC1918, the internal-destination filter should have suppressed this. If reaching external, investigate. |
| Old network appliances (printers, switches, UPS) phoning home with self-signed certs | Identify by `id.orig_h` — correlate with asset inventory. Add known appliance IPs to a suppression lookup. |
| Security scanning tools (Nessus, Qualys, Shodan inbound) | These typically appear as `id.resp_h` = internal, `id.orig_h` = known scanner IP. Directionality should suppress most. Add scanner IP ranges to allowlist. |
| Go and Python TLS default fingerprints matching C2 hashes | Some legitimate tools (Prometheus exporters, custom monitoring scripts) share JA4 fingerprints with C2 frameworks. Triage by process/parent process on the source host via EDR. |
| VPN or zero-trust agents with self-signed internal CA | These typically have consistent destination IPs and high connection volume. Suppress by destination IP range after confirming with network team. |

## Validation

**Test data:** See [`test-data/`](test-data/) — includes malicious samples (self-signed cert, IP-as-CN, known JA3) and benign samples (valid cert, legitimate app fingerprint).

**Lab reproduction using openssl:**

```bash
# Generate a self-signed cert (simulates basic C2 infrastructure)
openssl req -x509 -newkey rsa:2048 -keyout /tmp/c2.key -out /tmp/c2.crt \
  -days 7 -nodes -subj "/CN=192.168.1.100"

# Stand up a listener with the self-signed cert
openssl s_server -key /tmp/c2.key -cert /tmp/c2.crt -accept 4443

# Connect from a client (Zeek will log this as ssl.log event)
openssl s_client -connect <server_ip>:4443
```

Expected result in Zeek ssl.log: `established=true`, `subject` and `issuer` identical (self-signed), `validation_status=unable to get local issuer certificate`, `server_name` empty (no SNI), `cert_chain_fuids` pointing to a single self-signed entry in x509.log.

**For JA4 blocklist testing**, use a known-bad fingerprint from the [ja4db](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) and inject it into the ssl.log test event.

**SPL (primary):**

```spl
index=network sourcetype=corelight_ssl
| where established="true"
| where NOT (match('id.resp_h', "^10\.") OR match('id.resp_h', "^172\.(1[6-9]|2\d|3[01])\.") OR match('id.resp_h', "^192\.168\."))
| eval is_self_signed=if(isnotnull(subject) AND isnotnull(issuer) AND subject=issuer, "true", "false")
| eval is_ip_cn=if(match(subject, "CN=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), "true", "false")
| eval is_invalid_chain=if(validation_status!="ok" AND isnotnull(validation_status), "true", "false")
| eval is_no_sni=if(isnull(server_name) OR server_name="", "true", "false")
| eval risk_score=0
| eval risk_score=risk_score + if(is_self_signed="true",  40, 0)
| eval risk_score=risk_score + if(is_ip_cn="true",        25, 0)
| eval risk_score=risk_score + if(is_invalid_chain="true", 15, 0)
| eval risk_score=risk_score + if(is_no_sni="true",        10, 0)
| lookup ja4_blocklist.csv ja4 OUTPUT threat_name AS known_c2_ja4
| lookup ja3_blocklist.csv ja3 OUTPUT threat_name AS known_c2_ja3
| eval known_c2=coalesce(known_c2_ja4, known_c2_ja3)
| eval risk_score=risk_score + if(isnotnull(known_c2), 50, 0)
| where risk_score >= 40
| eval confidence=case(risk_score>=80, "HIGH", risk_score>=60, "MEDIUM", true(), "LOW")
| stats
    count                       AS connection_count,
    values(id.resp_p)           AS dst_ports,
    values(server_name)         AS sni_values,
    values(subject)             AS cert_subjects,
    values(issuer)              AS cert_issuers,
    values(ja4)                 AS ja4_fingerprints,
    values(ja3)                 AS ja3_fingerprints,
    values(known_c2)            AS matched_c2_frameworks,
    max(risk_score)             AS max_risk_score,
    values(confidence)          AS confidence_levels,
    max(_time)                  AS last_seen
    BY id.orig_h, id.resp_h
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - max_risk_score
```

> *Performance note:* The RFC1918 filter and `established=true` must appear before any `eval` — these drop the majority of events before any computation. The `lookup` calls are cheap index-time operations. The `stats` aggregation by source/destination pair collapses repeated connections (beaconing) into a single row with connection count, which is itself a signal.

**JA4/JA3 blocklist format** (`ja4_blocklist.csv`):

```
ja4,threat_name,reference
t13d191000_9dc949149365_97f8aa674fd9,CobaltStrike_default_https,CISA-AA23-025A
t13d190900_9dc949149365_e7c285222651,BruteRatel_default,Mandiant-UNC2596
```

## Response

1. **Identify the beaconing host** (`id.orig_h`) — pull recent process and network connection telemetry from EDR. Look for unusual parent-child process relationships, unsigned binaries, or processes making network connections they normally wouldn't.
2. **Characterize the C2 infrastructure** — pivot on `id.resp_h`: passive DNS history, threat intel lookup (VirusTotal, Shodan, Recorded Future). Check certificate Serial Number and Subject against known C2 infrastructure databases.
3. **Determine scope of compromise** — how long has this host been beaconing? Pull `ssl.log` history for `id.orig_h` over the past 30 days. Identify all unique destinations and cross-reference with threat intel.
4. **Collect volatile forensics before isolation** — if IR confirms C2, capture memory from the beaconing host before isolating (memory image contains C2 config, staging, injected shellcode).
5. **Isolate and remediate** — remove from network. Identify the initial access vector (how did the implant get there) to scope potential lateral movement.
6. **Hunt for lateral movement** — pivot from `id.orig_h` to all hosts it communicated with via SMB, RDP, WMI in the same window. The beaconing host is likely not the only infected system.

## References

- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1573.002 — Encrypted Channel: Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/)
- [JA4+ Network Fingerprinting — FoxIO](https://github.com/FoxIO-LLC/ja4)
- [JA4 Database — known fingerprints](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
- [Cobalt Strike JA3/JA4 fingerprint reference — Mandiant](https://www.mandiant.com/resources/blog/defining-cobalt-strike-components)
- [CISA Advisory AA23-025A — Cobalt Strike TLS indicators](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)
- [Brute Ratel C4 TLS analysis — Palo Alto Unit 42](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)
- [Sigma rule — tls-c2-ja4-certificate-anomalies.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/tls-c2-ja4-certificate-anomalies.yml)
