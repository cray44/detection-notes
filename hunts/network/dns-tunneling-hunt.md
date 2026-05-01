# Hunt: DNS Tunneling and C2 over DNS

## Hypothesis

> "We believe a compromised host is exfiltrating data or receiving C2 commands via DNS because DNS is rarely inspected, passes through most egress controls, and is used by tools like iodine, dnscat2, and SUNBURST as a reliable covert channel. This would manifest in Zeek dns.log as a host making large volumes of queries to a single domain with high-entropy, long subdomains — a pattern that is statistically distinct from legitimate DNS resolution behavior."

**Structured form:**
- **Actor behavior:** Encoding data into DNS query labels (subdomains) and receiving responses in TXT, CNAME, or A records — effectively using the DNS protocol as a bidirectional data transport
- **Observable signal:** High query volume to a single parent domain, long subdomain strings (> 40 chars), high entropy in subdomain labels, and anomalously large TXT/CNAME response payloads
- **Data source:** Zeek dns.log via Corelight (`sourcetype=corelight_dns`)
- **Confidence:** Medium-High — entropy and length signals are strong for tool-based tunneling; manual low-and-slow exfil is harder to catch statistically

---

## ATT&CK Mapping

- **Tactic:** TA0011 — Command and Control, TA0010 — Exfiltration
- **Technique:** T1071.004 — Application Layer Protocol: DNS
- **Related:** T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

---

## Threat Context

DNS tunneling is used across the threat spectrum — from APT34/OilRig (documented in Unit 42 reporting, CISA AA20-258A) to commodity post-exploitation frameworks. SUNBURST (SolarWinds backdoor) used DNS as its initial C2 channel before pivoting to HTTPS — traffic that went undetected for months in environments that lacked DNS visibility.

Two distinct threat models:
1. **Tool-based tunneling (iodine, dnscat2, DNScat):** High-volume, high-entropy subdomains — noisy but fast. Relatively easy to detect statistically.
2. **Slow-drip exfiltration (custom malware, SUNBURST-style):** Low volume, periodic queries, may use dictionary words to reduce entropy. Harder to score — requires longer baseline windows.

This playbook primarily targets the tool-based model. A companion detection writeup covers the statistical approach for individual rules; this hunt goes broader across all internal hosts.

---

## Data Requirements

| Requirement | Detail |
|---|---|
| **Data source** | Zeek dns.log via Corelight — `sourcetype=corelight_dns` |
| **Minimum retention** | 7 days minimum; 30 days preferred for slow-drip detection |
| **Key fields** | `id.orig_h` (querying host), `query` (full FQDN), `qtype_name` (record type), `answers`, `AA`, `TTL`, `_time` |
| **Environment assumptions** | Internal hosts query a known DNS resolver; Zeek dns.log captures all queries, not just NXDOMAIN. Corelight with DNS enrichment preferred. |

---

## Hunt Queries

### Stage 1 — High query volume to a single parent domain

Finds internal hosts making unusually high query counts to a single registered domain. Legitimate CDNs and update servers generate volume, but to many different subdomains — tunneling concentrates volume on one parent.

```spl
index=network sourcetype=corelight_dns earliest=-7d
| where NOT cidrmatch("10.0.0.0/8", id.resp_h)
    AND NOT cidrmatch("172.16.0.0/12", id.resp_h)
    AND NOT cidrmatch("192.168.0.0/16", id.resp_h)
| rex field=query "^(?:[^.]+\.)*(?P<registered_domain>[^.]+\.[^.]+)$"
| where isnotnull(registered_domain) AND len(registered_domain) > 3
| stats
    count AS query_count,
    dc(query) AS unique_subdomains,
    avg(len(query)) AS avg_query_len,
    max(len(query)) AS max_query_len,
    values(qtype_name) AS record_types
    BY id.orig_h registered_domain
| where query_count >= 100 AND unique_subdomains >= 20
| eval subdomain_ratio=round(unique_subdomains / query_count, 3)
| sort - query_count
```

> *High `unique_subdomains` with high `query_count` to a single `registered_domain` is the key signal. Legitimate services repeat subdomains (CDN, update servers); tunneling generates a unique label per encoded data chunk. `avg_query_len > 50` is additionally suspicious.*

---

### Stage 2 — Entropy scoring on query labels

For candidate domains from Stage 1, compute Shannon entropy on the subdomain portion of each query. High entropy indicates encoded/encrypted content.

```spl
index=network sourcetype=corelight_dns earliest=-7d
| where match(query, "(?i)<CANDIDATE_DOMAIN>")
| rex field=query "^(?P<subdomain>(?:[^.]+\.)+)(?:[^.]+\.[^.]+)$"
| eval subdomain=rtrim(subdomain, ".")
| eval label_len=len(subdomain)
| eval char_counts=mvzip(
    split("abcdefghijklmnopqrstuvwxyz0123456789-", ""),
    split("abcdefghijklmnopqrstuvwxyz0123456789-", "")
  )
| where label_len > 20
| stats
    count AS query_count,
    avg(label_len) AS avg_label_len,
    max(label_len) AS max_label_len,
    values(qtype_name) AS record_types,
    values(substr(subdomain, 1, 60)) AS sample_labels
    BY id.orig_h query
| eval high_entropy_indicator=if(avg_label_len > 40, "YES", "check")
| sort - avg_label_len
```

> *Full Shannon entropy computation requires `eval` tricks or external lookup — in practice, `avg_label_len > 40` is a reliable proxy for high entropy. Random base32/base64 encoded strings average 45–55 chars. Human-readable subdomains average 8–15. Sample labels in output allow manual eyeball check.*

---

### Stage 3 — Large TXT/NULL record responses

DNS tunneling tools use TXT records for downstream data (C2 responses). Unusually large TXT responses to internal hosts are a strong signal.

```spl
index=network sourcetype=corelight_dns earliest=-7d
| where qtype_name IN ("TXT", "NULL", "CNAME") AND rcode_name="NOERROR"
| where NOT cidrmatch("10.0.0.0/8", id.resp_h)
| eval answer_len=len(mvjoin(answers, ""))
| where answer_len > 200
| stats
    count AS response_count,
    avg(answer_len) AS avg_answer_len,
    max(answer_len) AS max_answer_len,
    values(query) AS queries,
    dc(query) AS unique_queries
    BY id.orig_h
| where response_count >= 10
| sort - avg_answer_len
```

> *Legitimate TXT records (SPF, DKIM, DMARC) are large but queried infrequently and from mail servers. An internal workstation making 50 TXT queries with 500-byte responses is not doing SPF lookups.*

---

## Baseline Criteria

- **Typical volume:** In a 500-host environment, expect 5–15 hosts in Stage 1 results before filtering known-good. Most will be Windows Update, telemetry, or DNS-based load balancing.
- **Known-good patterns:** Microsoft update domains (`*.windowsupdate.com`, `*.microsoft.com`), cloud telemetry (`*.digicert.com`, `*.cloudflare.com`), and vendor management agents generate high query volume — build a `dns_allowlist.csv` lookup.
- **Label length baseline:** Pull `avg(len(query))` across all queries grouped by `registered_domain` — legitimate domains cluster at 20–30 chars. Anything consistently > 45 is worth examining.

---

## Analysis Guide

**High confidence indicators (escalate):**
- Internal workstation (not a DNS server) making > 500 unique subdomain queries to a domain registered < 90 days ago
- TXT record queries from a workstation at > 10/minute sustained
- Query labels that are clearly base32/base64 encoded (regex: `^[a-z2-7]{20,}$` for base32, `^[a-za-z0-9+/]{20,}={0,2}$` for base64)
- Domain with `NS` records pointing to a VPS/cheap hosting provider combined with high entropy queries

**Requires investigation:**
- High query count to a domain that resolves to a CDN or hosting provider — check whether the domain is legitimately used by any software installed on that host
- Long subdomain queries during off-hours from a single host — could be a misbehaving app or legitimate DNS-SD
- `*.onion.pet`, `*.tor2web`, or similar onion proxy domains in queries

**Likely benign (document and close):**
- DNS-SD (service discovery) queries with `_tcp.local` or `_udp.local` suffix
- Hosts running Kubernetes or Docker with internal service DNS generating `*.svc.cluster.local` queries
- Corporate MDM or endpoint management agents with known high-volume DNS patterns

---

## Pivot Queries

### Pivot 1 — Timeline of queries to the suspicious domain

Understand the query pattern over time — periodic (automated C2) vs. burst (active exfil session).

```spl
index=network sourcetype=corelight_dns earliest=-7d
| where match(query, "(?i)<CANDIDATE_DOMAIN>")
    AND id.orig_h="<CANDIDATE_SRC_IP>"
| timechart span=1h count AS queries_per_hour
```

---

### Pivot 2 — WHOIS / registration age context

Check whether the domain is newly registered — a strong indicator of attacker infrastructure.

```spl
index=network sourcetype=corelight_dns earliest=-7d
| where match(query, "(?i)<CANDIDATE_DOMAIN>")
| rex field=query "^(?:[^.]+\.)*(?P<registered_domain>[^.]+\.[^.]+)$"
| stats count BY registered_domain
| eval lookup_target=registered_domain
```

> *Feed `registered_domain` into a threat intel lookup (`| lookup domainthreatintel domain AS registered_domain`) or manually query a WHOIS service.*

---

### Pivot 3 — Network connections to the same destination after DNS resolution

If the DNS tunneling host also established TCP/UDP connections to the same destination, the exfil may be multi-channel.

```spl
index=network sourcetype=corelight_conn earliest=-7d
| where id.orig_h="<CANDIDATE_SRC_IP>"
| lookup dns_to_ip domain AS query OUTPUT ip
| where id.resp_h=ip
| stats
    count AS conn_count,
    values(id.resp_p) AS ports,
    sum(orig_bytes) AS total_bytes_out,
    sum(resp_bytes) AS total_bytes_in
    BY id.orig_h id.resp_h
```

---

## Escalation Criteria

- **Escalate immediately if:** Query labels match base32/base64 encoding patterns AND the target domain was registered within the last 180 days AND the querying host has no business reason to contact that domain
- **Investigate further before escalating if:** High entropy queries found but domain resolves to a known hosting provider — check installed software on that host for DNS-based update checks
- **Document and close if:** Domain is in the allowlist or identified as a vendor service, or if queries stop before the hunt window and host has since been reimaged

---

## Hunt Log

| Date | Analyst | Environment | Findings | Outcome |
|---|---|---|---|---|
| | | | | |

---

## References

- [CISA AA20-258A — APT34 / OilRig DNS tunneling](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-258a)
- [Unit 42 — OilRig DNS tunneling analysis](https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/)
- [Detecting DNS Tunneling — Cloudflare research](https://blog.cloudflare.com/dns-encryption-explained/)
- [iodine DNS tunnel tool](https://github.com/yarrick/iodine)
- [dnscat2](https://github.com/iagox86/dnscat2)
- [Related detection writeup — DNS Tunneling via High-Entropy Subdomains](../../detections/network/dns/dns-tunneling-high-entropy-subdomains.md)
