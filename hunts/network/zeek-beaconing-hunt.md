# Hunt: Statistical Beaconing via Zeek conn.log

## Hypothesis

> "We believe that a compromised host is performing automated C2 beaconing because modern C2 frameworks (Cobalt Strike, Metasploit, Sliver) produce periodic outbound connections with low jitter and consistent byte counts — behavior that is statistically distinguishable from human-driven traffic. This would manifest as a high connection-count series to a single external destination with low coefficient of variation in connection intervals, visible in Zeek conn.log."

**Structured form:**
- **Actor behavior:** Automated C2 check-in over HTTP/S or raw TCP at fixed sleep intervals
- **Observable signal:** Low CoV (< 0.3) across inter-connection deltas to a single external IP/FQDN, sustained over ≥ 20 connections
- **Data source:** Zeek conn.log via Corelight (`sourcetype=corelight_conn`)
- **Confidence:** Medium — statistical signal is necessary but not sufficient; human-driven polling tools (backup agents, telemetry) produce similar patterns

---

## ATT&CK Mapping

- **Tactic:** TA0011 — Command and Control
- **Technique:** T1071 — Application Layer Protocol
- **Sub-technique:** T1071.001 — Web Protocols (most common), T1071.004 — DNS (separate hunt)

---

## Threat Context

Cobalt Strike defaults to a 60-second sleep with 0% jitter — producing near-perfect 60s inter-connection intervals. Operators who enable jitter (typically 10–30%) still produce intervals with CoV well below 0.3. Sliver, Metasploit Meterpreter, and Havoc C2 exhibit the same pattern.

CISA AA23-129A (Volt Typhoon) documented low-and-slow beaconing over months using custom implants. Mandiant M-Trends 2024 reported median dwell time of 10 days for detected intrusions — beaconing analysis is one of the few controls that catches implants before hands-on activity begins.

This hunt is most valuable run weekly over a 7–30 day window rather than as a real-time detection, because the statistical signal requires enough connections to be meaningful.

---

## Data Requirements

| Requirement | Detail |
|---|---|
| **Data source** | Zeek conn.log via Corelight — `sourcetype=corelight_conn` |
| **Minimum retention** | 7 days minimum; 30 days preferred for low-frequency beacons |
| **Key fields** | `id.orig_h` (src IP), `id.resp_h` (dst IP), `id.resp_p` (dst port), `_time`, `orig_bytes`, `resp_bytes`, `duration` |
| **Environment assumptions** | Internal RFC1918 src IPs are workstations/servers; external dst IPs are routable. Corelight conn.log is forwarded to Splunk with standard field extraction. |

---

## Hunt Queries

### Stage 1 — Identify high-frequency external connection series

Finds source IPs making repeated connections to the same external destination over the hunt window. High connection count alone is suspicious; we filter to destinations unlikely to be CDNs or known-good infrastructure.

```spl
index=network sourcetype=corelight_conn earliest=-7d
    [| inputlookup known_internal_subnets.csv | rename cidr AS id.orig_h | fields id.orig_h]
| where NOT cidrmatch("10.0.0.0/8", 'id.resp_h')
    AND NOT cidrmatch("172.16.0.0/12", 'id.resp_h')
    AND NOT cidrmatch("192.168.0.0/16", 'id.resp_h')
| eval pair=id.orig_h + " -> " + id.resp_h
| stats
    count AS conn_count,
    earliest(_time) AS first_seen,
    latest(_time) AS last_seen,
    values(id.resp_p) AS ports,
    median(orig_bytes) AS med_orig_bytes,
    median(resp_bytes) AS med_resp_bytes
    BY id.orig_h id.resp_h
| where conn_count >= 20
| eval hunt_window_hours=round((last_seen - first_seen) / 3600, 1)
| sort - conn_count
```

> *Tune `conn_count >= 20` per environment. Noisy environments (frequent backup agents, endpoint telemetry) may require >= 50. Filter known-good infrastructure (Windows Update, CRL endpoints, vendor telemetry) before analysis — build this into a lookup rather than hardcoding.*

---

### Stage 2 — Score connection series by interval regularity (CoV)

For each candidate pair from Stage 1, compute the coefficient of variation (CoV = stddev / mean) of inter-connection intervals. Low CoV signals automated, clock-driven behavior. Human-driven traffic produces CoV > 1.0 by nature.

```spl
index=network sourcetype=corelight_conn earliest=-7d
| where NOT cidrmatch("10.0.0.0/8", 'id.resp_h')
    AND NOT cidrmatch("172.16.0.0/12", 'id.resp_h')
    AND NOT cidrmatch("192.168.0.0/16", 'id.resp_h')
| sort id.orig_h id.resp_h _time
| streamstats current=f last(_time) AS prev_time BY id.orig_h id.resp_h
| eval interval=_time - prev_time
| where interval > 0
| stats
    count AS conn_count,
    avg(interval) AS mean_interval,
    stdev(interval) AS stdev_interval,
    avg(orig_bytes) AS mean_orig_bytes,
    stdev(orig_bytes) AS stdev_orig_bytes,
    earliest(_time) AS first_seen,
    latest(_time) AS last_seen
    BY id.orig_h id.resp_h
| where conn_count >= 20
| eval cov_interval=round(stdev_interval / mean_interval, 3)
| eval cov_bytes=round(stdev_orig_bytes / mean_orig_bytes, 3)
| eval mean_interval_min=round(mean_interval / 60, 1)
| eval beacon_score=case(
    cov_interval < 0.1, "HIGH",
    cov_interval < 0.3, "MEDIUM",
    cov_interval < 0.5, "LOW",
    true(), "NOISE"
  )
| where beacon_score != "NOISE"
| fields id.orig_h id.resp_h conn_count mean_interval_min cov_interval cov_bytes beacon_score first_seen last_seen
| sort beacon_score - conn_count
```

> *CoV thresholds from RITA (Real Intelligence Threat Analytics) methodology. 0.3 is the accepted upper bound for beaconing — above that, interval variance is too high to distinguish from normal polling. Cobalt Strike at 0% jitter produces CoV < 0.01. At 30% jitter, CoV typically lands around 0.17–0.22.*

---

## Baseline Criteria

- **Typical volume:** In a 500-host environment expect 5–20 candidate pairs from Stage 1 before filtering known-good. Most will be endpoint agents, telemetry, or backup software.
- **Known-good patterns:** Windows Update (`dl.delivery.mp.microsoft.com`), CRL checks, cloud endpoint agents (CrowdStrike, Carbon Black), browser sync services. Build a `known_beacon_allowlist.csv` lookup and subtract before scoring.
- **Threshold guidance:** Start with `cov_interval < 0.3` and `conn_count >= 20`. After first run, tune based on what's in the NOISE bucket — if legitimate services cluster at 0.25–0.35, tighten to 0.2.
- **Sleep interval hints:** `mean_interval_min` near round numbers (1, 5, 10, 15, 60 minutes) is more suspicious than irregular intervals. C2 frameworks default to round-number sleeps.

---

## Analysis Guide

**High confidence indicators (escalate):**
- `beacon_score = HIGH` (CoV < 0.1) to an external IP with no DNS PTR record or resolving to hosting infrastructure (AS includes "AMAZON", "DIGITALOCEAN", "LINODE", "VULTR")
- Consistent small `orig_bytes` (50–500 bytes) with variable `resp_bytes` — classic implant check-in pattern (small outbound heartbeat, larger tasking response)
- Connection series that spans multiple days with no gap longer than 2x the mean interval — implant is persistent

**Requires investigation:**
- `beacon_score = MEDIUM` (CoV 0.1–0.3) — could be a jittered C2 or a well-behaved polling agent
- Known software vendor IP but unusual port or unexpected host making the connection
- `beacon_score = HIGH` to a CDN IP — check whether the FQDN is consistent across connections (CDN fronting is a real technique)

**Likely benign (document and close):**
- Source host is a known server (backup, monitoring, patch management) — verify against CMDB
- Destination resolves to a known-good vendor FQDN — add to allowlist
- CoV is low but `conn_count` < 50 and hunt window is < 24h — insufficient data to score

---

## Pivot Queries

### Pivot 1 — Resolve destination IPs to FQDNs via Zeek dns.log

For a candidate src/dst pair, find what names resolved to the destination IP around the time of beaconing.

```spl
index=network sourcetype=corelight_dns earliest=-7d
| eval answers=mvjoin(answers, " ")
| search answers="<CANDIDATE_DST_IP>"
| stats
    values(query) AS resolved_fqdns,
    count AS lookup_count,
    earliest(_time) AS first_lookup,
    latest(_time) AS last_lookup
    BY id.orig_h
| sort - lookup_count
```

> *If no DNS lookups precede the connections, the implant may be using a hardcoded IP — a higher-confidence indicator.*

---

### Pivot 2 — Inspect HTTP layer for C2 artifacts

If beaconing is on port 80/443, check Zeek http.log or ssl.log for consistent User-Agent strings, URI patterns, or certificate anomalies.

```spl
index=network (sourcetype=corelight_http OR sourcetype=corelight_ssl) earliest=-7d
| where id.orig_h="<CANDIDATE_SRC_IP>" AND id.resp_h="<CANDIDATE_DST_IP>"
| stats
    values(user_agent) AS user_agents,
    values(uri) AS uris,
    values(host) AS http_hosts,
    values(server_name) AS tls_sni,
    values(subject) AS cert_subject,
    count
    BY id.orig_h id.resp_h id.resp_p
```

> *Cobalt Strike malleable C2 profiles produce consistent URI patterns and sometimes reuse self-signed or domain-fronted certificates. A single User-Agent string across all connections is suspicious.*

---

### Pivot 3 — Check for lateral movement from the candidate host

If the beaconing host is confirmed, check whether it has made internal connections inconsistent with its role.

```spl
index=network sourcetype=corelight_conn earliest=-7d
| where id.orig_h="<CANDIDATE_SRC_IP>"
    AND cidrmatch("10.0.0.0/8", id.resp_h)
| where id.resp_p IN (445, 135, 5985, 5986, 22, 3389)
| stats
    count AS conn_count,
    values(id.resp_h) AS internal_targets,
    values(id.resp_p) AS ports
    BY id.orig_h
| sort - conn_count
```

---

## Escalation Criteria

- **Escalate immediately if:** `beacon_score = HIGH` to an IP with no prior DNS history on the network, OR a connection series that started within 48 hours of a phishing campaign, failed MFA event, or other precursor indicator
- **Investigate further before escalating if:** `beacon_score = MEDIUM` with suspicious FQDN or unusual port — run all pivot queries, check CMDB for host role
- **Document and close if:** Source is a known server/agent, destination resolves to a known vendor, or CoV drops to NOISE after allowlist subtraction

---

## Hunt Log

| Date | Analyst | Environment | Findings | Outcome |
|---|---|---|---|---|
| | | | | |

---

## References

- [RITA (Real Intelligence Threat Analytics) — beaconing methodology](https://github.com/activecm/rita)
- [Cobalt Strike Sleep and Jitter documentation](https://www.cobaltstrike.com/blog/sleep-and-jitter)
- [CISA AA23-129A — Volt Typhoon](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a)
- [Mandiant M-Trends 2024](https://www.mandiant.com/resources/reports/m-trends-2024)
- [PEAK Threat Hunting Framework — Splunk](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html)
- [Related detection writeup — Statistical Beaconing](../../detections/network/beaconing/statistical-beaconing-zeek-conn.md)
