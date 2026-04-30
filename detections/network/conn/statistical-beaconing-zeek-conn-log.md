# Statistical Beaconing via Zeek conn.log

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

Detect C2 implants beaconing home by measuring the statistical regularity of repeated outbound connections from a single host to the same external IP:port. Implants with a fixed callback interval — Cobalt Strike, Sliver, Havoc, Mythic, and most commodity RATs — exhibit low jitter in their inter-arrival times, a signal that persists even when TLS fingerprinting and certificate anomaly detection have been evaded.

## ATT&CK Categorization

- **Tactic:** TA0011 — Command and Control
- **Technique:** T1071 — Application Layer Protocol

## Threat Context

Every C2 framework with a callback interval produces this signal. Cobalt Strike's default sleep is 60 seconds with 0% jitter; operators who forget to configure jitter produce near-perfect beacons detectable in a single hour of conn.log data. Even operators who configure jitter (typically 10–30%) remain detectable — the coefficient of variation simply rises, requiring a longer observation window rather than a lower threshold.

Active Countermeasures published the RITA (Real Intelligence Threat Analytics) methodology in 2016 and later open-sourced the tool. RITA's beaconing score is built on the same statistical foundation — coefficient of variation of inter-arrival times — and remains the reference implementation for network-layer beaconing detection. Mandiant M-Trends has consistently reported C2 dwell times measured in weeks to months, meaning implants produce this signal for far longer than a single detection window.

The technique is protocol-agnostic: beaconing over HTTP, HTTPS, DNS-over-TCP, or raw TCP all produces the same behavioral artifact in conn.log, making this detection a useful backstop when protocol-specific detections are evaded.

## Strategy Abstract

Zeek `conn.log` records every completed network connection with a timestamp, source IP, destination IP:port, bytes in each direction, duration, and protocol. A beaconing implant connects to its C2 server at a fixed interval, producing a series of events with consistent inter-arrival times — that is, the time between successive connections to the same destination stays approximately constant.

The detection computes the **coefficient of variation (CoV)** of inter-arrival times for each (src_ip, dst_ip, dst_port) tuple: `CoV = stddev / mean`. A CoV near 0 indicates near-perfect regularity; a CoV above ~0.5 indicates irregular traffic. Legitimate polling software has nonzero jitter; C2 beacons typically do not.

Additional signals layer on top of the timing analysis:
- Small and consistent byte counts per connection (implant heartbeats transfer little data)
- High connection count relative to the observation window (many callbacks in a few hours = frequent polling)
- Connections on non-standard ports (443 is fine; 4444, 8443, or raw high ports warrant additional scrutiny)

Any tuple with ≥ 5 connections, mean interval ≥ 10 seconds, and CoV < 0.5 is surfaced. High confidence requires CoV < 0.1 and ≥ 20 connections.

## Technical Context

**Data source:** Zeek `conn.log` via Corelight App for Splunk — sourcetype `corelight_conn`

**Sigma rule:** [`rules/network/statistical-beaconing-zeek-conn-log.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/statistical-beaconing-zeek-conn-log.yml) in sigma-to-spl

> Sigma cannot express inter-arrival time computation, standard deviation, or coefficient of variation. The Sigma rule defines the structural pre-filter (external destination, TCP/UDP, nonzero bytes, not NTP). The SPL below applies the full statistical model. This is a case where SPL adds logic that Sigma cannot represent.

**Key fields:**

| Field | Description |
|---|---|
| `id.orig_h` | Source IP — the potentially beaconing host |
| `id.resp_h` | Destination IP — the C2 server |
| `id.resp_p` | Destination port — C2 commonly uses 443, 8443, 4444, or high ephemeral ports |
| `proto` | Protocol — tcp or udp; filters out irrelevant traffic types |
| `_time` | Connection timestamp — used to compute inter-arrival times via streamstats |
| `duration` | Connection duration in seconds — consistent short durations support the implant heartbeat pattern |
| `orig_bytes` | Bytes sent by the originating host — implant beacons typically send small, consistent payloads |
| `resp_bytes` | Bytes sent by the responding host — C2 tasking responses appear here |
| `conn_state` | Connection state — `SF` (normal close) is expected for established beacons; `S0` (no response) suggests scanning or dropped connections |

**Environment assumptions:**
- Zeek sensor deployed at network egress capturing full connection metadata; conn.log fields are indexed via Corelight App
- `established` or `conn_state` filtering is viable — prefer filtering on `conn_state=SF` or `orig_bytes > 0` to exclude half-open connections
- RFC1918 internal destinations are filtered; an asset inventory lookup is available to suppress known monitoring agents by source IP
- The search is run over a minimum 4-hour window; shorter windows may not accumulate enough connections for low-frequency beacons (e.g., 30-minute interval implants need several hours to reach the minimum count threshold)

## Performance Notes

- **Estimated event volume:** conn.log is the highest-volume Zeek log. In a 5,000-endpoint enterprise, expect 50–200M conn.log events per day. **This query must not be run as a raw search over a full day.** Use a 4–8 hour rolling window on a scheduled search.
- **Indexed fields:** `id.resp_h`, `proto`, `id.resp_p` should be indexed in the Corelight App. `orig_bytes` is typically extracted, not indexed — confirm with `| tstats count WHERE index=network sourcetype=corelight_conn by proto` before scheduling.
- **Sort cost:** The `sort 0` before `streamstats` is the most expensive step — it forces a full sort of all pre-filtered events. The RFC1918 and `orig_bytes > 0` filters before the sort are essential; run them first to minimize sorted event count.
- **Two-phase approach for high-volume environments:** Use `tstats` to pre-identify (src_ip, dst_ip, dst_port) tuples with ≥ 10 connections. Feed those as a subsearch filter into the per-event analysis. This avoids sorting the full conn.log dataset.
- **Recommended time range:** `-8h` on a 4-hour schedule (overlapping windows catch beacons near the boundary). Adjust based on the lowest-frequency implant you want to catch — a 30-minute beacon needs ≥ 3–4 hours to reach 5 connections.
- **Acceleration:** If conn.log volume exceeds 100M events/day, build a `tstats` summary index of (src_ip, dst_ip, dst_port, proto, minute_bucket, conn_count, byte_sum). Run the jitter model against the summary, not raw events.
- **Do not** use `transaction` for this detection — `transaction` on conn.log at scale is prohibitively expensive.

## Blind Spots

- **Jitter-configured implants:** Cobalt Strike, Sliver, and Havoc all have configurable jitter. An operator setting 30% jitter pushes CoV to ~0.17; at 50% jitter, CoV reaches ~0.29. Both remain below the 0.5 threshold but require a larger observation window. At 100% jitter (randomized sleep), the signal disappears entirely against a short window.
- **DNS-based C2:** If the C2 channel rides DNS (T1071.004), connections appear in `dns.log` to the resolver — not in conn.log as a direct connection to the C2 IP. This detection is blind to DNS tunneling; see the DNS tunneling writeup for that coverage.
- **HTTPS proxy environments:** If endpoints route all outbound traffic through an explicit HTTP proxy, conn.log shows repeated connections to the proxy, not to the C2 IP. The beacon signal is diluted into a high-volume connection pool. HTTP log or proxy log analysis is required.
- **Long-sleep implants (> 4 hour interval):** A beacon sleeping 6–8 hours between callbacks will not accumulate 5 connections in an 8-hour window. These require a 24–48 hour search window, which is operationally costly at conn.log volume. Alert tuning must explicitly account for minimum detectable beacon frequency.
- **Domain-fronted C2:** C2 traffic proxied through a CDN (Cloudflare, Fastly, Azure Front Door) shows connections to the CDN's IP pool — high-volume, geographically diverse destinations. Statistical regularity is present but buried in the CDN traffic mix and may not survive destination-keyed grouping.
- **Legitimate polling software with low jitter:** Some monitoring agents (Datadog, Dynatrace, CrowdStrike Falcon heartbeat) have very regular check-in intervals and will match the statistical profile. These are detectable false positives; see FP table for suppression approach.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| Endpoint security agents (CrowdStrike, Defender ATP, Carbon Black) | Regular heartbeat to known vendor cloud endpoints. Suppress by destination IP range (vendor-published) or by asset-inventory lookup for known agent source IPs. |
| IT monitoring agents (Datadog, Dynatrace, Prometheus remote write) | Check `id.resp_h` and `id.resp_p` against vendor documentation. Suppress confirmed monitoring destinations in an allowlist lookup. |
| Software update clients (Windows Update, AV signature pull) | Typically produce large `resp_bytes` relative to `orig_bytes`. Filter on `avg_resp_bytes < 10000` — implant beacons tend to have consistent small payloads. |
| NTP clients | Proto=udp, port=123 — filtered by default in the SPL. If appearing, confirm NTP filter is working. |
| Authentication heartbeats (Azure AD join, SSSD, PAM) | Consistent connections to well-known identity provider IPs. Suppress by destination IP range (Microsoft-published, Google, Okta). |
| CDN keep-alive connections | High `resp_bytes`, destination is a known CDN IP. Filter by large average response size or by CDN IP range lookup. |

## Validation

**Test data:** See [`test-data/`](test-data/) — includes malicious samples (Cobalt Strike-style 60-second beacon with low jitter) and benign samples (monitoring agent with high inter-arrival variance and NTP traffic).

**Lab reproduction using ncat:**

```bash
# Simulate a beaconing implant: connect every 60 seconds to a listener
# Run on the "victim" host; capture with Zeek or tcpdump at the sensor
while true; do
    ncat <c2_ip> 4444 -e /bin/echo <<< "beacon"
    sleep 60
done
```

```bash
# With configurable jitter (simulates 20% jitter)
while true; do
    ncat <c2_ip> 4444 -e /bin/echo <<< "beacon"
    jitter=$(( (RANDOM % 24) - 12 ))   # ±12 seconds on a 60-second base
    sleep $(( 60 + jitter ))
done
```

Expected in Zeek conn.log: repeated `(10.x.x.x, <c2_ip>, 4444, tcp)` tuples at ~60-second intervals with `conn_state=SF`, `orig_bytes` ~50–200, `resp_bytes` ~50–500.

In Splunk after the SPL runs: the (src, dst, port) tuple appears with `connection_count >= 5`, `mean_interval_sec ~60`, `jitter < 0.1`, `beacon_confidence=HIGH`.

**SPL (primary):**

```spl
index=network sourcetype=corelight_conn earliest=-8h latest=now
| where NOT (match('id.resp_h', "^10\.") OR match('id.resp_h', "^172\.(1[6-9]|2\d|3[01])\.") OR match('id.resp_h', "^192\.168\.") OR match('id.resp_h', "^127\."))
| where proto="tcp" OR proto="udp"
| where orig_bytes > 0
| where NOT (proto="udp" AND id.resp_p=123)
| sort 0 id.orig_h, id.resp_h, id.resp_p, _time
| streamstats window=1 current=f last(_time) AS prev_conn_time BY id.orig_h, id.resp_h, id.resp_p
| where isnotnull(prev_conn_time)
| eval inter_arrival_sec = _time - prev_conn_time
| where inter_arrival_sec > 5 AND inter_arrival_sec < 86400
| stats
    count                        AS connection_count,
    avg(inter_arrival_sec)       AS mean_interval_sec,
    stdev(inter_arrival_sec)     AS stddev_interval_sec,
    avg(duration)                AS avg_duration_sec,
    avg(orig_bytes)              AS avg_orig_bytes,
    avg(resp_bytes)              AS avg_resp_bytes,
    min(_time)                   AS first_seen,
    max(_time)                   AS last_seen
    BY id.orig_h, id.resp_h, id.resp_p, proto
| where connection_count >= 5 AND mean_interval_sec >= 10
| eval jitter = round(stddev_interval_sec / mean_interval_sec, 3)
| where jitter < 0.5
| eval beacon_confidence = case(
    jitter < 0.1  AND connection_count >= 20, "HIGH",
    jitter < 0.25 AND connection_count >= 10, "MEDIUM",
    true(), "LOW"
)
| eval mean_interval_min = round(mean_interval_sec / 60, 2)
| eval avg_orig_bytes    = round(avg_orig_bytes, 0)
| eval avg_resp_bytes    = round(avg_resp_bytes, 0)
| eval avg_duration_sec  = round(avg_duration_sec, 3)
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen  = strftime(last_seen,  "%Y-%m-%d %H:%M:%S")
| sort jitter
| table id.orig_h, id.resp_h, id.resp_p, proto, connection_count, mean_interval_sec, mean_interval_min, jitter, beacon_confidence, avg_orig_bytes, avg_resp_bytes, avg_duration_sec, first_seen, last_seen
```

> *Performance note:* The RFC1918 filter, `orig_bytes > 0`, and NTP exclusion must appear before `sort 0` — each filter applied before the sort reduces the cost of the full-data sort substantially. `sort 0` (the zero forces an unlimited sort) is required for `streamstats BY` to produce correct per-group inter-arrival times; removing it will produce incorrect deltas when events are out of order. The `where inter_arrival_sec > 5 AND < 86400` filter drops sub-5-second connections (scans, retries) and multi-day gaps that would skew the mean. The final `stats` aggregation collapses the per-interval dataset into one row per (src, dst, port, proto) tuple.

## Response

1. **Identify the beaconing host** (`id.orig_h`) — pull process and network telemetry from EDR for the same time window. Look for processes making outbound network calls that are unusual for that host class (e.g., `cmd.exe`, `powershell.exe`, `rundll32.exe` with outbound connections).
2. **Characterize the destination** (`id.resp_h`) — passive DNS, threat intel lookup (VirusTotal, Shodan, Recorded Future). Check if the IP was recently registered, is in an unusual ASN, or has other threat detections. Note `id.resp_p` — non-standard ports narrow the hypothesis significantly.
3. **Measure dwell time** — extend the search to 30–90 days for `id.orig_h` → `id.resp_h`. How long has this been running? A beacon with 30 days of history changes the scope of the investigation significantly.
4. **Pivot to HTTP/TLS logs** — pivot on the (src, dst, port) tuple in `corelight_ssl` or `corelight_http`. Certificate anomalies or known-bad JA4 fingerprints alongside a beaconing signal are high confidence. Empty `server_name` (no SNI) on port 443 is notable.
5. **Confirm before isolating** — if IR is not yet engaged, confirm the signal is real before isolating. False positives (monitoring agents) are common. Pulling EDR process context typically resolves ambiguity within minutes.
6. **Scope lateral movement** — once a beaconing host is confirmed, look for SMB, RDP, WMI, and DCOM connections originating from `id.orig_h` in the same window. The beaconing host is often not the initial access point.

## References

- [MITRE ATT&CK T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [RITA — Real Intelligence Threat Analytics (Active Countermeasures)](https://github.com/activecm/rita)
- [Beaconing Detection with RITA — Black Hills Information Security](https://www.blackhillsinfosec.com/using-rita-for-c2-beacon-detection/)
- [Cobalt Strike Beacon Configuration Reference](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructure_c2-http.htm)
- [Mandiant M-Trends 2024 — C2 dwell time statistics](https://www.mandiant.com/m-trends)
- [Sigma rule — statistical-beaconing-zeek-conn-log.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/network/statistical-beaconing-zeek-conn-log.yml)
