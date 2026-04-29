# detection-notes

Detection writeups in [Palantir ADS format](https://github.com/palantir/alerting-and-detection-strategy-framework). Each document covers the full context around a detection: what it catches, what it misses, known false positives, and how to validate it fires correctly.

Goal is quality over quantity — fewer well-documented detections beat a pile of undocumented queries.

---

## Structure

```
detections/
  network/       # Network-layer detections (Zeek, Suricata, pcap-derived)
  identity/      # Identity threat detections (Entra ID, Okta, AD)
  cloud/         # Cloud provider detections (AWS, Azure, GCP)
  endpoint/      # Endpoint/EDR detections
_template/       # Blank ADS template to copy for new detections
```

---

## Detections

### Network

| Detection | Technique | Data Source |
|---|---|---|
| [DNS Tunneling via High-Entropy Subdomains](detections/network/dns/dns-tunneling-high-entropy-subdomains.md) | T1071.004 | Zeek dns.log |

### Identity

*Coming soon*

### Cloud

*Coming soon*

### Endpoint

*Coming soon*
