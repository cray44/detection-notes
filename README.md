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
scripts/         # QA tooling — qa_check.py validates quality bar pre-commit
```

Sigma rules are maintained as the portable source of truth in [sigma-to-spl](https://github.com/cray44/sigma-to-spl). Each writeup references the rule by path rather than embedding it inline.

---

## Detections

### Network

| Detection | Technique | Threat Actor | Data Source |
|---|---|---|---|
| [DNS Tunneling via High-Entropy Subdomains](detections/network/dns/dns-tunneling-high-entropy-subdomains.md) | T1071.004 | APT34 / OilRig | Zeek dns.log |
| [TLS C2 via JA4 Fingerprint and Certificate Anomalies](detections/network/tls/tls-c2-ja4-certificate-anomalies.md) | T1071.001, T1573.002 | Cobalt Strike / Brute Ratel | Zeek ssl.log |

### Identity

| Detection | Technique | Threat Actor | Data Source |
|---|---|---|---|
| [OAuth Device Code Phishing](detections/identity/oauth-device-code-phishing/oauth-device-code-phishing.md) | T1528, T1566.002 | APT29 / Midnight Blizzard | Entra ID Sign-in Logs |
| [Service Principal Credential Addition](detections/identity/entra-id-service-principal-credential-addition/entra-id-service-principal-credential-addition.md) | T1098.001 | APT29 / Scattered Spider | Entra ID Audit Logs |

### Cloud

| Detection | Technique | Threat Actor | Data Source |
|---|---|---|---|
| [AWS IAM Privilege Escalation via Policy Attachment](detections/cloud/aws-iam/aws-iam-privilege-escalation-policy-attachment.md) | T1078.004, T1098 | Scattered Spider / LAPSUS$ | AWS CloudTrail |

### Endpoint

| Detection | Technique | Threat Actor | Data Source |
|---|---|---|---|
| [LSASS Process Access for Credential Dumping](detections/endpoint/lsass/lsass-process-access-credential-dumping.md) | T1003.001 | ALPHV / Scattered Spider | Sysmon Event ID 10 |

---

## Quality bar

Every writeup must satisfy all of the following before commit (enforced by pre-commit hook):

- **ADS format** — Goal, ATT&CK, Threat Context, Strategy Abstract, Technical Context, Performance Notes, Blind Spots, False Positives, Validation, Response
- **SPL as primary query** — with performance notes covering estimated event volume, indexed-field strategy, and recommended scheduling window
- **Sigma rule in [sigma-to-spl](https://github.com/cray44/sigma-to-spl)** — referenced by path, not embedded inline; includes explicit caveat where SPL adds logic Sigma cannot express
- **Test data** — `test-data/` directory alongside each writeup with malicious and benign sample log events
- **Threat-informed framing** — tied to published threat actor reporting or specific campaign where possible
