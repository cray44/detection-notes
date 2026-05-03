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
| [Statistical Beaconing via Zeek conn.log](detections/network/conn/statistical-beaconing-zeek-conn-log.md) | T1071 | Cobalt Strike / Sliver / Havoc | Zeek conn.log |
| [SMB Lateral Movement via Admin Share Access](detections/network/smb/smb-lateral-movement-admin-shares.md) | T1021.002 | Conti / BlackCat / Cobalt Strike | Zeek smb_mapping.log |

### Identity

| Detection | Technique | Threat Actor | Data Source |
|---|---|---|---|
| [OAuth Device Code Phishing](detections/identity/oauth-device-code-phishing/oauth-device-code-phishing.md) | T1528, T1566.002 | APT29 / Midnight Blizzard | Entra ID Sign-in Logs |
| [Service Principal Credential Addition](detections/identity/entra-id-service-principal-credential-addition/entra-id-service-principal-credential-addition.md) | T1098.001 | APT29 / Scattered Spider | Entra ID Audit Logs |
| [Kerberoasting via RC4 Encryption Downgrade](detections/identity/kerberoasting-rc4-downgrade/kerberoasting-rc4-downgrade.md) | T1558.003 | APT29 / Conti / eCrime | Windows Security Event 4769 |

### Cloud

| Detection | Technique | Threat Actor | Data Source |
|---|---|---|---|
| [AWS IAM Privilege Escalation via Policy Attachment](detections/cloud/aws-iam/aws-iam-privilege-escalation-policy-attachment.md) | T1078.004, T1098 | Scattered Spider / LAPSUS$ | AWS CloudTrail |
| [Azure Illicit OAuth App Consent Grant](detections/cloud/azure-oauth/azure-illicit-oauth-consent-grant.md) | T1528 | APT29 / Midnight Blizzard | Entra ID Audit Logs |
| [AWS EC2 Snapshot Exfiltration via Cross-Account Sharing](detections/cloud/aws-ec2/aws-ec2-snapshot-exfiltration.md) | T1537 | SCARLETEEL | AWS CloudTrail |

### Endpoint

| Detection | Technique | Threat Actor | Data Source |
|---|---|---|---|
| [LSASS Process Access for Credential Dumping](detections/endpoint/lsass/lsass-process-access-credential-dumping.md) | T1003.001 | ALPHV / Scattered Spider | Sysmon Event ID 10 |
| [WMI Event Subscription Persistence](detections/endpoint/wmi/wmi-event-subscription-persistence.md) | T1546.003 | APT29 / FIN7 / eCrime | Sysmon Event ID 20/21 |

---

## Hunting playbooks

Hypothesis-driven hunts in [PEAK framework](https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html) format — scoped queries with structured analysis approach, not standing alerts.

| Hunt | Technique | Data Source |
|---|---|---|
| [Zeek Statistical Beaconing](hunts/network/zeek-beaconing-hunt.md) | T1071 | Zeek conn.log |
| [DNS Tunneling via Zeek dns.log](hunts/network/dns-tunneling-hunt.md) | T1071.004 | Zeek dns.log |
| [Entra ID OAuth Abuse / Persistent Access](hunts/identity/entra-id-oauth-abuse-hunt.md) | T1528 | Entra ID Audit + Sign-in Logs |
| [Kerberoasting / AS-REP Roasting](hunts/identity/kerberoasting-hunt.md) | T1558.003, T1558.004 | Windows Event 4769 + Zeek kerberos.log |

---

## External contributions

Upstream PRs submitted from this detection research:

| PR | Repo | Description | Status |
|---|---|---|---|
| [#5975](https://github.com/SigmaHQ/sigma/pull/5975) | SigmaHQ/sigma | Device code phishing from non-compliant device (`azure_app_device_code_auth_non_compliant.yml`) | Open |
| [#5981](https://github.com/SigmaHQ/sigma/pull/5981) | SigmaHQ/sigma | Improve `aws_snapshot_backup_exfiltration`: scope to `createVolumePermission`, SCARLETEEL ref, FP triage | Open |
| [#5982](https://github.com/SigmaHQ/sigma/pull/5982) | SigmaHQ/sigma | Add correlation rules: MFA fatigue (T1621), Azure impossible travel→AWS login (T1078), LSASS→AssumeRole (T1003.001) | Open |

---

## Related tools

| Repo | Role |
|---|---|
| [sigma-to-spl](https://github.com/cray44/sigma-to-spl) | Sigma rules (source of truth) + pySigma Splunk converter with Corelight/Zeek field mapping |
| [detection-validator](https://github.com/cray44/detection-validator) | Validates Sigma rules against JSON test samples — no Splunk required |
| [spl-coverage-map](https://github.com/cray44/spl-coverage-map) | Generates ATT&CK Navigator layers from Sigma rule directories |
| [detection-workbench](https://github.com/cray44/detection-workbench) | Detection lifecycle manager — hypothesis capture, sigma-to-spl integration, Claude-assisted critique |

---

## Quality bar

Every writeup must satisfy all of the following before commit (enforced by pre-commit hook):

- **ADS format** — Goal, ATT&CK, Threat Context, Strategy Abstract, Technical Context, Performance Notes, Blind Spots, False Positives, Validation, Response
- **SPL as primary query** — with performance notes covering estimated event volume, indexed-field strategy, and recommended scheduling window
- **Sigma rule in [sigma-to-spl](https://github.com/cray44/sigma-to-spl)** — referenced by path, not embedded inline; includes explicit caveat where SPL adds logic Sigma cannot express
- **Test data** — `test-data/` directory alongside each writeup with malicious and benign sample log events
- **Threat-informed framing** — tied to published threat actor reporting or specific campaign where possible
