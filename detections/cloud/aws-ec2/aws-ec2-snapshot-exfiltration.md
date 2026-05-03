# AWS EC2 Snapshot Exfiltration via Cross-Account Sharing

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

Detect EBS snapshot permission modification that shares a snapshot with an external AWS account — the primary mechanism for cloud data exfiltration via snapshot replication. An attacker with `ec2:ModifySnapshotAttribute` can copy an entire volume's data to an account they control without moving a byte through the network perimeter.

## ATT&CK Categorization

- **Tactic:** TA0010 — Exfiltration
- **Technique:** T1537 — Transfer Data to Cloud Account

## Threat Context

SCARLETEEL (documented by Sysdig in 2023) demonstrated this technique in the wild: after gaining initial access via a misconfigured container in a Kubernetes cluster, attackers moved laterally to EC2 metadata credentials, enumerated EBS snapshots, and shared them cross-account to extract proprietary ML training data and software libraries. The attack achieved data exfiltration without generating S3 or network transfer events because the data never traversed traditional egress paths — it moved directly from EBS snapshot to attacker-mounted volume in a separate AWS account.

Unit 42's Cloud Threat Report (2H 2023) catalogues this as a distinct exfiltration pattern distinct from S3 abuse — specifically attractive because most organizations lack monitoring on `ModifySnapshotAttribute`, CloudTrail management events are not enabled by default in all regions, and the exfiltration side (volume creation in the attacker account) is invisible to the victim's CloudTrail entirely.

The permission required — `ec2:ModifySnapshotAttribute` — is frequently granted to developer and DevOps roles as part of broad EC2 policies. Blast radius correlates directly with how many snapshots exist and how permissive IAM snapshot visibility is.

## Strategy Abstract

CloudTrail records `ModifySnapshotAttribute` events whenever snapshot permissions are changed. The `createVolumePermission` attribute type specifically controls which AWS account IDs can create volumes from the snapshot. When an external account ID (not in the organization's trusted account list) is added to this permission, it is exfiltration staging.

The detection filters to `ModifySnapshotAttribute` events where `attributeType=createVolumePermission` and the shared account ID is not in a known-trusted allowlist. Sharing to `all` (making a snapshot public) is a separate but equally critical variant — the SPL handles both.

A secondary signal is velocity: legitimate automation (AWS Backup, snapshot lifecycle policies) shares to fixed account IDs on predictable schedules. An attacker bulk-sharing multiple snapshots in a short window from an unusual principal is high-confidence exfiltration.

## Technical Context

**Data source:** AWS CloudTrail via Splunk Add-on for AWS — sourcetype `aws:cloudtrail`, index `aws`

**Sigma rule:** [`rules/cloud/aws-ec2-snapshot-exfiltration.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/cloud/aws-ec2-snapshot-exfiltration.yml) in sigma-to-spl

> Sigma covers the API action and attribute type filter. It cannot filter shared account IDs against a trusted allowlist — that requires a Splunk lookup. Without the lookup, this rule FPs on cross-account backup automation. The SPL below adds allowlist suppression and public-snapshot detection.

**Key fields:**

| Field | Description |
|---|---|
| `eventName` | Always `ModifySnapshotAttribute` for this detection |
| `requestParameters.attributeType` | `createVolumePermission` — the sharing operation |
| `requestParameters.createVolumePermission.add.items{}.userId` | AWS account ID being granted access — the exfiltration destination |
| `requestParameters.snapshotId` | The snapshot being shared — pivot to identify what data is on the volume |
| `userIdentity.arn` | Who initiated the share — check against expected automation roles |
| `userIdentity.type` | `IAMUser` is more suspicious than `AssumedRole` from a known service |
| `sourceIPAddress` | `AWS Internal` expected for automation; external IP is high-signal |
| `userAgent` | `aws-cli` or `boto3` from a human-interactive session is suspicious for snapshot sharing |
| `recipientAccountId` | The victim account — useful in multi-account CloudTrail aggregation |

**Environment assumptions:**
- CloudTrail is enabled with management events logging in all regions
- CloudTrail logs are aggregated to a central account and ingested via Splunk Add-on for AWS
- `trusted_aws_accounts.csv` lookup exists listing known internal account IDs (org accounts, DR accounts, partner accounts)
- Multi-account environments should include `recipientAccountId` in grouping

## Performance Notes

- **Estimated event volume:** `ModifySnapshotAttribute` is extremely low volume — typically single digits to tens of events per day in most environments. This is one of the cheapest detections to run.
- **Indexed fields:** `eventName` and `sourcetype` are indexed. The `attributeType` check is a fast JSON extraction via the Add-on field alias on `aws:cloudtrail` events.
- **Recommended time range:** `-15m` on a 5-minute schedule. Low volume, high fidelity — run frequently.
- **Acceleration:** Not needed. This detection targets a single rare event type — no data model required.
- **Multi-account:** If ingesting CloudTrail from multiple accounts via an org-level trail, include `recipientAccountId` in the `stats` clause and output table. The exfiltration destination account will be in `shared_account_id`, not `recipientAccountId`.

## Blind Spots

- **Exfiltration via CopySnapshot cross-region:** `CopySnapshot` with a `destinationRegion` owned by the attacker is an alternative exfil path that never touches `ModifySnapshotAttribute`. Requires a separate detection on `CopySnapshot` events where the destination account is not the caller's account.
- **Attacker-created snapshots from compromised instance:** If the attacker creates a new snapshot of a volume they discover via `DescribeVolumes` and then immediately shares it, the detection fires on the share — but there will also be a `CreateSnapshot` event moments prior from the same identity. This pair is worth hunting separately.
- **Public snapshot (`"group": "all"`):** Making a snapshot world-readable uses `createVolumePermission` with a `group: all` item rather than a `userId`. The SPL handles this via `shared_group` extraction, but the Sigma rule does not — this is only covered in SPL.
- **CloudTrail gaps in non-default regions:** If CloudTrail is not enabled in all regions, an attacker can copy a snapshot to a region where logging is off before sharing. Verify CloudTrail org-level coverage.
- **Snapshot enumeration precursor:** The attacker must first enumerate available snapshots (`DescribeSnapshots` with no `owner-id` filter returns public snapshots globally). Hunting for unusual `DescribeSnapshots` calls is complementary but not in scope here.
- **Victim-side blindness post-share:** Once the snapshot is shared, the attacker creates a volume from it in their own account. That `CreateVolume` event appears only in the attacker's CloudTrail — you will never see it.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| AWS Backup cross-account sharing to DR account | `sourceIPAddress` will be `AWS Internal`, `userAgent` will be `aws-backup.amazonaws.com`, `userIdentity.arn` matches a known Backup service role. `shared_account_id` should be in `trusted_aws_accounts.csv`. Add to allowlist and suppress. |
| Terraform/Lambda snapshot lifecycle automation | Role ARN will match a known IaC or automation role. `shared_account_id` should be a known org account. Confirm via change record; suppress after validation. |
| AMI builder pipelines sharing snapshots to a staging account | Predictable schedule, fixed destination, automated role. Same allowlist suppression. |
| Authorized data sharing to a partner account | Verify business justification. If legitimate, add `shared_account_id` to `trusted_aws_accounts.csv` with a comment and suppress going forward. |

## Validation

**Test data:** See [`test-data/`](test-data/) alongside this file — includes malicious samples (external account share from compromised credential, bulk sharing) and benign samples (AWS Backup cross-account share, non-permission attribute modification).

**Lab reproduction** (requires EC2 access in a test AWS account):

```bash
# Create a test snapshot
SNAP_ID=$(aws ec2 create-snapshot \
  --volume-id vol-xxxxxxxxxxxxxxxxx \
  --description "exfil-test" \
  --query SnapshotId --output text)

# Share it with an external account (replace with your test account ID)
aws ec2 modify-snapshot-attribute \
  --snapshot-id "$SNAP_ID" \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids 999988887777

# Also test the public variant
aws ec2 modify-snapshot-attribute \
  --snapshot-id "$SNAP_ID" \
  --attribute createVolumePermission \
  --operation-type add \
  --group-names all
```

Expected: `ModifySnapshotAttribute` events in `aws:cloudtrail` within 5–15 minutes. The malicious sample fires the detection; the benign (if using a trusted account ID in the allowlist) is suppressed.

**SPL (primary):**

```spl
index=aws sourcetype="aws:cloudtrail"
    eventName=ModifySnapshotAttribute
    requestParameters.attributeType=createVolumePermission
| spath input=_raw path="requestParameters.createVolumePermission.add.items{}.userId" output=shared_account_id
| spath input=_raw path="requestParameters.createVolumePermission.add.items{}.group" output=shared_group
| eval is_public=if(mvfind(shared_group, "all")>=0, "true", "false")
| mvexpand shared_account_id
| eval shared_account_id=trim(shared_account_id)
| lookup trusted_aws_accounts.csv account_id AS shared_account_id OUTPUT is_trusted
| where isnull(is_trusted) OR is_public="true"
| eval snapshot_id='requestParameters.snapshotId'
| eval caller_arn='userIdentity.arn'
| eval caller_type='userIdentity.type'
| eval source_ip='sourceIPAddress'
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval risk_score=case(
    is_public="true",                          100,
    caller_type="Root",                        100,
    source_ip!="AWS Internal" AND caller_type="IAMUser", 85,
    source_ip!="AWS Internal",                  70,
    true(),                                     60)
| eval confidence=case(risk_score>=85, "HIGH", risk_score>=70, "MEDIUM", true(), "LOW")
| eval exfil_type=if(is_public="true",
    "PUBLIC snapshot — world-readable",
    "Cross-account share to: " + shared_account_id)
| stats
    count AS share_count
    values(snapshot_id) AS snapshots_shared
    values(exfil_type) AS exfil_type
    max(risk_score) AS risk_score
    values(confidence) AS confidence
    BY event_time, caller_arn, caller_type, source_ip, recipientAccountId
| sort - risk_score
```

> *Performance note:* The `eventName` and `attributeType` filters at the top drop event volume to near-zero before `spath` parsing. The `spath` path extraction for array elements (`items{}.userId`) handles multi-account shares (multiple `userId` entries in a single event) via multivalue expansion. Do not move the `lookup` call before `mvexpand` — you need one row per account ID to check each against the allowlist independently.

**Supporting lookup: `trusted_aws_accounts.csv`**

```
account_id,account_name,is_trusted,notes
444455556666,prod-dr-account,true,DR replication target — AWS Backup
555566667777,infra-staging,true,IaC staging account — Terraform pipelines
```

## Response

1. **Identify the snapshot** — `snapshot_id` tells you which volume's data was shared. Describe the snapshot (`aws ec2 describe-snapshots --snapshot-ids <snap-id>`) to find the source volume, the volume's attachment history, and any tags indicating data classification.
2. **Identify the destination account** — `shared_account_id` is the exfiltration destination. If not in your AWS Organization, this is an external account. You will not have visibility into what the attacker did with the volume in that account.
3. **Revoke the permission immediately** — `aws ec2 modify-snapshot-attribute --snapshot-id <snap-id> --attribute createVolumePermission --operation-type remove --user-ids <attacker-account-id>`. For public snapshots: `--group-names all`.
4. **Assess the compromised identity** — `caller_arn` performed the share. Disable the access key or IAM user immediately. Check CloudTrail for all actions by this identity in the past 30 days — what else did they enumerate or exfiltrate?
5. **Determine how long the snapshot was shared** — the `ModifySnapshotAttribute` event gives you the share time. The attacker may have had hours or days to create a volume from it. Assume data is compromised.
6. **Enumerate all shared snapshots** — check if other snapshots were shared to the same destination account: `aws ec2 describe-snapshots --owner-ids self --filters Name=attribute,Values=createVolumePermission`. Also query CloudTrail for all `ModifySnapshotAttribute` events from the same identity.
7. **Notify data owners** — identify what data lived on the source volume via tags, instance attachment history, and application context. Initiate data breach assessment per your organization's incident response plan.

## References

- [MITRE ATT&CK T1537 — Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [SCARLETEEL: Operation leveraging Terraform, Kubernetes, and AWS — Sysdig](https://sysdig.com/blog/cloud-breach-terraform-data-theft/)
- [Unit 42 Cloud Threat Report 2H 2023](https://unit42.paloaltonetworks.com/cloud-threat-report-2H2023/)
- [Modifying a snapshot's permissions — AWS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html)
- [Sigma rule — aws-ec2-snapshot-exfiltration.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/cloud/aws-ec2-snapshot-exfiltration.yml)
