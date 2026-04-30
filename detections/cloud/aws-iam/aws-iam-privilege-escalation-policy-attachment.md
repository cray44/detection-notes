# AWS IAM Privilege Escalation via Policy Attachment

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

Detect post-compromise privilege escalation in AWS where an attacker with limited IAM credentials attaches broad or administrative policies to a principal they control. Scattered Spider, Cozy Bear (APT29), and the LAPSUS$ group have all used IAM permission manipulation as a persistence and escalation primitive after gaining initial access via phishing, SIM swapping, or stolen credentials.

## ATT&CK Categorization

- **Tactic:** TA0004 — Privilege Escalation
- **Tactic:** TA0003 — Persistence
- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts
- **Technique:** T1098 — Account Manipulation

## Threat Context

Rhino Security Labs documented 21 distinct IAM privilege escalation paths in 2019 — policy attachment remains the most reliable because it requires only `iam:AttachUserPolicy` or `iam:AttachRolePolicy`, permissions that are frequently over-provisioned in developer and CI/CD roles. Unit 42 documented similar techniques in the 2023 cloud threat report, identifying IAM credential theft followed by `AttachRolePolicy` as the dominant lateral movement pattern in AWS-targeted intrusions.

LAPSUS$ specifically used compromised Okta service accounts to pivot into AWS environments and escalated via policy attachment before performing data exfiltration. Scattered Spider has used the same primitive in attacks on MGM Resorts and Caesars Entertainment — credentials obtained via helpdesk social engineering, then immediately weaponized against cloud IAM.

The detection targets both managed policy attachment (the most common path) and inline policy injection (`PutRolePolicy` with `Action: "*"`), which is the evasion variant used by operators who know managed policy ARNs are monitored.

## Strategy Abstract

AWS CloudTrail records every IAM control-plane action, including the six policy attachment/injection events that are relevant here: `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy` (managed policies) and `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy` (inline policies). The detection is two-tiered:

**Tier 1 — Managed policy attachment of known broad policies:** Any attachment of `AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`, or similar high-privilege AWS managed policies to any principal. These are near-zero-FP in a mature environment with proper change control.

**Tier 2 — Inline policy injection with wildcard actions:** `PutRolePolicy` events where the embedded policy document contains `"Action": "*"` or `"Action": ["*"]`. This catches custom escalation that bypasses ARN-based monitoring. Requires parsing the `requestParameters.policyDocument` field from CloudTrail JSON.

Both tiers are scored and surfaced together. Tier 1 events outside of expected IaC pipeline hours, or Tier 2 events by any non-IaC identity, are high confidence.

## Technical Context

**Data source:** AWS CloudTrail via Splunk Add-on for AWS — sourcetype `aws:cloudtrail`, index `aws` (adjust to match your environment)

**Sigma rule:** [`rules/cloud/aws-iam-privilege-escalation-policy-attachment.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/cloud/aws-iam-privilege-escalation-policy-attachment.yml) in sigma-to-spl

> Sigma covers Tier 1 (managed policy ARN matching). Sigma cannot parse embedded JSON in `requestParameters.policyDocument` to detect wildcard inline policies. The SPL below handles both tiers.

**Key fields:**

| Field | Description |
|---|---|
| `eventName` | CloudTrail API action name — the six attachment/injection events |
| `userIdentity.arn` | Full ARN of the caller — who performed the escalation |
| `userIdentity.type` | `IAMUser`, `AssumedRole`, `Root` — Root escalation events are critical |
| `userIdentity.sessionContext.sessionIssuer.arn` | The role ARN if the caller assumed a role — maps to service/instance identity |
| `requestParameters.policyArn` | ARN of the managed policy being attached |
| `requestParameters.userName` / `roleName` / `groupName` | Target principal receiving the policy |
| `requestParameters.policyDocument` | Inline policy JSON (PutXPolicy events only) — requires `spath` to parse |
| `sourceIPAddress` | IP of caller — `AWS Internal` for service-to-service; external IPs warrant attention |
| `userAgent` | CLI/SDK identifier — `aws-cli` vs. `Terraform` vs. `Boto3` differs from typical operator |
| `errorCode` | `AccessDenied` on failed attempts — useful for hunting escalation attempts that were blocked |

**Environment assumptions:**
- AWS CloudTrail is enabled in all regions with management events logging (not data events)
- CloudTrail logs are delivered to S3 and ingested via Splunk Add-on for AWS or Firehose
- IaC pipeline roles (Terraform, CDK) are known and stored in a lookup (`iac_roles.csv`) for suppression
- `aws_privileged_policies.csv` lookup exists with known over-privileged managed policy ARNs

## Performance Notes

- **Estimated event volume:** CloudTrail management events for IAM in an enterprise AWS environment average 1,000–10,000 events/day. IAM policy attachment events specifically are far lower — typically dozens per day during normal IaC activity. This is a low-volume, near-real-time detection.
- **Indexed fields:** `eventName` and `sourcetype` are indexed. `userIdentity.arn` is a JSON extraction — fast on `aws:cloudtrail` because the Add-on pre-extracts it as a field alias.
- **Recommended time range:** `-15m` on a 5-minute schedule. This is a low-volume, high-signal event type — no need to batch. Alert fast.
- **Acceleration:** Not needed. This detection runs over IAM events only, which are inherently low-volume. If you are running this across all CloudTrail events without a sourcetype pre-filter, add `sourcetype=aws:cloudtrail eventName IN ("AttachUserPolicy","AttachRolePolicy","AttachGroupPolicy","PutUserPolicy","PutRolePolicy","PutGroupPolicy")` as the opening filter.
- **Multi-account environments:** If ingesting CloudTrail from multiple AWS accounts, add `recipientAccountId` to the `stats by` clause and to the output. The escalation is account-scoped but the investigation is not.

## Blind Spots

- **Indirect escalation via trust policy modification:** An attacker who modifies a role's trust policy (`UpdateAssumeRolePolicy`) to allow a principal they control to assume an admin role never triggers a policy attachment event. Requires a separate detection on `UpdateAssumeRolePolicy` with cross-account trust additions.
- **Escalation via IAM group membership:** Adding a user to a group that already has `AdministratorAccess` attached (`AddUserToGroup`) achieves the same result as direct policy attachment. This detection does not cover group membership changes — that's a gap.
- **Escalation via permission boundary removal:** `DeleteRolePermissionsBoundary` removes the maximum-permissions ceiling on a role. If the underlying role already has broad permissions, removal escalates effective access without any attachment event.
- **CreateRole with embedded admin policy:** Creating a new role with an embedded admin policy in the same API call does not generate a separate attachment event. `CreateRole` events with `assumeRolePolicyDocument` containing broad statements are out of scope here.
- **AWS service-linked roles:** Some AWS services create roles with broad permissions during provisioning. These will appear as `AttachRolePolicy` events from `AWS Internal` and require suppression tuning.
- **Long dwell time before escalation:** An attacker who obtained credentials weeks ago and performs escalation during peak IaC pipeline activity blends into normal CloudTrail noise. Time-of-day context is important.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| Terraform/CDK pipeline runs during initial environment provisioning | Check `userIdentity.arn` — should match known IaC service role in `iac_roles.csv`. Confirm change ticket exists. Suppress by role ARN after validation. |
| Authorized IAM admin adding policy for new service | Correlate with change management record. `userIdentity.type` should be `IAMUser` with MFA; `sourceIPAddress` should be corporate egress. Flag if offhours or from unexpected IP. |
| Break-glass emergency access account activation | These should have a matching approval ticket. `userIdentity.arn` will be the break-glass role ARN — maintain a list of these and treat as low-priority alert requiring ticket correlation, not immediate IR. |
| AWS Organizations Service Control Policy enforcement creating service roles | `sourceIPAddress` will be `AWS Internal`. Correlate with expected organizational automation activity. |
| New account bootstrap (first IaC run against a new AWS account) | Expected pattern: burst of IAM events from IaC role, all within minutes, all successful. If isolated to account provisioning timeframe, note and suppress for that account. |

## Validation

**Test data:** See [`test-data/`](test-data/) alongside this file — includes malicious samples (escalation by compromised user, inline wildcard policy injection) and benign samples (IaC pipeline attachment, authorized admin action).

**Lab reproduction using AWS CLI** (requires an IAM user with `iam:AttachUserPolicy` in a test environment):

```bash
# Simulate attacker attaching AdministratorAccess to a compromised user
aws iam attach-user-policy \
  --user-name target-test-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Simulate inline wildcard policy injection to a role
aws iam put-role-policy \
  --role-name target-test-role \
  --policy-name escalation-test \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

Expected CloudTrail events: `AttachUserPolicy` with `requestParameters.policyArn=arn:aws:iam::aws:policy/AdministratorAccess` and `PutRolePolicy` with `requestParameters.policyDocument` containing `"Action":"*"`. Both should appear in `aws:cloudtrail` within 5–15 minutes of the API call.

**SPL (primary):**

```spl
index=aws sourcetype="aws:cloudtrail"
    eventName IN ("AttachUserPolicy","AttachRolePolicy","AttachGroupPolicy",
                  "PutUserPolicy","PutRolePolicy","PutGroupPolicy")
| eval target_principal=coalesce('requestParameters.userName',
                                  'requestParameters.roleName',
                                  'requestParameters.groupName')
| eval policy_arn='requestParameters.policyArn'
| eval caller_arn='userIdentity.arn'
| eval caller_type='userIdentity.type'
| eval source_ip='sourceIPAddress'
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")

| lookup aws_privileged_policies.csv policy_arn OUTPUT policy_label AS known_broad_policy
| eval tier1_hit=if(isnotnull(known_broad_policy), "true", "false")

| spath input=requestParameters.policyDocument output=parsed_policy
| eval has_wildcard_action=if(
    match('parsed_policy', "\"Action\"\s*:\s*\"\*\"") OR
    match('parsed_policy', "\"Action\"\s*:\s*\[\s*\"\*\"\s*\]"),
    "true", "false")
| eval tier2_hit=if(has_wildcard_action="true" AND
    eventName IN ("PutUserPolicy","PutRolePolicy","PutGroupPolicy"),
    "true", "false")

| where tier1_hit="true" OR tier2_hit="true"

| lookup iac_roles.csv caller_arn OUTPUT is_iac_role
| eval is_iac=if(isnotnull(is_iac_role), "true", "false")

| eval risk_score=case(
    caller_type="Root",                    100,
    tier2_hit="true" AND is_iac!="true",    80,
    tier1_hit="true" AND is_iac!="true",    70,
    tier1_hit="true" AND is_iac="true",     20,
    true(),                                 40)

| eval confidence=case(risk_score>=80, "HIGH", risk_score>=60, "MEDIUM", true(), "LOW")
| eval escalation_type=case(
    caller_type="Root",       "ROOT account policy action — critical",
    tier2_hit="true",         "Inline wildcard policy injection",
    tier1_hit="true",         "Broad managed policy: " + known_broad_policy,
    true(),                   "Unknown")

| table event_time, caller_arn, caller_type, source_ip, eventName,
         target_principal, policy_arn, escalation_type,
         confidence, risk_score, is_iac, recipientAccountId
| sort - risk_score
```

> *Performance note:* The `eventName IN (...)` filter at the top reduces the CloudTrail event set to only IAM policy attachment events — in most environments this drops volume by 95%+ before any `eval` runs. `spath` parsing of `policyDocument` is only triggered after the volume is already minimal. The `lookup` against `iac_roles.csv` is a cheap index-time operation. Do not move the `spath` call before the `eventName` filter.

**Supporting lookup: `aws_privileged_policies.csv`**

```
policy_arn,policy_label
arn:aws:iam::aws:policy/AdministratorAccess,AdministratorAccess
arn:aws:iam::aws:policy/PowerUserAccess,PowerUserAccess
arn:aws:iam::aws:policy/IAMFullAccess,IAMFullAccess
arn:aws:iam::aws:policy/SecurityAudit,SecurityAudit
```

## Response

1. **Identify the caller** — pull `caller_arn` and `caller_type`. Root actions require immediate escalation to cloud security team regardless of context. Assumed-role actions — determine what role was assumed and what service/instance assumed it.
2. **Determine if change was authorized** — correlate `event_time` with change management records. Does a ticket exist? Was the change within a scheduled maintenance window? Contact the IAM admin team.
3. **Assess the escalation target** — what principal (`target_principal`) received elevated access? What resources does that principal have access to? Pull all recent activity for that principal from CloudTrail over the past 30 days.
4. **Check for follow-on actions** — an attacker who just escalated permissions will use them within minutes. Search CloudTrail for the `target_principal` performing sensitive operations: `CreateAccessKey`, `GetSecretValue`, `AssumeRole`, S3 `GetObject` on sensitive buckets.
5. **Revoke the policy attachment** — if confirmed unauthorized, detach the policy or delete the inline policy immediately. Document the API call and time.
6. **Rotate compromised credentials** — the `caller_arn` used for escalation represents a compromised identity. Disable the access key or IAM user, rotate credentials, and investigate how initial access was obtained.
7. **Scope the blast radius** — what data did the elevated principal access between the escalation event and detection? Pull CloudTrail for the `target_principal` post-escalation. S3 access logs and CloudWatch data-plane events if enabled.

## References

- [MITRE ATT&CK T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [AWS IAM Privilege Escalation — Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Compromised Cloud Compute Credentials — Unit 42](https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/)
- [Scattered Spider TTPs — CISA Advisory AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Sigma rule — aws-iam-privilege-escalation-policy-attachment.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/cloud/aws-iam-privilege-escalation-policy-attachment.yml)
