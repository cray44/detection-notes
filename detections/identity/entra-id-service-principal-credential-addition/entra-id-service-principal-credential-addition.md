# Entra ID Service Principal Credential Addition

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

Detect when a new password or certificate credential is added to an existing Entra ID (Azure AD) service principal by an interactive user or unexpected identity. This is APT29's primary post-compromise persistence technique in cloud environments — after gaining access, they add credentials to high-privilege service principals to establish a durable, MFA-resistant backdoor that survives password resets and account remediation.

## ATT&CK Categorization

- **Tactic:** TA0003 — Persistence
- **Tactic:** TA0004 — Privilege Escalation
- **Technique:** T1098.001 — Account Manipulation: Additional Cloud Credentials

## Threat Context

APT29 (Midnight Blizzard/NOBELIUM) made service principal credential addition a defining technique of the SolarWinds/SUNBURST intrusion (2020) and subsequent cloud campaigns documented through 2025. Microsoft's January 2021 MSTIC post-mortem and CISA Advisory AA21-008A both detail how APT29 used `Add service principal credentials` to backdoor OAuth applications with delegated or application-level permissions — particularly those with `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, or `Mail.ReadWrite` API permissions. The technique is effective because service principal credentials are independent of the user whose account was originally compromised: rotating the human user's password does not revoke the SP credential. The backdoor persists until the SP credential is explicitly removed.

Scattered Spider used the same primitive in the MGM Resorts and Caesars Entertainment intrusions (2023), adding credentials to cloud service principals after gaining initial access via helpdesk social engineering. CISA's joint advisory on Scattered Spider (AA23-320A) specifically identifies cloud identity persistence as a post-compromise priority for this group.

The pattern is also documented as a common goal of illicit OAuth app consent grant attacks: once a victim consents to a malicious app, the attacker immediately adds long-lived credentials to the underlying service principal to lock in persistence independent of the consent.

## Strategy Abstract

Entra ID records every credential change to service principals in the Azure AD Audit Log under the operation `Add service principal credentials`. The event captures who initiated the change, which service principal was targeted, and what type of credential was added (password/client secret vs. certificate). The detection runs risk scoring across three independent dimensions:

| Signal | Risk contribution | Rationale |
|---|---|---|
| Initiator is an interactive user (not a service account/pipeline) | +40 | Legitimate secret rotation happens via automated pipelines or DevOps service accounts, not interactive logins |
| Service principal holds high-privilege API permissions | +40 | Backdooring a low-privilege SP is noisy with little benefit; attackers target SPs with directory-level or mail-read permissions |
| Credential added outside business hours | +20 | Automation runs at all hours; human-initiated changes after-hours warrant scrutiny |
| Credential type is Password (client secret) | +10 | Certificates are operationally heavier and less common for attacker-generated credentials |
| SP created within last 7 days with credential added immediately | +30 | New SP + immediate credential addition is a common attacker "land and persist" pattern |

Scores ≥ 50 are surfaced. The `Add service principal credentials` operation alone is not high-confidence — legitimate DevOps activity generates it constantly. Scoring on who did it and what they targeted separates signal from noise.

## Technical Context

**Data source:** Entra ID Audit Logs via Splunk Add-on for Microsoft Cloud Services — sourcetype `mscs:azure:audit`

**Sigma rule:** [`rules/identity/entra-id-service-principal-credential-addition.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/identity/entra-id-service-principal-credential-addition.yml) in sigma-to-spl

> The Sigma rule matches the core operation (`Add service principal credentials`) and filters to user-initiated events. The SPL below adds risk scoring on permission level, time-of-day, and credential type — none of which are expressible in Sigma condition syntax.

**Key fields:**

| Field | Description |
|---|---|
| `operationName` | Always `Add service principal credentials` for this detection |
| `properties.initiatedBy.user.userPrincipalName` | UPN of the initiating user — absent if initiated by a service/app |
| `properties.initiatedBy.app.displayName` | App/service that initiated the change — present for automated pipeline activity |
| `properties.initiatedBy.user.ipAddress` | Source IP of the initiating user — useful for geolocation analysis |
| `properties.targetResources{}.displayName` | Display name of the service principal being modified |
| `properties.targetResources{}.id` | Object ID of the target service principal — use for Graph API enrichment |
| `properties.additionalDetails{}.value` (key=`CredentialType`) | `Password` or `AsymmetricX509Cert` — credential type being added |
| `result` | `success` or `failure` — filter to `success` for persistence events |
| `time` | Event timestamp — used for business-hours scoring |

**Environment assumptions:**
- Azure AD Audit Logs are forwarded to Splunk via the Splunk Add-on for Microsoft Cloud Services or the Microsoft Azure Add-on
- A lookup `entra_service_principals_privileged.csv` exists mapping SP object IDs to their highest-sensitivity API permission (populated from Microsoft Graph `servicePrincipals/{id}/appRoleAssignments` or `oauth2PermissionGrants`)
- Known DevOps pipeline service account UPNs are stored in `devops_service_accounts.csv` for suppression
- Business hours are defined as 07:00–19:00 in the tenant's primary timezone

## Performance Notes

- **Estimated event volume:** `Add service principal credentials` operations are low-volume — typically dozens per day in a mid-size enterprise, concentrated during sprint cycles and deployment windows. This is not a high-throughput detection.
- **Indexed fields:** `sourcetype` and `operationName` are indexed in most deployments using the Microsoft Azure Add-on. `properties.initiatedBy.user.userPrincipalName` is a JSON extraction — `spath` performance is acceptable at this event volume.
- **Recommended time range:** `-60m` on a 30-minute schedule. The event is discrete and low-volume; near-real-time is achievable without resource pressure.
- **Enrichment cost:** The risk scoring on SP permission level requires a lookup join — pre-populate `entra_service_principals_privileged.csv` via a scheduled search querying the Microsoft Graph API, not inline in this detection. Keep the detection query self-contained.

## Blind Spots

- **Credential addition via MS Graph API with app-only context:** If the attacker uses a compromised service principal (not a user account) to add credentials to another SP, `initiatedBy.user` will be absent and the user-initiated risk score won't fire. Monitor `initiatedBy.app` for unexpected or recently-registered app names as a secondary signal.
- **Credential addition to newly-created SPs:** If the attacker creates a net-new service principal and immediately adds credentials, the creation event and the credential addition event are separate — this detection catches the credential add, but pivoting to the SP creation event provides fuller context.
- **Legitimate automated credential rotation:** Mature environments rotate SP credentials on automated schedules (Azure Key Vault rotation policies, GitHub Actions OIDC). Without a DevOps service account allowlist, these generate false positives that drown out real events.
- **PIM-activated roles:** A user who PIM-activates a highly-privileged role and immediately adds SP credentials will fire this detection but may be a legitimate administrator. PIM activation audit events are corroborating context, not exculpatory.
- **Certificate credentials:** Attacker-generated certificates are less common but harder to detect via the credential type signal alone — a self-signed certificate added by an interactive user to a high-privilege SP is equally suspicious. Don't over-weight the `Password` type signal.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| Automated DevOps pipeline rotating SP credentials | `initiatedBy.app` will be present (not `initiatedBy.user`); initiating app name will match known CI/CD tooling; timing will be consistent with deployment schedules |
| IT admin manually rotating a compromised SP secret | `initiatedBy.user` is a known admin UPN; correlate with helpdesk ticket; typically happens during business hours with a corresponding secret deletion shortly after |
| New application onboarding by a developer | SP will be recently created; initiating user is a developer account; Microsoft Graph explorer or Azure Portal user agent; low-privilege SP |
| Key Vault automated rotation | Initiating identity will be the Azure Key Vault service; `initiatedBy.app.displayName` = `Azure Key Vault`; highly consistent timing pattern |

## Validation

**Test data:** See [`test-data/`](test-data/) alongside this file — includes malicious events (APT29-style interactive user adding credentials to a high-privilege SP after-hours) and benign events (automated pipeline rotation, Key Vault-initiated rotation).

Reproduce in a lab tenant with appropriate permissions:

```bash
# Add a client secret to a service principal via Azure CLI (simulates attacker action)
az ad sp credential reset \
  --id <service-principal-object-id> \
  --append \
  --years 2

# Or via MS Graph API
POST https://graph.microsoft.com/v1.0/servicePrincipals/{id}/addPassword
{
  "passwordCredential": {
    "displayName": "backup-key",
    "endDateTime": "2028-01-01T00:00:00Z"
  }
}
```

Expected result: Entra ID Audit Log event with `operationName = "Add service principal credentials"`, `initiatedBy.user.userPrincipalName` populated with the test account, `targetResources[0].displayName` showing the target SP, and `additionalDetails` containing `CredentialType: Password`.

**SPL (primary):**
```spl
sourcetype=mscs:azure:audit operationName="Add service principal credentials" result=success
| spath input=_raw
| eval initiator_upn=coalesce('properties.initiatedBy.user.userPrincipalName', "")
| eval initiator_app=coalesce('properties.initiatedBy.app.displayName', "")
| eval sp_name='properties.targetResources{0}.displayName'
| eval sp_id='properties.targetResources{0}.id'
| eval cred_type=mvindex(mvfilter(match('properties.additionalDetails{}.key', "CredentialType")),0)
| eval hour=tonumber(strftime(_time, "%H"))
| eval is_interactive=if(initiator_upn!="", 1, 0)
| eval is_after_hours=if(hour < 7 OR hour > 19, 1, 0)
| eval is_password_cred=if(like(cred_type, "%Password%"), 1, 0)
| lookup entra_service_principals_privileged.csv sp_id AS sp_id OUTPUT permission_level
| eval is_privileged_sp=if(isnotnull(permission_level) AND permission_level="high", 1, 0)
| lookup devops_service_accounts.csv upn AS initiator_upn OUTPUT is_devops
| where isnull(is_devops) OR is_devops!="true"
| eval risk_score=0
| eval risk_score=risk_score + if(is_interactive=1, 40, 0)
| eval risk_score=risk_score + if(is_privileged_sp=1, 40, 0)
| eval risk_score=risk_score + if(is_after_hours=1, 20, 0)
| eval risk_score=risk_score + if(is_password_cred=1, 10, 0)
| where risk_score >= 50
| table _time, initiator_upn, initiator_app, sp_name, sp_id, cred_type, permission_level, is_after_hours, risk_score
| sort - risk_score
```

> The `coalesce` on `initiator_upn` and `initiator_app` handles both user-initiated and app-initiated events in a single pass. The DevOps allowlist lookup uses `isnull(is_devops)` to pass rows with no match (the expected case) while suppressing known pipeline accounts. `spath` on `_raw` is used here because the Add-on's automatic field extractions for nested `additionalDetails` arrays are inconsistent across versions — direct spath is more reliable for this event type.

## Response

1. Identify the target service principal — look up its API permissions and OAuth grants via the Azure portal or MS Graph (`GET /servicePrincipals/{id}/appRoleAssignments`)
2. Determine whether the newly-added credential has been used: query Entra ID Sign-in Logs for `servicePrincipalId` matching the SP, filtering to sign-ins occurring after the credential addition timestamp
3. If credential has been used from an unexpected IP: treat as confirmed persistence, revoke all credentials on the SP (`Remove-MgServicePrincipalPassword`), review all API actions taken by the SP since compromise
4. Correlate the initiating user account with Entra Sign-in Logs — if the account itself shows anomalous sign-in behavior (new location, new device, token theft indicators), the user account is likely the initial access vector
5. Audit all other service principals for credential additions in the same window — attackers frequently backdoor multiple SPs in a single session

## References

- [Palantir ADS Framework](https://github.com/palantir/alerting-and-detection-strategy-framework)
- [MITRE ATT&CK T1098.001](https://attack.mitre.org/techniques/T1098/001/)
- [MSTIC — NOBELIUM targeting delegated administrative privileges](https://www.microsoft.com/en-us/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/)
- [CISA AA21-008A — Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)
- [CISA AA23-320A — Scattered Spider](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Microsoft — Backdoor accounts via service principal credential addition](https://www.microsoft.com/en-us/security/blog/2023/03/22/dev-1101-enables-high-volume-aitm-campaigns-with-open-source-phishing-kit/)
- [Sigma rule](https://github.com/cray44/sigma-to-spl/blob/main/rules/identity/entra-id-service-principal-credential-addition.yml)
