# Azure Illicit OAuth App Consent Grant

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

Detect consent phishing attacks where a threat actor tricks a user — or compromises an administrator — into granting a malicious OAuth application persistent, delegated access to email, files, or directory data in Microsoft 365. Unlike credential theft, OAuth consent survives password resets and MFA changes; a single consent event gives the attacker a persistent foothold that persists until the grant is explicitly revoked. This is the dominant initial access vector for BEC campaigns targeting Microsoft 365 tenants.

## ATT&CK Categorization

- **Tactic:** TA0006 — Credential Access
- **Tactic:** TA0009 — Collection
- **Technique:** T1528 — Steal Application Access Token

## Threat Context

APT29 (Midnight Blizzard) used illicit OAuth consent grants as a primary persistence mechanism in their compromise of Microsoft corporate email in January 2024, documented in CISA Advisory AA24-057A. The same technique appeared in their 2021 SolarWinds-adjacent operations — the attacker registered OAuth apps impersonating legitimate Microsoft services, obtained tenant-wide admin consent through a compromised global admin, and maintained long-lived access via refresh tokens that survived multiple incident response cycles.

The technique has been widely commoditized. Proofpoint tracked multiple financially motivated threat actors using consent phishing at scale in 2022–2023, specifically targeting organizations with permissive OAuth app registration policies. The attack requires no exploit: the attacker registers a plausible-looking app ("Microsoft Teams Update", "OneDrive Backup"), sends a phishing link to the OAuth authorization URL, and waits for a user to click Accept. The resulting `offline_access` + `Mail.Read` grant persists indefinitely.

CISA's 2022 guidance on MFA phishing (AA22-074A) specifically calls out OAuth consent abuse as a post-MFA-bypass persistence mechanism, noting that password reset alone is insufficient remediation.

## Strategy Abstract

Every OAuth permission grant in Entra ID generates an audit event in the ApplicationManagement category: `Consent to application` for delegated (user-context) grants and `Add OAuth2PermissionGrant` for grants made via the Microsoft Graph API. The audit event records who consented, which app received the grant, and the specific permission scopes that were granted.

The detection is risk-scored across four independent signals:

| Signal | Risk contribution | Rationale |
|---|---|---|
| Admin consent grant (`IsAdminConsent=True`) | +60 | Grants permissions to all users in the tenant, not just the consenting user |
| High-risk mail scope (Mail.Send, Mail.ReadWrite, EWS.AccessAsUser) | +40 | Enables BEC: read and send email as the victim without their credentials |
| Directory write scope (Directory.ReadWrite, RoleManagement.ReadWrite, Application.ReadWrite) | +50 | Enables privilege escalation: modify tenant configuration or create new privileged apps |
| File write scope (Files.ReadWrite.All, Sites.ReadWrite.All) | +30 | Enables data exfiltration and ransomware staging via SharePoint/OneDrive |
| Persistent token scope (`offline_access`) | +15 | Grants refresh token that survives session expiry and password reset |

Any grant scoring ≥ 40 is surfaced. Admin consent with directory write scope (score ≥ 110) is near-zero false positive in a change-controlled environment.

## Technical Context

**Data source:** Entra ID Audit Logs via Splunk Add-on for Azure — sourcetype `azure:aad:audit`, index `azure`. The same events are available as `o365:management:activity` (Office 365 UAL) with `Workload=AzureActiveDirectory`; adjust field names accordingly if using the M365 add-on.

**Sigma rule:** [`rules/cloud/azure-illicit-oauth-consent-grant.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/cloud/azure-illicit-oauth-consent-grant.yml) in sigma-to-spl

> Sigma covers the event type filter (operationName, category, result). Sigma cannot parse the embedded `additionalDetails` JSON array to extract granted permission scopes or the `IsAdminConsent` flag, nor can it apply weighted risk scoring. The SPL below handles scope parsing and risk scoring via `mvexpand` + `spath` on the nested `additionalDetails` structure.

**Key fields:**

| Field | Description |
|---|---|
| `operationName` | `Consent to application` (user-initiated) or `Add OAuth2PermissionGrant` (API-initiated) |
| `category` | `ApplicationManagement` — filter to this to avoid noise from sign-in and provisioning logs |
| `result` | `success` — filter to completed grants; failed attempts are a separate signal |
| `properties.initiatedBy.user.userPrincipalName` | UPN of the user who clicked consent — the potential phishing victim |
| `properties.initiatedBy.user.ipAddress` | Source IP of the consent action — flag non-corporate IPs or VPN egress |
| `properties.targetResources{0}.displayName` | Display name of the OAuth app receiving the grant — attacker-controlled apps often impersonate Microsoft services |
| `properties.targetResources{0}.appId` | Application (client) ID — pivot to Entra app registration logs to check publisher verification and registration date |
| `properties.additionalDetails{}.key=IsAdminConsent` | `True` if this is an admin consent grant affecting all users |
| `properties.additionalDetails{}.key=Permissions` | Space-separated list of granted OAuth scopes |
| `correlationId` | Links this audit event to the associated sign-in log entry for the same session |

**Environment assumptions:**
- Entra ID Audit Logs are forwarded to Splunk via the Splunk Add-on for Azure (Diagnostic Settings → Log Analytics → Splunk HEC, or direct API pull)
- The `properties` field is indexed as a raw JSON string; `spath` extracts sub-fields at query time
- A `trusted_oauth_apps.csv` lookup exists listing known-good app IDs for suppression (ServiceNow, Salesforce, Zoom, Slack app IDs from your vendor list)
- P1/P2 licensing is required for Entra ID Audit Logs; these events are not available in free-tier Azure AD

## Performance Notes

- **Estimated event volume:** OAuth consent events are low-volume — typically 10–200 events/day in a 5,000-user tenant. Unlike sign-in logs (millions/day), audit log volume is manageable. Real-time alerting is viable.
- **Indexed fields:** `operationName`, `category`, and `result` should be extracted at index time via the add-on. Confirm with `| tstats count WHERE index=azure sourcetype=azure:aad:audit by operationName` before scheduling.
- **`mvexpand` cost:** The `additionalDetails` array expansion doubles event count briefly. With audit log volumes this is negligible.
- **Recommended time range:** Run as a real-time alert with a 5-minute scheduled search over the prior 15 minutes. Consent phishing windows are short — the attacker's infrastructure may be taken down quickly.
- **Acceleration:** Not needed at this event volume. A standard scheduled search is appropriate.
- **Lookup table:** Maintain a `trusted_oauth_apps.csv` with columns `app_id,app_name,owner,approved_date`. Suppress matches as expected behavior; alert on anything not in the list above a risk threshold.

## Blind Spots

- **Application permission grants (app-only consent):** When an admin grants application permissions (not delegated), the audit event is `Add app role assignment to service principal`, not `Consent to application`. This detection misses that event type. A separate detection on `Add app role assignment` with role IDs for Mail.Read, Files.Read.All, and Directory.Read.All is required for full coverage.
- **Pre-consented apps and admin-approved app registrations:** If an admin pre-configures an app as "admin consent required" and then approves it through the admin consent workflow, the consent may not generate a standard audit event in all Entra ID configurations. Validate in your tenant.
- **IaC-managed consent grants:** Terraform `azuread_service_principal_delegated_permission_grant` resources and Azure AD PowerShell `New-MgOauth2PermissionGrant` generate the same events as manual consent. These are legitimate but indistinguishable at the audit log level without correlating to IaC pipeline identity (a service principal, not a human UPN).
- **Microsoft first-party app consents:** Users frequently consent to legitimate Microsoft-published apps (Planner, To-Do, Viva Insights) with broad delegated permissions. These will score high if `offline_access` + `Mail.ReadWrite` is in scope. Suppress by verified Microsoft publisher flag or known Microsoft app IDs.
- **Consent events generated by compromised legitimate apps:** If an attacker compromises an existing, trusted OAuth app (rather than registering a new one) and uses it to re-request broader permissions, the consenting app name is familiar — the only signal is the scope change. This detection does not baseline historical consent scope per app.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| IT team provisioning a new SaaS integration (Salesforce, Zendesk, DocuSign) | Check `initiator_upn` — should be a known IT/admin account. Verify the `target_app_id` against your vendor's documented app ID. Add to `trusted_oauth_apps.csv` after confirmation. |
| Developer testing OAuth flows against a dev/test tenant app | Check if the app registration is in the same tenant (internal app). Internal apps registered by the same organization are lower risk than third-party apps. |
| Admin consent granted during a planned enterprise app rollout | Should correlate with a change ticket. Check whether a change window was open. `initiator_ip` should be a corporate IP. |
| Microsoft 365 ecosystem apps (Teams tabs, SharePoint add-ins) | Verify `target_app_id` against Microsoft's published first-party app ID list. These apps often request Mail.Read and Files.ReadWrite for legitimate functionality. |
| Security tools that use Graph API delegated permissions (CASB, DLP) | Check `initiator_upn` — security tool onboarding is typically done by a security admin UPN. Verify with the tool vendor's documented permission requirements. |

## Validation

**Test data:** See [`test-data/`](test-data/) — includes malicious samples (admin consent grant for a high-risk scope app, user consent with Mail.Send + offline_access) and benign samples (low-risk app consent, Microsoft first-party app).

**Lab reproduction (requires Entra ID test tenant):**

```bash
# Register a test app in Entra ID via Azure CLI
az ad app create --display-name "Test Consent Phishing App" \
  --required-resource-accesses '[{
    "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      {"id": "e383f46e-2787-4529-855e-0e479a3ffac0", "type": "Scope"},
      {"id": "024d486e-b451-40bb-833d-3e66d98c5c73", "type": "Scope"}
    ]
  }]'
# Resource access IDs above: Mail.Send (e383f...) and offline_access (024d...)

# Generate the consent URL and open in a browser logged in as a test user
# The consent audit event will appear in Entra ID Audit Logs within 1-2 minutes
```

Expected in Entra ID Audit Logs: `operationName="Consent to application"`, `result=success`, `additionalDetails` containing `IsAdminConsent=False` and `Permissions=openid profile Mail.Send offline_access`.

In Splunk after the SPL runs: event appears with `risk_score=55` (`has_mail_write=1` → +40, `has_offline=1` → +15), `confidence=LOW`, surfaced for review.

**SPL (primary):**

```spl
index=azure sourcetype=azure:aad:audit
| where category="ApplicationManagement"
| where operationName IN ("Consent to application", "Add OAuth2PermissionGrant")
| where result="success"
| spath input=properties output=initiator_upn    path=initiatedBy.user.userPrincipalName
| spath input=properties output=initiator_ip     path=initiatedBy.user.ipAddress
| spath input=properties output=target_app_name  path=targetResources{0}.displayName
| spath input=properties output=target_app_id    path=targetResources{0}.appId
| spath input=properties output=addl_details     path=additionalDetails{}
| mvexpand addl_details
| spath input=addl_details path=key   OUTPUT addl_key
| spath input=addl_details path=value OUTPUT addl_value
| eval is_admin_consent = if(addl_key="IsAdminConsent" AND lower(addl_value)="true", 1, 0)
| eval scopes_raw = if(addl_key="Permissions", addl_value, null())
| stats
    max(is_admin_consent)  AS is_admin_consent,
    values(scopes_raw)     AS granted_scopes,
    values(initiator_ip)   AS initiator_ip,
    first(target_app_name) AS target_app_name,
    first(target_app_id)   AS target_app_id,
    min(_time)             AS event_time
    BY correlationId, initiator_upn, operationName
| lookup trusted_oauth_apps.csv app_id AS target_app_id OUTPUT app_name AS trusted_app_name
| where isnull(trusted_app_name)
| eval scope_str = mvjoin(granted_scopes, " ")
| eval risk_score = 0
| eval risk_score = risk_score + if(is_admin_consent=1, 60, 0)
| eval has_mail_write  = if(match(scope_str, "Mail\.Send|Mail\.ReadWrite|EWS\.AccessAsUser\.All"), 1, 0)
| eval has_dir_write   = if(match(scope_str, "Directory\.ReadWrite|RoleManagement\.ReadWrite|Application\.ReadWrite"), 1, 0)
| eval has_file_write  = if(match(scope_str, "Files\.ReadWrite|Sites\.ReadWrite"), 1, 0)
| eval has_offline     = if(match(scope_str, "offline_access"), 1, 0)
| eval risk_score = risk_score + if(has_mail_write=1,  40, 0)
| eval risk_score = risk_score + if(has_dir_write=1,   50, 0)
| eval risk_score = risk_score + if(has_file_write=1,  30, 0)
| eval risk_score = risk_score + if(has_offline=1,     15, 0)
| where risk_score >= 40
| eval confidence = case(risk_score >= 100, "HIGH", risk_score >= 70, "MEDIUM", true(), "LOW")
| eval event_time = strftime(event_time, "%Y-%m-%d %H:%M:%S")
| sort - risk_score
| table initiator_upn, initiator_ip, target_app_name, target_app_id, operationName, granted_scopes, is_admin_consent, has_mail_write, has_dir_write, has_file_write, has_offline, risk_score, confidence, event_time
```

> *Performance note:* `mvexpand` on `addl_details` temporarily expands each event into 2–5 rows (one per key in the additionalDetails array), then `stats BY correlationId` collapses them back to one row per consent event. The `trusted_oauth_apps.csv` lookup suppression must happen after the re-aggregation but before risk scoring to avoid suppressing events with partially matching IDs. The `isnull(trusted_app_name)` filter drops known-good apps before any scoring computation.

## Response

1. **Identify the consenting user** (`initiator_upn`) — contact them immediately. Ask whether they remember clicking an authorization prompt. Phishing victims often do not recall — the consent page looked legitimate. Urgency matters: the attacker may already be accessing mailbox contents.
2. **Revoke the OAuth grant immediately** — in Entra ID: Enterprise Applications → find the app by `target_app_id` → Users and Groups → remove the user's assignment, OR via PowerShell: `Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <id>`. This invalidates the refresh token within minutes.
3. **Audit what the app accessed** — query Microsoft Graph audit logs or Defender for Cloud Apps for activity by the app's service principal in the window since the consent event. Look for `Mail.Read` queries, file downloads, or directory enumeration.
4. **Pivot to sign-in logs** — use `correlationId` to find the associated sign-in event. Check `ipAddress`, user agent, and whether the sign-in succeeded. If the sign-in was from a foreign or VPN-anonymized IP, assume the account was specifically targeted.
5. **Review for additional consented apps** — check whether the same user or other users in the tenant consented to the same `target_app_id`. Consent phishing is often sent to entire organizations, not just one user.
6. **Harden OAuth policies** — if not already enforced, enable "Restrict user consent to apps from verified publishers" in Entra ID Consent and Permissions settings. This prevents users from consenting to unverified third-party apps without admin approval.

## References

- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [CISA Advisory AA24-057A — Russian SVR Compromise of Microsoft Corporate Email](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a)
- [Microsoft Security Blog — How to protect against app consent phishing](https://www.microsoft.com/en-us/security/blog/2021/11/30/how-to-protect-your-organization-against-app-consent-phishing/)
- [CISA Advisory AA22-074A — MFA phishing and OAuth abuse](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-074a)
- [Microsoft — Investigate and remediate risky OAuth apps](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth)
- [Sigma rule — azure-illicit-oauth-consent-grant.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/cloud/azure-illicit-oauth-consent-grant.yml)
