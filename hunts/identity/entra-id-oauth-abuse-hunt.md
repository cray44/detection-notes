# Hunt: Entra ID OAuth Abuse and Persistent Access

## Hypothesis

> "We believe that a threat actor has established persistent access to our Entra ID tenant through OAuth application abuse because APT29/Midnight Blizzard TTPs (AA24-057A) demonstrate long-term persistence via illicit app consents and service principal credential additions — behaviors that produce low-volume, low-noise audit events that blend with normal developer activity and are rarely reviewed. This would manifest as unexpected service principal credential additions, new high-privilege app role assignments, or OAuth consent grants to unfamiliar applications in Entra ID audit logs."

**Structured form:**
- **Actor behavior:** Abusing OAuth application framework to establish persistence — adding credentials to existing service principals, granting consent to attacker-controlled apps, or creating new app registrations with elevated permissions
- **Observable signal:** Audit events for `Add service principal credentials`, `Consent to application`, `Add app role assignment to service principal`, or new `AppRegistration` events from unexpected identities or outside business hours
- **Data source:** Entra ID audit logs via Microsoft Defender / Sentinel (`sourcetype=o365:management:activity` or `sourcetype=azure:aad:audit`)
- **Confidence:** Medium-High — these events are definitively logged; the challenge is distinguishing malicious from legitimate developer activity

---

## ATT&CK Mapping

- **Tactic:** TA0003 — Persistence, TA0006 — Credential Access
- **Technique:** T1098.001 — Account Manipulation: Additional Cloud Credentials
- **Related:** T1528 — Steal Application Access Token, T1550.001 — Use Alternate Authentication Material: Application Access Token

---

## Threat Context

APT29 (Midnight Blizzard / Cozy Bear) used OAuth app abuse extensively in the SolarWinds follow-on campaign and the Microsoft corporate network intrusion disclosed in January 2024. CISA AA24-057A documents the specific TTP: compromise a low-privilege account, use it to grant consent to a new attacker-controlled OAuth app, then use that app's token for persistent access that survives password resets.

Key insight: OAuth app tokens are often not invalidated during incident response because responders focus on user accounts. An app with `Mail.Read` delegated permission on a compromised user's mailbox continues to work after the user's password is reset.

This hunt is most valuable run monthly with a 30–90 day lookback — the persistence mechanisms are designed to be planted and forgotten.

---

## Data Requirements

| Requirement | Detail |
|---|---|
| **Data source** | Entra ID / Azure AD audit logs — `sourcetype=o365:management:activity` (Unified Audit Log) or `sourcetype=azure:aad:audit` |
| **Minimum retention** | 30 days preferred; 90 days ideal for detecting low-frequency events |
| **Key fields** | `Operation` / `operationName`, `UserId` / `initiatedBy.user.userPrincipalName`, `ObjectId` / `targetResources`, `time`, `ipAddress` |
| **Environment assumptions** | Entra ID audit logs flowing to Splunk. A baseline of known service principals and app registrations is helpful but not required. |

---

## Hunt Queries

### Stage 1 — Surface all OAuth/app registration events in the hunt window

Pulls every audit event category that matters for OAuth abuse into one view. Volume scan before filtering.

```spl
index=cloud (sourcetype=o365:management:activity OR sourcetype=azure:aad:audit) earliest=-30d
| eval operation=coalesce(Operation, operationName)
| search operation IN (
    "Add service principal credentials.",
    "Add service principal.",
    "Update service principal.",
    "Consent to application.",
    "Add app role assignment to service principal.",
    "Add app role assignment grant to user.",
    "Add OAuth2PermissionGrant.",
    "Add application.",
    "Update application.",
    "Add delegated permission grant."
  )
| eval actor=coalesce(UserId, 'initiatedBy.user.userPrincipalName', "unknown")
| eval target=coalesce(ObjectId, mvindex('targetResources{}.displayName', 0), "unknown")
| stats
    count AS event_count,
    values(operation) AS operations,
    earliest(_time) AS first_seen,
    latest(_time) AS last_seen
    BY actor target
| sort - event_count
```

> *This gives a per-actor/per-target event count. Actors with high event counts are likely developers or automation. Actors with low counts and sensitive operations (credential additions, consent grants) deserve investigation.*

---

### Stage 2 — Isolate high-risk operations by non-service-account actors

Credential additions and consent grants from interactive users (non-service accounts) are higher risk than the same operations from known DevOps pipelines.

```spl
index=cloud (sourcetype=o365:management:activity OR sourcetype=azure:aad:audit) earliest=-30d
| eval operation=coalesce(Operation, operationName)
| search operation IN (
    "Add service principal credentials.",
    "Consent to application.",
    "Add app role assignment to service principal.",
    "Add OAuth2PermissionGrant.",
    "Add delegated permission grant."
  )
| eval actor=coalesce(UserId, 'initiatedBy.user.userPrincipalName', "unknown")
| eval ip=coalesce(ClientIP, ipAddress, 'initiatedBy.user.ipAddress')
| eval target_app=coalesce(mvindex('targetResources{}.displayName', 0), ObjectId, "unknown")
| eval hour=strftime(_time, "%H")
| eval outside_hours=if(hour < "08" OR hour > "18", "YES", "no")
| where NOT match(actor, "(?i)svc-|service|pipeline|automation|devops")
| table _time actor ip operation target_app outside_hours
| sort - outside_hours _time
```

> *Sort by `outside_hours=YES` first — malicious operations frequently occur during off-hours to minimize detection. Flag any credential additions to service principals the actor does not own.*

---

### Stage 3 — Find apps that received admin consent to high-risk permissions

Admin consent to `Mail.Read`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, or similar application permissions is a key indicator.

```spl
index=cloud (sourcetype=o365:management:activity OR sourcetype=azure:aad:audit) earliest=-30d
| eval operation=coalesce(Operation, operationName)
| search operation IN ("Consent to application.", "Add OAuth2PermissionGrant.", "Add app role assignment to service principal.")
| eval actor=coalesce(UserId, 'initiatedBy.user.userPrincipalName')
| eval target_app=coalesce(mvindex('targetResources{}.displayName', 0), "unknown")
| eval permissions=coalesce(
    mvindex('targetResources{}.modifiedProperties{}.newValue', 0),
    'modifiedProperties{}.newValue'
  )
| eval high_risk=if(
    match(permissions, "(?i)Mail\.ReadWrite|Files\.ReadWrite\.All|Directory\.ReadWrite|RoleManagement|AppRoleAssignment\.ReadWrite"),
    "YES", "no"
  )
| where high_risk="YES" OR isnull(high_risk)
| table _time actor target_app permissions high_risk
| sort - high_risk _time
```

> *Any `high_risk=YES` row warrants manual investigation regardless of who the actor is. `RoleManagement` and `AppRoleAssignment.ReadWrite` permissions in particular can be used to self-escalate.*

---

## Baseline Criteria

- **Typical volume:** In a 100-user tenant, expect 5–20 legitimate app registration / consent events per week from developers. Enterprise tenants with active DevOps pipelines will be noisier.
- **Known-good patterns:** CI/CD service accounts adding credentials to deployment service principals (these should have consistent naming patterns). IT admin accounts granting consent to known SaaS tools (document these in a lookup).
- **Threshold guidance:** Any single interactive user performing > 3 credential operations on service principals in a 30-day window is worth investigating. A user who has never performed these operations before is automatically interesting.

---

## Analysis Guide

**High confidence indicators (escalate):**
- Service principal credential addition followed within 24 hours by sign-in from an unknown IP using that service principal
- Admin consent granted to an app registered < 7 days ago, especially with `Directory.ReadWrite` or mail permissions
- App role assignment granting `Global Administrator` or `Privileged Role Administrator` to any service principal not in your known-good list
- Any of these operations performed from a Tor exit node, VPN, or hosting provider IP

**Requires investigation:**
- Credential addition to a service principal by a user who is not the service principal's owner
- Consent grant performed outside business hours by an account with no prior history of app management
- New app registration with a name similar to a legitimate internal app (typosquatting)

**Likely benign (document and close):**
- Known CI/CD pipeline service account performing credential rotation on schedule
- IT admin granting consent to a vetted SaaS application that was just purchased
- Developer creating app registration in a dev/test tenant with no production permissions

---

## Pivot Queries

### Pivot 1 — Sign-ins using the suspicious service principal

After identifying a suspicious credential addition, check whether the new credential was used.

```spl
index=cloud sourcetype=azure:aad:signin earliest=-30d
| where AppId="<CANDIDATE_APP_ID>" OR ServicePrincipalName="<CANDIDATE_SP_NAME>"
| stats
    count AS signin_count,
    values(IPAddress) AS ips,
    values(Location) AS locations,
    values(ResourceDisplayName) AS resources_accessed,
    earliest(_time) AS first_signin,
    latest(_time) AS last_signin
    BY AppId ServicePrincipalName
```

---

### Pivot 2 — Mail or file access by the suspicious app

If the app has `Mail.Read` or `Files.Read` permissions, check whether it accessed data.

```spl
index=cloud sourcetype=o365:management:activity earliest=-30d
| where ClientAppId="<CANDIDATE_APP_ID>"
| stats
    count AS operation_count,
    values(Operation) AS operations,
    values(UserId) AS affected_users,
    earliest(_time) AS first_activity,
    latest(_time) AS last_activity
    BY ClientAppId
```

---

### Pivot 3 — Full audit history for the actor who made the change

Understand what else the actor account has done — look for preceding account compromise indicators.

```spl
index=cloud (sourcetype=o365:management:activity OR sourcetype=azure:aad:audit OR sourcetype=azure:aad:signin) earliest=-30d
| eval actor=coalesce(UserId, 'initiatedBy.user.userPrincipalName', UserPrincipalName)
| where actor="<CANDIDATE_ACTOR_UPN>"
| table _time sourcetype Operation IPAddress ResultStatus
| sort _time
```

---

## Escalation Criteria

- **Escalate immediately if:** A suspicious service principal has been used to authenticate (Pivot 1 returns results), or if a credential addition was followed by access to executive mailboxes or HR/finance file shares
- **Investigate further before escalating if:** Credential addition occurred but no sign-in activity observed yet — assess whether the credential is still valid and revoke if unrecognized
- **Document and close if:** Operation is attributed to a known DevOps pipeline or IT admin performing a documented change, verified against change management records

---

## Hunt Log

| Date | Analyst | Environment | Findings | Outcome |
|---|---|---|---|---|
| | | | | |

---

## References

- [CISA AA24-057A — Midnight Blizzard / SVR targeting](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a)
- [Microsoft MSRC — Midnight Blizzard attack on Microsoft corporate systems](https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/)
- [MITRE ATT&CK T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [Related detection writeup — Entra ID Service Principal Credential Addition](../../detections/identity/entra-id/entra-id-service-principal-credential-addition.md)
- [Related detection writeup — Azure Illicit OAuth App Consent Grant](../../detections/cloud/azure-oauth/azure-illicit-oauth-consent-grant.md)
