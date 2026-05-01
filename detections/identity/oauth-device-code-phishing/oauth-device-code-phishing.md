# OAuth Device Code Phishing — Suspicious Device Authorization Flow

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

Detect OAuth 2.0 device code phishing attacks where adversaries abuse the device authorization grant flow to steal authentication tokens without ever touching the victim's credentials or MFA device. This is APT29/Midnight Blizzard's primary initial access technique against cloud targets since 2024 — it bypasses every form of MFA and leaves no malware footprint.

## ATT&CK Categorization

- **Tactic:** TA0001 — Initial Access
- **Technique:** T1566.002 — Phishing: Spearphishing Link (initial lure delivery)
- **Outcome technique:** T1528 — Steal Application Access Token
- **Post-compromise:** T1078.004 — Valid Accounts: Cloud Accounts

## Threat Context

APT29 (Midnight Blizzard/NOBELIUM) used device code phishing extensively in documented 2024–2025 campaigns targeting government agencies, defense contractors, and cloud service providers. Microsoft Threat Intelligence [disclosed these TTPs in January 2025](https://www.microsoft.com/en-us/security/blog/2025/01/31/new-ttps-observed-in-midnight-blizzard-attacks/), noting the technique specifically because it bypasses conditional access policies configured to require MFA. Storm-0867 uses the same technique as a precursor to BEC and OAuth app consent abuse. Unlike traditional phishing, the victim sees no fake login page — they authenticate on a legitimate Microsoft domain, making technical controls and user training less effective.

## Strategy Abstract

The OAuth 2.0 Device Authorization Grant (RFC 8628) was designed for input-constrained devices — smart TVs, printers, IoT sensors — that cannot display a browser. The flow generates a short-lived user code that the user enters at a central auth URL (`microsoft.com/devicelogin`). An attacker abuses this by initiating the flow from their own infrastructure, extracting the user code, and delivering it to a victim via a phishing message ("Enter this code at microsoft.com/devicelogin to complete your security verification"). When the victim authenticates, the attacker's polling process receives fully valid access and refresh tokens — with no malware, no credential harvesting page, and no MFA prompt beyond the one the victim just completed.

Two behavioral signals distinguish malicious device code flows:

1. **Browser user agent on device code flow** — legitimate device code clients (Azure CLI, az PowerShell, VS Code extensions) are non-browser apps. A browser UA (`Mozilla/`, `Chrome/`, etc.) completing a device code flow indicates a human was directed to `devicelogin` — the victim completing the attacker's request.

2. **Successful device code auth from unmanaged/unregistered device** — attacker infrastructure is not enrolled in the tenant. A device code success with no registered `deviceId` and `isCompliant=False` narrows to either a personal device or attacker infrastructure. When combined with geolocation anomalies or unusual apps, the signal sharpens.

## Technical Context

**Data source:** Entra ID Sign-in Logs via [Microsoft Azure Active Directory Add-on for Splunk](https://splunkbase.splunk.com/app/3757)

**Sourcetype:** `azure:aad:signin`

**Sigma rule:** [`rules/identity/oauth-device-code-phishing.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/identity/oauth-device-code-phishing.yml) in sigma-to-spl

> The Sigma rule covers the core condition (device code success on non-compliant device). The SPL below adds browser UA risk scoring and multi-value aggregation not expressible in Sigma condition syntax.

**Key fields:**

| Field | Description |
|---|---|
| `AuthenticationProtocol` | Set to `deviceCode` for this flow — primary filter |
| `ResultType` | `0` = success; non-zero = failure (attacker polling while waiting for victim produces failures) |
| `DeviceDetail.isCompliant` | `True` only for Intune-enrolled, policy-compliant devices |
| `DeviceDetail.deviceId` | Empty or absent on attacker infrastructure |
| `UserAgent` | Browser UAs on device code flows are high-confidence indicators |
| `IPAddress` | Attacker's polling IP — may be geographically inconsistent with user |
| `AppDisplayName` | What OAuth app the token was issued for |
| `Location.city` / `Location.countryOrRegion` | Geographic context |

**Environment assumptions:**
- Entra ID Sign-in logs are forwarded to Splunk (near-real-time preferred; up to 15 min latency is acceptable)
- Microsoft Azure AD Add-on is installed and configured with a service principal
- Conditional access policy exists that requires compliant devices for sensitive apps — otherwise the `isCompliant` filter produces excessive volume

## Performance Notes

- **Estimated event volume:** Device code sign-ins are low volume relative to total auth events — typically <1% of sign-in log volume. In a 5,000-user tenant, expect 100–500 device code events per day from legitimate CLI usage.
- **Indexed fields:** `AuthenticationProtocol` and `ResultType` should be extracted at index time by the add-on; confirm with `| tstats count WHERE index=azure sourcetype=azure:aad:signin by AuthenticationProtocol` before scheduling.
- **Recommended time range:** `-24h` on an hourly schedule. For high-risk environments, `-1h` on a 15-minute schedule.
- **Acceleration:** Not required at this volume. If sign-in log volume is very high (>10M events/day), consider a summary index pre-filtered to `AuthenticationProtocol=deviceCode`.

## Blind Spots

- **Compliant device as attacker proxy:** If the attacker compromises a managed, Intune-enrolled device and initiates the device code flow from it, `isCompliant=True` will suppress this detection. The browser UA check still applies if the victim completes auth via browser.
- **Token theft via AiTM proxy (Evilginx/Modlishka):** Adversary-in-the-middle attacks steal tokens through a different mechanism — this detection does not cover them. See separate AiTM detection.
- **Non-Entra targets:** Device code phishing against AWS SSO, GitHub, or other OAuth providers produces no signal in this data source.
- **Delayed token use:** An attacker who steals a token but waits days before using it may have their initial authentication appear low-risk (no immediate anomalous resource access). Correlate with token use patterns, not just issuance.
- **Tenant-level device code disable:** If your tenant has blocked device code flow entirely via conditional access, this detection produces no signal — but you also have no exposure to this technique.

## False Positives

| False Positive | Triage Guidance |
|---|---|
| Azure CLI / Azure PowerShell from personal (unmanaged) device | `UserAgent` will be `python-requests`, `PowerShell`, or `MSAL`, not a browser UA. If browser UA is absent, check if the user's role requires CLI access from personal devices and suppress by user if confirmed. |
| VS Code Azure extensions on unmanaged dev machines | Same UA pattern as above — non-browser. Verify `AppDisplayName` matches expected dev tooling (Visual Studio Code, Microsoft Azure). |
| CI/CD pipeline using device code from build agent | Build agents typically have consistent IPs and non-browser UAs. Suppress by IP range or service principal if confirmed. |
| Microsoft Teams Rooms / Surface Hub | Dedicated device accounts with known device IDs. Suppress by `UserPrincipalName` pattern (e.g., `*-room@domain.com`) after verifying. |
| Legitimate first-time device enrollment | One-time event; after enrollment the device gets a `deviceId`. No repeat signals expected for the same user/device. |

## Validation

**Test data:** See [`test-data/`](test-data/) — includes malicious (browser UA, no device ID) and benign (CLI UA, legitimate app) sign-in log samples.

**Lab reproduction** (requires a test tenant — do not run against production):

```powershell
# Initiate device code flow using the public Azure PowerShell app client ID
# Run this from attacker-controlled machine; enter the user_code from a browser
$body = @{
    client_id = "1950a258-227b-4e31-a9cf-717495945fc2"  # Azure PowerShell (public client)
    scope     = "https://graph.microsoft.com/.default offline_access"
}
$init = Invoke-RestMethod `
    -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" `
    -Body $body

Write-Host "User code : $($init.user_code)"
Write-Host "Enter at  : $($init.verification_uri)"
Write-Host "Expires in: $($init.expires_in) seconds"

# Poll for token (simulates attacker waiting for victim)
$poll_body = @{
    client_id   = "1950a258-227b-4e31-a9cf-717495945fc2"
    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
    device_code = $init.device_code
}
do {
    Start-Sleep -Seconds 5
    try {
        $token = Invoke-RestMethod `
            -Method Post `
            -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
            -Body $poll_body
    } catch { $token = $null }
} until ($token)

Write-Host "Access token acquired for: $($token.scope)"
```

Expected result in Splunk: a `azure:aad:signin` event with `AuthenticationProtocol=deviceCode`, `ResultType=0`, browser `UserAgent` (from the machine that navigated to `devicelogin`), and empty or absent `DeviceDetail.deviceId`.

**SPL (primary):**

```spl
index=azure sourcetype="azure:aad:signin"
| where AuthenticationProtocol="deviceCode" AND ResultType="0"
| eval is_browser_ua=if(match(UserAgent,"(?i)(mozilla|chrome|safari|firefox|edge|msie|webkit)"),"true","false")
| eval is_managed=if('DeviceDetail.isCompliant'="True","true","false")
| eval has_device_id=if(isnotnull('DeviceDetail.deviceId') AND 'DeviceDetail.deviceId'!="","true","false")
| eval risk=case(
    is_browser_ua="true",                                 "HIGH",
    is_managed="false" AND has_device_id="false",         "HIGH",
    is_managed="false",                                   "MEDIUM",
    true(),                                               "LOW"
  )
| where risk IN ("HIGH","MEDIUM")
| stats
    count                           AS auth_count,
    values(IPAddress)               AS src_ips,
    values(Location.city)           AS cities,
    values(Location.countryOrRegion) AS countries,
    values(AppDisplayName)          AS apps,
    values(UserAgent)               AS user_agents,
    values(risk)                    AS risk_levels,
    max(_time)                      AS last_seen
    BY UserDisplayName, UserPrincipalName
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - auth_count
```

> *Performance note:* `AuthenticationProtocol` and `ResultType` filter first to reduce volume before any `eval`. The `match()` call on `UserAgent` is applied to an already-small result set. This search is safe to run over 24h without acceleration.

**KQL (community-translated, untested — Microsoft Sentinel `SigninLogs`):**

```kql
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0
| extend IsBrowserUA   = UserAgent matches regex @"(?i)(mozilla|chrome|safari|firefox|edge|msie|webkit)"
| extend IsCompliant   = tostring(DeviceDetail.isCompliant) == "True"
| extend HasDeviceId   = isnotempty(tostring(DeviceDetail.deviceId))
| extend RiskLevel = case(
    IsBrowserUA,                          "HIGH",
    not IsCompliant and not HasDeviceId,  "HIGH",
    not IsCompliant,                      "MEDIUM",
    "LOW")
| where RiskLevel in ("HIGH", "MEDIUM")
| summarize
    AuthCount  = count(),
    SourceIps  = make_set(IPAddress),
    Cities     = make_set(tostring(LocationDetails.city)),
    Countries  = make_set(tostring(LocationDetails.countryOrRegion)),
    Apps       = make_set(AppDisplayName),
    UserAgents = make_set(UserAgent),
    RiskLevels = make_set(RiskLevel),
    LastSeen   = max(TimeGenerated)
    by UserDisplayName, UserPrincipalName
| sort by AuthCount desc
```

## Response

1. **Confirm or deny phishing** — contact the user directly via phone or a separate channel (not Teams/email, which may be compromised). Ask if they entered a code at `microsoft.com/devicelogin` in the past 24 hours without initiating it themselves.
2. **If confirmed phishing — immediate containment:** Revoke all refresh tokens (`Revoke-MgUserSignInSession -UserId <UPN>` or Entra portal → User → Revoke sessions). This invalidates the stolen tokens.
3. **Determine what the stolen token accessed:** Query Sign-in logs for the attacker's IP for all activity after token issuance. Check Microsoft 365 audit logs for mail access, file downloads, app consent grants.
4. **Hunt for persistence:** Check for new OAuth app consent grants, inbox forwarding rules, mail delegation, new service principal credentials, and guest account additions created within 24h of the device code auth.
5. **Harden:** Enable a Conditional Access policy blocking device code flow for all users except explicit exceptions (break-glass accounts, known build agent IPs). Most environments have no legitimate need for browser-based device code auth.
6. **If token was used for lateral movement or data access:** Escalate to full IR — scope the blast radius before assuming a single token revocation is sufficient.

## References

- [Microsoft Threat Intelligence: New TTPs Observed in Midnight Blizzard Attacks (Jan 2025)](https://www.microsoft.com/en-us/security/blog/2025/01/31/new-ttps-observed-in-midnight-blizzard-attacks/)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [Sigma rule — oauth-device-code-phishing.yml](https://github.com/cray44/sigma-to-spl/blob/main/rules/identity/oauth-device-code-phishing.yml)
- [Conditional Access: Block device code flow](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant)
