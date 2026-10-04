# Response playbook: Entra ID Protection risk detections

[← Back to the README](../README.md)

Generated from [`agent/knowledge.py`](../agent/knowledge.py) by `python tools/build_docs.py`, so this page and the agent never disagree.

Detection names, API values, timing and licence follow [Microsoft's risk detection reference](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks). Where Microsoft publishes investigation guidance for a detection, the response follows it (marked **Microsoft**). The rest is working practice (marked **practice**); adjust it to your organisation.

## 1. Triage by risk state first

| Risk state | What the agent does |
|---|---|
| `remediated`, `dismissed`, `confirmedSafe` | Closes the alert in code, with the reason from `riskDetail`, **if** three checks pass: no account change from the unfamiliar IP after the sign-in; passing MFA is enough for this detection type (see the last column below); a leaked password was actually changed. If any check fails, the alert is reopened and investigated |
| `atRisk` | Sets a priority, then investigates |
| `confirmedCompromised` | Treats the question as decided; scopes what the attacker changed and proposes containment |

## 2. Starting priority

Set before investigation, from the detection's base priority below. Raise one level for a privileged account and one for high risk; lower one for low risk.

| Priority | A person looks within | Typical alert |
|---|---|---|
| **P1** | 15 minutes | Token theft, attacker in the middle, leaked credentials, anything on an administrator |
| **P2** | 1 hour | Unfamiliar sign-in or anonymous IP at medium or high risk, password guessed in a spray |
| **P3** | 4 hours | Travel-pattern detections at medium risk |
| **P4** | next working day | Low-risk travel patterns |

## 3. Response by detection

### Sign-in risk detections

| Detection (`riskEventType`) | Timing | Starts at | Check first | Controls to verify | If malicious | If expected | MFA clears it? | Source |
|---|---|---|---|---|---|---|---|---|
| **Admin confirmed user compromised** (`adminConfirmedUserCompromised`)<br>An administrator marked the user as compromised. | offline | P1 | • Who confirmed it, and why (risk history)?<br>• Has containment been completed? | User risk policy | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | **no** | Microsoft |
| **Suspicious MFA authentication approval** (`authenticatorPhishing`)<br>A password plus MFA sign-in whose Authenticator telemetry and location suggest the approval was socially engineered. | real-time | P1 | • Where was the approval made versus where the sign-in came from?<br>• Repeated prompts before approval?<br>• Account change afterwards? | Phishing-resistant MFA<br>Sign-in risk policy<br>Report suspicious activity | revoke sessions, secure password reset, confirm user compromised, re-register MFA | confirm sign-in safe | **no** | practice |
| **Suspicious inbox forwarding** (`suspiciousInboxForwarding`)<br>A rule forwards the user's mail to an outside address. | offline | P1 | • Who created the rule, from which IP?<br>• What has been forwarded?<br>• Sign-ins from that IP | Automatic external forwarding is blocked<br>Sign-in risk policy<br>Require a compliant or hybrid-joined device | revoke sessions, secure password reset, confirm user compromised, remove mail forwarding | confirm sign-in safe | **no** | practice |
| **Suspicious inbox manipulation rules** (`mcasSuspiciousInboxManipulationRules`)<br>Rules that delete or move messages, often to hide an attacker's activity. | offline | P1 | • Rule content and creation time<br>• Sign-in that created it<br>• Sent items and payment-related mail | Sign-in risk policy<br>Require a compliant or hybrid-joined device<br>Automatic external forwarding is blocked | revoke sessions, secure password reset, confirm user compromised, disable inbox rule | confirm sign-in safe | **no** | practice |
| **Token issuer anomaly** (`tokenIssuerAnomaly`)<br>The SAML token issuer (the federation server) may be compromised; claims are unusual or match attacker patterns. | offline | P1 | • Is the domain federated?<br>• Any change to federation settings or token-signing certificates?<br>• AD FS server health and logs | Phishing-resistant MFA<br>Sign-in risk policy | revoke sessions, secure password reset, confirm user compromised, notify security lead | confirm sign-in safe | **no** | Microsoft |
| **Verified threat actor IP** (`nationStateIP`)<br>Sign-in consistent with IPs tied to nation-state or criminal groups. Always high risk. | real-time | P1 | • Did it succeed?<br>• What was accessed?<br>• Other accounts from the same IP? | Sign-in risk policy<br>Phishing-resistant MFA<br>Require a compliant or hybrid-joined device | revoke sessions, secure password reset, confirm user compromised, block the IP, notify security lead | confirm sign-in safe | **no** | practice |
| **Activity from anonymous IP address** (`riskyIPAddress`)<br>The user was active from an IP identified as an anonymous proxy. | offline | P2 | • What did the session do from that IP?<br>• Mail rules, forwarding, file downloads? | Sign-in risk policy<br>Require a compliant or hybrid-joined device<br>Sign-in frequency on unmanaged devices | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | practice |
| **Anonymous IP address** (`anonymizedIPAddress`)<br>Sign-in from Tor or an anonymising VPN. | real-time | P2 | • Does the user have a reason to use an anonymiser?<br>• Was MFA satisfied?<br>• Any account change from that IP? | Sign-in risk policy<br>Block countries you do not operate in<br>Require a compliant or hybrid-joined device | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | practice |
| **Malicious IP address** (`maliciousIPAddress`)<br>Sign-in from an IP with a high failure rate or a bad reputation. | offline | P2 | • Did the sign-in succeed?<br>• Does anyone legitimately use this IP?<br>• Other users targeted from it? | Sign-in risk policy<br>Block countries you do not operate in<br>MFA for all users | revoke sessions, secure password reset, confirm user compromised, block the IP | confirm sign-in safe | yes | Microsoft |
| **Mass access to sensitive files** (`mcasFinSuspiciousFileAccess`)<br>The user opened an unusual number of SharePoint or OneDrive files, some sensitive. | offline | P2 | • Which files, from which device and IP?<br>• Is the user leaving, or is the session suspicious? | Conditional Access app control<br>Require a compliant or hybrid-joined device<br>Sign-in risk policy | revoke sessions, secure password reset, confirm user compromised, notify security lead | confirm sign-in safe | yes | practice |
| **Password spray** (`passwordSpray`)<br>A spray attack in which the attacker guessed this user's password correctly. | real-time or offline | P2 | • Did any attempt get past MFA?<br>• Were other users sprayed from the same IPs?<br>• Is legacy authentication in use? | MFA for all users<br>Block legacy authentication<br>Sign-in risk policy<br>Smart lockout | secure password reset, block the IP | confirm sign-in safe | **no** | Microsoft |
| **Suspicious browser** (`suspiciousBrowser`)<br>The same browser signed in to several tenants from different countries. | offline | P2 | • Which accounts used this browser?<br>• Was MFA satisfied? | Sign-in risk policy<br>Require a compliant or hybrid-joined device | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | Microsoft |
| **Unfamiliar sign-in properties** (`unfamiliarFeatures`)<br>The sign-in's IP, network, location, device or browser is unlike this user's history. | real-time | P2 | • Is the device known and compliant?<br>• Is the IP a corporate or VPN range?<br>• Did MFA succeed, and with which method?<br>• Any account change afterwards? | Sign-in risk policy<br>Named locations are complete<br>Require a compliant or hybrid-joined device<br>Policy exclusions | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | practice |
| **Atypical travel** (`unlikelyTravel`)<br>Two sign-ins from places too far apart for the time between them, at least one unusual for the user. | offline | P3 | • Is one of the IPs a sanctioned VPN or a cloud proxy?<br>• Did the user travel?<br>• Same device on both sign-ins? | Named locations are complete<br>Sign-in risk policy<br>Require a compliant or hybrid-joined device | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | Microsoft |
| **Impossible travel** (`mcasImpossibleTravel`)<br>Activity from distant locations in less time than travel would take. | offline | P3 | • Is one location a VPN egress?<br>• Same device and session?<br>• What did each session do? | Named locations are complete<br>Sign-in risk policy<br>Require a compliant or hybrid-joined device | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | practice |
| **New country** (`newCountry`)<br>Sign-in from a country that is new or rare for this user. | offline | P3 | • Is the user travelling?<br>• Own compliant device?<br>• Any account change afterwards? | Named locations are complete<br>Block countries you do not operate in<br>Sign-in risk policy | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | practice |

### Detections raised as both sign-in and user risk

| Detection (`riskEventType`) | Timing | Starts at | Check first | Controls to verify | If malicious | If expected | MFA clears it? | Source |
|---|---|---|---|---|---|---|---|---|
| **Anomalous token** (`anomalousToken`)<br>A session or refresh token with unusual characteristics, or replayed from an unfamiliar location. | real-time or offline | P1 | • Is the token used from a new IP with no device?<br>• Scripted client?<br>• App consent, mail rules or Graph activity afterwards? | Token protection<br>Require a compliant or hybrid-joined device<br>Sign-in frequency on unmanaged devices<br>Sign-in risk policy | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | **no** | Microsoft |
| **Microsoft Entra threat intelligence** (`investigationsThreatIntelligence`)<br>Activity that is unusual for the user or matches known attack patterns from Microsoft's intelligence. | real-time or offline | P1 | • Does the IP show failures against other users?<br>• Unexpected protocol such as legacy Exchange?<br>• Are other users hit by the same pattern? | Sign-in risk policy<br>User risk policy<br>Block legacy authentication | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | **no** | Microsoft |
| **Additional risk detected** (`generic`)<br>A premium detection fired but the tenant's licence hides the detail. | real-time or offline | P3 | • Treat as unknown: review the sign-in and recent account changes by hand | Sign-in risk policy<br>User risk policy | revoke sessions, secure password reset, confirm user compromised | confirm sign-in safe | yes | practice |

### User risk detections

| Detection (`riskEventType`) | Timing | Starts at | Check first | Controls to verify | If malicious | If expected | MFA clears it? | Source |
|---|---|---|---|---|---|---|---|---|
| **Anomalous user activity** (`anomalousUserActivity`)<br>Directory changes that are unusual for this administrator. | offline | P1 | • What changed: roles, apps, policies?<br>• Was there a change ticket?<br>• Sign-in behind the change | Phishing-resistant MFA<br>User risk policy | revoke sessions, secure password reset, confirm user compromised, remove role assignment, notify security lead | confirm sign-in safe | **no** | practice |
| **Attacker in the Middle** (`attackerinTheMiddle`)<br>The session went through a malicious reverse proxy that captures the password and the token. High precision. | offline | P1 | • Token use from a second IP after the sign-in<br>• New MFA method or device registered<br>• Mail rules and consent grants | Phishing-resistant MFA<br>Require a compliant or hybrid-joined device<br>Token protection<br>User risk policy | revoke sessions, secure password reset, confirm user compromised, re-register MFA | confirm sign-in safe | **no** | Microsoft |
| **Leaked credentials** (`leakedCredentials`)<br>The user's valid password was found in a breach. Always high risk. | offline | P1 | • Has the password been changed since the detection?<br>• Any sign-in with the leaked password?<br>• Unfamiliar sign-ins around the same time | User risk policy<br>MFA for all users<br>Password hash sync<br>Legacy risk policies are migrated | secure password reset, revoke sessions, confirm user compromised | dismiss risk | **no** | Microsoft |
| **Possible attempt to access Primary Refresh Token** (`attemptedPrtAccess`)<br>Defender for Endpoint saw an attempt to read the device's Primary Refresh Token. Moves the user to high risk. | offline | P1 | • Which device? Isolate and investigate it<br>• Sign-ins from other devices with this user's token | Require a compliant or hybrid-joined device<br>Token protection<br>User risk policy | revoke sessions, secure password reset, confirm user compromised, notify security lead | confirm sign-in safe | **no** | practice |
| **Suspicious API traffic** (`suspiciousAPITraffic`)<br>Abnormal Graph traffic or directory enumeration from the user: reconnaissance. | offline | P2 | • Which app and client made the calls?<br>• What was enumerated?<br>• New app registrations or consents | User risk policy<br>Require a compliant or hybrid-joined device<br>User consent to apps is restricted | revoke sessions, secure password reset, confirm user compromised, revoke app consent | confirm sign-in safe | **no** | practice |
| **Suspicious sending patterns** (`suspiciousSendingPatterns`)<br>Abnormal outbound mail volume. The account may be used for spam or phishing. | offline | P2 | • What was sent, and to whom?<br>• Sign-in behind the sending session<br>• Inbox rules hiding replies | User risk policy<br>Sign-in risk policy | revoke sessions, secure password reset, confirm user compromised, disable inbox rule | confirm sign-in safe | **no** | practice |
| **User reported suspicious activity** (`userReportedSuspiciousActivity`)<br>The user denied an MFA prompt and reported it. Someone else has the password. | offline | P2 | • Where did the denied sign-in come from?<br>• Did any later prompt get approved? | User risk policy<br>Report suspicious activity<br>MFA for all users | secure password reset, revoke sessions | dismiss risk | **no** | practice |

## 4. Conditional Access policies and settings the agent reviews

After each investigation the agent checks the controls listed for that detection and reports gaps: no policy, report-only, the user excluded, or the app not covered.

| Control | Type | What good looks like |
|---|---|---|
| **Sign-in risk policy** | Conditional Access | Medium and high sign-in risk require MFA through authentication strength, with sign-in frequency set to every time |
| **User risk policy** | Conditional Access | High user risk requires risk remediation (secure password change for password users) |
| **MFA for all users** | Conditional Access | Every user and every app requires MFA, with no broad exclusions |
| **Phishing-resistant MFA** | Conditional Access | Administrators at minimum, ideally everyone, must use a phishing-resistant method (FIDO2, passkey, Windows Hello, certificate) |
| **Block legacy authentication** | Conditional Access | Protocols that cannot do MFA are blocked for everyone |
| **Require a compliant or hybrid-joined device** | Conditional Access | Access to company data needs a managed device, so a stolen password or token alone is not enough |
| **Token protection** | Conditional Access | Sign-in session tokens are bound to the device they were issued to, so a copied token fails elsewhere |
| **Named locations are complete** | Conditional Access | Offices and corporate VPN ranges are defined and marked trusted, so real travel and VPN use stop raising risk |
| **Block countries you do not operate in** | Conditional Access | Sign-ins from countries with no business presence are blocked |
| **Sign-in frequency on unmanaged devices** | Conditional Access | Short sessions and no persistent browser session on devices the company does not manage |
| **Conditional Access app control** | Conditional Access | Sessions to SharePoint and OneDrive are monitored and can block mass download from risky sessions |
| **Policy exclusions** | Conditional Access | The affected user is in scope of the risk and MFA policies |
| **Smart lockout** | Tenant setting | Lockout threshold and duration are configured |
| **Password hash sync** | Tenant setting | Enabled, so leaked credentials can be detected and a cloud password change clears the risk for hybrid users |
| **Report suspicious activity** | Tenant setting | Users can report an MFA prompt they did not start, which raises their user risk |
| **User consent to apps is restricted** | Tenant setting | Users cannot grant apps access to mail and files without an admin workflow |
| **Automatic external forwarding is blocked** | Tenant setting | The outbound spam policy stops mailboxes forwarding to outside addresses |
| **Legacy risk policies are migrated** | Tenant setting | Risk policies live in Conditional Access. Microsoft retired the legacy ID Protection risk policies on 1 October 2026 |

Microsoft's recommended risk policies: sign-in risk at medium and high requires MFA through authentication strength; user risk at high requires risk remediation; sign-in frequency is set to every time; emergency access and service accounts are excluded; new policies start in report-only. The legacy risk policies inside ID Protection were retired on 1 October 2026, so risk policies now live in Conditional Access ([source](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies)).

## 5. Closing the loop

| Outcome | Mark in ID Protection | Why |
|---|---|---|
| Account was compromised | Confirm user compromised | Raises user risk to high and improves detection |
| Sign-in was the real user | Confirm sign-in safe | Tells the system the pattern is legitimate |
| Investigated, no compromise, nothing to learn | Dismiss risk | Clears the risk without changing the password |
| Sanctioned VPN or office raised the risk | Confirm safe, then add the range to named locations | Stops the same false alarm recurring |
