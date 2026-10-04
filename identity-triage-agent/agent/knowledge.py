"""What the agent knows about Microsoft Entra ID Protection.

Names, API values, timing and licence come from Microsoft's risk detection reference:
https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
Where Microsoft publishes investigation guidance for a detection, the response follows it
("source": "microsoft"). For the rest it is my working practice ("source": "practice").

This file is the single source for the agent's playbook tool, the Conditional Access review
and the generated page docs/response-playbook.md.
"""

# ---------------------------------------------------------------------------------------
# Controls the agent checks after an alert: was the door this attack used actually closed?
# kind "ca" is a Conditional Access policy; kind "setting" is a related tenant setting.
# ---------------------------------------------------------------------------------------
CONTROLS = {
    "SIGNIN_RISK": {"kind": "ca", "name": "Sign-in risk policy",
                    "expect": "Medium and high sign-in risk require MFA through authentication strength, with sign-in frequency set to every time"},
    "USER_RISK": {"kind": "ca", "name": "User risk policy",
                  "expect": "High user risk requires risk remediation (secure password change for password users)"},
    "MFA_ALL": {"kind": "ca", "name": "MFA for all users", "expect": "Every user and every app requires MFA, with no broad exclusions"},
    "PR_MFA_ADMINS": {"kind": "ca", "name": "Phishing-resistant MFA",
                      "expect": "Administrators at minimum, ideally everyone, must use a phishing-resistant method (FIDO2, passkey, Windows Hello, certificate)"},
    "BLOCK_LEGACY": {"kind": "ca", "name": "Block legacy authentication", "expect": "Protocols that cannot do MFA are blocked for everyone"},
    "COMPLIANT_DEVICE": {"kind": "ca", "name": "Require a compliant or hybrid-joined device",
                         "expect": "Access to company data needs a managed device, so a stolen password or token alone is not enough"},
    "TOKEN_PROTECTION": {"kind": "ca", "name": "Token protection",
                         "expect": "Sign-in session tokens are bound to the device they were issued to, so a copied token fails elsewhere"},
    "NAMED_LOCATIONS": {"kind": "ca", "name": "Named locations are complete",
                        "expect": "Offices and corporate VPN ranges are defined and marked trusted, so real travel and VPN use stop raising risk"},
    "BLOCK_COUNTRIES": {"kind": "ca", "name": "Block countries you do not operate in", "expect": "Sign-ins from countries with no business presence are blocked"},
    "SIGNIN_FREQUENCY": {"kind": "ca", "name": "Sign-in frequency on unmanaged devices",
                         "expect": "Short sessions and no persistent browser session on devices the company does not manage"},
    "APP_CONTROL": {"kind": "ca", "name": "Conditional Access app control",
                    "expect": "Sessions to SharePoint and OneDrive are monitored and can block mass download from risky sessions"},
    "EXCLUSIONS": {"kind": "ca", "name": "Policy exclusions", "expect": "The affected user is in scope of the risk and MFA policies"},
    "SMART_LOCKOUT": {"kind": "setting", "name": "Smart lockout", "expect": "Lockout threshold and duration are configured"},
    "PASSWORD_HASH_SYNC": {"kind": "setting", "name": "Password hash sync",
                           "expect": "Enabled, so leaked credentials can be detected and a cloud password change clears the risk for hybrid users"},
    "REPORT_SUSPICIOUS": {"kind": "setting", "name": "Report suspicious activity", "expect": "Users can report an MFA prompt they did not start, which raises their user risk"},
    "USER_CONSENT": {"kind": "setting", "name": "User consent to apps is restricted", "expect": "Users cannot grant apps access to mail and files without an admin workflow"},
    "EXTERNAL_FORWARDING": {"kind": "setting", "name": "Automatic external forwarding is blocked", "expect": "The outbound spam policy stops mailboxes forwarding to outside addresses"},
    "LEGACY_RISK_POLICIES": {"kind": "setting", "name": "Legacy risk policies are migrated",
                             "expect": "Risk policies live in Conditional Access. Microsoft retired the legacy ID Protection risk policies on 1 October 2026"},
}

CONTAIN = ["revoke_sessions", "require_password_reset", "confirm_user_compromised"]


def _d(name, scope, timing, licence, means, check, controls, malicious=None, expected="confirm_sign_in_safe", priority="P2",
       mfa_clears=True, source="practice"):
    return {"name": name, "scope": scope, "timing": timing, "licence": licence, "means": means, "check": check, "controls": controls,
            "if_malicious": malicious or CONTAIN, "if_expected": expected, "priority": priority, "mfa_clears": mfa_clears, "source": source}


# mfa_clears: is passing MFA enough to consider the risk dealt with? False where the attacker
# already holds a token or the password, so MFA proves nothing.
DETECTIONS = {
    # ------------------------------------------------------------------ sign-in risk
    "unfamiliarFeatures": _d("Unfamiliar sign-in properties", "sign-in", "real-time", "P2",
        "The sign-in's IP, network, location, device or browser is unlike this user's history.",
        ["Is the device known and compliant?", "Is the IP a corporate or VPN range?", "Did MFA succeed, and with which method?", "Any account change afterwards?"],
        ["SIGNIN_RISK", "NAMED_LOCATIONS", "COMPLIANT_DEVICE", "EXCLUSIONS"]),
    "anonymizedIPAddress": _d("Anonymous IP address", "sign-in", "real-time", "Free",
        "Sign-in from Tor or an anonymising VPN.",
        ["Does the user have a reason to use an anonymiser?", "Was MFA satisfied?", "Any account change from that IP?"],
        ["SIGNIN_RISK", "BLOCK_COUNTRIES", "COMPLIANT_DEVICE"], priority="P2"),
    "riskyIPAddress": _d("Activity from anonymous IP address", "sign-in", "offline", "P2",
        "The user was active from an IP identified as an anonymous proxy.",
        ["What did the session do from that IP?", "Mail rules, forwarding, file downloads?"],
        ["SIGNIN_RISK", "COMPLIANT_DEVICE", "SIGNIN_FREQUENCY"]),
    "unlikelyTravel": _d("Atypical travel", "sign-in", "offline", "P2",
        "Two sign-ins from places too far apart for the time between them, at least one unusual for the user.",
        ["Is one of the IPs a sanctioned VPN or a cloud proxy?", "Did the user travel?", "Same device on both sign-ins?"],
        ["NAMED_LOCATIONS", "SIGNIN_RISK", "COMPLIANT_DEVICE"], priority="P3", source="microsoft"),
    "mcasImpossibleTravel": _d("Impossible travel", "sign-in", "offline", "P2",
        "Activity from distant locations in less time than travel would take.",
        ["Is one location a VPN egress?", "Same device and session?", "What did each session do?"],
        ["NAMED_LOCATIONS", "SIGNIN_RISK", "COMPLIANT_DEVICE"], priority="P3"),
    "newCountry": _d("New country", "sign-in", "offline", "P2",
        "Sign-in from a country that is new or rare for this user.",
        ["Is the user travelling?", "Own compliant device?", "Any account change afterwards?"],
        ["NAMED_LOCATIONS", "BLOCK_COUNTRIES", "SIGNIN_RISK"], priority="P3"),
    "maliciousIPAddress": _d("Malicious IP address", "sign-in", "offline", "P2",
        "Sign-in from an IP with a high failure rate or a bad reputation.",
        ["Did the sign-in succeed?", "Does anyone legitimately use this IP?", "Other users targeted from it?"],
        ["SIGNIN_RISK", "BLOCK_COUNTRIES", "MFA_ALL"], malicious=CONTAIN + ["block_ip"], source="microsoft"),
    "nationStateIP": _d("Verified threat actor IP", "sign-in", "real-time", "P2",
        "Sign-in consistent with IPs tied to nation-state or criminal groups. Always high risk.",
        ["Did it succeed?", "What was accessed?", "Other accounts from the same IP?"],
        ["SIGNIN_RISK", "PR_MFA_ADMINS", "COMPLIANT_DEVICE"], malicious=CONTAIN + ["block_ip", "notify_security_lead"], priority="P1", mfa_clears=False),
    "passwordSpray": _d("Password spray", "sign-in", "real-time or offline", "P2",
        "A spray attack in which the attacker guessed this user's password correctly.",
        ["Did any attempt get past MFA?", "Were other users sprayed from the same IPs?", "Is legacy authentication in use?"],
        ["MFA_ALL", "BLOCK_LEGACY", "SIGNIN_RISK", "SMART_LOCKOUT"], malicious=["require_password_reset", "block_ip"], priority="P2",
        mfa_clears=False, source="microsoft"),
    "anomalousToken": _d("Anomalous token", "both", "real-time or offline", "P2",
        "A session or refresh token with unusual characteristics, or replayed from an unfamiliar location.",
        ["Is the token used from a new IP with no device?", "Scripted client?", "App consent, mail rules or Graph activity afterwards?"],
        ["TOKEN_PROTECTION", "COMPLIANT_DEVICE", "SIGNIN_FREQUENCY", "SIGNIN_RISK"], priority="P1", mfa_clears=False, source="microsoft"),
    "tokenIssuerAnomaly": _d("Token issuer anomaly", "sign-in", "offline", "P2",
        "The SAML token issuer (the federation server) may be compromised; claims are unusual or match attacker patterns.",
        ["Is the domain federated?", "Any change to federation settings or token-signing certificates?", "AD FS server health and logs"],
        ["PR_MFA_ADMINS", "SIGNIN_RISK"], malicious=CONTAIN + ["notify_security_lead"], priority="P1", mfa_clears=False, source="microsoft"),
    "suspiciousBrowser": _d("Suspicious browser", "sign-in", "offline", "P2",
        "The same browser signed in to several tenants from different countries.",
        ["Which accounts used this browser?", "Was MFA satisfied?"],
        ["SIGNIN_RISK", "COMPLIANT_DEVICE"], source="microsoft"),
    "authenticatorPhishing": _d("Suspicious MFA authentication approval", "sign-in", "real-time", "P2",
        "A password plus MFA sign-in whose Authenticator telemetry and location suggest the approval was socially engineered.",
        ["Where was the approval made versus where the sign-in came from?", "Repeated prompts before approval?", "Account change afterwards?"],
        ["PR_MFA_ADMINS", "SIGNIN_RISK", "REPORT_SUSPICIOUS"], malicious=CONTAIN + ["require_mfa_reregistration"], priority="P1", mfa_clears=False),
    "suspiciousInboxForwarding": _d("Suspicious inbox forwarding", "sign-in", "offline", "P2",
        "A rule forwards the user's mail to an outside address.",
        ["Who created the rule, from which IP?", "What has been forwarded?", "Sign-ins from that IP"],
        ["EXTERNAL_FORWARDING", "SIGNIN_RISK", "COMPLIANT_DEVICE"], malicious=CONTAIN + ["remove_mail_forwarding"], priority="P1", mfa_clears=False),
    "mcasSuspiciousInboxManipulationRules": _d("Suspicious inbox manipulation rules", "sign-in", "offline", "P2",
        "Rules that delete or move messages, often to hide an attacker's activity.",
        ["Rule content and creation time", "Sign-in that created it", "Sent items and payment-related mail"],
        ["SIGNIN_RISK", "COMPLIANT_DEVICE", "EXTERNAL_FORWARDING"], malicious=CONTAIN + ["disable_inbox_rule"], priority="P1", mfa_clears=False),
    "mcasFinSuspiciousFileAccess": _d("Mass access to sensitive files", "sign-in", "offline", "P2",
        "The user opened an unusual number of SharePoint or OneDrive files, some sensitive.",
        ["Which files, from which device and IP?", "Is the user leaving, or is the session suspicious?"],
        ["APP_CONTROL", "COMPLIANT_DEVICE", "SIGNIN_RISK"], malicious=CONTAIN + ["notify_security_lead"]),
    "investigationsThreatIntelligence": _d("Microsoft Entra threat intelligence", "both", "real-time or offline", "Free",
        "Activity that is unusual for the user or matches known attack patterns from Microsoft's intelligence.",
        ["Does the IP show failures against other users?", "Unexpected protocol such as legacy Exchange?", "Are other users hit by the same pattern?"],
        ["SIGNIN_RISK", "USER_RISK", "BLOCK_LEGACY"], priority="P1", mfa_clears=False, source="microsoft"),
    "adminConfirmedUserCompromised": _d("Admin confirmed user compromised", "sign-in", "offline", "Free",
        "An administrator marked the user as compromised.",
        ["Who confirmed it, and why (risk history)?", "Has containment been completed?"],
        ["USER_RISK"], priority="P1", mfa_clears=False, source="microsoft"),
    "generic": _d("Additional risk detected", "both", "real-time or offline", "Free",
        "A premium detection fired but the tenant's licence hides the detail.",
        ["Treat as unknown: review the sign-in and recent account changes by hand"], ["SIGNIN_RISK", "USER_RISK"], priority="P3"),
    # ------------------------------------------------------------------ user risk
    "leakedCredentials": _d("Leaked credentials", "user", "offline", "Free",
        "The user's valid password was found in a breach. Always high risk.",
        ["Has the password been changed since the detection?", "Any sign-in with the leaked password?", "Unfamiliar sign-ins around the same time"],
        ["USER_RISK", "MFA_ALL", "PASSWORD_HASH_SYNC", "LEGACY_RISK_POLICIES"], malicious=["require_password_reset", "revoke_sessions", "confirm_user_compromised"],
        expected="dismiss_risk", priority="P1", mfa_clears=False, source="microsoft"),
    "attackerinTheMiddle": _d("Attacker in the Middle", "user", "offline", "P2",
        "The session went through a malicious reverse proxy that captures the password and the token. High precision.",
        ["Token use from a second IP after the sign-in", "New MFA method or device registered", "Mail rules and consent grants"],
        ["PR_MFA_ADMINS", "COMPLIANT_DEVICE", "TOKEN_PROTECTION", "USER_RISK"], malicious=CONTAIN + ["require_mfa_reregistration"],
        priority="P1", mfa_clears=False, source="microsoft"),
    "attemptedPrtAccess": _d("Possible attempt to access Primary Refresh Token", "user", "offline", "P2",
        "Defender for Endpoint saw an attempt to read the device's Primary Refresh Token. Moves the user to high risk.",
        ["Which device? Isolate and investigate it", "Sign-ins from other devices with this user's token"],
        ["COMPLIANT_DEVICE", "TOKEN_PROTECTION", "USER_RISK"], malicious=CONTAIN + ["notify_security_lead"], priority="P1", mfa_clears=False),
    "anomalousUserActivity": _d("Anomalous user activity", "user", "offline", "P2",
        "Directory changes that are unusual for this administrator.",
        ["What changed: roles, apps, policies?", "Was there a change ticket?", "Sign-in behind the change"],
        ["PR_MFA_ADMINS", "USER_RISK"], malicious=CONTAIN + ["remove_role_assignment", "notify_security_lead"], priority="P1", mfa_clears=False),
    "suspiciousAPITraffic": _d("Suspicious API traffic", "user", "offline", "P2",
        "Abnormal Graph traffic or directory enumeration from the user: reconnaissance.",
        ["Which app and client made the calls?", "What was enumerated?", "New app registrations or consents"],
        ["USER_RISK", "COMPLIANT_DEVICE", "USER_CONSENT"], malicious=CONTAIN + ["revoke_app_consent"], mfa_clears=False),
    "suspiciousSendingPatterns": _d("Suspicious sending patterns", "user", "offline", "P2",
        "Abnormal outbound mail volume. The account may be used for spam or phishing.",
        ["What was sent, and to whom?", "Sign-in behind the sending session", "Inbox rules hiding replies"],
        ["USER_RISK", "SIGNIN_RISK"], malicious=CONTAIN + ["disable_inbox_rule"], mfa_clears=False),
    "userReportedSuspiciousActivity": _d("User reported suspicious activity", "user", "offline", "P2",
        "The user denied an MFA prompt and reported it. Someone else has the password.",
        ["Where did the denied sign-in come from?", "Did any later prompt get approved?"],
        ["USER_RISK", "REPORT_SUSPICIOUS", "MFA_ALL"], malicious=["require_password_reset", "revoke_sessions"], expected="dismiss_risk",
        priority="P2", mfa_clears=False),
}

CLOSED_STATES = {"remediated": "remediated", "dismissed": "dismissed", "confirmedSafe": "confirmed safe"}
RISK_DETAIL = {   # values from the Microsoft Graph riskDetail enum
    "userPassedMFADrivenByRiskBasedPolicy": "the user passed MFA required by a risk-based policy",
    "userPerformedSecuredPasswordChange": "the user completed a secure password change",
    "userPerformedSecuredPasswordReset": "the user completed a secure password reset",
    "adminGeneratedTemporaryPassword": "an administrator issued a temporary password",
    "adminConfirmedSigninSafe": "an administrator confirmed the sign-in safe",
    "aiConfirmedSigninSafe": "ID Protection assessed the sign-in as safe",
    "adminDismissedAllRiskForUser": "an administrator dismissed the user's risk",
    "adminConfirmedSigninCompromised": "an administrator confirmed the sign-in compromised",
    "adminConfirmedUserCompromised": "an administrator confirmed the user compromised",
    "none": "no detail recorded", "hidden": "detail hidden by licence",
}
PASSWORD_WAS_CHANGED = {"userPerformedSecuredPasswordChange", "userPerformedSecuredPasswordReset", "adminGeneratedTemporaryPassword"}

# Priority: how fast a person should look, before the agent has investigated anything.
SLA = {"P1": "15 minutes", "P2": "1 hour", "P3": "4 hours", "P4": "next working day"}


def priority(risk_event_type, risk_level, privileged):
    """Base priority from the detection, raised for privileged accounts and high risk, lowered for low risk."""
    base = int(DETECTIONS.get(risk_event_type, DETECTIONS["generic"])["priority"][1])
    if privileged:
        base -= 1
    if risk_level == "high":
        base -= 1
    elif risk_level == "low":
        base += 1
    return f"P{min(4, max(1, base))}"


def playbook(risk_event_type):
    d = DETECTIONS.get(risk_event_type) or DETECTIONS["generic"]
    return {"risk_event_type": risk_event_type, "name": d["name"], "meaning": d["means"], "check": d["check"],
            "controls_to_review": [{"id": c, "name": CONTROLS[c]["name"]} for c in d["controls"]],
            "if_malicious_propose": d["if_malicious"], "if_expected": d["if_expected"],
            "passing_mfa_is_enough": d["mfa_clears"], "guidance_source": d["source"]}
