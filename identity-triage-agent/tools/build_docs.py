"""Rebuild the README graphics (light and dark) and docs/response-playbook.md from agent/knowledge.py.

    python tools/build_docs.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agent import ca_review, knowledge as kb      # noqa: E402
from viz import graphics as g                      # noqa: E402
from viz.theme import both                         # noqa: E402

A = str(ROOT / "assets")
N = len(kb.DETECTIONS)

both(g.banner, f"{A}/banner", "Identity threat triage agent",
     "An AI agent that triages Entra ID Protection risk, and guardrails that hold when it is wrong",
     [(str(N), "risk detections"), ("17", "alert scenarios"), ("18", "controls reviewed"), ("0", "unsafe outcomes allowed")])
both(g.architecture, f"{A}/architecture")
both(g.triage_flow, f"{A}/triage_flow")
both(g.detection_map, f"{A}/detection_map", kb.DETECTIONS, None)
both(g.cards, f"{A}/guardrails", "Seven guardrails, all in code",
     "None of them is a line in the prompt, so nothing the model reads can talk its way past them.",
     [("1", "Pre-triage", ["Closed alerts stay closed only if the logs agree. No model is called for them"], "verifier.py", "violet"),
      ("2", "Tool allow-list", ["Thirteen named tools. Eleven only read. Anything else is refused"], "loop.py", "blue"),
      ("3", "Step budget", ["An investigation that doesn't finish in 30 tool calls goes to a person"], "loop.py", "blue"),
      ("4", "Scope lock", ["Actions may only target the account or IP in this alert"], "policy.py", "orange"),
      ("5", "Action policy", ["Only session revocation runs by itself. The rest waits for approval"], "policy.py", "orange"),
      ("6", "Verifier", ["Evidence must cite real tool calls. A 'benign' that contradicts the data is overruled"], "verifier.py", "red"),
      ("7", "Audit trail", ["Every tool call, proposal, policy decision and verdict is logged"], "audit_log.jsonl", "aqua")], cols=4, ch=176)

CASE_TYPES = ["authenticatorPhishing", "attackerinTheMiddle", "anomalousToken", "leakedCredentials", "passwordSpray", "unfamiliarFeatures",
              "anonymizedIPAddress", "suspiciousInboxForwarding", "suspiciousAPITraffic", "mcasFinSuspiciousFileAccess", "unlikelyTravel", "newCountry",
              "nationStateIP", "investigationsThreatIntelligence"]
SHORT = {"SIGNIN_RISK": "Sign-in risk policy", "USER_RISK": "User risk policy", "MFA_ALL": "MFA for all users", "PR_MFA_ADMINS": "Phishing-resistant MFA",
         "BLOCK_LEGACY": "Block legacy auth", "COMPLIANT_DEVICE": "Compliant device", "TOKEN_PROTECTION": "Token protection", "NAMED_LOCATIONS": "Named locations",
         "BLOCK_COUNTRIES": "Block unused countries", "SIGNIN_FREQUENCY": "Sign-in frequency", "APP_CONTROL": "App control (sessions)",
         "EXCLUSIONS": "No stray exclusions", "SMART_LOCKOUT": "Smart lockout", "PASSWORD_HASH_SYNC": "Password hash sync",
         "REPORT_SUSPICIOUS": "Report suspicious MFA", "USER_CONSENT": "User consent limits", "EXTERNAL_FORWARDING": "Block ext. forwarding",
         "LEGACY_RISK_POLICIES": "Legacy policies moved"}
controls = [(cid, SHORT[cid], c["kind"]) for cid, c in kb.CONTROLS.items()]
both(g.control_matrix, f"{A}/control_matrix", [(k, kb.DETECTIONS[k]["name"]) for k in CASE_TYPES], controls,
     lambda key, cid: cid in kb.DETECTIONS[key]["controls"], ca_review.tenant_status())

# ---------------------------------------------------------------- response playbook page
ACTION_TEXT = {"revoke_sessions": "revoke sessions", "require_password_reset": "secure password reset", "confirm_user_compromised": "confirm user compromised",
               "require_mfa_reregistration": "re-register MFA", "remove_mfa_method": "remove attacker's MFA method", "disable_inbox_rule": "disable inbox rule",
               "remove_mail_forwarding": "remove mail forwarding", "revoke_app_consent": "revoke app consent", "remove_role_assignment": "remove role assignment",
               "block_ip": "block the IP", "block_sign_in": "block sign-in", "notify_security_lead": "notify security lead",
               "confirm_sign_in_safe": "confirm sign-in safe", "dismiss_risk": "dismiss risk"}
L = ["# Response playbook: Entra ID Protection risk detections\n",
     "[← Back to the README](../README.md)\n",
     "Generated from [`agent/knowledge.py`](../agent/knowledge.py) by `python tools/build_docs.py`, so this page and the agent never disagree.\n",
     f"Detection names, API values, timing and licence follow [Microsoft's risk detection reference](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks). "
     "Where Microsoft publishes investigation guidance for a detection, the response follows it (marked **Microsoft**). The rest is working practice (marked **practice**); adjust it to your organisation.\n",
     "## 1. Triage by risk state first\n",
     "| Risk state | What the agent does |", "|---|---|",
     "| `remediated`, `dismissed`, `confirmedSafe` | Closes the alert in code, with the reason from `riskDetail`, **if** three checks pass: no account change from the unfamiliar IP after the sign-in; passing MFA is enough for this detection type (see the last column below); a leaked password was actually changed. If any check fails, the alert is reopened and investigated |",
     "| `atRisk` | Sets a priority, then investigates |",
     "| `confirmedCompromised` | Treats the question as decided; scopes what the attacker changed and proposes containment |",
     "\n## 2. Starting priority\n",
     "Set before investigation, from the detection's base priority below. Raise one level for a privileged account and one for high risk; lower one for low risk.\n",
     "| Priority | A person looks within | Typical alert |", "|---|---|---|",
     f"| **P1** | {kb.SLA['P1']} | Token theft, attacker in the middle, leaked credentials, anything on an administrator |",
     f"| **P2** | {kb.SLA['P2']} | Unfamiliar sign-in or anonymous IP at medium or high risk, password guessed in a spray |",
     f"| **P3** | {kb.SLA['P3']} | Travel-pattern detections at medium risk |",
     f"| **P4** | {kb.SLA['P4']} | Low-risk travel patterns |",
     "\n## 3. Response by detection\n"]
for scope, heading in [("sign-in", "Sign-in risk detections"), ("both", "Detections raised as both sign-in and user risk"), ("user", "User risk detections")]:
    L += [f"### {heading}\n", "| Detection (`riskEventType`) | Timing | Starts at | Check first | Controls to verify | If malicious | If expected | MFA clears it? | Source |",
          "|---|---|---|---|---|---|---|---|---|"]
    for key, d in sorted(kb.DETECTIONS.items(), key=lambda kv: (kv[1]["priority"], kv[1]["name"])):
        if d["scope"] != scope:
            continue
        L.append(f"| **{d['name']}** (`{key}`)<br>{d['means']} | {d['timing']} | {d['priority']} | " + "<br>".join("• " + c for c in d["check"]) + " | "
                 + "<br>".join(kb.CONTROLS[c]["name"] for c in d["controls"]) + " | " + ", ".join(ACTION_TEXT[a] for a in d["if_malicious"])
                 + f" | {ACTION_TEXT[d['if_expected']]} | {'yes' if d['mfa_clears'] else '**no**'} | {'Microsoft' if d['source'] == 'microsoft' else 'practice'} |")
    L.append("")
L += ["## 4. Conditional Access policies and settings the agent reviews\n",
      "After each investigation the agent checks the controls listed for that detection and reports gaps: no policy, report-only, the user excluded, or the app not covered.\n",
      "| Control | Type | What good looks like |", "|---|---|---|"]
for cid, c in kb.CONTROLS.items():
    L.append(f"| **{c['name']}** | {'Conditional Access' if c['kind'] == 'ca' else 'Tenant setting'} | {c['expect']} |")
L += ["\nMicrosoft's recommended risk policies: sign-in risk at medium and high requires MFA through authentication strength; user risk at high requires risk remediation; "
      "sign-in frequency is set to every time; emergency access and service accounts are excluded; new policies start in report-only. "
      "The legacy risk policies inside ID Protection were retired on 1 October 2026, so risk policies now live in Conditional Access "
      "([source](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies)).\n",
      "## 5. Closing the loop\n",
      "| Outcome | Mark in ID Protection | Why |", "|---|---|---|",
      "| Account was compromised | Confirm user compromised | Raises user risk to high and improves detection |",
      "| Sign-in was the real user | Confirm sign-in safe | Tells the system the pattern is legitimate |",
      "| Investigated, no compromise, nothing to learn | Dismiss risk | Clears the risk without changing the password |",
      "| Sanctioned VPN or office raised the risk | Confirm safe, then add the range to named locations | Stops the same false alarm recurring |"]
(ROOT / "docs/response-playbook.md").write_text("\n".join(L) + "\n")
print(f"Built graphics in assets/ (light and dark) and docs/response-playbook.md for {N} detections")
