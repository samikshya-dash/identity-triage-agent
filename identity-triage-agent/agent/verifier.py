"""Verifier. Checks the model's verdict against facts computed straight from the data.

It is deliberately narrow. It can only make the outcome more cautious (send it to a person);
it can never turn 'needs a human' into 'benign' or 'compromised'.
"""
from datetime import datetime, timedelta

from . import knowledge as kb
from . import tools

PERSISTENCE = ("User registered security info", "New-InboxRule", "Set-Mailbox", "Consent to application", "Add member to role")


def red_flags(alert):
    """Hard facts that say 'this account was probably taken over'."""
    subject = alert["subject"]
    profile = tools.get_user_profile(subject)
    if "error" in profile:
        return []
    flags = []
    if alert.get("risk_event_type") == "leakedCredentials" and profile["password_last_changed"] < alert["time"]:
        flags.append("the leaked password has not been changed since the leak was detected")
    signins = tools.get_signins(subject)["signins"]
    audit = tools.get_audit_events(subject)["events"]
    for s in signins:
        if s["result"] != "success" or tools.check_named_location(s["ip"])["trusted"] or s["country"] in profile["usual_countries"]:
            continue
        when = datetime.fromisoformat(s["time"])
        after = [e for e in audit if e["ip"] == s["ip"] and datetime.fromisoformat(e["time"]) >= when and e["operation"] in PERSISTENCE]
        denials = [d for d in signins if d["ip"] == s["ip"] and d["mfa"] == "denied"
                   and timedelta(0) <= when - datetime.fromisoformat(d["time"]) <= timedelta(minutes=30)]
        rep = tools.get_ip_reputation(s["ip"])["category"]
        if after:
            flags.append(f"account change from the same unfamiliar IP after sign-in {s['id']}: {after[0]['operation']}")
        if len(denials) >= 3:
            flags.append(f"{len(denials)} MFA denials in the 30 minutes before successful sign-in {s['id']}")
        if rep in ("anonymising proxy", "hosting provider") and not s["device_id"]:
            flags.append(f"sign-in {s['id']} came from a network classed as '{rep}' with no known device")
    return flags


def verify(verdict, trace, alert):
    """Return (final_verdict, notes). `verdict` is what the model submitted."""
    notes, final = [], verdict["verdict"]
    call_ids = {step["id"] for step in trace}
    evidence = verdict.get("evidence") or []
    ungrounded = [e for e in evidence if e.get("source") not in call_ids]
    if ungrounded:
        notes.append(f"{len(ungrounded)} evidence item(s) cite a tool call that was never made")
    if final != "needs_human" and (ungrounded or len(evidence) < 2):
        notes.append("verdict is not backed by at least two grounded pieces of evidence: sent to a person")
        final = "needs_human"

    profile = tools.get_user_profile(alert["subject"])
    if profile.get("break_glass") and final != "needs_human":
        notes.append("break-glass account: always reviewed by a person")
        final = "needs_human"

    flags = red_flags(alert)
    if alert.get("risk_state") == "confirmedCompromised":
        flags.append("an administrator has confirmed this user compromised")
    if final == "benign" and flags:
        notes.append("closing as benign contradicts the data: " + "; ".join(flags))
        final = "needs_human"
    if final == "compromised" and not flags and "error" not in profile:
        notes.append("'compromised' is not supported by the data: sent to a person")
        final = "needs_human"
    return final, notes


def pretriage(alert):
    """Decide, before any model is called, whether an alert that ID Protection already closed can stay closed.

    Returns (close: bool, reason: str). Closing is refused when the data contradicts the closed state.
    """
    state, detail = alert.get("risk_state"), alert.get("risk_detail", "none")
    if alert.get("source") != "ID Protection" or state not in kb.CLOSED_STATES:
        return False, ""
    why = kb.RISK_DETAIL.get(detail, detail)
    flags = red_flags(alert)
    if flags:
        return False, f"ID Protection shows this as {state} ({why}), but the data disagrees: " + "; ".join(flags)
    det = kb.DETECTIONS.get(alert.get("risk_event_type"), kb.DETECTIONS["generic"])
    if detail == "userPassedMFADrivenByRiskBasedPolicy" and not det["mfa_clears"]:
        return False, f"closed because the user passed MFA, but passing MFA does not clear '{det['name']}'"
    return True, f"Already {kb.CLOSED_STATES[state]} in ID Protection ({why}), and nothing in the logs contradicts it"
