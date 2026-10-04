"""Action policy. The model proposes; this code decides.

Nothing the model says can change these rules, because they are not in the prompt.
"""
from .tools import ACTIONS, CLOSURE

AUTO = {"revoke_sessions", "notify_security_lead"}     # reversible and low impact: a user signs in again
MAX_AUTO_PER_INVESTIGATION = 2


def decide(action, target, alert, profile, auto_used):
    """Return (outcome, reason). outcome is 'auto', 'approval' or 'denied'."""
    if action not in ACTIONS:
        return "denied", "not an action this agent is allowed to propose"
    subject = alert.get("subject")
    in_scope = target == subject or (action == "block_ip" and target == alert.get("ip")) or action == "notify_security_lead"
    if not in_scope:
        return "denied", f"outside the scope of this alert (subject is {subject})"
    if profile.get("break_glass") and action != "notify_security_lead":
        return "denied", "break-glass accounts are never touched by automation"
    if action in CLOSURE:
        return "approval", "marks the risk as safe in ID Protection: a person confirms"
    if action == "notify_security_lead":
        return "auto", "a notification only; it changes nothing"
    if action in AUTO:
        if profile.get("privileged"):
            return "approval", "privileged account: a person approves every action"
        if auto_used >= MAX_AUTO_PER_INVESTIGATION:
            return "approval", "automatic action budget for this investigation is used up"
        return "auto", "reversible and low impact"
    return "approval", "changes an account or tenant setting: a person approves"
