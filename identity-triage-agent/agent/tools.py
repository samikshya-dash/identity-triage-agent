"""The agent's tools. Every one of them only reads, except propose_action and submit_verdict,
which record what the agent wants and hand it to the policy and verifier. Nothing here changes
a real system.

In production each function would call Microsoft Graph or Sentinel. Here they read
data/tenant.json so the whole thing runs offline.
"""
from datetime import datetime, timedelta

from . import ca_review, knowledge
from .tools_data import DATA, NOW


def _since(rows, hours):
    cutoff = NOW - timedelta(hours=hours)
    return [r for r in rows if datetime.fromisoformat(r["time"]) >= cutoff]


def get_alert(alert_id):
    a = DATA["alerts"].get(alert_id)
    return dict(a, alert_id=alert_id) if a else {"error": f"no alert {alert_id}"}


def get_user_profile(user):
    u = DATA["users"].get(user)
    return dict(u, user=user) if u else {"error": f"no user {user}"}


def get_signins(user, hours=72):
    return {"user": user, "signins": [r for r in _since(DATA["signins"], hours) if r["user"] == user]}


def get_signins_from_ip(ip, hours=72):
    rows = [r for r in _since(DATA["signins"], hours) if r["ip"] == ip]
    return {"ip": ip, "attempts": len(rows), "users_targeted": sorted({r["user"] for r in rows}),
            "successes": [r for r in rows if r["result"] == "success"], "sample": rows[:3]}


def get_audit_events(user, hours=72):
    return {"user": user, "events": [r for r in _since(DATA["audit"], hours) if r["actor"] == user]}


def get_device(device_id):
    d = DATA["devices"].get(device_id)
    return dict(d, device_id=device_id) if d else {"error": f"no device {device_id}"}


def check_named_location(ip):
    for loc in DATA["named_locations"]:
        if ip.startswith(loc["prefix"]):
            return {"ip": ip, "named_location": loc["name"], "trusted": loc["trusted"]}
    return {"ip": ip, "named_location": None, "trusted": False}


def get_ip_reputation(ip):
    return dict(DATA["ip_reputation"].get(ip, {"category": "unknown", "abuse_reports": 0}), ip=ip)


def get_risk_detections(user):
    """Other ID Protection detections for the same user, open or closed."""
    rows = [dict(a, alert_id=k) for k, a in DATA["alerts"].items() if a["subject"] == user and a["source"] == "ID Protection"]
    return {"user": user, "detections": [{k: r[k] for k in ("alert_id", "time", "risk_event_type", "risk_level", "risk_state", "risk_detail")} for r in rows]}


def lookup_playbook(risk_event_type):
    """What this detection means, what to check, and how to respond."""
    return knowledge.playbook(risk_event_type)


def review_conditional_access(risk_event_type, user=None, app=None):
    """Which Conditional Access policies and settings should have covered this attack, and where the gaps are."""
    return ca_review.review(risk_event_type, user, app)


READ_TOOLS = {f.__name__: f for f in (get_alert, get_user_profile, get_signins, get_signins_from_ip, get_audit_events, get_device,
                                      check_named_location, get_ip_reputation, get_risk_detections, lookup_playbook, review_conditional_access)}

VERDICTS = ["compromised", "benign", "attack_blocked", "needs_human"]
VERDICTS_BRAIN = VERDICTS                      # 'auto_closed' is set by the loop only, never by the brain
CONTAINMENT = ["revoke_sessions", "require_password_reset", "confirm_user_compromised", "require_mfa_reregistration", "remove_mfa_method",
               "disable_inbox_rule", "remove_mail_forwarding", "revoke_app_consent", "remove_role_assignment", "block_ip", "block_sign_in",
               "disable_account"]
CLOSURE = ["confirm_sign_in_safe", "dismiss_risk"]     # feedback to ID Protection when the sign-in was legitimate
ACTIONS = CONTAINMENT + CLOSURE + ["notify_security_lead"]


def _fn(name, description, props, required):
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": props, "required": required, "additionalProperties": False}}}


_S = {"type": "string"}
_H = {"type": "integer", "description": "How many hours back to look", "default": 72}
TOOL_SCHEMAS = [   # the format language models expect for tool calling
    _fn("get_alert", "Read the alert being investigated.", {"alert_id": _S}, ["alert_id"]),
    _fn("get_user_profile", "Role, department, usual countries, MFA methods, and whether the account is privileged or break-glass.", {"user": _S}, ["user"]),
    _fn("get_signins", "Sign-in log entries for one user.", {"user": _S, "hours": _H}, ["user"]),
    _fn("get_signins_from_ip", "All sign-in attempts from one IP address, across users.", {"ip": _S, "hours": _H}, ["ip"]),
    _fn("get_audit_events", "Directory and mailbox changes made by one user.", {"user": _S, "hours": _H}, ["user"]),
    _fn("get_device", "Compliance and join state of a device.", {"device_id": _S}, ["device_id"]),
    _fn("check_named_location", "Whether an IP belongs to a trusted corporate location.", {"ip": _S}, ["ip"]),
    _fn("get_ip_reputation", "Network type and abuse history of an IP.", {"ip": _S}, ["ip"]),
    _fn("get_risk_detections", "Other ID Protection risk detections for the same user, with their state.", {"user": _S}, ["user"]),
    _fn("lookup_playbook", "Guidance for one ID Protection detection type: meaning, what to check, how to respond.", {"risk_event_type": _S}, ["risk_event_type"]),
    _fn("review_conditional_access", "Check which Conditional Access policies and settings should have covered this attack and list the gaps.",
        {"risk_event_type": _S, "user": _S, "app": _S}, ["risk_event_type"]),
    _fn("propose_action", "Propose one containment or closure action. It is checked by policy; you cannot execute anything yourself.",
        {"action": {"type": "string", "enum": ACTIONS}, "target": {"type": "string", "description": "User or IP the action applies to"},
         "reason": _S}, ["action", "target", "reason"]),
    _fn("submit_verdict", "Finish the investigation. Every evidence item must cite the id of a tool call you made.",
        {"verdict": {"type": "string", "enum": VERDICTS}, "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
         "summary": _S,
         "evidence": {"type": "array", "items": {"type": "object", "properties": {"claim": _S, "source": {"type": "string", "description": "tool call id, e.g. call-3"}},
                                                  "required": ["claim", "source"]}}},
        ["verdict", "confidence", "summary", "evidence"]),
]
