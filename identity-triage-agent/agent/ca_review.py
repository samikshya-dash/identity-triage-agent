"""After the alert: would the tenant's Conditional Access policies have stopped this?

For the detection type in the alert, look up which controls matter (knowledge.py) and check
each against the tenant's policies and settings. The output is a list of gaps with a plain
recommendation. This is prevention advice; it never changes a policy.
"""
from . import knowledge as kb
from .tools_data import DATA


def review(risk_event_type, user=None, app=None):
    det = kb.DETECTIONS.get(risk_event_type) or kb.DETECTIONS["generic"]
    by_control = {p["control"]: p for p in DATA["ca_policies"]}
    findings = []
    for cid in det["controls"]:
        c = kb.CONTROLS[cid]
        if cid == "EXCLUSIONS":
            hit = [p["name"] for p in DATA["ca_policies"] if user in p["excluded_users"]]
            status = "gap: user excluded" if hit else "ok"
            fix = f"Remove {user} from the exclusion list of: {', '.join(hit)}" if hit else ""
        elif c["kind"] == "setting":
            ok = DATA["tenant_settings"].get(cid, False)
            status, fix = ("ok", "") if ok else ("gap: not configured", f"Turn on: {c['name']}. {c['expect']}")
        else:
            p = by_control.get(cid)
            if not p:
                status, fix = "gap: no policy", f"Create it. {c['expect']}"
            elif p["state"] == "reportOnly":
                status, fix = "gap: report-only", f"'{p['name']}' only reports. Review its impact, then switch it on"
            elif user and user in p["excluded_users"]:
                status, fix = "gap: user excluded", f"Remove {user} from the exclusions of '{p['name']}'"
            elif app and p["apps"] != "all" and app not in p["apps"]:
                status, fix = "gap: app not covered", f"'{p['name']}' covers {', '.join(p['apps'])} only; this sign-in used {app}"
            else:
                status, fix = "ok", ""
        findings.append({"control": cid, "name": c["name"], "kind": c["kind"], "status": status, "recommendation": fix})
    if user and "EXCLUSIONS" not in det["controls"]:      # a forgotten exclusion matters for every detection
        hit = [p["name"] for p in DATA["ca_policies"] if user in p["excluded_users"]]
        if hit:
            findings.append({"control": "EXCLUSIONS", "name": kb.CONTROLS["EXCLUSIONS"]["name"], "kind": "ca", "status": "gap: user excluded",
                             "recommendation": f"Remove {user} from the exclusion list of: {', '.join(hit)}"})
    gaps = [f for f in findings if f["status"] != "ok"]
    return {"risk_event_type": risk_event_type, "controls_checked": len(findings), "gaps": gaps,
            "ok": [f["name"] for f in findings if f["status"] == "ok"]}


def tenant_status():
    """'ok' or 'gap' for every control, for the tenant as a whole (used by the control matrix graphic)."""
    by_control = {p["control"]: p for p in DATA["ca_policies"]}
    out = {}
    for cid, c in kb.CONTROLS.items():
        if cid == "EXCLUSIONS":
            ok = not any(len(p["excluded_users"]) > 1 for p in DATA["ca_policies"])     # more than the break-glass account
        elif c["kind"] == "setting":
            ok = DATA["tenant_settings"].get(cid, False)
        else:
            p = by_control.get(cid)
            ok = bool(p) and p["state"] == "enabled" and p["apps"] == "all"
        out[cid] = "ok" if ok else "gap"
    return out
