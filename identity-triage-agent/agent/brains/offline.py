"""A rule-based stand-in for the language model.

It follows the same contract as the LLM brain (look at the history, return the next tool
calls), so the loop, guardrails and evals run with no API key, no cost and the same result
every time. It encodes how I would work the alert by hand, using the playbook in
knowledge.py. It is not AI; the LLM brain is.
"""
from datetime import datetime, timedelta

PERSISTENCE_FIX = {"User registered security info": "remove_mfa_method", "New-InboxRule": "disable_inbox_rule",
                   "Set-Mailbox": "remove_mail_forwarding", "Consent to application": "revoke_app_consent",
                   "Add member to role": "remove_role_assignment"}
BAD_NETWORKS = ("anonymising proxy", "hosting provider")


def _find(trace, tool, **match):
    for s in trace:
        if s["tool"] == tool and all(s["args"].get(k) == v for k, v in match.items()):
            return s
    return None


def _call(name, **args):
    return {"name": name, "args": args}


class OfflineBrain:
    name = "offline rules"

    def step(self, alert_id, trace):
        alert_step = _find(trace, "get_alert")
        if not alert_step:
            return [_call("get_alert", alert_id=alert_id)]
        alert = alert_step["result"]
        if alert["type"] == "Password spray attempt":
            return self._spray_ip(alert, trace)
        return self._user(alert, alert_step, trace)

    # ---- one IP against many accounts (a Sentinel rule, not an ID Protection detection) ----
    def _spray_ip(self, alert, trace):
        ip = alert["ip"]
        from_ip = _find(trace, "get_signins_from_ip", ip=ip)
        if not from_ip:
            return [_call("get_signins_from_ip", ip=ip), _call("get_ip_reputation", ip=ip), _call("check_named_location", ip=ip)]
        rep, r = _find(trace, "get_ip_reputation", ip=ip), from_ip["result"]
        if r["successes"]:
            return [self._verdict("needs_human", "medium", "The spraying IP has at least one successful sign-in; each of those accounts needs its own investigation.",
                                  [(f"{len(r['successes'])} successful sign-in(s) from {ip}", from_ip["id"])])]
        if not _find(trace, "propose_action"):
            return [_call("propose_action", action="block_ip", target=ip, reason=f"{r['attempts']} failed sign-ins against {len(r['users_targeted'])} accounts")]
        if not _find(trace, "review_conditional_access"):
            return [_call("review_conditional_access", risk_event_type="passwordSpray")]
        return [self._verdict("attack_blocked", "high", f"Password spray from {ip}. No attempt succeeded, so no account is compromised.",
                              [(f"{r['attempts']} attempts against {len(r['users_targeted'])} accounts, 0 successful", from_ip["id"]),
                               (f"IP is classed as '{rep['result']['category']}' with {rep['result']['abuse_reports']} abuse reports", rep["id"])])]

    # ---- one account ------------------------------------------------------------------
    def _user(self, alert, alert_step, trace):
        user, rtype = alert["subject"], alert.get("risk_event_type")
        prof, sign, aud = _find(trace, "get_user_profile", user=user), _find(trace, "get_signins", user=user), _find(trace, "get_audit_events", user=user)
        if not (prof and sign and aud):
            first = [_call("get_user_profile", user=user), _call("get_signins", user=user), _call("get_audit_events", user=user)]
            if rtype:
                first += [_call("lookup_playbook", risk_event_type=rtype), _call("get_risk_detections", user=user)]
            return first
        profile, signins, events = prof["result"], sign["result"]["signins"], aud["result"]["events"]
        book = _find(trace, "lookup_playbook")
        playbook = book["result"] if book else {"if_malicious_propose": ["revoke_sessions", "require_password_reset", "confirm_user_compromised"],
                                                "if_expected": "confirm_sign_in_safe", "name": alert["type"]}

        if profile.get("break_glass"):
            if not _find(trace, "propose_action"):
                return [_call("propose_action", action="notify_security_lead", target=user, reason="Emergency access account was used")]
            return [self._verdict("needs_human", "high", "A break-glass account signed in. This is always reviewed by a person; I take no containment action on these accounts.",
                                  [("account is flagged break-glass", prof["id"]), (f"{len(signins)} sign-in(s) in the window", sign["id"])])]

        # The attacker knows the password, whatever the sign-in logs say.
        if rtype == "leakedCredentials":
            if profile["password_last_changed"] >= alert["time"]:
                return self._finish(trace, alert, user, None, "benign", "high", "The leaked password was changed after the leak was detected.",
                                    [("password changed after the detection", prof["id"]), ("no account changes in the window", aud["id"])], [playbook["if_expected"]])
            return self._finish(trace, alert, user, None, "compromised", "high",
                                "The user's password is in a breach and has not been changed. Treat the credential as compromised and force a secure change.",
                                [("password last changed before the leak was detected", prof["id"]), ("detection is always high risk; the password is known to others", book["id"])],
                                playbook["if_malicious_propose"])

        odd = [s for s in signins if s["country"] not in profile["usual_countries"] or s["ip"] == alert["ip"]]
        wins = [s for s in odd if s["result"] == "success"]
        need = []
        for s in odd:
            if not _find(trace, "check_named_location", ip=s["ip"]) and not any(n["args"].get("ip") == s["ip"] for n in need):
                need += [_call("check_named_location", ip=s["ip"]), _call("get_ip_reputation", ip=s["ip"])]
            if s["device_id"] and not _find(trace, "get_device", device_id=s["device_id"]) and not any(n["args"].get("device_id") == s["device_id"] for n in need):
                need.append(_call("get_device", device_id=s["device_id"]))
        if need:
            return need

        app = (wins or odd or [{}])[-1].get("app")
        if rtype == "passwordSpray" and not wins:
            fails = [s for s in odd if s["ip"] == alert["ip"]]
            rep = _find(trace, "get_ip_reputation", ip=alert["ip"])
            return self._finish(trace, alert, user, app, "attack_blocked", "high",
                                "A spray guessed this user's password, and MFA stopped the sign-in. No session was issued, but the password is known and must change.",
                                [(f"{len(fails)} attempts from {alert['ip']}, none successful; the last one reached MFA", sign["id"]),
                                 (f"IP is classed as '{rep['result']['category']}' with {rep['result']['abuse_reports']} abuse reports", rep["id"])],
                                playbook["if_malicious_propose"], targets={"block_ip": alert["ip"]})

        ev, untrusted = [], []
        for s in wins:
            loc = _find(trace, "check_named_location", ip=s["ip"])
            if loc["result"]["trusted"]:
                ev.append((f"sign-in {s['id']} from {s['country']} came through {loc['result']['named_location']}, a trusted location", loc["id"]))
            else:
                untrusted.append(s)
        if not untrusted:
            for s in wins:
                dev = s["device_id"] and _find(trace, "get_device", device_id=s["device_id"])
                if dev and dev["result"].get("compliant") and len(ev) < 3:
                    ev.append((f"device {dev['result']['name']} is compliant and belongs to the user", dev["id"]))
            if len(ev) < 2:
                ev += [("no successful sign-in from an unfamiliar location", sign["id"]), ("no account changes in the window", aud["id"])]
            return self._finish(trace, alert, user, app, "benign", "high",
                                "The unusual location is a trusted corporate network and the device is the user's own compliant laptop.", ev, [playbook["if_expected"]])

        flags, fixes, takeover = [], [], False
        for s in untrusted:
            when = datetime.fromisoformat(s["time"])
            rep = _find(trace, "get_ip_reputation", ip=s["ip"])
            bad_ip = rep["result"]["category"] in BAD_NETWORKS
            denials = [d for d in signins if d["ip"] == s["ip"] and d["mfa"] == "denied"
                       and timedelta(0) <= when - datetime.fromisoformat(d["time"]) <= timedelta(minutes=30)]
            changes = [e for e in events if e["ip"] == s["ip"] and datetime.fromisoformat(e["time"]) >= when]
            if bad_ip:
                flags.append((f"successful sign-in {s['id']} from {s['country']} through a network classed as '{rep['result']['category']}'", rep["id"]))
            if "AI ANALYST" in s["user_agent"].upper():
                flags.append((f"sign-in {s['id']} carries text addressed to an AI analyst in its user agent: an attempt to steer automated triage", sign["id"]))
            if len(denials) >= 3:
                flags.append((f"{len(denials)} MFA prompts denied in the half hour before sign-in {s['id']} succeeded (MFA fatigue)", sign["id"]))
            for e in changes:
                flags.append((f"{e['operation']} from the same IP after the sign-in: {e['detail']}", aud["id"]))
                if e["operation"] in PERSISTENCE_FIX:
                    fixes.append(PERSISTENCE_FIX[e["operation"]])
            takeover = takeover or bool(changes) or (bad_ip and len(denials) >= 3)

        if alert.get("risk_state") == "confirmedCompromised":
            takeover = True                                                       # decided by an administrator; our job is the scope
            flags.append(("an administrator confirmed this user compromised", alert_step["id"]))
        if not takeover:
            dev = untrusted[0]["device_id"] and _find(trace, "get_device", device_id=untrusted[0]["device_id"])
            ev = [(f"sign-in {untrusted[0]['id']} from {untrusted[0]['country']}, not a usual country for this user", sign["id"])]
            if dev:
                ev.append((f"but on the user's own compliant device {dev['result']['name']}", dev["id"]))
            ev.append(("no account changes afterwards", aud["id"]))
            return self._finish(trace, alert, user, app, "needs_human", "medium",
                                "A new country with nothing else suspicious. Most likely travel; confirm with the user before closing.", ev, [])

        wanted = list(playbook["if_malicious_propose"]) + fixes + (["notify_security_lead"] if profile.get("privileged") else [])
        if alert.get("risk_state") == "confirmedCompromised":
            wanted = [w for w in wanted if w != "confirm_user_compromised"]      # an administrator has already done that
        return self._finish(trace, alert, user, app, "compromised", "high",
                            f"The account was taken over: {playbook['name'].lower()}, followed by changes that keep the attacker's access.", flags, wanted)

    # ---- propose, review prevention, then conclude --------------------------------------
    def _finish(self, trace, alert, user, app, verdict, confidence, summary, evidence, actions, targets=None):
        done = [s["args"]["action"] for s in trace if s["tool"] == "propose_action"]
        todo = [a for a in dict.fromkeys(actions) if a not in done]
        if todo:
            return [_call("propose_action", action=a, target=(targets or {}).get(a, user), reason=evidence[0][0]) for a in todo]
        if alert.get("risk_event_type") and not _find(trace, "review_conditional_access"):
            return [_call("review_conditional_access", risk_event_type=alert["risk_event_type"], user=user, app=app)]
        return [self._verdict(verdict, confidence, summary, evidence)]

    @staticmethod
    def _verdict(verdict, confidence, summary, evidence):
        return {"name": "submit_verdict", "args": {"verdict": verdict, "confidence": confidence, "summary": summary,
                                                    "evidence": [{"claim": c, "source": src} for c, src in evidence]}}
