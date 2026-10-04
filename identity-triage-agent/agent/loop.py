"""The agent loop: ask the brain what to do next, run the tool, hand back the result, repeat.

The loop owns everything that must not depend on the model behaving:
a step budget, the tool allow-list, the action policy, the verifier and the audit trail.
"""
import json
from dataclasses import dataclass, field

from . import knowledge as kb
from . import policy, tools, verifier

MAX_STEPS = 30
CONTAINMENT_NEEDS = {"compromised", "attack_blocked"}   # verdicts that justify acting
CLOSURE_NEEDS = {"benign"}                              # verdicts that justify marking the risk safe


@dataclass
class Result:
    alert_id: str
    brain: str
    trace: list = field(default_factory=list)       # every tool call, in order
    proposals: list = field(default_factory=list)   # {action, target, reason, outcome, why}
    submitted: dict = None                          # what the model said
    verdict: str = "needs_human"                    # what stands after verification
    notes: list = field(default_factory=list)
    stopped: str = ""
    priority: str = ""
    reopened: str = ""                               # set when a closed alert was sent for investigation anyway
    ca_gaps: list = field(default_factory=list)      # prevention findings from the Conditional Access review

    def actions(self, outcome=None):
        return [p["action"] for p in self.proposals if outcome is None or p["outcome"] == outcome]


def investigate(brain, alert_id, max_steps=MAX_STEPS):
    res = Result(alert_id, brain.name)
    alert = tools.get_alert(alert_id)
    profile = tools.get_user_profile(alert.get("subject", "")) if "error" not in alert else {}
    auto_used = 0
    res.priority = kb.priority(alert.get("risk_event_type"), alert.get("risk_level"), profile.get("privileged", False))

    # Pre-triage in code: alerts ID Protection already closed stay closed unless the data disagrees. No model call.
    close, reason = verifier.pretriage(alert)
    if close:
        res.verdict, res.notes, res.priority = "auto_closed", [reason], "closed"
        return res
    res.reopened = reason

    while len(res.trace) < max_steps and res.submitted is None:
        calls = brain.step(alert_id, res.trace)
        if not calls:
            res.stopped = "brain returned no tool call"
            break
        for call in calls:
            name, args = call["name"], call.get("args") or {}
            step = {"id": f"call-{len(res.trace)+1}", "tool": name, "args": args}
            if name in tools.READ_TOOLS:
                try:
                    step["result"] = tools.READ_TOOLS[name](**args)
                except TypeError as e:
                    step["result"] = {"error": f"bad arguments: {e}"}
            elif name == "propose_action":
                outcome, why = policy.decide(args.get("action"), args.get("target"), alert, profile, auto_used)
                auto_used += outcome == "auto"
                res.proposals.append({"action": args.get("action"), "target": args.get("target"), "reason": args.get("reason", ""),
                                      "outcome": outcome, "why": why})
                step["result"] = {"policy": outcome, "why": why}
            elif name == "submit_verdict":
                res.submitted = args
                step["result"] = {"received": True}
            else:
                step["result"] = {"error": f"unknown tool '{name}'"}     # allow-list: anything else is refused
            res.trace.append(step)
            if res.submitted is not None or len(res.trace) >= max_steps:
                break

    if res.submitted is None:
        res.stopped = res.stopped or f"step budget of {max_steps} reached"
        res.notes.append(f"no verdict submitted ({res.stopped}): sent to a person")
    else:
        res.verdict, notes = verifier.verify(res.submitted, res.trace, alert)
        res.notes += notes

    # Containment only goes ahead on a verdict that survived verification.
    for p in res.proposals:
        if p["outcome"] not in ("auto", "approval") or p["action"] == "notify_security_lead":
            continue
        needs = CLOSURE_NEEDS if p["action"] in tools.CLOSURE else CONTAINMENT_NEEDS
        if res.verdict not in needs:
            p["outcome"], p["why"] = "held", f"verdict is '{res.verdict}', so nothing is done until a person decides"
    for s in res.trace:
        if s["tool"] == "review_conditional_access" and isinstance(s["result"], dict):
            res.ca_gaps = s["result"].get("gaps", [])
    return res


def to_audit_record(res):
    return {"alert": res.alert_id, "brain": res.brain, "priority": res.priority, "verdict": res.verdict, "reopened": res.reopened,
            "ca_gaps": [g["name"] + " (" + g["status"] + ")" for g in res.ca_gaps], "submitted": res.submitted, "notes": res.notes,
            "proposals": res.proposals, "tool_calls": [{"id": s["id"], "tool": s["tool"], "args": s["args"]} for s in res.trace]}


def render(res):
    """A readable account of one investigation."""
    out = [f"Alert {res.alert_id} · priority {res.priority} · brain: {res.brain}", ""]
    if res.verdict == "auto_closed":
        return "\n".join(out + ["  No investigation needed.", f"Final verdict: AUTO_CLOSED. {res.notes[0]}"])
    if res.reopened:
        out += [f"  Reopened: {res.reopened}", ""]
    for s in res.trace:
        args = ", ".join(f"{k}={v}" for k, v in s["args"].items() if k not in ("evidence", "summary", "reason") and v)
        if s["tool"] == "propose_action":
            out.append(f"  {s['id']:>8}  propose_action({args})  ->  {s['result']['policy'].upper()}: {s['result']['why']}")
        elif s["tool"] == "submit_verdict":
            out.append(f"  {s['id']:>8}  submit_verdict({s['args']['verdict']}, confidence {s['args'].get('confidence')})")
        else:
            out.append(f"  {s['id']:>8}  {s['tool']}({args})")
    out.append("")
    if res.submitted:
        out.append(f"Brain said: {res.submitted['verdict']}. {res.submitted.get('summary', '')}")
        for e in res.submitted.get("evidence", []):
            out.append(f"   - {e['claim']}  [{e['source']}]")
    out.append(f"Final verdict after verification: {res.verdict.upper()}")
    for n in res.notes:
        out.append(f"   ! {n}")
    for p in res.proposals:
        out.append(f"   {p['outcome']:>8}  {p['action']} on {p['target']}  ({p['why']})")
    if res.ca_gaps:
        out.append("Prevention: Conditional Access and settings gaps that let this through")
        for g in res.ca_gaps:
            out.append(f"   - {g['name']} [{g['status'].replace('gap: ', '')}]: {g['recommendation']}")
    return "\n".join(out)
