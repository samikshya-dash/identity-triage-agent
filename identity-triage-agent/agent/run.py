"""Investigate one alert, or all of them.

    python -m agent.run ALERT-001                # offline brain
    python -m agent.run ALERT-001 --brain llm    # a real model (see README for the environment variables)
    python -m agent.run --all
"""
import argparse, json
from pathlib import Path

from .brains.offline import OfflineBrain
from .loop import investigate, render, to_audit_record
from .tools import DATA

ROOT = Path(__file__).resolve().parent.parent


def make_brain(kind):
    if kind == "llm":
        from .brains.llm import LLMBrain
        return LLMBrain()
    return OfflineBrain()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("alert", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--brain", choices=["offline", "llm"], default="offline")
    a = ap.parse_args()
    brain = make_brain(a.brain)
    alerts = list(DATA["alerts"]) if a.all or not a.alert else [a.alert]
    log = (ROOT / "audit_log.jsonl").open("a")
    for alert_id in alerts:
        res = investigate(brain, alert_id)
        print(render(res), "\n" + "-" * 78)
        log.write(json.dumps(to_audit_record(res)) + "\n")


if __name__ == "__main__":
    main()
