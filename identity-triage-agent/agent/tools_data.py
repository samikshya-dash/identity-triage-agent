"""Loads the synthetic tenant once, for every module that reads it."""
import json
from datetime import datetime
from pathlib import Path

DATA = json.loads((Path(__file__).resolve().parent.parent / "data/tenant.json").read_text())
NOW = datetime.fromisoformat(DATA["now"])
