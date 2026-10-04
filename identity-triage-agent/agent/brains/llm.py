"""The language-model brain. Works with any endpoint that speaks the OpenAI chat completions
format with tool calling: OpenAI, Azure OpenAI, or a local model served by Ollama or similar.

Configure with environment variables (never put keys in code):

    LLM_BASE_URL   default https://api.openai.com/v1
                   Azure OpenAI: https://<resource>.openai.azure.com/openai/deployments/<deployment>
                   Ollama:       http://localhost:11434/v1
    LLM_API_KEY    the key (not needed for a local model)
    LLM_MODEL      model name, e.g. gpt-4o-mini or llama3.1
    LLM_API_VERSION  Azure OpenAI only, e.g. 2024-10-21
    LLM_TOOL_CHOICE  default "required" (the model must call a tool each turn); set "auto" if your server rejects it

The brain is stateless: on every step it rebuilds the conversation from the trace the loop
keeps, so the loop stays the single source of truth for what happened.
"""
import json, os, urllib.request

from ..prompts import SYSTEM
from ..tools import TOOL_SCHEMAS


def _http_post(url, headers, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


class LLMBrain:
    name = "llm"

    def __init__(self, post=_http_post):
        self.base = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.key = os.environ.get("LLM_API_KEY", "")
        self.model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.api_version = os.environ.get("LLM_API_VERSION", "")
        self.tool_choice = os.environ.get("LLM_TOOL_CHOICE", "required")
        self.post = post                       # injectable, so the tests need no network
        self.name = f"llm ({self.model})"

    def _messages(self, alert_id, trace):
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Investigate alert {alert_id}."}]
        for s in trace:
            msgs.append({"role": "assistant", "content": None, "tool_calls": [
                {"id": s["id"], "type": "function", "function": {"name": s["tool"], "arguments": json.dumps(s["args"])}}]})
            # Tool output is wrapped and labelled so log text can't pass for an instruction.
            msgs.append({"role": "tool", "tool_call_id": s["id"],
                         "content": json.dumps({"tool_call_id": s["id"], "untrusted_log_data": s["result"]})})
        return msgs

    def step(self, alert_id, trace):
        url = f"{self.base}/chat/completions" + (f"?api-version={self.api_version}" if self.api_version else "")
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["api-key" if self.api_version else "Authorization"] = self.key if self.api_version else f"Bearer {self.key}"
        body = {"model": self.model, "messages": self._messages(alert_id, trace), "tools": TOOL_SCHEMAS,
                "tool_choice": self.tool_choice, "temperature": 0}
        msg = self.post(url, headers, body)["choices"][0]["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append({"name": tc["function"]["name"], "args": args if isinstance(args, dict) else {}})
        return calls
