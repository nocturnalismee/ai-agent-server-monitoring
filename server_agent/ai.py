from __future__ import annotations

import json
import ssl
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .redaction import sanitize_incident


class AIAnalyzer:
    """Gemini enrichment via the official HTTPS REST API and Python stdlib."""

    _API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
    _SYSTEM_INSTRUCTION = (
        "You are a Linux SRE incident assistant. Analyze only the supplied telemetry. "
        "Do not invent facts. Keep the answer under 180 words. Return plain text with: "
        "Likely cause, Immediate checks (safe/read-only commands only), Risk, and Next step. "
        "Never recommend destructive commands or automatic remediation."
    )

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger
        self.enabled = bool(config.gemini_enabled and config.gemini_api_key)
        self.ssl_context = ssl.create_default_context()

    @staticmethod
    def _extract_text(response: Dict[str, Any]) -> str:
        candidates = response.get("candidates", [])
        if not isinstance(candidates, list) or not candidates:
            return ""
        content = candidates[0].get("content", {}) if isinstance(candidates[0], dict) else {}
        parts = content.get("parts", []) if isinstance(content, dict) else []
        if not isinstance(parts, list):
            return ""
        return "".join(
            part.get("text", "") for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ).strip()

    def analyze(self, incident) -> str:
        if not self.enabled:
            return ""

        # Defense in depth: the Agent already redacts outbound telemetry.
        incident = sanitize_incident(incident)
        payload = {
            "server": self.cfg.server_name,
            "environment": self.cfg.environment,
            "incident": incident.as_dict(),
        }
        body = {
            "systemInstruction": {"parts": [{"text": self._SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": json.dumps(payload, ensure_ascii=False)}]}],
            "generationConfig": {
                "maxOutputTokens": self.cfg.gemini_max_output_tokens,
                "temperature": 0.2,
            },
        }
        request = Request(
            f"{self._API_BASE}/{self.cfg.gemini_model}:generateContent",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "x-goog-api-key": self.cfg.gemini_api_key,
            },
            method="POST",
        )
        try:
            with urlopen(
                request, timeout=self.cfg.gemini_timeout_seconds, context=self.ssl_context
            ) as response:
                data = json.loads(response.read().decode("utf-8"))
            if not isinstance(data, dict):
                self.logger.warning("Gemini API returned an invalid response")
                return ""
            return self._extract_text(data)[:4000]
        except HTTPError as exc:
            self.logger.warning("Gemini API returned HTTP %s", exc.code)
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            self.logger.warning("Gemini analysis failed: %s", exc)
        return ""

    def close(self):
        """Kept for a stable Agent lifecycle; stdlib HTTP requests are per-call."""
