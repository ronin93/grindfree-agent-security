"""
LangChain-style tool wrapper sketch.
Uses HTTP + your own x402-paying session. Do not embed GrindFree keys.
"""
from __future__ import annotations
from typing import Any, Optional

# from langchain_core.tools import tool  # optional


def make_promptshield_screen(paid_post):
    """paid_post(url, json_body) -> dict; must settle x402 with the caller's wallet."""

    def promptshield_screen(content: str, format: str = "text") -> dict[str, Any]:
        """Screen untrusted text/HTML for prompt injection before the model reads it."""
        result = paid_post(
            "https://promptshield.grindfree.net/v1/screen",
            {"content": content, "format": format},
        )
        if result.get("risk") == "high":
            return {
                "blocked": True,
                "findings": result.get("findings"),
                "sanitized": result.get("sanitized"),
            }
        return {"blocked": False, **result}

    return promptshield_screen


def make_crawlsafe_check(paid_post):
    def crawlsafe_check(url: str, user_agent: str = "MyBot/1.0", check_page: bool = True) -> dict:
        return paid_post(
            "https://crawlsafe.grindfree.net/v1/check",
            {"url": url, "user_agent": user_agent, "check_page": check_page},
        )

    return crawlsafe_check


def make_toolguard_evaluate(paid_post):
    def toolguard_evaluate(
        tool: str,
        destination: Optional[dict] = None,
        policy: Optional[dict] = None,
        **kwargs,
    ) -> dict:
        """Caller MUST enforce allow|review|deny. Funded settlement+delivery unproven for ToolGuard."""
        body = {"tool": tool, **kwargs}
        if destination is not None:
            body["destination"] = destination
        if policy is not None:
            body["policy"] = policy
        return paid_post("https://toolguard.grindfree.net/v1/evaluate", body)

    return toolguard_evaluate
