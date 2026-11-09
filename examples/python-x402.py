"""
Minimal Python paid-call sketch for GrindFree x402 APIs.
Install a maintained x402 Python client that supports ExactEvmScheme on Base
(or drive PAYMENT-REQUIRED → PAYMENT-SIGNATURE yourself). This file shows the
HTTP shapes; swap `paid_post` for your wallet-backed client.
Never put GrindFree keys here — use the caller's wallet only.
"""
from __future__ import annotations
import json
import os
import urllib.request

PS = "https://promptshield.grindfree.net/v1/screen"
CS = "https://crawlsafe.grindfree.net/v1/check"
TG = "https://toolguard.grindfree.net/v1/evaluate"


def unpaid_probe(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"status": r.status, "body": json.loads(r.read())}
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "payment_required": e.headers.get("PAYMENT-REQUIRED"),
            "body": json.loads(e.read().decode()),
        }


def paid_post(url: str, body: dict) -> dict:
    """Replace with your x402-paying client bound to PRIVATE_KEY / X402_PRIVATE_KEY."""
    raise NotImplementedError(
        "Wire your Base USDC signer here (e.g. official x402 Python ExactEvm client). "
        f"Missing key? set PRIVATE_KEY. Target={url}"
    )


if __name__ == "__main__":
    print("unpaid screen", unpaid_probe(PS, {"content": "hi", "format": "text"})["status"])
    print("unpaid check", unpaid_probe(CS, {"url": "https://promptshield.grindfree.net/"})["status"])
    print("unpaid evaluate", unpaid_probe(TG, {"tool": "http.fetch", "policy": {"allow_tools": ["http.fetch"]}})["status"])
    if os.environ.get("PRIVATE_KEY") and os.environ.get("I_APPROVE_SPEND") == "yes":
        print(paid_post(PS, {"content": "hi", "format": "text"}))
