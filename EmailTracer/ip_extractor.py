"""IP filtering helpers for EmailTracer."""

from __future__ import annotations

from typing import Any


MAIL_INFRASTRUCTURE_TERMS = (
    "google llc",
    "google",
    "microsoft corporation",
    "microsoft",
    "yahoo",
    "oath inc",
    "amazon.com",
    "amazon",
    "aws",
    "hewlett-packard",
    "hewlett packard",
    "cloudflare",
    "mailchimp",
    "rocket science group",
    "sendgrid",
    "twilio",
    "mimecast",
    "proofpoint",
)


def is_mail_infrastructure_ip(ip_api_data: dict[str, Any]) -> bool:
    """Return True when ip-api identifies a major mail provider or relay."""
    if ip_api_data.get("status") != "success":
        return False

    org = str(ip_api_data.get("org", "") or "").lower()
    isp = str(ip_api_data.get("isp", "") or "").lower()
    return any(term in org or term in isp for term in MAIL_INFRASTRUCTURE_TERMS)
