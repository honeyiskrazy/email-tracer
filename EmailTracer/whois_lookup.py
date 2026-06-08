"""Dedicated WHOIS investigation helpers for EmailTracer."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

try:
    import whois
except ImportError:  # pragma: no cover - handled by run_whois
    whois = None


EMAIL_DOMAIN_RE = re.compile(
    r"(?:<)?[A-Za-z0-9._%+\-]+@([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})(?:>)?",
    re.IGNORECASE,
)
WHOIS_FIELDS = [
    "registrar",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "emails",
    "name",
    "org",
    "country",
]
NOT_AVAILABLE = "Not Available"
PRIVACY_TERMS = ("privacy", "protect", "guard", "proxy", "whoisguard")


def extract_domain(email_str: str) -> str:
    """Extract only the domain from an email address or display-name header."""
    match = EMAIL_DOMAIN_RE.search(email_str or "")
    return match.group(1).strip().lower() if match else ""


def _first_value(value: Any) -> Any:
    if value is None or value == "":
        return NOT_AVAILABLE
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if item is not None and item != "":
                return item
        return NOT_AVAILABLE
    return value


def _record_get(record: Any, field: str) -> Any:
    try:
        return record.get(field)
    except AttributeError:
        return getattr(record, field, None)
    except Exception:
        return None


def run_whois(domain: str) -> dict[str, Any]:
    """Run python-whois and return normalized WHOIS fields."""
    try:
        if not domain:
            return {"error": "No domain provided"}
        if whois is None:
            return {"error": "python-whois is not installed"}

        record = whois.whois(domain)
        result: dict[str, Any] = {"domain": domain}
        for field in WHOIS_FIELDS:
            result[field] = _first_value(_record_get(record, field))
        return result
    except Exception as exc:
        return {"error": str(exc)}


def _as_datetime(value: Any) -> datetime | None:
    if value in (None, "", NOT_AVAILABLE):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (list, tuple, set)):
        return _as_datetime(_first_value(value))
    if isinstance(value, str):
        text = value.strip()
        for parser in (
            lambda item: datetime.fromisoformat(item.replace("Z", "+00:00")),
            lambda item: datetime.strptime(item, "%Y-%m-%d %H:%M:%S"),
            lambda item: datetime.strptime(item, "%Y-%m-%d"),
            lambda item: datetime.strptime(item, "%d-%b-%Y"),
            lambda item: datetime.strptime(item, "%Y.%m.%d %H:%M:%S"),
        ):
            try:
                parsed = parser(text)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def analyze_whois(whois_data: dict[str, Any]) -> dict[str, list[str]]:
    """Return WHOIS investigation flags."""
    flags: list[str] = []
    now = datetime.now(timezone.utc)

    creation_date = _as_datetime(whois_data.get("creation_date"))
    if creation_date is not None:
        age_days = (now - creation_date).days
        if 0 <= age_days < 30:
            flags.append("RECENTLY_REGISTERED")

    expiration_date = _as_datetime(whois_data.get("expiration_date"))
    if expiration_date is not None:
        days_until_expiration = (expiration_date - now).days
        if 0 <= days_until_expiration < 30:
            flags.append("EXPIRING_SOON")

    emails = str(whois_data.get("emails", "")).lower()
    if any(term in emails for term in PRIVACY_TERMS):
        flags.append("PRIVACY_PROTECTED")

    return {"flags": flags}


def compare_domains(from_email: str, return_path: str) -> dict[str, Any]:
    """Compare From and Return-Path domains for mismatch indicators."""
    from_domain = extract_domain(from_email)
    return_path_domain = extract_domain(return_path)
    if from_domain and return_path_domain and from_domain != return_path_domain:
        return {
            "mismatch": True,
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
        }
    return {"mismatch": False}
