"""Email header parsing utilities for EmailTracer."""

from __future__ import annotations

from email import policy
from email.parser import Parser
from email.utils import parseaddr
import ipaddress
import re
from typing import Any


IPV4_RE = re.compile(
    r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"
)
IPV6_RE = re.compile(r"(?<![\w:])(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9:.]{1,}(?![\w:])")
DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def _clean_header(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())


def _all_headers_as_dict(message: Any) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key, []).append(_clean_header(value))
    return headers


def _first(message: Any, name: str) -> str:
    return _clean_header(message.get(name, ""))


def parse_headers(raw_text: str) -> dict[str, Any]:
    """Parse raw email headers and return the fields used by the app."""
    raw_text = raw_text or ""
    message = Parser(policy=policy.default).parsestr(raw_text)
    all_headers = _all_headers_as_dict(message)

    headers: dict[str, Any] = {
        "from": _first(message, "From"),
        "reply_to": _first(message, "Reply-To"),
        "return_path": _first(message, "Return-Path"),
        "message_id": _first(message, "Message-ID"),
        "subject": _first(message, "Subject"),
        "date": _first(message, "Date"),
        "received": [_clean_header(value) for value in message.get_all("Received", [])],
        "x_originating_ip": [_clean_header(value) for value in message.get_all("X-Originating-IP", [])],
        "authentication_results": [
            _clean_header(value) for value in message.get_all("Authentication-Results", [])
        ],
        "arc_authentication_results": [
            _clean_header(value) for value in message.get_all("ARC-Authentication-Results", [])
        ],
        "received_spf": [_clean_header(value) for value in message.get_all("Received-SPF", [])],
        "dkim_signatures": [_clean_header(value) for value in message.get_all("DKIM-Signature", [])],
        "all_headers": all_headers,
        "header_count": len(message.items()),
    }
    headers["provider"] = detect_provider(headers)
    headers["dkim_selectors"] = extract_dkim_selectors(headers["dkim_signatures"])
    return headers


def detect_provider(headers: dict[str, Any]) -> str:
    """Fingerprint the likely sending provider from common header patterns."""
    all_headers = headers.get("all_headers", {})
    keys = " ".join(all_headers.keys()).lower()
    values = " ".join(
        value.lower()
        for header_values in all_headers.values()
        for value in header_values
        if isinstance(value, str)
    )
    haystack = f"{keys} {values}"

    provider_patterns = [
        ("Gmail / Google Workspace", ["x-google-dkim-signature", "google.com", "gmail.com"]),
        (
            "Outlook / Microsoft 365",
            ["x-ms-exchange", "x-microsoft", "protection.outlook.com", "outlook.com"],
        ),
        ("Yahoo Mail", ["x-yahoo", "ymail", "yahoodns.net", "yahoo.com"]),
        ("Zoho Mail", ["x-zoho", "zoho.com"]),
        ("Proton Mail", ["protonmail", "proton.me"]),
        ("Amazon SES", ["amazonses.com", "x-ses-", "amazonses"]),
        ("SendGrid", ["sendgrid.net", "x-sg-", "x-sendgrid"]),
        ("Mailgun", ["mailgun.org", "mailgun.net", "x-mailgun"]),
        ("Mailchimp / Mandrill", ["mandrillapp.com", "mailchimpapp.net", "x-mandrill"]),
        ("SparkPost", ["sparkpostmail.com", "sparkpost"]),
    ]
    for provider, patterns in provider_patterns:
        if any(pattern in haystack for pattern in patterns):
            return provider

    from_domain = extract_domain_from_header(headers.get("from", ""))
    if from_domain:
        return f"Custom Domain ({from_domain})"
    return "Unknown"


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _candidate_ips(text: str) -> list[str]:
    candidates = IPV4_RE.findall(text or "")
    candidates.extend(match.group(0).strip("[]()<>.,;") for match in IPV6_RE.finditer(text or ""))
    return candidates


def extract_ips(received_headers: list[str]) -> list[str]:
    """Extract unique public IP addresses from Received and related headers."""
    seen: set[str] = set()
    public_ips: list[str] = []
    for header in received_headers or []:
        for candidate in _candidate_ips(header):
            try:
                normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if normalized in seen or not _is_public_ip(normalized):
                continue
            seen.add(normalized)
            public_ips.append(normalized)
    return public_ips


def extract_domain_from_header(value: str) -> str:
    """Extract the domain part from an email-like header value."""
    if not value:
        return ""
    _, address = parseaddr(value)
    address = address or value.strip("<> ")
    if "@" in address:
        domain = address.rsplit("@", 1)[1].strip(">. ").lower()
        return domain
    match = DOMAIN_RE.search(value)
    return match.group(1).lower() if match else ""


def extract_message_id_domain(message_id: str) -> str:
    match = DOMAIN_RE.search(message_id or "")
    return match.group(1).lower() if match else ""


def extract_dkim_selectors(signatures: list[str]) -> list[dict[str, str]]:
    """Return DKIM selector/domain pairs from DKIM-Signature headers."""
    selectors: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for signature in signatures or []:
        selector = ""
        domain = ""
        for part in signature.split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if key == "s":
                selector = value
            elif key == "d":
                domain = value.lower()
        if selector and domain and (selector, domain) not in seen:
            seen.add((selector, domain))
            selectors.append({"selector": selector, "domain": domain})
    return selectors


def check_mismatch(headers: dict[str, Any]) -> dict[str, Any]:
    """Compare visible sender fields and flag domain mismatches."""
    from_domain = extract_domain_from_header(headers.get("from", ""))
    reply_to_domain = extract_domain_from_header(headers.get("reply_to", ""))
    return_path_domain = extract_domain_from_header(headers.get("return_path", ""))

    issues: list[str] = []
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        issues.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain}).")
    if from_domain and return_path_domain and from_domain != return_path_domain:
        issues.append(
            f"Return-Path domain ({return_path_domain}) differs from From domain ({from_domain})."
        )

    return {
        "mismatch": bool(issues),
        "details": " ".join(issues) if issues else "Sender, Reply-To, and Return-Path domains are aligned.",
        "domains": {
            "from": from_domain or "Not Available",
            "reply_to": reply_to_domain or "Not Available",
            "return_path": return_path_domain or "Not Available",
        },
    }
