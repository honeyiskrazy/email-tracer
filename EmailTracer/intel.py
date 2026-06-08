"""Network and domain intelligence helpers for EmailTracer."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any
import requests

try:
    import whois
except ImportError:  # pragma: no cover - handled in whois_lookup
    whois = None


HTTP_TIMEOUT = 10
NA = "Not Available"


def _safe(value: Any) -> str:
    if value is None or value == "":
        return NA
    if isinstance(value, list):
        if not value:
            return NA
        return ", ".join(_safe(item) for item in value if item is not None) or NA
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    return str(value)


def _first_date(value: Any) -> datetime | None:
    def normalize(item: datetime) -> datetime:
        return item if item.tzinfo else item.replace(tzinfo=timezone.utc)

    if isinstance(value, list):
        dates = [normalize(item) for item in value if isinstance(item, datetime)]
        return min(dates) if dates else None
    return normalize(value) if isinstance(value, datetime) else None


def extract_domain_from_email(email_str: str) -> str:
    """Parse a domain from user-visible email header formats."""
    if not email_str:
        return ""
    _, address = parseaddr(email_str)
    address = address or email_str.strip("<> ")
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip(">. ").lower()


def geolocate_ip(ip: str) -> dict[str, Any]:
    """Use ip-api.com to locate a public IP address."""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,message,query,country,regionName,city,isp,org,as,lat,lon,timezone,reverse,proxy,hosting"
            },
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            return {
                "status": "error",
                "ip": ip,
                "message": data.get("message", "Lookup failed."),
                "country": NA,
                "region": NA,
                "city": NA,
                "isp": NA,
                "org": NA,
                "asn": NA,
            }
        return {
            "status": "success",
            "ip": data.get("query", ip),
            "country": data.get("country") or NA,
            "region": data.get("regionName") or NA,
            "city": data.get("city") or NA,
            "isp": data.get("isp") or NA,
            "org": data.get("org") or NA,
            "asn": data.get("as") or NA,
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone") or NA,
            "reverse": data.get("reverse") or NA,
            "proxy": bool(data.get("proxy")),
            "hosting": bool(data.get("hosting")),
        }
    except Exception as exc:
        return {
            "status": "error",
            "ip": ip,
            "message": f"IP geolocation failed: {exc}",
            "country": NA,
            "region": NA,
            "city": NA,
            "isp": NA,
            "org": NA,
            "asn": NA,
        }


def check_abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    """Check AbuseIPDB reputation. Skips cleanly when no key is supplied."""
    if not api_key:
        return {
            "status": "skipped",
            "abuseConfidenceScore": None,
            "totalReports": None,
            "lastReportedAt": None,
            "isTor": None,
            "message": "AbuseIPDB key not provided.",
        }
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "status": "success",
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "totalReports": data.get("totalReports", 0),
            "lastReportedAt": data.get("lastReportedAt") or NA,
            "isTor": data.get("isTor", False),
            "usageType": data.get("usageType") or NA,
            "domain": data.get("domain") or NA,
            "countryCode": data.get("countryCode") or NA,
        }
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return {
            "status": "error",
            "abuseConfidenceScore": None,
            "totalReports": None,
            "lastReportedAt": None,
            "isTor": None,
            "message": f"AbuseIPDB lookup failed with HTTP {status}.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "abuseConfidenceScore": None,
            "totalReports": None,
            "lastReportedAt": None,
            "isTor": None,
            "message": f"AbuseIPDB lookup failed: {exc}",
        }


def whois_lookup(domain: str) -> dict[str, Any]:
    """Run a WHOIS lookup and normalize common fields."""
    if not domain:
        return {"status": "error", "message": "No domain found in the email headers."}
    if whois is None:
        return {"status": "error", "message": "python-whois is not installed."}

    try:
        record = whois.whois(domain)
        creation_date = _first_date(getattr(record, "creation_date", None))
        now = datetime.now(timezone.utc)
        if creation_date and creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (now - creation_date).days if creation_date else None

        return {
            "status": "success",
            "domain": domain,
            "registrar": _safe(getattr(record, "registrar", None)),
            "creation_date": _safe(getattr(record, "creation_date", None)),
            "expiration_date": _safe(getattr(record, "expiration_date", None)),
            "updated_date": _safe(getattr(record, "updated_date", None)),
            "name_servers": _safe(getattr(record, "name_servers", None)),
            "emails": _safe(getattr(record, "emails", None)),
            "name": _safe(getattr(record, "name", None)),
            "org": _safe(getattr(record, "org", None)),
            "country": _safe(getattr(record, "country", None)),
            "age_days": age_days,
            "newly_registered": age_days is not None and age_days < 30,
        }
    except Exception as exc:
        return {
            "status": "error",
            "domain": domain,
            "message": f"WHOIS lookup failed: {exc}",
            "registrar": NA,
            "creation_date": NA,
            "expiration_date": NA,
            "name_servers": NA,
            "emails": NA,
            "name": NA,
            "org": NA,
            "country": NA,
            "age_days": None,
            "newly_registered": False,
        }
