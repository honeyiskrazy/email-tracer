"""SPF, DKIM, and DMARC checks for EmailTracer."""

from __future__ import annotations

import re
from typing import Any

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - handled by query helpers
    dns = None


COMMON_DKIM_SELECTORS = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]
AUTH_STATUSES = ["pass", "fail", "softfail", "temperror", "permerror", "neutral", "none"]


def _txt_records(name: str) -> tuple[list[str], str]:
    if dns is None:
        return [], "dnspython is not installed."
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=6)
        records = []
        for answer in answers:
            records.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
        return records, ""
    except dns.resolver.NXDOMAIN:
        return [], "DNS name does not exist."
    except dns.resolver.NoAnswer:
        return [], "No TXT records found."
    except dns.exception.Timeout:
        return [], "DNS lookup timed out."
    except Exception as exc:
        return [], f"DNS lookup failed: {exc}"


def _normalize_status(value: str | None) -> str:
    value = (value or "").lower().strip()
    return value if value in AUTH_STATUSES else "unknown"


def parse_authentication_results(
    authentication_results: list[str] | None = None,
    received_spf: list[str] | None = None,
) -> dict[str, Any]:
    """Extract observed SPF, DKIM, and DMARC results from authentication headers."""
    observed: dict[str, list[str]] = {"spf": [], "dkim": [], "dmarc": []}
    for header in authentication_results or []:
        for mechanism in observed:
            for match in re.finditer(rf"\b{mechanism}\s*=\s*([a-zA-Z]+)", header, flags=re.I):
                observed[mechanism].append(_normalize_status(match.group(1)))

    for header in received_spf or []:
        match = re.search(r"\b(pass|fail|softfail|temperror|permerror|neutral|none)\b", header, flags=re.I)
        if match:
            observed["spf"].append(_normalize_status(match.group(1)))

    def choose_status(values: list[str]) -> str:
        if not values:
            return "unknown"
        if "fail" in values or "softfail" in values or "permerror" in values:
            return next(value for value in values if value in {"fail", "softfail", "permerror"})
        if "pass" in values:
            return "pass"
        return values[0]

    return {
        "spf": choose_status(observed["spf"]),
        "dkim": choose_status(observed["dkim"]),
        "dmarc": choose_status(observed["dmarc"]),
        "raw": observed,
    }


def check_spf(domain: str, observed_result: str | None = None) -> dict[str, Any]:
    records, error = _txt_records(domain)
    spf_records = [record for record in records if record.lower().startswith("v=spf1")]
    return {
        "exists": bool(spf_records),
        "record": spf_records[0] if spf_records else "",
        "records": spf_records,
        "pass_fail": _normalize_status(observed_result) if observed_result else "unknown",
        "error": "" if spf_records else error,
    }


def check_dkim(domain: str, selector: str = "default") -> dict[str, Any]:
    record_name = f"{selector}._domainkey.{domain}"
    records, error = _txt_records(record_name)
    dkim_records = [
        record for record in records if "v=dkim1" in record.lower() or record.lower().startswith("k=") or "p=" in record
    ]
    return {
        "selector": selector,
        "domain": domain,
        "record_name": record_name,
        "exists": bool(dkim_records),
        "record": dkim_records[0] if dkim_records else "",
        "records": dkim_records,
        "error": "" if dkim_records else error,
    }


def check_dmarc(domain: str, observed_result: str | None = None) -> dict[str, Any]:
    records, error = _txt_records(f"_dmarc.{domain}")
    dmarc_records = [record for record in records if record.lower().startswith("v=dmarc1")]
    policy = ""
    if dmarc_records:
        match = re.search(r"(?:^|;)\s*p\s*=\s*([^;]+)", dmarc_records[0], flags=re.I)
        policy = match.group(1).strip().lower() if match else ""
    return {
        "exists": bool(dmarc_records),
        "policy": policy,
        "record": dmarc_records[0] if dmarc_records else "",
        "records": dmarc_records,
        "pass_fail": _normalize_status(observed_result) if observed_result else "unknown",
        "error": "" if dmarc_records else error,
    }


def _auth_passed(observed_status: str, configured: bool) -> bool:
    if observed_status == "pass":
        return True
    if observed_status in {"fail", "softfail", "permerror"}:
        return False
    return configured


def full_auth_check(
    domain: str,
    authentication_results: list[str] | None = None,
    received_spf: list[str] | None = None,
    dkim_selectors: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Run SPF, DKIM, and DMARC checks with observed header results when present."""
    observed = parse_authentication_results(authentication_results, received_spf)
    if not domain:
        return {
            "observed": observed,
            "spf": {"exists": False, "record": "", "pass_fail": "unknown", "error": "No domain found."},
            "dkim": {
                "exists": False,
                "record": "",
                "pass_fail": "unknown",
                "selectors_checked": [],
                "checks": [],
                "error": "No domain found.",
            },
            "dmarc": {"exists": False, "record": "", "policy": "", "pass_fail": "unknown", "error": "No domain found."},
            "overall_verdict": "Suspicious",
            "explanation": "No sender domain was available for authentication checks.",
            "passed": {"spf": False, "dkim": False, "dmarc": False},
        }

    spf = check_spf(domain, observed["spf"])
    dmarc = check_dmarc(domain, observed["dmarc"])

    selector_pairs: list[tuple[str, str]] = []
    for item in dkim_selectors or []:
        selector = item.get("selector")
        selector_domain = item.get("domain") or domain
        if selector:
            selector_pairs.append((selector, selector_domain))
    selector_pairs.extend((selector, domain) for selector in COMMON_DKIM_SELECTORS)

    seen: set[tuple[str, str]] = set()
    dkim_checks = []
    for selector, selector_domain in selector_pairs:
        pair = (selector, selector_domain)
        if pair in seen:
            continue
        seen.add(pair)
        check = check_dkim(selector_domain, selector)
        dkim_checks.append(check)
        if check["exists"]:
            break

    dkim_exists = any(check["exists"] for check in dkim_checks)
    dkim_record = next((check["record"] for check in dkim_checks if check["exists"]), "")
    dkim = {
        "exists": dkim_exists,
        "record": dkim_record,
        "pass_fail": observed["dkim"],
        "selectors_checked": [check["record_name"] for check in dkim_checks],
        "checks": dkim_checks,
        "error": "" if dkim_exists else "No DKIM selector record was found for checked selectors.",
    }

    passed = {
        "spf": _auth_passed(observed["spf"], spf["exists"]),
        "dkim": _auth_passed(observed["dkim"], dkim["exists"]),
        "dmarc": _auth_passed(observed["dmarc"], dmarc["exists"] and dmarc.get("policy") not in {"", "none"}),
    }

    failed_observed = [
        name for name, status in observed.items() if name != "raw" and status in {"fail", "softfail", "permerror"}
    ]
    if observed["dmarc"] == "fail" or (not passed["spf"] and not passed["dkim"] and not passed["dmarc"]):
        verdict = "Likely Spoofed"
        explanation = "Authentication failed or no usable SPF, DKIM, or DMARC evidence was found."
    elif failed_observed or not dmarc["exists"]:
        verdict = "Suspicious"
        explanation = "Some authentication evidence is missing or failed. Review the sender before trusting it."
    else:
        verdict = "Likely Legitimate"
        explanation = "Authentication records are present and the observed results do not show a failure."

    return {
        "observed": observed,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "overall_verdict": verdict,
        "explanation": explanation,
        "passed": passed,
    }
