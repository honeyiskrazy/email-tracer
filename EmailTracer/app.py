"""Streamlit UI for EmailTracer."""

from __future__ import annotations

import base64
from datetime import datetime
import html
from typing import Any

import streamlit as st
import streamlit.components.v1 as components

from auth import full_auth_check
from ip_extractor import is_mail_infrastructure_ip
from intel import check_abuseipdb, geolocate_ip
from parser import check_mismatch, extract_ips, extract_message_id_domain, parse_headers
from whois_lookup import analyze_whois, compare_domains, extract_domain, run_whois


st.set_page_config(page_title="EmailTracer", page_icon="@", layout="wide")


CSS = """
<style>
    .main .block-container { padding-top: 2rem; max-width: 1180px; }
    .risk-low { color: #166534; background: #dcfce7; border: 1px solid #86efac; }
    .risk-medium { color: #92400e; background: #fef3c7; border: 1px solid #fbbf24; }
    .risk-high { color: #991b1b; background: #fee2e2; border: 1px solid #fca5a5; }
    .badge {
        display: inline-block;
        border-radius: 999px;
        padding: .18rem .58rem;
        font-weight: 700;
        font-size: .78rem;
        line-height: 1.25;
    }
    .ok { color: #166534; background: #dcfce7; border: 1px solid #86efac; }
    .warn { color: #92400e; background: #fef3c7; border: 1px solid #fbbf24; }
    .bad { color: #991b1b; background: #fee2e2; border: 1px solid #fca5a5; }
    .muted { color: #374151; background: #f3f4f6; border: 1px solid #d1d5db; }
    .summary {
        border: 1px solid #d7dde7;
        border-radius: 8px;
        padding: 1rem;
        background: #ffffff;
    }
    .small-note { color: #4b5563; font-size: .92rem; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def badge(text: str, kind: str = "muted") -> str:
    return f'<span class="badge {kind}">{html.escape(text)}</span>'


def risk_badge(level: str) -> str:
    kind = {"LOW": "risk-low", "MEDIUM": "risk-medium", "HIGH": "risk-high"}.get(level, "muted")
    return f'<span class="badge {kind}">{html.escape(level)}</span>'


def auth_badge(name: str, passed: bool, observed: str, configured: bool) -> str:
    if passed:
        label = "PASS" if observed == "pass" else "CONFIGURED"
        return badge(f"{name}: {label}", "ok")
    if observed in {"fail", "softfail", "permerror"}:
        return badge(f"{name}: FAIL", "bad")
    if configured:
        return badge(f"{name}: CONFIGURED", "ok")
    return badge(f"{name}: FAIL", "bad")


def choose_sender_domain(parsed: dict[str, Any]) -> str:
    return (
        extract_domain(parsed.get("from", ""))
        or extract_domain(parsed.get("return_path", ""))
        or extract_message_id_domain(parsed.get("message_id", ""))
    )


def max_abuse_score(ip_results: list[dict[str, Any]]) -> int:
    scores = [
        item.get("abuse", {}).get("abuseConfidenceScore")
        for item in ip_results
        if isinstance(item.get("abuse", {}).get("abuseConfidenceScore"), int)
    ]
    return max(scores) if scores else 0


def has_header(parsed: dict[str, Any], header_name: str) -> bool:
    return any(key.lower() == header_name.lower() for key in parsed.get("all_headers", {}))


def is_gmail_sender(parsed: dict[str, Any]) -> bool:
    return has_header(parsed, "X-Google-DKIM-Signature")


def is_outlook_sender(parsed: dict[str, Any]) -> bool:
    provider = str(parsed.get("provider", "")).lower()
    from_value = str(parsed.get("from", "")).lower()
    return (
        "outlook" in provider
        or "microsoft" in provider
        or "hotmail.com" in from_value
        or "outlook.com" in from_value
        or "live.com" in from_value
    )


def calculate_risk(analysis: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    mismatch = analysis["mismatch"]["mismatch"] or analysis.get("domain_compare", {}).get("mismatch", False)
    abuse_score = max_abuse_score(analysis["ip_results"])
    auth_passed = analysis["auth"]["passed"]
    failed_auth_count = sum(1 for passed in auth_passed.values() if not passed)
    auth_all_fail = failed_auth_count == 3
    whois_flags = set(analysis.get("whois_analysis", {}).get("flags", []))

    if mismatch:
        reasons.append("Sender address domains do not align.")
    if abuse_score > 75:
        reasons.append(f"At least one IP has a high AbuseIPDB score ({abuse_score}).")
    elif 25 <= abuse_score <= 75:
        reasons.append(f"At least one IP has a moderate AbuseIPDB score ({abuse_score}).")
    if auth_all_fail:
        reasons.append("SPF, DKIM, and DMARC all failed or were missing.")
    elif failed_auth_count in {1, 2}:
        reasons.append(f"{failed_auth_count} authentication check(s) failed or were missing.")
    if "RECENTLY_REGISTERED" in whois_flags:
        reasons.append("The sender domain appears to be less than 30 days old.")
    if "EXPIRING_SOON" in whois_flags:
        reasons.append("The sender domain appears to expire within 30 days.")
    if "PRIVACY_PROTECTED" in whois_flags:
        reasons.append("The registrant contact appears to use privacy or proxy protection.")

    if mismatch or abuse_score > 75 or auth_all_fail:
        level = "HIGH"
    elif 25 <= abuse_score <= 75 or failed_auth_count in {1, 2} or whois_flags:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"level": level, "reasons": reasons or ["No major suspicious indicators were found."]}


def analyze_headers(raw_headers: str, abuse_api_key: str) -> dict[str, Any]:
    parsed = parse_headers(raw_headers)
    x_originating_ips = extract_ips(parsed.get("x_originating_ip", []))
    received_ips = extract_ips(parsed.get("received", []))
    public_ips = []
    for ip in x_originating_ips + received_ips:
        if ip not in public_ips:
            public_ips.append(ip)
    domain = choose_sender_domain(parsed)
    mismatch = check_mismatch(parsed)
    outlook_sender = is_outlook_sender(parsed)

    ip_results = []
    filtered_ip_results = []
    for ip in public_ips:
        geo = geolocate_ip(ip)
        is_x_originating_ip = ip in x_originating_ips
        if is_mail_infrastructure_ip(geo) and not (outlook_sender and is_x_originating_ip):
            filtered_ip_results.append(
                {
                    "ip": ip,
                    "geo": geo,
                    "reason": "Major mail infrastructure provider",
                }
            )
            continue
        ip_results.append(
            {
                "ip": ip,
                "geo": geo,
                "abuse": check_abuseipdb(ip, abuse_api_key.strip()),
                "source": "X-Originating-IP" if is_x_originating_ip else "Received",
            }
        )

    whois = run_whois(domain)
    whois_analysis = analyze_whois(whois)
    domain_compare = compare_domains(parsed.get("from", ""), parsed.get("return_path", ""))
    auth = full_auth_check(
        domain,
        parsed.get("authentication_results", []) + parsed.get("arc_authentication_results", []),
        parsed.get("received_spf", []),
        parsed.get("dkim_selectors", []),
    )

    analysis = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "raw_headers": raw_headers,
        "parsed": parsed,
        "domain": domain,
        "public_ips": public_ips,
        "ip_results": ip_results,
        "filtered_ip_results": filtered_ip_results,
        "gmail_sender": is_gmail_sender(parsed),
        "outlook_sender": outlook_sender,
        "x_originating_ips": x_originating_ips,
        "whois": whois,
        "whois_analysis": whois_analysis,
        "domain_compare": domain_compare,
        "auth": auth,
        "mismatch": mismatch,
    }
    analysis["risk"] = calculate_risk(analysis)
    analysis["report"] = build_report(analysis)
    return analysis


def build_report(analysis: dict[str, Any]) -> str:
    parsed = analysis["parsed"]
    risk = analysis["risk"]
    whois = analysis["whois"]
    auth = analysis["auth"]
    whois_flags = analysis.get("whois_analysis", {}).get("flags", [])
    domain_compare = analysis.get("domain_compare", {})

    ip_lines = []
    for item in analysis["ip_results"]:
        geo = item["geo"]
        abuse = item["abuse"]
        abuse_text = "Reputation not checked"
        if abuse.get("status") == "success":
            abuse_text = (
                f"AbuseIPDB {abuse.get('abuseConfidenceScore', 0)}/100, "
                f"{abuse.get('totalReports', 0)} reports"
            )
        elif abuse.get("status") == "error":
            abuse_text = abuse.get("message", "AbuseIPDB lookup failed")
        ip_lines.append(
            f"- {item['ip']}: {geo.get('city')}, {geo.get('country')} | "
            f"{geo.get('isp')} | {abuse_text}"
        )
    if not ip_lines:
        ip_lines.append(
            "- All IPs belong to mail infrastructure providers. No sender IP available. "
            "If sender used Gmail, Outlook or Yahoo - real device IP is not exposed."
        )

    next_steps = {
        "LOW": "Keep normal caution. Verify links and attachments if the message asks for payment, login, or urgent action.",
        "MEDIUM": "Do not click links or open attachments until the sender confirms through a trusted channel.",
        "HIGH": "Treat this email as suspicious. Do not click links, do not reply, and report it to your email provider or security team.",
    }

    return "\n".join(
        [
            "EmailTracer Report",
            f"Generated: {analysis['generated_at']}",
            "",
            "Summary",
            f"- From: {parsed.get('from') or 'Not Available'}",
            f"- Reply-To: {parsed.get('reply_to') or 'Not Available'}",
            f"- Return-Path: {parsed.get('return_path') or 'Not Available'}",
            f"- Provider: {parsed.get('provider') or 'Unknown'}",
            f"- Sender domain: {analysis.get('domain') or 'Not Available'}",
            f"- Risk level: {risk['level']}",
            "",
            "Risk reasons",
            *[f"- {reason}" for reason in risk["reasons"]],
            "",
            "IP analysis",
            *ip_lines,
            "",
            "Domain intelligence",
            f"- Registrar: {whois.get('registrar', 'Not Available')}",
            f"- Created: {whois.get('creation_date', 'Not Available')}",
            f"- Expires: {whois.get('expiration_date', 'Not Available')}",
            f"- Registrant organization: {whois.get('org', 'Not Available')}",
            f"- WHOIS flags: {', '.join(whois_flags) if whois_flags else 'None'}",
            (
                "- From/Return-Path mismatch: "
                f"{domain_compare.get('from_domain')} != {domain_compare.get('return_path_domain')}"
                if domain_compare.get("mismatch")
                else "- From/Return-Path mismatch: No"
            ),
            "",
            "Authentication",
            f"- SPF: {'PASS' if auth['passed']['spf'] else 'FAIL'} ({auth['spf'].get('pass_fail', 'unknown')})",
            f"- DKIM: {'PASS' if auth['passed']['dkim'] else 'FAIL'} ({auth['dkim'].get('pass_fail', 'unknown')})",
            f"- DMARC: {'PASS' if auth['passed']['dmarc'] else 'FAIL'} ({auth['dmarc'].get('pass_fail', 'unknown')})",
            f"- Verdict: {auth.get('overall_verdict')}",
            "",
            "What to do next",
            f"- {next_steps[risk['level']]}",
        ]
    )


def render_header_summary(analysis: dict[str, Any]) -> None:
    parsed = analysis["parsed"]
    st.subheader("Header Summary")
    st.table(
        {
            "Field": ["From", "Reply-To", "Return-Path", "Date", "Subject", "Provider"],
            "Value": [
                parsed.get("from") or "Not Available",
                parsed.get("reply_to") or "Not Available",
                parsed.get("return_path") or "Not Available",
                parsed.get("date") or "Not Available",
                parsed.get("subject") or "Not Available",
                parsed.get("provider") or "Unknown",
            ],
        }
    )

    mismatch = analysis["mismatch"]
    if mismatch["mismatch"]:
        st.error(mismatch["details"])
    else:
        st.success(mismatch["details"])

    risk = analysis["risk"]
    st.markdown(
        f"<div class='summary'><strong>Risk level:</strong> {risk_badge(risk['level'])}<br>"
        f"<span class='small-note'>{html.escape(' '.join(risk['reasons']))}</span></div>",
        unsafe_allow_html=True,
    )


def render_ip_analysis(analysis: dict[str, Any]) -> None:
    st.subheader("IP Analysis")
    if analysis.get("gmail_sender"):
        st.info("Gmail sender - Google strips device IP. Only Google mail server visible.")
    if analysis.get("outlook_sender"):
        originating_ips = analysis.get("x_originating_ips", [])
        if originating_ips:
            st.info(
                "Outlook/Hotmail X-Originating-IP found. This IP may be the real sender: "
                + ", ".join(originating_ips)
            )
        else:
            st.info(
                "Outlook/Hotmail sender detected with no X-Originating-IP. "
                "Only mail infrastructure IPs are available."
            )
    if not analysis["ip_results"]:
        st.info(
            "All IPs belong to mail infrastructure providers. No sender IP available. "
            "If sender used Gmail, Outlook or Yahoo - real device IP is not exposed."
        )
        return

    for item in analysis["ip_results"]:
        geo = item["geo"]
        abuse = item["abuse"]
        with st.container(border=True):
            st.markdown(f"**{item['ip']}**")
            st.caption("Source: " + item.get("source", "Received"))
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("City", geo.get("city", "Not Available"))
            col2.metric("Country", geo.get("country", "Not Available"))
            col3.metric("ISP", geo.get("isp", "Not Available"))
            col4.metric("ASN", geo.get("asn", "Not Available"))

            if geo.get("status") == "error":
                st.warning(geo.get("message", "IP lookup failed."))
            if geo.get("proxy") or geo.get("hosting"):
                st.info("This IP is marked as proxy, hosting, or data-center infrastructure.")

            if abuse.get("status") == "success":
                score = abuse.get("abuseConfidenceScore", 0)
                kind = "ok" if score <= 25 else "warn" if score <= 75 else "bad"
                st.markdown(
                    f"{badge(f'AbuseIPDB: {score}/100', kind)} "
                    f"{html.escape(str(abuse.get('totalReports', 0)))} report(s), "
                    f"last seen {html.escape(str(abuse.get('lastReportedAt', 'Not Available')))}",
                    unsafe_allow_html=True,
                )
            elif abuse.get("status") != "skipped":
                st.warning(abuse.get("message", "AbuseIPDB lookup failed."))


def render_domain_intel(analysis: dict[str, Any]) -> None:
    st.subheader("Domain Intelligence")
    whois = analysis["whois"]
    whois_flags = analysis.get("whois_analysis", {}).get("flags", [])
    domain_compare = analysis.get("domain_compare", {})

    if "error" in whois:
        st.warning("WHOIS lookup failed: " + str(whois["error"]))
    if domain_compare.get("mismatch"):
        st.error("⚠️ From domain and Return-Path domain do not match")

    st.table(
        {
            "Field": [
                "Domain",
                "Registrar",
                "Created",
                "Expires",
                "Updated",
                "Name servers",
                "Registrant email",
                "Registrant name",
                "Registrant organization",
                "Country",
            ],
            "Value": [
                whois.get("domain", analysis.get("domain") or "Not Available"),
                whois.get("registrar", "Not Available"),
                whois.get("creation_date", "Not Available"),
                whois.get("expiration_date", "Not Available"),
                whois.get("updated_date", "Not Available"),
                whois.get("name_servers", "Not Available"),
                whois.get("emails", "Not Available"),
                whois.get("name", "Not Available"),
                whois.get("org", "Not Available"),
                whois.get("country", "Not Available"),
            ],
        }
    )
    for flag in whois_flags:
        if flag == "RECENTLY_REGISTERED":
            st.error("⚠️ Domain registered < 30 days ago")
        elif flag == "EXPIRING_SOON":
            st.warning("⚠️ Domain expiring soon")
        elif flag == "PRIVACY_PROTECTED":
            st.warning("⚠️ Registrant identity hidden")


def render_auth(analysis: dict[str, Any]) -> None:
    st.subheader("Authentication")
    auth = analysis["auth"]
    observed = auth["observed"]
    st.markdown(
        " ".join(
            [
                auth_badge("SPF", auth["passed"]["spf"], observed["spf"], auth["spf"]["exists"]),
                auth_badge("DKIM", auth["passed"]["dkim"], observed["dkim"], auth["dkim"]["exists"]),
                auth_badge(
                    "DMARC",
                    auth["passed"]["dmarc"],
                    observed["dmarc"],
                    auth["dmarc"]["exists"],
                ),
            ]
        ),
        unsafe_allow_html=True,
    )
    st.write(auth["explanation"])
    st.table(
        {
            "Check": ["SPF", "DKIM", "DMARC"],
            "Observed result": [observed["spf"], observed["dkim"], observed["dmarc"]],
            "DNS evidence": [
                auth["spf"].get("record") or auth["spf"].get("error") or "Not Available",
                auth["dkim"].get("record") or auth["dkim"].get("error") or "Not Available",
                auth["dmarc"].get("record") or auth["dmarc"].get("error") or "Not Available",
            ],
        }
    )


def render_report(analysis: dict[str, Any]) -> None:
    report = analysis["report"]
    st.subheader("Report")
    st.code(report, language="text")
    encoded_report = base64.b64encode(report.encode("utf-8")).decode("ascii")
    components.html(
        f"""
        <button id="copy-report" style="
            border: 1px solid #c7d2fe; background: #eef2ff; color: #1e3a8a;
            padding: 9px 13px; border-radius: 6px; cursor: pointer; font-weight: 700;">
            Copy report
        </button>
        <span id="copy-status" style="margin-left: 8px; color: #475569;"></span>
        <script>
        const button = document.getElementById("copy-report");
        const status = document.getElementById("copy-status");
        button.addEventListener("click", async () => {{
            try {{
                const bytes = Uint8Array.from(atob("{encoded_report}"), char => char.charCodeAt(0));
                const report = new TextDecoder().decode(bytes);
                await navigator.clipboard.writeText(report);
                status.textContent = "Copied";
            }} catch (error) {{
                status.textContent = "Copy failed";
            }}
        }});
        </script>
        """,
        height=48,
    )
    st.download_button("Download report", report, file_name="emailtracer-report.txt", mime="text/plain")


def main() -> None:
    st.title("EmailTracer")
    st.caption("Email forensics for raw headers: origin, sender domain, authentication, and risk.")

    with st.sidebar:
        st.header("Settings")
        abuse_api_key = st.text_input("AbuseIPDB API key", type="password")
        st.caption("Optional. Leave blank to skip reputation scoring.")
        st.divider()
        st.caption("Free lookups can be rate-limited by their providers.")

    tab_analyze, tab_raw, tab_report = st.tabs(["Analyze", "Raw Headers", "Report"])

    with tab_analyze:
        raw_headers = st.text_area(
            "Paste raw email headers here",
            height=280,
            placeholder="Paste the full raw headers from the email message...",
        )
        if st.button("Analyze", type="primary", use_container_width=True):
            if not raw_headers.strip():
                st.warning("Paste raw email headers before running analysis.")
            else:
                with st.spinner("Analyzing..."):
                    try:
                        st.session_state["analysis"] = analyze_headers(raw_headers, abuse_api_key)
                    except Exception as exc:
                        st.error(f"Analysis failed safely: {exc}")

        analysis = st.session_state.get("analysis")
        if analysis:
            render_header_summary(analysis)
            render_ip_analysis(analysis)
            render_domain_intel(analysis)
            render_auth(analysis)

    with tab_raw:
        analysis = st.session_state.get("analysis")
        if analysis:
            st.json(analysis["parsed"])
        else:
            st.info("Run an analysis first to see parsed headers.")

    with tab_report:
        analysis = st.session_state.get("analysis")
        if analysis:
            render_report(analysis)
        else:
            st.info("Run an analysis first to generate a report.")


if __name__ == "__main__":
    main()
