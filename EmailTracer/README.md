# EmailTracer

EmailTracer is a Streamlit web app for investigating raw email headers. It extracts sender details, public IPs, domain registration data, and authentication signals to produce a simple risk report for non-technical users.

## What It Checks

- Header summary: From, Reply-To, Return-Path, Message-ID, date, subject, and likely sending provider
- Public IPs from `Received` and `X-Originating-IP` headers
- IP location and network owner through the free `ip-api.com` JSON endpoint
- Optional AbuseIPDB reputation checks with a free AbuseIPDB API key
- Sender domain WHOIS data through `python-whois`
- SPF, DKIM, and DMARC DNS records through `dnspython`
- Observed authentication results from `Authentication-Results` and `Received-SPF` headers
- Suspicious indicators such as sender mismatch, new domains, failed authentication, and high-abuse IPs

## Setup

```powershell
cd C:\taniya\HTML\EmailTracer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

If your system uses the Python launcher, replace `python` with `py`.

## AbuseIPDB Key

AbuseIPDB is optional. Without a key, EmailTracer still runs and skips IP reputation scoring.

1. Create a free account at `https://www.abuseipdb.com/`.
2. Open your account API settings.
3. Create or copy an API key.
4. Paste it into the EmailTracer sidebar.

## Limitations

- Gmail, Outlook, Yahoo, and other large providers often hide the original sender IP.
- Proton Mail and privacy-focused services may provide limited routing information.
- VPNs, proxies, hosting providers, and relays can obscure the real sender.
- WHOIS data may be hidden by privacy protection or unavailable for some TLDs.
- SPF, DKIM, and DMARC DNS records show domain configuration; the most reliable pass/fail evidence comes from the email's `Authentication-Results` headers.
- Free APIs may be rate-limited or temporarily unavailable.
