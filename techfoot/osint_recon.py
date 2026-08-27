"""
DNS + Certificate Transparency OSINT.

- DNS record enumeration (A/AAAA/MX/NS/TXT) using only the stdlib `socket`
  module for A/AAAA, plus a minimal DNS-over-HTTPS (DoH) client for the
  record types Python's socket module can't do natively (MX/NS/TXT/CNAME).
  Uses Cloudflare's public DoH endpoint (1.1.1.1/dns-query) — no API key,
  no local resolver library dependency.
- Subdomain enumeration via crt.sh, which indexes Certificate Transparency
  logs. This is 100% passive: it never touches the target, it queries a
  third-party public log of certificates that have already been issued.
"""

import json
import socket
import urllib.error
import urllib.parse
import urllib.request


DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"


def _doh_query(name, record_type, timeout=8):
    """Minimal DNS-over-HTTPS query using stdlib only."""
    params = urllib.parse.urlencode({"name": name, "type": record_type})
    url = f"{DOH_ENDPOINT}?{params}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            # filter out any malformed answers so callers never see None entries
            return [a.get("data") for a in data.get("Answer", []) if a.get("data")]
    except Exception:
        return []


def enumerate_dns(domain, timeout=8):
    """Returns a dict of record_type -> list of values."""
    records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}

    try:
        records["A"] = list({addr[4][0] for addr in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except socket.gaierror:
        pass
    try:
        records["AAAA"] = list({addr[4][0] for addr in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except socket.gaierror:
        pass

    for rtype in ("MX", "NS", "TXT", "CNAME"):
        records[rtype] = _doh_query(domain, rtype, timeout=timeout)

    # Derive useful OSINT hints from TXT records (SPF senders, verification tokens)
    hints = []
    for txt in records["TXT"]:
        if not txt:
            continue
        clean = txt.strip('"')
        if clean.lower().startswith("v=spf1"):
            hints.append(f"SPF record reveals mail infrastructure: {clean}")
        if "google-site-verification" in clean.lower():
            hints.append("Google Workspace / Search Console verification present")
        if "MS=ms" in clean:
            hints.append("Microsoft 365 domain verification present")
    records["_osint_hints"] = hints
    return records


def enumerate_subdomains_crtsh(domain, timeout=20, limit=200):
    """
    Passive subdomain enumeration via crt.sh (Certificate Transparency log
    search). Returns a sorted list of unique subdomains. This never sends
    any traffic to the target itself.
    """
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "techfoot-osint-tool/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return {"error": f"crt.sh lookup failed: {e}", "subdomains": []}

    subdomains = set()
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        # crt.sh occasionally returns concatenated JSON objects; recover what we can
        entries = []
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name and name.endswith(domain):
                subdomains.add(name)

    result = sorted(subdomains)[:limit]
    return {"error": None, "subdomains": result, "total_found": len(subdomains)}
