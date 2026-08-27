"""
WHOIS domain registration lookup — pure stdlib `socket`, no dependencies.

Queries IANA's WHOIS server to find the authoritative WHOIS server for the
domain's TLD, then queries that server directly (following one level of
"refer:" redirection, which is how most registrar-level WHOIS servers work).
This is standard passive OSINT: registrar, creation/expiry dates, name
servers, and (increasingly rare post-GDPR) registrant contact info.
"""

import re
import socket


IANA_WHOIS = "whois.iana.org"


def _raw_whois_query(server, query, timeout=8, port=43):
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall((query + "\r\n").encode("utf-8"))
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception as e:
        return None


def _find_referral_server(iana_response):
    if not iana_response:
        return None
    m = re.search(r"^refer:\s*(\S+)", iana_response, re.MULTILINE | re.IGNORECASE)
    return m.group(1) if m else None


_FIELD_PATTERNS = {
    "registrar": r"Registrar:\s*(.+)",
    "creation_date": r"Creation Date:\s*(.+)",
    "expiry_date": r"Registr(?:y|ar) Expiry Date:\s*(.+)",
    "updated_date": r"Updated Date:\s*(.+)",
    "domain_status": r"Domain Status:\s*(.+)",
    "registrant_org": r"Registrant Organization:\s*(.+)",
    "registrant_country": r"Registrant Country:\s*(.+)",
    "dnssec": r"DNSSEC:\s*(.+)",
}


def _extract_fields(text):
    result = {}
    for field, pattern in _FIELD_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if not matches:
            continue
        cleaned = [m.strip() for m in matches if m.strip() and m.strip().lower() != "redacted for privacy"]
        if not cleaned:
            continue
        result[field] = cleaned[0] if field != "domain_status" else list(dict.fromkeys(cleaned))
    name_servers = sorted(set(re.findall(r"Name Server:\s*(\S+)", text, re.IGNORECASE)))
    if name_servers:
        result["name_servers"] = name_servers
    return result


def whois_lookup(domain, timeout=8):
    """
    Returns a dict with parsed WHOIS fields plus the raw response text, or
    {"error": ...} if the lookup couldn't be completed. Domain privacy
    services increasingly redact registrant PII — this is expected and not
    a tool failure.
    """
    domain = domain.lower().strip().rstrip(".")
    iana_resp = _raw_whois_query(IANA_WHOIS, domain, timeout=timeout)
    if iana_resp is None:
        return {"error": f"Could not reach {IANA_WHOIS}", "domain": domain}

    referral = _find_referral_server(iana_resp)
    if not referral:
        # Some TLD registries answer directly from IANA's response (rare) —
        # fall back to whatever IANA gave us rather than failing outright.
        fields = _extract_fields(iana_resp)
        return {"error": None, "domain": domain, "whois_server": IANA_WHOIS,
                "fields": fields, "raw": iana_resp[:4000]}

    registrar_resp = _raw_whois_query(referral, domain, timeout=timeout)
    if registrar_resp is None:
        return {"error": f"IANA referred to {referral} but it did not respond",
                "domain": domain, "whois_server": referral}

    fields = _extract_fields(registrar_resp)
    return {
        "error": None,
        "domain": domain,
        "whois_server": referral,
        "fields": fields,
        "raw": registrar_resp[:4000],
    }
