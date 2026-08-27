"""
HTTP security header grading, similar to securityheaders.com.

Purely informational OSINT — reads response headers already returned by the
target and scores them against known best-practice headers. No exploitation.
"""

# (header name lowercased, points if present, description)
CHECKED_HEADERS = [
    ("strict-transport-security", 15, "Enforces HTTPS (HSTS)."),
    ("content-security-policy", 20, "Mitigates XSS/data-injection via a content policy."),
    ("x-frame-options", 10, "Mitigates clickjacking."),
    ("x-content-type-options", 10, "Prevents MIME-sniffing (should be 'nosniff')."),
    ("referrer-policy", 10, "Controls how much referrer info is leaked."),
    ("permissions-policy", 10, "Restricts powerful browser features (camera, geo, etc.)."),
    ("x-xss-protection", 5, "Legacy XSS filter toggle (superseded by CSP, still checked)."),
    ("cross-origin-opener-policy", 10, "Isolates browsing context from cross-origin windows."),
    ("cross-origin-resource-policy", 10, "Restricts cross-origin resource embedding."),
]

INFO_LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
]


def grade_headers(headers: dict):
    """
    Returns a dict with per-header findings, a 0-100 score, and a letter grade.
    `headers` should be the raw response header dict from the target's root page.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    max_points = sum(p for _, p, _ in CHECKED_HEADERS)
    earned = 0
    findings = []

    for header, points, desc in CHECKED_HEADERS:
        present = header in lower_headers
        if present:
            earned += points
        findings.append({
            "header": header,
            "present": present,
            "value": lower_headers.get(header, ""),
            "points": points if present else 0,
            "max_points": points,
            "description": desc,
        })

    leaks = [{"header": h, "value": lower_headers[h]} for h in INFO_LEAK_HEADERS if h in lower_headers]

    score_pct = round((earned / max_points) * 100) if max_points else 0
    if score_pct >= 90:
        grade = "A+"
    elif score_pct >= 80:
        grade = "A"
    elif score_pct >= 65:
        grade = "B"
    elif score_pct >= 50:
        grade = "C"
    elif score_pct >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "score_pct": score_pct,
        "grade": grade,
        "findings": findings,
        "information_disclosure": leaks,
    }
