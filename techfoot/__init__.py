"""
techfoot — Technology Footprinting & OSINT CVE Correlation Toolkit
=====================================================================
Passive/authorized-recon toolkit for identifying a target's technology
stack from public information and correlating it with known CVEs.

Modules:
    fingerprint      -- HTTP/HTML/cookie technology detection + robots.txt/sitemap OSINT
    favicon_hash     -- Shodan-style mmh3 favicon hashing
    tls_analysis     -- Certificate & TLS configuration inspection, legacy protocol check
    security_headers -- HTTP security header grading
    osint_recon      -- DNS records + certificate-transparency subdomain enum
    whois_lookup     -- Raw-socket WHOIS registration lookup
    cve_engine       -- CPE resolution + NVD CVE lookup with backoff
    kev_check        -- Cross-reference CVEs against CISA's Known Exploited Vulnerabilities catalog
    port_scan        -- Opt-in active TCP-connect scan + banner grab (off by default)
    config           -- NVD API key resolution (CLI flag > env var > .env file)
    report           -- JSON / Markdown / HTML / CSV report generation with risk scoring

LEGAL: only use against systems you own or are explicitly authorized
to test. Everything except port_scan is passive/public-record OSINT;
port_scan is active and requires explicit --ports opt-in in the CLI.
"""

__version__ = "2.2.0"
