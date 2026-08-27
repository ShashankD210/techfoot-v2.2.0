# techfoot v2.2.0 — Advanced Technology Footprinting & OSINT CVE Correlation Toolkit

A passive, authorized-recon toolkit for identifying a target's technology
stack from public information and correlating it with known vulnerabilities.
Pure Python 3 standard library for core functionality; optional `weasyprint`
dependency for PDF report generation.

## ⚠️ Legal / Ethical Use

Only run this against systems you **own** or are **explicitly authorized**
to test (a bug bounty program's in-scope assets, a signed pentest
agreement, your own infrastructure). This toolkit does reconnaissance and
public-record lookups only — it does not exploit, brute-force, or run
intrusive scans. Unauthorized scanning of third-party systems can be
illegal in many jurisdictions.

## Installation

```bash
# Basic install (core only, no PDF support)
pip install .

# With PDF report generation
pip install ".[pdf]"

# Or run directly without installing
python3 techfoot_cli.py -u https://example.com
```

## What it does

| Module | Capability |
|---|---|
| `fingerprint.py` | Detects web server, language/framework, CMS, JS libraries via headers, HTML, cookies, and well-known paths |
| `security_headers.py` | Grades HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) like securityheaders.com |
| `tls_analysis.py` | Inspects the TLS certificate (issuer, SANs, expiry) and probes for legacy TLS 1.0/1.1 support |
| `favicon_hash.py` | Computes a Shodan-style MurmurHash3 favicon hash for internet-wide pivoting (`http.favicon.hash:<n>`) |
| `osint_recon.py` | Enumerates DNS records (via DNS-over-HTTPS) and subdomains (via Certificate Transparency logs on crt.sh — 100% passive, never touches the target) |
| `whois_lookup.py` | WHOIS domain registration lookup (registrar, dates, name servers) |
| `kev_check.py` | Cross-references found CVEs against CISA's Known Exploited Vulnerabilities catalog |
| `port_scan.py` | Opt-in active TCP-connect scan + banner grab of common ports |
| `cve_engine.py` | Resolves detected products to official CPEs and queries the NVD CVE database, with keyword-search fallback and rate-limit backoff |
| `report.py` | Builds a risk-scored report and renders it as JSON, Markdown, HTML, CSV, or PDF |

## Setup

```bash
cp .env.example .env
cp targets.example.txt targets.txt
# Edit .env and paste in your real NVD API key (optional but recommended)
# Edit targets.txt and add your authorized targets
```

## NVD API key setup

NVD's public CVE lookup rate limit is only 5 requests/30s without a key,
50/30s with one — worth setting up if you're scanning more than a
handful of technologies.

Key resolution order (first found wins): `--nvd-api-key` CLI flag >
`TECHFOOT_NVD_API_KEY` or `NVD_API_KEY` environment variable > `.env`
file in the working directory.

Get a free key (instant, no approval wait): https://nvd.nist.gov/developers/request-an-api-key

Note: `.env.example` ships with a randomly generated *placeholder* value
so you can see the expected format (NVD issues keys as UUIDv4 strings).
It is not a working credential — NVD validates every key server-side, so
a random string just behaves like having no key at all. There's no way
to generate a real, working key locally; it has to come from NIST.

## Quick start

```bash
# Single target, full scan (fingerprint + headers + TLS + favicon + DNS + subdomains + CVEs)
python3 techfoot_cli.py -u https://example.com

# Multiple targets from a file, 4 at a time
python3 techfoot_cli.py -f targets.txt --workers 4

# Fingerprint + CVEs only, skip the slower recon steps
python3 techfoot_cli.py -u https://example.com --no-subdomains --no-tls-legacy-check --no-dns --no-whois

# Fingerprint only, no CVE lookups at all
python3 techfoot_cli.py -u https://example.com --no-cve

# With a free NVD API key (raises rate limit from 5 to 50 requests/30s)
python3 techfoot_cli.py -u https://example.com --nvd-api-key YOUR_KEY

# Scan an IP address
python3 techfoot_cli.py -u 93.184.216.34
```

## Output

Writes five files from the `-o/--output` prefix (default `techfoot_report`):
- `.json` — full machine-readable report
- `.md` — Markdown report
- `.html` — styled, dark-mode HTML report with a risk-score badge and per-CVE severity coloring
- `.csv` — flat CVE-per-row export for spreadsheets
- `.pdf` — printable PDF version of the HTML report (requires `weasyprint`)

## All CLI flags

```
-u, --url URL             Single target URL or IP address
-f, --file FILE            File with one target URL per line
-o, --output PREFIX        Output file prefix (default: techfoot_report)
--workers N                 Concurrent scans when using -f (default: 3)
--no-cve                    Skip CVE correlation
--no-probe                  Skip well-known-path probing
--no-headers                 Skip security header grading
--no-tls                     Skip TLS certificate analysis
--no-tls-legacy-check        Skip legacy TLS 1.0/1.1 protocol probing
--no-favicon                 Skip favicon hashing
--no-dns                     Skip DNS record enumeration
--no-subdomains               Skip Certificate-Transparency subdomain enumeration
--no-whois                   Skip WHOIS registration lookup
--no-kev                     Skip CISA KEV cross-reference
--ports                      ACTIVE SCAN: TCP-connect scan + banner grab of common ports
--nvd-api-key KEY             NVD API key
--max-cves N                  Max CVEs fetched per technology (default: 5)
--insecure                    Skip TLS certificate verification on requests
```

## Design notes

- **CPE-precise CVE matching.** Rather than a plain keyword search (which
  returns false positives — e.g. searching "PHP 7.4" also matches CVEs that
  merely *mention* PHP and 7.4 somewhere), the tool first resolves each
  detected product/version to an official NVD CPE URI, then queries CVEs
  against that exact CPE. Falls back to keyword search when no confident
  CPE match exists.
- **Rate-limit aware.** The NVD client backs off exponentially on HTTP 429
  and paces requests to stay under the public rate limit.
- **All passive by default.** Subdomain enumeration uses Certificate
  Transparency logs (crt.sh), not active brute-forcing. Well-known-path
  probing only requests a small, fixed list of common paths (can be
  disabled with `--no-probe`).
- **Risk scoring.** Aggregates all discovered CVEs into a single 0–100
  score, weighted by severity and dampened so a pile of low-severity
  findings doesn't outrank a couple of criticals.
- **No mandatory third-party dependencies.** Core functionality uses only
  the Python standard library. Favicon hashing reimplements MurmurHash3
  (x86, 32-bit) in pure Python instead of requiring `mmh3`; DNS lookups
  use DNS-over-HTTPS over `urllib` instead of `dnspython`.
- **PDF reports.** Optional WeasyPrint integration produces print-ready
  PDF reports with a single flag (`pip install ".[pdf]"`).
- **Packaged project.** `pyproject.toml` is included for standard Python
  packaging and editable installs (`pip install -e .`).

## Extending it

- Add more fingerprint signatures in `fingerprint.py`
  (`JS_LIBRARY_SIGNATURES`, `META_GENERATOR_SIGNATURES`, `COOKIE_SIGNATURES`,
  `WELL_KNOWN_PATHS`).
- Swap or add another CVE source in `cve_engine.py` (e.g. Vulners, OSV.dev,
  GitHub Advisory Database) alongside NVD.
- `osint_recon.py`'s `enumerate_subdomains_crtsh` can be combined with
  passive DNS sources (e.g. SecurityTrails, if you have an API key) for
  broader subdomain coverage.
