#!/usr/bin/env python3
"""
techfoot_cli.py — Advanced Technology Footprinting & OSINT CVE Correlation Tool
==================================================================================

A passive/authorized-recon toolkit that:
  1. Fingerprints a target's technology stack (headers, HTML, cookies, paths)
  2. Grades its HTTP security headers (like securityheaders.com)
  3. Inspects its TLS certificate + checks for legacy TLS 1.0/1.1 support
  4. Computes a Shodan-style favicon hash for internet-wide pivoting
  5. Enumerates DNS records and subdomains (via Certificate Transparency)
  6. Resolves detected products to official CPEs and correlates them with
     the NVD CVE database (CPE-precise, with keyword fallback)
  7. Produces a risk-scored report in JSON, Markdown, HTML, and CSV
  8. Supports scanning multiple targets concurrently

LEGAL / ETHICAL USE
--------------------
Only run this against systems you own or are explicitly authorized to test
(bug bounty program scope, signed pentest agreement, your own assets). This
tool performs reconnaissance and public-record lookups only — it does not
exploit, brute-force, or intrusively probe anything beyond a handful of
well-known static paths.

USAGE
-----
    # Single target, full scan
    python3 techfoot_cli.py -u https://example.com

    # Multiple targets from a file, concurrently
    python3 techfoot_cli.py -f targets.txt --workers 4

    # Faster / narrower scans
    python3 techfoot_cli.py -u https://example.com --no-subdomains --no-tls-legacy-check
    python3 techfoot_cli.py -u https://example.com --no-cve   # fingerprint + recon only

    # With an NVD API key (recommended — raises rate limit 5->50 req/30s)
    python3 techfoot_cli.py -u https://example.com --nvd-api-key YOUR_KEY

Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key
"""

import argparse
import concurrent.futures
import os
import sys
import threading
import time
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from techfoot.fingerprint import TechFingerprinter
from techfoot.favicon_hash import fetch_favicon_hash
from techfoot.tls_analysis import analyze_tls, check_weak_protocols
from techfoot.security_headers import grade_headers
from techfoot.osint_recon import enumerate_dns, enumerate_subdomains_crtsh
from techfoot.whois_lookup import whois_lookup
from techfoot.kev_check import check_kev
from techfoot.port_scan import scan_common_ports
from techfoot.cve_engine import NVDClient
from techfoot.config import resolve_nvd_api_key
from techfoot.report import build_report, render_markdown, render_html, render_csv, render_json, render_pdf


# safe_print() itself isn't guaranteed atomic across threads (it can issue separate
# write() calls for content vs. the trailing newline), so concurrent scans of
# multiple targets (-f/--workers) can interleave mid-line and produce garbled
# console output. All progress messages go through this lock instead.
_print_lock = threading.Lock()


def safe_print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)


def scan_target(url, args):
    """Runs the full pipeline against a single target and returns the report dict."""
    start = time.time()
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    hostname = parsed.hostname
    safe_print(f"\n[*] === Scanning {url} ===")

    # 1. Fingerprint
    fp = TechFingerprinter(url, verify_tls=not args.insecure)
    detections, body, exposures = fp.run(probe_paths=not args.no_probe)
    safe_print(f"[+] HTTP {fp.raw_status} — {len(detections)} technologies detected")
    for d in detections:
        v = f" v{d.version}" if d.version else ""
        safe_print(f"    - [{d.category}] {d.product}{v} ({d.confidence})")
    if exposures:
        safe_print(f"[!] {len(exposures)} potentially exposed path(s) found:")
        for e in exposures:
            safe_print(f"    - {e['path']} (HTTP {e['status']}) — {e['note']}")

    extras = {"exposures": exposures, "robots": getattr(fp, "robots_info", {})}

    # 2. Security headers
    if not args.no_headers and fp.raw_headers:
        extras["security_headers"] = grade_headers(fp.raw_headers)
        safe_print(f"[+] Security headers grade: {extras['security_headers']['grade']} "
              f"({extras['security_headers']['score_pct']}%)")

    # 3. TLS analysis
    if not args.no_tls and hostname:
        safe_print("[*] Analyzing TLS certificate...")
        extras["tls"] = analyze_tls(hostname)
        if extras["tls"].get("connected"):
            safe_print(f"    - Issuer: {extras['tls'].get('issuer_cn')}, "
                  f"expires in {extras['tls'].get('days_until_expiry')} days")
        if not args.no_tls_legacy_check:
            safe_print("[*] Checking for legacy TLS protocol support...")
            extras["weak_protocols"] = check_weak_protocols(hostname)
            if extras["weak_protocols"].get("legacy_protocols_enabled"):
                safe_print(f"    [!] Legacy protocols enabled: "
                      f"{extras['weak_protocols']['legacy_protocols_enabled']}")

    # 4. Favicon hash
    if not args.no_favicon:
        fav = fetch_favicon_hash(url, ssl_context=fp.ssl_context)
        if fav:
            extras["favicon"] = fav
            safe_print(f"[+] Favicon hash: {fav['hash']}  (Shodan pivot: {fav['shodan_query']})")

    # 5. DNS + subdomains
    if hostname and not args.no_dns:
        safe_print("[*] Enumerating DNS records...")
        extras["dns"] = enumerate_dns(hostname)
    if hostname and not args.no_subdomains:
        safe_print("[*] Enumerating subdomains via Certificate Transparency (crt.sh)...")
        extras["subdomains"] = enumerate_subdomains_crtsh(hostname)
        n = extras["subdomains"].get("total_found", 0)
        safe_print(f"    - {n} unique subdomains found")

    # 5b. WHOIS
    if hostname and not args.no_whois:
        safe_print("[*] Looking up WHOIS registration record...")
        # WHOIS wants the registrable domain, not a subdomain (e.g. WHOIS a
        # "www.example.com" target as "example.com") — a full public-suffix
        # split needs a PSL, so this is a practical heuristic: last two
        # labels, which is correct for the overwhelming majority of TLDs.
        labels = hostname.split(".")
        registrable_domain = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
        extras["whois"] = whois_lookup(registrable_domain)
        if extras["whois"].get("error"):
            safe_print(f"    [!] WHOIS lookup failed: {extras['whois']['error']}")
        else:
            reg = extras["whois"].get("fields", {}).get("registrar", "unknown")
            safe_print(f"    - Registrar: {reg}")

    # 5c. Optional active port scan (opt-in only — see port_scan.py header)
    if args.ports and hostname:
        safe_print("[*] Running common-port TCP connect scan (ACTIVE — you confirmed authorization)...")
        extras["open_ports"] = scan_common_ports(hostname)
        safe_print(f"    - {len(extras['open_ports'])} open port(s) found")

    # 6. CVE correlation
    cve_results, cpe_map = {}, {}
    if not args.no_cve and detections:
        safe_print(f"[*] Correlating CVEs via NVD "
              f"({'with API key' if args.nvd_api_key else 'no API key — rate limited'})...")
        nvd = NVDClient(api_key=args.nvd_api_key, results_per_product=args.max_cves)
        for det in detections:
            label = f"{det.product} {det.version}".strip()
            safe_print(f"    -> {label}")
            results, cpe = nvd.lookup(det.product, det.version)
            cve_results[det.key()] = results
            cpe_map[det.key()] = cpe
            if results:
                top = results[0]
                safe_print(f"       {len(results)} CVE(s), top: {top.cve_id} "
                      f"({top.severity}, CVSS {top.cvss_score})")

        # 6b. Cross-reference all found CVEs against CISA's Known Exploited
        # Vulnerabilities catalog — the single strongest real-world
        # prioritization signal available (see kev_check.py).
        if not args.no_kev:
            all_ids = [c.cve_id for results in cve_results.values() for c in results]
            if all_ids:
                safe_print(f"[*] Cross-referencing {len(all_ids)} CVE(s) against CISA KEV catalog...")
                kev = check_kev(all_ids)
                extras["kev"] = kev
                if kev["available"]:
                    hits = sum(1 for cid in all_ids if cid in kev["matches"])
                    if hits:
                        safe_print(f"    [!!] {hits} CVE(s) have CONFIRMED ACTIVE EXPLOITATION per CISA KEV")
                else:
                    safe_print("    [!] CISA KEV feed unreachable — skipping enrichment")

    elapsed = time.time() - start
    report = build_report(url, detections, cve_results, cpe_map, extras, elapsed)
    safe_print(f"[+] Scan of {url} complete in {elapsed:.1f}s — "
          f"risk: {report['risk_summary']['level']} ({report['risk_summary']['score']}/100), "
          f"{report['total_cves']} CVE(s) total")
    return report


def write_reports(report, output_prefix):
    with open(f"{output_prefix}.json", "w") as f:
        f.write(render_json(report))
    with open(f"{output_prefix}.md", "w") as f:
        f.write(render_markdown(report))
    with open(f"{output_prefix}.html", "w") as f:
        f.write(render_html(report))
    with open(f"{output_prefix}.csv", "w", newline="") as f:
        f.write(render_csv(report))
    pdf_ok = render_pdf(report, f"{output_prefix}.pdf")
    exts = ["json", "md", "html", "csv"] + (["pdf"] if pdf_ok else [])
    return [f"{output_prefix}.{ext}" for ext in exts]


def sanitize_filename(url):
    return (url.replace("https://", "").replace("http://", "")
               .replace("/", "_").replace(":", "_").strip("_"))


def main():
    parser = argparse.ArgumentParser(
        description="Advanced technology footprinting + OSINT CVE correlation toolkit. "
                     "Only use against systems you are authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Single target URL, e.g. https://example.com")
    target_group.add_argument("-f", "--file", help="File with one target URL per line")

    parser.add_argument("-o", "--output", default="techfoot_report",
                         help="Output file prefix (writes .json/.md/.html/.csv/.pdf)")
    parser.add_argument("--workers", type=int, default=3,
                         help="Concurrent target scans when using -f (default 3)")

    parser.add_argument("--no-cve", action="store_true", help="Skip CVE correlation")
    parser.add_argument("--no-probe", action="store_true", help="Skip well-known-path probing")
    parser.add_argument("--no-headers", action="store_true", help="Skip security header grading")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS certificate analysis")
    parser.add_argument("--no-tls-legacy-check", action="store_true",
                         help="Skip legacy TLS 1.0/1.1 protocol probing")
    parser.add_argument("--no-favicon", action="store_true", help="Skip favicon hashing")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS record enumeration")
    parser.add_argument("--no-subdomains", action="store_true",
                         help="Skip Certificate-Transparency subdomain enumeration")
    parser.add_argument("--no-whois", action="store_true", help="Skip WHOIS registration lookup")
    parser.add_argument("--no-kev", action="store_true",
                         help="Skip cross-referencing found CVEs against CISA's Known Exploited "
                              "Vulnerabilities catalog")
    parser.add_argument("--ports", action="store_true",
                         help="ACTIVE SCAN (opt-in): TCP-connect scan + banner grab of ~19 common ports. "
                              "More intrusive than the rest of the toolkit's passive recon — only use "
                              "against systems you are explicitly authorized to port-scan.")

    parser.add_argument("--nvd-api-key", default=None,
                         help="NVD API key. If omitted, falls back to the TECHFOOT_NVD_API_KEY or "
                              "NVD_API_KEY environment variable, then a .env file in the current "
                              "directory (see .env.example).")
    parser.add_argument("--max-cves", type=int, default=5, help="Max CVEs to fetch per technology")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification on requests")
    args = parser.parse_args()

    resolved_key = resolve_nvd_api_key(args.nvd_api_key)
    key_source = "CLI flag" if args.nvd_api_key else ("env/.env file" if resolved_key else None)
    args.nvd_api_key = resolved_key

    if args.ports:
        safe_print("[!] --ports enables an ACTIVE TCP port scan. Make sure you are authorized "
              "to port-scan this target before continuing.")

    safe_print("[*] techfoot v2.1 — advanced technology footprinting & OSINT CVE correlation")
    safe_print("[*] Reminder: only scan systems you are authorized to test.")
    if key_source:
        safe_print(f"[*] NVD API key loaded from {key_source}.")
    else:
        safe_print("[*] No NVD API key found — using NVD's slower unauthenticated rate limit "
                    "(5 req/30s). See .env.example to set one up.")

    targets = []
    if args.url:
        targets = [args.url]
    else:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    reports = []
    if len(targets) == 1:
        reports.append((targets[0], scan_target(targets[0], args)))
    else:
        safe_print(f"[*] Scanning {len(targets)} targets with {args.workers} concurrent workers...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            future_map = {pool.submit(scan_target, t, args): t for t in targets}
            for future in concurrent.futures.as_completed(future_map):
                t = future_map[future]
                try:
                    reports.append((t, future.result()))
                except Exception as e:
                    safe_print(f"[!] Scan of {t} failed: {e}", file=sys.stderr)

    all_files = []
    for target, report in reports:
        if len(targets) == 1:
            prefix = args.output
        else:
            prefix = f"{args.output}_{sanitize_filename(target)}"
        files = write_reports(report, prefix)
        all_files.extend(files)

    safe_print(f"\n[+] All scans complete. {len(reports)}/{len(targets)} succeeded.")
    safe_print("[+] Reports written:")
    for f in all_files:
        safe_print(f"    - {f}")


if __name__ == "__main__":
    main()
