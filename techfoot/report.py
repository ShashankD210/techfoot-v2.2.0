"""Report assembly and multi-format export: JSON, Markdown, HTML, CSV."""

import csv
import html as html_module
import io
import json
from datetime import datetime, timezone


def _esc(value):
    """HTML-escape any value before interpolating it into render_html.

    Every string embedded in the HTML report can originate from the
    *scanned target* (HTML comments, header values, meta tags) or from
    third-party OSINT sources (CVE descriptions, WHOIS text) — none of
    it is trusted. Without escaping, a target page containing something
    like `<!-- <script>...</script> -->` would have that markup executed
    when the analyst opens their own report locally. Everything rendered
    into HTML must go through this first.
    """
    if value is None:
        return ""
    return html_module.escape(str(value), quote=True)


def _md_cell(value):
    """Sanitize a value for use inside a Markdown table cell.

    A raw `|` in the text (common in CSP header values like
    `default-src 'self' | style-src ...`-style notes, or in CVE
    descriptions) silently breaks the table's column alignment for every
    row after it. Escape pipes and collapse newlines so one row can never
    corrupt the rest of the table.
    """
    if value is None:
        return ""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEVERITY_COLOR = {
    "CRITICAL": "#7f1d1d", "HIGH": "#dc2626", "MEDIUM": "#d97706",
    "LOW": "#65a30d", "UNKNOWN": "#6b7280",
}


def compute_risk_score(all_cves):
    """
    Aggregate 0-100 risk score from every CVE found across all detected
    technologies. Weighted by severity and CVSS, dampened via sqrt-like
    scaling so 50 low-severity CVEs don't outrank 2 criticals.
    """
    if not all_cves:
        return {"score": 0, "level": "None", "critical": 0, "high": 0, "medium": 0, "low": 0}

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    weighted_sum = 0
    kev_hits = 0
    for cve in all_cves:
        sev = (cve.get("severity") or "UNKNOWN").upper()
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] = counts.get(sev, 0) + 1
        contribution = SEVERITY_WEIGHT.get(sev, 0) * max(cve.get("cvss_score") or 0, 1)
        if cve.get("known_exploited"):
            # A CVE with confirmed active exploitation (CISA KEV) is a much
            # stronger real-world risk signal than CVSS alone implies.
            contribution *= 2.5
            kev_hits += 1
        weighted_sum += contribution

    raw = min(weighted_sum, 400)  # cap contribution
    score = round((raw / 400) * 100)

    if kev_hits > 0:
        level = "Critical"  # actively-exploited CVEs always mean Critical, regardless of CVSS
    elif counts["CRITICAL"] > 0:
        level = "Critical"
    elif counts["HIGH"] > 0:
        level = "High"
    elif counts["MEDIUM"] > 0:
        level = "Medium"
    elif counts["LOW"] > 0:
        level = "Low"
    else:
        level = "Informational"

    return {
        "score": score, "level": level,
        "critical": counts["CRITICAL"], "high": counts["HIGH"],
        "medium": counts["MEDIUM"], "low": counts["LOW"],
        "known_exploited_count": kev_hits,
    }


def build_report(target, detections, cve_results, cpe_map, extras, elapsed):
    """
    detections: list[Detection]
    cve_results: dict[product_key -> list[CVEMatch]]
    cpe_map: dict[product_key -> cpe string or None]
    extras: dict with optional keys: dns, subdomains, tls, weak_protocols,
            security_headers, favicon, exposures
    """
    report = {
        "target": target,
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "technologies_detected": [],
        "extras": extras or {},
    }

    all_cves_flat = []
    for det in detections:
        entry = {
            "category": det.category,
            "product": det.product,
            "version": det.version or "unknown",
            "confidence": det.confidence,
            "evidence": det.evidence,
            "cpe": cpe_map.get(det.key()),
            "cves": [],
        }
        for cve in cve_results.get(det.key(), []):
            cve_entry = {
                "id": cve.cve_id,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "published": cve.published,
                "description": cve.description[:400],
                "references": cve.references,
                "match_type": cve.match_type,
                "known_exploited": False,   # filled in below if KEV data is available
            }
            entry["cves"].append(cve_entry)
            all_cves_flat.append(cve_entry)
        report["technologies_detected"].append(entry)

    # Cross-reference against CISA KEV, if the caller fetched it
    kev = (extras or {}).get("kev")
    if kev and kev.get("available"):
        for cve_entry in all_cves_flat:
            if cve_entry["id"] in kev["matches"]:
                cve_entry["known_exploited"] = True
                cve_entry["kev_info"] = kev["matches"][cve_entry["id"]]

    report["risk_summary"] = compute_risk_score(all_cves_flat)
    report["total_cves"] = len(all_cves_flat)
    report["kev_matches"] = sum(1 for c in all_cves_flat if c["known_exploited"])
    return report


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

def render_markdown(report):
    lines = ["# Technology Footprint & CVE Report", ""]
    lines.append(f"**Target:** {report['target']}  ")
    lines.append(f"**Scan time (UTC):** {report['scan_time_utc']}  ")
    lines.append(f"**Duration:** {report['elapsed_seconds']}s  ")
    risk = report["risk_summary"]
    lines.append(f"**Risk level:** {risk['level']} (score {risk['score']}/100) — "
                 f"{risk['critical']} critical / {risk['high']} high / "
                 f"{risk['medium']} medium / {risk['low']} low")
    lines.append("")
    lines.append("> ⚠️ Passive/authorized-recon results only. Verify manually before acting.")
    lines.append("")

    extras = report.get("extras", {})
    if extras.get("security_headers"):
        sh = extras["security_headers"]
        lines.append(f"## Security Headers Grade: {sh['grade']} ({sh['score_pct']}%)")
        lines.append("")
        lines.append("| Header | Present | Value |")
        lines.append("|---|---|---|")
        for f in sh["findings"]:
            lines.append(f"| {_md_cell(f['header'])} | {'✅' if f['present'] else '❌'} "
                         f"| {_md_cell(f['value'][:60])} |")
        if sh["information_disclosure"]:
            lines.append("")
            lines.append("**Information disclosure headers found:**")
            for leak in sh["information_disclosure"]:
                lines.append(f"- `{leak['header']}`: {leak['value']}")
        lines.append("")

    if extras.get("tls"):
        tls = extras["tls"]
        lines.append("## TLS Certificate")
        if tls.get("error"):
            lines.append(f"- Error: {tls['error']}")
        else:
            lines.append(f"- Subject CN: {tls.get('subject_cn')}")
            lines.append(f"- Issuer: {tls.get('issuer_cn')} ({tls.get('issuer_org')})")
            lines.append(f"- Valid until: {tls.get('not_after')} "
                         f"({tls.get('days_until_expiry')} days remaining)")
            lines.append(f"- TLS version negotiated: {tls.get('tls_version')}")
            lines.append(f"- Cipher: {tls.get('cipher')}")
            san = tls.get("subject_alt_names") or []
            if san:
                lines.append(f"- SANs: {', '.join(san[:15])}{' ...' if len(san) > 15 else ''}")
        lines.append("")

    if extras.get("weak_protocols"):
        wp = extras["weak_protocols"]
        lines.append("## TLS Protocol Support")
        for proto, status in wp["protocol_support"].items():
            lines.append(f"- {proto}: {status}")
        if wp.get("risk_note"):
            lines.append(f"- ⚠️ {wp['risk_note']}")
        lines.append("")

    if extras.get("favicon"):
        fav = extras["favicon"]
        lines.append("## Favicon Fingerprint (Shodan-style)")
        lines.append(f"- mmh3 hash: `{fav['hash']}`")
        lines.append(f"- Pivot query: `{fav['shodan_query']}`")
        lines.append("")

    if extras.get("dns"):
        dns = extras["dns"]
        lines.append("## DNS Records")
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            vals = dns.get(rtype) or []
            if vals:
                lines.append(f"- **{rtype}:** {', '.join(vals[:10])}")
        if dns.get("_osint_hints"):
            lines.append("")
            lines.append("**OSINT hints:**")
            for h in dns["_osint_hints"]:
                lines.append(f"- {h}")
        lines.append("")

    if extras.get("subdomains"):
        sub = extras["subdomains"]
        lines.append(f"## Subdomains (Certificate Transparency — {sub.get('total_found', 0)} found)")
        for s in sub.get("subdomains", [])[:50]:
            lines.append(f"- {s}")
        lines.append("")

    if extras.get("exposures"):
        lines.append("## ⚠️ Potentially Exposed Paths")
        for exp in extras["exposures"]:
            lines.append(f"- `{exp['path']}` (HTTP {exp['status']}) — {exp['note']}")
        lines.append("")

    if extras.get("whois") and not extras["whois"].get("error"):
        w = extras["whois"]
        f = w.get("fields", {})
        lines.append("## WHOIS")
        lines.append(f"- Registrar: {f.get('registrar', 'n/a')}")
        lines.append(f"- Created: {f.get('creation_date', 'n/a')}")
        lines.append(f"- Expires: {f.get('expiry_date', 'n/a')}")
        lines.append(f"- Registrant org: {f.get('registrant_org', 'n/a (often redacted)')}")
        if f.get("name_servers"):
            lines.append(f"- Name servers: {', '.join(f['name_servers'])}")
        lines.append("")

    if extras.get("robots"):
        r = extras["robots"]
        if r.get("robots_found"):
            lines.append("## robots.txt Disclosure")
            if r["disallowed_paths"]:
                lines.append(f"**{len(r['disallowed_paths'])} disallowed path(s) revealed:**")
                for p in r["disallowed_paths"][:30]:
                    lines.append(f"- `{p}`")
            if r["sitemaps"]:
                lines.append("")
                lines.append("**Sitemaps:**")
                for sm in r["sitemaps"]:
                    lines.append(f"- {sm}")
            lines.append("")

    if extras.get("open_ports"):
        lines.append("## Open Ports (banner grab)")
        lines.append("| Port | Service (guess) | Banner |")
        lines.append("|---|---|---|")
        for p in extras["open_ports"]:
            banner = (p["banner"][:60] + "...") if len(p["banner"]) > 60 else p["banner"]
            lines.append(f"| {p['port']} | {_md_cell(p['service_guess'])} | `{_md_cell(banner)}` |")
        lines.append("")

    if report.get("kev_matches"):
        lines.append(f"## 🚨 {report['kev_matches']} CVE(s) with CONFIRMED ACTIVE EXPLOITATION (CISA KEV)")
        lines.append("These are being used by attackers in the wild right now — prioritize immediately.")
        lines.append("")

    lines.append("## Detected Technologies & CVEs")
    lines.append("")
    for tech in report["technologies_detected"]:
        version_str = f" v{tech['version']}" if tech["version"] != "unknown" else " (version unknown)"
        lines.append(f"### {tech['product']}{version_str}")
        lines.append(f"- **Category:** {tech['category']}")
        lines.append(f"- **Confidence:** {tech['confidence']}")
        lines.append(f"- **Evidence:** {tech['evidence']}")
        if tech.get("cpe"):
            lines.append(f"- **CPE:** `{tech['cpe']}`")
        if tech["cves"]:
            lines.append("")
            lines.append("| CVE | Severity | CVSS | Match | Published | KEV | Summary |")
            lines.append("|---|---|---|---|---|---|---|")
            for cve in tech["cves"]:
                summary = cve["description"].replace("\n", " ")
                if len(summary) > 90:
                    summary = summary[:87] + "..."
                kev_flag = "🚨 EXPLOITED" if cve.get("known_exploited") else ""
                lines.append(f"| [{cve['id']}](https://nvd.nist.gov/vuln/detail/{cve['id']}) "
                              f"| {_md_cell(cve['severity'])} | {cve['cvss_score']} | {_md_cell(cve['match_type'])} "
                              f"| {_md_cell(cve['published'][:10])} | {kev_flag} | {_md_cell(summary)} |")
        else:
            lines.append("- No CVEs matched.")
        lines.append("")
    return "\n".join(lines)


def render_html(report):
    risk = report["risk_summary"]
    risk_color = {"Critical": "#7f1d1d", "High": "#dc2626", "Medium": "#d97706",
                  "Low": "#65a30d", "Informational": "#0891b2", "None": "#6b7280"}.get(risk["level"], "#6b7280")

    tech_blocks = []
    for tech in report["technologies_detected"]:
        version_str = f"v{_esc(tech['version'])}" if tech["version"] != "unknown" else "(version unknown)"
        cve_rows = ""
        for cve in tech["cves"]:
            color = SEVERITY_COLOR.get(cve["severity"], "#6b7280")
            summary = (cve["description"][:150] + "...") if len(cve["description"]) > 150 else cve["description"]
            kev_badge = ('<span class="badge" style="background:#7f1d1d">🚨 EXPLOITED</span>'
                         if cve.get("known_exploited") else "")
            cve_rows += f"""
            <tr>
              <td><a href="https://nvd.nist.gov/vuln/detail/{_esc(cve['id'])}" target="_blank">{_esc(cve['id'])}</a></td>
              <td><span class="badge" style="background:{color}">{_esc(cve['severity'])}</span></td>
              <td>{_esc(cve['cvss_score'])}</td>
              <td>{_esc(cve['match_type'])}</td>
              <td>{_esc(cve['published'][:10])}</td>
              <td>{kev_badge}</td>
              <td>{_esc(summary)}</td>
            </tr>"""
        cve_table = f"""
            <table>
              <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Match</th><th>Published</th><th></th><th>Summary</th></tr>
              {cve_rows}
            </table>""" if tech["cves"] else "<p class='muted'>No CVEs matched.</p>"

        cpe_line = f"<div class='muted'>CPE: <code>{_esc(tech['cpe'])}</code></div>" if tech.get("cpe") else ""

        tech_blocks.append(f"""
        <div class="card">
          <h3>{_esc(tech['product'])} <span class="muted">{version_str}</span></h3>
          <div class="meta">Category: {_esc(tech['category'])} &nbsp;·&nbsp; Confidence: {_esc(tech['confidence'])}</div>
          <div class="muted">Evidence: {_esc(tech['evidence'])}</div>
          {cpe_line}
          {cve_table}
        </div>""")

    extras = report.get("extras", {})
    extra_blocks = []

    if report.get("kev_matches"):
        extra_blocks.append(f"""
        <div class="card warn">
          <h3>🚨 {report['kev_matches']} CVE(s) with CONFIRMED ACTIVE EXPLOITATION (CISA KEV)</h3>
          <p class="muted">These are being used by attackers in the wild right now — prioritize immediately.</p>
        </div>""")

    if extras.get("security_headers"):
        sh = extras["security_headers"]
        rows = "".join(
            f"<tr><td>{_esc(f['header'])}</td><td>{'✅' if f['present'] else '❌'}</td>"
            f"<td>{_esc((f['value'] or '')[:80])}</td></tr>" for f in sh["findings"]
        )
        leak_items = "".join(f"<li><code>{_esc(l['header'])}</code>: {_esc(l['value'])}</li>"
                              for l in sh.get("information_disclosure", []))
        leak_block = f"<div class='muted' style='margin-top:0.5rem'>Information disclosure:<ul>{leak_items}</ul></div>" if leak_items else ""
        extra_blocks.append(f"""
        <div class="card">
          <h3>Security Headers — Grade {_esc(sh['grade'])} ({sh['score_pct']}%)</h3>
          <table><tr><th>Header</th><th>Present</th><th>Value</th></tr>{rows}</table>
          {leak_block}
        </div>""")

    if extras.get("tls"):
        tls = extras["tls"]
        if tls.get("error"):
            body = f"<p class='muted'>Error: {_esc(tls['error'])}</p>"
        else:
            san = tls.get("subject_alt_names") or []
            san_str = _esc(", ".join(san[:15]) + (" ..." if len(san) > 15 else "")) if san else ""
            body = f"""
            <div class="meta">Subject: {_esc(tls.get('subject_cn'))}</div>
            <div class="meta">Issuer: {_esc(tls.get('issuer_cn'))} ({_esc(tls.get('issuer_org'))})</div>
            <div class="meta">Valid until {_esc(tls.get('not_after'))} ({_esc(tls.get('days_until_expiry'))} days left)</div>
            <div class="meta">TLS: {_esc(tls.get('tls_version'))} · Cipher: {_esc(tls.get('cipher'))}</div>
            {f'<div class="meta">SANs: {san_str}</div>' if san_str else ''}"""
        extra_blocks.append(f"<div class='card'><h3>TLS Certificate</h3>{body}</div>")

    if extras.get("weak_protocols"):
        wp = extras["weak_protocols"]
        rows = "".join(f"<div class='meta'>{_esc(proto)}: {_esc(status)}</div>"
                        for proto, status in wp["protocol_support"].items())
        risk_note = f"<div class='muted' style='margin-top:0.5rem'>⚠️ {_esc(wp['risk_note'])}</div>" if wp.get("risk_note") else ""
        extra_blocks.append(f"<div class='card'><h3>TLS Protocol Support</h3>{rows}{risk_note}</div>")

    if extras.get("favicon"):
        fav = extras["favicon"]
        extra_blocks.append(f"""
        <div class="card">
          <h3>Favicon Fingerprint (Shodan-style)</h3>
          <div class="meta">mmh3 hash: <code>{_esc(fav['hash'])}</code></div>
          <div class="meta">Pivot query: <code>{_esc(fav['shodan_query'])}</code></div>
        </div>""")

    if extras.get("dns"):
        dns = extras["dns"]
        rows = ""
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            vals = dns.get(rtype) or []
            if vals:
                rows += f"<div class='meta'><b>{rtype}:</b> {_esc(', '.join(vals[:10]))}</div>"
        hints = "".join(f"<li>{_esc(h)}</li>" for h in dns.get("_osint_hints", []))
        hint_block = f"<div class='muted' style='margin-top:0.5rem'>OSINT hints:<ul>{hints}</ul></div>" if hints else ""
        extra_blocks.append(f"<div class='card'><h3>DNS Records</h3>{rows}{hint_block}</div>")

    if extras.get("whois") and not extras["whois"].get("error"):
        w = extras["whois"]
        f = w.get("fields", {})
        ns = f.get("name_servers")
        extra_blocks.append(f"""
        <div class="card">
          <h3>WHOIS</h3>
          <div class="meta">Registrar: {_esc(f.get('registrar', 'n/a'))}</div>
          <div class="meta">Created: {_esc(f.get('creation_date', 'n/a'))}</div>
          <div class="meta">Expires: {_esc(f.get('expiry_date', 'n/a'))}</div>
          <div class="meta">Registrant org: {_esc(f.get('registrant_org', 'n/a (often redacted)'))}</div>
          {f"<div class='meta'>Name servers: {_esc(', '.join(ns))}</div>" if ns else ""}
        </div>""")

    if extras.get("robots") and extras["robots"].get("robots_found"):
        r = extras["robots"]
        items = "".join(f"<li><code>{_esc(p)}</code></li>" for p in r.get("disallowed_paths", [])[:30])
        sitemaps = "".join(f"<li>{_esc(sm)}</li>" for sm in r.get("sitemaps", []))
        extra_blocks.append(f"""
        <div class="card">
          <h3>robots.txt Disclosure</h3>
          {f"<div class='muted'>{len(r['disallowed_paths'])} disallowed path(s):</div><ul class='sublist'>{items}</ul>" if items else ""}
          {f"<div class='muted' style='margin-top:0.5rem'>Sitemaps:</div><ul>{sitemaps}</ul>" if sitemaps else ""}
        </div>""")

    if extras.get("subdomains") and extras["subdomains"].get("subdomains"):
        subs = extras["subdomains"]["subdomains"][:50]
        items = "".join(f"<li>{_esc(s)}</li>" for s in subs)
        extra_blocks.append(f"""
        <div class="card">
          <h3>Subdomains ({extras['subdomains'].get('total_found', 0)} found via Certificate Transparency)</h3>
          <ul class="sublist">{items}</ul>
        </div>""")

    if extras.get("open_ports"):
        rows = "".join(
            f"<tr><td>{p['port']}</td><td>{_esc(p['service_guess'])}</td><td><code>{_esc(p['banner'][:80])}</code></td></tr>"
            for p in extras["open_ports"]
        )
        extra_blocks.append(f"""
        <div class="card warn">
          <h3>Open Ports (active TCP connect scan)</h3>
          <table><tr><th>Port</th><th>Service (guess)</th><th>Banner</th></tr>{rows}</table>
        </div>""")

    if extras.get("exposures"):
        items = "".join(f"<li><code>{_esc(e['path'])}</code> — HTTP {e['status']} ({_esc(e['note'])})</li>"
                         for e in extras["exposures"])
        extra_blocks.append(f"<div class='card warn'><h3>⚠️ Potentially Exposed Paths</h3><ul>{items}</ul></div>")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Technology Footprint Report — {_esc(report['target'])}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#e5e7eb; margin:0; padding:2rem; }}
  h1 {{ font-size:1.6rem; margin-bottom:0.25rem; }}
  .muted {{ color:#9ca3af; font-size:0.85rem; }}
  .meta {{ color:#cbd5e1; font-size:0.85rem; margin:2px 0; }}
  .header {{ display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;
             background:#161a22; padding:1.2rem 1.5rem; border-radius:12px; margin-bottom:1.5rem; }}
  .risk-badge {{ padding:0.5rem 1rem; border-radius:999px; font-weight:600; color:white; background:{risk_color}; }}
  .card {{ background:#161a22; border:1px solid #232733; border-radius:12px; padding:1.2rem 1.5rem; margin-bottom:1rem; }}
  .card.warn {{ border-color:#7f1d1d; }}
  table {{ width:100%; border-collapse:collapse; margin-top:0.75rem; font-size:0.85rem; }}
  th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid #232733; }}
  th {{ color:#9ca3af; font-weight:600; }}
  a {{ color:#60a5fa; text-decoration:none; }}
  .badge {{ padding:2px 8px; border-radius:6px; color:white; font-size:0.75rem; font-weight:600; }}
  .sublist {{ columns:2; font-size:0.85rem; color:#cbd5e1; }}
  code {{ background:#0c0e13; padding:1px 5px; border-radius:4px; word-break:break-all; }}
  .stats {{ display:flex; gap:0.75rem; font-size:0.85rem; }}
  .stat {{ background:#0c0e13; padding:4px 10px; border-radius:8px; }}
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>Technology Footprint &amp; CVE Report</h1>
      <div class="muted">{_esc(report['target'])} &nbsp;·&nbsp; scanned {_esc(report['scan_time_utc'])} &nbsp;·&nbsp; {_esc(report['elapsed_seconds'])}s</div>
    </div>
    <div style="text-align:right">
      <div class="risk-badge">{_esc(risk['level'])} risk — {risk['score']}/100</div>
      <div class="stats" style="margin-top:0.5rem; justify-content:flex-end;">
        <span class="stat">Critical: {risk['critical']}</span>
        <span class="stat">High: {risk['high']}</span>
        <span class="stat">Medium: {risk['medium']}</span>
        <span class="stat">Low: {risk['low']}</span>
      </div>
    </div>
  </div>

  {''.join(extra_blocks)}

  <h2>Detected Technologies ({len(report['technologies_detected'])})</h2>
  {''.join(tech_blocks)}

  <p class="muted">Passive/authorized-recon results only. Verify manually before acting; false positives
  are possible. Generated by techfoot v2.0 — only run against systems you are authorized to test.</p>
</body>
</html>"""
    return html


def render_csv(report):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["product", "version", "category", "confidence", "cpe",
                      "cve_id", "severity", "cvss_score", "published", "match_type",
                      "known_exploited_kev", "description"])
    for tech in report["technologies_detected"]:
        if not tech["cves"]:
            writer.writerow([tech["product"], tech["version"], tech["category"],
                              tech["confidence"], tech.get("cpe", ""), "", "", "", "", "", "", ""])
        for cve in tech["cves"]:
            writer.writerow([tech["product"], tech["version"], tech["category"], tech["confidence"],
                              tech.get("cpe", ""), cve["id"], cve["severity"], cve["cvss_score"],
                              cve["published"], cve["match_type"],
                              "YES" if cve.get("known_exploited") else "",
                              cve["description"]])
    return buf.getvalue()


def render_json(report):
    return json.dumps(report, indent=2)


def render_pdf(report, output_path):
    try:
        from weasyprint import HTML
        html = render_html(report)
        HTML(string=html).write_pdf(target=output_path)
        return True
    except Exception:
        return False
