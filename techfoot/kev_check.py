"""
CISA Known Exploited Vulnerabilities (KEV) cross-reference.

The NVD tells you a CVE exists and how severe it theoretically is. It does
NOT tell you whether anyone is actually exploiting it right now. CISA's KEV
catalog is a curated, public list of CVEs with *confirmed active
exploitation in the wild* — it's the single highest-value prioritization
signal in vulnerability management: a "MEDIUM" CVSS bug on the KEV list is
usually a bigger real-world risk than a "CRITICAL" one that isn't, because
attackers are demonstrably already using it.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
(public JSON feed, no API key required)
"""

import json
import urllib.error
import urllib.request

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_cache = {"data": None}


def _load_kev_catalog(timeout=15, force_refresh=False):
    if _cache["data"] is not None and not force_refresh:
        return _cache["data"]
    req = urllib.request.Request(KEV_FEED_URL, headers={"User-Agent": "techfoot-osint-tool/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return None

    by_cve = {}
    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if cve_id:
            by_cve[cve_id] = {
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "date_added": entry.get("dateAdded"),
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "due_date": entry.get("dueDate"),
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
            }
    _cache["data"] = {"by_cve": by_cve, "catalog_version": data.get("catalogVersion"),
                       "date_released": data.get("dateReleased"), "count": len(by_cve)}
    return _cache["data"]


def check_kev(cve_ids, timeout=15):
    """
    cve_ids: iterable of CVE ID strings (e.g. ["CVE-2021-44228", ...])
    Returns dict: {"available": bool, "matches": {cve_id: kev_entry, ...},
                    "catalog_count": int or None}
    If the feed can't be reached, returns available=False rather than raising
    — KEV enrichment is a bonus, not a hard dependency for the rest of the scan.
    """
    catalog = _load_kev_catalog(timeout=timeout)
    if catalog is None:
        return {"available": False, "matches": {}, "catalog_count": None}

    matches = {cid: catalog["by_cve"][cid] for cid in cve_ids if cid in catalog["by_cve"]}
    return {"available": True, "matches": matches, "catalog_count": catalog["count"]}
