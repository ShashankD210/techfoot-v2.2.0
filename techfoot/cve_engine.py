"""
NVD CVE correlation engine.

Two lookup strategies:
  1. CPE-based (preferred, precise): resolve "product + version" to an
     official CPE (Common Platform Enumeration) URI via NVD's CPE
     dictionary API, then query CVEs matching that exact CPE. This avoids
     the false positives that plain keyword search produces (e.g.
     searching "PHP 7.4" also returning unrelated CVEs that merely mention
     "PHP" and "7.4" somewhere in their description).
  2. Keyword fallback: used when no confident CPE match is found (e.g.
     product name doesn't map cleanly, or version is unknown).

Includes exponential backoff to respect NVD's public rate limit
(5 requests/30s unauthenticated, 50 requests/30s with a free API key).
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


@dataclass
class CVEMatch:
    cve_id: str
    description: str
    cvss_score: float = 0.0
    severity: str = "UNKNOWN"
    published: str = ""
    references: list = field(default_factory=list)
    match_type: str = "keyword"   # "cpe" or "keyword"


class NVDClient:
    def __init__(self, api_key=None, results_per_product=5, max_retries=3):
        self.api_key = api_key
        self.results_per_product = results_per_product
        self.max_retries = max_retries
        self.base_delay = 1.2 if api_key else 6.0

    def _request(self, url):
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "techfoot-osint-tool/2.0")
        if self.api_key:
            req.add_header("apiKey", self.api_key)

        delay = self.base_delay
        for attempt in range(self.max_retries):
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < self.max_retries - 1:
                    time.sleep(delay)
                    delay *= 2
                    continue
                return None
            except Exception:
                return None
        return None

    # -- CPE resolution --------------------------------------------------

    def resolve_cpe(self, product, version=""):
        """
        Looks up the best-matching official CPE URI for a product/version
        using NVD's CPE dictionary. Returns the CPE match string
        (cpe:2.3:a:vendor:product:version:...) or None if no confident
        match was found.
        """
        query = f"{product} {version}".strip()
        params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 5})
        data = self._request(f"{NVD_CPE_URL}?{params}")
        time.sleep(self.base_delay)
        if not data:
            return None

        products = data.get("products", [])
        if not products:
            return None

        version_l = version.lower()
        for p in products:
            cpe = p.get("cpe", {})
            criteria = cpe.get("cpeName", "")
            if version_l and version_l in criteria.lower():
                return criteria

        # No CPE explicitly matched this version. Returning an arbitrary
        # other-version CPE here would silently attribute CVEs to the wrong
        # version, so we deliberately return None and let the caller fall
        # back to keyword search instead of guessing.
        return None

    # -- CVE search --------------------------------------------------------

    def search_by_cpe(self, cpe_name):
        params = urllib.parse.urlencode({
            "cpeName": cpe_name,
            "resultsPerPage": self.results_per_product,
        })
        data = self._request(f"{NVD_CVE_URL}?{params}")
        time.sleep(self.base_delay)
        return self._parse_cve_response(data, match_type="cpe")

    def search_by_keyword(self, keyword):
        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": self.results_per_product,
        })
        data = self._request(f"{NVD_CVE_URL}?{params}")
        time.sleep(self.base_delay)
        return self._parse_cve_response(data, match_type="keyword")

    def _parse_cve_response(self, data, match_type):
        if not data:
            return []
        matches = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score, severity = 0.0, "UNKNOWN"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0) or 0.0
                    severity = (metrics[key][0].get("baseSeverity")
                                or cvss_data.get("baseSeverity")
                                or "UNKNOWN")
                    break
            refs = [r.get("url") for r in cve.get("references", [])][:3]
            matches.append(CVEMatch(
                cve_id=cve_id, description=desc, cvss_score=score, severity=severity,
                published=cve.get("published", ""), references=refs, match_type=match_type,
            ))
        matches.sort(key=lambda m: m.cvss_score, reverse=True)
        return matches

    # -- Combined strategy -------------------------------------------------

    def lookup(self, product, version=""):
        """
        Best-effort CVE lookup: tries CPE resolution first (precise),
        falls back to keyword search if no CPE match is found or the
        version is unknown.
        """
        if version:
            cpe = self.resolve_cpe(product, version)
            if cpe:
                results = self.search_by_cpe(cpe)
                if results:
                    return results, cpe
        # fallback
        keyword = f"{product} {version}".strip()
        return self.search_by_keyword(keyword), None
