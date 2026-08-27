"""Technology fingerprinting: headers, HTML, cookies, well-known paths."""

import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin


@dataclass
class Detection:
    category: str
    product: str
    version: str = ""
    confidence: str = "medium"      # low / medium / high
    evidence: str = ""

    def key(self):
        return self.product.lower()


class SimpleHTMLIndexer(HTMLParser):
    """Collects meta tags, script srcs, link hrefs, and comments."""

    def __init__(self):
        super().__init__()
        self.meta_tags = []
        self.scripts = []
        self.links = []
        self.comments = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta":
            self.meta_tags.append(attrs)
        elif tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        elif tag == "link" and attrs.get("href"):
            self.links.append(attrs)

    def handle_comment(self, data):
        self.comments.append(data)


class TechFingerprinter:

    JS_LIBRARY_SIGNATURES = [
        (r"jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", "JS Library", "jQuery"),
        (r"bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)", "JS Library", "Bootstrap"),
        (r"react(?:-dom)?@(\d+\.\d+\.\d+)", "JS Framework", "React"),
        (r"vue@(\d+\.\d+\.\d+)", "JS Framework", "Vue.js"),
        (r"angular[.-](\d+\.\d+\.\d+)", "JS Framework", "AngularJS"),
        (r"lodash[.-](\d+\.\d+\.\d+)", "JS Library", "Lodash"),
        (r"moment\.js/(\d+\.\d+\.\d+)", "JS Library", "Moment.js"),
        (r"swiper[-.](\d+\.\d+\.\d+)", "JS Library", "Swiper"),
        (r"font-awesome/(\d+\.\d+\.\d+)", "JS Library", "Font Awesome"),
        (r"gsap[-.](\d+\.\d+\.\d+)", "JS Library", "GSAP"),
        (r"d3\.v(\d+)\.js", "JS Library", "D3.js"),
    ]

    META_GENERATOR_SIGNATURES = [
        (r"WordPress\s*([\d.]+)?", "CMS", "WordPress"),
        (r"Joomla!?\s*([\d.]+)?", "CMS", "Joomla"),
        (r"Drupal\s*([\d.]+)?", "CMS", "Drupal"),
        (r"Wix\.com", "Website Builder", "Wix"),
        (r"Squarespace", "Website Builder", "Squarespace"),
        (r"Shopify", "E-commerce", "Shopify"),
        (r"Ghost\s*([\d.]+)?", "CMS", "Ghost"),
        (r"TYPO3\s*([\d.]+)?", "CMS", "TYPO3"),
        (r"Magento\s*([\d.]+)?", "E-commerce", "Magento"),
        (r"PrestaShop\s*([\d.]+)?", "E-commerce", "PrestaShop"),
        (r"Webflow", "Website Builder", "Webflow"),
    ]

    SERVER_HEADER_RE = re.compile(
        r"(?P<product>Apache|nginx|Microsoft-IIS|LiteSpeed|Caddy|Cowboy|openresty)"
        r"(?:/(?P<version>[\d.]+))?", re.IGNORECASE
    )
    POWERED_BY_RE = re.compile(
        r"(?P<product>PHP|ASP\.NET|Express|Next\.js)"
        r"(?:/(?P<version>[\d.]+))?", re.IGNORECASE
    )

    COOKIE_SIGNATURES = [
        (r"PHPSESSID", "Language", "PHP"),
        (r"JSESSIONID", "Language", "Java (JSP/Servlet)"),
        (r"ASP\.NET_SessionId", "Language", "ASP.NET"),
        (r"laravel_session", "Framework", "Laravel"),
        (r"django", "Framework", "Django"),
        (r"connect\.sid", "Framework", "Express.js"),
        (r"csrftoken", "Framework", "Django"),
        (r"__cfduid|cf_clearance", "CDN/WAF", "Cloudflare"),
        (r"incap_ses|visid_incap", "CDN/WAF", "Imperva Incapsula"),
        (r"AWSALB|AWSALBCORS", "Cloud/LB", "AWS Application Load Balancer"),
    ]

    WELL_KNOWN_PATHS = {
        "/wp-login.php": ("CMS", "WordPress", ""),
        "/wp-json/": ("CMS", "WordPress", ""),
        "/administrator/": ("CMS", "Joomla", ""),
        "/user/login": ("CMS", "Drupal", ""),
        "/CHANGELOG.txt": ("CMS", "Drupal", ""),
        "/readme.html": ("CMS", "WordPress", ""),
        "/server-status": ("Web Server", "Apache", ""),
        "/actuator/health": ("Framework", "Spring Boot", ""),
        "/.git/HEAD": ("Exposure", "Exposed .git directory", ""),
        "/.env": ("Exposure", "Exposed .env file", ""),
        "/phpinfo.php": ("Exposure", "Exposed phpinfo()", ""),
    }

    # Extra header -> tech mappings beyond Server/X-Powered-By
    MISC_HEADER_SIGNATURES = [
        ("x-drupal-cache", None, "CMS", "Drupal"),
        ("x-varnish", None, "Cache/CDN", "Varnish"),
        ("cf-ray", None, "CDN/WAF", "Cloudflare"),
        ("x-amz-cf-id", None, "CDN", "Amazon CloudFront"),
        ("x-akamai-transformed", None, "CDN", "Akamai"),
        ("x-sucuri-id", None, "WAF", "Sucuri"),
        ("x-litespeed-cache", None, "Cache", "LiteSpeed Cache"),
        ("x-shopify-stage", None, "E-commerce", "Shopify"),
        ("x-nf-request-id", None, "Hosting", "Netlify"),
        ("x-vercel-id", None, "Hosting", "Vercel"),
    ]

    def __init__(self, target_url, timeout=10, verify_tls=True, user_agent=None):
        self.target_url = target_url if target_url.startswith("http") else "https://" + target_url
        self.timeout = timeout
        self.detections = {}
        self.raw_headers = {}
        self.raw_status = None
        self.ssl_context = ssl.create_default_context()
        if not verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        self.user_agent = user_agent or (
            "Mozilla/5.0 (compatible; TechFootBot/2.0; OSINT recon tool)"
        )

    def _get(self, path="/"):
        url = urljoin(self.target_url, path)
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                body = resp.read(500_000).decode("utf-8", errors="ignore")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            body = e.read(500_000).decode("utf-8", errors="ignore") if e.fp else ""
            return e.code, dict(e.headers or {}), body
        except Exception:
            return None, {}, ""

    def _add(self, category, product, version="", confidence="medium", evidence=""):
        d = Detection(category, product, version or "", confidence, evidence)
        existing = self.detections.get(d.key())
        if existing is None or (not existing.version and d.version):
            self.detections[d.key()] = d

    def analyze_headers(self, headers):
        lower_map = {k.lower(): v for k, v in headers.items()}
        for name, value in lower_map.items():
            if name == "server":
                m = self.SERVER_HEADER_RE.search(value)
                if m:
                    self._add("Web Server", m.group("product"), m.group("version") or "",
                               "high", f"Server header: {value}")
                else:
                    self._add("Web Server", value.split("/")[0], "", "low", f"Server header: {value}")
            elif name == "x-powered-by":
                m = self.POWERED_BY_RE.search(value)
                if m:
                    self._add("Language/Framework", m.group("product"), m.group("version") or "",
                               "high", f"X-Powered-By: {value}")
                else:
                    self._add("Language/Framework", value, "", "medium", f"X-Powered-By: {value}")
            elif name == "x-generator":
                self._add("CMS", value, "", "medium", f"X-Generator: {value}")
            elif name == "set-cookie":
                for pattern, category, product in self.COOKIE_SIGNATURES:
                    if re.search(pattern, value, re.IGNORECASE):
                        self._add(category, product, "", "medium", f"Cookie signature: {pattern}")

        for header_name, _, category, product in self.MISC_HEADER_SIGNATURES:
            if header_name in lower_map:
                self._add(category, product, "", "high", f"{header_name} header present")

    def analyze_html(self, body):
        parser = SimpleHTMLIndexer()
        try:
            parser.feed(body)
        except Exception:
            pass

        for meta in parser.meta_tags:
            if meta.get("name", "").lower() == "generator":
                content = meta.get("content", "")
                for pattern, category, product in self.META_GENERATOR_SIGNATURES:
                    m = re.search(pattern, content, re.IGNORECASE)
                    if m:
                        version = m.group(1) if m.groups() and m.group(1) else ""
                        self._add(category, product, version, "high", f"meta generator: {content}")

        for comment in parser.comments:
            for pattern, category, product in self.META_GENERATOR_SIGNATURES:
                m = re.search(pattern, comment, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.groups() and m.group(1) else ""
                    self._add(category, product, version, "medium", "HTML comment")

        for src in parser.scripts:
            for pattern, category, product in self.JS_LIBRARY_SIGNATURES:
                m = re.search(pattern, src, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.groups() else ""
                    self._add(category, product, version, "high", f"script src: {src}")

        for link in parser.links:
            href = link.get("href", "")
            for pattern, category, product in self.JS_LIBRARY_SIGNATURES:
                m = re.search(pattern, href, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.groups() else ""
                    self._add(category, product, version, "high", f"link href: {href}")

        body_signatures = [
            (r"/wp-content/", "CMS", "WordPress", "", "high", "/wp-content/ path found"),
            (r"Drupal\.settings", "CMS", "Drupal", "", "high", "Drupal.settings JS object"),
            (r"/sites/all/modules/", "CMS", "Drupal", "", "medium", "/sites/all/modules/ path"),
            (r"cdn\.shopify\.com", "E-commerce", "Shopify", "", "high", "cdn.shopify.com reference"),
            (r"__NEXT_DATA__", "JS Framework", "Next.js", "", "high", "__NEXT_DATA__ found"),
            (r"data-reactroot", "JS Framework", "React", "", "medium", "React DOM marker"),
        ]
        for pattern, category, product, version, confidence, note in body_signatures:
            if re.search(pattern, body, re.IGNORECASE):
                self._add(category, product, version, confidence, note)

        m = re.search(r'ng-version="([\d.]+)"', body)
        if m:
            self._add("JS Framework", "Angular", m.group(1), "high", "ng-version attribute")

    def _detect_soft_404(self, delay=0.2):
        """
        Some servers return HTTP 200 (with a friendly error page) for ANY
        path instead of a real 404 — probing well-known paths against such
        a server would otherwise "detect" every CMS/framework at once.
        We request a random, virtually-guaranteed-nonexistent path first;
        if the response is 200-ish, we fingerprint its content length /
        a content hash so later probes can tell "this is just the same
        soft-404 page" apart from a genuinely different, real resource.
        """
        import random
        import string
        import hashlib
        probe_path = "/__techfoot_baseline_" + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=16)) + "__/"
        status, headers, body = self._get(probe_path)
        time.sleep(delay)
        if status and status < 400:
            digest = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
            return {"soft_404": True, "status": status, "body_hash": digest, "body_len": len(body)}
        return {"soft_404": False}

    def probe_well_known_paths(self, delay=0.2):
        exposures = []
        baseline = self._detect_soft_404(delay=delay)
        import hashlib
        for path, (category, product, version) in self.WELL_KNOWN_PATHS.items():
            status, headers, body = self._get(path)
            is_candidate = bool(status and status < 400)
            if is_candidate and baseline.get("soft_404"):
                digest = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
                # Same status + same body content as the nonexistent-path baseline
                # => this server fakes 200s for everything; don't trust this hit.
                if digest == baseline["body_hash"] or len(body) == baseline["body_len"]:
                    is_candidate = False
            if is_candidate:
                if category == "Exposure":
                    # Exposure findings (.git/.env/phpinfo) are not software
                    # products — do NOT add to self.detections, or they get
                    # fed into the NVD CVE lookup as if they were a product
                    # (e.g. searching CVEs for "Exposed .git directory").
                    # Surface them only via the dedicated exposures list.
                    exposures.append({"path": path, "status": status, "note": product})
                else:
                    self._add(category, product, version, "high", f"Reachable path: {path} (HTTP {status})")
            time.sleep(delay)
        return exposures

    def analyze_robots_and_sitemap(self):
        """
        Passively reads /robots.txt and any linked sitemap(s) for OSINT
        value: disallowed paths often reveal admin panels, staging areas,
        or internal tooling the operator didn't want indexed (but which
        are still just as reachable). Purely a GET on two well-known,
        publicly-intended files — not active enumeration.
        """
        result = {"robots_found": False, "disallowed_paths": [], "sitemaps": []}
        status, headers, body = self._get("/robots.txt")
        if status and status < 400 and body:
            result["robots_found"] = True
            for line in body.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path not in result["disallowed_paths"]:
                        result["disallowed_paths"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm:
                        result["sitemaps"].append(sm)
        result["disallowed_paths"] = result["disallowed_paths"][:40]
        return result

    def run(self, probe_paths=True):
        status, headers, body = self._get("/")
        self.raw_status = status
        self.raw_headers = headers
        if status is None:
            return [], "", []
        self.analyze_headers(headers)
        self.analyze_html(body)
        exposures = self.probe_well_known_paths() if probe_paths else []
        self.robots_info = self.analyze_robots_and_sitemap() if probe_paths else {
            "robots_found": False, "disallowed_paths": [], "sitemaps": []}
        return list(self.detections.values()), body, exposures
