"""
Shodan-style favicon hashing.

Shodan (and by extension search.censys.io / Fofa) index sites by taking the
base64 of a site's /favicon.ico and running it through MurmurHash3 (x86, 32-bit).
This lets you pivot: `http.favicon.hash:<value>` on Shodan reveals every other
IP on the internet serving the *identical* favicon — extremely useful for
finding other instances of a custom admin panel, C2 panel, IoT device UI, or
self-hosted app that a generic banner grab wouldn't identify.

This module implements MurmurHash3 in pure Python (no `mmh3` pip dependency)
so it works in constrained/offline environments, and fetches the favicon
from the target to compute the hash.
"""

import base64
import urllib.error
import urllib.request
from urllib.parse import urljoin


def _mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 (x86, 32-bit) — matches the `mmh3.hash()` output
    used by Shodan's favicon hashing, including its signed-int wraparound."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = (length & 0xfffffffc)  # round down to multiple of 4

    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | ((data[i + 3]) << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    k1 = 0
    tail_start = rounded_end
    tail_size = length & 3
    if tail_size == 3:
        k1 ^= (data[tail_start + 2] & 0xff) << 16
    if tail_size >= 2:
        k1 ^= (data[tail_start + 1] & 0xff) << 8
    if tail_size >= 1:
        k1 ^= (data[tail_start] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)

    # Shodan reports the *signed* 32-bit representation
    if h1 & 0x80000000:
        h1 = -((h1 ^ 0xffffffff) + 1)
    return h1


def fetch_favicon_hash(target_url, timeout=10, ssl_context=None, user_agent=None):
    """
    Fetches /favicon.ico from the target and returns:
        {"hash": <int>, "shodan_query": "http.favicon.hash:<int>", "size_bytes": N}
    or None if no favicon was found / reachable.
    """
    url = urljoin(target_url if target_url.startswith("http") else "https://" + target_url,
                   "/favicon.ico")
    req = urllib.request.Request(url, headers={
        "User-Agent": user_agent or "Mozilla/5.0 (compatible; TechFootBot/2.0)"
    })
    try:
        kwargs = {"timeout": timeout}
        if ssl_context:
            kwargs["context"] = ssl_context
        with urllib.request.urlopen(req, **kwargs) as resp:
            if resp.status != 200:
                return None
            raw = resp.read(1_000_000)
    except Exception:
        return None

    if not raw:
        return None

    b64 = base64.b64encode(raw)
    h = _mmh3_x86_32(b64)
    return {
        "hash": h,
        "shodan_query": f"http.favicon.hash:{h}",
        "size_bytes": len(raw),
        "source_url": url,
    }
