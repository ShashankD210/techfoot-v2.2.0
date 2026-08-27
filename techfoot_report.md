# Technology Footprint & CVE Report

**Target:** https://example.com  
**Scan time (UTC):** 2026-08-27T12:29:58.172028+00:00  
**Duration:** 14.6s  
**Risk level:** None (score 0/100) — 0 critical / 0 high / 0 medium / 0 low

> ⚠️ Passive/authorized-recon results only. Verify manually before acting.

## Security Headers Grade: F (0%)

| Header | Present | Value |
|---|---|---|
| strict-transport-security | ❌ |  |
| content-security-policy | ❌ |  |
| x-frame-options | ❌ |  |
| x-content-type-options | ❌ |  |
| referrer-policy | ❌ |  |
| permissions-policy | ❌ |  |
| x-xss-protection | ❌ |  |
| cross-origin-opener-policy | ❌ |  |
| cross-origin-resource-policy | ❌ |  |

**Information disclosure headers found:**
- `server`: cloudflare

## TLS Certificate
- Subject CN: example.com
- Issuer: Cloudflare TLS Issuing ECC CA 3 (SSL Corporation)
- Valid until: Oct 27 22:17:21 2026 GMT (61 days remaining)
- TLS version negotiated: TLSv1.3
- Cipher: TLS_AES_256_GCM_SHA384
- SANs: example.com, *.example.com

## TLS Protocol Support
- TLSv1: inconclusive (blocked by local OpenSSL policy, not the server)
- TLSv1_1: inconclusive (blocked by local OpenSSL policy, not the server)
- TLSv1_2: supported by server
- TLSv1_3: supported by server

## DNS Records
- **A:** 172.66.147.243, 104.20.23.154
- **AAAA:** 2606:4700:8d75:72db:f2d7:a6d:ef6b:ff98
- **MX:** 0 .
- **NS:** hera.ns.cloudflare.com., elliott.ns.cloudflare.com.
- **TXT:** "v=spf1 -all", "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"

**OSINT hints:**
- SPF record reveals mail infrastructure: v=spf1 -all

## Subdomains (Certificate Transparency — 0 found)

## WHOIS
- Registrar: n/a
- Created: n/a
- Expires: n/a
- Registrant org: n/a (often redacted)

## Detected Technologies & CVEs

### cloudflare (version unknown)
- **Category:** Web Server
- **Confidence:** low
- **Evidence:** Server header: cloudflare
- No CVEs matched.
