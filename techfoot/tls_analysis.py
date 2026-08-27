"""TLS/certificate inspection: issuer, SANs, validity window, protocol/cipher."""

import socket
import ssl
from datetime import datetime, timezone


def analyze_tls(hostname, port=443, timeout=8):
    """
    Connects to hostname:port, negotiates TLS, and returns a dict describing
    the certificate and negotiated session. Returns {"error": ...} on failure.
    This is passive inspection only — no vulnerability exploitation.
    """
    result = {
        "hostname": hostname,
        "port": port,
        "connected": False,
    }
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["connected"] = True
                result["tls_version"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                days_remaining = None
                expired = None
                if not_after:
                    try:
                        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc)
                        days_remaining = (expiry_dt - datetime.now(timezone.utc)).days
                        expired = days_remaining < 0
                    except ValueError:
                        pass

                result.update({
                    "subject_cn": subject.get("commonName"),
                    "issuer_cn": issuer.get("commonName"),
                    "issuer_org": issuer.get("organizationName"),
                    "subject_alt_names": san,
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_until_expiry": days_remaining,
                    "expired": expired,
                    "serial_number": cert.get("serialNumber"),
                })
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection failed: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def check_weak_protocols(hostname, port=443, timeout=6):
    """
    Best-effort passive check of which legacy TLS/SSL protocol versions the
    server will still negotiate (e.g. TLS 1.0/1.1 still enabled is a common
    finding). Does not attempt any cipher downgrade attack — just tries a
    clean handshake pinned to each protocol version via SSLContext.minimum/
    maximum_version, which is the supported non-intrusive way to test this.
    """
    findings = {}
    protocol_map = {}
    for name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
        attr = getattr(ssl.TLSVersion, name, None)
        if attr is not None:
            protocol_map[name] = attr

    for name, version_enum in protocol_map.items():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version_enum
            ctx.maximum_version = version_enum
        except (ValueError, OSError):
            findings[name] = "unsupported by local OpenSSL"
            continue
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    findings[name] = "supported by server"
        except ssl.SSLError as e:
            msg = str(e).upper()
            # OpenSSL 3.x's default @SECLEVEL often blocks TLS1.0/1.1 locally
            # before any bytes reach the server — don't misreport that as a
            # server-side finding.
            if "NO_PROTOCOLS_AVAILABLE" in msg or "UNSUPPORTED_PROTOCOL" in msg:
                findings[name] = "inconclusive (blocked by local OpenSSL policy, not the server)"
            else:
                findings[name] = "rejected by server"
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            findings[name] = f"inconclusive (connection error: {e.__class__.__name__})"
        except Exception as e:
            findings[name] = f"inconclusive ({e.__class__.__name__})"

    legacy_enabled = [k for k, v in findings.items()
                       if v == "supported by server" and k in ("TLSv1", "TLSv1_1")]
    return {
        "protocol_support": findings,
        "legacy_protocols_enabled": legacy_enabled,
        "risk_note": ("Server accepts deprecated TLS 1.0/1.1 — these are considered "
                       "insecure (RFC 8996) and should be disabled.") if legacy_enabled else None,
    }
