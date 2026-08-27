"""
Lightweight common-port TCP connect scan + banner grab.

NOTE ON SCOPE: this is more "active" than the rest of the toolkit (which is
purely passive/OSINT). A plain TCP connect + read is the same class of
action as opening the port in a browser or `nc`/`telnet` — it is not an
exploit, flood, or protocol-abuse technique — but scanning ports you don't
control can still violate a host's terms of service or local law if you are
not authorized. This module is OFF by default in the CLI (`--ports` opts in)
for that reason.

Only checks a short list of common ports and does a single plain-text
banner read with a short timeout — no service-specific probing, no
brute-forcing, no protocol fuzzing.
"""

import concurrent.futures
import socket

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB",
}


def _grab_banner(sock, timeout=2):
    try:
        sock.settimeout(timeout)
        data = sock.recv(256)
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _check_port(hostname, port, timeout):
    service = COMMON_PORTS.get(port, "unknown")
    entry = {"port": port, "service_guess": service, "state": "closed/filtered", "banner": ""}
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            entry["state"] = "open"
            entry["banner"] = _grab_banner(sock, timeout=min(timeout, 2))
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return entry


def scan_common_ports(hostname, ports=None, timeout=2.5, max_workers=12):
    """
    Attempts a TCP connect to each port in `ports` (defaults to
    COMMON_PORTS), concurrently (bounded by `max_workers`) so a full sweep
    of ~19 ports takes a couple of seconds instead of up to ~47s run
    sequentially. For open ports, does a best-effort single-read banner
    grab (works for banner-on-connect protocols like SSH/FTP/SMTP; silent
    for request-response protocols like HTTP, which just show as "open").
    Returns a list of {"port", "service_guess", "state", "banner"} dicts,
    sorted by port number, containing only the ports found open.
    """
    ports = sorted(ports or COMMON_PORTS)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_port, hostname, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            entry = future.result()
            if entry["state"] == "open":
                results.append(entry)
    results.sort(key=lambda e: e["port"])
    return results
