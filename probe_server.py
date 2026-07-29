#!/usr/bin/env python3
"""
Cloudflare probe origin server — returns the connecting client IP as JSON.

Deploy behind a Cloudflare-proxied domain (orange cloud).
The checker connects to a Cloudflare edge IP with SNI = your probe domain,
Cloudflare forwards the request here, and we return the IP we see.

Usage:
    python3 probe_server.py                  # listen on 0.0.0.0:8443
    python3 probe_server.py --port 8080       # custom port
    python3 probe_server.py --bind 127.0.0.1  # localhost only (nginx reverse proxy)
    python3 probe_server.py --ipv6            # listen on [::]:8443 (dual-stack)

Environment variables:
    PROBE_PORT    — listen port (default 8443)
    PROBE_BIND    — bind address (default 0.0.0.0)
    PROBE_IPV6    — set to "1" to enable IPv6 dual-stack
"""

import json
import os
import re
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from socket import IPPROTO_IPV6, IPV6_V6ONLY

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BIND_HOST = os.environ.get("PROBE_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("PROBE_PORT", "8443"))
ENABLE_IPV6 = os.environ.get("PROBE_IPV6", "").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IPv4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def _is_ipv4(ip: str) -> bool:
    return bool(_IPv4_RE.match(ip))


def _ip_family(ip: str) -> str:
    """Return 'ipv4' or 'ipv6'."""
    if _is_ipv4(ip):
        return "ipv4"
    if ":" in ip:
        return "ipv6"
    return "ipv4"  # safe default


def _extract_colo(cf_ray: str) -> str:
    """Cloudflare Ray ID encodes the datacenter code as the last segment.
    Example: '8d3f2a1b9c0e-NRT' → 'NRT'."""
    if not cf_ray:
        return ""
    parts = cf_ray.rsplit("-", 1)
    if len(parts) == 2:
        return parts[1].upper()
    return ""


def _get_real_ip(headers: dict, client_address: tuple) -> str:
    """Get the real client IP, respecting Cloudflare headers."""
    # Cloudflare passes the original client IP here
    cf_ip = headers.get("CF-Connecting-IP", "").strip()
    if cf_ip:
        return cf_ip
    # Fallback: True-Client-IP (enterprise plan)
    true_ip = headers.get("True-Client-IP", "").strip()
    if true_ip:
        return true_ip
    # Last resort: direct connection IP (not behind CF reverse proxy)
    return client_address[0]


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class ProbeHandler(BaseHTTPRequestHandler):
    """Single-endpoint handler that returns client IP info as JSON."""

    # Silence request logging for production
    def log_message(self, format, *args):
        pass

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Build a lowercase header dict for convenience
        headers_lower = {k.lower(): v for k, v in self.headers.items()}

        client_ip = _get_real_ip(headers_lower, self.client_address)
        ip_type = _ip_family(client_ip)

        # Parse CF-Ray for colo code
        cf_ray = headers_lower.get("cf-ray", "")
        colo = _extract_colo(cf_ray)

        # Build response — same shape the checker expects
        payload = {
            "ip": client_ip,
            "ipType": ip_type,
            "colo": colo or "???",
            "country": headers_lower.get("cf-ipcountry", ""),
            "asOrganization": "",
            "asn": None,
            "continent": headers_lower.get("cf-ipcontinent", ""),
            "region": "",
            "regionCode": "",
            "city": "",
            "postalCode": "",
            "timezone": headers_lower.get("cf-timezone", ""),
            "longitude": "",
            "latitude": "",
            "loc": "",
            "org": "",
            "cnIspCode": "",
            "time": self.date_time_string(),
        }
        self._json(payload)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Simple CLI override
    bind = BIND_HOST
    port = BIND_PORT
    ipv6 = ENABLE_IPV6

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2
        elif args[i] == "--bind" and i + 1 < len(args):
            bind = args[i + 1]; i += 2
        elif args[i] == "--ipv6":
            ipv6 = True; i += 1
        elif args[i] in ("--help", "-h"):
            print(__doc__)
            sys.exit(0)
        else:
            i += 1

    server = HTTPServer((bind, port), ProbeHandler)

    # Enable IPv6 dual-stack if requested
    if ipv6:
        server.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)

    proto = "IPv4+IPv6" if ipv6 else "IPv4"
    print(f"Probe server listening on {bind}:{port} ({proto})")
    print(f"Put this behind Cloudflare (orange cloud) DNS → your-probe-domain.com")
    print(f"Then check with: curl -k https://your-probe-domain.com/")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
