#!/usr/bin/env python3
"""
Direct proxy IP checker — replicates the Cloudflare Worker's TCP+TLS+SNI probe
approach without depending on external check APIs.

For each candidate IP:port, it:
  1. Opens a raw TCP socket to the candidate
  2. Wraps it in TLS with SNI set to a probe target hostname
  3. Sends a crafted HTTP GET request through the tunnel
  4. Parses the JSON response to extract the exit IP and IP family

Probe targets (same as the Worker):
  - ipv4.soe.cc.cd  → forced IPv4 exit detection
  - ipv6.soe.cc.cd  → forced IPv6 exit detection
  - my.ippure.com    → fraud score
"""

import socket
import ssl
import time
import json
import re
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, Any, List, Tuple

# ---------------------------------------------------------------------------
# Constants (mirroring the Worker)
# ---------------------------------------------------------------------------

_HTTP_HEADER_BODY_SEP = b"\r\n\r\n"
_HTTP_STATUS_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d+)")
_CHUNKED_RE = re.compile(rb"(?i)transfer-encoding\s*:\s*chunked")
_CRLF = b"\r\n"

DEFAULT_TIMEOUT = 12       # seconds per probe
DEFAULT_READ_LIMIT = 65536
DEFAULT_CONCURRENCY = 5

# ---------------------------------------------------------------------------
# Probe targets
# ---------------------------------------------------------------------------

def _env_probe_target(name: str, default_host: str, default_path: str = "/") -> dict:
    """Build a probe target from env vars or defaults.

    Set PROBE_IPV4_HOST / PROBE_IPV6_HOST / PROBE_IPPURE_HOST to override.
    """
    env_key = f"PROBE_{name.upper()}_HOST"
    host = os.environ.get(env_key, default_host)
    path = os.environ.get(f"PROBE_{name.upper()}_PATH", default_path)
    return {
        "name": name,
        "host": host,
        "path": path,
        "request": (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Accept: application/json, text/plain, */*\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii"),
    }


PROBE_TARGETS = [
    _env_probe_target("ipv4", "ipv4.soe.cc.cd"),
    _env_probe_target("ipv6", "ipv6.soe.cc.cd"),
]

IPPURE_TARGET = _env_probe_target("ippure", "my.ippure.com", "/v1/info")


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _index_of(haystack: bytes, needle: bytes, start: int = 0) -> int:
    """Byte-level indexOf, matching the Worker's indexOfBytes."""
    return haystack.find(needle, start)


def _parse_chunked_body(raw: bytes) -> bytes:
    """Decode HTTP chunked transfer encoding."""
    parts = []
    offset = 0
    while offset < len(raw):
        line_end = _index_of(raw, _CRLF, offset)
        if line_end < 0:
            break
        size_hex = raw[offset:line_end].split(b";", 1)[0].strip().decode("ascii", "replace")
        try:
            size = int(size_hex, 16)
        except ValueError:
            break
        if size == 0:
            break
        body_start = line_end + len(_CRLF)
        body_end = body_start + size
        if body_end > len(raw):
            break
        parts.append(raw[body_start:body_end])
        offset = body_end + len(_CRLF)
    return b"".join(parts)


def _split_http_response(data: bytes) -> Tuple[bytes, bytes]:
    """Split raw HTTP response into header bytes and body bytes."""
    idx = _index_of(data, _HTTP_HEADER_BODY_SEP)
    if idx < 0:
        return data, b""
    header = data[:idx]
    body = data[idx + len(_HTTP_HEADER_BODY_SEP):]
    return header, body


def _pick_exit_ip(payload: dict) -> Optional[str]:
    """Extract exit IP from a probe JSON response."""
    ip = payload.get("ip") or payload.get("ipAddress")
    if isinstance(ip, str) and ip:
        return ip
    return None


def _is_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _get_exit_family(result: dict) -> Optional[str]:
    """Determine IP family from a probe result, matching the Worker's getExitFamily."""
    if not result.get("ok"):
        return None
    ip_type = str(result.get("exit", {}).get("ipType", "")).lower()
    if ip_type in ("ipv4", "ipv6"):
        return ip_type
    exit_ip = _pick_exit_ip(result.get("exit", {})) or ""
    if _is_ipv4(exit_ip):
        return "ipv4"
    if ":" in exit_ip:
        return "ipv6"
    return None


def _normalize_ippure(payload: dict) -> Optional[dict]:
    """Normalize ippure response, matching the Worker's normalizeIppureInfo."""
    if not isinstance(payload, dict):
        return None
    fraud_score = payload.get("fraudScore")
    if fraud_score is None or not isinstance(fraud_score, (int, float)):
        return None
    fraud_score = int(fraud_score)
    network_parts = []
    if payload.get("isResidential"):
        network_parts.append("residential")
    if payload.get("isBroadcast"):
        network_parts.append("broadcast")
    if payload.get("isDatacenter"):
        network_parts.append("datacenter")
    if payload.get("isProxy"):
        network_parts.append("proxy")
    if payload.get("isVpn"):
        network_parts.append("vpn")
    return {
        "ip": str(payload.get("ip", "")),
        "fraudScore": fraud_score,
        "networkType": "/".join(network_parts) or "unknown",
        "isResidential": payload.get("isResidential") is True,
        "isBroadcast": payload.get("isBroadcast") is True,
        "isDatacenter": payload.get("isDatacenter") is True,
        "isProxy": payload.get("isProxy") is True,
        "isVpn": payload.get("isVpn") is True,
        "asn": payload.get("asn"),
        "asOrganization": payload.get("asOrganization", ""),
        "country": payload.get("country", ""),
        "countryCode": payload.get("countryCode", ""),
        "region": payload.get("region", ""),
        "city": payload.get("city", ""),
    }


# ---------------------------------------------------------------------------
# Core probe
# ---------------------------------------------------------------------------

def probe_single(candidate_ip: str, candidate_port: int,
                 target: dict, timeout: float = DEFAULT_TIMEOUT,
                 read_limit: int = DEFAULT_READ_LIMIT) -> dict:
    """
    Probe a single candidate through one target endpoint.

    Returns a dict like:
        {"ok": bool, "status_code": int|None, "error": str|None,
         "connect_ms": int|None, "tls_ms": int|None, "http_ms": int|None,
         "exit": dict|None}
    """
    connect_ms = None
    tls_ms = None
    http_ms = None
    status_code = None
    sock = None
    tls_sock = None

    def _result(ok, code=None, error=None, exit_data=None):
        return {
            "candidate": f"{candidate_ip}:{candidate_port}",
            "connect_ms": connect_ms,
            "tls_ms": tls_ms,
            "http_ms": http_ms,
            "status_code": code,
            "ok": ok,
            "error": error,
            "exit": exit_data,
        }

    try:
        # 1. TCP connect
        started = time.monotonic()
        sock = socket.create_connection(
            (candidate_ip, candidate_port), timeout=timeout
        )
        sock.settimeout(timeout)
        connect_ms = round((time.monotonic() - started) * 1000)

        # 2. TLS handshake with SNI
        started = time.monotonic()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(
            sock, server_hostname=target["host"]
        )
        tls_ms = round((time.monotonic() - started) * 1000)

        # 3. Send HTTP request
        started = time.monotonic()
        tls_sock.sendall(target["request"])

        # 4. Read response
        chunks = []
        total_read = 0
        while total_read < read_limit:
            try:
                chunk = tls_sock.recv(min(4096, read_limit - total_read))
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total_read += len(chunk)
        http_ms = round((time.monotonic() - started) * 1000)

        if not chunks:
            return _result(False, error="empty response")

        raw = b"".join(chunks)
        header_bytes, body_bytes = _split_http_response(raw)

        # Parse status code
        m = _HTTP_STATUS_RE.match(header_bytes)
        if m:
            status_code = int(m.group(1))

        # Handle chunked encoding
        if _CHUNKED_RE.search(b"\r\n" + header_bytes + b"\r\n"):
            try:
                body_bytes = _parse_chunked_body(body_bytes)
            except Exception:
                pass

        body_text = body_bytes.decode("utf-8", "replace")

        if status_code != 200:
            preview = body_text[:200] if body_text else ""
            return _result(False, status_code,
                           f"unexpected status {status_code}: {preview}")

        try:
            payload = json.loads(body_text)
        except json.JSONDecodeError as e:
            return _result(False, status_code,
                           f"invalid json: {e}")

        if not _pick_exit_ip(payload):
            return _result(False, status_code,
                           "probe json missing exit ip")

        return _result(True, status_code, exit_data=payload)

    except (socket.timeout, TimeoutError) as e:
        return _result(False, status_code, f"timeout: {e}")
    except (ConnectionRefusedError, OSError) as e:
        return _result(False, status_code, f"connection failed: {e}")
    except ssl.SSLError as e:
        return _result(False, status_code, f"tls error: {e}")
    except Exception as e:
        return _result(False, status_code, f"{type(e).__name__}: {e}")
    finally:
        try:
            if tls_sock:
                tls_sock.close()
            elif sock:
                sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Full candidate check (all probes + ippure)
# ---------------------------------------------------------------------------

def check_one_candidate(ip_port: str, timeout: float = DEFAULT_TIMEOUT,
                        read_limit: int = DEFAULT_READ_LIMIT) -> dict:
    """
    Check a single candidate IP:port through all probe targets + ippure.

    Returns a dict mirroring the Worker's /check single-result shape:
        candidate, success, proxyIP, portRemote, inferred_stack,
        supports_ipv4, supports_ipv6, dual_stack, responseTime,
        probe_results, ippure, colo, timeStamp
    """
    # Parse candidate
    candidate = ip_port.strip()
    if candidate.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", candidate)
        if not m:
            return {"candidate": candidate, "success": False,
                    "error": f"invalid ipv6 candidate: {candidate}"}
        host = m.group(1)
        port = int(m.group(2) or 443)
    else:
        m = re.match(r"^([^:]+):(\d+)$", candidate)
        if m:
            host, port = m.group(1), int(m.group(2))
        else:
            host, port = candidate, 443

    # Run all probes in parallel
    all_targets = PROBE_TARGETS + [IPPURE_TARGET]
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(probe_single, host, port, t, timeout, read_limit): t["name"]
            for t in all_targets
        }
        results_by_name = {}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results_by_name[name] = fut.result()
            except Exception as e:
                results_by_name[name] = {"ok": False, "error": str(e)}

    ipv4_result = results_by_name.get("ipv4", {})
    ipv6_result = results_by_name.get("ipv6", {})
    ippure_result = results_by_name.get("ippure", {})

    has_ipv4 = _get_exit_family(ipv4_result) == "ipv4"
    has_ipv6 = _get_exit_family(ipv6_result) == "ipv6"

    # Build probe_results (same display rules as Worker)
    probe_results = {}
    if not has_ipv4 and not has_ipv6:
        if ipv4_result:
            probe_results["ipv4"] = ipv4_result
        if ipv6_result:
            probe_results["ipv6"] = ipv6_result
    else:
        if has_ipv4 and ipv4_result:
            probe_results["ipv4"] = ipv4_result
        if has_ipv6 and ipv6_result:
            probe_results["ipv6"] = ipv6_result

    inferred = ("dual_stack" if (has_ipv4 and has_ipv6)
                else "ipv4_only" if has_ipv4
                else "ipv6_only" if has_ipv6
                else "unknown")

    # Attach ippure info to matching probe
    ippure_info = _normalize_ippure(ippure_result.get("exit", {}))
    if ippure_info:
        ippure_ip = ippure_info["ip"]
        attached = False
        for key in ("ipv4", "ipv6"):
            pr = probe_results.get(key)
            if pr and pr.get("ok") and _pick_exit_ip(pr.get("exit", {})) == ippure_ip:
                pr["exit"]["ippure"] = ippure_info
                attached = True
                break
        if not attached:
            # Attach to the sole successful probe
            ok_probes = [pr for pr in probe_results.values()
                         if pr.get("ok") and pr.get("exit")]
            if len(ok_probes) == 1:
                ok_probes[0]["exit"]["ippure"] = ippure_info

    # Response time: average connect_ms of ipv4 + ipv6 probes
    connect_times = [
        r.get("connect_ms", 0) for r in (ipv4_result, ipv6_result)
        if isinstance(r.get("connect_ms"), (int, float))
    ]
    response_time = (round(sum(connect_times) / len(connect_times))
                     if connect_times else 0)

    success = ipv4_result.get("ok") or ipv6_result.get("ok")

    return {
        "candidate": candidate,
        "success": success,
        "proxyIP": host,
        "portRemote": port,
        "inferred_stack": inferred,
        "supports_ipv4": has_ipv4,
        "supports_ipv6": has_ipv6,
        "dual_stack": inferred == "dual_stack",
        "responseTime": response_time,
        "probe_results": probe_results,
        "ippure": ippure_info,
        "colo": "GH",          # GitHub Actions
        "timeStamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ---------------------------------------------------------------------------
# Batch check entry point (compatible with existing workflow)
# ---------------------------------------------------------------------------

def batch_check(ip_port_list: list, concurrency: int = DEFAULT_CONCURRENCY,
                timeout: float = DEFAULT_TIMEOUT,
                read_limit: int = DEFAULT_READ_LIMIT,
                verbose: bool = True) -> dict:
    """
    Check a batch of IP:PORT candidates directly.

    Returns a dict mapping "IP:PORT" → {success, fraudScore, data},
    compatible with the existing workflow's batch_check_single_endpoint output.
   """
    results = {}
    concurrency = max(1, min(concurrency, len(ip_port_list)))

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_map = {
            pool.submit(check_one_candidate, ip_port, timeout, read_limit): ip_port
            for ip_port in ip_port_list
        }
        for future in as_completed(future_map):
            ip_port = future_map[future]
            try:
                entry = future.result()
            except Exception as e:
                entry = {"candidate": ip_port, "success": False,
                         "error": str(e)}

            fraud_score = None
            pr = entry.get("probe_results", {})
            for key in ("ipv4", "ipv6"):
                probe = pr.get(key, {})
                if probe.get("ok"):
                    ipp = probe.get("exit", {}).get("ippure", {})
                    if isinstance(ipp, dict) and "fraudScore" in ipp:
                        fraud_score = ipp["fraudScore"]
                        break

            results[ip_port] = {
                "success": entry.get("success", False),
                "fraudScore": fraud_score,
                "data": entry,
            }

            if verbose:
                if entry.get("success"):
                    fs = f" fraudScore:{fraud_score}" if fraud_score is not None else ""
                    print(f"    [OK] {ip_port} valid ({entry.get('inferred_stack', '?')}){fs}")
                else:
                    err = entry.get("error", "unknown")
                    print(f"    [FAIL] {ip_port}: {err[:80]}")

    return results


# ---------------------------------------------------------------------------
# CLI for standalone use
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Direct proxy IP checker (TCP+TLS+SNI probe)"
    )
    parser.add_argument("targets", nargs="*",
                        help="IP:PORT candidates to check")
    parser.add_argument("--file", "-f",
                        help="Read candidates from file (one IP:PORT per line)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Per-probe timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Max concurrent checks (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--json", action="store_true",
                        help="Output full JSON results")
    args = parser.parse_args()

    candidates = list(args.targets)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    candidates.append(line)

    if not candidates:
        print("Usage: direct_check.py [IP:PORT ...] [--file ips.txt] [--json]")
        print("Example: direct_check.py 104.26.0.1:443 104.26.1.1:443 --json")
        sys.exit(1)

    print(f"Checking {len(candidates)} candidates directly "
          f"(concurrency={args.concurrency}, timeout={args.timeout}s)...\n")

    results = batch_check(candidates, concurrency=args.concurrency,
                          timeout=args.timeout, verbose=True)

    if args.json:
        output = {k: v["data"] for k, v in results.items()}
        print("\n" + json.dumps(output, indent=2, ensure_ascii=False))
    else:
        success_count = sum(1 for v in results.values() if v["success"])
        print(f"\nDone: {success_count}/{len(candidates)} valid")
