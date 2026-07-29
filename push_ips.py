#!/usr/bin/env python3
"""
Push raw pureip.txt content to the configured API endpoint.

Expects env vars:
  PUSH_API_URL    - base URL (e.g. https://kxzn.svi.cc.cd)
  PUSH_API_TOKEN  - Bearer token
"""

import os, sys, requests

PUSH_API_URL = os.environ.get("PUSH_API_URL", "").strip().rstrip("/")
PUSH_API_TOKEN = os.environ.get("PUSH_API_TOKEN", "").strip()
PURE_FILE = "pureip.txt"


def main():
    if not PUSH_API_URL:
        print("SKIP: PUSH_API_URL not configured")
        return
    if not PUSH_API_TOKEN:
        print("SKIP: PUSH_API_TOKEN not configured")
        return
    if not os.path.exists(PURE_FILE):
        print(f"SKIP: {PURE_FILE} not found")
        return

    with open(PURE_FILE, "r", encoding="utf-8") as f:
        body = f.read()

    # Strip comments and count valid lines
    lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        print("No IPs to push")
        return

    api_url = f"{PUSH_API_URL}/api/proxy-ips"
    print(f"Pushing {len(lines)} IPs to {api_url} ...")

    headers = {
        "Authorization": f"Bearer {PUSH_API_TOKEN}",
        "Content-Type": "text/plain",
    }

    try:
        resp = requests.post(api_url, data=body.encode("utf-8"), headers=headers, timeout=30)
        print(f"Response: HTTP {resp.status_code}")
        if resp.text:
            print(f"Body: {resp.text[:500]}")
        if resp.status_code >= 400:
            print(f"ERROR: Push failed with status {resp.status_code}")
            sys.exit(1)
        else:
            print(f"SUCCESS: Pushed {len(lines)} IPs")
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
