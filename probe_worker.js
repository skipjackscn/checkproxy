/**
 * Cloudflare Worker — Proxy IP probe endpoint.
 *
 * Paste this into the Cloudflare Dashboard → Workers & Pages → Create → Edit code.
 * Then bind it to a domain routed through Cloudflare (orange cloud).
 *
 * The checker connects to a CF edge IP with SNI = your probe domain,
 * Cloudflare forwards the request here, and we return the IP we see.
 *
 * Deploy this SINGLE Worker, then create TWO Worker Routes (or custom domains):
 *   ipv4.your-domain.com  → DNS: A record only
 *   ipv6.your-domain.com  → DNS: AAAA record only
 *
 * The Worker detects ipv4/ipv6 by the hostname prefix and returns the matching
 * ipType. The checker only needs to reach the probe through the candidate IP —
 * if the connection succeeds, that protocol stack is supported.
 *
 * Then set env vars in your checker:
 *   PROBE_IPV4_HOST=ipv4.your-domain.com
 *   PROBE_IPV6_HOST=ipv6.your-domain.com
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cf = request.cf || {};

    // Cloudflare passes the original client IP in this header.
    const clientIp = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const isIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(clientIp)
      && clientIp.split(".").every(p => Number(p) <= 255);

    // Determine ipType from hostname or fall back to IP format.
    // This is the key difference from a VPS-based probe:
    // Workers run at the edge and see the same CF-Connecting-IP for both
    // IPv4 and IPv6 probes. We differentiate by hostname.
    const host = (request.headers.get("Host") || url.hostname || "").toLowerCase();
    let ipType;
    if (host.startsWith("ipv6") || host.includes("ipv6.")) {
      ipType = "ipv6";
    } else if (host.startsWith("ipv4") || host.includes("ipv4.")) {
      ipType = "ipv4";
    } else {
      ipType = isIPv4 ? "ipv4" : "ipv6";
    }

    // Colo code from CF-Ray or request.cf
    const cfRay = request.headers.get("CF-Ray") || "";
    const rayColo = cfRay.includes("-") ? cfRay.split("-").pop() : "";
    const colo = rayColo || cf.colo || "???";

    const payload = {
      ip: clientIp,
      ipType,
      colo,
      country: cf.country || "",
      asOrganization: cf.asOrganization || "",
      asn: cf.asn || null,
      continent: cf.continent || "",
      region: cf.region || "",
      regionCode: cf.regionCode || "",
      city: cf.city || "",
      postalCode: cf.postalCode || "",
      timezone: cf.timezone || "",
      longitude: cf.longitude || "",
      latitude: cf.latitude || "",
      loc: cf.longitude && cf.latitude ? `${cf.latitude},${cf.longitude}` : "",
      org: "",
      cnIspCode: "",
      time: new Date().toISOString().replace("T", " ").slice(0, 19),
    };

    return new Response(JSON.stringify(payload, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
      },
    });
  },
};
