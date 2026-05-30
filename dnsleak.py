#!/usr/bin/env python3
"""
dnsleak.py — Detect DNS leaks on your VPN connection from the command line.

Tests whether DNS queries are routed through your VPN tunnel or leak to
your ISP. Detects fallback to IPv4 ISP resolvers, IPv6 leaks, and the
notorious Windows Smart Multi-Homed Name Resolution (SMHNR) leak.

Usage:
    python dnsleak.py                  # Run all checks
    python dnsleak.py --vpn-asn 6789   # Compare against expected VPN ASN
    python dnsleak.py --json           # Machine-readable output
    python dnsleak.py --verbose        # Show per-query details

References:
    - Methodology: https://www.anonymflow.com/en/blog/dns-leak-test
    - DNS leak background: https://en.wikipedia.org/wiki/DNS_leak
    - RFC 1034 (DNS): https://datatracker.ietf.org/doc/html/rfc1034
    - RFC 8484 (DoH):  https://datatracker.ietf.org/doc/html/rfc8484

License: MIT
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Optional
from urllib import request
from urllib.error import URLError

__version__ = "0.1.0"


@dataclass
class LeakResult:
    """Single resolver detection result."""

    resolver_ip: str
    asn: Optional[int]
    org: Optional[str]
    country: Optional[str]
    is_isp: bool
    notes: str = ""


@dataclass
class Report:
    """Full diagnostic report."""

    own_ip: Optional[str]
    own_asn: Optional[int]
    own_org: Optional[str]
    own_country: Optional[str]
    resolvers: list[LeakResult]
    ipv6_leak: bool
    smhnr_suspected: bool
    overall_leak: bool


# ---------- IP / ASN utilities ----------

def get_public_ip(timeout: int = 5) -> Optional[str]:
    """Return the public IPv4 as seen by ipify."""
    try:
        with request.urlopen("https://api.ipify.org?format=text", timeout=timeout) as r:
            return r.read().decode().strip()
    except URLError:
        return None


def get_asn_info(ip: str, timeout: int = 5) -> tuple[Optional[int], Optional[str], Optional[str]]:
    """Look up ASN + org + country from ip-api.com (free, no key)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,as,asname,org"
        with request.urlopen(url, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        if data.get("status") != "success":
            return None, None, None
        # AS field looks like "AS6789 Some ISP Inc"
        as_field = data.get("as", "")
        asn = None
        if as_field.startswith("AS"):
            try:
                asn = int(as_field.split()[0][2:])
            except (ValueError, IndexError):
                pass
        org = data.get("org") or data.get("asname") or as_field
        country = data.get("country")
        return asn, org, country
    except (URLError, json.JSONDecodeError, KeyError):
        return None, None, None


# ---------- DNS leak detection ----------

def generate_probe_host() -> str:
    """Generate a unique subdomain so caches don't mask leaks."""
    nonce = uuid.uuid4().hex[:12]
    return f"{nonce}.dnsleaktest.com"


def trigger_dns_queries(host: str, n: int = 6) -> None:
    """Force the OS to resolve the host several times. Each resolution
    may hit a different recursive resolver in the upstream chain."""
    for _ in range(n):
        try:
            socket.gethostbyname(host)
        except (socket.gaierror, socket.herror):
            pass
        time.sleep(0.05)


def query_external_leak_endpoint(timeout: int = 8) -> list[str]:
    """Query the bash.ws DNS leak detection endpoint (free, public API)."""
    nonce = uuid.uuid4().hex[:16]
    probe_url = f"https://{nonce}.bash.ws"
    try:
        # First, trigger DNS resolution
        socket.gethostbyname(f"{nonce}.bash.ws")
    except socket.gaierror:
        pass
    # Then, query their detection endpoint
    try:
        url = f"https://bash.ws/dnsleak/test/{nonce}?json"
        with request.urlopen(url, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        resolvers = []
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and entry.get("type") == "dns":
                    ip = entry.get("ip")
                    if ip:
                        resolvers.append(ip)
        return resolvers
    except (URLError, json.JSONDecodeError, TimeoutError):
        return []


def check_ipv6_leak(timeout: int = 4) -> bool:
    """Returns True if a routable public IPv6 is detectable — outside
    a VPN that tunnels IPv6, this often indicates a leak vector."""
    try:
        with request.urlopen("https://api64.ipify.org?format=text", timeout=timeout) as r:
            ipv6 = r.read().decode().strip()
        # If it parses as IPv6 and isn't link-local or loopback, leak risk
        if ":" in ipv6:
            return not (ipv6.startswith("fe80") or ipv6 == "::1")
        return False
    except URLError:
        return False


def detect_smhnr(resolvers: list[str], own_country: Optional[str]) -> bool:
    """Smart Multi-Homed Name Resolution (Windows) typically presents
    >=2 distinct resolver ASNs in the same DNS query batch — one VPN,
    one ISP. Heuristic: if 3+ unique resolvers are seen across regions
    inconsistent with the VPN exit, SMHNR is the likely cause."""
    if len(resolvers) < 3:
        return False
    countries = set()
    with ThreadPoolExecutor(max_workers=8) as pool:
        for _, _, country in pool.map(get_asn_info, resolvers):
            if country:
                countries.add(country)
    return len(countries) >= 2 and (own_country in countries or len(countries) >= 3)


# ---------- Main report builder ----------

KNOWN_ISP_KEYWORDS = (
    "orange", "free", "sfr", "bouygues",  # FR
    "bt ", "sky", "virgin",                 # UK
    "comcast", "verizon", "att", "spectrum",  # US
    "movistar", "vodafone", "telefonica",  # ES
    "deutsche telekom",                    # DE
)


def looks_like_isp(org: Optional[str]) -> bool:
    if not org:
        return False
    o = org.lower()
    return any(kw in o for kw in KNOWN_ISP_KEYWORDS)


def build_report(
    expected_vpn_asn: Optional[int] = None,
    verbose: bool = False,
) -> Report:
    """Run the full set of checks and return a Report."""
    own_ip = get_public_ip()
    own_asn, own_org, own_country = (None, None, None)
    if own_ip:
        own_asn, own_org, own_country = get_asn_info(own_ip)

    # Probe DNS queries through multiple mechanisms
    probe_host = generate_probe_host()
    trigger_dns_queries(probe_host)
    resolver_ips = query_external_leak_endpoint()

    leak_results: list[LeakResult] = []
    if resolver_ips:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {
                pool.submit(get_asn_info, ip): ip for ip in resolver_ips
            }
            for fut in as_completed(futures):
                ip = futures[fut]
                asn, org, country = fut.result()
                is_isp = looks_like_isp(org) or (
                    expected_vpn_asn is not None
                    and asn is not None
                    and asn != expected_vpn_asn
                )
                note = ""
                if expected_vpn_asn and asn and asn != expected_vpn_asn:
                    note = f"expected ASN {expected_vpn_asn}, got {asn}"
                leak_results.append(LeakResult(ip, asn, org, country, is_isp, note))

    ipv6_leak = check_ipv6_leak()
    smhnr = detect_smhnr(resolver_ips, own_country)

    overall_leak = (
        any(r.is_isp for r in leak_results)
        or ipv6_leak
        or smhnr
        or len(leak_results) == 0  # No resolver found = inconclusive, flag it
    )

    if verbose:
        sys.stderr.write(f"[verbose] probe host: {probe_host}\n")
        sys.stderr.write(f"[verbose] resolvers detected: {len(resolver_ips)}\n")

    return Report(
        own_ip=own_ip,
        own_asn=own_asn,
        own_org=own_org,
        own_country=own_country,
        resolvers=leak_results,
        ipv6_leak=ipv6_leak,
        smhnr_suspected=smhnr,
        overall_leak=overall_leak,
    )


# ---------- CLI ----------

def format_human(report: Report) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append(" DNS LEAK DETECTOR — by AnonymFlow.com")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Your public IPv4:  {report.own_ip or 'unknown'}")
    if report.own_asn:
        lines.append(f"Your ASN/org:      AS{report.own_asn} ({report.own_org})")
    if report.own_country:
        lines.append(f"Your country:      {report.own_country}")
    lines.append("")
    lines.append(f"DNS resolvers detected: {len(report.resolvers)}")
    for r in report.resolvers:
        flag = "⚠️  ISP LEAK" if r.is_isp else "✅ tunneled"
        lines.append(f"  {flag}  {r.resolver_ip}  AS{r.asn}  {r.org}  ({r.country})")
        if r.notes:
            lines.append(f"     note: {r.notes}")
    lines.append("")
    lines.append(f"IPv6 leak suspected:    {'⚠️ YES' if report.ipv6_leak else '✅ no'}")
    lines.append(f"SMHNR pattern (Win):    {'⚠️ likely' if report.smhnr_suspected else '✅ no'}")
    lines.append("")
    verdict = "❌ LEAK DETECTED" if report.overall_leak else "✅ NO LEAK"
    lines.append(f"VERDICT: {verdict}")
    lines.append("")
    lines.append("More background, mitigation steps and a web-based")
    lines.append("checker:  https://www.anonymflow.com/en/blog/dns-leak-test")
    lines.append("=" * 60)
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnsleak",
        description="Detect DNS leaks on your VPN connection.",
        epilog="Methodology: https://www.anonymflow.com/en/blog/dns-leak-test",
    )
    parser.add_argument(
        "--vpn-asn",
        type=int,
        metavar="ASN",
        help="Expected ASN of your VPN provider. Any other ASN counts as a leak.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human output.")
    parser.add_argument("--verbose", action="store_true", help="Print probe details on stderr.")
    parser.add_argument("--version", action="version", version=f"dnsleak {__version__}")
    args = parser.parse_args(argv)

    report = build_report(expected_vpn_asn=args.vpn_asn, verbose=args.verbose)

    if args.json:
        out = asdict(report)
        out["resolvers"] = [asdict(r) for r in report.resolvers]
        print(json.dumps(out, indent=2))
    else:
        print(format_human(report))

    return 1 if report.overall_leak else 0


if __name__ == "__main__":
    sys.exit(main())
