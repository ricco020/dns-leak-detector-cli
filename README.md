# dnsleak — DNS leak detector CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A no-dependency command-line tool to detect **DNS leaks** on your VPN
connection — including Windows SMHNR leaks, IPv6 leaks, and ISP-resolver
fallbacks that web-based testers often miss.

```text
============================================================
 DNS LEAK DETECTOR — by AnonymFlow.com
============================================================

Your public IPv4:  198.51.100.42
Your ASN/org:      AS136787 (Tefincom S.A.)
Your country:      United States

DNS resolvers detected: 2
  ✅ tunneled  103.86.96.100   AS136787  Tefincom   (US)
  ⚠️  ISP LEAK  80.10.246.2     AS3215    Orange     (FR)

IPv6 leak suspected:    ✅ no
SMHNR pattern (Win):    ⚠️ likely

VERDICT: ❌ LEAK DETECTED
```

## Why this tool exists

Most web-based DNS leak testers (dnsleaktest.com, browserleaks, ipleak.net)
do an excellent job at flagging the obvious case — but they all share two
blind spots:

1. **They only see queries triggered by your browser**, so leaks that
   happen at the OS level (Windows SMHNR, system services bypassing the
   VPN) often slip through.
2. **They can't enforce your expected VPN ASN.** If your tunnel exits via
   a different provider than you think, no warning is raised.

This CLI complements those checkers by probing from the operating system
itself (via `getaddrinfo()` and an external probe domain), then comparing
each detected resolver's ASN to your expected VPN provider.

For the full methodology and a detailed write-up of every leak vector —
KRACK, IPv6, SMHNR, DoH overrides, captive-portal short-circuits — see
the companion guide:

**[Test a DNS leak in 2 minutes — complete methodology](https://www.anonymflow.com/en/blog/dns-leak-test)**

We also publish a [web-based DNS + WebRTC + IPv6 checker](https://www.anonymflow.com/en/tools/test-fuite-dns)
that mirrors the same logic in the browser.

## Install

No PyPI dependency — just clone and run:

```bash
git clone https://github.com/<your-org>/dns-leak-detector-cli
cd dns-leak-detector-cli
python3 dnsleak.py
```

Requires Python 3.8+. Tested on Linux, macOS, and Windows 10/11.

## Usage

```bash
# Quick check, human-readable output
python3 dnsleak.py

# Compare against your expected VPN provider (find the ASN at bgp.he.net)
python3 dnsleak.py --vpn-asn 136787   # NordVPN (Tefincom S.A.)

# Machine-readable JSON, useful for scripting / CI
python3 dnsleak.py --json

# Show probe details on stderr (debugging)
python3 dnsleak.py --verbose
```

### Exit codes

| Code | Meaning                          |
|------|----------------------------------|
| 0    | No leak detected                 |
| 1    | Leak detected or inconclusive    |
| 2    | Argument error                   |

This makes the tool usable inside health-checks and CI:

```bash
# Cron job that alerts when a leak appears
*/15 * * * * /usr/bin/python3 /opt/dns-leak-detector-cli/dnsleak.py \
  --vpn-asn 136787 || /usr/local/bin/alert-on-call.sh
```

## How it works

1. **Public IP + ASN lookup** — queries `ipify.org` (free, no key) for
   your egress IPv4, then `ip-api.com` for the ASN, org, and country.
2. **DNS probe** — generates a unique random subdomain and forces the
   OS to resolve it through `getaddrinfo()`, then asks the open
   `bash.ws` leak-detection endpoint which resolver(s) actually
   answered the recursive query. Because each probe is fresh, no cache
   can mask a leak.
3. **ASN comparison** — every detected resolver's ASN is checked.
   Known ISP keywords (Orange, Free, BT, Comcast, Movistar, …) are
   flagged automatically; with `--vpn-asn`, anything outside your
   expected provider is also flagged.
4. **IPv6 probe** — calls `api64.ipify.org`. If a routable public IPv6
   exits *outside* your tunnel (and your VPN doesn't tunnel IPv6),
   that's a leak vector.
5. **SMHNR heuristic** — Windows' [Smart Multi-Homed Name Resolution](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-resolution-issue-smart-multihomed)
   forwards a DNS query to *every* active adapter in parallel and
   accepts whichever response arrives first. If we see ≥3 resolvers
   across ≥2 distinct countries on a single probe burst, SMHNR is the
   most likely cause and gets flagged.

## Privacy

The tool talks to four free public APIs:

| Endpoint              | Purpose                | Data sent          |
|-----------------------|------------------------|--------------------|
| `api.ipify.org`       | Your public IPv4       | Standard HTTP req  |
| `api64.ipify.org`     | IPv6 detection         | Standard HTTP req  |
| `ip-api.com`          | ASN + country lookup   | IPs (yours + DNS)  |
| `bash.ws`             | DNS resolver detection | A nonce subdomain  |

No data is sent to AnonymFlow servers; everything stays between your
machine and these public endpoints.

## Limitations

- The bash.ws endpoint is rate-limited; running the tool dozens of times
  in a row will start returning empty resolver lists. Wait a minute and
  retry.
- ASN data from ip-api is updated weekly; very fresh VPN ranges may
  briefly appear as "unknown".
- The SMHNR heuristic can produce false positives on multi-homed
  servers with split DNS — interpret in context.

## Companion resources

- [Full DNS leak methodology + per-OS fixes](https://www.anonymflow.com/en/blog/dns-leak-test) — the reference write-up this CLI mirrors
- [VPN security audit — 9 tests](https://www.anonymflow.com/en/blog/complete-vpn-security-audit) — broader battery of checks (WebRTC, kill-switch, IPv6, etc.)
- [WebRTC leak detector tool](https://www.anonymflow.com/en/tools/test-fuite-dns) — browser-based companion

## License

[MIT](LICENSE) — do whatever you want, including commercial use.

## Acknowledgements

- [DNS leak test methodology by AnonymFlow](https://www.anonymflow.com/en/blog/dns-leak-test) — primary reference
- [bash.ws](https://bash.ws/) — public DNS leak detection endpoint
- [ip-api.com](https://ip-api.com/) — free ASN/geo lookup
- [RFC 1034 — Domain Names](https://datatracker.ietf.org/doc/html/rfc1034)
- [Windows SMHNR documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-resolution-issue-smart-multihomed)

---

*Built and maintained by the team behind [AnonymFlow](https://www.anonymflow.com) — independent VPN / privacy tooling and research. Read our [methodology](https://www.anonymflow.com/en/methodology) and the [95-session VPN streaming study](https://www.anonymflow.com/en/blog/study-vpn-streaming-2026-95-test-sessions) for the kind of testing this CLI was distilled from.*
