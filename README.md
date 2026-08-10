# WhereDNS (AI GENERATED)

[![CI](https://github.com/MinottiAlessandro/WhereDNS/actions/workflows/ci.yml/badge.svg)](https://github.com/MinottiAlessandro/WhereDNS/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MinottiAlessandro/WhereDNS)](https://github.com/MinottiAlessandro/WhereDNS/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-2f765e.svg)](LICENSE)

WhereDNS is a DNS learning, visualization, and defensive-security utility. The native CLI is the primary application; the same engine also powers an optional local web interface.

Current release: **v0.1.0**.

It is designed to answer two questions at the same time:

1. **What did DNS return?** Records, sections, flags, response codes, EDNS, DNSSEC evidence, timing, cache state, and raw wire bytes.
2. **Why does it matter?** Plain-language protocol explanations, attack mechanics, observable defender signals, mitigations, and isolated exercises.

## Quick start

Go 1.26 or newer is required.

```bash
make build
./bin/wheredns help
./bin/wheredns query example.com --type A
./bin/wheredns trace example.com --type MX --no-cache
./bin/wheredns attacks cache-poisoning
./bin/wheredns lab run cache-poisoning
```

Prebuilt archives for Linux, macOS, and Windows are available from [GitHub Releases](https://github.com/MinottiAlessandro/WhereDNS/releases/latest). Each release includes `SHA256SUMS` for download verification.

Launch the optional visualization UI:

```bash
./bin/wheredns serve
# open http://127.0.0.1:8080
```

The web server deliberately refuses non-loopback bind addresses. The standalone CLI does not depend on the web interface.

## Commands

| Command | Purpose |
|---|---|
| `query NAME` | Perform and explain a DNS exchange |
| `trace NAME` | Iteratively walk root → TLD → authoritative servers |
| `reverse IP` | Build the `in-addr.arpa` or `ip6.arpa` PTR query |
| `compare NAME` | Compare responses from several recursive resolvers |
| `cache list\|clear\|path` | Inspect and control the explicit WhereDNS cache |
| `learn [TOPIC]` | Read protocol lessons and runnable examples |
| `attacks [ATTACK]` | Explore attack mechanism, prerequisites, signals, and defenses |
| `lab list\|run\|server` | Use offline simulations or the loopback DNS server |
| `serve` | Run the embedded local visualization UI |
| `types` | List the record types understood by the wire library |

Options can follow the query name:

```bash
wheredns query example.com --type HTTPS --server 1.1.1.1 --no-cache
wheredns query example.com --type DNSKEY --dnssec --wire
wheredns query example.com --transport tcp
wheredns query example.com --transport dot --server dns.google:853
wheredns query example.com --transport doh --server https://dns.google/dns-query
wheredns query bücher.example --type A
wheredns reverse 2001:db8::1 --no-cache
```

Use `--json` on query, trace, attack, and lab commands when consuming results programmatically.

## What the query engine exposes

- All registered and unknown `TYPE####` record types supported by the DNS wire library.
- Answer, Authority, and Additional sections with owner, class, TTL, type, RDATA, original text, and an explanation.
- Header flags: QR, AA, TC, RD, RA, AD, and CD.
- Response codes, including educational treatment of NOERROR/NODATA, NXDOMAIN, SERVFAIL, REFUSED, FORMERR, and NOTIMP.
- EDNS version, advertised UDP size, DO bit, extended RCODE, and returned options.
- DNSSEC evidence: AD assertion, RRSIG, DS, DNSKEY, NSEC, and NSEC3 presence.
- UDP with automatic TCP retry on truncation, direct TCP, DNS over TLS, and RFC 8484 wire-format DNS over HTTPS.
- IDN-to-Punycode normalization and IPv4/IPv6 reverse-name construction.
- Query/response size, round-trip timing, and optional hexadecimal packet dump.
- Warnings for suspicious Additional-section address data and important trust-boundary caveats.

### DNSSEC wording is intentionally precise

WhereDNS currently distinguishes:

- `validated-by-resolver`: the recursive resolver set AD;
- `signed-not-locally-validated`: signatures were returned, but WhereDNS did not build and cryptographically validate the entire chain itself;
- `unsigned-or-no-proof-returned`; and
- `not-requested`.

An AD bit is an assertion by the resolver. Over plaintext DNS, it is trustworthy only when the resolver path itself is trusted. DoT/DoH protects the client-to-resolver path, while DNSSEC authenticates DNS data. They address different threats.

## Explicit cache behavior

The WhereDNS cache is separate from the operating-system and upstream-resolver caches.

- It is enabled by default.
- `--no-cache` bypasses both cache reads and writes for that command.
- `--cache=false` is equivalent.
- Positive entries expire at the shortest relevant answer TTL.
- NXDOMAIN/NODATA entries use the SOA negative-cache limits.
- TTLs count down when cached data is displayed.
- The cache key includes name, type, server, transport, DNSSEC/recursion/checking flags, and EDNS size.
- `wheredns cache list` shows every live entry and expiry.
- `wheredns cache clear` removes only WhereDNS's own cache.

The default path is the platform user cache directory, normally `~/.cache/wheredns/cache.json`. Set `WHEREDNS_CACHE` to use another path. The cache contains DNS wire responses, not browsing history or application payloads.

## Iterative trace

`trace` starts with built-in IANA root hints and sends non-recursive queries directly to root, TLD, and authoritative servers. Every hop explains:

- the responding server and address;
- its hierarchy role;
- response code and timing;
- the referral, CNAME redirect, NODATA result, or final-answer decision;
- delegation NS records, DS proofs, and glue/address hints.

In-bailiwick glue is distinguished from out-of-bailiwick address hints. When a referral contains no usable address, this first release bootstraps the name-server address through the machine's configured recursive resolver and says so explicitly in the trace.

Direct DNS traffic may be blocked by restrictive networks. That is a network policy outcome, not necessarily a DNS error.

## Defensive attack atlas

The attack catalog currently covers:

- cache poisoning and Kaminsky-style forgery;
- on-path spoofing;
- resolver/router/registrar hijacking;
- reflection and amplification;
- DNS tunneling;
- DNS rebinding;
- dangling records and subdomain takeover;
- unauthorized zone transfer and dynamic update;
- DNSSEC downgrade and operational failures;
- SAD DNS and fragment-based poisoning;
- random-subdomain/water-torture and NXNSAttack;
- ghost-domain persistence;
- fast flux and domain-generation algorithms;
- IDN homographs and typosquatting;
- encrypted-DNS policy bypass; and
- lame or cyclic delegation.

Each entry separates prerequisites from mechanism, observable signals, and mitigations. That separation is useful in exams and real incident analysis: a plausible mechanism is not evidence that it occurred.

## Isolated laboratory

List deterministic exercises:

```bash
wheredns lab list
wheredns lab run amplification
wheredns lab run dnssec-bogus
wheredns lab run rebinding
```

The simulations do not generate attack traffic. They walk actor state, resolver decisions, defensive observations, metrics, and check-your-model questions.

For packet-level practice, start the loopback-only authoritative server:

```bash
wheredns lab server --scenario basic
wheredns query learn.test --server 127.0.0.1:15353 --type ANY --no-cache --wire
```

Available live modes:

| Mode | Query example | What to inspect |
|---|---|---|
| `basic` | `learn.test` | Ordinary A/AAAA/NS/MX/TXT/CAA/SOA records |
| `cache-poisoning` | `x.poison.test` | Unrelated Additional-section address warning |
| `rebinding` | `rebind.test` twice with `--no-cache` | Public documentation address alternating with loopback |
| `tunneling` | `mfrggzdfmztwq2lk.tunnel.test TXT` | Encoded-looking label and detection context |
| `lame-delegation` | `host.broken.test` | REFUSED without authoritative service |

The server:

- binds only to an explicit loopback IP;
- supports UDP and TCP on an unprivileged port;
- uses only `.test`, documentation, and loopback addresses;
- has no flooding, source spoofing, Internet targeting, recursive proxy, or mutation capability.

## Feature boundaries

DNS is a large protocol family. WhereDNS explains AXFR/IXFR, NOTIFY, dynamic update, TSIG, SIG(0), DNS cookies, ECS, and administrative security in its lessons and record views. This initial release deliberately does not send external zone transfers, dynamic updates, or NOTIFY operations. Those are administrative actions rather than normal learning queries and require a clearer authorization boundary.

Not yet implemented:

- independent cryptographic DNSSEC chain validation using a local trust-anchor store;
- DoQ, DNSCrypt, mDNS, LLMNR, and operating-system resolver event capture;
- a zone-file editor and fully simulated recursive-resolver state machine;
- passive packet capture/PCAP import; and
- authenticated local TSIG administration exercises.

The code is structured so these can be added without changing the CLI/web data contract.

## Project structure

```text
cmd/wheredns/          native executable entry point
internal/cli/          commands and terminal rendering
internal/dnsengine/    wire queries, trace, cache, explanations, result model
internal/learn/        protocol lessons and defensive attack atlas
internal/lab/          deterministic exercises and loopback DNS server
internal/webui/        loopback HTTP API and embedded static visualization UI
```

Both interfaces call `dnsengine.Engine`; the web layer never shells out to the CLI.

## Verification

```bash
make test
make check
```

Tests cover cache expiry, SOA negative TTLs, a loopback DNS exchange and cache hit, IDN normalization, curriculum completeness, lab safety constraints, and web security/API behavior.

## Protocol references

- [RFC 1034 — Domain Names: Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)
- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 4033 — DNS Security Introduction and Requirements](https://www.rfc-editor.org/rfc/rfc4033)
- [RFC 5452 — Measures for Making DNS More Resilient against Forged Answers](https://www.rfc-editor.org/rfc/rfc5452)
- [RFC 6891 — Extension Mechanisms for DNS (EDNS(0))](https://www.rfc-editor.org/rfc/rfc6891)
- [RFC 7766 — DNS Transport over TCP](https://www.rfc-editor.org/rfc/rfc7766)
- [RFC 7858 — DNS over TLS](https://www.rfc-editor.org/rfc/rfc7858)
- [RFC 8484 — DNS Queries over HTTPS](https://www.rfc-editor.org/rfc/rfc8484)

## Responsible use

Use direct queries only on public DNS infrastructure or systems you own or are explicitly authorized to test. The attack material is for defensive education. WhereDNS intentionally omits unrestricted spoofing, flooding, resolver abuse, and external mutation workflows.
