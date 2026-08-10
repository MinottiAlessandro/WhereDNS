# Changelog

All notable changes to WhereDNS are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-08-10

### Added

- Native DNS CLI with recursive/direct querying, record and flag explanations, JSON output, raw wire dumps, IDN handling, reverse DNS, and resolver comparison.
- Direct iterative tracing from root servers through TLD and authoritative servers.
- Explicit persistent TTL-aware cache with bypass, inspection, clearing, and negative caching.
- UDP, TCP, DNS over TLS, and DNS over HTTPS transports.
- DNSSEC and EDNS evidence inspection with precise trust-boundary explanations.
- Defensive atlas covering nineteen DNS attack families.
- Seven isolated security exercises and a loopback-only UDP/TCP authoritative lab server.
- Embedded responsive web visualization UI using the same engine as the CLI.
- Automated tests, race checks, vetting, multi-platform release builds, and checksums.

[0.1.0]: https://github.com/MinottiAlessandro/WhereDNS/releases/tag/v0.1.0
