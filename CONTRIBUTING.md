# Contributing to WhereDNS

Thank you for helping improve WhereDNS. Contributions should preserve its two central goals: protocol accuracy and safe defensive education.

## Development setup

WhereDNS requires Go 1.26 or newer.

```bash
git clone https://github.com/MinottiAlessandro/WhereDNS.git
cd WhereDNS
make test
make build
```

Before opening a pull request, run:

```bash
gofmt -w cmd internal
make check
node --check internal/webui/static/app.js
```

## Pull requests

- Keep changes focused and explain the user-visible behavior.
- Add tests for protocol decisions, cache behavior, API contracts, and lab safety boundaries.
- Distinguish observed DNSSEC evidence from locally verified cryptographic proof.
- Update `README.md` and `CHANGELOG.md` when commands or output contracts change.
- Do not include generated binaries, cache files, credentials, packet captures containing private data, or unrelated DNS histories.

## Security-lab boundaries

Educational attack content must remain isolated and defensive:

- live lab services bind only to loopback;
- examples use `.test`, documentation, or loopback addresses;
- no source spoofing, flooding, unrestricted recursive proxying, credential capture, or Internet mutation workflows;
- every scenario explains defender-visible signals and mitigations.

For a vulnerability in WhereDNS itself, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.
