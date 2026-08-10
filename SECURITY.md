# Security policy

## Supported versions

Until WhereDNS reaches 1.0, security fixes are provided for the latest published minor release.

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| Older | No |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository:

`Security` → `Advisories` → `Report a vulnerability`

Include the affected version, operating system, reproduction conditions, impact, and any suggested mitigation. Avoid public disclosure until a fix or coordinated disclosure plan is available.

## Scope notes

WhereDNS intentionally originates DNS queries and can contact user-selected DNS/DoH/DoT endpoints. Reports should distinguish intended query behavior from vulnerabilities such as unsafe bind exposure, cache corruption, trust misrepresentation, command execution, or bypass of the loopback-only laboratory boundary.
