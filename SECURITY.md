# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in `kafka-stig-audit`:

1. **Do not** open a public GitHub issue
2. Email the maintainers at: security@audit-forge.io (or open a private GitHub advisory)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 14 days.

## Scope

Security issues in scope:
- Incorrect security assessments (false negatives) that could give false confidence
- Command injection vulnerabilities in the runner
- Credential exposure in logs or output files

Out of scope:
- False positives (FAIL when the control is actually met)
- Performance issues
- Feature requests

## Responsible Disclosure

We follow responsible disclosure practices. If you report a valid vulnerability,
we will credit you in the release notes unless you prefer anonymity.
