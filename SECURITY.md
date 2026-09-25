# Security Policy

## Reporting

Please report suspected vulnerabilities privately through the repository's GitHub
Security Advisory page. Do not open a public issue for an undisclosed vulnerability.

Do not include real account credentials, personal communications, phone numbers,
email addresses, or raw captures from production systems in a report.

## Benchmark-specific rules

- Never run untrusted fork code on self-hosted device or account runners.
- Use synthetic accounts, contacts, and one-time canary identifiers.
- Treat Playwright traces, HAR files, page source, logs, screenshots, video, and packet
  captures as sensitive even when they originate from synthetic accounts.
- Do not attempt unauthorized certificate-pinning bypass, penetration testing, or
  contact enumeration.
- Review provider terms and app-store rules before automating any subject.
- Pin third-party Actions to reviewed commit SHAs and container images to digests.
