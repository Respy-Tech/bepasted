# Security Policy

## Reporting a Vulnerability

At BePasted, we take security seriously. If you believe you've found a security vulnerability in our service, we encourage you to report it to us responsibly.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them directly to us at **security@bepasted.com**.

Please include the following details in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact of the vulnerability
- Any potential mitigations you've identified

We commit to:

- Acknowledge receipt of your vulnerability report within 48 hours
- Provide an initial assessment of the report within 5 business days
- Keep you informed of our progress addressing the issue
- Not take legal action against security researchers who responsibly report vulnerabilities

## Scope

This security policy applies to:
- bepasted.com website and subdomains
- BePasted API services
- All source code in the BePasted GitHub repository

## Security Measures

BePasted implements several security measures to protect user data and privacy:

### Privacy Protection
- IP anonymization with cryptographic hashing
- Strict data retention policies (configurable, defaults: 30 days for active pastes, 90 days for archived)
- No tracking cookies or user profiling
- Privacy-focused analytics

### Security Measures
- Content scanning for malicious code
- CSRF protection against cross-site request forgery
- Content Security Policy (CSP) implementation
- Strict input validation and content sanitization
- Secure password handling with bcrypt
- Rate limiting to prevent abuse

### Infrastructure Security
- Database connection pooling with security timeouts
- Comprehensive error handling and secure logging
- Cross-Origin Resource Sharing (CORS) protection
- DDoS protection with Arcjet

## Supported Versions

We provide security updates for the current production version of BePasted. We recommend always using the latest version.

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| < 2.0.0 | :x:                |

## Vulnerability Disclosure Policy

- We follow a coordinated disclosure process
- We request a 90-day disclosure deadline from initial report
- Vulnerabilities will be disclosed after they have been fixed
- Credit will be given to security researchers who report valid vulnerabilities (unless they prefer to remain anonymous)

## Security Headers

BePasted implements recommended security headers including:
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- X-XSS-Protection

## Third-Party Security Tools

BePasted uses several third-party security tools:

- **Cloudflare Turnstile** for bot detection and prevention
- **Arcjet** for DDoS protection and rate limiting
- **BetterStack** for centralized, privacy-focused logging

## Security Updates

For significant security updates, we will:
- Issue security advisories on GitHub
- Update our status page
- Notify users through the website when appropriate

## Responsible Disclosure

We believe in responsible disclosure and follow these principles:
- Users' privacy and data security come first
- We fix vulnerabilities as quickly as possible
- We disclose vulnerabilities responsibly after they've been fixed
- We acknowledge and credit those who responsibly disclose valid issues

Thank you for helping keep BePasted and our users safe!

---

*This security policy was last updated on February 26, 2025* 