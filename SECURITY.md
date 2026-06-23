# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly by emailing **security@trygeosuite.it** instead of using the public issue tracker.

### What to include

- A clear description of the vulnerability and its potential impact
- Steps to reproduce (if applicable)
- Your name and affiliation (optional)
- Any additional context (e.g., environment details)

### Timeline

- **Initial response**: within 48 hours
- **Assessment**: within 7 days
- **Fix and disclosure**: within 30 days (or sooner if feasible)

Once we've confirmed and fixed a vulnerability, we will:
1. Release a patched version
2. Publish a security advisory
3. Credit you as the reporter (with your consent)

## Scope

This policy covers vulnerabilities in:
- Production code (src/, lib/, bin/)
- Dependencies and transitive dependencies
- CI/CD pipeline and GitHub Actions workflows

## Out of Scope

- Configuration issues in user deployments
- Missing security hardening recommendations
- Social engineering / phishing attacks
- Denial of service from external services

## Security Best Practices

Users of this project should:
- Keep dependencies up to date via `npm update` / `pip install --upgrade`
- Review the `CHANGELOG.md` for security-related updates
- Monitor [Dependabot alerts](https://github.com/TryGeoSuite) for this repo
- Use the latest stable release (not development versions)

## Questions?

For general security questions or advice, open a discussion on GitHub or email **security@trygeosuite.it**.
