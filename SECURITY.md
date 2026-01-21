# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

### 🔒 For Security Issues

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues by emailing:
- Create a private security advisory in the repository's Security tab
- Or email the maintainers directly (if contact info is available)

### 📋 What to Include

When reporting a vulnerability, please include:

1. **Description** - A clear description of the vulnerability
2. **Steps to Reproduce** - Detailed steps to reproduce the issue
3. **Impact** - What an attacker could potentially do
4. **Affected Versions** - Which versions are affected
5. **Suggested Fix** - If you have a suggestion for fixing the issue

### ⏱️ Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 5 business days
- **Resolution Timeline:** Depends on severity
  - Critical: 24-48 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: Next release

### 🏆 Recognition

We appreciate security researchers who help keep LeaseSign secure. Contributors who report valid security issues will be:

- Acknowledged in our release notes (unless they prefer to remain anonymous)
- Added to our security hall of fame (coming soon)

## Security Best Practices for Users

When deploying LeaseSign:

1. **Change the JWT Secret** - Never use the default secret in production
2. **Use HTTPS** - Always deploy behind HTTPS in production
3. **Secure SMTP Credentials** - Store email credentials securely
4. **Regular Updates** - Keep dependencies updated
5. **Database Backups** - Regularly backup your data directory
6. **Access Control** - Limit server access to authorized personnel

## Known Security Considerations

- JWT tokens expire after 7 days
- Passwords are hashed with bcrypt (10 rounds)
- Signing tokens are unique UUIDs per party
- IP addresses are logged for signatures (ESIGN compliance)

Thank you for helping keep LeaseSign secure! 🔐
