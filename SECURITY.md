# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.26.x  | :white_check_mark: |
| < 1.26  | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security concerns to the maintainers (see repository contacts)
3. Include a description of the vulnerability, steps to reproduce, and potential impact
4. Allow 90 days for a fix before public disclosure

## Security Measures

This project implements the following security controls:

### Authentication & Authorization
- JWT-based authentication with short-lived tokens (4 hours)
- Server-side token revocation via blocklist
- bcrypt password hashing (12 salt rounds)
- Rate limiting on login (10 attempts / 15 min) and registration endpoints
- Platform mode requires explicit proxy authentication header

### Data Protection
- AES-256-GCM encryption for credentials stored in SQLite
- No password hashes exposed in API responses
- Session files written with restrictive permissions (0600)
- Repo URLs sanitized to strip embedded credentials

### Input Validation
- Parameterized SQL queries throughout (no string concatenation)
- Path traversal prevention on file operations and plugin system
- Plugin names validated with strict alphanumeric regex
- Git refs and branch names validated before use
- `shell: false` enforced on all `spawn` calls in server routes

### Infrastructure
- CORS restricted to explicit origin allowlist
- Security headers via `helmet` (X-Frame-Options, X-Content-Type-Options, etc.)
- WebSocket connections authenticated via JWT
- Global error handler prevents stack trace leakage in production
- SVG plugin icons sanitized with DOMPurify

### CI/CD Security
- CodeQL SAST scanning on every push and weekly
- Dependency review blocks PRs introducing high-severity vulnerabilities
- npm audit runs in CI for known vulnerability detection
- OSSF Scorecard for supply chain security assessment
- 54 automated security regression tests

## Development Guidelines

When contributing, please follow these security practices:

1. **Never use `exec()` or `execSync()`** in server code — use `spawn()` with `shell: false`
2. **Never use `dangerouslySetInnerHTML`** without DOMPurify sanitization
3. **Never store secrets in plaintext** — use the encryption helpers in `db.js`
4. **Always validate and sanitize** user input before use in file paths, shell commands, or SQL
5. **Never export secrets** from modules — expose functions, not values
6. **Run `npm test:security`** before submitting PRs to verify no regressions
