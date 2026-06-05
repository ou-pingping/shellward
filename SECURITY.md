# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in ShellWard, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **ialanhacker@gmail.com**

Or use [GitHub Security Advisories](https://github.com/jnMetaCode/shellward/security/advisories/new) to report privately.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **24 hours**: Acknowledgment of your report
- **72 hours**: Initial assessment and severity classification
- **7 days**: Fix development for critical/high severity issues
- **14 days**: Fix development for medium/low severity issues

### Recognition

We credit all reporters in our CHANGELOG (unless you prefer to remain anonymous).

## Security Measures

ShellWard itself is a security tool. We hold ourselves to a high standard:

- Zero external runtime dependencies (reduced supply chain risk)
- All regex patterns guarded against ReDoS by an automated audit (`npm run test:redos`, run in CI) that feeds adversarial inputs and enforces a per-detector time budget
- Audit log permissions restricted to owner-only (0600)
- **Detection is fully local** — command/injection/PII/tool-poisoning checks make no network calls.
  The only outbound requests are the optional update & vulnerability-DB checks
  (`checkForUpdate`, `fetchVulnDB`); disable them by setting `autoCheckOnStartup: false`.
- A release pipeline (`.github/workflows/release.yml`) is configured to publish to npm with [provenance](https://docs.npmjs.com/generating-provenance-statements) (SLSA build attestation); it activates once the repository's `NPM_TOKEN` secret is set
