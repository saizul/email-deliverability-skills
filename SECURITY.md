# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## What counts as a vulnerability

These skills are run by AI agents on real mail data, so unsafe behaviour is treated like a code
vulnerability:

- A script that sends email, uploads data, or contacts a host without an explicit opt-in flag
- A script that prints a secret value (SMTP passwords, API keys from `wp-config.php`, tokens)
- Parsing flaws: crafted DMARC XML (entity expansion), archives (zip/gzip bombs, path traversal),
  `.eml`/mbox or CSV files that make a script execute something or write outside its output path
- A `SKILL.md` workflow that tells the agent to change DNS, ESP settings or a WordPress site, or
  upload a list, without asking the user first

A check that misses a problem (false negative) is a normal bug: please open an issue.

## Reporting

Please **do not** open a public issue. Use
[GitHub private vulnerability reporting](https://github.com/saizul/email-deliverability-skills/security/advisories/new)
with the affected skill, version, impact and steps to reproduce. Redact email addresses, domains,
IPs and any secrets from examples.

You will get an answer within 5 working days. Fixes are released as soon as possible and
credited in the changelog unless you prefer otherwise.
