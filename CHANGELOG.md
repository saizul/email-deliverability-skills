# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `warmup-plan`: `warmup_plan.py --metrics` accepts raw counts
  (`sent=N,bounced=N,complaints=N,deferred=N`) and converts them to percentages; the
  decision output now shows the rates it used (`metrics` in JSON).

### Fixed

- `warmup-plan`: the per-provider split now adds up to the day's volume exactly (largest
  remainder rounding); before, rows could be one or two messages over or under.
- `list-hygiene`: `list_hygiene.py --fuzzy-typos` flags domains one edit (insert, delete,
  replace or adjacent swap) away from a major mailbox provider (`gmaik.com` -> `gmail.com`,
  `yahoo.cm` -> `yahoo.com`) in addition to the built-in typo map. Real neighbouring domains
  such as `mail.com` and `ymail.com` are exempt, and ambiguous matches are not guessed.

## [0.1.0] - 2026-11-25

### Added

- `dns-auth-audit`: SPF (recursive lookup and void-lookup counting, duplicates, qualifiers,
  ptr, CIDR checks), DKIM (revoked, testing, RSA key size from DER), DMARC (tags, policy, external
  report authorisation, subdomain inheritance), BIMI, MTA-STS policy vs MX, TLS-RPT, null MX;
  offline from record text or JSON, optional `--live` via dig.
- `dmarc-report-analysis`: aggregate report parser for .xml, .gz and .zip (incl. DMARCbis
  namespace), duplicate report detection, per-source/reporter/header_from summaries, alignment
  rates and failure cause labels; safe against entity expansion and oversized archives.
- `bounce-and-complaint-triage`: DSN, ARF, mbox, Postfix/Exim log and CSV parsing; hard, soft,
  block, auth, throttle, content and complaint categories with actions and a suppression CSV.
- `email-template-lint`: Gmail clipping, image/text balance, alt text, risky links, forms and
  scripts, unsubscribe link, plain-text part, List-Unsubscribe/One-Click headers, attachments.
- `list-hygiene`: syntax, duplicates (Gmail folding), role, disposable, typo and suppression flags
  with clean and flagged CSV outputs.
- `warmup-plan`: warm-up schedule generator (presets, weekdays, provider split, segments) and a
  daily advance/hold/step-back decision.
- `sender-requirements-2024-plus`: Gmail/Yahoo/Outlook.com requirement checklist from a received
  message plus spam rate and volume.
- `wordpress-smtp-deliverability`: WordPress mail diagnosis from a test message, WP-CLI plugin
  list and wp-config.php constant names.
- Claude Code plugin marketplace manifest, `tools/validate_skills.py`, CI and release workflows.

[Unreleased]: https://github.com/saizul/email-deliverability-skills/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/email-deliverability-skills/releases/tag/v0.1.0
