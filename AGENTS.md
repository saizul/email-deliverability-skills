# AGENTS.md

Guidance for Codex CLI and other coding agents that use or work on this repository.

## Using the skills

The skills live in `skills/<name>/SKILL.md` and follow the Agent Skills format. Codex discovers
them when they are copied to `~/.agents/skills/` or `.agents/skills/` (see README "Install"). If
you are reading this file inside the repository instead:

1. Pick the skill whose `description` matches the user's request:

   | Request is about | Skill |
   | --- | --- |
   | SPF, DKIM, DMARC, BIMI, MTA-STS records; "permerror", "too many lookups" | `dns-auth-audit` |
   | DMARC aggregate report XML / .gz / .zip, "who sends as my domain" | `dmarc-report-analysis` |
   | bounce messages, SMTP error codes, mail logs, complaints | `bounce-and-complaint-triage` |
   | HTML email template or .eml review, Gmail clipping | `email-template-lint` |
   | cleaning or deduplicating a list CSV, suppression | `list-hygiene` |
   | new domain/IP ramp-up, "can I send more today?" | `warmup-plan` |
   | Gmail/Yahoo/Outlook.com sender rules, one-click unsubscribe | `sender-requirements-2024-plus` |
   | WordPress / WooCommerce email not arriving or in spam | `wordpress-smtp-deliverability` |

2. Read that `SKILL.md` completely and follow its Workflow section in order.
3. Paths such as `scripts/x.py` and `references/y.md` are relative to the skill folder.
   `${CLAUDE_SKILL_DIR}` in the text means that folder; Codex does not expand it.
4. Read files in `references/` only when a workflow step points to them.

## Safety rules (apply to every skill)

- Scripts are read-only and offline. Use network flags (`--live`, `--resolve`) only when the user
  agrees, and only for domains and IPs the user named or that their records reference.
- Never ask for or print passwords, API keys, SMTP credentials or DNS/registrar logins. Scripts
  report credential constant names only; keep it that way when summarising.
- DNS changes, ESP settings, plugin (de)activation and suppression uploads are proposed as exact
  values or commands; the user applies them or explicitly confirms before you run anything.
- Lists, bounce data and reports contain personal data (addresses, IPs). Summarise with counts;
  do not paste full lists into the conversation or send them to third-party services.
- Do not help send unsolicited bulk email; hygiene and warm-up do not replace consent.

## Working on this repository

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python tools/validate_skills.py   # frontmatter, sections, links, marketplace listing
ruff check . && ruff format --check .
pytest
```

- Scripts: Python 3.8+ standard library only, `#!/usr/bin/env python3`, `argparse` with
  `--help`, `--json` where output is structured, exit 0/1/2 (ok / findings / error).
- Every script needs tests in `tests/test_<skill_with_underscores>.py` with fixtures in
  `tests/fixtures/<skill>/`. Use `example.com`/`.example` domains and documentation IPs
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32); never commit real addresses,
  keys or secrets. DKIM test keys are generated at test time (`tests/keys.py`).
- Keep each `SKILL.md` under 400 lines; move detail to `references/`.
- A new skill must be added to `.claude-plugin/marketplace.json` (`plugins[0].skills`), the README
  table, the table above and `CHANGELOG.md`. The validator enforces the manifest.
