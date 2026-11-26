# email-deliverability-skills

[![CI](https://github.com/saizul/email-deliverability-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/email-deliverability-skills/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/saizul/email-deliverability-skills?sort=semver)](https://github.com/saizul/email-deliverability-skills/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/saizul/email-deliverability-skills?style=social)](https://github.com/saizul/email-deliverability-skills/stargazers)

**Agent Skills that help Claude Code and Codex get your transactional and marketing email into the inbox.**

Eight skills for the jobs every sender hits: SPF/DKIM/DMARC that actually pass, DMARC reports
you can read, bounces sorted into "suppress" vs "fix your reputation", templates that are not
clipped or spam-foldered, clean lists, safe warm-up plans, the Gmail/Yahoo/Outlook.com sender
rules and WordPress mail that stops coming from `wordpress@`. Each skill is a step-by-step
workflow plus a tested, standard-library-only Python script, so the agent works from exact
results instead of guesses.

- **Offline by default.** Scripts read record text, XML reports, `.eml` files, logs and CSVs you
  provide. Network lookups (`dig`, reverse DNS) are opt-in flags.
- **Tested.** 130+ tests with fixtures (sample DMARC XML, DSN bounces, ARF complaints, Postfix logs,
  templates, WordPress setups), run on Python 3.11-3.13 in CI.
- **No dependencies.** Python 3.8+ standard library only.
- **Current rules.** Gmail and Yahoo bulk sender requirements (2024), Outlook.com high-volume
  sender requirements (2025), RFC 8058 one-click unsubscribe, DMARCbis report XML.

## Skills

| Skill | What it does | Try asking |
| --- | --- | --- |
| [dns-auth-audit](skills/dns-auth-audit/SKILL.md) | SPF (recursive 10-lookup count, +all, duplicates), DKIM key size/revocation, DMARC tags and report authorisation, BIMI, MTA-STS vs MX, TLS-RPT; from record text, a JSON export or `--live` dig | "Why does SPF say permerror for example.com?" |
| [dmarc-report-analysis](skills/dmarc-report-analysis/SKILL.md) | Parses aggregate reports (.xml/.gz/.zip) into sources, pass/fail, DKIM/SPF alignment, reporters and a likely cause for every failing source | "Here are a month of DMARC reports. Can we move to p=reject?" |
| [bounce-and-complaint-triage](skills/bounce-and-complaint-triage/SKILL.md) | Classifies DSNs, ARF complaints, mbox, Postfix/Exim logs and ESP CSVs into hard/soft/block/auth/throttle/content/complaint with actions and a suppression CSV | "Our Outlook bounces say S3150. What do we do?" |
| [email-template-lint](skills/email-template-lint/SKILL.md) | Gmail 102 KB clipping, image-only layouts, alt text, risky links, forms/scripts, unsubscribe link, plain-text part, List-Unsubscribe headers | "Lint this newsletter before tomorrow's send" |
| [list-hygiene](skills/list-hygiene/SKILL.md) | Syntax, duplicates (Gmail dot/+tag folding), role accounts, disposable domains, typo domains with suggestions (optional single-edit fuzzy matching), suppression; clean and flagged CSVs | "Clean contacts.csv before I import it into Brevo" |
| [warmup-plan](skills/warmup-plan/SKILL.md) | Day-by-day ramp to a target volume with segments, per-hour rate and provider split, plus a daily advance/hold/step-back gate | "Plan a warm-up for our new dedicated IP to 80k/day" |
| [sender-requirements-2024-plus](skills/sender-requirements-2024-plus/SKILL.md) | Pass/fail checklist from a received message: SPF+DKIM, DMARC, alignment, one-click unsubscribe (and DKIM coverage), TLS, PTR, RFC 5322, spam rate | "Do we meet the Gmail and Yahoo bulk sender rules?" |
| [wordpress-smtp-deliverability](skills/wordpress-smtp-deliverability/SKILL.md) | Detects PHP mail(), wordpress@ sender, conflicting SMTP plugins, disabled email, auth failures; guides one-plugin SMTP/API setup | "WooCommerce order emails go to spam. Fix it." |

## Install

### Claude Code: plugin marketplace (recommended)

```text
/plugin marketplace add saizul/email-deliverability-skills
/plugin install email-deliverability-skills@email-deliverability-skills
```

Or from your shell:

```bash
claude plugin marketplace add saizul/email-deliverability-skills
claude plugin install email-deliverability-skills@email-deliverability-skills
```

Plugin skills are namespaced, e.g. `/email-deliverability-skills:dns-auth-audit`. Claude also
picks them up automatically when your request matches a skill's description. Update later with
`/plugin marketplace update email-deliverability-skills`.

### Claude Code: copy the skills

```bash
git clone https://github.com/saizul/email-deliverability-skills.git
# all projects (personal skills)
mkdir -p ~/.claude/skills && cp -r email-deliverability-skills/skills/* ~/.claude/skills/
# or just one project
mkdir -p .claude/skills && cp -r email-deliverability-skills/skills/dns-auth-audit .claude/skills/
```

Each release also has one zip per skill and an all-skills zip under
[Releases](https://github.com/saizul/email-deliverability-skills/releases).

### Codex CLI

Codex reads skills from `~/.agents/skills` (all repositories) and `.agents/skills` in a
repository (from the current directory up to the repository root):

```bash
git clone https://github.com/saizul/email-deliverability-skills.git
mkdir -p ~/.agents/skills && cp -r email-deliverability-skills/skills/* ~/.agents/skills/
```

Codex also ships a `$skill-installer` skill that can install skills from a GitHub repository;
ask it to install from `saizul/email-deliverability-skills`. Skill locations and the installer
are described in the [Codex skills documentation](https://developers.openai.com/codex/skills);
check it if your Codex version behaves differently. [AGENTS.md](AGENTS.md) explains how Codex
and other agents should use these skills.

### Any other agent

The skills follow the open [Agent Skills format](https://agentskills.io/specification): a folder
with `SKILL.md` (YAML frontmatter + instructions), `scripts/` and `references/`. Point your agent
at the folder, or run the scripts yourself; every script has `--help`.

## Usage examples

```text
> Our newsletters started landing in Gmail spam last week. Domain is example.com.
  (sender-requirements-2024-plus on a received copy -> alignment fails for the ESP ->
   dns-auth-audit proposes the DKIM CNAMEs and an SPF record under 10 lookups.)

> Here is a zip of DMARC reports from Google and Microsoft.
  (dmarc-report-analysis: 97% pass; HubSpot is failing alignment; 600 spoofed messages;
   recommends fixing HubSpot, then p=quarantine in two weeks with the exact TXT record.)

> I attached last campaign's bounces and the contact export.
  (bounce-and-complaint-triage builds the suppression CSV; list-hygiene removes duplicates,
   role and typo addresses before the next import.)
```

Run the scripts directly too:

```bash
python3 skills/dns-auth-audit/scripts/dns_auth_audit.py example.com --live --selector s1
python3 skills/dmarc-report-analysis/scripts/dmarc_report.py ~/dmarc-reports/ --domain example.com
python3 skills/bounce-and-complaint-triage/scripts/bounce_triage.py /var/log/mail.log --suppress-out suppress.csv
python3 skills/email-template-lint/scripts/email_lint.py newsletter.html --json
python3 skills/list-hygiene/scripts/list_hygiene.py contacts.csv --clean-out clean.csv
python3 skills/warmup-plan/scripts/warmup_plan.py --target 50000 --preset standard
python3 skills/sender-requirements-2024-plus/scripts/sender_check.py original.eml --spam-rate 0.08
python3 skills/wordpress-smtp-deliverability/scripts/wp_mail_check.py --plugins plugins.json
```

## How skills work

At startup the agent loads only each skill's `name` and `description` (about 100 tokens each).
When your request matches a description, it reads that skill's `SKILL.md`: the workflow,
decision points and safety rules. Longer material lives in `references/` and is read only when a
step needs it. Scripts run as normal commands, so their output is exact and repeatable.

```
skills/<skill-name>/
  SKILL.md          frontmatter (name, description) + workflow
  scripts/          standalone Python 3 helpers (stdlib only, --help, --json)
  references/       record syntax, code tables, checklists, provider rules
```

## FAQ

**Does anything leave my machine?**
No script sends telemetry or uploads data. Only `dns-auth-audit --live` (DNS queries through
`dig`) and `dmarc_report.py --resolve` (reverse DNS) touch the network, and only when you pass
those flags.

**Will the agent change my DNS, ESP settings or WordPress site?**
The skills tell it not to. Scripts only read; DNS records, plugin changes and suppression uploads
are proposed as exact values or commands for you to apply or approve.

**Can it check whether an address exists?**
No. `list-hygiene` catches what can be known offline (syntax, duplicates, disposable, typos,
roles). SMTP "verification" probes harm your reputation and are deliberately not included.

**Is this legal advice?**
No. The skills point out unsubscribe and consent requirements (CAN-SPAM, GDPR/PECR, CASL) as
deliverability factors; check the law that applies to you.

**The provider rules changed again.**
Each rule in `sender-requirements-2024-plus/references/requirements.md` is dated with sources.
Open an issue or a pull request when a provider updates its page.

## Roadmap

Ideas for new skills (great first contributions; see [CONTRIBUTING.md](CONTRIBUTING.md)):

- `blocklist-check` - opt-in DNSBL lookups for an IP/domain with delisting links
- `tls-rpt-analysis` - summarise SMTP TLS reports (JSON) like the DMARC skill does for XML
- `postmaster-tools-review` - interpret Google Postmaster Tools / SNDS CSV exports
- `arc-and-forwarding` - explain ARC headers and forwarding failures in received messages
- `esp-migration` - checklist and DNS diff for moving between ESPs without losing reputation
- `unsubscribe-endpoint-test` - local test harness for an RFC 8058 one-click endpoint
- `email-header-explain` - turn a raw header block into a hop-by-hop timeline
- `postfix-outbound-review` - lint `main.cf` for a self-hosted sender (TLS, rate limits, DKIM milter)

## Contributing

Contributions are welcome: new checks, new skills, fixes and better docs. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the skill template, the quality bar and how to run the
validator and tests:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python tools/validate_skills.py && ruff check . && ruff format --check . && pytest
```

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and report security issues privately as
described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) (c) Saizul Amin
