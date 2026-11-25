# Contributing to email-deliverability-skills

Thank you for helping! New checks, new skills, fixes, redacted real-world fixtures (bounce texts,
DMARC reports, provider error messages) and clearer docs are all welcome.

- [Ways to contribute](#ways-to-contribute)
- [Good first issues](#good-first-issues)
- [Development setup](#development-setup)
- [Repository layout](#repository-layout)
- [Write a new skill](#write-a-new-skill)
- [Quality bar](#quality-bar)
- [Pull request process](#pull-request-process)

## Ways to contribute

| Size | Idea |
| --- | --- |
| 10 minutes | Fix a typo, clarify a workflow step, add a FAQ entry |
| 30 minutes | Add a provider bounce message you saw (redacted) to the classifier tests |
| 1-2 hours | Add a check to an existing script (see below) |
| Half a day | Write a new skill from the template |

Comment on an issue before you start so nobody else picks the same one.

## Good first issues

Each of these is self-contained and touches one script and its test file.

1. **bounce-and-complaint-triage: more provider messages.** Add rules and parametrised tests for
   iCloud, GMX/Web.de, Comcast and Zoho rejection texts you have seen (redacted).
2. **bounce-and-complaint-triage: Exim deferral lines.** Parse `==` deferral lines with
   `R=`/`T=` fields and the `defer (-44)` style codes.
3. **dns-auth-audit: SPF macro awareness.** Report `info` for `%{i}`-style macros and count
   `exists:` with macros correctly.
4. **dns-auth-audit: zone file input.** Accept a BIND zone file (`--zone example.com.zone`) in
   addition to JSON.
5. **dmarc-report-analysis: CSV export.** Add `--csv-out` writing one row per source IP.
6. **dmarc-report-analysis: per-day trend.** Group pass rate by report day for a quick chart.
7. **email-template-lint: preheader check.** Report `info` when the first 90 characters of
   visible text are boilerplate ("View in browser", "Having trouble viewing").
8. **email-template-lint: dark-mode hints.** Flag `color` without `background-color` on the
   same element and transparent PNG logos (info).
9. **list-hygiene: IDN domains.** Accept internationalised domains (punycode them) and add tests.
10. **warmup-plan: per-provider gate.** Let `--metrics` accept per-provider values
    (`gmail.bounce=...`) and decide per provider.
11. **wordpress-smtp-deliverability: more plugins.** Extend the SMTP and logging plugin slugs
    with fixtures from `wp plugin list --format=json`.
12. **New skill: `tls-rpt-analysis`** (see the roadmap in the README).

## Development setup

```bash
git clone https://github.com/saizul/email-deliverability-skills.git
cd email-deliverability-skills
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

python tools/validate_skills.py   # SKILL.md frontmatter, sections, links, marketplace listing
ruff check . && ruff format --check .
pytest
```

No test needs the network. To try your changes in Claude Code, copy a skill to
`~/.claude/skills/` or add your checkout as a local marketplace:

```bash
claude plugin marketplace add ./email-deliverability-skills
claude plugin install email-deliverability-skills@email-deliverability-skills
```

For Codex, copy the skill folder to `~/.agents/skills/`.

## Repository layout

```
.claude-plugin/
  marketplace.json      marketplace + plugin entry listing every skill
  plugin.json           plugin manifest (name, version, author)
skills/<name>/
  SKILL.md              frontmatter + workflow (the part agents read)
  scripts/*.py          standalone helpers, Python 3.8+ stdlib only
  references/*.md       detail loaded on demand
templates/skill/        copy this to start a new skill
tests/
  test_<skill>.py       one test module per skill
  fixtures/<skill>/     inputs for those tests
  keys.py               generates throwaway DKIM keys for tests
tools/validate_skills.py
```

## Write a new skill

1. Open a "New skill proposal" issue first so we can agree on scope.
2. Copy the template:
   ```bash
   cp -r templates/skill skills/my-new-skill
   mv skills/my-new-skill/scripts/your_script.py skills/my-new-skill/scripts/my_check.py
   ```
3. Edit `SKILL.md`:
   - `name` equals the folder name: lowercase letters, digits, single hyphens, max 64 chars.
   - `description` (max 1024 chars) says **what** it does with concrete keywords and **when** to
     use it, starting the second part with "Use when ...". This text decides whether the agent
     picks the skill, so list the phrases and error codes users actually paste.
   - Required sections: `## When to use`, `## When not to use`, `## Workflow`, `## Output`.
   - Workflow steps are imperative and numbered, with exact commands, decision points and the
     point where the agent must ask before changing anything.
   - Keep it under 400 lines; move tables and long references to `references/`.
4. Write the script: `argparse` with a useful `--help`, `--json` output, exit codes 0 (ok) /
   1 (findings) / 2 (error), offline by default (network only behind an explicit flag).
5. Add `tests/test_my_new_skill.py` and fixtures in `tests/fixtures/my-new-skill/`. Cover a "bad"
   input, a "good" input that produces no findings, edge cases and the CLI exit codes.
6. Add the skill to `.claude-plugin/marketplace.json` (`plugins[0].skills`), the README skills
   table, the table in `AGENTS.md` and `CHANGELOG.md` under "Unreleased".
7. Run the validator, ruff and pytest.

## Quality bar

- **Evidence over folklore.** Cite RFCs or provider documentation for every rule; "spam words"
  style advice without evidence is not accepted.
- **Deterministic where it matters.** If a step is "parse this and count X", write a script and
  test it rather than relying on the model reading a 5,000-line XML file.
- **Safe fixtures.** Use `example.com`/`.example` domains, documentation IP ranges and generated
  keys. Redact real bounce texts (addresses, hostnames, IPs).
- **Privacy.** Scripts must not upload data or print secret values.
- **Low false positives.** If a check is often wrong, make it `info` or drop it.

## Pull request process

1. Fork, create a branch, make focused commits.
2. Make sure CI passes locally (validator, ruff, pytest).
3. Fill in the pull request template.
4. A maintainer reviews within a few days. Small, focused pull requests are merged fastest.

By contributing you agree that your contributions are licensed under the MIT License.
