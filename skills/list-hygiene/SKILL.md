---
name: list-hygiene
description: Clean an email list CSV offline before sending - flag invalid syntax and reserved domains, duplicates (case-insensitive, optional Gmail dot and +tag folding), role accounts (info@, admin@, sales@, noreply@), disposable/throwaway domains, common domain typos with a suggested fix (gmial.com -> gmail.com), and addresses on a suppression list - then write a clean CSV and a flagged CSV with reasons, keeping all original columns. Use when the user wants to import, clean, dedupe or validate a mailing list or contacts export, asks why a list has a high bounce rate, plans to send to an old or imported list, or needs to apply a suppression file before a campaign.
license: MIT
compatibility: Python 3.8+ standard library. No network: MX checks and paid verification services are out of scope.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# List hygiene

Remove the addresses that cause hard bounces, spam-trap hits and complaints before they cost
sender reputation. Works on a copy; the input file is never modified.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- Importing a contacts CSV into an ESP or CRM
- Before sending to a list that is old, merged from several sources or imported
- After a campaign with a high hard-bounce rate
- Applying suppression (bounces, complaints, unsubscribes) across lists

## When not to use

- Classifying bounces that already happened: `bounce-and-complaint-triage`
- Purchased or scraped lists: do not clean them, do not send to them. Hygiene cannot fix
  missing consent, and these lists contain spam traps that no script detects.
- Real-time signup validation: use double opt-in and the ESP's validation API

## Workflow

1. **Ask about the source.** How were addresses collected, when were they last mailed, is there
   consent (opt-in record)? If the answer is "bought", "scraped" or "never mailed in 2+ years",
   say so plainly and recommend a re-permission campaign instead of a normal send.
2. **Run the checks** (read-only; outputs go to new files):
   ```bash
   python3 scripts/list_hygiene.py contacts.csv
   python3 scripts/list_hygiene.py contacts.csv --gmail-normalize \
       --suppress suppress.csv --clean-out contacts.clean.csv --flagged-out contacts.flagged.csv
   python3 scripts/list_hygiene.py contacts.csv --column "Work Email" --drop-role --json
   ```
   The email column is auto-detected (`--column` to choose). `--disposable-list` adds domains.
   Exit 1 means some rows were flagged.
3. **Decide per flag** (see [references/policy.md](references/policy.md)):
   - `invalid`, `duplicate`, `disposable`, `suppressed`: excluded from the clean file.
   - `typo`: excluded; the flagged file has a `suggestion` column. Do not auto-correct and
     mail the suggestion without consent from that person; offer the corrected addresses to
     the user for review or a confirmation email.
   - `role`: kept by default (B2B lists often need them); `--drop-role` for marketing to
     consumers or when complaint rates are high.
4. **Segment by engagement** if the ESP data allows: send first to people who opened or
   clicked in the last 90 days; treat 6-12 months inactive as a re-engagement segment; sunset
   12+ months inactive.
5. **Report** counts and where the files are. Ask before uploading anything to an ESP.

## Output

```
contacts.csv: 48,210 rows -> 44,905 clean, 3,305 flagged (column "Email Address")
  duplicate   1,912   invalid 604   role 410 (kept)   disposable 221   typo 98   suppressed 60
Files: contacts.clean.csv, contacts.flagged.csv (with flags, reason, suggestion)
Advice: 31% of rows have no activity since 2024 -> send a re-permission email to them first.
```

## Privacy

Lists are personal data. Process locally; never paste full lists into chat or send them to
third-party verification services unless the user decides to. Show counts and a few examples.
