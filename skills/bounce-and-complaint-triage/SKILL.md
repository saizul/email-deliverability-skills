---
name: bounce-and-complaint-triage
description: Classify email bounces and complaints - DSN messages (multipart/report delivery-status), ARF feedback-loop complaints, mbox exports, Postfix and Exim log lines, ESP CSV exports and bare SMTP replies - into hard, soft, block (blocklist/reputation), auth (SPF/DKIM/DMARC/PTR), throttle (rate limited, TSS04, 4.7.28), content and complaint, with counts per recipient domain, a suppression list and the action for each category. Use when the user pastes bounce messages or SMTP errors like "550 5.1.1", "5.7.26 unauthenticated", "421 4.7.0 TSS04", "blocked using Spamhaus", "S3150", asks why emails bounce, which addresses to remove, or why delivery to Gmail, Outlook or Yahoo suddenly fails.
license: MIT
compatibility: Python 3.8+ standard library.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Bounce and complaint triage

Sort delivery failures into what to suppress, what to retry and what signals a reputation or
authentication problem that needs fixing before sending more.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- A batch of bounce emails, a mail log or an ESP bounce export to make sense of
- A single SMTP error the user wants explained ("what does 550 5.7.1 mean?")
- Sudden failures at one provider (Gmail, Microsoft, Yahoo)
- Building a suppression list after a campaign

## When not to use

- Cleaning a list before sending (syntax, duplicates, disposable): `list-hygiene`
- Fixing DNS records after auth bounces: `dns-auth-audit`
- Reputation trends without bounces: read Google Postmaster Tools / Microsoft SNDS data directly

## Workflow

1. **Collect input.** Accept any mix: `.eml` bounce messages, an `.mbox`, a CSV export
   (needs an email column and a response/diagnostic/reason column), mail logs
   (`/var/log/mail.log`, `exim_mainlog`) or pasted SMTP replies. Ask for the number of
   messages sent in the same period if rates matter.
2. **Classify.**
   ```bash
   python3 scripts/bounce_triage.py bounces/ /var/log/mail.log --sent 25000
   python3 scripts/bounce_triage.py export.csv --suppress-out suppress.csv --json
   echo "550 5.7.26 Unauthenticated email is not accepted" | python3 scripts/bounce_triage.py -
   python3 scripts/bounce_triage.py bounces.mbox --items          # every event, one per line
   ```
   Exit 1 when block, auth, throttle, content or complaint events exist.
3. **Act by category** (codes and provider-specific messages in
   [references/codes.md](references/codes.md)):
   - **hard / complaint**: suppress now. Offer the `--suppress-out` CSV for import into the ESP.
     Never re-mail these.
   - **soft**: let the ESP/MTA retry; suppress addresses with 3+ soft bounces over 72 hours
     (listed under "Repeated soft bounces").
   - **auth**: stop and fix SPF/DKIM/DMARC/PTR (switch to `dns-auth-audit`); resend after.
   - **block**: pause the stream to that provider. Check the IP/domain on the blocklist named in
     the message, find the cause (purchased list, spam traps, compromised form, sudden volume),
     fix it, then request delisting through the list's own form.
   - **throttle**: lower the per-provider send rate and keep retrying; do not open more
     connections. Persistent throttling at Yahoo (TSS04) or Gmail (4.7.28) means complaints or
     volume spikes: send to engaged recipients only for a while.
   - **content**: inspect the message with `email-template-lint`; check link domains and URL
     shorteners against blocklists.
   - **unknown**: read the diagnostic; quote it to the user.
4. **Check rates** with `--sent`: hard bounces above ~2% suggest a stale or bought list;
   complaints above 0.1% need attention and 0.3% breaks the Gmail/Yahoo bulk sender limit.
5. **Report** per the output below. Ask before uploading a suppression file to any ESP.

## Output

```
1,240 events from 25,000 sent (bounce 4.9%, hard 2.6%, complaints 0.12%)
hard       650  suppress (file: suppress.csv)
soft       310  retry; 22 addresses with 3+ soft bounces -> suppress
block      180  outlook.com S3150 (IP on Microsoft block list) -> pause Outlook stream, request delist
auth        70  gmail 5.7.26 DMARC -> SPF/DKIM not aligned for news.example.com (run dns-auth-audit)
complaint   30  suppress; most from the "imported 2023 leads" segment
Next: fix DKIM alignment, delist at Microsoft, send only to 90-day engaged for a week.
```

## Privacy

Bounce data contains email addresses. Summarise counts and domains; list individual
addresses only when the user asks or when writing the suppression file.
