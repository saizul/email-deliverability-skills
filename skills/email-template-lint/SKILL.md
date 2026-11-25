---
name: email-template-lint
description: Lint HTML email templates and .eml messages before sending - Gmail clipping over 102 KB, image-only or image-heavy layouts, missing alt text, base64 and http images, risky links (URL shorteners, raw IP links, javascript:, link text showing a different domain), forms, scripts and iframes, external CSS, missing unsubscribe link, missing plain-text part, List-Unsubscribe and one-click List-Unsubscribe-Post headers, Message-ID/Date, long unencoded lines and dangerous attachments. Use when the user asks to review a newsletter, campaign or transactional template for spam-folder risk, why Gmail shows "[Message clipped]", whether an email will land in spam, or to check an exported .eml before a big send.
license: MIT
compatibility: Python 3.8+ standard library.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Email template lint

Catch the template mistakes that hurt inbox placement or break rendering, with exact fixes,
before the campaign goes out.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- Reviewing an HTML template (newsletter, promo, receipt, password reset) before sending
- "Gmail shows [Message clipped]", "my newsletter goes to spam", "is this email OK?"
- Checking a test send saved as `.eml` (headers + MIME structure + HTML)

## When not to use

- DNS authentication problems: `dns-auth-audit`
- Whether a received message meets Gmail/Yahoo rules end to end: `sender-requirements-2024-plus`
- Visual rendering across clients (Outlook desktop, dark mode): use a rendering preview service;
  this skill checks structure, not pixels

## Workflow

1. **Get the real artefact.** Ask for the final HTML as the ESP will send it (after the
   template engine runs), or better a test message saved as `.eml` ("Show original" ->
   download in Gmail). Ask whether it is `marketing` or `transactional`.
2. **Lint.**
   ```bash
   python3 scripts/email_lint.py newsletter.html
   python3 scripts/email_lint.py test-send.eml --type marketing --json
   python3 scripts/email_lint.py receipt.html --type transactional
   python3 scripts/email_lint.py a.html b.html c.eml          # several at once
   ```
   Exit 1 means high or medium findings.
3. **Fix in priority order** (details and rationale in
   [references/checklist.md](references/checklist.md)):
   - High: clipping, image-only, javascript:/IP/mismatched links, missing unsubscribe
     (marketing), missing one-click headers (marketing), risky attachments.
   - Medium: base64 images, shorteners, scripts, forms and iframes, no plain-text part, missing
     Message-ID/Date, lines over 998 characters.
   - Low/info: alt text, http links, external CSS, title, many link domains.
4. **Propose the edits** as concrete diffs to the template (or settings in the ESP for headers),
   and explain which provider rule each one satisfies. The user applies them.
5. **Re-lint** the new version and a fresh test send; both should exit 0.

## Output

```
newsletter.html (marketing): 118.4 KB HTML, 210 words, 14 images, 31 links
HIGH   HTML 118.4 KB > 102 KB: Gmail clips it (unsubscribe link hidden) -> remove 3 unused <style> blocks, minify
HIGH   link text "www.paypal.com" -> tracking.example.net             -> show your own domain
MEDIUM 2 bit.ly links                                                 -> use the ESP's branded link domain
LOW    6 images without alt
Fixes applied in the diff below; re-run shows 0 high, 0 medium.
```

## Notes

- Spam filters do not count "spam words"; reputation, authentication and engagement matter far
  more. The script checks structure that filters and clients demonstrably penalise.
- Size is measured on the HTML part as sent. ESPs add tracking markup: lint the test send.
