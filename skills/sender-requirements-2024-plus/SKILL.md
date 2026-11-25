---
name: sender-requirements-2024-plus
description: Check compliance with the Gmail and Yahoo sender requirements (February 2024 onward) and the Outlook.com high-volume sender requirements (2025) from a received message - SPF and DKIM pass, DMARC published, From aligned with SPF or DKIM, one-click unsubscribe (List-Unsubscribe https + List-Unsubscribe-Post) covered by the DKIM signature, TLS, reverse DNS (PTR), RFC 5322 headers, freemail From addresses - plus spam rate under 0.3% (aim under 0.1%) and the 5,000 messages/day bulk threshold, with a pass/fail/warn checklist and fixes. Use when the user asks whether they meet the new Gmail/Yahoo/Microsoft bulk sender rules, sees 5.7.26, 4.7.27, 5.7.515 or 550-5.7.1 rejections, or wants a compliance checklist before a campaign.
license: MIT
compatibility: Python 3.8+ standard library.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Sender requirements 2024+ (Gmail, Yahoo, Outlook.com)

Verify, from evidence in a real received message, that a sender meets the mailbox providers'
published requirements, and produce a checklist with exact fixes.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- "Do we meet Google's and Yahoo's bulk sender requirements?"
- Rejections such as `550-5.7.26` (Gmail, unauthenticated), `550 5.7.515` (Outlook.com,
  authentication level), or rising Gmail spam-folder placement
- A pre-launch checklist for a new ESP, domain or campaign type

## When not to use

- Writing or repairing the DNS records themselves: `dns-auth-audit`
- Template structure and content: `email-template-lint`
- Bounce batches: `bounce-and-complaint-triage`

## Workflow

1. **Get a received copy.** Ask the user to send a real campaign (not a preview) to a Gmail
   account and download it: open the message -> three dots -> "Show original" ->
   "Download Original". Only a received copy has `Authentication-Results` and the receiving
   server's `Received` header. A copy received at Outlook.com or Yahoo also works.
2. **Ask for what headers cannot show:** daily volume to personal Gmail/Yahoo/Outlook
   accounts, the user-reported spam rate from Google Postmaster Tools, and whether the message
   is marketing or transactional.
3. **Run the check.**
   ```bash
   python3 scripts/sender_check.py original.eml --spam-rate 0.08 --daily-volume 20000
   python3 scripts/sender_check.py receipt.eml --type transactional --daily-volume 9000
   python3 scripts/sender_check.py original.eml --dmarc "v=DMARC1; p=none; rua=mailto:d@example.com" --json
   ```
   Without `--daily-volume` bulk rules are applied. Exit 1 means at least one rule failed.
4. **Explain the result per rule** using
   [references/requirements.md](references/requirements.md) (who requires what, since when).
   For `unknown` rules, tell the user how to get the evidence (Postmaster Tools, `dig -x`,
   a real unsubscribe test).
5. **Fix in this order:** authentication and alignment (with `dns-auth-audit`), one-click
   unsubscribe (ESP setting or app code: the https endpoint must accept a POST with
   `List-Unsubscribe=One-Click` and unsubscribe without login), PTR/TLS (host or ESP), spam
   rate (list hygiene, consent, frequency).
6. **Test the unsubscribe path** with the user: unsubscribe from a test address and confirm
   processing within 2 days and no further marketing mail.
7. **Re-check** a fresh received copy; all rules should be `pass` or `n/a`.

## Output

```
example.com marketing, 20,000/day (bulk)
FAIL  alignment: DKIM d=esp-shared.example.net, SPF esp-shared.example.net, From example.com
      -> enable domain authentication at the ESP (DKIM CNAMEs for example.com)
FAIL  one-click: List-Unsubscribe has only mailto:, no List-Unsubscribe-Post
PASS  SPF, DKIM, DMARC record (p=none), TLS, PTR, RFC 5322
WARN  spam rate 0.18% (limit 0.3%, aim < 0.1%)
UNKNOWN unsubscribes processed within 2 days -> test it
```

## Notes

Provider rules change. Facts in the reference are dated; when a provider page says something
newer, follow the provider and update the reference.
