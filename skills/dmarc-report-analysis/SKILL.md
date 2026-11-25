---
name: dmarc-report-analysis
description: Parse DMARC aggregate (RUA) reports - .xml, .xml.gz and .zip attachments from Google, Microsoft, Yahoo and others, including DMARCbis namespaced XML - into a summary of sending sources, message volumes, DMARC pass/fail rates, DKIM and SPF alignment, dispositions and reporters, and label each failing source with a likely cause (unaligned third-party service, own service not aligned, forwarding or mailing list, spoofing). Use when the user has DMARC report emails or attachments, asks "who is sending as my domain", "is it safe to move DMARC to quarantine or reject", "why does DMARC fail", or wants a weekly DMARC summary without a paid tool.
license: MIT
compatibility: Python 3.8+ standard library. Optional reverse DNS with --resolve (network).
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# DMARC aggregate report analysis

Turn a pile of `google.com!example.com!...xml.gz` attachments into a decision: which sources
are legitimate, which need fixing, and whether the domain can move to a stricter policy.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- The user has DMARC aggregate reports (XML, `.gz`, `.zip`) or a folder of them
- "Who is sending email as my domain?", "can I go to p=reject?"
- DMARC failures after adding a CRM, helpdesk, newsletter tool or a new mail server
- A periodic DMARC summary for a team

## When not to use

- Checking the DNS records themselves: `dns-auth-audit`
- One message's headers: `sender-requirements-2024-plus`
- Forensic/failure (ruf) reports: they are individual message samples, read them directly
  and treat them as personal data

## Workflow

1. **Gather reports.** Ask the user to save the attachments into one folder (most mail clients
   can export several at once). Do not ask for mailbox credentials. Two to four weeks of reports
   gives a reliable picture.
2. **Summarise.**
   ```bash
   python3 scripts/dmarc_report.py ~/dmarc/ --domain example.com
   python3 scripts/dmarc_report.py ~/dmarc/ --domain example.com --domain example.net \
       --known-ip 192.0.2.0/24 --json > dmarc-summary.json
   python3 scripts/dmarc_report.py report.zip --max-fail-pct 2   # exit 1 above 2% failures
   ```
   `--domain` lists the user's own domains (labels "own service, not aligned").
   `--known-ip` marks the user's own servers. `--resolve` adds reverse DNS (network; ask first).
   Duplicate reports (same reporter and report ID) are counted once.
3. **Identify each top source.** Use the auth domains (DKIM `d=` and SPF domain), reverse DNS
   and the user's list of tools. Map them with
   [references/interpreting.md](references/interpreting.md). Ask the user to confirm any
   source you cannot name; never guess that an unknown IP is legitimate.
4. **Classify and fix.**
   - Legitimate and passing: nothing to do (note if it passes on SPF only: add aligned DKIM,
     because SPF breaks on forwarding).
   - Legitimate but failing: configure DKIM with `d=` the user's domain at that service, or a
     custom Return-Path / MAIL FROM on a subdomain. Then re-check DNS with `dns-auth-audit`.
   - Forwarding / mailing lists: expected residue; aligned DKIM survives most forwarding.
   - Unknown, unauthenticated: spoofing. This is what `p=reject` blocks.
5. **Policy recommendation.** Ready for the next step when every legitimate source passes,
   the remaining failures are spoofing or forwarding, and this has held for at least two weeks.
   Path: `none` -> `quarantine` (optionally a `pct` ramp) -> `reject`. Write the exact new
   `_dmarc` TXT value for the user to publish.
6. **Report** using the format below. Keep IP lists short; offer the JSON for detail.

## Output

```
DMARC example.com, 2026-11-01 -> 2026-11-28, 41 reports, 182,400 messages
Pass 96.8% (DKIM aligned 95.1%, SPF aligned 90.3%); policy p=none

Legitimate, passing:  Google Workspace (209.85.x), SendGrid (167.89.x)
Legitimate, FAILING:  HubSpot 203.0.113.50 - 3,900 msgs, DKIM d=hubspotemail.net (not aligned)
                      -> enable HubSpot domain authentication (CNAME DKIM for example.com)
Forwarding:           1,200 msgs (mailing lists, university forwarders) - expected
Spoofing:             640 msgs from 12 IPs - will be rejected at p=reject

Recommendation: fix HubSpot, wait 2 weeks, then publish
  _dmarc.example.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

## Privacy and safety

Reports contain IP addresses and volumes, not message content. Process them locally; do not
upload them to third-party services unless the user chooses to. The script refuses XML with
DOCTYPE/ENTITY declarations and decompressed files over 50 MB.
