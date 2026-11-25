---
name: dns-auth-audit
description: Audit a sending domain's email authentication DNS records - SPF (syntax, +all/?all, ptr, recursive DNS lookup count against the 10-lookup limit, void lookups, duplicate records), DKIM (key present, revoked, test mode, RSA key size), DMARC (policy, pct, sp, alignment tags, rua/ruf and external report authorisation), BIMI, MTA-STS policy vs MX and TLS-RPT - offline from record text or a JSON export, or live with dig. Use when the user asks to check or fix SPF, DKIM or DMARC, sees "SPF permerror", "too many DNS lookups", "DMARC fail", "dkim=neutral", wants to add a new ESP (Google Workspace, Microsoft 365, SendGrid, Mailgun, Amazon SES, Brevo, Postmark) to SPF, or wants to move DMARC from p=none to p=reject.
license: MIT
compatibility: Python 3.8+ standard library. Optional `dig` (dnsutils / bind-utils) for --live lookups.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# DNS authentication audit (SPF, DKIM, DMARC, BIMI, MTA-STS)

Find out exactly why a domain's mail fails authentication and produce the corrected DNS
records. The script only reads; DNS changes are proposed for the user to apply.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- "Check my SPF/DKIM/DMARC", "is my domain set up for Gmail and Yahoo?"
- `spf=permerror`, "too many DNS lookups", `dkim=fail`/`neutral`, `dmarc=fail` in headers
- Adding an ESP or Microsoft 365 / Google Workspace to an existing SPF record
- Planning the DMARC journey from `p=none` to `p=quarantine` / `p=reject`
- Setting up BIMI, MTA-STS or TLS-RPT

## When not to use

- Reading DMARC aggregate (rua) XML reports: use `dmarc-report-analysis`
- A single message failing in one mailbox: start with `sender-requirements-2024-plus`
  on the received headers, then come back here for the records
- Registrar or DNS host UI questions unrelated to email

## Workflow

1. **Collect the facts.** Ask for: the visible From domain, every service that sends as it
   (ESP, CRM, helpdesk, Workspace/365, the web server), and one DKIM selector per service
   (the `s=` tag in a received message's `DKIM-Signature`).
2. **Get the records.** Prefer data the user can paste or export:
   - Paste values: `--spf`, `--dmarc`, `--dkim SELECTOR=VALUE`, `--bimi`, `--mta-sts`,
     `--tlsrpt`, `--mx`.
   - A JSON export (`{"name": {"TXT": [...], "MX": [...]}}` or a list of
     `{"name","type","value"}`); add the TXT records of included SPF domains for an exact
     lookup count.
   - Or, if the user agrees to network lookups, `--live` (uses `dig`).
3. **Run the audit.**
   ```bash
   python3 scripts/dns_auth_audit.py example.com --records dns.json --selector s1
   python3 scripts/dns_auth_audit.py example.com --live --selector google --selector s1 \
       --mta-sts-policy mta-sts.txt
   python3 scripts/dns_auth_audit.py example.com --spf "v=spf1 include:_spf.google.com ~all" \
       --dmarc "v=DMARC1; p=none" --json
   ```
   Exit 1 means high or medium findings.
4. **Fix SPF first** (it breaks hardest):
   - One record only; merge duplicates.
   - Over 10 lookups: remove includes for services no longer used, replace `a`/`mx` with
     `ip4:`/`ip6:`, move a bulk ESP to its own subdomain (`news.example.com`) with its own
     SPF and DKIM. Flattening to IPs is a last resort: ESP IPs change without notice.
   - End with `~all` (or `-all` once DMARC enforces); never `+all` or `?all`.
5. **DKIM**: every sending service signs with `d=` your domain (or a subdomain). 2048-bit
   RSA where the provider allows it; 1024 is the minimum. Remove `t=y` after testing.
6. **DMARC journey** (details in [references/records.md](references/records.md)):
   `p=none` with `rua` -> read reports with `dmarc-report-analysis` for 2-4 weeks -> fix
   every legitimate source -> `p=quarantine` (optionally `pct=` ramp) -> `p=reject`.
   Do not jump to reject while legitimate sources still fail.
7. **Optional hardening**: MTA-STS + TLS-RPT for inbound TLS; BIMI only after DMARC is at
   quarantine/reject with pct=100.
8. **Write the corrected records** as exact name / type / value lines, and say which DNS
   host field each goes in. Ask the user to apply them; re-run the audit after TTL expiry.

## Output

```
example.org - 3 high, 2 medium
HIGH  SPF: 14 lookups (limit 10)  -> drop include:old-esp.example.net, replace mx with ip4:192.0.2.10
HIGH  SPF: two v=spf1 records     -> merge into one
MED   DMARC p=none                -> keep for 2 weeks of reports, then p=quarantine
Corrected records:
  example.org        TXT  "v=spf1 ip4:192.0.2.10 include:_spf.google.com include:sendgrid.net ~all"
  _dmarc.example.org TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.org; fo=1"
Next: apply, wait for TTL, re-run; revisit DMARC policy on <date>.
```

## Safety

Read-only. `--live` only queries the domain the user named and the domains its SPF record
includes. Never ask for DNS host or registrar credentials; the user applies changes.
