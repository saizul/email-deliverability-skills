# Interpreting DMARC aggregate reports

## Report anatomy

```xml
<feedback>
  <report_metadata> org_name, report_id, date_range (Unix seconds, UTC) </report_metadata>
  <policy_published> domain, p, sp, pct, adkim, aspf </policy_published>
  <record>
    <row> source_ip, count, policy_evaluated (disposition, dkim, spf, reason) </row>
    <identifiers> header_from, envelope_from </identifiers>
    <auth_results> dkim (domain, selector, result), spf (domain, result) </auth_results>
  </record>
</feedback>
```

- `policy_evaluated/dkim` and `/spf` already include **alignment**: `pass` there means the
  mechanism passed *and* its domain aligned with `header_from`. A row passes DMARC when either
  is `pass`.
- `auth_results` shows the raw results. `dkim result=pass` with `domain=esp.example.net` while
  `policy_evaluated/dkim=fail` means "signed, but by someone else's domain" (not aligned).
- `disposition` is what the receiver did: `none`, `quarantine`, `reject`. With `p=none` it is
  always `none`.
- `reason` may say `forwarded`, `mailing_list`, `local_policy`, `trusted_forwarder`,
  `sampled_out` (pct) - the receiver overrode the policy.

## Causes the script assigns

| Cause | What it means | Fix |
| --- | --- | --- |
| third-party service authenticating as X | A tool signs with its own domain X | Set up domain authentication at the tool (DKIM `d=` your domain, custom Return-Path) |
| own service, not aligned | Signed by another domain you own (e.g. example.net for example.com) | Sign with the From domain or send From the domain that signs |
| dkim pass but not aligned | Strict `adkim=s` or a subdomain signature | Relax to `adkim=r` or sign with the exact domain |
| forwarded / mailing list | Receiver flagged forwarding | Usually nothing; aligned DKIM survives most forwarders; ARC helps |
| forwarded (dkim broken, spf of forwarder) | Forwarder modified the message | Nothing to fix at the sender beyond DKIM on every message |
| dkim signature failed | Message altered in transit, or wrong key in DNS | Check the selector record; footers added by gateways break signatures |
| unauthenticated | No passing SPF or DKIM at all | Spoofing, or a server you forgot (printer, website, old CRM) |

## Recognising common sources

Look at the authenticated domains and reverse DNS (`--resolve` or `dig -x IP`):

| Hint | Likely source |
| --- | --- |
| `*.google.com`, `d=<yourdomain>` selector `google` | Google Workspace |
| `*.outbound.protection.outlook.com`, selector `selector1`/`selector2` | Microsoft 365 |
| `amazonses.com` | Amazon SES (also many SaaS tools built on it) |
| `sendgrid.net` | SendGrid / Twilio |
| `mailgun.org` | Mailgun |
| `mcsv.net`, `mcdlv.net`, `rsgsv.net` | Mailchimp / Mandrill |
| `sendinblue.com`, `brevo.com` | Brevo |
| `mtasv.net` | Postmark |
| `hubspotemail.net` | HubSpot |
| `zendesk.com`, `freshdesk.com` | Helpdesks |
| reverse DNS of a VPS provider with no auth | A web server sending with PHP mail() |

These hints are starting points: confirm with the user which tools they actually use.

## When is it safe to tighten the policy?

All of these for at least two weeks of reports:

1. Every source the user recognises passes (ideally with aligned DKIM).
2. Remaining failures are unknown IPs without authentication, or forwarding.
3. No large reporter shows a sudden drop in pass rate.

Then move one step: `none` -> `quarantine` -> `reject`. Watch the next week of reports after
each change.
