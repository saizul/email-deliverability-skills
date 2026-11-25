# Email authentication records: reference

## SPF (RFC 7208)

- One TXT record at the domain used in the envelope sender (Return-Path / MAIL FROM), starting
  with `v=spf1`. Two records = `permerror` = SPF fails everywhere.
- Mechanisms that cost a DNS lookup: `include`, `a`, `mx`, `ptr`, `exists`, and the `redirect=`
  modifier. The total, counted recursively through includes, must be **10 or fewer**.
  `ip4`, `ip6` and `all` are free. More than **2 void lookups** (names with no record) is also
  a `permerror`.
- Qualifiers: `-all` fail, `~all` softfail (the common choice while DMARC is the real policy),
  `?all` neutral (useless), `+all` pass for everyone (never).
- A single TXT string holds 255 characters; longer records are split into several quoted strings
  inside one record (`"v=spf1 ... " "include:... ~all"`). Most DNS UIs do this for you.
- SPF only checks the envelope domain. For DMARC it must also **align** with the From domain
  (same organisational domain in relaxed mode).

Common includes (confirm in the provider's current documentation before publishing):

| Service | SPF | Notes |
| --- | --- | --- |
| Google Workspace | `include:_spf.google.com` | DKIM: Admin console, selector `google` by default |
| Microsoft 365 | `include:spf.protection.outlook.com` | DKIM: two CNAMEs `selector1`/`selector2` |
| Amazon SES | `include:amazonses.com` only with a custom MAIL FROM domain | Easy DKIM: three CNAMEs |
| SendGrid | handled by the CNAMEs of domain authentication | |
| Mailgun | `include:mailgun.org` | |
| Brevo | `include:spf.brevo.com` | |
| Postmark / Mailchimp | not needed on the From domain (they use their own Return-Path) | DKIM CNAMEs/TXT still required |

## DKIM (RFC 6376)

- Published at `<selector>._domainkey.<domain>` as `v=DKIM1; k=rsa; p=<base64 key>` (often a
  CNAME to the provider, which can rotate keys for you).
- `p=` empty means revoked. `t=y` means testing. Use 2048-bit RSA; 1024 is the minimum Gmail
  accepts. Ed25519 (`k=ed25519`) is not verified by every receiver: dual-sign with RSA.
- For DMARC, the signature's `d=` must align with the From domain.

## DMARC (RFC 7489; DMARCbis adds `np=`, `t=`, `psd=` and drops `pct=`)

```
_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
```

| Tag | Meaning |
| --- | --- |
| `p` | policy for the domain: `none`, `quarantine`, `reject` (required) |
| `sp` | policy for subdomains (defaults to `p`) |
| `np` | policy for non-existent subdomains (DMARCbis) |
| `rua` | where aggregate reports go (`mailto:`); you want this |
| `ruf` | failure reports; few providers send them, they may contain personal data |
| `adkim`, `aspf` | `r` relaxed (default) or `s` strict alignment |
| `pct` | percentage the policy applies to (legacy; ramp tool) |
| `fo` | when to generate failure reports (`1` = any mechanism failed) |

Reports sent to another domain need an authorisation record at the destination:
`example.com._report._dmarc.reports.example.net TXT "v=DMARC1"` (DMARC vendors publish
this for you).

### The journey to p=reject

1. `p=none` + `rua`. Collect 2-4 weeks of reports.
2. Identify every legitimate source (`dmarc-report-analysis`); make each one pass with aligned
   DKIM (preferred) or aligned SPF.
3. `p=quarantine` (optionally `pct=25` -> `50` -> `100` over a few weeks).
4. `p=reject` once failures are only spoofing and forwarding.
5. Keep reading reports: new tools (a CRM, a survey app) appear and fail.

Bulk senders to Gmail, Yahoo and Outlook.com need at least `p=none` with alignment;
enforcement (`quarantine`/`reject`) is what actually stops spoofing and is required for BIMI.

## BIMI

```
default._bimi.example.com TXT "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem"
```

- Requires DMARC `p=quarantine` or `p=reject` at 100% (and `sp` not `none`).
- `l=` is an https URL to an SVG Tiny Portable/Secure (SVG Tiny PS) file.
- `a=` is a Verified Mark Certificate (VMC) or Common Mark Certificate (CMC). Gmail and
  Apple Mail show logos only with a certificate; check each provider's current rules.

## MTA-STS (RFC 8461) and TLS-RPT (RFC 8460)

```
_mta-sts.example.com  TXT "v=STSv1; id=20261125"
_smtp._tls.example.com TXT "v=TLSRPTv1; rua=mailto:tls-reports@example.com"
```

Policy at `https://mta-sts.example.com/.well-known/mta-sts.txt` (valid certificate required):

```
version: STSv1
mode: testing
mx: mx1.example.com
mx: *.example.net
max_age: 604800
```

- Every MX host must match an `mx:` line (a `*.` wildcard matches one label), or senders in
  `enforce` mode stop delivering.
- Start with `mode: testing`, read TLS-RPT reports, then switch to `enforce`. Change `id=` in the
  TXT record every time the policy file changes. `max_age` is at most 31557600.

## Null MX (RFC 7505)

`example.com MX 0 .` says the domain receives no mail. Do not send from such a domain: many
receivers reject it (RFC 7505 assigns `5.7.27` "sender address has null MX").
