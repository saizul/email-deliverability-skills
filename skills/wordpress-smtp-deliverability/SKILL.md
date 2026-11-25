---
name: wordpress-smtp-deliverability
description: Fix WordPress email delivery - password resets, WooCommerce order emails and contact-form notifications going to spam or never arriving - by diagnosing a received test message (PHP mail()/sendmail from the web server, default wordpress@ sender, Return-Path on the server hostname, SPF/DKIM/DMARC results), the plugin list from WP-CLI (several SMTP plugins fighting over wp_mail(), no mailer plugin, email-disabling plugins, no mail log) and wp-config.php mail constants (names only, never values), then setting up authenticated SMTP or an ESP API with one mailer plugin. Use when the user says WordPress or WooCommerce emails are not sent, land in spam, come from wordpress@, or asks how to configure WP Mail SMTP, FluentSMTP, Post SMTP, Amazon SES, SendGrid, Mailgun, Brevo or Google Workspace SMTP for WordPress.
license: MIT
compatibility: Python 3.8+ standard library. WP-CLI on the server is helpful (`wp plugin list --format=json`).
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# WordPress SMTP deliverability

WordPress sends with PHP `mail()` by default: no authentication, a server-hostname
Return-Path and a `wordpress@` From. Replace that with one authenticated mailer on the site's
own domain, then prove it with a received test message.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- "WordPress emails go to spam / are not delivered", "WooCommerce order emails missing"
- Contact Form 7 / WPForms / Gravity Forms notifications not arriving
- Choosing and configuring a mailer plugin and an SMTP/API provider

## When not to use

- DNS record repair for the domain: `dns-auth-audit` (this skill hands over to it)
- Newsletter plugins sending bulk marketing (MailPoet, Newsletter): also apply
  `sender-requirements-2024-plus` and `warmup-plan`
- Site hacked and sending spam: treat as an incident first (malware cleanup, password
  rotation), not a deliverability tuning task

## Workflow

1. **Collect evidence (read-only).**
   - A test email received at a Gmail address, downloaded via "Show original" (send one with
     the mail plugin's test feature, or trigger a password reset).
   - `wp plugin list --format=json > plugins.json` (run by the user on the server).
   - Optionally `wp-config.php` (the script reports constant names only, never values).
2. **Diagnose.**
   ```bash
   python3 scripts/wp_mail_check.py --eml reset.eml --plugins plugins.json \
       --wp-config wp-config.php --site-domain example.com
   python3 scripts/wp_mail_check.py --plugins plugins.json --json
   ```
   Exit 1 means high or medium findings.
3. **Pick the sending path** (comparison in
   [references/setup.md](references/setup.md)):
   - Transactional ESP API (Amazon SES, Postmark, SendGrid, Mailgun, Brevo) for stores and
     anything that sends volume; best deliverability and logs.
   - Mailbox SMTP (Google Workspace, Microsoft 365, the host's mailbox) for low-volume sites;
     watch provider sending limits and authentication method support.
   - Never: the web server's own `mail()`/Postfix on a VPS IP without PTR, SPF and DKIM.
4. **Configure one mailer plugin.** Deactivate the others (show the exact `wp plugin deactivate`
   command and ask first). Set From email on the site's domain, enable "force From email",
   set the From name, connect the provider (API key or SMTP credentials entered by the user in
   the plugin or as wp-config constants; never paste them into chat).
5. **Authenticate the domain at the provider**: add the DKIM records and SPF include it gives
   you, set a custom Return-Path/MAIL FROM where offered, publish DMARC. Verify with
   `dns-auth-audit`.
6. **Prove it.** Send a new test to Gmail, re-run the script on the received message: expect
   `spf=pass`, `dkim=pass`, `dmarc=pass`, no PHP mail() finding. Enable the plugin's email log.
7. **Report** what changed, what the user must still do (DNS, credentials), and how to test.

## Output

```
example.com WordPress mail: 3 high, 2 medium
HIGH  sent through PHP mail() on vps123 (Return-Path www-data@vps123.localdomain)
HIGH  WP Mail SMTP and Post SMTP both active -> keep WP Mail SMTP: wp plugin deactivate post-smtp
HIGH  dkim missing, dmarc=fail
MED   From wordpress@example.com -> hello@example.com (force From)
Plan: WP Mail SMTP + Amazon SES API, DKIM CNAMEs + custom MAIL FROM mail.example.com,
      DMARC p=none with rua. Then re-test with a password reset to Gmail.
```

## Safety

The script is read-only and never prints values of constants such as `WPMS_SMTP_PASS`. Do not
ask the user to paste SMTP passwords or API keys into the conversation. Plugin changes on a live
site are shown as commands and run only after the user confirms.
