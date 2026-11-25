# WordPress mail setup reference

## How WordPress sends mail

Everything goes through `wp_mail()`, which uses the bundled PHPMailer. Without a mailer plugin,
PHPMailer calls PHP `mail()`, which hands the message to the server's local `sendmail`
(Postfix/Exim). Results: Return-Path `www-data@server-hostname`, no DKIM, the VPS IP not in
SPF, often no PTR. Gmail and Outlook.com reject or spam-folder this.

Mailer plugins hook `phpmailer_init` or replace `wp_mail()`; with two active, the last one
loaded wins and the other's settings silently do nothing.

## Choosing a sending path

| Option | Good for | Watch out for |
| --- | --- | --- |
| Amazon SES (API) | Stores, high volume, lowest cost | Starts in sandbox; request production access; set custom MAIL FROM |
| Postmark | Transactional only, fast, strict on marketing | Separate "broadcast" stream for newsletters |
| SendGrid / Mailgun / Brevo | Mixed transactional + marketing | Shared IPs on low tiers; authenticate the domain |
| Google Workspace SMTP relay or OAuth | Low-volume sites on a Workspace domain | Daily sending limits; prefer OAuth/relay over app passwords |
| Microsoft 365 | Low-volume sites on a 365 domain | Basic SMTP AUTH is being retired; use OAuth or an ESP |
| Host mailbox SMTP | Very small sites | Shared reputation of the host's mail servers |

API connections (HTTPS) avoid SMTP port blocks: many cloud providers block outbound port 25 and
sometimes 465/587 on new accounts.

## Plugin settings that matter

- **From email**: an address on the site's domain (`hello@example.com`), **Force From Email**
  on, so plugins (WooCommerce, forms) cannot override it with the visitor's address.
- **Reply-To**: forms should set Reply-To to the visitor, never From.
- **Return-Path**: set to match From where the plugin offers it (SMTP), or configure the ESP's
  custom bounce domain.
- **Credentials**: prefer wp-config constants (WP Mail SMTP `WPMS_*`, others similar) or the
  plugin's encrypted storage; keep `wp-config.php` at 600/640 and out of git.
- **Logging**: turn on the email log (built into FluentSMTP and Post SMTP; WP Mail SMTP Pro, or
  WP Mail Logging) and keep it for at least a few weeks.

## WP-CLI commands (run by the user)

```bash
wp plugin list --format=json > plugins.json
wp plugin deactivate post-smtp              # only after agreeing which mailer to keep
wp option get admin_email
wp eval 'var_dump( wp_mail( "you@gmail.example", "WP test", "Test body" ) );'
wp cron event list --fields=hook,next_run_relative | head    # queued mail depends on cron
```

`wp_mail()` returning `true` only means PHPMailer handed the message off; check the received
copy's headers, not the return value.

## DNS after choosing a provider

1. Add the provider's DKIM records (often CNAMEs) for the From domain.
2. Add its SPF include if it sends with your domain as Return-Path (custom MAIL FROM).
3. Publish DMARC: `_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"`.
4. Remove the web server from SPF if it no longer sends.
5. Run `dns-auth-audit`, then send a new test to Gmail.

## WooCommerce specifics

- Order emails come from **WooCommerce -> Settings -> Emails** "From" fields; keep them equal to
  the mailer plugin's forced From.
- Large stores: use an API provider and consider a dedicated transactional subdomain
  (`orders.example.com`) separate from marketing mail.
- Action Scheduler and WP-Cron must run for queued emails; with `DISABLE_WP_CRON` add a system
  cron (`*/5 * * * * wp cron event run --due-now --path=/var/www/site`).
