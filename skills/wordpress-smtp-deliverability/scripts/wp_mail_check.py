#!/usr/bin/env python3
"""Diagnose WordPress email delivery from a test message, the plugin list and wp-config.php.

Inputs (any combination, all read-only):
  --eml FILE         a WordPress email as received (Gmail "Show original" -> download),
                     e.g. a password reset or a contact-form notification
  --plugins FILE     output of: wp plugin list --format=json
  --wp-config FILE   wp-config.php (only constant NAMES are reported, never values)
  --site-domain D    the site's domain, to check the From and Return-Path domains

Finds: PHP mail()/sendmail instead of authenticated SMTP or an API, the default
wordpress@ sender, Return-Path on the server hostname, SPF/DKIM/DMARC failures, several
SMTP plugins fighting over wp_mail(), no SMTP plugin at all, plugins that disable email,
and missing mail logging.

Exit codes: 0 = no high/medium findings, 1 = findings, 2 = input error.
"""

from __future__ import annotations

import argparse
import email
import json
import re
import sys
from email import policy
from email.utils import getaddresses

SEVERITIES = ("high", "medium", "low", "info")
SMTP_PLUGINS = {
    "wp-mail-smtp": "WP Mail SMTP",
    "wp-mail-smtp-pro": "WP Mail SMTP Pro",
    "post-smtp": "Post SMTP",
    "fluent-smtp": "FluentSMTP",
    "easy-wp-smtp": "Easy WP SMTP",
    "smtp-mailer": "SMTP Mailer",
    "gmail-smtp": "Gmail SMTP",
    "wp-ses": "WP Offload SES",
    "mailgun": "Mailgun",
    "sendgrid-email-delivery-simplified": "SendGrid",
    "suremails": "SureMail",
    "brevo-smtp": "Brevo",
    "postmark-approved-wordpress-plugin": "Postmark",
    "wp-smtp": "WP SMTP",
    "site-mailer": "Site Mailer",
}
DISABLE_PLUGINS = {"disable-emails", "stop-emails", "disable-wordpress-emails", "wp-mail-catcher-disable"}
LOG_PLUGINS = {"wp-mail-logging", "email-log", "wp-mail-catcher", "check-email"}
SECRET_NAME_RE = re.compile(r"PASS|SECRET|API_KEY|APIKEY|TOKEN", re.I)


def finding(sev: str, area: str, title: str, fix: str = "") -> dict:
    return {"severity": sev, "area": area, "title": title, "fix": fix}


def org_domain(domain: str) -> str:
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "ac", "gov", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def check_plugins(data: list[dict]) -> tuple[list[dict], dict]:
    out: list[dict] = []
    active = {p.get("name", ""): p for p in data if str(p.get("status", "")).startswith("active")}
    smtp = [n for n in active if n in SMTP_PLUGINS]
    info = {"active_smtp_plugins": smtp, "active_plugins": len(active)}
    if len(smtp) > 1:
        out.append(
            finding(
                "high",
                "plugins",
                "several mail plugins active: " + ", ".join(SMTP_PLUGINS[n] for n in smtp),
                "keep one; each replaces wp_mail()/PHPMailer and the last one loaded wins unpredictably",
            )
        )
    elif not smtp:
        out.append(
            finding(
                "medium",
                "plugins",
                "no SMTP/API mail plugin active: WordPress sends with PHP mail() from the web server",
                "install one mailer plugin (e.g. WP Mail SMTP or FluentSMTP) connected to your ESP or mailbox SMTP",
            )
        )
    for name in active:
        if name in DISABLE_PLUGINS:
            out.append(finding("high", "plugins", f"'{name}' is active: it blocks outgoing email", "deactivate it"))
    if not any(n in LOG_PLUGINS for n in active) and not any(
        n in ("wp-mail-smtp-pro", "post-smtp", "fluent-smtp") for n in smtp
    ):
        out.append(
            finding(
                "low",
                "plugins",
                "no email log",
                "enable logging in your mail plugin or add WP Mail Logging, to see what WordPress tried to send",
            )
        )
    return out, info


def check_wp_config(text: str) -> tuple[list[dict], dict]:
    out: list[dict] = []
    consts = dict(re.findall(r"define\s*\(\s*['\"]([A-Z0-9_]+)['\"]\s*,\s*([^)]*)\)", text))
    mail_consts = sorted(n for n in consts if re.search(r"SMTP|WPMS_|MAIL|SES_|SENDGRID|MAILGUN|POSTMARK|BREVO", n))
    secrets = [n for n in mail_consts if SECRET_NAME_RE.search(n)]
    info = {"mail_constants": mail_consts, "secret_constants": secrets}
    if secrets:
        out.append(
            finding(
                "info",
                "wp-config",
                f"mail credentials defined as constants ({', '.join(secrets)}): good, kept out of the database",
                "keep wp-config.php at mode 600/640, outside version control; values are not shown",
            )
        )
    if consts.get("WPMS_ON", "").strip().lower() == "true" and "WPMS_MAILER" not in consts:
        out.append(finding("low", "wp-config", "WPMS_ON is true but WPMS_MAILER is not set", "define WPMS_MAILER"))
    if consts.get("DISABLE_WP_CRON", "").strip().lower() == "true":
        out.append(
            finding(
                "info",
                "wp-config",
                "DISABLE_WP_CRON is true: queued and scheduled emails need a real cron job",
                "*/5 * * * * wp cron event run --due-now --path=/var/www/site",
            )
        )
    return out, info


def check_eml(raw: bytes, site_domain: str | None) -> tuple[list[dict], dict]:
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    out: list[dict] = []
    froms = getaddresses(msg.get_all("From") or [])
    from_addr = froms[0][1].lower() if froms else ""
    from_dom = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else ""
    rp = getaddresses([str(msg.get("Return-Path") or "")])
    rp_addr = rp[0][1].lower() if rp else ""
    rp_dom = rp_addr.rsplit("@", 1)[-1] if "@" in rp_addr else ""
    ar = " ".join(" ".join(str(v).split()) for v in msg.get_all("Authentication-Results") or [])
    received = [" ".join(str(r).split()) for r in msg.get_all("Received") or []]
    mailer = str(msg.get("X-Mailer") or "")
    info = {"from": from_addr, "return_path": rp_addr, "x_mailer": mailer}

    if from_addr.startswith("wordpress@"):
        out.append(
            finding(
                "medium",
                "sender",
                f"default sender {from_addr}",
                "set a real From on your domain (e.g. no-reply@ or hello@) in the mail plugin and force it",
            )
        )
    if site_domain and from_dom and org_domain(from_dom) != org_domain(site_domain):
        out.append(
            finding(
                "high" if from_dom.endswith(("gmail.com", "yahoo.com", "outlook.com", "hotmail.com")) else "low",
                "sender",
                f"From domain {from_dom} is not the site domain {site_domain}",
                "send from your own domain; free-mail From addresses fail DMARC through other servers",
            )
        )
    php_mail = bool(msg.get("X-PHP-Originating-Script")) or any(
        re.search(
            r"from userid \d+|by \S+ \(Postfix, from userid|with local|"
            r"\(Exim [\d.]+\)\s*\(envelope-from <(?:www-data|apache|nginx)",
            r,
            re.I,
        )
        for r in received
    )
    if php_mail or re.match(
        r"^(www-data|apache|nginx|nobody|daemon|[a-z0-9_]+)@[a-z0-9-]+\.(?:localdomain|local|vps|server|host)",
        rp_addr,
    ):
        out.append(
            finding(
                "high",
                "transport",
                "sent through PHP mail()/local sendmail on the web server",
                "route wp_mail() through authenticated SMTP or your ESP's API with a mail plugin",
            )
        )
    if rp_dom and from_dom and org_domain(rp_dom) != org_domain(from_dom):
        out.append(
            finding(
                "medium" if not re.search(r"dkim=pass", ar, re.I) else "low",
                "alignment",
                f"Return-Path {rp_addr} is not on the From domain",
                "fine if DKIM aligns; otherwise set a custom Return-Path/bounce domain at your ESP",
            )
        )
    if ar:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", ar, re.I)
            res = m.group(1).lower() if m else "missing"
            info[mech] = res
            if res != "pass":
                fix = {
                    "spf": "add the mail plugin's SMTP/ESP include to the SPF record (see dns-auth-audit)",
                    "dkim": "enable DKIM for your domain at the ESP and publish its key",
                    "dmarc": "publish DMARC and make SPF or DKIM align with the From domain",
                }[mech]
                out.append(
                    finding("high" if mech != "spf" or res == "fail" else "medium", "auth", f"{mech}={res}", fix)
                )
    else:
        out.append(
            finding(
                "info",
                "auth",
                "no Authentication-Results header",
                "send the test to a Gmail/Outlook mailbox and download the original from there",
            )
        )
    if not msg.get("Message-ID"):
        out.append(finding("medium", "format", "missing Message-ID", "use a mail plugin; raw mail() often omits it"))
    return out, info


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Diagnose WordPress email delivery (test message, plugin list, wp-config.php).",
        epilog="Example: wp_mail_check.py --eml reset.eml --plugins plugins.json --site-domain example.com",
    )
    p.add_argument("--eml", help="a received WordPress email (.eml)")
    p.add_argument("--plugins", help="JSON from: wp plugin list --format=json")
    p.add_argument("--wp-config", help="path to wp-config.php (names only are reported)")
    p.add_argument("--site-domain", help="site domain, e.g. example.com")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)
    if not (args.eml or args.plugins or args.wp_config):
        p.error("give at least one of --eml, --plugins, --wp-config")
    findings: list[dict] = []
    details: dict = {}
    try:
        if args.plugins:
            with open(args.plugins, encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, list):
                raise ValueError("--plugins must be the JSON list from 'wp plugin list --format=json'")
            f, details["plugins"] = check_plugins(data)
            findings += f
        if args.wp_config:
            with open(args.wp_config, encoding="utf-8", errors="replace") as fh:
                f, details["wp_config"] = check_wp_config(fh.read())
            findings += f
        if args.eml:
            with open(args.eml, "rb") as fh:
                f, details["message"] = check_eml(fh.read(), args.site_domain)
            findings += f
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    report = {"findings": findings, "counts": counts, "details": details}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for f in findings:
            fix = f"  -> {f['fix']}" if f["fix"] else ""
            print(f"[{f['severity'].upper():6}] {f['area']}: {f['title']}{fix}")
        print(f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low, {counts['info']} info")
    return 1 if counts["high"] or counts["medium"] else 0


if __name__ == "__main__":
    sys.exit(main())
