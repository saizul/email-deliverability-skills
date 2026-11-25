import json

from conftest import FIXTURES, load_script, run_script

SKILL = "wordpress-smtp-deliverability"
SCRIPT = "wp_mail_check.py"
mod = load_script(SKILL, SCRIPT)
DIR = FIXTURES / SKILL


def wp(*args):
    r = run_script(SKILL, SCRIPT, *args, "--json")
    assert r.returncode in (0, 1), r.stderr
    return r.returncode, json.loads(r.stdout), r.stdout


def titles(rep):
    return " | ".join(f["title"] for f in rep["findings"])


def test_php_mail_setup():
    code, rep, raw = wp(
        "--eml",
        str(DIR / "php-mail.eml"),
        "--plugins",
        str(DIR / "plugins-conflict.json"),
        "--wp-config",
        str(DIR / "wp-config.php"),
        "--site-domain",
        "example.com",
    )
    assert code == 1
    t = titles(rep)
    for expected in (
        "several mail plugins active: WP Mail SMTP, Post SMTP",
        "'disable-emails' is active",
        "PHP mail()",
        "dkim=missing",
        "dmarc=fail",
        "spf=softfail",
        "default sender",
        "missing Message-ID",
        "WPMS_MAILER",
        "DISABLE_WP_CRON",
        "WPMS_SMTP_PASS",
    ):
        assert expected in t, expected
    assert "FIXTURE-NOT-A-REAL-VALUE" not in raw  # secret values are never printed
    assert rep["details"]["wp_config"]["secret_constants"] == ["WPMS_SMTP_PASS"]


def test_good_setup_is_clean():
    code, rep, _ = wp(
        "--eml",
        str(DIR / "smtp.eml"),
        "--plugins",
        str(DIR / "plugins-good.json"),
        "--site-domain",
        "example.com",
    )
    assert code == 0 and rep["findings"] == []
    assert rep["details"]["plugins"]["active_smtp_plugins"] == ["fluent-smtp"]
    assert rep["details"]["message"]["dkim"] == "pass"


def test_no_mail_plugin(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps([{"name": "akismet", "status": "active"}, {"name": "wp-mail-smtp", "status": "inactive"}]))
    code, rep, _ = wp("--plugins", str(f))
    assert code == 1 and "no SMTP/API mail plugin" in titles(rep) and "no email log" in titles(rep)


def test_freemail_from_domain(tmp_path):
    f = tmp_path / "m.eml"
    f.write_text((DIR / "smtp.eml").read_text().replace("hello@example.com", "owner.site@gmail.com"))
    _, rep, _ = wp("--eml", str(f), "--site-domain", "example.com")
    high = [x for x in rep["findings"] if x["severity"] == "high"]
    assert any("not the site domain" in x["title"] for x in high)


def test_errors_and_text(tmp_path):
    assert run_script(SKILL, SCRIPT).returncode == 2
    assert run_script(SKILL, SCRIPT, "--plugins", str(tmp_path / "none.json")).returncode == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"name": "x"}')
    assert run_script(SKILL, SCRIPT, "--plugins", str(bad)).returncode == 2
    r = run_script(SKILL, SCRIPT, "--plugins", str(DIR / "plugins-conflict.json"))
    assert r.returncode == 1 and "[HIGH  ] plugins" in r.stdout
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0


def test_org_domain():
    assert mod.org_domain("mail.example.co.uk") == "example.co.uk"
    assert mod.org_domain("a.b.example.com") == "example.com"
