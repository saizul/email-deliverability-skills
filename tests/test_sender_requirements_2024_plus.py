import email
import json
from email import policy

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "sender-requirements-2024-plus"
SCRIPT = "sender_check.py"
mod = load_script(SKILL, SCRIPT)
DIR = FIXTURES / SKILL


def check(*args):
    r = run_script(SKILL, SCRIPT, *args, "--json")
    assert r.returncode in (0, 1), r.stderr
    rep = json.loads(r.stdout)
    return r.returncode, rep, {x["id"]: x["status"] for x in rep["rules"]}


def test_compliant_message():
    code, rep, st = check(str(DIR / "compliant.eml"), "--spam-rate", "0.05", "--daily-volume", "20000")
    assert code == 0
    for rid in (
        "spf",
        "dkim",
        "spf-and-dkim",
        "dmarc-record",
        "alignment",
        "one-click",
        "one-click-signed",
        "tls",
        "ptr",
        "rfc5322",
        "spam-rate",
    ):
        assert st[rid] == "pass", rid
    assert st["unsubscribe-2-days"] == "unknown"
    assert rep["from_domain"] == "example.com" and rep["bulk_assumed"] is False


def test_noncompliant_message():
    code, _, st = check(str(DIR / "noncompliant.eml"), "--spam-rate", "0.4")
    assert code == 1
    assert st["alignment"] == "fail" and st["one-click"] == "fail" and st["tls"] == "fail"
    assert st["ptr"] == "fail" and st["rfc5322"] == "fail" and st["spam-rate"] == "fail"
    assert st["spf"] == "pass" and st["dmarc-record"] == "pass"


def test_small_sender_gets_warnings_not_failures(tmp_path):
    f = tmp_path / "m.eml"
    text = (DIR / "noncompliant.eml").read_text()
    text = text.replace("with SMTP id", "with ESMTPS id").replace(
        "from vps123 (unknown", "from mail.example.com (mail.example.com."
    )
    text = text.replace(
        "Subject: Sale", "Subject: Sale\nDate: Wed, 25 Nov 2026 10:00:00 +0000\nMessage-ID: <1@example.com>"
    )
    f.write_text(text)
    code, _, st = check(str(f), "--daily-volume", "300", "--spam-rate", "0.2")
    assert st["alignment"] == "warn" and st["one-click"] == "warn" and st["spam-rate"] == "warn"
    assert code == 0


def test_transactional_and_dmarc_override():
    _, _, st = check(str(DIR / "noncompliant.eml"), "--type", "transactional", "--dmarc", "v=DMARC1; p=reject")
    assert st["one-click"] == "n/a" and "unsubscribe-2-days" not in st and st["dmarc-record"] == "pass"


def test_unsigned_unsubscribe_headers(tmp_path):
    f = tmp_path / "m.eml"
    f.write_text((DIR / "compliant.eml").read_text().replace("list-unsubscribe:list-unsubscribe-post:", ""))
    _, _, st = check(str(f))
    assert st["one-click-signed"] == "fail"


def test_freemail_from_and_missing_auth(tmp_path):
    f = tmp_path / "m.eml"
    f.write_text("From: someone@gmail.com\nTo: x@example.org\nSubject: hi\n\nbody\n")
    code, _, st = check(str(f))
    assert code == 1 and st["freemail-from"] == "fail" and st["spf"] == "unknown" and st["dkim"] == "fail"
    assert st["tls"] == "unknown" and st["spam-rate"] == "unknown"


def test_parse_auth_results():
    res = mod.parse_auth_results(
        [
            "mx.example; spf=fail smtp.mailfrom=a@x.example; spf=pass smtp.mailfrom=b@y.example; "
            "dkim=pass header.d=y.example; dmarc=pass (p=QUARANTINE) header.from=y.example"
        ]
    )
    assert res["spf"] == ("pass", "y.example") and res["dkim"] == [("pass", "y.example")]
    assert res["dmarc"] == ("pass", "y.example") and res["dmarc_policy"] == "quarantine"


@pytest.mark.parametrize(
    "a,b,ok",
    [
        ("mail.example.com", "example.com", True),
        ("example.co.uk", "news.example.co.uk", True),
        ("esp.example.net", "example.com", False),
        ("", "example.com", False),
    ],
)
def test_aligned(a, b, ok):
    assert mod.aligned(a, b) == ok


def test_text_output_and_errors(tmp_path):
    r = run_script(SKILL, SCRIPT, str(DIR / "noncompliant.eml"))
    assert (
        r.returncode == 1 and "[FAIL   ]" in r.stdout and "fix:" in r.stdout and "bulk-sender rules applied" in r.stdout
    )
    assert run_script(SKILL, SCRIPT, str(tmp_path / "missing.eml")).returncode == 2
    empty = tmp_path / "e.eml"
    empty.write_text("\n\njust a body\n")
    assert run_script(SKILL, SCRIPT, str(empty)).returncode == 2
    msg = email.message_from_bytes((DIR / "compliant.eml").read_bytes(), policy=policy.compat32)
    assert mod.dkim_signatures(msg)[0]["d"] == "example.com"
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
