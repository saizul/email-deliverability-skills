import csv
import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "bounce-and-complaint-triage"
SCRIPT = "bounce_triage.py"
mod = load_script(SKILL, SCRIPT)
DIR = FIXTURES / SKILL


def triage(*args):
    r = run_script(SKILL, SCRIPT, *args, "--json")
    assert r.returncode in (0, 1), r.stderr
    return r.returncode, json.loads(r.stdout)


def by_rcpt(s):
    return {i["recipient"]: i["category"] for i in s["items"]}


def test_whole_fixture_directory(tmp_path):
    out = tmp_path / "suppress.csv"
    code, s = triage(str(DIR), "--suppress-out", str(out), "--sent", "1000")
    assert code == 1
    assert s["total"] == 15
    assert s["categories"] == {
        "hard": 5,
        "soft": 2,
        "throttle": 2,
        "block": 2,
        "unknown": 1,
        "complaint": 1,
        "auth": 1,
        "content": 1,
    }
    assert s["rates"]["hard_pct"] == 0.5 and s["rates"]["complaint_pct"] == 0.1
    rows = list(csv.DictReader(out.open()))
    assert {r["email"] for r in rows} == set(s["suppress"])
    assert {"angry.reader@example.org": "complaint"}.items() <= {r["email"]: r["reason"] for r in rows}.items()
    assert "gone@example.com" in s["suppress"] and "full@example.com" not in s["suppress"]


def test_dsn_messages():
    _, s = triage(str(DIR / "inbox"))
    m = by_rcpt(s)
    assert m["nobody@gmail.example"] == "hard"
    assert m["full@example.net"] == "soft"
    assert m["angry.reader@example.org"] == "complaint"
    assert m["gone.user@legacy-host.example"] == "hard"
    hard = next(i for i in s["items"] if i["recipient"] == "nobody@gmail.example")
    assert hard["status"] == "5.1.1" and "does not exist" in hard["diagnostic"]


def test_postfix_log():
    _, s = triage(str(DIR / "postfix.log"))
    m = by_rcpt(s)
    assert m == {
        "a.user@yahoo.example": "throttle",
        "someone@outlook.example": "block",
        "reader@gmail.example": "auth",
        "x@example.net": "hard",
        "buyer@gmail.example": "content",
        "fast@gmail.example": "throttle",
        "listed@example.org": "block",
    }
    assert "ok@example.net" not in m


def test_csv_export_and_repeat_soft(tmp_path):
    _, s = triage(str(DIR / "esp-export.csv"))
    assert s["categories"]["hard"] == 2 and by_rcpt(s)["full@example.com"] == "soft"
    f = tmp_path / "soft.csv"
    f.write_text("email,reason\n" + "a@example.com,452 4.2.2 mailbox full\n" * 3)
    _, s = triage(str(f))
    assert s["repeat_soft"] == ["a@example.com"]
    bad = tmp_path / "bad.csv"
    bad.write_text("name,value\nx,y\n")
    assert run_script(SKILL, SCRIPT, str(bad)).returncode == 2


def test_mbox_and_stdin(tmp_path):
    mbox = tmp_path / "bounces.mbox"
    parts = []
    for name in ("dsn-hard.eml", "arf-complaint.eml"):
        parts.append("From MAILER-DAEMON Wed Nov 25 10:00:00 2026\n" + (DIR / "inbox" / name).read_text() + "\n")
    mbox.write_text("".join(parts))
    _, s = triage(str(mbox))
    assert set(s["categories"]) == {"hard", "complaint"}
    r = run_script(SKILL, SCRIPT, "-", "--json", stdin="550 5.1.1 <a@example.com>: user unknown\nnoise line\n")
    assert json.loads(r.stdout)["categories"] == {"hard": 1}


@pytest.mark.parametrize(
    "text,cat",
    [
        ("550 5.1.1 The email account that you tried to reach does not exist", "hard"),
        ("550 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP address lookup", "hard"),
        ("553 5.1.2 Host or domain name not found", "hard"),
        ("452 4.2.2 Mailbox full", "soft"),
        ("552 5.2.2 Quota exceeded", "soft"),
        ("450 4.1.1 user unknown (temporary)", "soft"),
        ("421 4.7.0 [TSS04] Messages from 192.0.2.1 temporarily deferred", "throttle"),
        (
            "450 4.2.1 The user you are trying to contact is receiving mail at a rate that prevents additional messages",
            "throttle",
        ),
        ("554 5.7.1 Service unavailable; Client host [192.0.2.1] blocked using zen.spamhaus.org", "block"),
        ("550 5.7.606 Access denied, banned sending IP [192.0.2.1]", "block"),
        ("550 5.7.26 This mail has been blocked because the sender is unauthenticated", "auth"),
        ("550 5.7.25 The IP address sending this message does not have a PTR record setup", "auth"),
        ("550 5.7.515 Access denied, sending domain does not meet the required authentication level", "auth"),
        ("550 5.7.1 Our system has detected that this message is likely unsolicited mail", "content"),
        ("552 5.3.4 Message size exceeds fixed limit", "content"),
        ("554 5.6.0 something unusual", "unknown"),
        ("451 4.3.0 Temporary server error", "soft"),
    ],
)
def test_classify(text, cat):
    assert mod.classify(text, mod.status_code(text)) == cat


def test_exit_codes_and_help(tmp_path):
    hard_only = tmp_path / "h.txt"
    hard_only.write_text("550 5.1.1 <a@example.com> user unknown\n")
    assert run_script(SKILL, SCRIPT, str(hard_only)).returncode == 0
    r = run_script(SKILL, SCRIPT, str(DIR / "postfix.log"), "--items")
    assert r.returncode == 1 and "block" in r.stdout and "Suppress now" in r.stdout
    assert run_script(SKILL, SCRIPT, str(tmp_path / "missing.log")).returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
