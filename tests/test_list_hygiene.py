import csv
import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "list-hygiene"
SCRIPT = "list_hygiene.py"
mod = load_script(SKILL, SCRIPT)
DIR = FIXTURES / SKILL
CONTACTS = DIR / "contacts.csv"


def hygiene(*args):
    r = run_script(SKILL, SCRIPT, *args, "--json")
    assert r.returncode in (0, 1), r.stderr
    return r.returncode, json.loads(r.stdout)


def test_contacts_flags_and_outputs(tmp_path):
    clean, flagged = tmp_path / "clean.csv", tmp_path / "flagged.csv"
    original = CONTACTS.read_bytes()
    code, s = hygiene(
        str(CONTACTS),
        "--allow-reserved",
        "--gmail-normalize",
        "--suppress",
        str(DIR / "suppress.csv"),
        "--clean-out",
        str(clean),
        "--flagged-out",
        str(flagged),
    )
    assert code == 1
    assert CONTACTS.read_bytes() == original  # input untouched
    assert s["column"] == "Email Address" and s["rows"] == 14 and s["clean"] == 5
    assert s["flags"] == {
        "invalid": 4,
        "disposable": 2,
        "typo": 1,
        "role": 1,
        "duplicate": 1,
        "suppressed": 1,
    }
    rows = {r["email"]: r for r in s["flagged_rows"]}
    assert rows["cara@gmial.com"]["suggestion"] == "cara@gmail.com"
    assert rows["firstlast@gmail.com"]["reason"] == "duplicate of line 9"
    kept = [r["Email Address"] for r in csv.DictReader(clean.open())]
    assert kept == [
        "ana@example.com",
        "BEN@Example.com",
        "info@example.org",
        "first.last+promo@gmail.com",
        "jo@example.net",
    ]
    frows = list(csv.DictReader(flagged.open()))
    assert frows[0]["flags"] and "suggestion" in frows[0] and frows[0]["First Name"]


def test_drop_role_and_no_gmail_normalize():
    _, s = hygiene(str(CONTACTS), "--allow-reserved", "--drop-role")
    assert s["clean"] == 6  # info@ dropped; firstlast@gmail.com is no longer a duplicate
    assert "duplicate" not in s["flags"]


def test_reserved_domains_rejected_by_default():
    _, s = hygiene(str(CONTACTS))
    assert s["flags"]["invalid"] == 9  # 4 bad syntax + 5 example.* addresses


def test_headerless_file_and_extra_disposable(tmp_path):
    extra = tmp_path / "disp.txt"
    extra.write_text("# custom\nexample.net\n")
    _, s = hygiene(str(DIR / "plain.txt"), "--allow-reserved", "--disposable-list", str(extra))
    assert s["rows"] == 3 and s["flags"] == {"disposable": 2, "invalid": 1}


def test_clean_list_exit_zero(tmp_path):
    f = tmp_path / "ok.csv"
    f.write_text("email\nreader@example.com\nother@example.com\n")
    code, s = hygiene(str(f), "--allow-reserved")
    assert code == 0 and s["flagged"] == 0


@pytest.mark.parametrize(
    "addr,ok",
    [
        ("a@b.co", True),
        ("first.last+tag@sub.domain.io", True),
        ("o'brien@domain.ie", True),
        ("a@b", False),
        ("a@@b.com", False),
        (".a@b.com", False),
        ("a.@b.com", False),
        ("a@-b.com", False),
        ("a@b.c", False),
        ("a@b.123", False),
        ("x" * 65 + "@b.com", False),
        ("a@b.local", False),
        ("a b@c.com", False),
    ],
)
def test_validate_syntax(addr, ok):
    assert (mod.validate_syntax(addr) is None) == ok


def test_normalise():
    assert mod.normalise("F.Irst+x@GoogleMail.com", gmail=True) == "first@gmail.com"
    assert mod.normalise("F.Irst+x@GoogleMail.com") == "f.irst+x@googlemail.com"
    assert mod.normalise("<A@Example.COM>") == "a@example.com"


def test_errors_and_column(tmp_path):
    f = tmp_path / "x.csv"
    f.write_text("name,phone\nA,1\n")
    assert run_script(SKILL, SCRIPT, str(f)).returncode == 2
    f.write_text("name,contact\nA,a@example.com\n")
    assert run_script(SKILL, SCRIPT, str(f), "--column", "contact", "--allow-reserved").returncode == 0
    assert run_script(SKILL, SCRIPT, str(f), "--column", "missing").returncode == 2
    assert run_script(SKILL, SCRIPT, str(tmp_path / "none.csv")).returncode == 2
    r = run_script(SKILL, SCRIPT, str(CONTACTS), "--allow-reserved")
    assert "typo -> cara@gmail.com" in r.stdout
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0


@pytest.mark.parametrize(
    ("a", "b", "dist"),
    [
        ("gmail.com", "gmail.com", 0),
        ("gmaik.com", "gmail.com", 1),
        ("gmali.com", "gmail.com", 1),  # adjacent swap counts as one edit
        ("gmail.cm", "gmail.com", 1),
        ("ggmail.com", "gmail.com", 1),
        ("gmx.com", "gmail.com", 2),
        ("company.com", "gmail.com", 2),
    ],
)
def test_edit_distance(a, b, dist):
    assert mod.edit_distance(a, b) == dist


def test_fuzzy_typo_targets_and_exemptions():
    assert mod.fuzzy_typo("gmaik.com") == "gmail.com"
    assert mod.fuzzy_typo("outlookk.com") == "outlook.com"
    assert mod.fuzzy_typo("yahoo.cm") == "yahoo.com"
    assert mod.fuzzy_typo("comcast.nt") == "comcast.net"
    for real in ("gmail.com", "mail.com", "ymail.com", "yahoo.co.uk", "acme.com", "gmial.com"):
        assert mod.fuzzy_typo(real) is None, real


def test_fuzzy_typos_flag_is_opt_in(tmp_path):
    f = tmp_path / "list.csv"
    f.write_text("email\nzoe@gmaik.com\nyan@hotmial.com\nkai@mail.com\nbo@outlok.cm\n")
    _, plain = hygiene(str(f))
    assert plain["flags"] == {"typo": 1}  # only the built-in map (hotmial.com)
    _, fuzzy = hygiene(str(f), "--fuzzy-typos")
    assert fuzzy["flags"] == {"typo": 2}
    rows = {r["email"]: r for r in fuzzy["flagged_rows"]}
    assert rows["zoe@gmaik.com"]["suggestion"] == "zoe@gmail.com"
    assert "kai@mail.com" not in rows
    assert "bo@outlok.cm" not in rows  # two edits away: not guessed
