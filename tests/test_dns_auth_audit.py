import base64
import json

import pytest

from conftest import FIXTURES, load_script, run_script
from keys import fake_spki_b64

SKILL = "dns-auth-audit"
SCRIPT = "dns_auth_audit.py"
mod = load_script(SKILL, SCRIPT)
GOOD = FIXTURES / SKILL / "good.json"
BAD = FIXTURES / SKILL / "bad.json"
POLICY = FIXTURES / SKILL / "mta-sts.txt"


def audit_json(*args):
    r = run_script(SKILL, SCRIPT, *args, "--json")
    assert r.returncode in (0, 1), r.stderr
    return r.returncode, json.loads(r.stdout)


def titles(report, area=None):
    return [f["title"] for f in report["findings"] if area is None or f["area"].startswith(area)]


def test_good_domain_is_clean():
    code, rep = audit_json("example.com", "--records", str(GOOD), "--mta-sts-policy", str(POLICY))
    assert code == 0, rep["findings"]
    assert rep["counts"] == {"high": 0, "medium": 0, "low": 0, "info": 0}
    assert rep["details"]["spf"]["lookups"] == 2
    assert rep["details"]["dkim"][0]["bits"] == 2048
    assert rep["details"]["mx"] == ["mx1.example.com", "mx2.example.com"]


def test_bad_domain_findings():
    code, rep = audit_json("example.org", "--records", str(BAD))
    assert code == 1
    spf = " | ".join(titles(rep, "spf"))
    assert "2 SPF records" in spf and "+all" in spf and "18 DNS lookups" in spf
    assert "gone.example.net has no SPF record" in spf and "ptr" in spf
    assert "loop" not in spf  # spf4 included twice is not a loop
    dmarc = " | ".join(titles(rep, "dmarc"))
    assert "p=none" in dmarc and "pct=50" in dmarc and "another domain" in dmarc
    dkim = " | ".join(titles(rep, "dkim"))
    assert "1024-bit" in dkim and "t=y" in dkim and "revoked" in dkim
    assert any("https URL to an SVG" in t for t in titles(rep, "bimi"))
    assert any("BIMI needs DMARC" in t for t in titles(rep, "bimi"))
    assert any("id= must be" in t for t in titles(rep, "mta-sts"))


def test_mta_sts_policy_must_cover_mx(tmp_path):
    pol = tmp_path / "p.txt"
    pol.write_text("version: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 3600\n")
    _, rep = audit_json("example.com", "--records", str(GOOD), "--mta-sts-policy", str(pol))
    t = " | ".join(titles(rep, "mta-sts"))
    assert "mx2.example.com is not covered" in t and "testing" in t and "short" in t


def test_inline_records_and_missing():
    code, rep = audit_json("example.net", "--spf", "v=spf1 mx ~all")
    assert code == 0  # only SPF given: the rest is reported as "not checked"
    assert not any("no DMARC record" in t for t in titles(rep))
    code, rep = audit_json("example.net", "--spf", "v=spf1 mx ~all", "--dmarc", "")
    assert any("no DMARC record" in t for t in titles(rep))
    code, rep = audit_json(
        "example.net",
        "--spf",
        "v=spf1 ip4:192.0.2.1",
        "--dmarc",
        "v=DMARC1; p=reject; rua=mailto:d@example.net",
    )
    assert any("no 'all'" in t for t in titles(rep))


@pytest.mark.parametrize(
    "record,expected",
    [
        ("v=spf1 ?all", "'?all'"),
        ("v=spf1 ip4:192.0.2.300 -all", "invalid address"),
        ("v=spf1 ip4:10.0.0.0/8 -all", "very broad"),
        ("v=spf1 foo:bar -all", "unknown mechanism"),
        ("v=spf1 -all ip4:192.0.2.1", "never evaluated"),
        (
            "v=spf1 ip6:2001:db8::/32 ip4:192.0.2.1 " + "ip4:192.0.2.2 " * 20 + "-all",
            "one TXT string holds 255",
        ),
    ],
)
def test_spf_rules(record, expected):
    _, rep = audit_json("example.net", "--spf", record)
    assert any(expected in t for t in titles(rep, "spf")), titles(rep)


@pytest.mark.parametrize(
    "record,expected",
    [
        ("v=DMARC1; p=maybe", "invalid or missing p="),
        ("v=DMARC1; p=reject; sp=none; rua=mailto:a@example.net", "sp=none"),
        ("v=DMARC1; p=reject; adkim=x; rua=mailto:a@example.net", "invalid adkim"),
        ("v=DMARC1; p=reject; pct=abc; rua=mailto:a@example.net", "invalid pct"),
        ("v=DMARC1; p=reject; rua=a@example.net", "invalid report URI"),
        ("v=DMARC1; p=reject; rua=mailto:a@example.net; foo=1", "unknown tag"),
        ("v=DMARC1; p=quarantine", "no rua="),
    ],
)
def test_dmarc_rules(record, expected):
    _, rep = audit_json("example.net", "--dmarc", record)
    assert any(expected in t for t in titles(rep, "dmarc")), titles(rep)


def test_dkim_key_sizes_and_formats():
    for bits, word in ((512, "512-bit"), (1024, "1024-bit")):
        _, rep = audit_json("example.net", "--dkim", f"s=v=DKIM1; k=rsa; p={fake_spki_b64(bits)}")
        assert any(word in t for t in titles(rep, "dkim")), titles(rep)
    assert mod.rsa_key_bits(base64.b64decode(fake_spki_b64(2048, pkcs1=True))) == 2048
    assert mod.rsa_key_bits(b"\x30\x03\x02\x01\x00") is None
    _, rep = audit_json("example.net", "--dkim", "s=v=DKIM1; p=!!notbase64")
    assert any("not valid base64" in t for t in titles(rep, "dkim"))
    _, rep = audit_json("example.net", "--dkim", "s=v=DKIM1; p=AAAA")
    assert any("not a valid RSA" in t for t in titles(rep, "dkim"))
    _, rep = audit_json("example.net", "--dkim", "s=v=DKIM1; k=ed25519; p=" + "A" * 44)
    assert any("ed25519" in t for t in titles(rep, "dkim"))
    _, rep = audit_json("example.net", "--dkim", "s=v=DKIM2; p=" + fake_spki_b64(2048))
    assert any("must be DKIM1" in t for t in titles(rep, "dkim"))


def test_dig_style_chunks_are_joined():
    assert mod._join_txt('"v=spf1 include:a.example " "-all"') == "v=spf1 include:a.example -all"
    assert mod._join_txt("plain") == "plain"


def test_live_lookup_uses_dig(monkeypatch):
    calls = []

    def fake_dig(name, rtype, timeout=5):
        calls.append((name, rtype))
        return {"example.net": ["v=spf1 -all"]}.get(name, []) if rtype == "TXT" else []

    monkeypatch.setattr(mod, "dig", fake_dig)
    rep = mod.audit("example.net", mod.Records(live=True))
    assert ("example.net", "TXT") in calls and ("_dmarc.example.net", "TXT") in calls
    assert any("no DMARC" in f["title"] for f in rep["findings"])


def test_subdomain_inherits_org_dmarc():
    recs = mod.Records(
        {
            "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"]},
            "news.example.com": {"TXT": ["v=spf1 -all"]},
            "_dmarc.news.example.com": {"TXT": []},
        }
    )
    rep = mod.audit("news.example.com", recs)
    assert any("inherits DMARC" in f["title"] for f in rep["findings"])
    assert rep["details"]["dmarc"]["tags"]["p"] == "quarantine"


def test_null_mx_and_no_mx():
    _, rep = audit_json("example.net", "--spf", "v=spf1 -all", "--mx", "0 .")
    assert any("null MX" in t for t in titles(rep, "mx"))


def test_text_output_and_errors(tmp_path):
    r = run_script(SKILL, SCRIPT, "example.com", "--records", str(GOOD))
    assert r.returncode == 0 and "SPF:" in r.stdout and "[2/10 lookups]" in r.stdout
    assert run_script(SKILL, SCRIPT, "example.com").returncode == 2
    assert run_script(SKILL, SCRIPT, "example.com", "--records", str(tmp_path / "none.json")).returncode == 2
    bad = tmp_path / "bad.json"
    bad.write_text('[{"x": 1}]')
    assert run_script(SKILL, SCRIPT, "example.com", "--records", str(bad)).returncode == 2
    assert run_script(SKILL, SCRIPT, "example.com", "--dkim", "novalue").returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
