import gzip
import json
import shutil
import zipfile

from conftest import FIXTURES, load_script, run_script

SKILL = "dmarc-report-analysis"
SCRIPT = "dmarc_report.py"
mod = load_script(SKILL, SCRIPT)
DIR = FIXTURES / SKILL
GOOGLE = DIR / "google.com!example.com!1795478400!1795564799.xml"
OUTLOOK = DIR / "outlook-dmarcbis.xml"


def summary(*args):
    r = run_script(SKILL, SCRIPT, *args, "--json")
    assert r.returncode in (0, 1), r.stderr
    return r.returncode, json.loads(r.stdout)


def test_two_reports_summary():
    code, s = summary(str(GOOGLE), str(OUTLOOK), "--domain", "example.com", "--domain", "example.net")
    assert code == 0
    assert s["reports"] == 2 and s["messages"] == 2000
    assert s["dmarc_pass"] == 1700 and s["fail_pct"] == 15.0
    assert s["dkim_aligned_pct"] == 70.0 and s["spf_aligned_pct"] == 85.0
    assert s["spf_only_pass_pct"] == 15.0
    assert s["period"]["begin"].startswith("2026-11-24")
    assert s["top_sources"][0]["source_ip"] == "192.0.2.10" and s["top_sources"][0]["messages"] == 1400
    causes = {x["source_ip"]: x["main_cause"] for x in s["failing_sources"]}
    assert causes["203.0.113.50"].startswith("third-party service")
    assert causes["192.0.2.77"].startswith("own service")
    assert causes["2001:db8::25"] == "forwarded / mailing list"
    assert causes["203.0.113.99"].startswith("unauthenticated")
    assert s["by_reporter"]["Outlook.com"]["messages"] == 640
    assert s["policies"]["example.com"]["p"] == "none"


def test_gzip_zip_and_duplicates(tmp_path):
    gz = tmp_path / "google.xml.gz"
    gz.write_bytes(gzip.compress(GOOGLE.read_bytes()))
    zp = tmp_path / "outlook.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.write(OUTLOOK, "report.xml")
        zf.writestr("readme.txt", "ignored")
    shutil.copy(GOOGLE, tmp_path / "dup.xml")  # same org + report_id as the .gz: counted once
    _, s = summary(str(tmp_path))
    assert s["reports"] == 2 and s["messages"] == 2000


def test_known_ips_and_unknown_failing():
    _, s = summary(str(GOOGLE), str(OUTLOOK), "--known-ip", "192.0.2.0/24")
    unknown = [x["source_ip"] for x in s["unknown_failing_sources"]]
    assert "192.0.2.77" not in unknown and "203.0.113.50" in unknown


def test_bad_inputs_are_warnings(tmp_path):
    _, s = summary(str(DIR))
    assert s["reports"] == 2
    assert any("DOCTYPE" in e for e in s["errors"]) and any("expected <feedback>" in e for e in s["errors"])
    (tmp_path / "x.xml").write_text("not xml")
    r = run_script(SKILL, SCRIPT, str(tmp_path / "x.xml"))
    assert r.returncode == 2 and "not valid XML" in r.stderr
    assert run_script(SKILL, SCRIPT, str(tmp_path / "missing.xml")).returncode == 2
    (tmp_path / "broken.gz").write_bytes(b"\x1f\x8b\x08garbage")
    assert run_script(SKILL, SCRIPT, str(tmp_path / "broken.gz")).returncode == 2


def test_size_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(mod, "MAX_BYTES", 100)
    gz = tmp_path / "big.gz"
    gz.write_bytes(gzip.compress(GOOGLE.read_bytes()))
    reports, errors = mod.collect([str(gz)])
    assert not reports and "larger than" in errors[0]


def test_fail_gate_and_text():
    assert run_script(SKILL, SCRIPT, str(GOOGLE), "--max-fail-pct", "5").returncode == 1
    assert run_script(SKILL, SCRIPT, str(GOOGLE), "--max-fail-pct", "50").returncode == 0
    r = run_script(SKILL, SCRIPT, str(GOOGLE), str(OUTLOOK))
    assert "DMARC pass 85.0%" in r.stdout and "Failing sources" in r.stdout and "passes on SPF alone" in r.stdout
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0


def test_classify_dkim_broken_by_forwarder():
    rec = {
        "dkim": "fail",
        "spf": "fail",
        "reasons": [],
        "header_from": "example.com",
        "dkim_results": [{"domain": "example.com", "result": "fail"}],
        "spf_results": [{"domain": "example.com", "result": "fail"}],
    }
    assert mod.classify(rec, set()) == "dkim signature failed"
    rec["spf_results"] = [{"domain": "example.com", "result": "pass"}]
    assert mod.classify(rec, set()) == "forwarded (dkim broken, spf of forwarder)"
