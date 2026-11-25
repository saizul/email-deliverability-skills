import json

from conftest import FIXTURES, load_script, run_script

SKILL = "email-template-lint"
SCRIPT = "email_lint.py"
mod = load_script(SKILL, SCRIPT)
DIR = FIXTURES / SKILL


def lint(*args):
    r = run_script(SKILL, SCRIPT, *args, "--json")
    assert r.returncode in (0, 1), r.stderr
    return r.returncode, json.loads(r.stdout)


def titles(rep):
    return " | ".join(f["title"] for f in rep["findings"])


def test_good_html_and_eml_are_clean():
    for name in ("good.html", "good.eml"):
        code, rep = lint(str(DIR / name))
        assert code == 0, rep["findings"]
        assert rep["counts"]["high"] == rep["counts"]["medium"] == 0
    _, rep = lint(str(DIR / "good.html"))
    assert rep["stats"]["tracking_pixels"] == 1 and rep["stats"]["images"] == 1
    assert rep["stats"]["unsubscribe_links"] == 2


def test_bad_html():
    code, rep = lint(str(DIR / "bad.html"))
    assert code == 1
    t = titles(rep)
    for expected in (
        "image-only",
        "javascript:",
        "raw IP",
        "different domain",
        "no visible unsubscribe",
        "base64",
        "shortener",
        "<script>",
        "<form>",
        "without alt",
        "external stylesheet",
        "empty or '#'",
    ):
        assert expected in t, expected


def test_gmail_clipping(tmp_path):
    html = (DIR / "good.html").read_text()
    big = tmp_path / "big.html"
    big.write_text(html.replace("</body>", "<p>" + "lorem ipsum dolor " * 7000 + "</p></body>"))
    _, rep = lint(str(big))
    assert "Gmail clips" in titles(rep)
    near = tmp_path / "near.html"
    near.write_text(html.replace("</body>", "<!--" + "x" * (95 * 1024) + "--></body>"))
    _, rep = lint(str(near))
    assert "close to Gmail" in titles(rep)


def test_image_heavy_medium(tmp_path):
    words = " ".join(["word"] * 60)
    f = tmp_path / "heavy.html"
    imgs = "".join(f'<img src="https://cdn.example.com/{i}.png" alt="x">' for i in range(3))
    f.write_text(
        f"<html><body>{imgs}<p>{words}</p><a href='https://example.com/unsubscribe'>Unsubscribe</a></body></html>"
    )
    _, rep = lint(str(f))
    assert "image-heavy" in titles(rep)


def test_bad_eml():
    code, rep = lint(str(DIR / "bad.eml"))
    assert code == 1 and rep["input"] == "eml"
    t = titles(rep)
    for expected in (
        "List-Unsubscribe-Post",
        "risky attachment(s): invoice.exe",
        "missing Date",
        "missing Message-ID",
        "angle brackets",
        "no https URL",
        "no text/plain alternative",
        "shouty subject",
    ):
        assert expected in t, expected


def test_transactional_relaxes_unsubscribe(tmp_path):
    f = tmp_path / "receipt.html"
    f.write_text(
        "<html><head><title>Receipt</title></head><body><p>" + "Thanks for your order. " * 10 + "</p></body></html>"
    )
    code, rep = lint(str(f), "--type", "transactional")
    assert code == 0 and "fine for purely transactional" in titles(rep)
    code, rep = lint(str(f))
    assert code == 1


def test_long_lines_need_encoding(tmp_path):
    f = tmp_path / "long.eml"
    f.write_text(
        "From: a@example.com\nDate: Wed, 25 Nov 2026 10:00:00 +0000\nMessage-ID: <1@example.com>\n"
        "Subject: hi\nMIME-Version: 1.0\nContent-Type: text/html\n\n<p>" + "a" * 1200 + "</p>\n"
    )
    _, rep = lint(str(f), "--type", "transactional")
    assert "998 characters" in titles(rep)


def test_multiple_files_stdin_and_errors(tmp_path):
    r = run_script(SKILL, SCRIPT, str(DIR / "good.html"), str(DIR / "bad.html"), "--json")
    assert r.returncode == 1 and len(json.loads(r.stdout)) == 2
    r = run_script(SKILL, SCRIPT, "-", stdin=(DIR / "good.html").read_text())
    assert r.returncode == 0 and "0 high" in r.stdout
    assert run_script(SKILL, SCRIPT, str(tmp_path / "nope.html")).returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
