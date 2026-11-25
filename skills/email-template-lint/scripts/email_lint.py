#!/usr/bin/env python3
"""Lint an HTML email (or a full .eml message) for deliverability and rendering problems.

HTML checks: Gmail clipping (>102 KB of HTML), image-heavy / image-only layout, missing
alt text, base64 and http images, risky links (shorteners, raw IPs, javascript:, link
text showing a different domain than the href), forms/scripts/iframes, external CSS,
and an unsubscribe link for marketing mail.

.eml checks (in addition): plain-text alternative, List-Unsubscribe and one-click
List-Unsubscribe-Post (RFC 8058), Message-ID/Date/From, long unencoded lines, risky
attachments.

Exit codes: 0 = no high/medium findings, 1 = findings, 2 = input error.
"""

from __future__ import annotations

import argparse
import email
import ipaddress
import json
import re
import sys
from email import policy
from html.parser import HTMLParser
from urllib.parse import urlsplit

GMAIL_CLIP_BYTES = 102 * 1024
SEVERITIES = ("high", "medium", "low", "info")
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd", "lnkd.in",
}  # fmt: skip
UNSUB_RE = re.compile(
    r"unsubscribe|opt[- ]?out|manage (?:your )?(?:email )?preferences|email preferences|"
    r"abmelden|d[ée]sinscri|darse de baja|cancelar suscri",
    re.I,
)
RISKY_EXT = re.compile(r"\.(exe|scr|bat|cmd|com|js|vbs|jar|msi|ps1|iso|img|lnk|hta|docm|xlsm)$", re.I)
DOMAIN_TEXT_RE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#].*)?$", re.I)


def finding(sev: str, title: str, fix: str = "", count: int = 1) -> dict:
    return {"severity": sev, "title": title, "fix": fix, "count": count}


class EmailHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.images: list[dict] = []
        self.links: list[dict] = []
        self.tags: dict[str, int] = {}
        self.stylesheets = 0
        self.title = ""
        self._skip = 0
        self._in_title = False
        self._link: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        self.tags[tag] = self.tags.get(tag, 0) + 1
        if tag in ("style", "script"):
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag == "img":
            self.images.append(dict(a, _has_alt="alt" in a))
            if self._link is not None:
                self._link["has_img"] = True
        if tag == "a":
            self._link = {"href": a.get("href", ""), "text": "", "has_img": False, "has_href": "href" in a}
        if tag == "link" and "stylesheet" in a.get("rel", "").lower():
            self.stylesheets += 1

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in ("style", "script") and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False
        if tag == "a" and self._link is not None:
            self.links.append(self._link)
            self._link = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
            return
        if self._skip:
            return
        self.text.append(data)
        if self._link is not None:
            self._link["text"] += data

    def visible_text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.text)).strip()


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _base(host: str) -> str:
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    return ".".join(host.split(".")[-2:])


def lint_html(html: str, kind: str = "marketing") -> tuple[list[dict], dict]:
    out: list[dict] = []
    size = len(html.encode("utf-8"))
    parser = EmailHTML()
    parser.feed(html)
    parser.close()
    text = parser.visible_text()
    words = len(re.findall(r"\w+", text))
    real_images = [
        i
        for i in parser.images
        if not (i.get("width", "").strip("px") in ("0", "1") and i.get("height", "").strip("px") in ("0", "1"))
    ]
    pixels = len(parser.images) - len(real_images)
    stats = {
        "html_bytes": size,
        "words": words,
        "images": len(real_images),
        "tracking_pixels": pixels,
        "links": len(parser.links),
        "link_domains": sorted({_host(lk["href"]) for lk in parser.links if _host(lk["href"])}),
    }

    if size > GMAIL_CLIP_BYTES:
        out.append(
            finding(
                "high",
                f"HTML is {size / 1024:.1f} KB: Gmail clips messages over 102 KB (hides the rest, incl. unsubscribe)",
                "minify, inline less CSS, remove unused markup or split the content",
            )
        )
    elif size > 90 * 1024:
        out.append(finding("low", f"HTML is {size / 1024:.1f} KB, close to Gmail's 102 KB clip", "trim markup"))

    if real_images and words < 25:
        out.append(
            finding(
                "high",
                f"image-only email ({len(real_images)} image(s), {words} words of text)",
                "put the message in live HTML text; images are blocked by default in many clients",
            )
        )
    elif real_images and words / len(real_images) < 40:
        out.append(
            finding(
                "medium",
                f"image-heavy: {words} words for {len(real_images)} images",
                "aim for at least ~60% text by area; move headlines and offers into HTML text",
            )
        )
    missing_alt = [i for i in real_images if not i["_has_alt"]]
    if missing_alt:
        out.append(
            finding(
                "low",
                f"{len(missing_alt)} image(s) without alt attribute",
                'add alt="description" (alt="" for decorative images)',
                len(missing_alt),
            )
        )
    b64 = [i for i in parser.images if i.get("src", "").lower().startswith("data:")]
    if b64:
        out.append(
            finding(
                "medium",
                f"{len(b64)} base64 data: image(s): blocked by Gmail and Outlook, inflate size",
                "host images over https",
                len(b64),
            )
        )
    http_img = [i for i in parser.images if i.get("src", "").lower().startswith("http://")]
    if http_img:
        out.append(finding("low", f"{len(http_img)} image(s) over plain http", "use https URLs", len(http_img)))

    risky: dict[str, list[str]] = {}
    for lk in parser.links:
        href = lk["href"].strip()
        low = href.lower()
        host = _host(href)
        if not lk["has_href"] or href in ("", "#"):
            risky.setdefault("empty", []).append(lk["text"].strip()[:40])
            continue
        if low.startswith("javascript:"):
            risky.setdefault("javascript", []).append(href[:60])
        elif low.startswith("http://"):
            risky.setdefault("http", []).append(href[:80])
        if host and _is_ip(host):
            risky.setdefault("ip", []).append(href[:80])
        if host in SHORTENERS:
            risky.setdefault("shortener", []).append(href[:80])
        shown = lk["text"].strip()
        m = DOMAIN_TEXT_RE.match(shown)
        if m and host and not lk["has_img"] and " " not in shown:
            shown_host = m.group(1).lower()
            if _base(shown_host) != _base(host) and "." in shown_host:
                risky.setdefault("mismatch", []).append(f"text '{shown[:50]}' -> {host}")
    rules = {
        "javascript": ("high", "javascript: link(s)", "remove; scripts never run in email and look malicious"),
        "ip": ("high", "link(s) to raw IP addresses", "link to your domain"),
        "mismatch": ("high", "link text shows a different domain than the link goes to", "make text and href match"),
        "shortener": ("medium", "public URL shortener link(s) (shared reputation, often blocklisted)",
                      "use your own domain or your ESP's branded tracking domain"),
        "http": ("low", "link(s) over plain http", "use https"),
        "empty": ("low", "link(s) with empty or '#' href", "point them somewhere or remove the <a>"),
    }  # fmt: skip
    for key, (sev, title, fix) in rules.items():
        if key in risky:
            sample = "; ".join(risky[key][:3])
            out.append(finding(sev, f"{len(risky[key])} {title}: {sample}", fix, len(risky[key])))

    for tag, sev, why in (
        ("script", "medium", "scripts are stripped and are a spam/malware signal"),
        ("form", "medium", "forms are unsupported or warned about in many clients"),
        ("iframe", "medium", "iframes are stripped and look suspicious"),
        ("embed", "medium", "embedded objects are stripped"),
        ("object", "medium", "embedded objects are stripped"),
    ):
        if parser.tags.get(tag):
            out.append(finding(sev, f"<{tag}> used ({parser.tags[tag]}x)", why, parser.tags[tag]))
    if parser.stylesheets:
        out.append(finding("low", "external stylesheet <link>: most clients ignore it", "inline CSS or use <style>"))
    unsub_links = [lk for lk in parser.links if UNSUB_RE.search(lk["text"]) or UNSUB_RE.search(lk["href"])]
    stats["unsubscribe_links"] = len(unsub_links)
    if not unsub_links:
        if kind == "marketing":
            out.append(
                finding(
                    "high",
                    "no visible unsubscribe link (required for marketing mail by CAN-SPAM, GDPR/PECR, Gmail, Yahoo)",
                    "add an unsubscribe link in the footer, plus the List-Unsubscribe header",
                )
            )
        else:
            out.append(finding("info", "no unsubscribe link (fine for purely transactional mail)", ""))
    if not parser.title.strip():
        out.append(finding("info", "no <title> (shown by some clients and web views)", "add a <title>"))
    if pixels > 2:
        out.append(finding("info", f"{pixels} tracking pixels", "one open pixel is enough"))
    if len(stats["link_domains"]) > 6:
        out.append(
            finding(
                "low",
                f"links point to {len(stats['link_domains'])} different domains",
                "fewer, consistent link domains look more trustworthy",
            )
        )
    return out, stats


def _decode(part) -> str:
    payload = part.get_payload(decode=True) or b""
    return payload.decode(part.get_content_charset() or "utf-8", "replace")


def lint_eml(raw: bytes, kind: str = "marketing") -> tuple[list[dict], dict]:
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    out: list[dict] = []
    html_parts, text_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = (part.get("Content-Disposition") or "").lower()
        fname = part.get_filename()
        if fname or disp.startswith("attachment"):
            attachments.append(fname or "(unnamed)")
            continue
        if part.get_content_type() == "text/html":
            html_parts.append(part)
        elif part.get_content_type() == "text/plain":
            text_parts.append(part)
    stats: dict = {"message_bytes": len(raw), "attachments": attachments}
    for hdr, sev in (("From", "high"), ("Date", "medium"), ("Message-ID", "medium"), ("Subject", "medium")):
        if not msg.get(hdr):
            out.append(finding(sev, f"missing {hdr} header", f"set {hdr} (RFC 5322)"))
    if len(msg.get_all("From") or []) > 1:
        out.append(finding("high", "more than one From header (rejected by Gmail)", "send one From"))
    subject = str(msg.get("Subject") or "")
    if subject and (subject.isupper() and len(subject) > 10 or "!!!" in subject):
        out.append(finding("low", f"shouty subject: {subject[:60]!r}", "avoid ALL CAPS and repeated !"))

    lu = str(msg.get("List-Unsubscribe") or "")
    lup = str(msg.get("List-Unsubscribe-Post") or "")
    stats["list_unsubscribe"] = lu
    stats["list_unsubscribe_post"] = lup
    sev_missing = "high" if kind == "marketing" else "info"
    if not lu:
        out.append(
            finding(
                sev_missing,
                "no List-Unsubscribe header",
                "List-Unsubscribe: <https://example.com/u/TOKEN>, <mailto:unsub@example.com?subject=unsub>",
            )
        )
    else:
        uris = re.findall(r"<([^>]+)>", lu)
        if not uris:
            out.append(finding("medium", "List-Unsubscribe values must be in <angle brackets>", ""))
        if not any(u.lower().startswith("https://") for u in uris):
            out.append(
                finding(
                    "medium" if kind == "marketing" else "low",
                    "List-Unsubscribe has no https URL (one-click unsubscribe needs one)",
                    "add <https://...> next to the mailto:",
                )
            )
        if lup.replace(" ", "").lower() != "list-unsubscribe=one-click":
            out.append(
                finding(
                    sev_missing if kind == "marketing" else "low",
                    "missing 'List-Unsubscribe-Post: List-Unsubscribe=One-Click' (RFC 8058, Gmail/Yahoo bulk rule)",
                    "add the header and accept a POST on the https URL without login",
                )
            )
    if html_parts and not text_parts:
        out.append(
            finding(
                "medium",
                "no text/plain alternative",
                "send multipart/alternative with a real plain-text version",
            )
        )
    elif text_parts and html_parts:
        plain = " ".join(_decode(p) for p in text_parts)
        if len(re.findall(r"\w+", plain)) < 15:
            out.append(finding("low", "plain-text part is nearly empty", "include the actual message text"))
    for part in html_parts + text_parts:
        cte = (part.get("Content-Transfer-Encoding") or "7bit").lower()
        if cte in ("7bit", "8bit") and any(len(ln) > 998 for ln in part.get_payload().splitlines()):
            out.append(
                finding(
                    "medium",
                    f"{part.get_content_type()} has lines over 998 characters (RFC 5322) with {cte} encoding",
                    "use quoted-printable or base64 Content-Transfer-Encoding",
                )
            )
    risky = [a for a in attachments if RISKY_EXT.search(a)]
    if risky:
        out.append(finding("high", f"risky attachment(s): {', '.join(risky)}", "link to a download instead"))
    if html_parts:
        html_out, html_stats = lint_html(_decode(html_parts[0]), kind)
        out += html_out
        stats.update(html_stats)
    elif not text_parts:
        out.append(finding("high", "no text/html or text/plain body found", ""))
    return out, stats


def run(path: str, kind: str) -> dict:
    if path == "-":
        raw = sys.stdin.buffer.read()
    else:
        with open(path, "rb") as fh:
            raw = fh.read()
    head = raw[:4096].decode("utf-8", "replace")
    is_eml = path.lower().endswith(".eml") or bool(
        re.match(r"^(?:[A-Za-z0-9-]+:[^\n]*\n(?:[ \t][^\n]*\n)*)+", head) and re.search(r"^From:", head, re.M | re.I)
    )
    if is_eml:
        findings, stats = lint_eml(raw, kind)
    else:
        findings, stats = lint_html(raw.decode("utf-8", "replace"), kind)
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    return {"file": path, "type": kind, "input": "eml" if is_eml else "html", "stats": stats,
            "findings": findings, "counts": counts}  # fmt: skip


def render(report: dict) -> str:
    st = report["stats"]
    lines = [
        f"{report['file']} ({report['input']}, {report['type']}): "
        f"{st.get('html_bytes', 0) / 1024:.1f} KB HTML, {st.get('words', 0)} words, "
        f"{st.get('images', 0)} images, {st.get('links', 0)} links"
    ]
    for f in report["findings"]:
        fix = f"  -> {f['fix']}" if f["fix"] else ""
        lines.append(f"[{f['severity'].upper():6}] {f['title']}{fix}")
    c = report["counts"]
    lines.append(f"{c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Lint an HTML email or .eml message for deliverability problems.",
        epilog="Example: email_lint.py newsletter.html --type marketing --json",
    )
    p.add_argument("paths", nargs="+", help=".html or .eml files, or - for stdin")
    p.add_argument(
        "--type",
        choices=("marketing", "transactional"),
        default="marketing",
        help="marketing requires unsubscribe link + headers (default); transactional relaxes that",
    )
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)
    reports = []
    for path in args.paths:
        try:
            reports.append(run(path, args.type))
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
    else:
        print("\n\n".join(render(r) for r in reports))
    return 1 if any(r["counts"]["high"] or r["counts"]["medium"] for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
