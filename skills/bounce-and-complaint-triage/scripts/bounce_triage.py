#!/usr/bin/env python3
"""Classify bounces (DSNs, SMTP replies, MTA log lines) and complaints (ARF) with actions.

Inputs (mix freely; directories are walked):
  *.eml / *.msg     one message: a DSN (multipart/report; report-type=delivery-status),
                    an ARF complaint (report-type=feedback-report) or a plain bounce
  *.mbox            many messages
  *.csv             columns email + response/diagnostic/reason/smtp (header row required)
  anything else     text lines: Postfix/Exim logs or bare SMTP replies, one per line

Categories and the action for each:
  hard      address does not exist / domain invalid     -> suppress now
  soft      mailbox full, temporary failure            -> retry; suppress after repeats
  block     IP/domain reputation, blocklist, policy    -> stop and fix reputation
  auth      SPF/DKIM/DMARC/PTR failure                 -> fix authentication (dns-auth-audit)
  throttle  rate limited / deferred for volume         -> slow down, retry later
  content   rejected as spam or for content/size       -> fix the message
  complaint recipient reported spam (ARF/FBL)          -> suppress now, review consent
  unknown   no rule matched                            -> read the diagnostic

Exit codes: 0 = only hard/soft/unknown, 1 = block/auth/throttle/content/complaint found, 2 = error.
"""

from __future__ import annotations

import argparse
import csv
import email
import io
import json
import mailbox
import re
import sys
from collections import Counter, defaultdict
from email import policy
from pathlib import Path

ACTIONS = {
    "hard": "suppress the address now; never retry",
    "soft": "retry with backoff; suppress after 3-5 soft bounces over 72 hours",
    "block": "pause the stream to that provider; check blocklists and reputation, then request delisting",
    "auth": "fix SPF/DKIM/DMARC/PTR (see dns-auth-audit), then resend",
    "throttle": "reduce the send rate to that provider and retry later; do not hammer",
    "content": "fix the message (links, spammy content, size, attachments) before resending",
    "complaint": "suppress now; review how the address was collected and the send frequency",
    "unknown": "read the diagnostic text; add a rule if it recurs",
}
ACTION_NEEDED = {"block", "auth", "throttle", "content", "complaint"}

# (category, regex) checked in order against the diagnostic text; first match wins.
TEXT_RULES: list[tuple[str, str]] = [
    (
        "auth",
        r"5\.7\.2[3-7]|4\.7\.2[3-7]|5\.7\.515|dmarc|not pass authentication|unauthenticated|"
        r"spf (?:check )?fail|dkim (?:check )?fail|reverse dns|ptr record|authentication (?:check|required)",
    ),
    (
        "throttle",
        r"4\.7\.28|4\.2\.1|tss04|rate limit|rate-limit|too many (?:messages|connections|recipients)|"
        r"try again later|temporarily deferred|unusual rate|exceeded.*(?:rate|limit)|throttl|"
        r"4\.7\.650|4\.7\.0\b.*(?:deferred|later|volume)",
    ),
    (
        "block",
        r"spamhaus|barracuda|spamcop|sorbs|blocklist|blacklist|block ?list|\bdnsbl|\brbl\b|"
        r"listed (?:at|by|on|in)|blocked using|poor reputation|reputation|banned sending ip|"
        r"5\.7\.606|5\.7\.511|s3140|s3150|access denied, banned|ip .{0,40}blocked|"
        r"service unavailable.{0,40}client host|554 5\.7\.1 .{0,60}(?:block|refused)",
    ),
    (
        "content",
        r"5\.7\.1 .{0,80}(?:spam|unsolicited|content)|likely (?:unsolicited|suspicious|spam)|"
        r"message (?:content|looks like spam)|spam detected|virus|malware|5\.3\.4|5\.2\.3|"
        r"message (?:size|too (?:big|large))|exceeds (?:size|maximum)|phish|url.{0,20}(?:blocked|reputation)",
    ),
    (
        "soft",
        r"5\.2\.2|4\.2\.2|mailbox (?:is )?full|over ?quota|quota exceeded|insufficient (?:storage|system storage)|"
        r"4\.4\.\d|4\.3\.\d|5\.4\.7|delivery (?:time )?expired|connection timed out|temporar",
    ),
    (
        "hard",
        r"5\.1\.[0-9]{1,2}|5\.2\.1\b|5\.4\.1\b.{0,60}access denied|5\.4\.4|user unknown|unknown user|"
        r"no such (?:user|recipient|mailbox|address)|does not exist|doesn.t exist|"
        r"invalid (?:recipient|mailbox|address)|"
        r"recipient (?:address )?rejected|address rejected|mailbox (?:unavailable|not found|disabled)|"
        r"account (?:has been )?(?:disabled|deactivated|closed)|host or domain name not found|"
        r"domain (?:not found|does not exist)|null mx|no mx",
    ),
]
COMPILED = [(cat, re.compile(rx, re.I)) for cat, rx in TEXT_RULES]
ENHANCED_RE = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")
BASIC_RE = re.compile(r"\b([245]\d\d)[ -]")
ADDR_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
POSTFIX_RE = re.compile(r"to=<([^>]+)>.*?status=(bounced|deferred|sent|expired)\s*\((.*)\)\s*$")
EXIM_RE = re.compile(r"\*\* (\S+@\S+?)(?: <[^>]+>)?(?: R=\S+)?(?: T=\S+)?: (.*)$")


def classify(text: str, status: str = "", action: str = "") -> str:
    """Return a category for a diagnostic text plus optional DSN Status/Action fields."""
    blob = f"{status} {text}"
    for cat, rx in COMPILED:
        if rx.search(blob):
            if cat == "hard" and (status.startswith("4") or action.lower() == "delayed"):
                return "soft"
            return cat
    code = status or (ENHANCED_RE.search(text).group(0) if ENHANCED_RE.search(text) else "")
    if not code:
        m = BASIC_RE.search(text)
        code = m.group(1) if m else ""
    if action.lower() == "delayed" or code.startswith("4"):
        return "soft"
    if code.startswith("5"):
        return "unknown"
    return "unknown"


def status_code(text: str) -> str:
    m = ENHANCED_RE.search(text)
    if m:
        return m.group(0)
    m = BASIC_RE.search(text)
    return m.group(1) if m else ""


def item(recipient: str, text: str, source: str, status: str = "", action: str = "", kind: str = "") -> dict:
    text = " ".join(text.split())
    cat = kind or classify(text, status, action)
    rcpt = recipient.strip().strip("<>").lower()
    return {
        "recipient": rcpt,
        "domain": rcpt.rsplit("@", 1)[1] if "@" in rcpt else "",
        "category": cat,
        "status": status or status_code(text),
        "diagnostic": text[:300],
        "source": source,
    }


# --------------------------------------------------------------------------- parsers


def _part_text(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = part.get_payload()
            if isinstance(payload, list):
                return "\n".join(_part_text(p) for p in payload)
            return str(payload)
        return payload.decode(part.get_content_charset() or "utf-8", "replace")
    except (LookupError, AttributeError):
        return ""


def _field_blocks(part) -> list[dict]:
    """Parse message/delivery-status or message/feedback-report into header blocks."""
    payload = part.get_payload()
    blocks = []
    if isinstance(payload, list):
        for sub in payload:
            blocks.append({k.lower(): str(v) for k, v in sub.items()})
        if blocks:
            return blocks
    text = _part_text(part)
    for chunk in re.split(r"\n\s*\n", text.replace("\r\n", "\n")):
        fields: dict[str, str] = {}
        last = None
        for line in chunk.splitlines():
            if line[:1] in (" ", "\t") and last:
                fields[last] += " " + line.strip()
            elif ":" in line:
                k, v = line.split(":", 1)
                last = k.strip().lower()
                fields[last] = v.strip()
        if fields:
            blocks.append(fields)
    return blocks


def _strip_type(value: str) -> str:
    return value.split(";", 1)[1].strip() if ";" in value else value.strip()


def parse_message(msg, source: str) -> list[dict]:
    ctype = msg.get_content_type()
    report_type = (msg.get_param("report-type") or "").lower() if ctype == "multipart/report" else ""
    out: list[dict] = []
    if report_type == "feedback-report" or any(p.get_content_type() == "message/feedback-report" for p in msg.walk()):
        rcpt = ""
        ftype = "abuse"
        for part in msg.walk():
            if part.get_content_type() == "message/feedback-report":
                for block in _field_blocks(part):
                    ftype = block.get("feedback-type", ftype)
                    rcpt = rcpt or block.get("original-rcpt-to", "") or block.get("removal-recipient", "")
            elif part.get_content_type() in ("message/rfc822", "text/rfc822-headers") and not rcpt:
                inner = _part_text(part)
                m = re.search(r"^To:\s*(.+)$", inner, re.M)
                if m:
                    found = ADDR_RE.search(m.group(1))
                    rcpt = found.group(0) if found else ""
        kind = "complaint" if ftype.lower() in ("abuse", "fraud", "virus", "other") else "unknown"
        return [item(_strip_type(rcpt), f"ARF feedback-type={ftype}", source, kind=kind)]
    for part in msg.walk():
        if part.get_content_type() == "message/delivery-status":
            blocks = _field_blocks(part)
            for block in blocks[1:] or blocks:
                if "final-recipient" not in block and "original-recipient" not in block:
                    continue
                action = block.get("action", "")
                if action.lower() in ("delivered", "relayed", "expanded"):
                    continue
                rcpt = _strip_type(block.get("final-recipient") or block.get("original-recipient", ""))
                diag = _strip_type(block.get("diagnostic-code", "")) or block.get("status", "")
                out.append(item(rcpt, diag, source, block.get("status", ""), action))
    if out:
        return out
    # Non-standard bounce: look for recipient + SMTP reply in the body.
    body = "\n".join(_part_text(p) for p in msg.walk() if p.get_content_maintype() == "text")
    subject = str(msg.get("subject", ""))
    if not re.search(
        r"undeliver|delivery (?:status|failure)|returned|failure notice|bounce", subject + body[:500], re.I
    ):
        return []
    rcpt = ""
    for m in ADDR_RE.finditer(body):
        if not m.group(0).lower().startswith(("mailer-daemon", "postmaster")):
            rcpt = m.group(0)
            break
    reply = ""
    for line in body.splitlines():
        if ENHANCED_RE.search(line) or BASIC_RE.search(line):
            reply = line.strip()
            break
    return [item(rcpt, reply or subject, source)]


def parse_line(line: str, source: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    m = POSTFIX_RE.search(line)
    if m:
        if m.group(2) == "sent":
            return None
        action = "delayed" if m.group(2) == "deferred" else "failed"
        dsn = re.search(r"dsn=([245]\.\d{1,3}\.\d{1,3})", line)
        return item(m.group(1), m.group(3), source, dsn.group(1) if dsn else "", action)
    m = EXIM_RE.search(line)
    if m:
        return item(m.group(1), m.group(2), source, action="failed")
    if " == " in line and ADDR_RE.search(line):  # exim deferral
        return item(ADDR_RE.search(line).group(0), line.split(" == ", 1)[1], source, action="delayed")
    if not (ENHANCED_RE.search(line) or BASIC_RE.search(line)):
        return None
    addr = ADDR_RE.search(line)
    return item(addr.group(0) if addr else "", line, source)


def parse_csv(text: str, source: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    fields = {f.lower().strip(): f for f in reader.fieldnames or []}
    email_col = next((fields[k] for k in ("email", "recipient", "address", "to", "rcpt") if k in fields), None)
    diag_col = next(
        (
            fields[k]
            for k in (
                "response",
                "diagnostic",
                "diagnostic_code",
                "reason",
                "smtp",
                "error",
                "message",
                "bounce",
            )
            if k in fields
        ),
        None,
    )
    status_col = next((fields[k] for k in ("status", "code", "status_code") if k in fields), None)
    if not email_col or not diag_col:
        raise ValueError(f"{source}: CSV needs an email column and a response/diagnostic/reason column")
    out = []
    for row in reader:
        out.append(
            item(
                row.get(email_col) or "",
                row.get(diag_col) or "",
                source,
                (row.get(status_col) or "") if status_col else "",
            )
        )
    return out


def parse_path(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".mbox":
        out = []
        for i, msg in enumerate(mailbox.mbox(str(path), factory=None, create=False)):
            parsed = email.message_from_bytes(msg.as_bytes(), policy=policy.compat32)
            out += parse_message(parsed, f"{path.name}#{i + 1}")
        return out
    raw = path.read_bytes()
    if (
        suffix in (".eml", ".msg")
        or re.match(rb"^(?:[A-Za-z-]+: .*\r?\n)+", raw[:2000])
        and b"\nContent-Type:" in raw[:5000]
    ):
        msg = email.message_from_bytes(raw, policy=policy.compat32)
        return parse_message(msg, path.name)
    text = raw.decode("utf-8", "replace")
    if suffix == ".csv":
        return parse_csv(text, path.name)
    return [r for r in (parse_line(ln, path.name) for ln in text.splitlines()) if r]


def collect(paths: list[str]) -> tuple[list[dict], list[str]]:
    items, errors = [], []
    for p in paths:
        if p == "-":
            items += [r for r in (parse_line(ln, "stdin") for ln in sys.stdin) if r]
            continue
        path = Path(p)
        files = sorted(f for f in path.rglob("*") if f.is_file()) if path.is_dir() else [path]
        for f in files:
            try:
                items += parse_path(f)
            except (OSError, ValueError) as exc:
                errors.append(str(exc))
    return items, errors


def summarise(items: list[dict], sent: int | None = None) -> dict:
    cats = Counter(i["category"] for i in items)
    by_domain: dict[str, Counter] = defaultdict(Counter)
    for i in items:
        by_domain[i["domain"] or "(unknown)"][i["category"]] += 1
    suppress = sorted({i["recipient"] for i in items if i["category"] in ("hard", "complaint") and i["recipient"]})
    soft_counts = Counter(i["recipient"] for i in items if i["category"] == "soft" and i["recipient"])
    repeat_soft = sorted(a for a, n in soft_counts.items() if n >= 3)
    examples: dict[str, list[str]] = defaultdict(list)
    for i in items:
        if len(examples[i["category"]]) < 3 and i["diagnostic"] not in examples[i["category"]]:
            examples[i["category"]].append(i["diagnostic"])
    summary = {
        "total": len(items),
        "categories": dict(cats.most_common()),
        "actions": {c: ACTIONS[c] for c in cats},
        "by_domain": {d: dict(c) for d, c in sorted(by_domain.items(), key=lambda kv: -sum(kv[1].values()))},
        "suppress": suppress,
        "repeat_soft": repeat_soft,
        "examples": dict(examples),
        "items": items,
    }
    if sent:
        summary["rates"] = {
            "bounce_pct": round(100.0 * sum(cats[c] for c in cats if c != "complaint") / sent, 3),
            "hard_pct": round(100.0 * cats["hard"] / sent, 3),
            "complaint_pct": round(100.0 * cats["complaint"] / sent, 3),
        }
    return summary


def render(s: dict, errors: list[str]) -> str:
    out = [f"Bounce and complaint triage: {s['total']} event(s)"]
    if "rates" in s:
        r = s["rates"]
        out.append(f"Rates: bounce {r['bounce_pct']}%, hard {r['hard_pct']}%, complaints {r['complaint_pct']}%")
    out.append("")
    for cat, n in s["categories"].items():
        out.append(f"{cat:9} {n:>6}  -> {ACTIONS[cat]}")
        for ex in s["examples"].get(cat, []):
            out.append(f"            e.g. {ex[:140]}")
    out.append("")
    out.append("By recipient domain:")
    for dom, cats in list(s["by_domain"].items())[:15]:
        out.append(f"  {dom:30} " + ", ".join(f"{k}={v}" for k, v in sorted(cats.items())))
    out.append("")
    out.append(f"Suppress now (hard + complaint): {len(s['suppress'])}")
    if s["repeat_soft"]:
        out.append(f"Repeated soft bounces (3+): {len(s['repeat_soft'])} -> suppress if they continue")
    for e in errors:
        out.append(f"warning: {e}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Classify bounces and complaints into hard/soft/block/auth/throttle/content/complaint.",
        epilog="Example: bounce_triage.py bounces/ /var/log/mail.log --suppress-out suppress.csv",
    )
    p.add_argument("paths", nargs="+", help=".eml, .mbox, .csv, log files, directories, or - for stdin lines")
    p.add_argument("--sent", type=int, help="messages sent in the same period, to compute rates")
    p.add_argument("--suppress-out", help="write hard-bounce and complaint addresses to this CSV")
    p.add_argument("--items", action="store_true", help="include every classified event in text output")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)
    items, errors = collect(args.paths)
    if not items and errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2
    s = summarise(items, args.sent)
    if args.suppress_out:
        try:
            with open(args.suppress_out, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["email", "reason"])
                reasons = {}
                for i in items:
                    if i["recipient"] in s["suppress"]:
                        reasons.setdefault(i["recipient"], i["category"])
                for addr in s["suppress"]:
                    w.writerow([addr, reasons[addr]])
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(dict(s, errors=errors), indent=2))
    else:
        print(render(s, errors))
        if args.items:
            for i in items:
                print(f"  {i['category']:9} {i['status']:8} {i['recipient']:35} {i['diagnostic'][:100]}")
    return 1 if ACTION_NEEDED & set(s["categories"]) else 0


if __name__ == "__main__":
    sys.exit(main())
