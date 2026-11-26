#!/usr/bin/env python3
"""Clean an email list CSV offline: syntax, duplicates, role accounts, disposable domains, typos.

Never modifies the input. Writes optional outputs:
  --clean-out FILE    rows that passed every check (original columns kept)
  --flagged-out FILE  rows that were flagged, with 'flags' and 'suggestion' columns added

Flags:
  invalid      not a valid address (syntax, length, bad domain, reserved TLD)
  duplicate    same address seen earlier (case-insensitive; --gmail-normalize also folds
               dots and +tags for Gmail/Googlemail)
  role         role account (info@, admin@, sales@ ...): shared inboxes complain more
  disposable   throwaway mailbox provider
  typo         common domain typo (gmial.com -> gmail.com); suggestion column says the fix.
               --fuzzy-typos also catches any single-edit typo (insert, delete, swap,
               replace) of a major mailbox provider domain (gmaik.com, yahoo.cm)
  suppressed   present in --suppress FILE (previous hard bounces, complaints, unsubscribes)

By default 'role' rows are kept in the clean output (flagged only); use --drop-role to drop them.

Exit codes: 0 = no rows flagged, 1 = some rows flagged, 2 = input error.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter

LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
RESERVED_TLDS = {"example", "invalid", "localhost", "test", "local", "lan", "internal", "home", "corp"}
ROLE_LOCALS = {
    "abuse", "accounting", "accounts", "admin", "administrator", "billing", "careers", "contact",
    "customerservice", "dev", "devnull", "dns", "enquiries", "ftp", "hello", "help", "helpdesk",
    "hostmaster", "hr", "info", "inquiries", "it", "jobs", "list", "mail", "mailer-daemon",
    "marketing", "media", "news", "newsletter", "no-reply", "noc", "noreply", "do-not-reply",
    "donotreply", "office", "orders", "postmaster", "press", "privacy", "root", "sales",
    "security", "service", "spam", "support", "sysadmin", "team", "webmaster", "www",
}  # fmt: skip
DISPOSABLE = {
    "10minutemail.com", "10minutemail.net", "20minutemail.com", "33mail.com", "anonaddy.me",
    "burnermail.io", "discard.email", "dispostable.com", "emailondeck.com", "fakeinbox.com",
    "getairmail.com", "getnada.com", "guerrillamail.biz", "guerrillamail.com", "guerrillamail.de",
    "guerrillamail.info", "guerrillamail.net", "guerrillamail.org", "guerrillamailblock.com",
    "harakirimail.com", "inboxkitten.com", "jetable.org", "mail.tm", "mailcatch.com",
    "maildrop.cc", "mailinator.com", "mailinator.net", "mailnesia.com", "mailpoof.com",
    "mintemail.com", "moakt.com", "mohmal.com", "mytemp.email", "nada.email", "sharklasers.com",
    "spam4.me", "spambox.us", "spamgourmet.com", "temp-mail.io", "temp-mail.org", "tempail.com",
    "tempmail.com", "tempmail.net", "tempmailo.com", "tempr.email", "throwawaymail.com",
    "trashmail.com", "trashmail.de", "trashmail.net", "yopmail.com", "yopmail.fr", "yopmail.net",
    "emailfake.com", "fakemail.net", "grr.la", "pokemail.net", "spamex.com", "mvrht.net",
}  # fmt: skip
TYPOS = {
    "gmial.com": "gmail.com", "gmai.com": "gmail.com", "gamil.com": "gmail.com", "gnail.com": "gmail.com",
    "gmail.co": "gmail.com", "gmail.con": "gmail.com", "gmail.cm": "gmail.com", "gmaill.com": "gmail.com",
    "gmal.com": "gmail.com", "gmali.com": "gmail.com", "gmail.om": "gmail.com", "gmailcom": "gmail.com",
    "googlemail.co": "googlemail.com",
    "hotmial.com": "hotmail.com", "hotmai.com": "hotmail.com", "hotmal.com": "hotmail.com",
    "hotmail.co": "hotmail.com", "hotmail.con": "hotmail.com", "hotmil.com": "hotmail.com",
    "hotamil.com": "hotmail.com", "homail.com": "hotmail.com",
    "outlok.com": "outlook.com", "outllok.com": "outlook.com", "outlook.co": "outlook.com",
    "outlook.con": "outlook.com", "otlook.com": "outlook.com",
    "yaho.com": "yahoo.com", "yahooo.com": "yahoo.com", "yahoo.co": "yahoo.com", "yahoo.con": "yahoo.com",
    "yhoo.com": "yahoo.com", "yaoo.com": "yahoo.com", "yahho.com": "yahoo.com",
    "icloud.co": "icloud.com", "iclod.com": "icloud.com", "icoud.com": "icloud.com",
    "aol.co": "aol.com", "aol.con": "aol.com", "comcast.com": "comcast.net", "verizon.com": "verizon.net",
    "live.co": "live.com", "msn.co": "msn.com", "protonmail.co": "protonmail.com",
}  # fmt: skip
GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
FUZZY_TARGETS = (
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "protonmail.com", "comcast.net",
)  # fmt: skip
# Real mailbox domains one edit away from a target: never reported as typos.
REAL_NEARBY = {
    "mail.com", "gmx.com", "ymail.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.fr", "yahoo.de",
    "hotmail.co.uk", "hotmail.fr", "hotmail.de", "outlook.de", "outlook.fr", "icloud.co",
}  # fmt: skip


def edit_distance(a: str, b: str, limit: int = 2) -> int:
    """Optimal string alignment distance (insert, delete, replace, adjacent swap), capped at limit."""
    if abs(len(a) - len(b)) >= limit:
        return limit
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return min(prev[-1], limit)


def fuzzy_typo(domain: str) -> str | None:
    """Return the provider domain that `domain` is one edit away from, if any."""
    if domain in FUZZY_TARGETS or domain in REAL_NEARBY or domain in TYPOS:
        return None
    hits = [t for t in FUZZY_TARGETS if edit_distance(domain, t) == 1]
    return hits[0] if len(hits) == 1 else None


def validate_syntax(addr: str) -> str | None:
    """Return a reason string if the address is invalid, else None."""
    if not addr:
        return "empty"
    if len(addr) > 254:
        return "longer than 254 characters"
    if addr.count("@") != 1:
        return "must contain exactly one @"
    local, domain = addr.rsplit("@", 1)
    if not local or len(local) > 64:
        return "local part empty or longer than 64"
    if not LOCAL_RE.match(local):
        return "invalid characters or dots in local part"
    if not domain or "." not in domain:
        return "domain has no dot"
    labels = domain.split(".")
    if not all(LABEL_RE.match(lbl) for lbl in labels):
        return "invalid domain label"
    tld = labels[-1].lower()
    if tld.isdigit() or len(tld) < 2:
        return "invalid top-level domain"
    if tld in RESERVED_TLDS or domain.lower() in ("example.com", "example.net", "example.org"):
        return f"reserved domain ({domain.lower()})"
    return None


def normalise(addr: str, gmail: bool = False) -> str:
    addr = addr.strip().strip("<>").strip()
    if "@" not in addr:
        return addr.lower()
    local, domain = addr.rsplit("@", 1)
    domain = domain.lower().rstrip(".")
    key_local = local.lower()
    if gmail and domain in GMAIL_DOMAINS:
        key_local = key_local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"
    return f"{key_local}@{domain}"


def detect_column(fieldnames: list[str], wanted: str | None) -> str:
    if wanted:
        for f in fieldnames:
            if f.strip().lower() == wanted.lower():
                return f
        raise ValueError(f"column '{wanted}' not found (have: {', '.join(fieldnames)})")
    for f in fieldnames:
        if f.strip().lower() in ("email", "e-mail", "email address", "email_address", "mail", "address"):
            return f
    for f in fieldnames:
        if "mail" in f.lower():
            return f
    raise ValueError(f"no email column found (have: {', '.join(fieldnames)}); use --column")


def check_rows(
    rows: list[dict],
    column: str,
    gmail_normalize: bool = False,
    suppress: set[str] | None = None,
    extra_disposable: set[str] | None = None,
    allow_reserved: bool = False,
    fuzzy_typos: bool = False,
) -> list[dict]:
    disposable = DISPOSABLE | (extra_disposable or set())
    suppress = {normalise(s, gmail_normalize) for s in (suppress or set())}
    seen: dict[str, int] = {}
    results = []
    for idx, row in enumerate(rows, start=2):  # line 1 is the header
        raw = (row.get(column) or "").strip()
        addr = raw.strip("<>").strip()
        flags: list[str] = []
        reason = ""
        suggestion = ""
        err = validate_syntax(addr)
        if err and allow_reserved and err.startswith("reserved"):
            err = None
        if err:
            flags.append("invalid")
            reason = err
        domain = addr.rsplit("@", 1)[1].lower() if "@" in addr else ""
        local = addr.rsplit("@", 1)[0].lower() if "@" in addr else ""
        fixed = TYPOS.get(domain) or (fuzzy_typo(domain) if fuzzy_typos and not err else None)
        if fixed:
            flags.append("typo")
            suggestion = f"{addr.rsplit('@', 1)[0]}@{fixed}"
        if domain in disposable or any(domain.endswith("." + d) for d in disposable):
            flags.append("disposable")
        base_local = re.split(r"[+]", local, maxsplit=1)[0]
        if base_local in ROLE_LOCALS:
            flags.append("role")
        key = normalise(addr, gmail_normalize)
        if key in suppress:
            flags.append("suppressed")
        if addr and key in seen:
            flags.append("duplicate")
            reason = reason or f"duplicate of line {seen[key]}"
        elif addr:
            seen[key] = idx
        results.append(
            {"line": idx, "email": raw, "normalized": key, "flags": flags, "reason": reason,
             "suggestion": suggestion, "row": row}
        )  # fmt: skip
    return results


def read_list(path: str, encoding: str = "utf-8-sig") -> tuple[list[str], list[dict]]:
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, encoding=encoding, newline="") as fh:
            text = fh.read()
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    lines = text.splitlines()
    if lines and "@" in lines[0] and not any(h in lines[0].lower() for h in ("email", "mail")):
        text = "email\n" + text  # headerless one-address-per-line file
    reader = csv.DictReader(text.splitlines(), dialect=dialect)
    return list(reader.fieldnames or []), list(reader)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Flag invalid, duplicate, role, disposable, typo and suppressed addresses in a CSV.",
        epilog="Example: list_hygiene.py contacts.csv --clean-out clean.csv --flagged-out flagged.csv",
    )
    p.add_argument("csv", help="input CSV (header row; or one address per line), or - for stdin")
    p.add_argument("--column", help="email column name (auto-detected by default)")
    p.add_argument("--gmail-normalize", action="store_true", help="treat Gmail dots/+tags as duplicates")
    p.add_argument("--suppress", help="file of addresses to exclude (one per line or CSV with an email column)")
    p.add_argument("--disposable-list", help="extra disposable domains, one per line")
    p.add_argument("--drop-role", action="store_true", help="drop role accounts from the clean output")
    p.add_argument(
        "--fuzzy-typos",
        action="store_true",
        help="also flag single-edit typos of major provider domains (gmaik.com, yahoo.cm)",
    )
    p.add_argument("--allow-reserved", action="store_true", help="accept example.com/.test (for testing)")
    p.add_argument("--clean-out", help="write rows that pass to this CSV")
    p.add_argument("--flagged-out", help="write flagged rows (with flags/suggestion columns) to this CSV")
    p.add_argument("--json", action="store_true", help="print JSON summary")
    args = p.parse_args(argv)
    try:
        fields, rows = read_list(args.csv)
        column = detect_column(fields, args.column)
        suppress: set[str] = set()
        if args.suppress:
            sfields, srows = read_list(args.suppress)
            scol = detect_column(sfields, None)
            suppress = {r.get(scol, "") for r in srows if r.get(scol)}
        extra: set[str] = set()
        if args.disposable_list:
            with open(args.disposable_list, encoding="utf-8") as fh:
                extra = {ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")}
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = check_rows(rows, column, args.gmail_normalize, suppress, extra, args.allow_reserved, args.fuzzy_typos)
    drop = {"invalid", "duplicate", "disposable", "typo", "suppressed"} | ({"role"} if args.drop_role else set())
    clean = [r for r in results if not drop & set(r["flags"])]
    flagged = [r for r in results if r["flags"]]
    try:
        if args.clean_out:
            with open(args.clean_out, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                w.writerows(r["row"] for r in clean)
        if args.flagged_out:
            with open(args.flagged_out, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=[*fields, "flags", "reason", "suggestion"], extrasaction="ignore")
                w.writeheader()
                for r in flagged:
                    w.writerow(
                        dict(
                            r["row"],
                            flags=";".join(r["flags"]),
                            reason=r["reason"],
                            suggestion=r["suggestion"],
                        )
                    )
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    counts = Counter(f for r in results for f in r["flags"])
    domains = Counter(r["normalized"].rsplit("@", 1)[-1] for r in clean if "@" in r["normalized"])
    summary = {
        "column": column,
        "rows": len(results),
        "clean": len(clean),
        "flagged": len(flagged),
        "flags": dict(counts.most_common()),
        "top_domains": domains.most_common(10),
        "flagged_rows": [{k: r[k] for k in ("line", "email", "flags", "reason", "suggestion")} for r in flagged],
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"{summary['rows']} rows, {summary['clean']} clean, {summary['flagged']} flagged (column '{column}')")
        for flag, n in counts.most_common():
            print(f"  {flag:11} {n}")
        for r in flagged[:25]:
            extra_txt = f" -> {r['suggestion']}" if r["suggestion"] else (f" ({r['reason']})" if r["reason"] else "")
            print(f"  line {r['line']:>5}: {r['email']:40} {','.join(r['flags'])}{extra_txt}")
        if len(flagged) > 25:
            print(f"  ... {len(flagged) - 25} more (use --flagged-out)")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
