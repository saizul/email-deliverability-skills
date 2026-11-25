#!/usr/bin/env python3
"""Check a received message against the Gmail, Yahoo and Outlook.com sender requirements.

Give it a message exactly as a mailbox provider received it (Gmail: "Show original" ->
"Download original"), so the Authentication-Results and Received headers are present.
Add what a message cannot show: --spam-rate (Postmaster Tools), --daily-volume,
--dmarc (the _dmarc TXT value) and --type.

Every rule gets pass / fail / warn / unknown with the evidence it used and the fix.
Rules marked "bulk" apply to senders of about 5,000+ messages a day to that provider.

Exit codes: 0 = no failures, 1 = at least one rule failed, 2 = input error.
"""

from __future__ import annotations

import argparse
import email
import json
import re
import sys
from email import policy
from email.utils import getaddresses

FREEMAIL = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "yandex.com",
}
STATUS_ORDER = ("fail", "warn", "unknown", "pass", "n/a")


def org_domain(domain: str) -> str:
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "ac", "gov", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def aligned(a: str, b: str, strict: bool = False) -> bool:
    if not a or not b:
        return False
    return a.lower() == b.lower() if strict else org_domain(a) == org_domain(b)


def parse_auth_results(values: list[str]) -> dict:
    """Merge Authentication-Results headers into {'spf': (result, domain), 'dkim': [...], 'dmarc': ...}."""
    res: dict = {"spf": None, "dkim": [], "dmarc": None, "dmarc_policy": None, "authserv": ""}
    for v in values:
        text = " ".join(v.split())
        if not res["authserv"]:
            res["authserv"] = text.split(";", 1)[0].strip()
        for m in re.finditer(r"\bspf=(\w+)[^;]*?smtp\.mailfrom=([^\s;]+)", text, re.I):
            dom = m.group(2).rsplit("@", 1)[-1].strip("<>").lower()
            if res["spf"] is None or m.group(1).lower() == "pass":
                res["spf"] = (m.group(1).lower(), dom)
        for m in re.finditer(r"\bdkim=(\w+)[^;]*?header\.(?:d|i)=@?([^\s;]+)", text, re.I):
            res["dkim"].append((m.group(1).lower(), m.group(2).rsplit("@", 1)[-1].lower()))
        m = re.search(r"\bdmarc=(\w+)(?:\s*\(([^)]*)\))?[^;]*?header\.from=([^\s;]+)", text, re.I)
        if m:
            res["dmarc"] = (m.group(1).lower(), m.group(3).lower())
            pm = re.search(r"\bp=(\w+)", m.group(2) or "", re.I)
            if pm:
                res["dmarc_policy"] = pm.group(1).lower()
    return res


def dkim_signatures(msg) -> list[dict]:
    sigs = []
    for raw in msg.get_all("DKIM-Signature") or []:
        tags = {}
        for part in " ".join(str(raw).split()).split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        sigs.append(
            {
                "d": tags.get("d", "").lower(),
                "s": tags.get("s", ""),
                "h": [h.strip().lower() for h in tags.get("h", "").replace(" ", "").split(":") if h.strip()],
                "a": tags.get("a", ""),
            }
        )
    return sigs


def rule(rid: str, applies: str, title: str, status: str, evidence: str = "", fix: str = "") -> dict:
    return {"id": rid, "applies": applies, "title": title, "status": status, "evidence": evidence, "fix": fix}


def check(
    msg,
    kind: str = "marketing",
    spam_rate: float | None = None,
    daily_volume: int | None = None,
    dmarc_record: str | None = None,
) -> dict:
    rules: list[dict] = []
    froms = getaddresses(msg.get_all("From") or [])
    from_addr = froms[0][1].lower() if froms else ""
    from_dom = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else ""
    rp = getaddresses([str(msg.get("Return-Path") or "")])
    rp_dom = rp[0][1].rsplit("@", 1)[-1].lower() if rp and "@" in rp[0][1] else ""
    ar = parse_auth_results([str(v) for v in msg.get_all("Authentication-Results") or []])
    sigs = dkim_signatures(msg)
    bulk = daily_volume is None or daily_volume >= 5000
    bulk_label = "bulk" if daily_volume is None or bulk else "bulk (not you: under 5,000/day)"

    # --- SPF / DKIM -------------------------------------------------------------------
    spf = ar["spf"]
    if spf:
        rules.append(
            rule(
                "spf",
                "all senders",
                "SPF passes",
                "pass" if spf[0] == "pass" else "fail",
                f"spf={spf[0]} smtp.mailfrom={spf[1]}",
                "" if spf[0] == "pass" else f"authorise the sending IP in the SPF record of {spf[1]}",
            )
        )
    else:
        rules.append(
            rule(
                "spf",
                "all senders",
                "SPF passes",
                "unknown",
                "no Authentication-Results spf=",
                "check a copy received at Gmail/Yahoo (Show original)",
            )
        )
    dkim_pass = [d for r, d in ar["dkim"] if r == "pass"]
    if ar["dkim"]:
        rules.append(
            rule(
                "dkim",
                "all senders (bulk: required)",
                "DKIM passes",
                "pass" if dkim_pass else "fail",
                ", ".join(f"dkim={r} d={d}" for r, d in ar["dkim"]),
                "" if dkim_pass else "sign with a DKIM key published under your domain (1024-bit+, 2048 preferred)",
            )
        )
    elif sigs:
        rules.append(
            rule(
                "dkim",
                "all senders (bulk: required)",
                "DKIM passes",
                "unknown",
                "signed d=" + ",".join(s["d"] for s in sigs) + " but no verification result",
                "check a copy received at Gmail/Yahoo",
            )
        )
    else:
        rules.append(
            rule(
                "dkim",
                "all senders (bulk: required)",
                "DKIM passes",
                "fail",
                "no DKIM-Signature",
                "turn on DKIM signing at your ESP / MTA",
            )
        )
    # Gmail: all senders need SPF or DKIM; bulk senders need both.
    if spf and ar["dkim"]:
        both = spf[0] == "pass" and bool(dkim_pass)
        rules.append(
            rule(
                "spf-and-dkim",
                bulk_label,
                "both SPF and DKIM pass",
                "pass" if both else ("fail" if bulk else "warn"),
                f"spf={spf[0]}, dkim={'pass' if dkim_pass else 'fail'}",
                "" if both else "bulk senders must pass both",
            )
        )

    # --- DMARC + alignment --------------------------------------------------------------
    policy_val = ar["dmarc_policy"]
    if dmarc_record:
        m = re.search(r"\bp\s*=\s*(\w+)", dmarc_record, re.I)
        policy_val = m.group(1).lower() if m else None
    if policy_val in ("none", "quarantine", "reject"):
        rules.append(
            rule(
                "dmarc-record",
                bulk_label,
                "DMARC record published (p=none or stronger)",
                "pass",
                f"p={policy_val}",
                "" if policy_val != "none" else "p=none meets the rule; plan quarantine/reject",
            )
        )
    elif ar["dmarc"] and ar["dmarc"][0] in ("none",):
        rules.append(
            rule(
                "dmarc-record",
                bulk_label,
                "DMARC record published",
                "fail",
                "dmarc=none (no record)",
                f'TXT _dmarc.{from_dom} "v=DMARC1; p=none; rua=mailto:dmarc@{from_dom}"',
            )
        )
    else:
        rules.append(
            rule(
                "dmarc-record",
                bulk_label,
                "DMARC record published",
                "unknown",
                "no dmarc= result and no --dmarc",
                "pass --dmarc with the _dmarc TXT value",
            )
        )
    spf_aligned = bool(spf and spf[0] == "pass" and aligned(spf[1], from_dom))
    dkim_aligned = any(aligned(d, from_dom) for d in dkim_pass)
    if not ar["dkim"] and sigs:
        dkim_aligned_guess = any(aligned(s["d"], from_dom) for s in sigs)
    else:
        dkim_aligned_guess = dkim_aligned
    if ar["dmarc"] and ar["dmarc"][0] == "pass" or spf_aligned or dkim_aligned:
        status = "pass"
    elif ar["dmarc"] or spf or ar["dkim"]:
        status = "fail" if bulk else "warn"
    else:
        status = "unknown"
    dkim_shown = ",".join(dkim_pass) or ",".join(s["d"] for s in sigs) or "-"
    evidence = (
        f"From {from_dom or '?'}; SPF domain {spf[1] if spf else rp_dom or '?'} "
        f"({'aligned' if spf_aligned else 'not aligned'}); DKIM d={dkim_shown} "
        f"({'aligned' if dkim_aligned or dkim_aligned_guess else 'not aligned'})"
    )
    rules.append(
        rule(
            "alignment",
            bulk_label,
            "From domain aligned with SPF or DKIM (DMARC pass)",
            status,
            evidence + (f"; dmarc={ar['dmarc'][0]}" if ar["dmarc"] else ""),
            "" if status == "pass" else "sign DKIM with d= your From domain (or a subdomain) at your ESP",
        )
    )
    if from_dom in FREEMAIL:
        rules.append(
            rule(
                "freemail-from",
                "all senders",
                "From is your own domain, not a mailbox provider's",
                "fail",
                f"From: {from_addr}",
                "send from your own domain; Gmail/Yahoo/AOL DMARC policies reject this through an ESP",
            )
        )

    # --- Unsubscribe ---------------------------------------------------------------------
    lu = str(msg.get("List-Unsubscribe") or "")
    lup = str(msg.get("List-Unsubscribe-Post") or "")
    one_click = "https://" in lu.lower() and lup.replace(" ", "").lower() == "list-unsubscribe=one-click"
    if kind == "transactional":
        rules.append(
            rule(
                "one-click",
                "bulk, marketing/subscribed mail",
                "one-click unsubscribe (RFC 8058)",
                "n/a",
                "transactional message",
                "keep marketing content out of transactional mail",
            )
        )
    else:
        rules.append(
            rule(
                "one-click",
                "bulk, marketing/subscribed mail",
                "one-click unsubscribe: List-Unsubscribe <https://...> + List-Unsubscribe-Post",
                "pass" if one_click else ("fail" if bulk else "warn"),
                f"List-Unsubscribe: {lu[:80] or '-'}; List-Unsubscribe-Post: {lup or '-'}",
                "" if one_click else "add both headers; the https URL must accept a POST and unsubscribe without login",
            )
        )
        if one_click:
            signed = [s for s in sigs if "list-unsubscribe" in s["h"] and "list-unsubscribe-post" in s["h"]]
            rules.append(
                rule(
                    "one-click-signed",
                    "bulk, marketing/subscribed mail",
                    "DKIM signature covers List-Unsubscribe and List-Unsubscribe-Post (RFC 8058)",
                    "pass" if signed else ("warn" if not sigs else "fail"),
                    "h=" + ":".join(sigs[0]["h"]) if sigs else "no DKIM-Signature",
                    "" if signed else "add both headers to the DKIM h= list at your ESP/MTA",
                )
            )
        rules.append(
            rule(
                "unsubscribe-2-days",
                "bulk",
                "unsubscribes processed within 2 days",
                "unknown",
                "cannot be seen in a message",
                "test it: unsubscribe and confirm no mail after 48h",
            )
        )

    # --- Transport / format -------------------------------------------------------------
    received = [" ".join(str(r).split()) for r in msg.get_all("Received") or []]
    top = received[0] if received else ""
    if top:
        tls = bool(re.search(r"ESMTPS|ESMTPSA|version=TLS|TLSv1\.[23]|\(TLS", top, re.I))
        rules.append(
            rule(
                "tls",
                "all senders",
                "delivered over TLS",
                "pass" if tls else "fail",
                top[:120],
                "" if tls else "enable STARTTLS on the sending MTA",
            )
        )
        m = re.search(r"^from \S+ \((\S+?)\.? \[([0-9a-f:.]+)\]\)", top, re.I)
        if m:
            ptr_ok = m.group(1).lower() not in ("unknown", "")
            rules.append(
                rule(
                    "ptr",
                    "all senders",
                    "sending IP has reverse DNS (PTR) matching forward DNS",
                    "pass" if ptr_ok else "fail",
                    f"{m.group(1)} [{m.group(2)}]",
                    "" if ptr_ok else "ask your host/ESP to set a PTR that resolves back to the IP",
                )
            )
        else:
            rules.append(
                rule(
                    "ptr",
                    "all senders",
                    "sending IP has valid forward and reverse DNS",
                    "unknown",
                    "Received header has no rDNS detail",
                    "dig -x <sending IP>, then dig A <that name>",
                )
            )
    else:
        rules.append(
            rule(
                "tls",
                "all senders",
                "delivered over TLS",
                "unknown",
                "no Received headers",
                "use a copy received at the provider",
            )
        )
    missing = [h for h in ("From", "Date", "Message-ID") if not msg.get(h)]
    multi_from = len(msg.get_all("From") or []) > 1
    rules.append(
        rule(
            "rfc5322",
            "all senders",
            "RFC 5322 format: one From, Date, Message-ID",
            "fail" if missing or multi_from else "pass",
            ("missing " + ", ".join(missing) if missing else "") + ("; several From headers" if multi_from else ""),
            "" if not (missing or multi_from) else "fix the message headers",
        )
    )

    # --- Spam rate / volume -------------------------------------------------------------
    if spam_rate is None:
        rules.append(
            rule(
                "spam-rate",
                "all senders",
                "user-reported spam rate below 0.3% (aim < 0.1%)",
                "unknown",
                "pass --spam-rate from Google Postmaster Tools / Yahoo Sender Hub",
                "register your domain in Postmaster Tools",
            )
        )
    else:
        st = "pass" if spam_rate < 0.1 else ("warn" if spam_rate < 0.3 else "fail")
        rules.append(
            rule(
                "spam-rate",
                "all senders",
                "user-reported spam rate below 0.3% (aim < 0.1%)",
                st,
                f"{spam_rate}%",
                "" if st == "pass" else "cut unengaged recipients, fix consent, lower frequency",
            )
        )

    rules.sort(key=lambda r: STATUS_ORDER.index(r["status"]))
    counts = {s: sum(1 for r in rules if r["status"] == s) for s in STATUS_ORDER}
    return {
        "from_domain": from_dom,
        "type": kind,
        "bulk_assumed": daily_volume is None,
        "rules": rules,
        "counts": counts,
    }


def render(report: dict) -> str:
    lines = [f"Sender requirements check for {report['from_domain'] or '?'} ({report['type']})"]
    if report["bulk_assumed"]:
        lines.append("(daily volume not given: bulk-sender rules applied)")
    for r in report["rules"]:
        lines.append(f"[{r['status'].upper():7}] {r['title']}  ({r['applies']})")
        if r["evidence"]:
            lines.append(f"           evidence: {r['evidence']}")
        if r["fix"] and r["status"] != "pass":
            lines.append(f"           fix: {r['fix']}")
    c = report["counts"]
    lines.append(f"{c['fail']} fail, {c['warn']} warn, {c['unknown']} unknown, {c['pass']} pass")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Check a received message against Gmail/Yahoo/Outlook.com sender requirements.",
        epilog="Example: sender_check.py original.eml --spam-rate 0.08 --daily-volume 20000",
    )
    p.add_argument("eml", help="message as received (.eml), or - for stdin")
    p.add_argument("--type", choices=("marketing", "transactional"), default="marketing")
    p.add_argument("--spam-rate", type=float, help="user-reported spam rate in %% (Postmaster Tools)")
    p.add_argument("--daily-volume", type=int, help="messages per day to personal Gmail/Yahoo/Outlook accounts")
    p.add_argument("--dmarc", help="the _dmarc TXT value of the From domain")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)
    try:
        if args.eml == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(args.eml, "rb") as fh:
                raw = fh.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    if not msg.keys():
        print("error: input has no message headers", file=sys.stderr)
        return 2
    report = check(msg, args.type, args.spam_rate, args.daily_volume, args.dmarc)
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 1 if report["counts"]["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
