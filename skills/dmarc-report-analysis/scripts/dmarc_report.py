#!/usr/bin/env python3
"""Summarise DMARC aggregate (RUA) reports: sources, volumes, SPF/DKIM alignment, failures.

Reads .xml, .xml.gz, .gz and .zip files (or directories of them) exactly as mailbox
providers send them. Works offline; nothing is uploaded anywhere.

A row passes DMARC when the DKIM or SPF result in policy_evaluated is "pass" (that result
already includes identifier alignment). Sources are grouped by IP, by reporting org and by
header_from domain, and each failing source is labelled with a likely cause.

Exit codes: 0 = ok, 1 = DMARC failure rate above --max-fail-pct, 2 = input error.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import io
import ipaddress
import json
import socket
import sys
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 50 * 1024 * 1024  # refuse to decompress more than this per report


class ReportError(ValueError):
    pass


def _read_limited(fh, name: str) -> bytes:
    data = fh.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ReportError(f"{name}: larger than {MAX_BYTES // (1024 * 1024)} MB after decompression")
    return data


def read_report_blobs(path: Path) -> list[tuple[str, bytes]]:
    """Return [(name, xml_bytes)] for one file; zip files may hold several reports."""
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
            return [(path.name, _read_limited(fh, path.name))]
    if raw[:4] == b"PK\x03\x04":
        out = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".xml"):
                    continue
                if info.file_size > MAX_BYTES:
                    raise ReportError(f"{path.name}:{info.filename}: too large")
                with zf.open(info) as fh:
                    out.append((f"{path.name}:{info.filename}", _read_limited(fh, info.filename)))
        return out
    return [(path.name, raw)]


def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _text(el: ET.Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def parse_report(name: str, data: bytes) -> dict:
    head = data[:2048].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        raise ReportError(f"{name}: DOCTYPE/ENTITY declarations are not allowed")
    try:
        root = _strip_ns(ET.fromstring(data))
    except ET.ParseError as exc:
        raise ReportError(f"{name}: not valid XML ({exc})") from exc
    if root.tag != "feedback":
        raise ReportError(f"{name}: root element is <{root.tag}>, expected <feedback>")
    meta = root.find("report_metadata")
    policy = root.find("policy_published")
    begin = _text(meta, "date_range/begin", "0")
    end = _text(meta, "date_range/end", "0")
    report = {
        "file": name,
        "org": _text(meta, "org_name", "unknown"),
        "report_id": _text(meta, "report_id"),
        "begin": int(begin) if begin.isdigit() else 0,
        "end": int(end) if end.isdigit() else 0,
        "policy": {
            k: _text(policy, k)
            for k in ("domain", "adkim", "aspf", "p", "sp", "np", "pct", "testing")
            if _text(policy, k)
        },
        "records": [],
    }
    for rec in root.findall("record"):
        row = rec.find("row")
        count_txt = _text(row, "count", "0")
        dkim_results = [
            {
                "domain": _text(d, "domain").lower(),
                "selector": _text(d, "selector"),
                "result": _text(d, "result").lower(),
            }
            for d in rec.findall("auth_results/dkim")
        ]
        spf_results = [
            {"domain": _text(s, "domain").lower(), "result": _text(s, "result").lower()}
            for s in rec.findall("auth_results/spf")
        ]
        reasons = [_text(r, "type").lower() for r in rec.findall("row/policy_evaluated/reason")]
        report["records"].append(
            {
                "source_ip": _text(row, "source_ip"),
                "count": int(count_txt) if count_txt.isdigit() else 0,
                "disposition": _text(row, "policy_evaluated/disposition", "none").lower(),
                "dkim": _text(row, "policy_evaluated/dkim").lower(),
                "spf": _text(row, "policy_evaluated/spf").lower(),
                "reasons": [r for r in reasons if r],
                "header_from": _text(rec, "identifiers/header_from").lower(),
                "envelope_from": _text(rec, "identifiers/envelope_from").lower(),
                "dkim_results": dkim_results,
                "spf_results": spf_results,
            }
        )
    return report


def collect(paths: list[str]) -> tuple[list[dict], list[str]]:
    reports, errors = [], []
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files += sorted(f for f in path.rglob("*") if f.is_file() and not f.name.startswith("."))
        elif path.is_file():
            files.append(path)
        else:
            errors.append(f"{p}: not found")
    seen_ids = set()
    for f in files:
        try:
            for name, blob in read_report_blobs(f):
                rep = parse_report(name, blob)
                key = (rep["org"], rep["report_id"])
                if rep["report_id"] and key in seen_ids:
                    continue  # the same report delivered twice
                seen_ids.add(key)
                reports.append(rep)
        except (ReportError, OSError, zipfile.BadZipFile, EOFError, gzip.BadGzipFile) as exc:
            errors.append(str(exc))
    return reports, errors


def classify(rec: dict, own_domains: set[str]) -> str:
    """Short reason a row failed DMARC (or 'pass')."""
    if rec["dkim"] == "pass" or rec["spf"] == "pass":
        return "pass"
    reasons = set(rec["reasons"])
    if "forwarded" in reasons or "mailing_list" in reasons:
        return "forwarded / mailing list"
    hf = rec["header_from"]
    dkim_pass_other = [d for d in rec["dkim_results"] if d["result"] == "pass" and d["domain"] != hf]
    spf_pass_other = [s for s in rec["spf_results"] if s["result"] == "pass" and s["domain"] != hf]
    if any(d["result"] == "pass" for d in rec["dkim_results"]) and not dkim_pass_other:
        return "dkim pass but not aligned"
    if dkim_pass_other or spf_pass_other:
        doms = sorted({d["domain"] for d in dkim_pass_other} | {s["domain"] for s in spf_pass_other})
        if own_domains and any(d in own_domains or d.endswith(tuple("." + o for o in own_domains)) for d in doms):
            return "own service, not aligned (fix DKIM d= or Return-Path)"
        return "third-party service authenticating as " + ", ".join(doms[:3])
    if rec["dkim_results"] and all(d["result"] in ("fail", "permerror", "temperror") for d in rec["dkim_results"]):
        if any(s["result"] == "pass" for s in rec["spf_results"]):
            return "forwarded (dkim broken, spf of forwarder)"
        return "dkim signature failed"
    return "unauthenticated (spoofing or unconfigured sender)"


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def summarise(
    reports: list[dict],
    own_domains: set[str] | None = None,
    known_ips: list[str] | None = None,
    top: int = 15,
    resolve: bool = False,
) -> dict:
    own_domains = {d.lower() for d in (own_domains or set())}
    nets = []
    for k in known_ips or []:
        try:
            nets.append(ipaddress.ip_network(k, strict=False))
        except ValueError:
            continue
    total = passed = 0
    dkim_aligned = spf_aligned = both = 0
    disp = defaultdict(int)
    by_source: dict[str, dict] = {}
    by_org = defaultdict(lambda: {"messages": 0, "pass": 0, "reports": 0})
    by_from = defaultdict(lambda: {"messages": 0, "pass": 0})
    policies = {}
    begin = min((r["begin"] for r in reports if r["begin"]), default=0)
    end = max((r["end"] for r in reports), default=0)
    for rep in reports:
        by_org[rep["org"]]["reports"] += 1
        if rep["policy"].get("domain"):
            policies[rep["policy"]["domain"]] = rep["policy"]
        for rec in rep["records"]:
            n = rec["count"]
            ok = rec["dkim"] == "pass" or rec["spf"] == "pass"
            total += n
            passed += n if ok else 0
            dkim_aligned += n if rec["dkim"] == "pass" else 0
            spf_aligned += n if rec["spf"] == "pass" else 0
            both += n if rec["dkim"] == "pass" and rec["spf"] == "pass" else 0
            disp[rec["disposition"]] += n
            by_org[rep["org"]]["messages"] += n
            by_org[rep["org"]]["pass"] += n if ok else 0
            by_from[rec["header_from"]]["messages"] += n
            by_from[rec["header_from"]]["pass"] += n if ok else 0
            src = by_source.setdefault(
                rec["source_ip"],
                {
                    "source_ip": rec["source_ip"],
                    "messages": 0,
                    "pass": 0,
                    "dkim_aligned": 0,
                    "spf_aligned": 0,
                    "header_from": set(),
                    "auth_domains": set(),
                    "causes": defaultdict(int),
                    "reporters": set(),
                },
            )
            src["messages"] += n
            src["pass"] += n if ok else 0
            src["dkim_aligned"] += n if rec["dkim"] == "pass" else 0
            src["spf_aligned"] += n if rec["spf"] == "pass" else 0
            src["header_from"].add(rec["header_from"])
            src["reporters"].add(rep["org"])
            src["auth_domains"].update(
                d["domain"] for d in rec["dkim_results"] + rec["spf_results"] if d["result"] == "pass" and d["domain"]
            )
            src["causes"][classify(rec, own_domains)] += n

    sources = []
    for src in by_source.values():
        fail = src["messages"] - src["pass"]
        ip = src["source_ip"]
        known = False
        with contextlib.suppress(ValueError):
            known = any(ipaddress.ip_address(ip) in net for net in nets)
        item = {
            "source_ip": ip,
            "messages": src["messages"],
            "pass": src["pass"],
            "fail": fail,
            "pass_pct": round(100.0 * src["pass"] / src["messages"], 1) if src["messages"] else 0.0,
            "dkim_aligned": src["dkim_aligned"],
            "spf_aligned": src["spf_aligned"],
            "header_from": sorted(src["header_from"]),
            "auth_domains": sorted(src["auth_domains"]),
            "main_cause": max(src["causes"].items(), key=lambda kv: kv[1])[0],
            "known": known,
            "reporters": sorted(src["reporters"]),
        }
        if resolve and not is_private(ip):
            try:
                item["ptr"] = socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                item["ptr"] = None
        sources.append(item)
    sources.sort(key=lambda s: (-s["messages"], s["source_ip"]))
    failing = sorted((s for s in sources if s["fail"]), key=lambda s: (-s["fail"], s["source_ip"]))
    pct = lambda a, b: round(100.0 * a / b, 2) if b else 0.0  # noqa: E731
    return {
        "reports": len(reports),
        "period": {
            "begin": _iso(begin),
            "end": _iso(end),
        },
        "policies": policies,
        "messages": total,
        "dmarc_pass": passed,
        "dmarc_fail": total - passed,
        "pass_pct": pct(passed, total),
        "fail_pct": pct(total - passed, total),
        "dkim_aligned_pct": pct(dkim_aligned, total),
        "spf_aligned_pct": pct(spf_aligned, total),
        "both_aligned_pct": pct(both, total),
        "spf_only_pass_pct": pct(passed - dkim_aligned, total),
        "dispositions": dict(sorted(disp.items())),
        "by_reporter": {k: dict(v, pass_pct=pct(v["pass"], v["messages"])) for k, v in sorted(by_org.items())},
        "by_header_from": {k: dict(v, pass_pct=pct(v["pass"], v["messages"])) for k, v in sorted(by_from.items())},
        "top_sources": sources[:top],
        "failing_sources": failing[:top],
        "unknown_failing_sources": [s for s in failing if not s["known"]][:top] if nets else [],
    }


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else ""


def render(s: dict, errors: list[str]) -> str:
    out = [
        f"DMARC aggregate summary: {s['reports']} report(s), {s['period']['begin']} -> {s['period']['end']}",
    ]
    for dom, pol in s["policies"].items():
        out.append(
            f"Policy {dom}: p={pol.get('p', '?')} sp={pol.get('sp', '-')} pct={pol.get('pct', '100')} "
            f"adkim={pol.get('adkim', 'r')} aspf={pol.get('aspf', 'r')}"
        )
    out.append(
        f"Messages {s['messages']:,}: DMARC pass {s['pass_pct']}%, fail {s['fail_pct']}% "
        f"(DKIM aligned {s['dkim_aligned_pct']}%, SPF aligned {s['spf_aligned_pct']}%)"
    )
    if s["spf_only_pass_pct"]:
        out.append(f"  {s['spf_only_pass_pct']}% passes on SPF alone (breaks when forwarded: add aligned DKIM)")
    out.append("Dispositions: " + ", ".join(f"{k}={v:,}" for k, v in s["dispositions"].items()))
    out.append("")
    out.append("By reporter:")
    for org, v in s["by_reporter"].items():
        out.append(f"  {org:30} {v['messages']:>9,}  pass {v['pass_pct']}%")
    out.append("")
    out.append("Top sources (IP, messages, pass %, DKIM/SPF aligned, auth domains):")
    for src in s["top_sources"]:
        tag = " [known]" if src["known"] else ""
        ptr = f" ({src['ptr']})" if src.get("ptr") else ""
        out.append(
            f"  {src['source_ip']:39}{ptr} {src['messages']:>8,}  {src['pass_pct']:>5}%  "
            f"dkim {src['dkim_aligned']:,} spf {src['spf_aligned']:,}  {', '.join(src['auth_domains']) or '-'}{tag}"
        )
    if s["failing_sources"]:
        out.append("")
        out.append("Failing sources (most failures first):")
        for src in s["failing_sources"]:
            out.append(f"  {src['source_ip']:39} {src['fail']:>8,} failed  cause: {src['main_cause']}")
    for e in errors:
        out.append(f"warning: {e}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Summarise DMARC aggregate reports (.xml, .gz, .zip, or directories).",
        epilog="Example: dmarc_report.py ~/dmarc-reports/ --domain example.com --max-fail-pct 2",
    )
    p.add_argument("paths", nargs="+", help="report files or directories")
    p.add_argument(
        "--domain",
        action="append",
        default=[],
        help="your own domain(s); helps label 'own service, not aligned' (repeatable)",
    )
    p.add_argument("--known-ip", action="append", default=[], help="IP or CIDR of a known sender (repeatable)")
    p.add_argument("--top", type=int, default=15, help="rows per table (default 15)")
    p.add_argument("--resolve", action="store_true", help="reverse-DNS each source IP (network)")
    p.add_argument("--max-fail-pct", type=float, help="exit 1 when DMARC failure %% is above this")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)
    reports, errors = collect(args.paths)
    if not reports:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print("error: no DMARC reports could be read", file=sys.stderr)
        return 2
    summary = summarise(reports, set(args.domain), args.known_ip, args.top, args.resolve)
    if args.json:
        print(json.dumps(dict(summary, errors=errors), indent=2))
    else:
        print(render(summary, errors))
    if args.max_fail_pct is not None and summary["fail_pct"] > args.max_fail_pct:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
