#!/usr/bin/env python3
"""Audit SPF, DKIM, DMARC, BIMI, MTA-STS and TLS-RPT records for a sending domain.

Works offline from record text (--spf, --dmarc, --dkim ...) or a JSON file of DNS records
(--records). With --live it asks `dig` for the records (opt-in network access).

Records JSON (either shape):
  {"example.com": {"TXT": ["v=spf1 ..."], "MX": ["10 mx.example.com"]},
   "_dmarc.example.com": {"TXT": ["v=DMARC1; p=none"]}}
  [{"name": "example.com", "type": "TXT", "value": "v=spf1 ..."}, ...]

SPF lookups are counted recursively through include: and redirect= when the included
domains' TXT records are in the JSON (or with --live); otherwise they are reported as
unresolved and counted as one lookup each.

Exit codes: 0 = no high/medium findings, 1 = findings, 2 = usage or input error.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import shutil
import subprocess
import sys

SEVERITIES = ("high", "medium", "low", "info")
SPF_LOOKUP_LIMIT = 10
SPF_VOID_LIMIT = 2
LOOKUP_MECHS = {"include", "a", "mx", "ptr", "exists"}
ALL_MECHS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
DMARC_TAGS = {"v", "p", "sp", "np", "rua", "ruf", "adkim", "aspf", "pct", "fo", "rf", "ri", "t", "psd"}
MTA_STS_MAX_AGE = 31557600


def finding(sev: str, area: str, title: str, fix: str = "") -> dict:
    return {"severity": sev, "area": area, "title": title, "fix": fix}


# --------------------------------------------------------------------------- records


class Records:
    """DNS lookups backed by a dict and, optionally, by `dig`."""

    def __init__(self, data: dict | None = None, live: bool = False, timeout: int = 5):
        self.data: dict[str, dict[str, list[str]]] = {}
        self.live = live
        self.timeout = timeout
        for name, types in (data or {}).items():
            for rtype, values in types.items():
                self.add(name, rtype, values)

    def add(self, name: str, rtype: str, values) -> None:
        if isinstance(values, str):
            values = [values]
        bucket = self.data.setdefault(name.lower().rstrip("."), {}).setdefault(rtype.upper(), [])
        bucket.extend(str(v) for v in values)

    def known(self, name: str, rtype: str = "TXT") -> bool:
        return rtype.upper() in self.data.get(name.lower().rstrip("."), {})

    def get(self, name: str, rtype: str = "TXT") -> list[str] | None:
        """Return values, [] when the name is known to have none, None when unknown."""
        key = name.lower().rstrip(".")
        if self.known(key, rtype):
            return [_join_txt(v) if rtype.upper() == "TXT" else v for v in self.data[key][rtype.upper()]]
        if self.live:
            values = dig(key, rtype, self.timeout)
            self.add(key, rtype, values)
            return values
        return None


def _join_txt(value: str) -> str:
    """Join dig-style quoted chunks: '"v=spf1 " "-all"' -> 'v=spf1 -all'."""
    v = value.strip()
    if v.startswith('"'):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', v)
        return "".join(p.replace('\\"', '"') for p in parts)
    return v


def dig(name: str, rtype: str, timeout: int = 5) -> list[str]:
    if not shutil.which("dig"):
        raise RuntimeError("--live needs the 'dig' command (dnsutils / bind-utils)")
    out = subprocess.run(
        ["dig", "+short", f"+time={timeout}", "+tries=2", rtype, name],
        capture_output=True,
        text=True,
        timeout=timeout * 3,
        check=False,
    )
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip() and not ln.startswith(";")]
    if rtype.upper() == "TXT":
        return [_join_txt(ln) for ln in lines]
    return lines


def load_records(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        out: dict = {}
        for item in raw:
            if not isinstance(item, dict) or not {"name", "type"} <= set(item):
                raise ValueError("list entries need 'name', 'type' and 'value' (or 'content')")
            value = item.get("value", item.get("content", ""))
            out.setdefault(item["name"], {}).setdefault(item["type"].upper(), []).append(value)
        return out
    raise ValueError("records JSON must be an object or a list")


# --------------------------------------------------------------------------- SPF


def spf_records(txts: list[str]) -> list[str]:
    return [t for t in txts if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def parse_spf(record: str) -> list[dict]:
    terms = []
    for raw in record.split()[1:]:
        m = re.match(r"^([+\-~?]?)([a-zA-Z][a-zA-Z0-9_.-]*)(?:([:=/])(.*))?$", raw)
        if not m:
            terms.append({"raw": raw, "qualifier": "", "name": "", "value": None, "valid": False})
            continue
        qual, name, sep, value = m.group(1) or "+", m.group(2).lower(), m.group(3), m.group(4)
        if sep == "/":
            value = "/" + (value or "")
        kind = "modifier" if sep == "=" else "mechanism"
        terms.append({"raw": raw, "qualifier": qual, "name": name, "value": value, "kind": kind, "valid": True})
    return terms


def count_spf_lookups(domain: str, records: Records, seen: frozenset | None = None, depth: int = 0) -> dict:
    """Return {'lookups', 'void', 'unresolved', 'tree', 'errors'} for domain's SPF policy."""
    seen = frozenset() if seen is None else seen
    result = {"lookups": 0, "void": 0, "unresolved": [], "tree": [], "errors": []}
    key = domain.lower()
    if key in seen or depth > 12:
        result["errors"].append(f"include loop at {domain}")
        return result
    seen = seen | {key}
    txts = records.get(domain, "TXT")
    if txts is None:
        result["unresolved"].append(domain)
        return result
    found = spf_records(txts)
    if not found:
        result["void"] += 1
        result["errors"].append(f"{domain} has no SPF record")
        return result
    if len(found) > 1:
        result["errors"].append(f"{domain} has {len(found)} SPF records (permerror)")
    for term in parse_spf(found[0]):
        if not term["valid"]:
            continue
        name = term["name"]
        if name in LOOKUP_MECHS or (term["kind"] == "modifier" and name == "redirect"):
            result["lookups"] += 1
            target = term["value"] or domain
            if name in ("include", "redirect") and term["value"]:
                if "%{" in target:
                    result["unresolved"].append(target)
                    continue
                sub = count_spf_lookups(target, records, seen, depth + 1)
                result["lookups"] += sub["lookups"]
                result["void"] += sub["void"]
                result["unresolved"] += sub["unresolved"]
                result["errors"] += sub["errors"]
                result["tree"].append({"term": term["raw"], "lookups": 1 + sub["lookups"]})
            else:
                result["tree"].append({"term": term["raw"], "lookups": 1})
    return result


def audit_spf(domain: str, txts: list[str] | None, records: Records) -> tuple[list[dict], dict]:
    out: list[dict] = []
    info: dict = {}
    if txts is None:
        return [finding("info", "spf", "SPF not checked (no TXT data for the domain)")], info
    found = spf_records(txts)
    if not found:
        out.append(
            finding(
                "high",
                "spf",
                "no SPF record",
                f'publish a TXT record on {domain}, e.g. "v=spf1 include:<your ESP> -all"',
            )
        )
        return out, info
    if len(found) > 1:
        out.append(
            finding(
                "high",
                "spf",
                f"{len(found)} SPF records published (receivers return permerror)",
                "merge them into one v=spf1 record",
            )
        )
    record = found[0]
    info["record"] = record
    terms = parse_spf(record)
    seen_all = False
    for t in terms:
        if not t["valid"]:
            out.append(finding("high", "spf", f"cannot parse SPF term '{t['raw']}' (permerror)", "fix the typo"))
            continue
        if seen_all and t["kind"] == "mechanism":
            out.append(finding("low", "spf", f"'{t['raw']}' after 'all' is never evaluated", "move it before all"))
        if t["kind"] == "mechanism" and t["name"] not in ALL_MECHS:
            out.append(finding("high", "spf", f"unknown mechanism '{t['raw']}' (permerror)", "remove or correct it"))
        if t["name"] == "all":
            seen_all = True
            if t["qualifier"] == "+":
                out.append(finding("high", "spf", "'+all' authorises every server on the internet", "use -all or ~all"))
            elif t["qualifier"] == "?":
                out.append(finding("medium", "spf", "'?all' is neutral: SPF protects nothing", "use ~all or -all"))
        if t["name"] == "ptr":
            out.append(finding("low", "spf", "'ptr' is deprecated (RFC 7208) and slow", "use ip4/ip6 or include"))
        if t["name"] in ("ip4", "ip6") and t["value"]:
            try:
                net = ipaddress.ip_network(t["value"], strict=False)
                if net.version != int(t["name"][-1]):
                    raise ValueError
                if net.prefixlen < (16 if net.version == 4 else 32):
                    out.append(finding("medium", "spf", f"very broad range {t['raw']}", "list only your sending IPs"))
            except ValueError:
                out.append(finding("high", "spf", f"invalid address in '{t['raw']}'", "fix the IP or CIDR"))
    has_redirect = any(t.get("kind") == "modifier" and t["name"] == "redirect" for t in terms)
    if not seen_all and not has_redirect:
        out.append(
            finding(
                "medium",
                "spf",
                "no 'all' mechanism (defaults to neutral)",
                "end the record with ~all or -all",
            )
        )
    if len(record) > 255:
        out.append(
            finding(
                "low",
                "spf",
                f"record is {len(record)} chars; one TXT string holds 255",
                "split it into several quoted strings in one record, or trim includes",
            )
        )
    counts = count_spf_lookups(domain, records)
    info.update(
        {
            "lookups": counts["lookups"],
            "void_lookups": counts["void"],
            "unresolved": counts["unresolved"],
            "tree": counts["tree"],
        }
    )
    for err in counts["errors"]:
        if not err.startswith(f"{domain} "):
            out.append(finding("high", "spf", err, "remove or fix that include"))
    if counts["lookups"] > SPF_LOOKUP_LIMIT:
        out.append(
            finding(
                "high",
                "spf",
                f"{counts['lookups']} DNS lookups (limit {SPF_LOOKUP_LIMIT}, permerror)",
                "remove unused includes, replace a/mx with ip4/ip6, or use a subdomain per ESP",
            )
        )
    elif counts["lookups"] >= 8:
        out.append(
            finding("low", "spf", f"{counts['lookups']} DNS lookups (limit 10): little headroom", "trim includes")
        )
    if counts["void"] > SPF_VOID_LIMIT:
        out.append(finding("high", "spf", f"{counts['void']} void lookups (limit 2)", "remove dead includes"))
    if counts["unresolved"]:
        out.append(
            finding(
                "info",
                "spf",
                "lookups not counted for: " + ", ".join(sorted(set(counts["unresolved"]))),
                "add their TXT records to the JSON or use --live for an exact count",
            )
        )
    return out, info


# --------------------------------------------------------------------------- DMARC


def parse_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def org_domain(domain: str) -> str:
    """Approximate organisational domain (last two labels, three for common 2-level TLDs)."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "ac", "gov", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def audit_dmarc(domain: str, txts: list[str] | None) -> tuple[list[dict], dict]:
    out: list[dict] = []
    if txts is None:
        return [finding("info", "dmarc", f"DMARC not checked (no TXT data for _dmarc.{domain})")], {}
    found = [t for t in txts if t.replace(" ", "").lower().startswith("v=dmarc1")]
    if not found:
        return [
            finding(
                "high",
                "dmarc",
                "no DMARC record (required by Gmail, Yahoo and Outlook.com for bulk senders)",
                f'TXT _dmarc.{domain} "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"',
            )
        ], {}
    if len(found) > 1:
        out.append(finding("high", "dmarc", "more than one DMARC record (ignored by receivers)", "keep one"))
    record = found[0]
    tags = parse_tags(record)
    info = {"record": record, "tags": tags}
    if not record.strip().startswith("v=DMARC1"):
        out.append(finding("high", "dmarc", "record must start with exactly 'v=DMARC1'", "put v=DMARC1 first"))
    for k in tags:
        if k not in DMARC_TAGS:
            out.append(finding("low", "dmarc", f"unknown tag '{k}'", "remove it or fix the spelling"))
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        out.append(
            finding(
                "high",
                "dmarc",
                f"invalid or missing p= ({tags.get('p', 'missing')})",
                "set p=none, quarantine or reject",
            )
        )
    elif p == "none":
        out.append(
            finding(
                "medium",
                "dmarc",
                "p=none: monitoring only, spoofed mail is still delivered",
                "review reports, then move to p=quarantine and p=reject",
            )
        )
    for tag in ("sp", "np"):
        if tag in tags and tags[tag].lower() not in ("none", "quarantine", "reject"):
            out.append(finding("high", "dmarc", f"invalid {tag}={tags[tag]}", "use none, quarantine or reject"))
    if p in ("quarantine", "reject") and tags.get("sp", "").lower() == "none":
        out.append(finding("low", "dmarc", "sp=none leaves subdomains spoofable", "remove sp or raise it"))
    for tag in ("adkim", "aspf"):
        if tag in tags and tags[tag].lower() not in ("r", "s"):
            out.append(finding("high", "dmarc", f"invalid {tag}={tags[tag]}", "use r (relaxed) or s (strict)"))
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
            if not 0 <= pct <= 100:
                raise ValueError
            if pct < 100:
                out.append(finding("low", "dmarc", f"pct={pct}: policy applies to part of the mail", "raise to 100"))
        except ValueError:
            out.append(finding("high", "dmarc", f"invalid pct={tags['pct']}", "use an integer 0-100"))
    rua = tags.get("rua", "")
    if not rua:
        out.append(
            finding(
                "medium",
                "dmarc",
                "no rua=: you get no aggregate reports",
                f"add rua=mailto:dmarc-reports@{domain} (or your DMARC tool's address)",
            )
        )
    for uri in [u.strip() for u in (rua + "," + tags.get("ruf", "")).split(",") if u.strip()]:
        if not re.match(r"^(mailto:[^@\s]+@[^@\s!]+|https?://\S+)(![0-9]+[kmgt]?)?$", uri, re.I):
            out.append(finding("high", "dmarc", f"invalid report URI '{uri}'", "use mailto:addr@domain"))
            continue
        if uri.lower().startswith("mailto:"):
            dest = uri.split("@", 1)[1].split("!")[0].lower()
            if org_domain(dest) != org_domain(domain):
                out.append(
                    finding(
                        "info",
                        "dmarc",
                        f"reports go to another domain ({dest})",
                        f'{dest} must publish TXT {domain}._report._dmarc.{dest} "v=DMARC1"',
                    )
                )
    return out, info


# --------------------------------------------------------------------------- DKIM


def _der_len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    return int.from_bytes(data[i + 1 : i + 1 + n], "big"), i + 1 + n


def _der_items(data: bytes) -> list[tuple[int, bytes]]:
    items = []
    i = 0
    while i < len(data):
        tag = data[i]
        length, start = _der_len(data, i + 1)
        items.append((tag, data[start : start + length]))
        i = start + length
    return items


def rsa_key_bits(der: bytes) -> int | None:
    """Modulus size of an RSA SubjectPublicKeyInfo or PKCS#1 RSAPublicKey, else None."""
    try:
        top = _der_items(der)
        if not top or top[0][0] != 0x30:
            return None
        inner = _der_items(top[0][1])
        if len(inner) >= 2 and inner[0][0] == 0x30 and inner[1][0] == 0x03:  # SPKI
            rsa = _der_items(inner[1][1][1:])  # skip the unused-bits byte
            if not rsa or rsa[0][0] != 0x30:
                return None
            inner = _der_items(rsa[0][1])
        if len(inner) >= 2 and inner[0][0] == 0x02:
            modulus = inner[0][1].lstrip(b"\x00")
            return len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else None
    except (IndexError, ValueError):
        return None
    return None


def audit_dkim(selector: str, domain: str, txts: list[str] | None) -> tuple[list[dict], dict]:
    area = f"dkim:{selector}"
    name = f"{selector}._domainkey.{domain}"
    if txts is None:
        return [finding("info", area, f"{name} not checked (no data)")], {}
    found = [t for t in txts if "p=" in t.replace(" ", "")]
    if not found:
        return [finding("high", area, f"no DKIM key at {name}", "publish the key your ESP gives you")], {}
    tags = parse_tags(re.sub(r"\s", "", found[0]))
    out: list[dict] = []
    info: dict = {"name": name, "k": tags.get("k", "rsa")}
    if "v" in tags and tags["v"] != "DKIM1":
        out.append(finding("high", area, f"v={tags['v']} (must be DKIM1)", "set v=DKIM1 or drop it"))
    if not tags.get("p"):
        out.append(finding("info", area, "empty p=: this key is revoked", "remove the selector if unused"))
        return out, info
    if "y" in tags.get("t", "").split(":"):
        out.append(finding("low", area, "t=y testing flag set", "remove t=y once signing works"))
    if tags.get("h") and "sha256" not in tags["h"]:
        out.append(finding("medium", area, f"h={tags['h']} excludes sha256", "allow sha256"))
    try:
        der = base64.b64decode(re.sub(r"\s", "", tags["p"]), validate=True)
    except (ValueError, base64.binascii.Error):
        out.append(finding("high", area, "p= is not valid base64", "re-copy the key without quotes or line breaks"))
        return out, info
    if info["k"] == "ed25519":
        info["bits"] = 256
        out.append(finding("info", area, "ed25519 key: also sign with RSA, many receivers ignore ed25519", "dual-sign"))
        return out, info
    bits = rsa_key_bits(der)
    info["bits"] = bits
    if bits is None:
        out.append(finding("high", area, "p= is not a valid RSA public key", "re-copy the key from your ESP"))
    elif bits < 1024:
        out.append(finding("high", area, f"{bits}-bit RSA key (Gmail requires 1024+)", "rotate to 2048-bit"))
    elif bits < 2048:
        out.append(finding("low", area, f"{bits}-bit RSA key", "rotate to a 2048-bit key when convenient"))
    return out, info


# --------------------------------------------------------------------------- BIMI / MTA-STS / TLS-RPT / MX


def audit_bimi(domain: str, txts: list[str] | None, dmarc_tags: dict) -> list[dict]:
    if txts is None:
        return []
    found = [t for t in txts if t.replace(" ", "").lower().startswith("v=bimi1")]
    if not found:
        return [finding("info", "bimi", "no BIMI record (optional brand logo)", "see references/records.md")]
    out: list[dict] = []
    tags = parse_tags(found[0])
    logo = tags.get("l", "")
    if logo and not (logo.lower().startswith("https://") and logo.lower().endswith(".svg")):
        out.append(finding("high", "bimi", "l= must be an https URL to an SVG Tiny PS file", "fix l="))
    if not tags.get("a"):
        out.append(
            finding("info", "bimi", "no a= certificate (VMC/CMC): Gmail and Apple Mail will not show the logo", "")
        )
    p = dmarc_tags.get("p", "").lower()
    pct = dmarc_tags.get("pct", "100")
    if p not in ("quarantine", "reject") or pct != "100" or dmarc_tags.get("sp", "").lower() == "none":
        out.append(
            finding(
                "medium",
                "bimi",
                "BIMI needs DMARC p=quarantine or p=reject at pct=100 (and sp not none)",
                "enforce DMARC first",
            )
        )
    return out


def parse_mta_sts_policy(text: str) -> dict:
    policy: dict = {"mx": []}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = (s.strip() for s in line.split(":", 1))
        if k == "mx":
            policy["mx"].append(v.lower())
        else:
            policy[k] = v
    return policy


def mx_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return host == pattern.rstrip(".")


def audit_mta_sts(
    domain: str,
    txts: list[str] | None,
    policy_text: str | None,
    mx_hosts: list[str],
    tlsrpt: list[str] | None,
) -> list[dict]:
    out: list[dict] = []
    if txts is None:
        return out
    found = [t for t in txts if t.replace(" ", "").lower().startswith("v=stsv1")]
    if not found:
        out.append(
            finding("info", "mta-sts", "no MTA-STS (inbound TLS not enforced)", "optional: references/records.md")
        )
    else:
        tags = parse_tags(found[0])
        if not re.match(r"^[A-Za-z0-9]{1,32}$", tags.get("id", "")):
            out.append(finding("high", "mta-sts", "id= must be 1-32 letters/digits", "e.g. id=20261125"))
        if policy_text is None:
            out.append(
                finding(
                    "info",
                    "mta-sts",
                    "policy file not checked",
                    f"pass --mta-sts-policy with https://mta-sts.{domain}/.well-known/mta-sts.txt",
                )
            )
        else:
            pol = parse_mta_sts_policy(policy_text)
            if pol.get("version") != "STSv1":
                out.append(finding("high", "mta-sts", "policy must start with 'version: STSv1'", ""))
            mode = pol.get("mode")
            if mode not in ("enforce", "testing", "none"):
                out.append(finding("high", "mta-sts", f"invalid mode: {mode}", "enforce, testing or none"))
            elif mode == "testing":
                out.append(finding("info", "mta-sts", "mode: testing (reports only)", "move to enforce"))
            try:
                age = int(pol.get("max_age", ""))
                if not 0 <= age <= MTA_STS_MAX_AGE:
                    raise ValueError
                if age < 86400:
                    out.append(finding("low", "mta-sts", f"max_age {age} is short", "use 604800 or more"))
            except ValueError:
                out.append(finding("high", "mta-sts", "missing or invalid max_age", "max_age: 604800"))
            for host in mx_hosts:
                if not any(mx_matches(host, p) for p in pol["mx"]):
                    out.append(
                        finding(
                            "high",
                            "mta-sts",
                            f"MX {host} is not covered by the policy mx: lines",
                            "add it, or senders in enforce mode will refuse to deliver",
                        )
                    )
    rpt = [t for t in (tlsrpt or []) if t.replace(" ", "").lower().startswith("v=tlsrptv1")]
    if tlsrpt is not None:
        if rpt:
            if not re.search(r"rua=(mailto:|https:)", rpt[0].replace(" ", ""), re.I):
                out.append(finding("high", "tls-rpt", "TLS-RPT needs rua=mailto: or https:", ""))
        elif found:
            out.append(
                finding(
                    "low",
                    "tls-rpt",
                    "MTA-STS without TLS-RPT: you will not see TLS failures",
                    f'TXT _smtp._tls.{domain} "v=TLSRPTv1; rua=mailto:tls-reports@{domain}"',
                )
            )
    return out


def parse_mx(values: list[str]) -> list[tuple[int, str]]:
    out = []
    for v in values:
        parts = v.split()
        if len(parts) == 2 and parts[0].isdigit():
            out.append((int(parts[0]), parts[1].rstrip(".").lower()))
        elif len(parts) == 1:
            out.append((10, parts[0].rstrip(".").lower()))
    return sorted(out)


def audit_mx(domain: str, values: list[str] | None) -> tuple[list[dict], list[str]]:
    if values is None:
        return [], []
    mx = parse_mx(values)
    if not mx:
        return [finding("low", "mx", "no MX: replies and bounces to this domain fail", "add MX or use a subdomain")], []
    if any(host in ("", ".") for _, host in mx) or (len(mx) == 1 and mx[0][1] in ("", ".")):
        return [
            finding(
                "medium",
                "mx",
                "null MX (RFC 7505): many receivers reject mail from domains that cannot receive",
                "do not send from a null-MX domain",
            )
        ], []
    return [], [h for _, h in mx]


# --------------------------------------------------------------------------- driver


def audit(
    domain: str,
    records: Records,
    selectors: list[str] | None = None,
    mta_sts_policy: str | None = None,
) -> dict:
    domain = domain.lower().rstrip(".")
    findings: list[dict] = []
    details: dict = {"domain": domain}

    spf_f, details["spf"] = audit_spf(domain, records.get(domain, "TXT"), records)
    findings += spf_f
    dmarc_f, dmarc_info = audit_dmarc(domain, records.get(f"_dmarc.{domain}", "TXT"))
    if not dmarc_info and domain != org_domain(domain):
        parent = records.get(f"_dmarc.{org_domain(domain)}", "TXT")
        parent_f, parent_info = audit_dmarc(org_domain(domain), parent)
        if parent_info:
            dmarc_f = [finding("info", "dmarc", f"inherits DMARC from {org_domain(domain)}", "")] + parent_f
            dmarc_info = parent_info
            if "sp" in parent_info["tags"]:
                dmarc_info = dict(parent_info, tags=dict(parent_info["tags"], p=parent_info["tags"]["sp"]))
    findings += dmarc_f
    details["dmarc"] = dmarc_info

    sels = list(selectors or [])
    suffix = f"._domainkey.{domain}"
    for name in records.data:
        if name.endswith(suffix):
            sel = name[: -len(suffix)]
            if sel not in sels:
                sels.append(sel)
    details["dkim"] = []
    if not sels:
        findings.append(
            finding(
                "info",
                "dkim",
                "no DKIM selector given",
                "find s= in a received message's DKIM-Signature and pass --selector",
            )
        )
    for sel in sels:
        f, info = audit_dkim(sel, domain, records.get(f"{sel}{suffix}", "TXT"))
        findings += f
        details["dkim"].append(dict(info, selector=sel))

    mx_f, mx_hosts = audit_mx(domain, records.get(domain, "MX"))
    findings += mx_f
    details["mx"] = mx_hosts
    findings += audit_bimi(domain, records.get(f"default._bimi.{domain}", "TXT"), dmarc_info.get("tags", {}))
    findings += audit_mta_sts(
        domain,
        records.get(f"_mta-sts.{domain}", "TXT"),
        mta_sts_policy,
        mx_hosts,
        records.get(f"_smtp._tls.{domain}", "TXT"),
    )
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    return {"domain": domain, "findings": findings, "counts": counts, "details": details}


def render(report: dict) -> str:
    lines = [f"Email authentication audit: {report['domain']}"]
    spf = report["details"].get("spf") or {}
    if "lookups" in spf:
        lines.append(f"SPF: {spf.get('record')}  [{spf['lookups']}/10 lookups]")
    dmarc = report["details"].get("dmarc") or {}
    if dmarc:
        lines.append(f"DMARC: {dmarc.get('record')}")
    for d in report["details"].get("dkim", []):
        if d.get("bits"):
            lines.append(f"DKIM {d['selector']}: {d.get('k')} {d['bits']} bits")
    lines.append("")
    for f in report["findings"]:
        fix = f"  -> {f['fix']}" if f["fix"] else ""
        lines.append(f"[{f['severity'].upper():6}] {f['area']}: {f['title']}{fix}")
    c = report["counts"]
    lines.append("")
    lines.append(f"{c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Audit SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT records (offline by default).",
        epilog="Example: dns_auth_audit.py example.com --records dns.json --selector s1 --json",
    )
    p.add_argument("domain", help="sending domain (the visible From: domain)")
    p.add_argument("--records", help="JSON file of DNS records (see module docstring)")
    p.add_argument("--spf", help="SPF TXT value for the domain")
    p.add_argument("--dmarc", help="TXT value of _dmarc.<domain>")
    p.add_argument(
        "--dkim",
        action="append",
        default=[],
        metavar="SELECTOR=VALUE",
        help="DKIM TXT value, e.g. 's1=v=DKIM1; k=rsa; p=...' (repeatable)",
    )
    p.add_argument("--selector", action="append", default=[], help="DKIM selector to check (repeatable)")
    p.add_argument("--bimi", help="TXT value of default._bimi.<domain>")
    p.add_argument("--mta-sts", dest="mta_sts", help="TXT value of _mta-sts.<domain>")
    p.add_argument("--mta-sts-policy", help="file with the mta-sts.txt policy body")
    p.add_argument("--tlsrpt", help="TXT value of _smtp._tls.<domain>")
    p.add_argument("--mx", action="append", default=None, help="MX value '10 mx.example.com' (repeatable)")
    p.add_argument("--live", action="store_true", help="look up missing records with dig (network)")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)

    domain = args.domain.lower().rstrip(".")
    try:
        records = Records(load_records(args.records) if args.records else None, live=args.live)
        policy = None
        if args.mta_sts_policy:
            with open(args.mta_sts_policy, encoding="utf-8") as fh:
                policy = fh.read()
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.spf is not None:
        records.add(domain, "TXT", [args.spf])
    if args.dmarc is not None:
        records.add(f"_dmarc.{domain}", "TXT", [args.dmarc])
    for item in args.dkim:
        if "=" not in item:
            print("error: --dkim takes SELECTOR=VALUE", file=sys.stderr)
            return 2
        sel, value = item.split("=", 1)
        records.add(f"{sel}._domainkey.{domain}", "TXT", [value])
    if args.bimi is not None:
        records.add(f"default._bimi.{domain}", "TXT", [args.bimi])
    if args.mta_sts is not None:
        records.add(f"_mta-sts.{domain}", "TXT", [args.mta_sts])
    if args.tlsrpt is not None:
        records.add(f"_smtp._tls.{domain}", "TXT", [args.tlsrpt])
    if args.mx is not None:
        records.add(domain, "MX", args.mx)
    if not records.data and not args.live:
        print("error: give --records, record values (--spf, --dmarc, ...) or --live", file=sys.stderr)
        return 2
    try:
        report = audit(domain, records, args.selector, policy)
    except (RuntimeError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 1 if report["counts"]["high"] or report["counts"]["medium"] else 0


if __name__ == "__main__":
    sys.exit(main())
