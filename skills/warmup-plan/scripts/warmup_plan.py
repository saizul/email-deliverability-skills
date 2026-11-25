#!/usr/bin/env python3
"""Generate a domain/IP warm-up schedule, and decide whether to advance, hold or step back.

Plan mode (default): daily volumes grow geometrically from --start to --target, with an
engagement segment for each day, a per-hour rate, and an optional per-provider split.

Decision mode (--metrics): given yesterday's results, say whether to advance to the next
day's volume, hold, or step back, using conservative thresholds.

Output: markdown table (default), --csv or --json. Nothing is sent anywhere.

Exit codes: 0 = ok (decision: advance), 1 = decision is hold or step back, 2 = usage error.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import sys
from datetime import date, timedelta

PRESETS = {
    "conservative": 1.3,  # new domain AND new IP, or a list with unknown history
    "standard": 1.5,  # new IP on a domain with good history, or new domain on a shared ESP pool
    "aggressive": 2.0,  # moving an established, well-engaged program to a new IP
}
DEFAULT_SHARE = {"gmail": 0.45, "microsoft": 0.20, "yahoo": 0.10, "apple": 0.10, "other": 0.15}
THRESHOLDS = {
    "bounce_hold": 2.0,
    "bounce_back": 5.0,
    "complaint_hold": 0.1,
    "complaint_back": 0.3,
    "deferral_hold": 5.0,
    "deferral_back": 15.0,
}


def segment_for(volume: int, target: int) -> str:
    ratio = volume / target if target else 1
    if ratio < 0.15:
        return "engaged 30 days (opened/clicked)"
    if ratio < 0.35:
        return "engaged 60 days"
    if ratio < 0.7:
        return "engaged 90 days"
    if ratio < 1:
        return "engaged 180 days"
    return "full permitted list (exclude 12+ months inactive)"


def build_plan(
    target: int,
    start: int = 50,
    growth: float = 1.5,
    start_date: date | None = None,
    hours: int = 8,
    share: dict[str, float] | None = None,
    weekdays_only: bool = False,
    hold_at_target: int = 3,
    max_days: int = 120,
) -> list[dict]:
    if target <= 0 or start <= 0:
        raise ValueError("start and target must be positive")
    if growth <= 1.0:
        raise ValueError("growth must be greater than 1.0")
    start = min(start, target)
    day_date = start_date or date.today()
    days: list[dict] = []
    volume = float(start)
    cumulative = 0
    n = 0
    at_target = 0
    while n < max_days:
        while weekdays_only and day_date.weekday() >= 5:
            day_date += timedelta(days=1)
        vol = min(int(round(volume)), target)
        if vol >= 1000:
            vol = int(round(vol, -2)) if vol < target else target
        n += 1
        cumulative += vol
        row = {
            "day": n,
            "date": day_date.isoformat(),
            "volume": vol,
            "cumulative": cumulative,
            "per_hour": math.ceil(vol / max(hours, 1)),
            "segment": segment_for(vol, target),
        }
        if share:
            row["providers"] = {k: int(round(vol * v)) for k, v in share.items()}
        days.append(row)
        if vol >= target:
            at_target += 1
            if at_target >= hold_at_target:
                break
        volume *= growth
        day_date += timedelta(days=1)
    return days


def decide(metrics: dict[str, float]) -> dict:
    """Advance / hold / step back from bounce %, complaint %, deferral % and block flag."""
    b = metrics.get("bounce", 0.0)
    c = metrics.get("complaint", 0.0)
    d = metrics.get("deferral", 0.0)
    blocks = metrics.get("blocks", 0.0)
    reasons = []
    t = THRESHOLDS
    if blocks > 0 or b >= t["bounce_back"] or c >= t["complaint_back"] or d >= t["deferral_back"]:
        if blocks > 0:
            reasons.append("blocklist or policy blocks seen")
        if b >= t["bounce_back"]:
            reasons.append(f"bounce {b}% >= {t['bounce_back']}%")
        if c >= t["complaint_back"]:
            reasons.append(f"complaints {c}% >= {t['complaint_back']}%")
        if d >= t["deferral_back"]:
            reasons.append(f"deferrals {d}% >= {t['deferral_back']}%")
        return {
            "decision": "step back",
            "reasons": reasons,
            "action": "pause 24-48h, fix the cause (list source, auth, content), resume at the volume "
            "of 2-3 days earlier with the most engaged segment only",
        }
    if b >= t["bounce_hold"]:
        reasons.append(f"bounce {b}% >= {t['bounce_hold']}%")
    if c >= t["complaint_hold"]:
        reasons.append(f"complaints {c}% >= {t['complaint_hold']}%")
    if d >= t["deferral_hold"]:
        reasons.append(f"deferrals {d}% >= {t['deferral_hold']}%")
    if reasons:
        return {
            "decision": "hold",
            "reasons": reasons,
            "action": "repeat today's volume until the numbers are back under the thresholds",
        }
    return {"decision": "advance", "reasons": [], "action": "send the next day's volume"}


def parse_kv(text: str) -> dict[str, float]:
    out = {}
    for part in text.split(","):
        if not part.strip():
            continue
        if "=" not in part:
            raise ValueError(f"expected key=value, got '{part}'")
        k, v = part.split("=", 1)
        out[k.strip().lower()] = float(v.strip().rstrip("%"))
    return out


def render_markdown(plan: list[dict], args) -> str:
    providers = list(plan[0].get("providers", {})) if plan else []
    head = ["Day", "Date", "Volume", "Cumulative", "Per hour", "Segment", *providers]
    lines = [
        f"# Warm-up plan: {plan[-1]['volume']:,}/day in {len(plan)} days "
        f"(start {plan[0]['volume']:,}, growth x{args.growth_value})",
        "",
        "| " + " | ".join(head) + " |",
        "| " + " | ".join("---" for _ in head) + " |",
    ]
    for r in plan:
        cells = [
            str(r["day"]),
            r["date"],
            f"{r['volume']:,}",
            f"{r['cumulative']:,}",
            f"{r['per_hour']:,}",
            r["segment"],
            *(f"{r['providers'][p]:,}" for p in providers),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    t = THRESHOLDS
    lines += [
        "",
        "Advance to the next row only when the previous day had:",
        f"- bounces < {t['bounce_hold']}% (step back at {t['bounce_back']}%)",
        f"- complaints < {t['complaint_hold']}% (step back at {t['complaint_back']}%; Gmail/Yahoo limit 0.3%)",
        f"- deferrals/throttling < {t['deferral_hold']}% and no blocklist or policy blocks",
        "Otherwise repeat the day (hold). Check with: warmup_plan.py --metrics bounce=..,complaint=..,deferral=..",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate an email warm-up schedule or decide whether to advance.",
        epilog="Examples: warmup_plan.py --target 50000 --preset standard --start-date 2026-12-01\n"
        "          warmup_plan.py --metrics bounce=1.2,complaint=0.05,deferral=2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", type=int, help="daily volume to reach")
    p.add_argument("--start", type=int, default=50, help="day-1 volume (default 50)")
    p.add_argument("--preset", choices=sorted(PRESETS), default="standard", help="growth preset")
    p.add_argument("--growth", type=float, help="daily growth factor (overrides --preset), e.g. 1.4")
    p.add_argument("--start-date", help="YYYY-MM-DD (default today)")
    p.add_argument("--hours", type=int, default=8, help="sending window in hours per day (default 8)")
    p.add_argument(
        "--providers",
        nargs="?",
        const="default",
        help="add a per-provider split; 'gmail=0.5,microsoft=0.3,other=0.2' or no value for a typical B2C mix",
    )
    p.add_argument("--weekdays-only", action="store_true", help="skip Saturdays and Sundays")
    p.add_argument("--hold-days", type=int, default=3, help="days to stay at target at the end (default 3)")
    p.add_argument("--metrics", help="decision mode: bounce=%%,complaint=%%,deferral=%%,blocks=N")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="print JSON")
    fmt.add_argument("--csv", action="store_true", help="print CSV")
    args = p.parse_args(argv)

    try:
        if args.metrics:
            result = decide(parse_kv(args.metrics))
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Decision: {result['decision'].upper()}")
                for r in result["reasons"]:
                    print(f"  - {r}")
                print(f"Action: {result['action']}")
            return 0 if result["decision"] == "advance" else 1
        if not args.target:
            p.error("--target is required (or use --metrics)")
        growth = args.growth or PRESETS[args.preset]
        args.growth_value = growth
        share = None
        if args.providers:
            share = DEFAULT_SHARE if args.providers == "default" else parse_kv(args.providers)
            total = sum(share.values())
            if not 0.99 <= total <= 1.01:
                raise ValueError(f"provider shares must add up to 1.0 (got {total:.2f})")
        start_date = date.fromisoformat(args.start_date) if args.start_date else None
        plan = build_plan(
            args.target, args.start, growth, start_date, args.hours, share, args.weekdays_only, args.hold_days
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"growth": growth, "target": args.target, "days": plan, "thresholds": THRESHOLDS}, indent=2))
    elif args.csv:
        buf = io.StringIO()
        providers = list(plan[0].get("providers", {}))
        w = csv.writer(buf)
        w.writerow(["day", "date", "volume", "cumulative", "per_hour", "segment", *providers])
        for r in plan:
            w.writerow([r["day"], r["date"], r["volume"], r["cumulative"], r["per_hour"], r["segment"],
                        *(r["providers"][k] for k in providers)])  # fmt: skip
        print(buf.getvalue(), end="")
    else:
        print(render_markdown(plan, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
