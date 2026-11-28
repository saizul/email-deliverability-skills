---
name: warmup-plan
description: Generate a day-by-day email warm-up schedule for a new sending domain, subdomain or dedicated IP - geometric volume ramp from a start volume to a target (conservative, standard or aggressive presets or a custom growth factor), dates with optional weekday-only sending, per-hour send rate, engagement segment for each day (30/60/90/180-day engaged) and per-provider split (Gmail, Microsoft, Yahoo, Apple) - as markdown, CSV or JSON, plus a daily advance / hold / step-back decision from bounce, complaint and deferral rates. Use when the user sets up a new domain or IP, moves to a new ESP or dedicated IP, restarts sending after a pause, asks how fast to ramp up volume, or asks whether to increase volume today.
license: MIT
compatibility: Python 3.8+ standard library.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Warm-up plan

Build reputation at a new domain or IP by sending small, highly engaged volumes first and
growing only while the numbers stay clean.

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- New sending domain/subdomain, new dedicated IP, or a new ESP
- Restarting after weeks without sending, or after a blocklisting is resolved
- "How many emails can I send per day on a new domain?", "should I increase volume today?"

## When not to use

- Shared IP pools at an ESP for small volumes: the ESP's pool is already warm; warm the
  domain gently, a full IP plan is unnecessary (say so)
- Cold outreach to people who never opted in: warm-up does not make unsolicited mail
  acceptable; decline to plan it as bulk marketing
- Diagnosing current bounces: `bounce-and-complaint-triage`

## Workflow

1. **Prerequisites first** (stop and fix before day 1): SPF, DKIM and DMARC pass and align
   (`dns-auth-audit`), PTR set for a dedicated IP, one-click unsubscribe in place
   (`sender-requirements-2024-plus`), list cleaned (`list-hygiene`), Google Postmaster Tools
   and Microsoft SNDS registered.
2. **Pick inputs.** Target daily volume (the real steady-state volume, not the list size),
   situation -> preset:
   - `conservative` (x1.3/day): new domain and new IP together, or unknown list history
   - `standard` (x1.5/day): new IP on a domain with good history, or new domain on a warm pool
   - `aggressive` (x2/day): established, well-engaged program moving infrastructure
   Ask for the sending window (hours) and whether weekends are skipped.
3. **Generate the plan.**
   ```bash
   python3 scripts/warmup_plan.py --target 50000 --preset standard --start-date 2026-12-01
   python3 scripts/warmup_plan.py --target 20000 --preset conservative --weekdays-only --providers
   python3 scripts/warmup_plan.py --target 8000 --start 100 --growth 1.4 --hours 10 --csv > plan.csv
   ```
   `--providers` uses a typical consumer mix; pass `gmail=0.6,microsoft=0.2,other=0.2` for
   the user's real mix (from their list's domain counts).
4. **Explain the segments.** Early days go only to the most engaged recipients (recent
   openers/clickers, recent purchasers, new sign-ups); older segments are added as volume grows.
   Spread each day's volume evenly over the window; keep the same From, domain and content
   style every day. More in [references/warmup-guide.md](references/warmup-guide.md).
5. **Daily gate.** Each morning, check the previous day's results:
   ```bash
   python3 scripts/warmup_plan.py --metrics bounce=0.8,complaint=0.04,deferral=2
   python3 scripts/warmup_plan.py --metrics sent=5000,bounced=40,complaints=2,deferred=100
   ```
   Raw counts from the ESP report are converted to percentages of `sent`, so nobody
   has to do the division (a common source of 10x mistakes with complaint rates).
   `advance` (exit 0), `hold` or `step back` (exit 1) with the reason and what to do.
6. **Report** the plan table, the gates and the prerequisites still open.

## Output

```
Warm-up plan: 50,000/day in 21 days (start 50, growth x1.5), weekdays and weekends
| Day | Date | Volume | Per hour | Segment |
| 1 | 2026-12-01 | 50 | 7 | engaged 30 days |
...
Gates: bounces < 2%, complaints < 0.1%, deferrals < 5%, no blocks - otherwise hold
Open prerequisites: DMARC record missing (blocker), Postmaster Tools not verified
```

## Safety

The script only prints a plan. It never sends mail or connects to an ESP. Treat the numbers as
upper limits: providers respond to engagement and complaints, not to the calendar.
