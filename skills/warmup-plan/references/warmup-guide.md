# Warm-up guide

## Why warm up

Mailbox providers judge a new IP or domain by its first weeks: volume consistency, bounces,
spam-trap hits, complaints and engagement. A sudden large send from an unknown source looks
like a compromised server or a spammer and is throttled (`421 4.7.0`, `4.7.28`, `TSS04`) or
blocked.

## Domain vs IP

- **Dedicated IP**: both the IP and the domain need reputation. Follow the full plan.
- **Shared ESP pool**: the IP is warm; the domain is still judged. Ramp the domain over 2-4 weeks,
  starting with engaged recipients; a full IP-style ramp is usually unnecessary below
  ~50k messages/day.
- **New subdomain on a good domain** (news.example.com): inherits some organisational
  reputation, but warm it anyway; keep separate subdomains for marketing and transactional mail.

## Rules during warm-up

1. Same From address, domain, tracking domain and content style every day.
2. Most engaged recipients first; never start with the oldest or an imported segment.
3. Spread sends through the day; respect per-provider limits from deferrals.
4. Transactional mail (password resets, receipts) can be used as warm-up volume: it has the
   best engagement.
5. Watch every provider separately. If one provider defers, slow down only that provider.
6. Do not skip more than a day or two; long gaps reset trust partially.

## Daily thresholds (used by `--metrics`)

| Metric | Advance below | Hold at | Step back at |
| --- | --- | --- | --- |
| Bounce rate | 2% | 2% | 5% |
| Complaint rate | 0.1% | 0.1% | 0.3% |
| Deferrals / throttling | 5% | 5% | 15% |
| Blocklist or policy blocks | none | - | any |

Step back = pause 24-48 hours, fix the cause, resume at the volume of 2-3 days earlier with the
most engaged segment.

## Where to look

- **Google Postmaster Tools**: spam rate, IP and domain reputation, authentication, delivery
  errors. Needs some daily volume to Gmail before data appears.
- **Microsoft SNDS** (for your IPs) and the Outlook.com sender support form for blocks.
- **Yahoo Sender Hub** for complaint feedback loop sign-up.
- Your ESP's per-domain bounce and deferral reports, or `bounce-and-complaint-triage` on logs.

## After warm-up

Keep volume steady. Spikes (Black Friday, product launches) should be planned as a short
mini-ramp over 1-2 weeks, and sunset unengaged recipients continually.
