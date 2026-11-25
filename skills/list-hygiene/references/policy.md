# List hygiene policy

## What each flag means and why it matters

| Flag | Risk if mailed | Default |
| --- | --- | --- |
| invalid | Guaranteed hard bounce | exclude |
| duplicate | Double sends -> complaints; inflated counts | exclude later copies |
| disposable | Addresses die within hours; often abuse of sign-up offers | exclude |
| typo | Hard bounce, or worse: typo domains are used as spam traps | exclude, review suggestion |
| suppressed | Previously bounced, complained or unsubscribed: mailing again is a legal and reputation problem | exclude |
| role | Shared inboxes (info@, sales@) complain more and are often on traps | keep for B2B, drop for B2C |

## What a script cannot detect

- **Spam traps** (pristine traps never belonged to a person; recycled traps are abandoned
  addresses reactivated by providers). Only consent and regular engagement-based sunsetting
  protect you.
- **Mailboxes that no longer exist** on valid domains. Only sending (or a paid verification
  service) reveals them. A list unmailed for over a year typically bounces at several percent.
- **Consent.** No tool can add it.

## Engagement-based sending

| Segment | Treatment |
| --- | --- |
| Opened or clicked in the last 90 days | Normal sends |
| 90-180 days | Lower frequency, best content |
| 180-365 days | Re-engagement series ("still want these?") |
| 12+ months, no engagement | Sunset: stop mailing |

Apple Mail Privacy Protection inflates opens; prefer clicks, purchases and logins as signals.

## Re-permission for old lists

If a list has not been mailed in over a year:

1. Clean it with this skill.
2. Send a single, plain re-permission email to a small engaged-looking slice first
   (the warm-up rules in `warmup-plan` apply).
3. Keep only people who confirm or click; suppress the rest.

## Suppression list hygiene

Keep one global suppression list (hard bounces, complaints, unsubscribes, legal removals)
and apply it to every import, every tool and every list. Never delete it when changing ESPs:
export it and import it into the new one first.
