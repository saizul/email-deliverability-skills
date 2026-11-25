# Mailbox provider sender requirements

Checked against provider documentation in November 2026. Re-check the sources below before
relying on details; providers tighten enforcement over time.

## Gmail (personal @gmail.com / @googlemail.com recipients), since February 2024

All senders:

| Requirement | Notes |
| --- | --- |
| SPF **or** DKIM | DKIM key 1024 bits or longer (2048 recommended) |
| Valid forward and reverse DNS (PTR) for sending IPs | The PTR hostname must resolve back to the IP |
| TLS for transmission | |
| Spam rate in Postmaster Tools below 0.3% | Aim below 0.1%; never reach 0.3% |
| RFC 5322 message format | One From, Date, Message-ID |
| Do not impersonate Gmail From: headers | Gmail's DMARC policy affects gmail.com From addresses sent elsewhere |

Bulk senders (close to or more than 5,000 messages a day to personal Gmail accounts; once
classified as bulk, a sender stays bulk):

| Requirement | Notes |
| --- | --- |
| SPF **and** DKIM | |
| DMARC record for the sending domain | `p=none` is enough to comply |
| From domain aligned with SPF or DKIM domain | DMARC pass |
| One-click unsubscribe for marketing/subscribed mail | `List-Unsubscribe` with an https URL and `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058), plus a visible unsubscribe link in the body |
| Process unsubscribes within 2 days | From the Gmail/Yahoo sender FAQ |

Typical rejections: `5.7.26` (unauthenticated / DMARC), `5.7.25` (PTR), `4.7.27`/`5.7.27`
(SPF did not pass), `5.7.1` (policy or content), `4.7.28` (rate limited due to spam).

## Yahoo (and AOL), since February 2024

Same model as Gmail: authenticate (SPF and DKIM for bulk), DMARC at least `p=none` with
alignment, one-click unsubscribe (RFC 8058) honoured within 2 days, spam rate below 0.3%,
valid PTR, RFC 5321/5322 compliance. Yahoo offers a complaint feedback loop via the Yahoo
Sender Hub; temporary deferrals show as `421 4.7.0 [TSS04]`.

## Outlook.com / Hotmail / Live (consumer Microsoft accounts), since May 2025

For domains sending more than 5,000 messages a day to Outlook.com consumer addresses:

| Requirement | Notes |
| --- | --- |
| SPF pass | |
| DKIM pass | |
| DMARC published, at least `p=none`, aligned with SPF or DKIM (preferably both) | |

Non-compliant mail was first routed to Junk, then rejected with
`550 5.7.515 Access denied, sending domain ... does not meet the required authentication level`.
Microsoft also recommends a compliant From/Reply-To, a working unsubscribe link, list hygiene
and transparent mailing practices. Microsoft 365 business tenants apply their own policies.

## What the checker can and cannot see

| Rule | Evidence |
| --- | --- |
| SPF/DKIM/DMARC results | `Authentication-Results` added by the receiver |
| Alignment | From domain vs SPF `smtp.mailfrom` and DKIM `header.d`/`header.i` |
| One-click headers and their DKIM coverage | `List-Unsubscribe*` headers and DKIM `h=` |
| TLS | Top `Received` header (`ESMTPS`, `version=TLS...`) |
| PTR | Top `Received` header shows the rDNS name or `unknown` |
| Spam rate, volume, unsubscribe processing time | Not in the message: from Postmaster Tools, the ESP and a manual test |

## Sources

- Google: Email sender guidelines - https://support.google.com/a/answer/81126
- Google: Email sender guidelines FAQ - https://support.google.com/a/answer/14229414
- Yahoo: Sender best practices - https://senders.yahooinc.com/best-practices/
- Microsoft: Outlook's new requirements for high-volume senders -
  https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730
- Microsoft: Fix NDR error 550 5.7.515 -
  https://support.microsoft.com/en-us/outlook/fix-ndr-error-550-5-7-515-in-outlook-com
- RFC 8058 (one-click unsubscribe), RFC 7489 (DMARC), RFC 5322 (message format)
