# SMTP and DSN codes for triage

Basic reply codes: `2xx` success, `4xx` temporary (retry), `5xx` permanent. Enhanced status
codes (RFC 3463) are `class.subject.detail`, e.g. `5.1.1`.

## Enhanced status codes

| Code | Meaning | Category |
| --- | --- | --- |
| 5.1.1 | Bad destination mailbox (user unknown) | hard |
| 5.1.2 | Bad destination system (domain does not exist / no MX) | hard |
| 5.1.3 | Bad destination address syntax | hard |
| 5.1.6 | Mailbox moved, no forwarding | hard |
| 5.1.10 | Recipient domain has a null MX (RFC 7505); Microsoft also uses it for "recipient not found" | hard |
| 5.2.1 | Mailbox disabled | hard |
| 4.2.2 / 5.2.2 | Mailbox full / over quota | soft |
| 5.2.3, 5.3.4 | Message too large | content |
| 4.3.x, 4.4.x | System or network problem at the receiver | soft |
| 5.4.1 | Microsoft: "Recipient address rejected: Access denied" (recipient does not exist) | hard |
| 5.4.4 | Unable to route (domain has no usable MX/A) | hard |
| 5.7.1 | Delivery not authorised: policy, blocklist or spam content (read the text) | block / content |
| 5.7.23 | SPF validation failed | auth |
| 5.7.25 | Reverse DNS (PTR) validation failed | auth |
| 5.7.26 | Multiple authentication checks failed / DMARC policy (Gmail: "unauthenticated email") | auth |
| 5.7.27 | Sender address has a null MX | auth |
| 4.7.0 | Temporary policy failure, often rate limiting or greylisting | throttle / soft |

## Provider messages worth recognising

| Provider | Text | Meaning | Category |
| --- | --- | --- | --- |
| Gmail | `550-5.7.26 ... unauthenticated ... DMARC policy` | SPF/DKIM not aligned with From | auth |
| Gmail | `550-5.7.1 ... likely unsolicited mail` | Content or reputation filter | content |
| Gmail | `421-4.7.28 ... unusual rate of unsolicited mail` | Reputation-based rate limit | throttle |
| Gmail | `450-4.2.1 ... receiving mail at a rate` | Recipient-level rate limit | throttle |
| Gmail | `550-5.7.25 ... does not have a PTR record` | Missing reverse DNS | auth |
| Microsoft | `S3150` / `S3140` "part of their network is on our block list" | IP reputation block | block |
| Microsoft | `5.7.606` / `5.7.511` "banned sending IP" | IP banned; use the delist portal | block |
| Microsoft | `5.7.515` "does not meet the required authentication level" | Outlook.com bulk sender auth rule | auth |
| Yahoo/AOL | `421 4.7.0 [TSS04]` "temporarily deferred due to unexpected volume or user complaints" | Complaints or volume spike | throttle |
| Any | `blocked using zen.spamhaus.org` / `Barracuda` / `SpamCop` | Public blocklist listing | block |

Provider wording changes over time; when a message does not match, classify it by the
enhanced code and the words in it, and update `TEXT_RULES` in `scripts/bounce_triage.py`.

## Suppression rules of thumb

- Hard bounce: suppress on the first occurrence.
- Complaint (ARF `Feedback-Type: abuse`): suppress on the first occurrence, from every stream
  except strictly transactional mail the person still needs.
- Soft bounce: suppress after 3-5 consecutive soft bounces or 72 hours of retries.
- Block / auth / throttle: do not suppress the recipient; the problem is on the sending side.

## ARF complaints (RFC 5965)

Feedback-loop reports are `multipart/report; report-type=feedback-report` with a
`message/feedback-report` part (`Feedback-Type: abuse`, `Original-Rcpt-To`) and the original
message or its headers. Gmail does not send per-message complaints; use the spam rate in
Google Postmaster Tools instead. Microsoft (JMRP) and Yahoo (CFL) do send them after sign-up.
