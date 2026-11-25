# Email template checklist

## Size and structure

- **Gmail clips HTML over about 102 KB** and shows "[Message clipped] View entire message".
  Everything after the cut, often the unsubscribe link and the open pixel, is hidden.
  Fixes: remove unused CSS and comments, avoid repeated inline styles from drag-and-drop
  builders, minify, shorten tracking URLs, split very long digests.
- Send **multipart/alternative** with a real `text/plain` part. Some filters and many
  accessibility tools use it; a near-empty plain part ("view in browser") looks careless.
- Lines over 998 characters violate RFC 5322; use `quoted-printable` or `base64` transfer
  encoding (ESPs do this; hand-rolled SMTP code often does not).
- Always set `Message-ID`, `Date`, one `From`. Missing headers are a Gmail requirement for all
  senders (RFC 5322 format).

## Images

- Live text first: many clients block images by default. An image-only email shows nothing
  and is a classic spam pattern. Aim for at least ~60% text by area; put offers, prices and
  calls to action in HTML text.
- `alt` on every meaningful image; `alt=""` for spacers and decorative images.
- Host images over https on your domain or the ESP's CDN. `data:` base64 images are blocked
  by Gmail and Outlook and inflate the size toward the clipping limit.
- One open-tracking pixel is enough.

## Links

- Use your own domain or the ESP's **branded** click-tracking domain. Public shorteners share
  reputation with abusers and appear on URL blocklists.
- Never link to raw IP addresses.
- The visible text of a link must not show a different domain than the `href` (phishing
  pattern, flagged by Gmail and Microsoft).
- No `javascript:` links, forms, scripts, iframes, `embed`/`object`: they are stripped and
  raise suspicion.
- Fewer distinct link domains is better; every domain is checked against blocklists.

## Unsubscribe and compliance (marketing mail)

- A visible unsubscribe link in the footer (CAN-SPAM, GDPR/PECR, CASL).
- `List-Unsubscribe: <https://example.com/u/TOKEN>, <mailto:unsub@example.com>` and
  `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058). Gmail and Yahoo require
  one-click unsubscribe for bulk marketing mail; the https endpoint must accept a POST and
  unsubscribe without a login or confirmation page, and the DKIM signature must cover both
  headers.
- A physical postal address (CAN-SPAM) and a reason for receiving the mail.
- Process unsubscribes within 2 days (Gmail/Yahoo bulk rule).

## Transactional mail

Receipts, password resets and security alerts do not need an unsubscribe link, but keep them
free of promotions; mixing marketing into transactional mail makes it marketing mail under
both law and provider policies.

## Subject and From

- Consistent, recognisable From name and address on your own domain.
- No ALL CAPS subjects or `!!!`; no misleading `RE:`/`FWD:` prefixes.
- Preheader text: the first ~90 characters of body text show in the inbox list; set it on
  purpose (a hidden preheader `div` is common practice).
