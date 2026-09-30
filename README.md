# 🔗 Linkboard

Linkboard is a colourful links page anyone can create: pick a username, add your links in
columns, share one address, and see who opened it and what they tapped.

**Live:** https://annilinks.github.io/ · every page lives at `?u=username`

## How it works

- `index.html` — the whole site: landing page, signup and login, a links page,
  the editor and the stats screen. Nothing else to build or install.
- `stats-worker/` — a Cloudflare Worker with a D1 database that stores accounts,
  each page and every visit. Deploy it with `cd stats-worker && npx wrangler deploy`.
- `links.json` / `auth.json` — the old single-user setup, kept only as a backup.
  They are no longer used by the site.

## For a visitor

1. Open the site and pick a username and password.
2. Click **✏️ Edit** on your page to add links and columns, then **💾 Save**.
3. Share `https://annilinks.github.io/?u=yourname`.
4. Click **📊 Stats** to see page views, visitors by IP, which links were tapped
   and which were not, sources, countries and devices.

Passwords are stored as PBKDF2-SHA256 hashes, never in plain text. Login sessions
last 90 days and only a hash of each session token is stored.

## For the site owner

The account named in the worker's `OWNERS` variable sees an **Admin** link in the
footer: every account, its views and taps, and a switch to turn an account off.

## Plans and payments

Free accounts get 3 columns, 20 links and 7 days of stats, and their pages carry a small
"Made with Linkboard" badge. **Pro** (one-time payment for a month or a year, no auto-renewal)
raises that to 30 columns and 300 links, all-time stats with visitors by IP and a CSV download,
custom column colours, a QR code, and no badge.

Payments run through Razorpay. The worker only turns Pro on when it has verified Razorpay's
signature, either from the browser (`/api/verify`) or from the webhook (`/razorpay/webhook`).

To switch payments on, set these on the worker (they are never in this repo):

```
npx wrangler secret put RAZORPAY_KEY_ID
npx wrangler secret put RAZORPAY_KEY_SECRET
npx wrangler secret put RAZORPAY_WEBHOOK_SECRET
```

Then add a webhook in Razorpay for `payment.captured` pointing at
`https://<your-worker>/razorpay/webhook`. Prices live in `wrangler.toml` as paise
(`PRICE_MONTH`, `PRICE_YEAR`). Until the keys are set, the site simply says Pro can't be bought yet.

Terms, privacy and the refund policy are in [`legal.html`](legal.html) — fill in your contact
details there before taking payments.

## Forgotten passwords

There is no email in the loop, so recovery works two ways:

- **Recovery code.** Every new account is shown one code (`LB-XXXX-XXXX-XXXX-XXXX`) at signup.
  "Forgot your password?" on the login screen takes the username plus that code and sets a new
  password. Using a code replaces it with a fresh one, so a code only ever works once.
  A logged-in owner can make a new code any time with **🆘 Recovery code** in edit mode.
- **Owner reset.** In the Admin list the site owner can reset any account's password; the temporary
  password is shown once, to be passed on privately. That account is logged out everywhere.

Codes are stored the same way as passwords — PBKDF2-SHA256 of the code, never the code itself —
and reset attempts share the login rate limit.
