# 🔗 Links pages for everyone

A colourful links page anyone can create: pick a username, add your links in
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
