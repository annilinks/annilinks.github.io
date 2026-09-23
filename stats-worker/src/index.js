// API for the links site: accounts, page storage, visit tracking and per-page stats.
//
//   POST /api/signup           { username, password }        -> session token + page
//   POST /api/login            { username, password }        -> session token + page
//   POST /api/logout           (session)
//   GET  /api/me               (session)                     -> account + page
//   GET  /api/page?u=name                                    -> public page data
//   PUT  /api/page             (session) { title, subtitle, columns }
//   POST /api/password         (session) { current, next }
//   GET  /api/stats?days&tz    (session)                     -> stats for the caller's page
//   GET  /api/admin/users      (owner session)               -> all accounts
//   POST /api/admin/disable    (owner session) { username, disabled }
//   POST /track                { page, type, title, url, ref }

const DAY = 86400000;
const SESSION_DAYS = 90;
// Cloudflare Workers cap PBKDF2 at 100,000 iterations.
const ITERATIONS = 100000;
const MAX_PAGE_BYTES = 100000;
const BOT_UA = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|headless|lighthouse|curl|wget|python|axios|node-fetch/i;
const USERNAME_RE = /^[a-z0-9][a-z0-9_-]{2,29}$/;
const RESERVED = new Set([
  "api", "admin", "administrator", "www", "root", "support", "help", "about", "track", "stats",
  "login", "signup", "signin", "signout", "logout", "account", "settings", "user", "users", "me",
  "assets", "static", "public", "index", "home", "null", "undefined", "anonymous", "annilinks",
]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const allowed = env.ALLOWED_ORIGINS.split(",").map(s => s.trim());
    const cors = {
      "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : allowed[0],
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;
    try {
      if (path === "/track" && method === "POST") return await track(request, env, cors, allowed.includes(origin));
      if (path === "/api/signup" && method === "POST") return await signup(request, env, cors);
      if (path === "/api/login" && method === "POST") return await login(request, env, cors);
      if (path === "/api/logout" && method === "POST") return await logout(request, env, cors);
      if (path === "/api/me" && method === "GET") return await me(request, env, cors);
      if (path === "/api/page" && method === "GET") return await publicPage(url, env, cors);
      if (path === "/api/page" && method === "PUT") return await savePage(request, env, cors);
      if (path === "/api/password" && method === "POST") return await changePassword(request, env, cors);
      if (path === "/api/stats" && method === "GET") return await stats(request, env, cors, url);
      if (path === "/api/admin/users" && method === "GET") return await adminUsers(request, env, cors);
      if (path === "/api/admin/disable" && method === "POST") return await adminDisable(request, env, cors);
      return json({ error: "Not found" }, 404, cors);
    } catch (e) {
      console.error(e);
      return json({ error: "Server error" }, 500, cors);
    }
  },
};

// ---------- accounts ----------

async function signup(request, env, cors) {
  const { username = "", password = "" } = await body(request);
  const name = String(username).trim();
  const uname = name.toLowerCase();
  if (!USERNAME_RE.test(uname)) {
    return json({ error: "Username must be 3–30 characters: letters, numbers, - or _" }, 400, cors);
  }
  if (RESERVED.has(uname)) return json({ error: "That username is reserved. Pick another one." }, 400, cors);
  if (String(password).length < 8) return json({ error: "Password must be at least 8 characters." }, 400, cors);

  const taken = await env.DB.prepare("SELECT 1 FROM users WHERE username = ?1").bind(uname).first();
  if (taken) return json({ error: "That username is taken." }, 409, cors);

  const salt = randomB64(16);
  const hash = await hashPassword(password, salt, ITERATIONS);
  const page = starterPage(name);
  await env.DB.prepare(
    `INSERT INTO users (username, display, salt, hash, iterations, created, page) VALUES (?1,?2,?3,?4,?5,?6,?7)`
  ).bind(uname, name, salt, hash, ITERATIONS, Date.now(), JSON.stringify(page)).run();

  return json({ token: await newSession(env, uname), username: uname, display: name, page }, 200, cors);
}

async function login(request, env, cors) {
  const { username = "", password = "" } = await body(request);
  const ip = clientIp(request);
  if (await tooManyAttempts(env, ip)) {
    return json({ error: "Too many wrong tries. Please wait a few minutes." }, 429, cors);
  }
  const uname = String(username).trim().toLowerCase();
  const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?1").bind(uname).first();
  const ok = user && (await hashPassword(password, user.salt, user.iterations)) === user.hash;
  if (!ok) {
    await env.DB.prepare("INSERT INTO attempts (ip, ts) VALUES (?1, ?2)").bind(ip, Date.now()).run();
    return json({ error: "Wrong username or password." }, 401, cors);
  }
  if (user.disabled) return json({ error: "This account has been turned off." }, 403, cors);
  return json({ token: await newSession(env, uname), username: uname, display: user.display, page: JSON.parse(user.page) }, 200, cors);
}

async function logout(request, env, cors) {
  const raw = bearer(request);
  if (raw) await env.DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(await sha256(raw)).run();
  return json({ ok: true }, 200, cors);
}

async function me(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  return json({ username: user.username, display: user.display, page: JSON.parse(user.page), owner: isOwner(env, user.username) }, 200, cors);
}

async function changePassword(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  const { current = "", next = "" } = await body(request);
  if (String(next).length < 8) return json({ error: "New password must be at least 8 characters." }, 400, cors);
  const ok = (await hashPassword(current, user.salt, user.iterations)) === user.hash;
  if (!ok) return json({ error: "Your current password is wrong." }, 401, cors);

  const salt = randomB64(16);
  const hash = await hashPassword(next, salt, ITERATIONS);
  const raw = bearer(request);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET salt = ?2, hash = ?3, iterations = ?4 WHERE username = ?1").bind(user.username, salt, hash, ITERATIONS),
    // every other device has to log in again
    env.DB.prepare("DELETE FROM sessions WHERE username = ?1 AND token != ?2").bind(user.username, await sha256(raw)),
  ]);
  return json({ ok: true }, 200, cors);
}

// ---------- pages ----------

function starterPage(name) {
  return {
    title: name + "'s links",
    subtitle: "All my links in one place ✨",
    columns: [
      { name: "Social", icon: "💬", links: [] },
      { name: "Favourites", icon: "⭐", links: [] },
    ],
  };
}

async function publicPage(url, env, cors) {
  const uname = String(url.searchParams.get("u") || "").trim().toLowerCase();
  if (!USERNAME_RE.test(uname)) return json({ error: "No such page" }, 404, cors);
  const row = await env.DB.prepare("SELECT display, page, disabled FROM users WHERE username = ?1").bind(uname).first();
  if (!row || row.disabled) return json({ error: "No such page" }, 404, cors);
  return json({ username: uname, display: row.display, page: JSON.parse(row.page) }, 200, cors);
}

async function savePage(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  const clean = cleanPage(await body(request));
  if (clean.error) return json({ error: clean.error }, 400, cors);
  const text = JSON.stringify(clean.page);
  if (text.length > MAX_PAGE_BYTES) return json({ error: "That's too much for one page." }, 413, cors);
  await env.DB.prepare("UPDATE users SET page = ?2 WHERE username = ?1").bind(user.username, text).run();
  return json({ ok: true, page: clean.page }, 200, cors);
}

function cleanPage(input) {
  if (!input || typeof input !== "object") return { error: "Nothing to save." };
  const columns = Array.isArray(input.columns) ? input.columns : [];
  if (columns.length > 30) return { error: "Too many columns (30 max)." };
  const page = {
    title: str(input.title, 80) || "My Links",
    subtitle: str(input.subtitle, 160),
    columns: columns.map(c => ({
      name: str(c && c.name, 60) || "Column",
      icon: str(c && c.icon, 12) || "🔗",
      links: (Array.isArray(c && c.links) ? c.links : []).slice(0, 100).map(l => ({
        title: str(l && l.title, 120) || "Link",
        url: safeUrl(l && l.url),
      })).filter(l => l.url),
    })),
  };
  return { page };
}

function str(v, max) {
  return v == null ? "" : String(v).slice(0, max);
}

function safeUrl(raw) {
  let value = String(raw || "").trim();
  if (!value) return "";
  if (!/^(https?:|mailto:|tel:)/i.test(value)) value = "https://" + value.replace(/^\/+/, "");
  try {
    const u = new URL(value);
    return /^(https?:|mailto:|tel:)$/.test(u.protocol) ? u.href.slice(0, 500) : "";
  } catch {
    return "";
  }
}

// ---------- tracking ----------

async function track(request, env, cors, originOk) {
  const done = new Response(null, { status: 204, headers: cors });
  const ua = request.headers.get("User-Agent") || "";
  if (!originOk || BOT_UA.test(ua)) return done;

  let data;
  try { data = JSON.parse(await request.text()); } catch { return json({ error: "Bad body" }, 400, cors); }
  const type = ["view", "click", "copy"].includes(data.type) ? data.type : null;
  const page = String(data.page || "").trim().toLowerCase();
  if (!type || !USERNAME_RE.test(page)) return json({ error: "Bad request" }, 400, cors);

  const cf = request.cf || {};
  const { device, browser, os } = parseUA(ua);
  const isView = type === "view";
  await env.DB.prepare(
    `INSERT INTO events (ts, type, ip, country, region, city, device, browser, os, source, link_title, link_url, page)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)`
  ).bind(
    Date.now(), type, clientIp(request),
    clip(cf.country, 8), clip(cf.region, 80), clip(cf.city, 80),
    device, browser, os,
    isView ? source(data.ref, ua) : null,
    isView ? null : clip(data.title, 200),
    isView ? null : clip(data.url, 500),
    page,
  ).run();
  return done;
}

function clip(v, max) {
  return v == null || v === "" ? null : String(v).slice(0, max);
}

function parseUA(ua) {
  const device = /iPad|Tablet/i.test(ua) || (/Android/i.test(ua) && !/Mobi/i.test(ua)) ? "Tablet"
    : /Mobi|iPhone|iPod/i.test(ua) ? "Mobile" : "Desktop";
  const browser = /Instagram/.test(ua) ? "Instagram app"
    : /FBAN|FBAV|FB_IAB/.test(ua) ? "Facebook app"
    : /LinkedInApp/.test(ua) ? "LinkedIn app"
    : /Edg\//.test(ua) ? "Edge"
    : /OPR\/|Opera/.test(ua) ? "Opera"
    : /SamsungBrowser/.test(ua) ? "Samsung Internet"
    : /Firefox|FxiOS/.test(ua) ? "Firefox"
    : /Chrome|CriOS/.test(ua) ? "Chrome"
    : /Safari/.test(ua) ? "Safari" : "Other";
  const os = /Android/.test(ua) ? "Android"
    : /iPhone|iPad|iPod/.test(ua) ? "iOS"
    : /Windows/.test(ua) ? "Windows"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS"
    : /Linux|CrOS/.test(ua) ? "Linux" : "Other";
  return { device, browser, os };
}

function source(ref, ua) {
  if (/Instagram/.test(ua)) return "Instagram";
  if (/FBAN|FBAV|FB_IAB/.test(ua)) return "Facebook";
  if (/LinkedInApp/.test(ua)) return "LinkedIn";
  if (/Snapchat/.test(ua)) return "Snapchat";
  let host = "";
  try { host = new URL(ref).hostname.replace(/^(www|m|l|lm|mobile)\./, ""); } catch {}
  if (!host) return "Direct";
  const known = [
    [/instagram\.com$/, "Instagram"], [/facebook\.com$|fb\.com$/, "Facebook"],
    [/^t\.co$|twitter\.com$|^x\.com$/, "X (Twitter)"], [/linkedin\.com$|lnkd\.in$/, "LinkedIn"],
    [/youtube\.com$|youtu\.be$/, "YouTube"], [/google\./, "Google"], [/bing\.com$/, "Bing"],
    [/github\.com$/, "GitHub"], [/whatsapp\.com$/, "WhatsApp"], [/^t\.me$|telegram\.org$/, "Telegram"],
  ];
  for (const [re, name] of known) if (re.test(host)) return name;
  return host.slice(0, 100);
}

// ---------- stats ----------

async function stats(request, env, cors, url) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);

  const days = clampInt(url.searchParams.get("days"), 0, 3650, 7); // 0 = all time
  const tz = clampInt(url.searchParams.get("tz"), -840, 840, 0);   // Date#getTimezoneOffset()
  const shift = tz * 60;
  const since = days ? startOfLocalDay(Date.now(), tz) - (days - 1) * DAY : 0;
  const hourly = days === 1;
  const page = user.username;
  const q = (sql, ...extra) => env.DB.prepare(sql).bind(since, page, ...extra);
  const bucket = hourly ? "strftime('%H', ts / 1000 - ?3, 'unixepoch')" : "date(ts / 1000 - ?3, 'unixepoch')";

  const [totals, series, links, visitors, sources, countries, devices, browsers, systems, recent, first] = await env.DB.batch([
    q(`SELECT COALESCE(SUM(type = 'view'), 0) AS views,
              COUNT(DISTINCT CASE WHEN type = 'view' THEN ip END) AS visitors,
              COALESCE(SUM(type = 'click'), 0) AS clicks,
              COALESCE(SUM(type = 'copy'), 0) AS copies
       FROM events WHERE ts >= ?1 AND page = ?2`),
    q(`SELECT ${bucket} AS bucket, SUM(type = 'view') AS views,
              COUNT(DISTINCT CASE WHEN type = 'view' THEN ip END) AS visitors, SUM(type = 'click') AS clicks
       FROM events WHERE ts >= ?1 AND page = ?2 GROUP BY bucket ORDER BY bucket`, shift),
    q(`SELECT link_url AS url, MAX(link_title) AS title, SUM(type = 'click') AS clicks, SUM(type = 'copy') AS copies,
              COUNT(DISTINCT ip) AS people, MAX(ts) AS last
       FROM events WHERE ts >= ?1 AND page = ?2 AND type IN ('click', 'copy')
       GROUP BY link_url ORDER BY clicks DESC, copies DESC`),
    q(`SELECT ip, SUM(type = 'view') AS views, SUM(type = 'click') AS clicks, MIN(ts) AS first, MAX(ts) AS last,
              MAX(country) AS country, MAX(city) AS city, MAX(device) AS device, MAX(browser) AS browser, MAX(os) AS os,
              GROUP_CONCAT(DISTINCT CASE WHEN type = 'click' THEN link_title END) AS clicked
       FROM events WHERE ts >= ?1 AND page = ?2 GROUP BY ip ORDER BY views DESC, clicks DESC, last DESC LIMIT 200`),
    q(`SELECT source AS name, COUNT(*) AS views FROM events WHERE ts >= ?1 AND page = ?2 AND type = 'view' GROUP BY source ORDER BY views DESC LIMIT 12`),
    q(`SELECT country AS name, COUNT(DISTINCT ip) AS visitors FROM events WHERE ts >= ?1 AND page = ?2 AND type = 'view' GROUP BY country ORDER BY visitors DESC LIMIT 12`),
    q(`SELECT device AS name, COUNT(DISTINCT ip) AS visitors FROM events WHERE ts >= ?1 AND page = ?2 AND type = 'view' GROUP BY device ORDER BY visitors DESC`),
    q(`SELECT browser AS name, COUNT(DISTINCT ip) AS visitors FROM events WHERE ts >= ?1 AND page = ?2 AND type = 'view' GROUP BY browser ORDER BY visitors DESC LIMIT 8`),
    q(`SELECT os AS name, COUNT(DISTINCT ip) AS visitors FROM events WHERE ts >= ?1 AND page = ?2 AND type = 'view' GROUP BY os ORDER BY visitors DESC LIMIT 8`),
    q(`SELECT ts, type, ip, country, city, device, browser, link_title AS title FROM events WHERE ts >= ?1 AND page = ?2 ORDER BY ts DESC LIMIT 100`),
    q(`SELECT MIN(ts) AS first FROM events WHERE ts >= ?1 AND page = ?2`),
  ]);

  return json({
    range: { days, since, until: Date.now(), hourly, firstEvent: first.results[0] ? first.results[0].first : null },
    totals: totals.results[0],
    series: series.results,
    links: links.results,
    visitors: visitors.results,
    sources: sources.results,
    countries: countries.results,
    devices: devices.results,
    browsers: browsers.results,
    systems: systems.results,
    recent: recent.results,
  }, 200, cors);
}

// ---------- admin (site owner only) ----------

function isOwner(env, username) {
  return env.OWNERS.split(",").map(s => s.trim().toLowerCase()).includes(username);
}

async function adminUsers(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user || !isOwner(env, user.username)) return json({ error: "Not allowed" }, 403, cors);
  const { results } = await env.DB.prepare(
    `SELECT u.username, u.display, u.created, u.disabled,
            (SELECT COUNT(*) FROM events e WHERE e.page = u.username AND e.type = 'view') AS views,
            (SELECT COUNT(*) FROM events e WHERE e.page = u.username AND e.type = 'click') AS clicks
     FROM users u ORDER BY u.created DESC LIMIT 500`
  ).all();
  return json({ users: results }, 200, cors);
}

async function adminDisable(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user || !isOwner(env, user.username)) return json({ error: "Not allowed" }, 403, cors);
  const { username = "", disabled = true } = await body(request);
  const target = String(username).trim().toLowerCase();
  if (!target || isOwner(env, target)) return json({ error: "You can't turn off your own account." }, 400, cors);
  const off = disabled ? 1 : 0;
  const batch = [env.DB.prepare("UPDATE users SET disabled = ?2 WHERE username = ?1").bind(target, off)];
  if (off) batch.push(env.DB.prepare("DELETE FROM sessions WHERE username = ?1").bind(target));
  await env.DB.batch(batch);
  return json({ ok: true, username: target, disabled: !!off }, 200, cors);
}

// ---------- helpers ----------

async function body(request) {
  try { return (await request.json()) || {}; } catch { return {}; }
}

function bearer(request) {
  return (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

async function sessionUser(request, env) {
  const raw = bearer(request);
  if (!raw) return null;
  const row = await env.DB.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.username = s.username
     WHERE s.token = ?1 AND s.expires > ?2`
  ).bind(await sha256(raw), Date.now()).first();
  return row && !row.disabled ? row : null;
}

async function newSession(env, username) {
  const raw = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO sessions (token, username, created, expires) VALUES (?1,?2,?3,?4)")
      .bind(await sha256(raw), username, now, now + SESSION_DAYS * DAY),
    env.DB.prepare("DELETE FROM sessions WHERE expires < ?1").bind(now),
    env.DB.prepare("DELETE FROM attempts WHERE ts < ?1").bind(now - DAY),
  ]);
  return raw;
}

async function tooManyAttempts(env, ip) {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM attempts WHERE ip = ?1 AND ts > ?2")
    .bind(ip, Date.now() - 10 * 60 * 1000).first();
  return (row ? row.n : 0) >= 10;
}

async function hashPassword(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(String(password)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: Uint8Array.from(atob(salt), c => c.charCodeAt(0)), iterations },
    key, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

function randomB64(bytes) {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes))));
}

function b64url(buf) {
  return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function clampInt(v, min, max, fallback) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

function startOfLocalDay(now, tz) {
  const local = now - tz * 60000;
  return Math.floor(local / DAY) * DAY + tz * 60000;
}

function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), { status, headers: { ...headers, "Content-Type": "application/json" } });
}
