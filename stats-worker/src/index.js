// API for the links site: accounts, page storage, visit tracking and per-page stats.
//
//   POST /api/signup           { username, password }        -> session token + page
//   POST /api/login            { username, password }        -> session token + page
//   POST /api/logout           (session)
//   GET  /api/me               (session)                     -> account + page
//   GET  /api/page?u=name                                    -> public page data
//   PUT  /api/page             (session) { title, subtitle, columns }
//   POST /api/password         (session) { current, next }
//   POST /api/recovery         (session)                     -> a fresh recovery code
//   POST /api/reset            { username, code, password }   -> new password from a recovery code
//   POST /api/admin/reset      (owner session) { username }   -> a temporary password
//   POST /api/telegram/link    (session)                     -> a one-time link to the bot
//   POST /api/telegram/unlink  (session)
//   POST /api/forgot           { username }                  -> sends a code to a linked Telegram
//   POST /api/reset-code       { username, code, password }
//   POST /telegram/webhook     (Telegram) bot updates
//   GET  /api/stats?days&tz    (session)                     -> stats for the caller's page
//   GET  /api/admin/users      (owner session)               -> all accounts
//   POST /api/admin/disable    (owner session) { username, disabled }
//   GET  /api/plans                                          -> prices and whether payments are on
//   POST /api/checkout         (session) { period }          -> a Razorpay order to pay for Pro
//   POST /api/verify           (session) { orderId, paymentId, signature }
//   POST /razorpay/webhook     (Razorpay) payment events
//   POST /track                { page, type, title, url, ref }

const DAY = 86400000;
const SESSION_DAYS = 90;
// Cloudflare Workers cap PBKDF2 at 100,000 iterations.
const ITERATIONS = 100000;
const MAX_PAGE_BYTES = 100000;
const BOT_UA = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|headless|lighthouse|curl|wget|python|axios|node-fetch/i;
const USERNAME_RE = /^[a-z0-9][a-z0-9_-]{2,29}$/;
const DAY_MS = 86400000;
// What each plan may do. Free is generous enough to be useful on its own.
const LIMITS = {
  free: { columns: 3, links: 20, statsDays: 7, visitorList: false, colours: false, badge: true },
  pro: { columns: 30, links: 300, statsDays: 3650, visitorList: true, colours: true, badge: false },
};
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
      if (path === "/api/recovery" && method === "POST") return await newRecoveryCode(request, env, cors);
      if (path === "/api/reset" && method === "POST") return await resetWithCode(request, env, cors);
      if (path === "/api/admin/reset" && method === "POST") return await adminReset(request, env, cors);
      if (path === "/api/telegram/link" && method === "POST") return await telegramLink(request, env, cors);
      if (path === "/api/telegram/unlink" && method === "POST") return await telegramUnlink(request, env, cors);
      if (path === "/api/forgot" && method === "POST") return await sendResetCode(request, env, cors);
      if (path === "/api/reset-code" && method === "POST") return await resetWithSentCode(request, env, cors);
      if (path === "/telegram/webhook" && method === "POST") return await telegramWebhook(request, env, cors);
      if (path === "/api/stats" && method === "GET") return await stats(request, env, cors, url);
      if (path === "/api/admin/users" && method === "GET") return await adminUsers(request, env, cors);
      if (path === "/api/admin/disable" && method === "POST") return await adminDisable(request, env, cors);
      if (path === "/api/plans" && method === "GET") return plans(env, cors);
      if (path === "/api/checkout" && method === "POST") return await checkout(request, env, cors);
      if (path === "/api/verify" && method === "POST") return await verifyPayment(request, env, cors);
      if (path === "/razorpay/webhook" && method === "POST") return await webhook(request, env, cors);
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
  const recovery = makeRecoveryCode();
  const recoverySalt = randomB64(16);
  const recoveryHash = await hashPassword(tidyCode(recovery), recoverySalt, ITERATIONS);
  await env.DB.prepare(
    `INSERT INTO users (username, display, salt, hash, iterations, created, page, recovery_salt, recovery_hash)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
  ).bind(uname, name, salt, hash, ITERATIONS, Date.now(), JSON.stringify(page), recoverySalt, recoveryHash).run();

  return json({
    token: await newSession(env, uname), username: uname, display: name, page,
    plan: "free", planUntil: null, limits: LIMITS.free, recoveryCode: recovery,
  }, 200, cors);
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
  return json({
    token: await newSession(env, uname), username: uname, display: user.display, page: JSON.parse(user.page),
    ...accountInfo(user),
  }, 200, cors);
}

async function logout(request, env, cors) {
  const raw = bearer(request);
  if (raw) await env.DB.prepare("DELETE FROM sessions WHERE token = ?1").bind(await sha256(raw)).run();
  return json({ ok: true }, 200, cors);
}

async function me(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  return json({
    username: user.username, display: user.display, page: JSON.parse(user.page),
    owner: isOwner(env, user.username), telegram: telegramInfo(user), ...accountInfo(user),
  }, 200, cors);
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

// ---------- forgotten passwords ----------

// Letters and digits that are hard to mix up when read out or typed.
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function makeRecoveryCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const chars = [...bytes].map(b => CODE_ALPHABET[b % CODE_ALPHABET.length]);
  return "LB-" + [0, 4, 8, 12].map(i => chars.slice(i, i + 4).join("")).join("-");
}

const tidyCode = code => String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

function makePassword() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return [...bytes].map(b => CODE_ALPHABET[b % CODE_ALPHABET.length]).join("").replace(/(.{4})(?=.)/g, "$1-");
}

async function setPassword(env, username, password) {
  const salt = randomB64(16);
  const hash = await hashPassword(password, salt, ITERATIONS);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET salt = ?2, hash = ?3, iterations = ?4 WHERE username = ?1")
      .bind(username, salt, hash, ITERATIONS),
    env.DB.prepare("DELETE FROM sessions WHERE username = ?1").bind(username), // every device logs out
  ]);
}

async function newRecoveryCode(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  const code = makeRecoveryCode();
  const salt = randomB64(16);
  const hash = await hashPassword(tidyCode(code), salt, ITERATIONS);
  await env.DB.prepare("UPDATE users SET recovery_salt = ?2, recovery_hash = ?3 WHERE username = ?1")
    .bind(user.username, salt, hash).run();
  return json({ recoveryCode: code }, 200, cors);
}

async function resetWithCode(request, env, cors) {
  const ip = clientIp(request);
  if (await tooManyAttempts(env, ip)) {
    return json({ error: "Too many wrong tries. Please wait a few minutes." }, 429, cors);
  }
  const { username = "", code = "", password = "" } = await body(request);
  if (String(password).length < 8) return json({ error: "New password must be at least 8 characters." }, 400, cors);

  const uname = String(username).trim().toLowerCase();
  const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?1").bind(uname).first();
  const given = tidyCode(code);
  let ok = false;
  if (user && user.recovery_hash && given) {
    ok = (await hashPassword(given, user.recovery_salt, ITERATIONS)) === user.recovery_hash;
  }
  if (!ok) {
    await env.DB.prepare("INSERT INTO attempts (ip, ts) VALUES (?1, ?2)").bind(ip, Date.now()).run();
    return json({ error: "That username and recovery code don't match." }, 401, cors);
  }
  if (user.disabled) return json({ error: "This account has been turned off." }, 403, cors);

  await setPassword(env, uname, password);
  // The used code is replaced, so a copied-down code can't be used twice.
  const next = makeRecoveryCode();
  const salt = randomB64(16);
  const hash = await hashPassword(tidyCode(next), salt, ITERATIONS);
  await env.DB.prepare("UPDATE users SET recovery_salt = ?2, recovery_hash = ?3 WHERE username = ?1")
    .bind(uname, salt, hash).run();

  return json({ ok: true, recoveryCode: next }, 200, cors);
}

async function adminReset(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user || !isOwner(env, user.username)) return json({ error: "Not allowed" }, 403, cors);
  const { username = "" } = await body(request);
  const target = String(username).trim().toLowerCase();
  const row = await env.DB.prepare("SELECT username FROM users WHERE username = ?1").bind(target).first();
  if (!row) return json({ error: "No such account" }, 404, cors);
  const password = makePassword();
  await setPassword(env, target, password);
  return json({ ok: true, username: target, password }, 200, cors);
}

// ---------- Telegram ----------
// An account can be tied to one Telegram chat; that chat is where reset codes go.

const RESET_CODE_MINUTES = 15;
const LINK_MINUTES = 15;

function telegramInfo(user) {
  return { connected: !!user.tg_chat_id, name: user.tg_name || null };
}

async function telegram(env, method, payload) {
  if (!env.TELEGRAM_BOT_TOKEN) return { ok: false, offline: true };
  const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const out = await res.json().catch(() => ({}));
  if (!out.ok) console.error("telegram " + method, res.status, out.description);
  return out;
}

async function telegramLink(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  if (!env.TELEGRAM_BOT) return json({ error: "Telegram isn't switched on yet." }, 503, cors);
  const code = makeRecoveryCode().replace(/-/g, "").slice(0, 12);
  await env.DB.prepare("UPDATE users SET link_code = ?2, link_expires = ?3 WHERE username = ?1")
    .bind(user.username, code, Date.now() + LINK_MINUTES * 60000).run();
  return json({
    url: `https://t.me/${env.TELEGRAM_BOT}?start=${code}`,
    bot: env.TELEGRAM_BOT,
    minutes: LINK_MINUTES,
  }, 200, cors);
}

async function telegramUnlink(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  await env.DB.prepare("UPDATE users SET tg_chat_id = NULL, tg_name = NULL WHERE username = ?1")
    .bind(user.username).run();
  return json({ ok: true }, 200, cors);
}

async function telegramWebhook(request, env, cors) {
  if (!env.TELEGRAM_WEBHOOK_SECRET ||
      request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.TELEGRAM_WEBHOOK_SECRET) {
    return json({ error: "Bad secret" }, 401, cors);
  }
  const update = await body(request);
  const message = update.message || update.edited_message;
  const chatId = message && message.chat && message.chat.id;
  const text = ((message && message.text) || "").trim();
  if (!chatId) return json({ ok: true }, 200, cors);

  const start = text.match(/^\/start(?:\s+(\S+))?$/i);
  if (start && start[1]) {
    const code = start[1].toUpperCase().replace(/[^A-Z0-9]/g, "");
    const user = await env.DB.prepare(
      "SELECT username FROM users WHERE link_code = ?1 AND link_expires > ?2"
    ).bind(code, Date.now()).first();
    if (!user) {
      await telegram(env, "sendMessage", { chat_id: chatId, text: "That link has expired. Open your Linkboard page, click ✏️ Edit and then ✈️ Telegram to get a fresh one." });
      return json({ ok: true }, 200, cors);
    }
    const name = [message.chat.first_name, message.chat.last_name].filter(Boolean).join(" ")
      || (message.chat.username ? "@" + message.chat.username : "");
    await env.DB.prepare(
      "UPDATE users SET tg_chat_id = ?2, tg_name = ?3, link_code = NULL, link_expires = NULL WHERE username = ?1"
    ).bind(user.username, String(chatId), clip(name, 80)).run();
    await telegram(env, "sendMessage", {
      chat_id: chatId,
      text: `✅ Connected to @${user.username}.\n\nIf you ever forget your password, choose "Send a code to my Telegram" on the login screen and the code will arrive here.`,
    });
    return json({ ok: true }, 200, cors);
  }

  await telegram(env, "sendMessage", {
    chat_id: chatId,
    text: "Hi! I send password reset codes for Linkboard pages.\n\nTo connect your page: open it, click ✏️ Edit, then ✈️ Telegram, and tap the link it gives you.",
  });
  return json({ ok: true }, 200, cors);
}

function makeSixDigits() {
  return String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
}

async function sendResetCode(request, env, cors) {
  const ip = clientIp(request);
  if (await tooManyAttempts(env, ip)) {
    return json({ error: "Too many tries. Please wait a few minutes." }, 429, cors);
  }
  const { username = "" } = await body(request);
  const uname = String(username).trim().toLowerCase();
  const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?1").bind(uname).first();
  if (!user || !user.tg_chat_id) {
    await env.DB.prepare("INSERT INTO attempts (ip, ts) VALUES (?1, ?2)").bind(ip, Date.now()).run();
    return json({ sent: false, reason: "no-telegram" }, 200, cors);
  }
  if (user.disabled) return json({ error: "This account has been turned off." }, 403, cors);

  const code = makeSixDigits();
  const salt = randomB64(16);
  const hash = await hashPassword(code, salt, ITERATIONS);
  await env.DB.prepare(
    "UPDATE users SET reset_salt = ?2, reset_hash = ?3, reset_expires = ?4 WHERE username = ?1"
  ).bind(uname, salt, hash, Date.now() + RESET_CODE_MINUTES * 60000).run();

  const out = await telegram(env, "sendMessage", {
    chat_id: user.tg_chat_id,
    text: `🔑 Your Linkboard reset code is ${code}\n\nIt works for ${RESET_CODE_MINUTES} minutes and only for @${uname}. If this wasn't you, ignore this message — nothing has changed.`,
  });
  if (!out.ok) return json({ error: "Couldn't send the code. Please try again." }, 502, cors);
  return json({ sent: true, via: "telegram", minutes: RESET_CODE_MINUTES }, 200, cors);
}

async function resetWithSentCode(request, env, cors) {
  const ip = clientIp(request);
  if (await tooManyAttempts(env, ip)) {
    return json({ error: "Too many wrong tries. Please wait a few minutes." }, 429, cors);
  }
  const { username = "", code = "", password = "" } = await body(request);
  if (String(password).length < 8) return json({ error: "New password must be at least 8 characters." }, 400, cors);
  const uname = String(username).trim().toLowerCase();
  const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?1").bind(uname).first();
  const given = String(code).replace(/\D/g, "");
  let ok = false;
  if (user && user.reset_hash && (user.reset_expires || 0) > Date.now() && given.length === 6) {
    ok = (await hashPassword(given, user.reset_salt, ITERATIONS)) === user.reset_hash;
  }
  if (!ok) {
    await env.DB.prepare("INSERT INTO attempts (ip, ts) VALUES (?1, ?2)").bind(ip, Date.now()).run();
    return json({ error: "That code is wrong or has expired." }, 401, cors);
  }
  await setPassword(env, uname, password);
  await env.DB.prepare(
    "UPDATE users SET reset_salt = NULL, reset_hash = NULL, reset_expires = NULL WHERE username = ?1"
  ).bind(uname).run();
  if (user.tg_chat_id) {
    await telegram(env, "sendMessage", {
      chat_id: user.tg_chat_id,
      text: `✅ The password for @${uname} was just changed. If that wasn't you, change it again straight away.`,
    });
  }
  return json({ ok: true }, 200, cors);
}

// ---------- plans ----------

function planOf(user) {
  return user && user.plan === "pro" && (user.plan_until || 0) > Date.now() ? "pro" : "free";
}

function accountInfo(user) {
  const plan = planOf(user);
  return { plan, planUntil: plan === "pro" ? user.plan_until : null, limits: LIMITS[plan] };
}

function plans(env, cors) {
  return json({
    enabled: !!(env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET),
    currency: "INR",
    month: Number(env.PRICE_MONTH || 9900),
    year: Number(env.PRICE_YEAR || 79900),
    limits: LIMITS,
  }, 200, cors);
}

async function checkout(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ error: "Payments aren't switched on yet." }, 503, cors);
  }
  const { period = "month" } = await body(request);
  if (!["month", "year"].includes(period)) return json({ error: "Unknown plan" }, 400, cors);
  const amount = Number(period === "year" ? env.PRICE_YEAR || 79900 : env.PRICE_MONTH || 9900);

  const res = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: {
      Authorization: "Basic " + btoa(env.RAZORPAY_KEY_ID + ":" + env.RAZORPAY_KEY_SECRET),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      amount, currency: "INR",
      receipt: ("lb_" + user.username + "_" + Date.now()).slice(0, 40),
      notes: { username: user.username, period },
    }),
  });
  const order = await res.json().catch(() => ({}));
  if (!res.ok || !order.id) {
    console.error("razorpay order failed", res.status, order);
    return json({ error: "Couldn't start the payment. Please try again." }, 502, cors);
  }
  await env.DB.prepare(
    `INSERT INTO payments (order_id, username, period, amount, status, created) VALUES (?1,?2,?3,?4,'created',?5)`
  ).bind(order.id, user.username, period, amount, Date.now()).run();

  return json({ orderId: order.id, amount, currency: "INR", keyId: env.RAZORPAY_KEY_ID }, 200, cors);
}

async function verifyPayment(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  const { orderId = "", paymentId = "", signature = "" } = await body(request);
  const expected = await hmacHex(env.RAZORPAY_KEY_SECRET || "", orderId + "|" + paymentId);
  if (!expected || expected !== String(signature)) return json({ error: "Payment couldn't be verified." }, 400, cors);
  const row = await activate(env, orderId, paymentId);
  if (!row) return json({ error: "That payment doesn't match an order." }, 400, cors);
  const fresh = await env.DB.prepare("SELECT * FROM users WHERE username = ?1").bind(row.username).first();
  return json({ ok: true, ...accountInfo(fresh) }, 200, cors);
}

// Razorpay also tells us about the payment directly, in case the browser never came back.
async function webhook(request, env, cors) {
  const raw = await request.text();
  const signature = request.headers.get("X-Razorpay-Signature") || "";
  const expected = await hmacHex(env.RAZORPAY_WEBHOOK_SECRET || "", raw);
  if (!expected || expected !== signature) return json({ error: "Bad signature" }, 400, cors);
  let event = {};
  try { event = JSON.parse(raw); } catch {}
  const payment = event && event.payload && event.payload.payment && event.payload.payment.entity;
  if (event.event === "payment.captured" && payment && payment.order_id) {
    await activate(env, payment.order_id, payment.id);
  }
  return json({ ok: true }, 200, cors);
}

// Turns a paid order into Pro time. Running it twice does nothing the second time.
async function activate(env, orderId, paymentId) {
  const row = await env.DB.prepare("SELECT * FROM payments WHERE order_id = ?1").bind(orderId).first();
  if (!row) return null;
  if (row.status === "paid") return row;

  const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?1").bind(row.username).first();
  if (!user) return null;
  const days = row.period === "year" ? 366 : 31;
  const from = Math.max(Date.now(), user.plan_until || 0);
  const until = from + days * DAY_MS;
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET plan = 'pro', plan_until = ?2 WHERE username = ?1").bind(row.username, until),
    env.DB.prepare("UPDATE payments SET status = 'paid', payment_id = ?2, paid = ?3 WHERE order_id = ?1")
      .bind(orderId, paymentId, Date.now()),
  ]);
  return row;
}

async function hmacHex(secret, message) {
  if (!secret) return null;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
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
  const row = await env.DB.prepare("SELECT display, page, disabled, plan, plan_until FROM users WHERE username = ?1").bind(uname).first();
  if (!row || row.disabled) return json({ error: "No such page" }, 404, cors);
  return json({ username: uname, display: row.display, page: JSON.parse(row.page), plan: planOf(row) }, 200, cors);
}

async function savePage(request, env, cors) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Not logged in" }, 401, cors);
  const plan = planOf(user);
  const clean = cleanPage(await body(request), LIMITS[plan]);
  if (clean.error) return json({ error: clean.error, upgrade: plan === "free" }, 400, cors);
  const text = JSON.stringify(clean.page);
  if (text.length > MAX_PAGE_BYTES) return json({ error: "That's too much for one page." }, 413, cors);
  await env.DB.prepare("UPDATE users SET page = ?2 WHERE username = ?1").bind(user.username, text).run();
  return json({ ok: true, page: clean.page }, 200, cors);
}

function cleanPage(input, limits) {
  if (!input || typeof input !== "object") return { error: "Nothing to save." };
  const columns = Array.isArray(input.columns) ? input.columns : [];
  if (columns.length > limits.columns) {
    return { error: `Your plan allows ${limits.columns} columns.` };
  }
  const page = {
    title: str(input.title, 80) || "My Links",
    subtitle: str(input.subtitle, 160),
    columns: columns.map(c => {
      const column = {
        name: str(c && c.name, 60) || "Column",
        icon: str(c && c.icon, 12) || "🔗",
        links: (Array.isArray(c && c.links) ? c.links : []).slice(0, 100).map(l => {
          const link = { title: str(l && l.title, 120) || "Link", url: safeUrl(l && l.url) };
          const description = str(l && l.description, 200).trim();
          if (description) link.description = description;
          return link;
        }).filter(l => l.url),
      };
      const colour = str(c && c.color, 20).trim();
      if (limits.colours && /^#[0-9a-f]{6}$/i.test(colour)) column.color = colour;
      return column;
    }),
  };
  const links = page.columns.reduce((n, c) => n + c.links.length, 0);
  if (links > limits.links) return { error: `Your plan allows ${limits.links} links.` };
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

  const plan = planOf(user);
  const limits = LIMITS[plan];
  let days = clampInt(url.searchParams.get("days"), 0, 3650, 7); // 0 = all time
  const wanted = days;
  if (days === 0 || days > limits.statsDays) days = limits.statsDays;
  // "All time" is only a limit when the plan can't reach that far back.
  const limited = wanted === 0 ? limits.statsDays < 3650 : wanted > limits.statsDays;
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
    plan, limited, limits,
    range: { days, since, until: Date.now(), hourly, firstEvent: first.results[0] ? first.results[0].first : null },
    totals: totals.results[0],
    series: series.results,
    links: links.results,
    visitors: limits.visitorList ? visitors.results : [],
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
    `SELECT u.username, u.display, u.created, u.disabled, u.plan, u.plan_until,
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
