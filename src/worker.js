// kortes.org Worker: static site + client area login + contact form + Substack feed.
// Static files live in /public and are served by the ASSETS binding.
// The Worker runs first only for /api/*, /client/* and /logout (see wrangler.jsonc).

const enc = new TextEncoder();
const SESSION_COOKIE = "kortes_session";
const SESSION_HOURS = 12;
const PBKDF2_ITERATIONS = 100000;
const MAX_FAILS = 10; // per username per 15 minutes

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return hex(bits);
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}

async function makeSession(env, userId) {
  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  const payload = `${userId}.${exp}`;
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

async function currentUser(env, request) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
  if (!m) return null;
  const [uid, exp, sig] = m[1].split(".");
  if (!uid || !exp || !sig || Date.now() > Number(exp)) return null;
  if (!safeEqual(sig, await hmac(env.SESSION_SECRET, `${uid}.${exp}`))) return null;
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(Number(uid)).first();
  if (!user || user.disabled) return null;
  if (user.expires_at && new Date(user.expires_at) < new Date()) return null;
  return user;
}

function allowedSlugs(user) {
  try {
    const v = JSON.parse(user.allowed_paths || "[]");
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}
const canSee = (user, slug) => {
  const s = allowedSlugs(user);
  return s.includes("*") || s.includes(slug);
};

const redirect = (to, headers = {}) => new Response(null, { status: 303, headers: { Location: to, ...headers } });
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const PRIVATE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "private, no-store",
  "X-Robots-Tag": "noindex, nofollow",
  "Referrer-Policy": "same-origin",
};

// ---------- login / logout ----------
async function handleLogin(request, env) {
  if (request.method !== "POST") return redirect("/login/");
  const form = await request.formData();
  const username = String(form.get("username") || "").trim().toLowerCase();
  const password = String(form.get("password") || "");
  let next = String(form.get("next") || "/client/");
  if (!next.startsWith("/client/")) next = "/client/";
  const back = (err) => redirect(`/login/?error=${err}&next=${encodeURIComponent(next)}`);

  const country = request.cf?.country || null;
  const ua = (request.headers.get("User-Agent") || "").slice(0, 300);

  const fails = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM logins WHERE username_tried = ? AND success = 0 AND created_at > datetime('now','-15 minutes')"
  ).bind(username).first();
  if (fails && fails.n >= MAX_FAILS) return back("locked");

  const user = username ? await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first() : null;
  let ok = false;
  if (user && !user.disabled && !(user.expires_at && new Date(user.expires_at) < new Date())) {
    ok = safeEqual(await hashPassword(password, user.salt), user.password_hash);
  }
  await env.DB.prepare("INSERT INTO logins (user_id, username_tried, success, country, user_agent) VALUES (?, ?, ?, ?, ?)")
    .bind(user ? user.id : null, username, ok ? 1 : 0, country, ua)
    .run();
  if (!ok) return back("1");

  const token = await makeSession(env, user.id);
  return redirect(next, {
    "Set-Cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}`,
  });
}

const logout = () =>
  redirect("/login/", { "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });

// ---------- client area ----------
function clientShell(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · kortes</title><meta name="robots" content="noindex, nofollow">
<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/site.css"></head><body>
<header class="site-header"><div class="wrap"><a class="brand" href="/" style="color:var(--paper);font-weight:700;font-size:22px;text-decoration:none">kortes</a>
<nav class="nav"><a href="/client/" aria-current="page">Client area</a><a class="cta" href="/logout">Sign out</a></nav></div></header>
<main id="main">${body}</main></body></html>`;
}

async function handleClient(request, env, url) {
  const user = await currentUser(env, request);
  if (!user) return redirect(`/login/?next=${encodeURIComponent(url.pathname)}`);

  const slug = url.pathname.replace(/^\/client\/?/, "").replace(/\/$/, "");
  if (!slug) {
    const list = await env.PRIVATE.list();
    const items = list.keys.filter((k) => canSee(user, k.name));
    const cards = items.length
      ? items
          .map(
            (k) =>
              `<a class="post" href="/client/${esc(k.name)}/"><h3>${esc(k.metadata?.title || k.name)}</h3><p>${esc(k.metadata?.summary || "")}</p></a>`
          )
          .join("")
      : `<p class="empty">Nothing here yet. Your reports will appear on this page.</p>`;
    const hello = user.display_name ? `Hello, ${esc(user.display_name)}` : "Your reports";
    return new Response(
      clientShell("Client area", `<div class="page-head"><div class="wrap"><h1>${hello}</h1><p>Dashboards and reports shared with you.</p></div></div><section><div class="wrap"><div class="posts">${cards}</div></div></section>`),
      { headers: PRIVATE_HEADERS }
    );
  }

  if (!/^[a-z0-9-]{1,80}$/.test(slug) || !canSee(user, slug)) {
    return new Response(clientShell("Not available", `<div class="page-head"><div class="wrap"><h1>Not available</h1><p>This report isn't shared with your account.</p></div></div>`), {
      status: 403,
      headers: PRIVATE_HEADERS,
    });
  }
  const html = await env.PRIVATE.get(slug);
  if (!html) return new Response(clientShell("Not found", `<div class="page-head"><div class="wrap"><h1>Not found</h1></div></div>`), { status: 404, headers: PRIVATE_HEADERS });
  await env.DB.prepare("INSERT INTO page_views (user_id, slug, country) VALUES (?, ?, ?)").bind(user.id, slug, request.cf?.country || null).run();
  return new Response(html, { headers: PRIVATE_HEADERS });
}

// ---------- contact form ----------
async function handleContact(request, env) {
  if (request.method !== "POST") return json({ ok: false }, 405);
  const f = await request.formData();
  if (String(f.get("website") || "")) return json({ ok: true }); // honeypot: silently drop bots
  const name = String(f.get("name") || "").trim().slice(0, 120);
  const email = String(f.get("email") || "").trim().slice(0, 200);
  const organisation = String(f.get("organisation") || "").trim().slice(0, 200);
  const message = String(f.get("message") || "").trim().slice(0, 4000);
  const consent = f.get("consent") === "1";
  if (!name || !message) return json({ ok: false, error: "Please fill in your name and your question." }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ ok: false, error: "Please check your email address." }, 400);
  if (!consent) return json({ ok: false, error: "Please tick the consent box so I can reply." }, 400);

  const res = await env.DB.prepare("INSERT INTO leads (name, email, organisation, message, consent) VALUES (?, ?, ?, ?, 1)")
    .bind(name, email, organisation || null, message)
    .run();

  if (env.HUBSPOT_TOKEN) {
    try {
      const [firstname, ...rest] = name.split(" ");
      const r = await fetch("https://api.hubapi.com/crm/v3/objects/contacts", {
        method: "POST",
        headers: { Authorization: `Bearer ${env.HUBSPOT_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ properties: { email, firstname, lastname: rest.join(" "), company: organisation, message } }),
      });
      if (r.ok || r.status === 409) {
        await env.DB.prepare("UPDATE leads SET crm_synced = 1 WHERE id = ?").bind(res.meta.last_row_id).run();
      }
    } catch {}
  }
  return json({ ok: true });
}

// ---------- Substack feed ----------
async function handlePosts(env, url) {
  const limit = Math.min(Number(url.searchParams.get("limit")) || 3, 50);
  if (!env.SUBSTACK_FEED) return json({ posts: [] });
  try {
    const r = await fetch(env.SUBSTACK_FEED, { cf: { cacheTtl: 900, cacheEverything: true } });
    if (!r.ok) return json({ posts: [] });
    const xml = await r.text();
    const pick = (block, tag) => {
      const m = block.match(new RegExp(`<${tag}>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</${tag}>`));
      return m ? m[1].trim() : "";
    };
    const posts = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].slice(0, limit).map(([, b]) => ({
      title: pick(b, "title"),
      link: pick(b, "link"),
      date: pick(b, "pubDate"),
      summary: pick(b, "description").replace(/<[^>]+>/g, "").slice(0, 220),
    }));
    return new Response(JSON.stringify({ posts }), {
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=900" },
    });
  } catch {
    return json({ posts: [] });
  }
}

function noindex(res) {
  const r = new Response(res.body, res);
  r.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive, noai, noimageai");
  return r;
}

export default {
  async fetch(request, env) {
    return noindex(await route(request, env));
  },
};

async function route(request, env) {
  {
    const url = new URL(request.url);
    const p = url.pathname;
    if (p === "/api/login") return handleLogin(request, env);
    if (p === "/api/contact") return handleContact(request, env);
    if (p === "/api/posts") return handlePosts(env, url);
    if (p === "/logout") return logout();
    if (p === "/client" || p.startsWith("/client/")) return handleClient(request, env, url);
    return env.ASSETS.fetch(request);
  }
}
