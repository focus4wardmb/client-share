// Per-client password gate for clients.focus4ward.co
//
// How it works:
// - Runs on every request to the site (path = "/*" in netlify.toml).
// - Extracts the first path segment as the client slug (e.g. /thynk-reference/index.html -> "thynk-reference").
// - Looks up the password from an env var named AUDIT_PASS_<SLUG_UPPER_UNDERSCORED>.
//   (Fallback table below for local testing only — replace with env vars before going wide.)
// - If no password is configured for that slug, request passes through (this is the
//   default for the root / images / augur, which are intentionally not gated).
// - If a password IS configured:
//     - Valid cookie ("audit_<slug>=<sha256-of-password+salt>") -> pass through.
//     - URL query "?key=<password>" matches -> set cookie scoped to /<slug>/, redirect to clean URL.
//     - Otherwise -> serve a login page (HTTP 401).
//
// Cookie scoping rule (the load-bearing security guarantee): every cookie is set
// with Path=/<slug>/. A client authenticated for /thynk-reference/ does NOT have
// their cookie sent on requests to /salecycle/, so they cannot bypass that gate
// by reusing their session. Each client gets cross-tenant isolation by default.

import type { Context } from "https://edge.netlify.com";

const SALT = "focus4ward-audit-2026";

// Local fallback passwords for testing before env vars are configured in
// Netlify dashboard. Env vars take precedence and should be used for production.
// REMOVE entries here once corresponding AUDIT_PASS_<SLUG> env vars are set.
const FALLBACK_PASSWORDS: Record<string, string> = {
  "thynk-reference": "purple-spacecraft-2026",
  "axeleo": "axeleo-portcos-2026",
  "augur": "augur-research-2026",
  "swan-audit": "swan-audit-audit-2026",
  "salecycle": "salecycle-audit-2026",
};

export default async function handler(req: Request, context: Context) {
  const url = new URL(req.url);
  const pathParts = url.pathname.split("/").filter(Boolean);

  // Root, /images/, top-level files — no slug, no gate.
  if (pathParts.length === 0) return context.next();

  const slug = pathParts[0];

  // Images and other non-client top-level paths are not gated.
  if (slug === "images" || slug.includes(".")) return context.next();

  // Look up password: env var first, fallback table second.
  const envVarName = `AUDIT_PASS_${slug.toUpperCase().replace(/-/g, "_")}`;
  const password = Deno.env.get(envVarName) ?? FALLBACK_PASSWORDS[slug];

  // No password configured for this folder = not gated (e.g. /augur/).
  if (!password) return context.next();

  const cookieName = `audit_${slug}`;
  const expectedCookieValue = await hashPassword(password);
  const cookies = parseCookies(req.headers.get("cookie") ?? "");

  // Already authenticated for THIS client (cookie is path-scoped per-slug).
  if (cookies[cookieName] === expectedCookieValue) {
    return context.next();
  }

  // Login attempt via ?key=...
  const submittedKey = url.searchParams.get("key");
  if (submittedKey && submittedKey === password) {
    const cleanUrl = new URL(req.url);
    cleanUrl.searchParams.delete("key");
    const headers = new Headers();
    headers.set("Location", cleanUrl.toString());
    headers.set(
      "Set-Cookie",
      `${cookieName}=${expectedCookieValue}; Path=/${slug}/; HttpOnly; SameSite=Strict; Secure; Max-Age=2592000`
    );
    return new Response(null, { status: 302, headers });
  }

  // Show login page. Pass the originally-requested path so the form submits
  // back to it — otherwise after auth we'd redirect to /<slug>/ which may
  // not have an index.html (e.g. the file lives at /<slug>/<page>/index.html).
  return new Response(loginPageHtml(slug, url.pathname, !!submittedKey), {
    status: 401,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieHeader.split(";").forEach((c) => {
    const [name, ...rest] = c.trim().split("=");
    if (name) cookies[name] = rest.join("=");
  });
  return cookies;
}

async function hashPassword(p: string): Promise<string> {
  const data = new TextEncoder().encode(p + SALT);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function loginPageHtml(slug: string, returnTo: string, wrongAttempt: boolean): string {
  const errorBanner = wrongAttempt
    ? `<div class="err">That password didn't match. Try again, or get in touch if you weren't sent one.</div>`
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Protected · Focus4ward</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:'Space Grotesk',sans-serif;background:#1E2530;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;-webkit-font-smoothing:antialiased}
.card{max-width:440px;width:100%}
.eyebrow{font-size:11px;font-weight:700;letter-spacing:2.5px;text-transform:uppercase;color:rgba(255,255,255,.5);margin-bottom:14px}
h1{font-size:26px;font-weight:700;line-height:1.2;letter-spacing:-.4px;margin-bottom:10px}
p.lede{font-size:15px;line-height:1.6;color:rgba(255,255,255,.7);margin-bottom:28px}
form{display:flex;gap:8px}
.pwwrap{position:relative;flex:1}
.pwwrap input{width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.15);color:#fff;padding:13px 56px 13px 16px;font-family:inherit;font-size:15px;border-radius:8px;outline:none;letter-spacing:.5px}
.pwwrap input:focus{border-color:#C9316E;background:rgba(255,255,255,.09)}
.show-btn{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:transparent;border:none;color:rgba(255,255,255,.55);font-family:inherit;font-size:11px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;padding:8px 10px;cursor:pointer;border-radius:5px}
.show-btn:hover{background:rgba(255,255,255,.08);color:rgba(255,255,255,.85)}
button.submit{background:#C9316E;color:#fff;border:none;padding:13px 22px;font-family:inherit;font-weight:600;font-size:14px;border-radius:8px;cursor:pointer;letter-spacing:.2px}
button.submit:hover{background:#b22a61}
.err{background:rgba(201,49,110,.15);border:1px solid rgba(201,49,110,.4);color:#ffcfdb;padding:11px 14px;border-radius:8px;font-size:13px;margin-bottom:20px;line-height:1.5}
.meta{margin-top:24px;font-size:12px;color:rgba(255,255,255,.4);line-height:1.6}
.meta a{color:rgba(255,255,255,.6);text-decoration:none;border-bottom:1px solid rgba(255,255,255,.2)}
</style>
</head>
<body>
<div class="card">
  <div class="eyebrow">Focus4ward · Confidential</div>
  <h1>This document is protected</h1>
  <p class="lede">Enter the password Miri sent you to view this audit.</p>
  ${errorBanner}
  <form method="get" action="${returnTo}">
    <div class="pwwrap">
      <input type="password" id="pw" name="key" placeholder="Password" autofocus autocomplete="current-password" required>
      <button type="button" class="show-btn" id="toggle" aria-label="Show password">Show</button>
    </div>
    <button type="submit" class="submit">Open</button>
  </form>
  <div class="meta">If you weren't sent a password and reached this page by mistake, you can <a href="/">return home</a>.</div>
</div>
<script>
(function(){
  var inp = document.getElementById('pw');
  var btn = document.getElementById('toggle');
  btn.addEventListener('click', function(){
    if(inp.type === 'password'){ inp.type = 'text'; btn.textContent = 'Hide'; }
    else { inp.type = 'password'; btn.textContent = 'Show'; }
    inp.focus();
  });
})();
</script>
</body>
</html>`;
}
