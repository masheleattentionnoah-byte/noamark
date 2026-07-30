// /api/auth-login.js
//
// SECURITY FIX — replaces client-side password verification.
//
// WHAT WAS WRONG BEFORE:
// Login worked by fetching the FULL user row (including the PBKDF2 password
// hash) from Supabase using the public anon key, then comparing the
// password in the browser. Because the browser needed to read that hash to
// verify a login, the `users` table RLS policies had to allow ANYONE (no
// login required) to read and write every row in the table — meaning every
// user's email + password hash was downloadable by anyone who opened dev
// tools, with no rate limit. Admin login had the same problem, and worse:
// the admin password was literally written in a comment in index.html.
//
// WHAT THIS FILE DOES INSTEAD:
// The password hash never leaves the server. This endpoint uses the
// Supabase SERVICE key (server-only, bypasses RLS) to fetch the user row,
// verifies the password here using Node's crypto (same PBKDF2-SHA256,
// 100,000 iterations, salt:hash format as the existing nmHashPassword /
// nmVerifyPassword functions in index.html — byte-for-byte compatible, so
// every existing password still works with zero migration needed), and
// returns only a safe, password-free user object to the browser.
//
// Once this is live and users.js RLS is tightened (separate step), a
// stolen/leaked anon key can no longer be used to read anyone's password
// hash or admin credentials — because the anon key will no longer be
// allowed to read the users table at all; only this server endpoint can,
// via the service key.
//
// SETUP NEEDED IN VERCEL (Project Settings → Environment Variables):
//   SUPABASE_URL, SUPABASE_SERVICE_KEY — already set, reused here.
//   ADMIN_EMAIL         — e.g. supportnoamark@gmail.com
//   ADMIN_PASSWORD      — your NEW admin password (plaintext value is fine
//                         to store as a Vercel env var — Vercel encrypts
//                         these at rest, and this is the standard way to
//                         store a single admin credential; it is NEVER
//                         shipped to the browser, unlike the old approach).
//                         Set this to a brand new password — the old one
//                         ("Noah#2026") was exposed in a source comment and
//                         must be treated as fully public/compromised.

import crypto from 'crypto';

// Issues a simple signed token proving "this browser successfully logged in
// as admin" — needed because admin actions after login (resetting a user's
// password, viewing the reset queue) must be verifiable server-side too;
// otherwise anyone could call those endpoints directly without ever
// actually logging in. 12-hour expiry — long enough for a work session,
// short enough that a leaked token doesn't stay valid indefinitely.
export function issueAdminToken() {
  const secret = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || '';
  const expires = Date.now() + 12 * 60 * 60 * 1000;
  const payload = String(expires);
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

export function verifyAdminToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const secret = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || '';
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  // Timing-safe comparison — a plain === check on a signature leaks timing
  // information an attacker could use to guess it byte-by-byte.
  const sigBuf = Buffer.from(sig || '', 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return false;
  return Date.now() < Number(payload);
}

function pbkdf2Hex(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return derived.toString('hex');
}

// Mirrors nmVerifyPassword() in index.html exactly, so every existing
// password (format "saltHex:hashHex") verifies correctly with no migration.
function verifyStoredPassword(password, storedStr) {
  if (!storedStr || !storedStr.includes(':')) {
    // Legacy plain-text fallback — matches existing client behaviour.
    return storedStr === password;
  }
  try {
    const [saltHex] = storedStr.split(':');
    const computed = saltHex + ':' + pbkdf2Hex(password, saltHex);
    return computed === storedStr;
  } catch (e) {
    return false;
  }
}

async function supaFetch(path) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  const res = await fetch(`${base}/rest/v1/${path}`, {
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) throw new Error('Supabase query failed: ' + (await res.text()));
  return res.json();
}

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigins = ['https://noamark.com', 'https://www.noamark.com'];
  const isVercelPreview = /\.vercel\.app$/.test(origin.replace(/^https?:\/\//, ''));
  if (allowedOrigins.includes(origin) || isVercelPreview) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, reason: 'Method not allowed' });
  }

  const { role, email, name, password } = req.body || {};
  if (!role || !password) {
    return res.status(400).json({ ok: false, reason: 'Missing role or password' });
  }

  try {
    // ── ADMIN ──
    if (role === 'admin') {
      const adminEmail = process.env.ADMIN_EMAIL || '';
      const adminPassword = process.env.ADMIN_PASSWORD || '';
      if (!adminEmail || !adminPassword) {
        console.error('ADMIN_EMAIL / ADMIN_PASSWORD not set in Vercel env vars.');
        return res.status(200).json({ ok: false, reason: 'Admin login not configured.' });
      }
      if ((email || '').toLowerCase() !== adminEmail.toLowerCase() || password !== adminPassword) {
        return res.status(200).json({ ok: false, reason: 'Incorrect email or password.' });
      }
      return res.status(200).json({
        ok: true,
        user: { type: 'admin', name: 'NoaMark Admin', owner: 'NoaMark', email: adminEmail, plan: 'Admin', id: 'admin-001' },
        adminToken: issueAdminToken(),
      });
    }

    // ── BUSINESS ──
    if (role === 'business') {
      if (!email || !name) return res.status(400).json({ ok: false, reason: 'Missing email or business name' });
      const rows = await supaFetch(
        `users?role=eq.business&email=ilike.${encodeURIComponent(email)}&select=*&limit=1`
      );
      const biz = rows[0];
      if (!biz) return res.status(200).json({ ok: false, reason: 'no_account' });
      if (biz.name.trim().toLowerCase() !== name.trim().toLowerCase()) {
        return res.status(200).json({ ok: false, reason: 'name_mismatch' });
      }
      if (!verifyStoredPassword(password, biz.password)) {
        return res.status(200).json({ ok: false, reason: 'bad_password' });
      }
      return res.status(200).json({
        ok: true,
        user: { type: 'business', name: biz.name, owner: biz.owner || biz.name, email: biz.email, plan: 'Business', id: biz.id, joinedAt: biz.joinedAt || biz.created_at },
      });
    }

    // ── SUBSCRIBER ──
    if (role === 'subscriber') {
      if (!email || !name) return res.status(400).json({ ok: false, reason: 'Missing email or name' });
      const rows = await supaFetch(
        `users?role=eq.subscriber&name=ilike.${encodeURIComponent(name)}&select=*&limit=1`
      );
      const sub = rows[0];
      if (!sub) return res.status(200).json({ ok: false, reason: 'no_account' });
      if (sub.email.toLowerCase() !== email.toLowerCase()) {
        return res.status(200).json({ ok: false, reason: 'email_mismatch' });
      }
      if (!verifyStoredPassword(password, sub.password)) {
        return res.status(200).json({ ok: false, reason: 'bad_password' });
      }
      return res.status(200).json({
        ok: true,
        user: { type: 'subscriber', name: sub.name, email: sub.email, plan: sub.plan || 'Free', id: sub.id },
      });
    }

    // ── GUEST ──
    if (role === 'guest') {
      if (!name) return res.status(400).json({ ok: false, reason: 'Missing name' });
      const rows = await supaFetch(
        `users?role=eq.guest&name=ilike.${encodeURIComponent(name)}&select=*&limit=1`
      );
      const guest = rows[0];
      if (!guest) return res.status(200).json({ ok: false, reason: 'no_account' });
      if (!verifyStoredPassword(password, guest.password)) {
        return res.status(200).json({ ok: false, reason: 'bad_password' });
      }
      return res.status(200).json({
        ok: true,
        user: { type: 'guest', name: guest.name, location: guest.email || '', plan: 'Explorer', id: guest.id },
      });
    }

    return res.status(400).json({ ok: false, reason: 'Unknown role' });
  } catch (e) {
    console.error('auth-login error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
