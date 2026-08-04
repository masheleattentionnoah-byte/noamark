// /api/auth.js
//
// SECURITY FIX — consolidated version of what was previously 4 separate
// files (auth-login.js, auth-change-password.js, auth-forgot-password.js,
// admin-resets.js). Vercel's Hobby plan caps a project at 12 serverless
// functions total, and adding those 4 alongside the existing 9 pushed this
// project to 13 — this merge brings it back down to 10, with room to spare.
//
// UPDATE (session tokens for business logins):
// Previously only admin logins got a signed session token — business
// logins just returned a user object the frontend trusted blindly, which
// meant any server endpoint that needed to know "is this really a logged-
// in business, and which one" had no way to check. Now business (and
// admin) logins both get a signed token, using the same HMAC pattern that
// was already trusted for admin. Nothing about password verification
// changes — this only adds a verifiable "who is calling" proof that other
// endpoints (like netcash-payment-request.js) can require.
//
// SETUP NEEDED IN VERCEL (unchanged from before):
//   SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_EMAIL, ADMIN_PASSWORD,
//   ADMIN_SESSION_SECRET

import crypto from 'crypto';

// ── shared helpers ──

function pbkdf2Hex(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}
function verifyStoredPassword(password, storedStr) {
  if (!storedStr || !storedStr.includes(':')) return storedStr === password;
  try {
    const [saltHex] = storedStr.split(':');
    return (saltHex + ':' + pbkdf2Hex(password, saltHex)) === storedStr;
  } catch (e) { return false; }
}
function hashNewPassword(password) {
  const saltHex = crypto.randomBytes(16).toString('hex');
  return saltHex + ':' + pbkdf2Hex(password, saltHex);
}

// Generalized session token — works for admin AND business (and could be
// extended to subscriber/guest later the same way). Same HMAC-signed,
// timing-safe-compared approach that was already used for admin only.
function issueSessionToken(claims) {
  const secret = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || '';
  const expires = Date.now() + 12 * 60 * 60 * 1000; // 12 hours
  const payload = Buffer.from(JSON.stringify({ ...claims, exp: expires })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `${payload}.${sig}`;
}
function verifySessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const secret = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || '';
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const sigBuf = Buffer.from(sig || '', 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() >= claims.exp) return null;
    return claims; // { role, id, email, exp }
  } catch (e) { return null; }
}

async function supaFetch(path, opts = {}) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  const res = await fetch(`${base}/rest/v1/${path}`, {
    ...opts,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Prefer: opts.prefer || 'return=representation',
      ...(opts.headers || {}),
    },
  });
  return res;
}

// ── mode handlers ──

async function handleLogin(body) {
  const { role, email, name, password } = body;
  if (!role || !password) return { status: 400, json: { ok: false, reason: 'Missing role or password' } };

  if (role === 'admin') {
    const adminEmail = process.env.ADMIN_EMAIL || '';
    const adminPassword = process.env.ADMIN_PASSWORD || '';
    if (!adminEmail || !adminPassword) {
      console.error('ADMIN_EMAIL / ADMIN_PASSWORD not set.');
      return { status: 200, json: { ok: false, reason: 'Admin login not configured.' } };
    }
    if ((email || '').toLowerCase() !== adminEmail.toLowerCase() || password !== adminPassword) {
      return { status: 200, json: { ok: false, reason: 'Incorrect email or password.' } };
    }
    return { status: 200, json: {
      ok: true,
      user: { type: 'admin', name: 'NoaMark Admin', owner: 'NoaMark', email: adminEmail, plan: 'Admin', id: 'admin-001' },
      sessionToken: issueSessionToken({ role: 'admin', id: 'admin-001', email: adminEmail }),
      // adminToken kept as an alias so existing frontend code that reads
      // `data.adminToken` doesn't break before you update it to sessionToken.
      adminToken: issueSessionToken({ role: 'admin', id: 'admin-001', email: adminEmail }),
    }};
  }

  if (role === 'business') {
    if (!email || !name) return { status: 400, json: { ok: false, reason: 'Missing email or business name' } };
    const r = await supaFetch(`users?role=eq.business&email=ilike.${encodeURIComponent(email)}&select=*&limit=1`);
    const rows = await r.json();
    const biz = rows[0];
    if (!biz) return { status: 200, json: { ok: false, reason: 'no_account' } };
    if (biz.name.trim().toLowerCase() !== name.trim().toLowerCase()) return { status: 200, json: { ok: false, reason: 'name_mismatch' } };
    if (!verifyStoredPassword(password, biz.password)) return { status: 200, json: { ok: false, reason: 'bad_password' } };
    return { status: 200, json: {
      ok: true,
      user: { type: 'business', name: biz.name, owner: biz.owner || biz.name, email: biz.email, plan: 'Business', id: biz.id, joinedAt: biz.joinedAt || biz.created_at },
      sessionToken: issueSessionToken({ role: 'business', id: biz.id, email: biz.email }),
    }};
  }

  if (role === 'subscriber') {
    if (!email || !name) return { status: 400, json: { ok: false, reason: 'Missing email or name' } };
    const r = await supaFetch(`users?role=eq.subscriber&name=ilike.${encodeURIComponent(name)}&select=*&limit=1`);
    const rows = await r.json();
    const sub = rows[0];
    if (!sub) return { status: 200, json: { ok: false, reason: 'no_account' } };
    if (sub.email.toLowerCase() !== email.toLowerCase()) return { status: 200, json: { ok: false, reason: 'email_mismatch' } };
    if (!verifyStoredPassword(password, sub.password)) return { status: 200, json: { ok: false, reason: 'bad_password' } };
    return { status: 200, json: {
      ok: true,
      user: { type: 'subscriber', name: sub.name, email: sub.email, plan: sub.plan || 'Free', id: sub.id },
      sessionToken: issueSessionToken({ role: 'subscriber', id: sub.id, email: sub.email }),
    }};
  }

  if (role === 'guest') {
    if (!name) return { status: 400, json: { ok: false, reason: 'Missing name' } };
    const r = await supaFetch(`users?role=eq.guest&name=ilike.${encodeURIComponent(name)}&select=*&limit=1`);
    const rows = await r.json();
    const guest = rows[0];
    if (!guest) return { status: 200, json: { ok: false, reason: 'no_account' } };
    if (!verifyStoredPassword(password, guest.password)) return { status: 200, json: { ok: false, reason: 'bad_password' } };
    return { status: 200, json: { ok: true, user: { type: 'guest', name: guest.name, location: guest.email || '', plan: 'Explorer', id: guest.id } } };
  }

  return { status: 400, json: { ok: false, reason: 'Unknown role' } };
}

async function handleChangePassword(body) {
  const { email, currentPassword, newPassword } = body;
  if (!email || !currentPassword || !newPassword) return { status: 400, json: { ok: false, reason: 'Missing email, current password, or new password' } };
  if (newPassword.length < 8) return { status: 200, json: { ok: false, reason: 'New password must be at least 8 characters.' } };

  const lookupRes = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}&select=id,password&limit=1`);
  const rows = await lookupRes.json();
  const row = rows[0];
  if (!row) return { status: 200, json: { ok: false, reason: 'Could not find your account. Please contact support.' } };
  if (!verifyStoredPassword(currentPassword, row.password)) return { status: 200, json: { ok: false, reason: 'Your current password is incorrect.' } };

  const newStored = hashNewPassword(newPassword);
  const updateRes = await supaFetch(`users?id=eq.${encodeURIComponent(row.id)}`, { method: 'PATCH', body: JSON.stringify({ password: newStored }) });
  const updated = await updateRes.json().catch(() => null);
  if (!updateRes.ok || !updated || updated.length === 0) return { status: 200, json: { ok: false, reason: 'The update did not go through. Please contact support.' } };

  return { status: 200, json: { ok: true } };
}

async function handleForgotPassword(body) {
  const { email, name } = body;
  if (!email || !name) return { status: 400, json: { ok: false, reason: 'Missing email or name' } };

  const lookupRes = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}&select=id,role&limit=1`);
  const rows = await lookupRes.json();
  const row = rows[0];
  if (!row) return { status: 200, json: { ok: false, reason: 'No account found with that email address. Please check the email and try again.' } };

  const insertRes = await supaFetch('password_resets', {
    method: 'POST',
    body: JSON.stringify({ email, name, user_role: row.role || 'unknown', requested_at: new Date().toISOString(), status: 'pending' }),
  });
  if (!insertRes.ok) {
    console.error('forgot-password: insert failed', await insertRes.text());
    return { status: 200, json: { ok: false, reason: 'Something went wrong. Please try again or contact support@noamark.com directly.' } };
  }

  return { status: 200, json: { ok: true } };
}

async function handleAdmin(req, body) {
  const adminToken = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const claims = verifySessionToken(adminToken);
  if (!claims || claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin session expired or invalid. Please log in again.' } };
  }

  const { action } = body;

  if (action === 'list') {
    const r = await supaFetch('password_resets?select=*&order=requested_at.desc');
    const resets = await r.json();
    return { status: 200, json: { ok: true, resets } };
  }

  if (action === 'mark-done') {
    const { id } = body;
    if (!id) return { status: 400, json: { ok: false, reason: 'Missing id' } };
    const upd = await supaFetch(`password_resets?id=eq.${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ status: 'done' }) });
    if (!upd.ok) throw new Error(await upd.text());
    return { status: 200, json: { ok: true } };
  }

  if (action === 'delete') {
    const { id } = body;
    if (!id) return { status: 400, json: { ok: false, reason: 'Missing id' } };
    const del = await supaFetch(`password_resets?id=eq.${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!del.ok) throw new Error(await del.text());
    return { status: 200, json: { ok: true } };
  }

  if (action === 'reset-password') {
    const { email, newPassword } = body;
    if (!email || !newPassword) return { status: 400, json: { ok: false, reason: 'Missing email or new password' } };
    if (newPassword.length < 8) return { status: 200, json: { ok: false, reason: 'Password must be at least 8 characters.' } };

    const stored = hashNewPassword(newPassword);
    const updRes = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}`, { method: 'PATCH', body: JSON.stringify({ password: stored }) });
    const updated = await updRes.json().catch(() => null);
    if (!updRes.ok || !updated || updated.length === 0) return { status: 200, json: { ok: false, reason: 'No account found with that email.' } };

    await supaFetch(`password_resets?email=eq.${encodeURIComponent(email)}&status=eq.pending`, { method: 'PATCH', body: JSON.stringify({ status: 'done' }) });
    return { status: 200, json: { ok: true } };
  }

  if (action === 'lookup') {
    const { email } = body;
    if (!email) return { status: 400, json: { ok: false, reason: 'Missing email' } };
    const r = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}&select=id,name,owner,email,role,plan,created_at,joinedAt,password`);
    const rows = await r.json();
    const safeRows = rows.map(row => ({ ...row, password: undefined, hasPassword: !!row.password }));
    return { status: 200, json: { ok: true, rows: safeRows } };
  }

  return { status: 400, json: { ok: false, reason: 'Unknown action' } };
}

// ── entry point ──

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigins = ['https://noamark.com', 'https://www.noamark.com'];
  const isVercelPreview = /\.vercel\.app$/.test(origin.replace(/^https?:\/\//, ''));
  if (allowedOrigins.includes(origin) || isVercelPreview) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, reason: 'Method not allowed' });
  }

  const body = req.body || {};
  const mode = body.mode;

  try {
    let result;
    if (mode === 'login') result = await handleLogin(body);
    else if (mode === 'change-password') result = await handleChangePassword(body);
    else if (mode === 'forgot-password') result = await handleForgotPassword(body);
    else if (mode === 'admin') result = await handleAdmin(req, body);
    else result = { status: 400, json: { ok: false, reason: 'Unknown or missing mode' } };

    return res.status(result.status).json(result.json);
  } catch (e) {
    console.error('auth.js error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
