// /api/admin-resets.js
//
// SECURITY FIX — replaces three client-side admin functions
// (admResetUserPassword, admLoadResets, admMarkResetDone) that all wrote
// to the `users` and `password_resets` tables directly with the anon key.
// Every action here now requires a valid admin session token (issued by
// /api/auth-login.js on admin login) — without one, this endpoint refuses
// to run, even though it uses the service key internally.
//
// SETUP NEEDED IN VERCEL: SUPABASE_URL, SUPABASE_SERVICE_KEY,
//   ADMIN_SESSION_SECRET (or reuses ADMIN_PASSWORD if not set — see
//   auth-login.js) — already covered by the admin login setup.

import crypto from 'crypto';

function verifyAdminToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const secret = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || '';
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const sigBuf = Buffer.from(sig || '', 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return false;
  return Date.now() < Number(payload);
}

function pbkdf2Hex(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}
function hashNewPassword(password) {
  const saltHex = crypto.randomBytes(16).toString('hex');
  return saltHex + ':' + pbkdf2Hex(password, saltHex);
}

async function supaFetch(path, opts = {}) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  return fetch(`${base}/rest/v1/${path}`, {
    ...opts,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Prefer: opts.prefer || 'return=representation',
      ...(opts.headers || {}),
    },
  });
}

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

  const adminToken = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!verifyAdminToken(adminToken)) {
    return res.status(401).json({ ok: false, reason: 'Admin session expired or invalid. Please log in again.' });
  }

  const { action } = req.body || {};

  try {
    if (action === 'list') {
      const listRes = await supaFetch('password_resets?select=*&order=requested_at.desc');
      const resets = await listRes.json();
      return res.status(200).json({ ok: true, resets });
    }

    if (action === 'mark-done') {
      const { id } = req.body;
      if (!id) return res.status(400).json({ ok: false, reason: 'Missing id' });
      const upd = await supaFetch(`password_resets?id=eq.${encodeURIComponent(id)}`, {
        method: 'PATCH', body: JSON.stringify({ status: 'done' }),
      });
      if (!upd.ok) throw new Error(await upd.text());
      return res.status(200).json({ ok: true });
    }

    if (action === 'reset-password') {
      const { email, newPassword } = req.body;
      if (!email || !newPassword) return res.status(400).json({ ok: false, reason: 'Missing email or new password' });
      if (newPassword.length < 8) return res.status(200).json({ ok: false, reason: 'Password must be at least 8 characters.' });

      const stored = hashNewPassword(newPassword);
      const updRes = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}`, {
        method: 'PATCH', body: JSON.stringify({ password: stored }),
      });
      const updated = await updRes.json().catch(() => null);
      if (!updRes.ok || !updated || updated.length === 0) {
        return res.status(200).json({ ok: false, reason: 'No account found with that email.' });
      }

      await supaFetch(`password_resets?email=eq.${encodeURIComponent(email)}&status=eq.pending`, {
        method: 'PATCH', body: JSON.stringify({ status: 'done' }),
      });

      return res.status(200).json({ ok: true });
    }

    if (action === 'lookup') {
      const { email } = req.body;
      if (!email) return res.status(400).json({ ok: false, reason: 'Missing email' });
      const lookupRes = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}&select=id,name,owner,email,role,plan,created_at,joinedAt,password`);
      const rows = await lookupRes.json();
      // SECURITY: strip the raw hash before it ever leaves the server —
      // the admin UI only ever needed to know whether one exists.
      const safeRows = rows.map(r => ({ ...r, password: undefined, hasPassword: !!r.password }));
      return res.status(200).json({ ok: true, rows: safeRows });
    }

    return res.status(400).json({ ok: false, reason: 'Unknown action' });
  } catch (e) {
    console.error('admin-resets error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
