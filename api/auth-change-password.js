// /api/auth-change-password.js
//
// SECURITY FIX — replaces the client-side "change my password" flow, which
// used to fetch the current password hash into the browser to verify it
// there. This endpoint does the same verification server-side, using the
// Supabase service key, so the hash never leaves the server. Uses the same
// PBKDF2-SHA256 (100,000 iterations) format as index.html's nmHashPassword,
// so existing passwords work with zero migration.
//
// This does NOT require a session token — the current password itself is
// the proof of identity, exactly as it was before. Nothing about "who's
// allowed to do this" changes; only WHERE the password gets checked.
//
// SETUP NEEDED IN VERCEL: SUPABASE_URL, SUPABASE_SERVICE_KEY — already set.

import crypto from 'crypto';

function pbkdf2Hex(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function verifyStoredPassword(password, storedStr) {
  if (!storedStr || !storedStr.includes(':')) return storedStr === password;
  try {
    const [saltHex] = storedStr.split(':');
    return (saltHex + ':' + pbkdf2Hex(password, saltHex)) === storedStr;
  } catch (e) {
    return false;
  }
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, reason: 'Method not allowed' });
  }

  const { email, currentPassword, newPassword } = req.body || {};
  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ ok: false, reason: 'Missing email, current password, or new password' });
  }
  if (newPassword.length < 8) {
    return res.status(200).json({ ok: false, reason: 'New password must be at least 8 characters.' });
  }

  try {
    const lookupRes = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}&select=id,password&limit=1`);
    const rows = await lookupRes.json();
    const row = rows[0];
    if (!row) return res.status(200).json({ ok: false, reason: 'Could not find your account. Please contact support.' });

    if (!verifyStoredPassword(currentPassword, row.password)) {
      return res.status(200).json({ ok: false, reason: 'Your current password is incorrect.' });
    }

    const newStored = hashNewPassword(newPassword);
    const updateRes = await supaFetch(`users?id=eq.${encodeURIComponent(row.id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ password: newStored }),
    });
    const updated = await updateRes.json().catch(() => null);
    if (!updateRes.ok || !updated || updated.length === 0) {
      return res.status(200).json({ ok: false, reason: 'The update did not go through. Please contact support.' });
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('auth-change-password error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
