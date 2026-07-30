// /api/auth-forgot-password.js
//
// SECURITY FIX — replaces the client-side version, which queried the
// `users` table directly with the anon key to check if an account exists.
// That's an account-enumeration risk on its own, and required `users` SELECT
// to stay open to the public — exactly the exposure this whole fix removes.
// This endpoint does the same check server-side with the service key, and
// only ever returns ok:true/false — never any user data.
//
// SETUP NEEDED IN VERCEL: SUPABASE_URL, SUPABASE_SERVICE_KEY — already set.

async function supaFetch(path, opts = {}) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  return fetch(`${base}/rest/v1/${path}`, {
    ...opts,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Prefer: opts.prefer || 'return=minimal',
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

  const { email, name } = req.body || {};
  if (!email || !name) return res.status(400).json({ ok: false, reason: 'Missing email or name' });

  try {
    const lookupRes = await supaFetch(`users?email=ilike.${encodeURIComponent(email)}&select=id,role&limit=1`);
    const rows = await lookupRes.json();
    const row = rows[0];
    if (!row) {
      return res.status(200).json({ ok: false, reason: 'No account found with that email address. Please check the email and try again.' });
    }

    const insertRes = await supaFetch('password_resets', {
      method: 'POST',
      body: JSON.stringify({
        email,
        name,
        user_role: row.role || 'unknown',
        requested_at: new Date().toISOString(),
        status: 'pending',
      }),
    });
    if (!insertRes.ok) {
      console.error('auth-forgot-password: insert failed', await insertRes.text());
      return res.status(200).json({ ok: false, reason: 'Something went wrong. Please try again or contact support@noamark.com directly.' });
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('auth-forgot-password error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
