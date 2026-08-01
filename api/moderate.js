// /api/moderate.js
//
// Combines what would otherwise be two separate serverless functions
// (admin-delete-listing + delete-review) into one, routed via a `mode`
// field in the request body — same consolidation pattern already used in
// auth.js, done for the same reason: Vercel's Hobby plan caps a project
// at 12 serverless functions total, and this project is already close to
// that limit. Nothing about the security model changes — same real
// session-token verification, same ownership checks, just one file
// instead of two.
//
// SECURITY FIX this file provides: both actions used to happen directly
// from the browser via the public Supabase key, protected only by RLS
// policies that were named as if they checked ownership/admin status but
// actually had `USING (true)` — meaning ANYONE could delete ANY listing
// or ANY review on the platform. Both actions now require a real, signed
// session token, verified server-side, plus a real ownership check for
// business-initiated review deletes.
//
// SETUP NEEDED IN VERCEL (already set for other endpoints, reused here):
//   SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_SESSION_SECRET / ADMIN_PASSWORD

import crypto from 'crypto';

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
    return claims;
  } catch (e) { return null; }
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

// ── mode: delete-listing (admin only) ──
async function handleDeleteListing(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const enq = await supaFetch(`enquiries?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!enq.ok) throw new Error('Failed deleting enquiries: ' + await enq.text());

    const bkg = await supaFetch(`bookings?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!bkg.ok) throw new Error('Failed deleting bookings: ' + await bkg.text());

    const notif = await supaFetch(`notifications?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!notif.ok) throw new Error('Failed deleting notifications: ' + await notif.text());

    const rev = await supaFetch(`reviews?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!rev.ok) throw new Error('Failed deleting reviews: ' + await rev.text());

    const lst = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!lst.ok) throw new Error('Failed deleting listing: ' + await lst.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-listing error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: delete-review (admin, or business who owns the listing) ──
async function handleDeleteReview(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { reviewId } = body;
  if (!reviewId) return { status: 400, json: { ok: false, reason: 'Missing reviewId' } };

  try {
    const revRes = await supaFetch(`reviews?id=eq.${encodeURIComponent(reviewId)}&select=id,listing_id&limit=1`);
    const revRows = await revRes.json();
    const review = revRows[0];
    if (!review) return { status: 404, json: { ok: false, reason: 'Review not found.' } };

    if (claims.role === 'business') {
      const bizRes = await supaFetch(`users?id=eq.${encodeURIComponent(claims.id)}&select=email&limit=1`);
      const bizRows = await bizRes.json();
      const businessEmail = bizRows[0]?.email || '';

      const listingRes = await supaFetch(
        `listings?id=eq.${encodeURIComponent(review.listing_id)}&select=id,email,owner_email&limit=1`
      );
      const listingRows = await listingRes.json();
      const listing = listingRows[0];

      const ownsIt = listing && businessEmail && (
        (listing.email || '').toLowerCase() === businessEmail.toLowerCase() ||
        (listing.owner_email || '').toLowerCase() === businessEmail.toLowerCase()
      );

      if (!ownsIt) {
        return { status: 403, json: { ok: false, reason: 'You can only delete reviews on your own listing.' } };
      }
    }

    const delRes = await supaFetch(`reviews?id=eq.${encodeURIComponent(reviewId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!delRes.ok) throw new Error(await delRes.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-review error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
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

  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const claims = verifySessionToken(token);
  if (!claims) {
    return res.status(401).json({ ok: false, reason: 'Please log in again.' });
  }

  const body = req.body || {};
  const mode = body.mode;

  try {
    let result;
    if (mode === 'delete-listing') result = await handleDeleteListing(claims, body);
    else if (mode === 'delete-review') result = await handleDeleteReview(claims, body);
    else result = { status: 400, json: { ok: false, reason: 'Unknown or missing mode' } };

    return res.status(result.status).json(result.json);
  } catch (e) {
    console.error('moderate.js error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
