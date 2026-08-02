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

// ── shared helper: does this business (or admin) own the given listing? ──
async function businessOwnsListing(claims, listingId) {
  if (claims.role === 'admin') return true;
  if (claims.role !== 'business') return false;

  const bizRes = await supaFetch(`users?id=eq.${encodeURIComponent(claims.id)}&select=email&limit=1`);
  const bizRows = await bizRes.json();
  const businessEmail = bizRows[0]?.email || '';
  if (!businessEmail) return false;

  const listingRes = await supaFetch(
    `listings?id=eq.${encodeURIComponent(listingId)}&select=id,email,owner_email&limit=1`
  );
  const listingRows = await listingRes.json();
  const listing = listingRows[0];
  if (!listing) return false;

  return (
    (listing.email || '').toLowerCase() === businessEmail.toLowerCase() ||
    (listing.owner_email || '').toLowerCase() === businessEmail.toLowerCase()
  );
}

// Looks up an enquiry and confirms the calling business owns the listing
// it belongs to. Returns { enquiry } on success or { error } on failure,
// so callers can just `if (error) return error;`.
async function getOwnedEnquiry(claims, enquiryId) {
  const enqRes = await supaFetch(`enquiries?id=eq.${encodeURIComponent(enquiryId)}&select=id,listing_id&limit=1`);
  const enqRows = await enqRes.json();
  const enquiry = enqRows[0];
  if (!enquiry) return { error: { status: 404, json: { ok: false, reason: 'Enquiry not found.' } } };

  const owns = await businessOwnsListing(claims, enquiry.listing_id);
  if (!owns) return { error: { status: 403, json: { ok: false, reason: 'You can only manage enquiries on your own listing.' } } };

  return { enquiry };
}

// ── mode: list-enquiries (admin, or business who owns the listing) ──
async function handleListEnquiries(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const owns = await businessOwnsListing(claims, listingId);
    if (!owns) return { status: 403, json: { ok: false, reason: 'You can only view enquiries on your own listing.' } };

    const res = await supaFetch(`enquiries?listing_id=eq.${encodeURIComponent(listingId)}&select=*&order=created_at.desc`);
    if (!res.ok) throw new Error(await res.text());
    const enquiries = await res.json();

    return { status: 200, json: { ok: true, enquiries } };
  } catch (e) {
    console.error('moderate/list-enquiries error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: reply-enquiry (admin, or business who owns the listing) ──
async function handleReplyEnquiry(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { enquiryId, replyText, smsSent, emailSent } = body;
  if (!enquiryId || !replyText) return { status: 400, json: { ok: false, reason: 'Missing enquiryId or replyText' } };

  try {
    const { error } = await getOwnedEnquiry(claims, enquiryId);
    if (error) return error;

    const upd = await supaFetch(`enquiries?id=eq.${encodeURIComponent(enquiryId)}`, {
      method: 'PATCH',
      prefer: 'return=minimal',
      body: JSON.stringify({ replied: true, reply: replyText, reply_sms_sent: !!smsSent, reply_email_sent: !!emailSent }),
    });
    if (!upd.ok) throw new Error(await upd.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/reply-enquiry error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: delete-enquiry (admin, or business who owns the listing) ──
async function handleDeleteEnquiry(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { enquiryId } = body;
  if (!enquiryId) return { status: 400, json: { ok: false, reason: 'Missing enquiryId' } };

  try {
    const { error } = await getOwnedEnquiry(claims, enquiryId);
    if (error) return error;

    const del = await supaFetch(`enquiries?id=eq.${encodeURIComponent(enquiryId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!del.ok) throw new Error(await del.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-enquiry error:', e.message);
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
    else if (mode === 'list-enquiries') result = await handleListEnquiries(claims, body);
    else if (mode === 'reply-enquiry') result = await handleReplyEnquiry(claims, body);
    else if (mode === 'delete-enquiry') result = await handleDeleteEnquiry(claims, body);
    else result = { status: 400, json: { ok: false, reason: 'Unknown or missing mode' } };

    return res.status(result.status).json(result.json);
  } catch (e) {
    console.error('moderate.js error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
