// /api/ozow-notify.js
//
// Ozow calls this directly, server-to-server, once a payment finishes —
// this is NOT triggered by the customer's browser, which is exactly why
// it's the only place that should be trusted to actually unlock a boost.
// The customer's browser also gets redirected back to your SuccessUrl,
// but that redirect can be faked by anyone just visiting the URL with
// made-up query params — it should only ever be used for a "nice"
// on-screen message, never to unlock anything. This file is the real
// source of truth.
//
// SETUP NEEDED IN VERCEL (Project Settings → Environment Variables):
//   OZOW_PRIVATE_KEY       — same one used in /api/ozow-initiate.js
//   SUPABASE_URL           — already set in this project (reused as-is)
//   SUPABASE_SERVICE_KEY   — already set in this project. This is
//                            Supabase's "Secret key" (what used to be
//                            called service_role) — NOT the publishable/
//                            anon key used in index.html. This one
//                            bypasses Row Level Security, which is
//                            exactly why it must only ever live here on
//                            the server, never in the browser.
//
// IMPORTANT — ask me to double check this with you once real transactions
// start flowing: Ozow's docs for the exact field order used in their
// response/notification hash aren't fully public without a merchant
// login, so this uses the order confirmed by Ozow's own integration
// examples (SiteCode, TransactionId, TransactionReference, Amount,
// Status + your private key). If real notifications start arriving and
// the hash never matches, that field order is the first thing to check
// against your Ozow merchant admin docs — this code is written to FAIL
// CLOSED (reject/ignore) on a bad hash rather than trust anything it
// can't verify, so a wrong field order blocks legitimate payments from
// activating rather than letting fake ones through.

import crypto from 'crypto';

function verifyHash(body, privateKey) {
  const raw = [
    body.SiteCode,
    body.TransactionId,
    body.TransactionReference,
    body.Amount,
    body.Status,
  ].join('') + privateKey;
  const expected = crypto.createHash('sha512').update(raw.toLowerCase()).digest('hex');
  return expected.toLowerCase() === String(body.Hash || '').toLowerCase();
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).send('Method not allowed');
  }

  const body = req.body || {};
  const privateKey = process.env.OZOW_PRIVATE_KEY;

  if (!privateKey) {
    console.error('OZOW_PRIVATE_KEY not set — cannot verify Ozow notification.');
    return res.status(200).send('OK'); // ack anyway so Ozow doesn't retry forever
  }

  if (!verifyHash(body, privateKey)) {
    console.warn('Ozow notify: hash mismatch, ignoring payload', body);
    // Still 200 — a wrong hash could just as easily mean a stale field
    // order on our side as an attack, and Ozow will keep retrying a
    // non-200 response. Logging it (visible in Vercel logs) is enough
    // to catch and fix a real mismatch without spamming retries.
    return res.status(200).send('OK');
  }

  const planKey    = body.Optional1;
  const listingId  = body.Optional2;
  const status     = body.Status; // 'Complete' | 'Cancelled' | 'Error' | 'Pending'

  if (!planKey || !listingId) {
    console.warn('Ozow notify: verified but missing plan/listing in Optional1/2', body);
    return res.status(200).send('OK');
  }

  if (status !== 'Complete') {
    console.log(`Ozow notify: ${status} for listing ${listingId}, plan ${planKey} — not activating.`);
    return res.status(200).send('OK');
  }

  const supaUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_KEY;

  if (!supaUrl || !serviceKey) {
    console.error('SUPABASE_URL / SUPABASE_SERVICE_KEY not set — payment confirmed but boost NOT activated. Fix env vars and manually activate this one:', { listingId, planKey, transactionId: body.TransactionId });
    return res.status(200).send('OK');
  }

  try {
    const updateRes = await fetch(`${supaUrl}/rest/v1/listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      headers: {
        'apikey': serviceKey,
        'Authorization': `Bearer ${serviceKey}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
      },
      body: JSON.stringify({
        boost_tier: planKey,
        boost_started_at: new Date().toISOString(),
      }),
    });

    const updated = await updateRes.json().catch(() => null);

    if (!updateRes.ok || !updated || updated.length === 0) {
      console.error('Ozow notify: Supabase update failed or matched no rows.', { listingId, planKey, status: updateRes.status, updated });
    } else {
      console.log(`Ozow notify: listing ${listingId} boosted to ${planKey} — transaction ${body.TransactionId}`);
    }
  } catch (e) {
    console.error('Ozow notify: Supabase update threw an error.', e);
  }

  // Always 200 once we've verified the hash — Ozow just needs the ack.
  return res.status(200).send('OK');
}
