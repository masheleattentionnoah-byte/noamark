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
// UPDATED (Aug 2026): verifyHash now covers the FULL 13-field notification
// hash, confirmed directly against Ozow's own published docs
// (ozow.com/integrations, Step 2 "Notification Response Post variables"):
// SiteCode, TransactionId, TransactionReference, Amount, Status, Optional1,
// Optional2, Optional3, Optional4, Optional5, CurrencyCode, IsTest,
// StatusMessage + private key, lowercased, SHA512.
//
// Previously this only hashed the first 5 fields (SiteCode through
// Status). That was a guess made before Ozow's field order was confirmed,
// and it meant the hash could basically never match a real Ozow
// notification — so every genuine payment confirmation would have been
// silently ignored by the fail-closed check below (logged as a mismatch,
// acked with 200, boost never activated). This is very likely the actual
// reason nothing has activated end-to-end yet — fixing this matters at
// least as much as anything on the initiate side.
//
// Still written to FAIL CLOSED on a bad hash — reject/ignore rather than
// trust anything that doesn't verify — so a stale field order blocks
// legitimate payments from activating rather than letting fake ones
// through. If this ever needs re-checking, compare again against
// ozow.com/integrations Step 2.
//
// UPDATED (Aug 2026): now also sets boost_paid_at and boost_payment_ref
// on activation. These two columns are what the admin Revenue dashboard
// (index.html, admLoadRevenue) actually checks to count a boost as
// CONFIRMED revenue vs. one an admin set manually via admSetBoost — this
// file previously only set boost_tier/boost_started_at, which meant
// every real Ozow payment was invisible to the Revenue dashboard even
// though the boost itself activated correctly. Netcash's notify handler
// (api/netcash-notify.js) already does this; this brings Ozow to parity.

import crypto from 'crypto';

function verifyHash(body, privateKey) {
  const raw = [
    body.SiteCode,
    body.TransactionId,
    body.TransactionReference,
    body.Amount,
    body.Status,
    body.Optional1 ?? '',
    body.Optional2 ?? '',
    body.Optional3 ?? '',
    body.Optional4 ?? '',
    body.Optional5 ?? '',
    body.CurrencyCode ?? '',
    body.IsTest ?? '',
    body.StatusMessage ?? '',
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
        // Same two columns netcash-notify.js sets — this is what makes
        // a payment count as CONFIRMED on the admin Revenue dashboard,
        // as opposed to a tier an admin set manually via admSetBoost.
        boost_paid_at: new Date().toISOString(),
        boost_payment_ref: body.TransactionId || body.TransactionReference || null,
        // Restores visibility for a listing that was previously unlisted
        // (status='suspended') by check-trials.js after an unpaid grace
        // period. Harmless no-op for a listing that was already approved.
        status: 'approved',
        // AUTO-VERIFY (Pro plan only): the pricing page lists "Verified
        // badge" as a Pro-tier feature, so a confirmed Pro payment should
        // grant it automatically instead of an admin having to click
        // "Mark Verified" by hand every time. Deliberately only ever sets
        // this to true here, never false — Starter/Growth payments just
        // don't touch the verified column at all, so a listing verified
        // for some other legitimate reason is never silently un-verified
        // by this webhook.
        ...(planKey === 'pro' ? { verified: true } : {}),
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
