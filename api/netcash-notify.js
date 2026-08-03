// /api/netcash-notify.js
//
// Rebuilt to mirror the real, working /api/ozow-initiate.js +
// /api/ozow-notify.js pattern exactly — no separate payments table,
// straight REST PATCH to `listings` on confirmed payment.
//
// ONE file, two jobs, split by query string:
//
//   POST /api/netcash-notify?action=init
//     → called by the frontend when a customer clicks a boost plan.
//       Builds the locked, server-signed Pay Now fields.
//
//   POST /api/netcash-notify   (no query string)
//     → called by Netcash itself, server-to-server, after a
//       transaction settles. This exact URL is already saved in your
//       Netcash dashboard (Account profile > Service profiles >
//       NetConnector > Pay Now > Payment notifications > Notify URL),
//       so don't rename this file/path.
//
// SETUP NEEDED IN VERCEL (already confirmed present in this project):
//   NETCASH_SERVICE_KEY   — Pay Now service key
//   SUPABASE_URL          — already set, reused as-is
//   SUPABASE_SERVICE_KEY  — already set, reused as-is (Supabase secret
//                           key, bypasses RLS — server only, never sent
//                           to the browser)
//
// ⚠ SECURITY GAP — READ BEFORE GOING LIVE WITH REAL MONEY:
// Ozow's notify handler verifies a SHA512 hash built from SiteCode +
// TransactionId + TransactionReference + Amount + Status + your private
// key, and REJECTS anything that doesn't match — that's what stops
// anyone from just POSTing a fake "payment succeeded" request to that
// URL. Netcash's Pay Now eCommerce docs, as far as we've confirmed in
// this conversation, do NOT show an equivalent hash field on the
// server-to-server Notify callback. Until that's confirmed one way or
// another (check the "Notify URL" page in the docs sidebar — the one
// link we haven't opened yet), this endpoint has no way to cryptographically
// verify a request genuinely came from Netcash. It's still safe to test
// with, but don't treat a real payment as "confirmed real" from this
// alone until we've checked that page together.
//
// ALSO UNCONFIRMED — same caution as before: the exact field names
// Netcash sends TO this notify URL (whether payment was accepted, the
// final amount, etc.) are a best-guess mapping below, not verified
// against a live payload yet. First thing this function does is log the
// raw body — check Vercel logs after one real test transaction and send
// me that log if anything looks off.

const PLAN_PRICES = {
  starter: 49.99,
  growth: 219.99,
  pro: 299.99,
};

const DEFAULT_VENDOR_KEY = '24ade73c-98cf-47b3-99be-cc7b867b3080';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).send('Method not allowed');
  }

  const isInit = req.query && req.query.action === 'init';
  if (isInit) {
    return handleInit(req, res);
  }
  return handleNotify(req, res);
}

// ---------------------------------------------------------------------
// JOB 1: build the locked Pay Now form fields for the frontend redirect
// ---------------------------------------------------------------------
async function handleInit(req, res) {
  const { planKey, listingId, email, name } = req.body || {};

  if (!planKey || !PLAN_PRICES[planKey]) {
    return res.status(400).json({ ok: false, reason: 'Unknown or missing planKey' });
  }
  if (!listingId) {
    return res.status(400).json({ ok: false, reason: 'Missing listingId' });
  }

  const serviceKey = process.env.NETCASH_SERVICE_KEY;
  if (!serviceKey) {
    console.warn('NETCASH_SERVICE_KEY not set — boost payment not started.');
    return res.status(200).json({ ok: false, reason: 'Payments not configured yet' });
  }

  const amount = PLAN_PRICES[planKey];
  // Same reference style as the Ozow side, for consistency across logs.
  const reference = 'NM-' + planKey.toUpperCase() + '-' + listingId + '-' + Date.now();

  const fields = {
    m1: serviceKey,
    m2: DEFAULT_VENDOR_KEY,
    p2: reference,
    p3: `NoaMark ${planKey.charAt(0).toUpperCase() + planKey.slice(1)} Boost`,
    p4: amount.toFixed(2),
    Budget: 'Y',
    // m4/m5 are Netcash's "Extra" fields — per the docs, any text sent
    // here is returned once settlement is done. Same role as Ozow's
    // Optional1/Optional2: this is how the notify handler below knows
    // which plan and listing this payment was for.
    m4: planKey,
    m5: String(listingId),
  };

  if (email) fields.m9 = email;
  if (name) fields.m10 = name;

  return res.status(200).json({
    ok: true,
    postUrl: 'https://paynow.netcash.co.za/site/paynow.aspx',
    fields,
    planName: planKey.charAt(0).toUpperCase() + planKey.slice(1) + ' Plan',
  });
}

// ---------------------------------------------------------------------
// JOB 2: receive Netcash's server-to-server settlement notification
// ---------------------------------------------------------------------
async function handleNotify(req, res) {
  const body = req.body || {};
  console.log('[netcash-notify] raw payload:', JSON.stringify(body));

  // --- Best-guess field mapping — see the security note above. ---
  const planKey   = body.m4 || body.Extra1 || body.extra1;
  const listingId = body.m5 || body.Extra2 || body.extra2;
  const amountPaid = parseFloat(body.p4 || body.Amount || body.amount || '0');
  const accepted =
    body.TransactionAccepted === 'true' ||
    body.TransactionAccepted === true ||
    body.Accepted === '1' ||
    body.transactionAccepted === true;
  const reasonCode = body.Reason || body.reason || body.ReasonCode || null;
  // -----------------------------------------------------------------

  if (!planKey || !listingId) {
    console.warn('[netcash-notify] Missing plan/listing in payload — cannot process.', body);
    return res.status(200).send('OK');
  }

  if (!PLAN_PRICES[planKey]) {
    console.warn('[netcash-notify] Unknown planKey in payload:', planKey);
    return res.status(200).send('OK');
  }

  const expectedAmount = PLAN_PRICES[planKey];
  const amountMatches = Math.abs(amountPaid - expectedAmount) < 0.01;

  if (!accepted) {
    console.log(`[netcash-notify] Not accepted for listing ${listingId}, plan ${planKey}, reason: ${reasonCode} — not activating.`);
    return res.status(200).send('OK');
  }

  if (!amountMatches) {
    console.warn('[netcash-notify] Amount mismatch — refusing to activate.', { listingId, planKey, amountPaid, expectedAmount });
    return res.status(200).send('OK');
  }

  const supaUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_KEY;

  if (!supaUrl || !serviceKey) {
    console.error('SUPABASE_URL / SUPABASE_SERVICE_KEY not set — payment confirmed but boost NOT activated. Fix env vars and manually activate this one:', { listingId, planKey });
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
        status: 'approved',
      }),
    });

    const updated = await updateRes.json().catch(() => null);

    if (!updateRes.ok || !updated || updated.length === 0) {
      console.error('[netcash-notify] Supabase update failed or matched no rows.', { listingId, planKey, status: updateRes.status, updated });
    } else {
      console.log(`[netcash-notify] listing ${listingId} boosted to ${planKey}`);
    }
  } catch (e) {
    console.error('[netcash-notify] Supabase update threw an error.', e);
  }

  return res.status(200).send('OK');
}
