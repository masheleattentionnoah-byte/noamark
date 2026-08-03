// /api/netcash-notify.js
//
// Mirrors the working /api/ozow-initiate.js + /api/ozow-notify.js pattern —
// straight REST PATCH to `listings` on confirmed payment, no separate
// payments table.
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
// ✅ SECURITY GAP CLOSED — Transaction Trace verification:
// Netcash's Pay Now eCommerce docs confirm there is genuinely no hash/
// signature field on the server-to-server Notify callback (unlike Ozow,
// which sends a SHA512 hash you can check). So instead of trusting the
// incoming POST body, this handler takes the `RequestTrace` value from
// that POST and calls Netcash's own server directly:
//
//   GET https://ws.netcash.co.za/PayNow/TransactionStatus/Check?RequestTrace=<value>
//
// Netcash replies with the authoritative, unspoofable transaction data
// for that trace id. ONLY that verified reply — never the raw POST body
// — is used to decide whether a payment was actually accepted and for
// how much. This means someone POSTing a fake "payment succeeded"
// request to this URL cannot activate a boost: without a real
// RequestTrace that Netcash itself recognizes, the verification call
// fails and nothing happens.
//
// Field names below are confirmed against the live Netcash docs
// (Notify, Accept, Decline, Redirect pages + Transaction Trace):
//   TransactionAccepted, CardHolderIpAddr, RequestTrace, Reference,
//   Extra1 (=your m4), Extra2 (=your m5), Extra3 (=your m6), Amount,
//   Method — no longer a guess.

const PLAN_PRICES = {
  starter: 49.99,
  growth: 219.99,
  pro: 299.99,
};

const DEFAULT_VENDOR_KEY = '24ade73c-98cf-47b3-99be-cc7b867b3080';
const TRACE_CHECK_URL = 'https://ws.netcash.co.za/PayNow/TransactionStatus/Check';

export default async function handler(req, res) {
  const action = req.query && req.query.action;

  // Netcash's Redirect URL sends the customer's browser back with a POST
  // (not a normal GET link click), carrying the transaction result as
  // form fields. A static homepage only accepts GET, which is exactly
  // why a bare https://noamark.com/ Redirect URL gave "HTTP ERROR 405".
  // This branch exists ONLY to accept that POST and bounce the browser
  // home with a normal 302 (which becomes a GET) — same DISPLAY-ONLY
  // principle as the Ozow return handling in index.html. It must NEVER
  // touch Supabase or grant a boost: the customer's own browser landing
  // here can be faked by anyone just visiting the URL, so only the real
  // server-to-server call below (no query string) is trusted for that.
  if (action === 'redirect') {
    res.writeHead(302, { Location: 'https://noamark.com/' });
    return res.end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).send('Method not allowed');
  }

  const isInit = action === 'init';
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
    // m4/m5 are Netcash's "Extra" fields — confirmed in the docs to be
    // returned as Extra1/Extra2 once settlement is done. Same role as
    // Ozow's Optional1/Optional2: this is how the notify handler below
    // knows which plan and listing this payment was for.
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

  // planKey/listingId just tell us WHAT to activate — they aren't the
  // security-sensitive part, so it's fine to read them straight off the
  // POST body (Netcash echoes back whatever we originally sent in
  // m4/m5). The security-sensitive part — WHETHER this payment really
  // happened and for how much — is decided below using ONLY the
  // verified Transaction Trace reply, never these raw fields.
  const planKey   = body.Extra1 || body.m4;
  const listingId = body.Extra2 || body.m5;
  const requestTrace = body.RequestTrace;

  if (!planKey || !listingId) {
    console.warn('[netcash-notify] Missing plan/listing in payload — cannot process.', body);
    return res.status(200).send('OK');
  }

  if (!PLAN_PRICES[planKey]) {
    console.warn('[netcash-notify] Unknown planKey in payload:', planKey);
    return res.status(200).send('OK');
  }

  if (!requestTrace) {
    console.error('[netcash-notify] No RequestTrace in payload — cannot verify, refusing to activate.', { listingId, planKey });
    return res.status(200).send('OK');
  }

  // --- Ask Netcash directly: did this transaction really happen? ---
  let verified;
  try {
    const traceRes = await fetch(`${TRACE_CHECK_URL}?RequestTrace=${encodeURIComponent(requestTrace)}`);
    if (!traceRes.ok) {
      console.error('[netcash-notify] Transaction Trace call returned non-OK status — refusing to activate.', { status: traceRes.status, listingId, planKey });
      return res.status(200).send('OK');
    }
    verified = await traceRes.json();
  } catch (e) {
    console.error('[netcash-notify] Transaction Trace call threw an error — refusing to activate.', e);
    return res.status(200).send('OK');
  }

  console.log('[netcash-notify] Transaction Trace verified data:', JSON.stringify(verified));

  if (!verified) {
    console.error('[netcash-notify] Transaction Trace returned no data — refusing to activate.', { listingId, planKey, requestTrace });
    return res.status(200).send('OK');
  }

  const accepted =
    verified.TransactionAccepted === true ||
    verified.TransactionAccepted === 'true';
  const amountPaid = parseFloat(verified.Amount || '0');
  const reasonCode = verified.Reason || null;

  if (!accepted) {
    console.log(`[netcash-notify] Netcash's own trace says NOT accepted for listing ${listingId}, plan ${planKey}, reason: ${reasonCode} — not activating.`);
    return res.status(200).send('OK');
  }

  const expectedAmount = PLAN_PRICES[planKey];
  const amountMatches = Math.abs(amountPaid - expectedAmount) < 0.01;

  if (!amountMatches) {
    console.warn('[netcash-notify] Verified amount mismatch — refusing to activate.', { listingId, planKey, amountPaid, expectedAmount });
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
      console.log(`[netcash-notify] listing ${listingId} boosted to ${planKey} (verified via Transaction Trace)`);
    }
  } catch (e) {
    console.error('[netcash-notify] Supabase update threw an error.', e);
  }

  return res.status(200).send('OK');
}
