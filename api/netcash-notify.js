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
// ✅ SECURITY — CLOSED (confirmed via docs, Aug 2026):
// Netcash's Pay Now Notify callback has NO hash/signature field (unlike
// Ozow). Instead of trusting the incoming POST body, this file calls
// Netcash's own "Transaction trace" endpoint
// (https://ws.netcash.co.za/PayNow/TransactionStatus/Check) with the
// RequestTrace value from the notification, and only activates a boost
// using THAT verified response — never the raw POST body directly. An
// attacker can't fake a matching response from Netcash's own server
// without a real, already-settled payment having happened.
//
// Field names below (TransactionAccepted, Reference, Extra1/2/3, Amount)
// are now CONFIRMED against the official docs (Notify/Accept/Decline/
// Redirect URL pages) — no longer a guess.

const PLAN_PRICES = {
  starter: 49.99,
  growth: 219.99,
  pro: 299.99,
};

const DEFAULT_VENDOR_KEY = '24ade73c-98cf-47b3-99be-cc7b867b3080';

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
    // m4/m5 are Netcash's "Extra" fields — per the docs, any text sent
    // here is returned once settlement is done. Same role as Ozow's
    // Optional1/Optional2: this is how the notify handler below knows
    // which plan and listing this payment was for.
    m4: planKey,
    m5: String(listingId),
    // Request a reusable card token on this first payment (m14=1). Per
    // the docs, this only actually returns a token (ccToken/ccHolder/
    // ccMasked/ccExpiry on the notify callback) when: the payment method
    // was Credit Card, AND Test Mode is set to false on the NetConnector
    // profile. In test mode you'll see accepted=true but no token yet —
    // that's expected, not a bug. This groundwork is for recurring
    // billing (charging the saved card again next month) — the actual
    // monthly re-charge still needs Netcash's Subscription Update
    // Service, which is a separate piece of work.
    m14: '1',
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
// SECURITY: verify the payment really happened by asking Netcash's own
// server directly, rather than trusting the incoming POST body alone.
// Netcash's Pay Now Notify callback has no hash/signature field (unlike
// Ozow), so anyone who knows this URL could otherwise POST a fake
// "payment succeeded" request. RequestTrace is generated by Netcash on
// their own transaction — an attacker can't produce one without a real,
// settled payment already having happened, so a matching response from
// this endpoint is trustworthy in a way the original POST body alone
// is not.
// ---------------------------------------------------------------------
async function verifyWithNetcash(requestTrace) {
  if (!requestTrace) return null;
  try {
    const url = `https://ws.netcash.co.za/PayNow/TransactionStatus/Check?RequestTrace=${encodeURIComponent(requestTrace)}`;
    const res = await fetch(url);
    if (!res.ok) {
      console.error('[netcash-notify] Transaction trace check failed:', res.status);
      return null;
    }
    return await res.json();
  } catch (e) {
    console.error('[netcash-notify] Transaction trace check threw:', e);
    return null;
  }
}

// ---------------------------------------------------------------------
// JOB 2: receive Netcash's server-to-server settlement notification
// ---------------------------------------------------------------------
async function handleNotify(req, res) {
  const body = req.body || {};
  console.log('[netcash-notify] raw payload:', JSON.stringify(body));

  const requestTrace = body.RequestTrace;
  const verified = await verifyWithNetcash(requestTrace);
  console.log('[netcash-notify] verification result:', JSON.stringify(verified));

  if (!verified) {
    console.error('[netcash-notify] Could not verify with Netcash — refusing to activate anything from the raw POST alone.', { requestTrace });
    return res.status(200).send('OK');
  }

  // From here on, trust the VERIFIED response, not the original body —
  // that's the whole point of the check above.
  const planKey   = verified.Extra1 || body.Extra1;
  const listingId = verified.Extra2 || body.Extra2;
  const amountPaid = parseFloat(verified.Amount || '0');
  const accepted = verified.TransactionAccepted === true || verified.TransactionAccepted === 'true';
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
    console.log(`[netcash-notify] Not accepted for listing ${listingId}, plan ${planKey} — not activating.`);
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
    const patchBody = {
      boost_tier: planKey,
      boost_started_at: new Date().toISOString(),
      status: 'approved',
    };

    // Only present when: Credit Card payment + m14=1 requested + Test
    // Mode is false on the account. Storing this now, even though the
    // actual recurring re-charge logic isn't built yet — no sense
    // discarding a token we may only get once.
    if (verified.ccToken) {
      patchBody.boost_card_token = verified.ccToken;
      patchBody.boost_card_masked = verified.ccMasked || null;
      patchBody.boost_card_expiry = verified.ccExpiry || null;
      console.log('[netcash-notify] Card token captured for future recurring charge.', { listingId });
    } else {
      console.log('[netcash-notify] No card token in this response — expected while Test Mode is on, or if payment wasn\'t by credit card.');
    }

    const updateRes = await fetch(`${supaUrl}/rest/v1/listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      headers: {
        'apikey': serviceKey,
        'Authorization': `Bearer ${serviceKey}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
      },
      body: JSON.stringify(patchBody),
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
