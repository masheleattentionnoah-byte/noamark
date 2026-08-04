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

  // ANY GET request here is the customer's browser — Netcash's real
  // server-to-server Notify call is always POST per the docs, so a GET
  // can only be a browser (or Netcash's results page following up with
  // one, which is what the Vercel logs showed happening). Always bounce
  // home cleanly rather than 405ing, regardless of query string.
  if (req.method === 'GET') {
    res.writeHead(302, { Location: 'https://noamark.com/' });
    return res.end();
  }

  // Explicit ?action=redirect still works when the query string survives
  // on a POST (e.g. testing this URL directly).
  if (action === 'redirect') {
    res.writeHead(302, { Location: 'https://noamark.com/' });
    return res.end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, GET');
    return res.status(405).send('Method not allowed');
  }

  if (action === 'init') {
    return handleInit(req, res);
  }

  // Everything else — including the customer's own browser POSTing here
  // after paying, now that the query string got stripped — runs through
  // the SAME verified logic. This is still safe: activation only ever
  // happens after verifyWithNetcash() confirms the payment against
  // Netcash's own server, regardless of who/what hit this URL. The only
  // difference is how we respond afterward: a real browser gets bounced
  // home with a clean redirect; Netcash's actual server-to-server call
  // gets the plain "OK" text it expects.
  const looksLikeBrowser = (req.headers['accept'] || '').includes('text/html');
  await handleNotify(req, res, { respondAsBrowser: looksLikeBrowser });
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
async function handleNotify(req, res, { respondAsBrowser = false } = {}) {
  const body = req.body || {};
  console.log('[netcash-notify] raw payload:', JSON.stringify(body));

  const finish = (status, text) => {
    if (respondAsBrowser) {
      // A real customer's browser ended up here — give them a clean
      // redirect home instead of raw "OK"/error text on screen.
      res.writeHead(302, { Location: 'https://noamark.com/' });
      return res.end();
    }
    return res.status(status).send(text);
  };

  const requestTrace = body.RequestTrace;
  const verified = await verifyWithNetcash(requestTrace);
  console.log('[netcash-notify] verification result:', JSON.stringify(verified));

  if (!verified) {
    console.error('[netcash-notify] Could not verify with Netcash — refusing to activate anything from the raw POST alone.', { requestTrace });
    return finish(200, 'OK');
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
    return finish(200, 'OK');
  }

  if (!PLAN_PRICES[planKey]) {
    console.warn('[netcash-notify] Unknown planKey in payload:', planKey);
    return finish(200, 'OK');
  }

  const expectedAmount = PLAN_PRICES[planKey];
  const amountMatches = Math.abs(amountPaid - expectedAmount) < 0.01;

  if (!accepted) {
    console.log(`[netcash-notify] Not accepted for listing ${listingId}, plan ${planKey} — not activating.`);
    return finish(200, 'OK');
  }

  if (!amountMatches) {
    console.warn('[netcash-notify] Amount mismatch — refusing to activate.', { listingId, planKey, amountPaid, expectedAmount });
    return finish(200, 'OK');
  }

  const supaUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_KEY;

  if (!supaUrl || !serviceKey) {
    console.error('SUPABASE_URL / SUPABASE_SERVICE_KEY not set — payment confirmed but boost NOT activated. Fix env vars and manually activate this one:', { listingId, planKey });
    return finish(200, 'OK');
  }

  try {
    const patchBody = {
      boost_tier: planKey,
      boost_started_at: new Date().toISOString(),
      status: 'approved',
      // These two columns exist specifically to distinguish a REAL,
      // webhook-confirmed payment from a boost tier an admin set manually
      // (admSetBoost in index.html deliberately does NOT set these).
      // The admin Revenue dashboard should sum confirmed revenue using
      // boost_paid_at IS NOT NULL, not boost_tier alone.
      boost_paid_at: new Date().toISOString(),
      boost_payment_ref: verified.Reference || body.Reference || null,
    };

    // AUTO-VERIFY (Pro plan only): the pricing page lists "Verified badge"
    // as a Pro-tier feature, so a confirmed Pro payment should grant it
    // automatically — same rule and same wording as ozow-notify.js.
    // Deliberately only ever sets this to true here, never false —
    // Starter/Growth payments don't touch verified at all, so a listing
    // verified for some other legitimate reason is never silently
    // un-verified by this webhook.
    if (planKey === 'pro') patchBody.verified = true;

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

  return finish(200, 'OK');
}
