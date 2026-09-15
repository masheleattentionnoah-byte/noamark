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
//
// ── ADDED: Maya AI-agent launch tickets ──
// This same file now ALSO handles Maya launch-ticket sales from
// noamark-ai-agent.html, using the SAME Netcash service key and the
// SAME Notify URL — no new file, no new key, no new Supabase table.
// A ticket's planKey always starts with 'ai-' (ai-starter/ai-growth/
// ai-pro), which is how handleInit/handleNotify below tell a ticket
// apart from a listing boost. A ticket sale:
//   - takes email/name instead of a listingId (no listing exists yet)
//   - never reads or writes the `listings` table
//   - on confirmed payment, emails a redemption code to the buyer AND
//     to ADMIN_EMAIL, so there's a durable record without a new table
import crypto from 'crypto';

const PLAN_PRICES = {
  starter: 49.99,
  growth: 219.99,
  pro: 299.99,
  // Maya AI-agent launch tickets — same prices as the listing boost
  // tiers, kept under a separate 'ai-' prefix so this ONE file can tell
  // a ticket sale apart from a listing boost and route it completely
  // differently below (no listingId, never touches `listings`).
  'ai-starter': 49.99,
  'ai-growth': 219.99,
  'ai-pro': 299.99,
};

const DEFAULT_VENDOR_KEY = '24ade73c-98cf-47b3-99be-cc7b867b3080';

// ---------------------------------------------------------------------
// Maya launch-ticket helpers — ONLY used when planKey starts with 'ai-'.
// A ticket buyer hasn't listed a business yet, so there's no listingId
// and nothing here ever reads/writes the `listings` table. Instead of a
// new database table, the redemption code is emailed to the buyer AND
// to ADMIN_EMAIL below, so there's always a durable record without
// standing up any new Supabase infrastructure.
// ---------------------------------------------------------------------
const ADMIN_EMAIL = 'supportnoamark@gmail.com';
const MAYA_LAUNCH_DATE_LABEL = '27 March 2027';

function generateTicketCode() {
  // MAYA-XXXX-XXXX, uppercase, no 0/O/1/I/L so it can't be mistyped.
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const seg = () => {
    const bytes = crypto.randomBytes(4);
    let out = '';
    for (let i = 0; i < 4; i++) out += alphabet[bytes[i] % alphabet.length];
    return out;
  };
  return `MAYA-${seg()}-${seg()}`;
}

async function sendViaExistingEmailApi(to, subject, message) {
  try {
    const r = await fetch('https://noamark.com/api/send-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to, subject, message }),
    });
    return await r.json().catch(() => ({}));
  } catch (e) {
    console.error('[netcash-notify][ai-ticket] send-email call failed:', e);
    return { ok: false, reason: e.message };
  }
}

// ---------------------------------------------------------------------
// ADDED: records one row in ai_ticket_sales per confirmed ticket, which
// is what powers the real "X spots left" counter on
// noamark-ai-agent.html (see /api/ai-ticket-availability.js). Uses the
// SAME Supabase env vars already set for the listing-boost path above
// (SUPABASE_URL / SUPABASE_SERVICE_KEY) — no new env vars needed.
// gateway_reference has a unique index (see the SQL migration), so if
// Netcash ever retries the same notification, this just no-ops instead
// of double-counting the sale.
// ---------------------------------------------------------------------
async function recordTicketSale({ tier, gateway, name, email, gatewayReference }) {
  const supaUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_KEY;
  if (!supaUrl || !serviceKey) {
    console.error('[ai-ticket] SUPABASE_URL / SUPABASE_SERVICE_KEY not set — sale not recorded for the spot counter.', { tier, gateway, gatewayReference });
    return;
  }
  try {
    const r = await fetch(`${supaUrl}/rest/v1/ai_ticket_sales`, {
      method: 'POST',
      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=ignore-duplicates',
      },
      body: JSON.stringify({
        tier,
        gateway,
        name: name || null,
        email,
        gateway_reference: gatewayReference || null,
        status: 'confirmed',
      }),
    });
    if (!r.ok) {
      console.error('[ai-ticket] Failed to record sale for spot counter.', { tier, gateway, status: r.status });
    }
  } catch (e) {
    console.error('[ai-ticket] recordTicketSale threw an error.', e);
  }
}

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

  const isTicket = planKey.startsWith('ai-');

  // Listing boosts need a listingId; launch tickets need an email
  // instead (there's no listing yet to attach a boost to).
  if (!isTicket && !listingId) {
    return res.status(400).json({ ok: false, reason: 'Missing listingId' });
  }
  if (isTicket && !email) {
    return res.status(400).json({ ok: false, reason: 'Missing email' });
  }

  const serviceKey = process.env.NETCASH_SERVICE_KEY;
  if (!serviceKey) {
    console.warn('NETCASH_SERVICE_KEY not set — payment not started.');
    return res.status(200).json({ ok: false, reason: 'Payments not configured yet' });
  }

  const amount = PLAN_PRICES[planKey];
  const tierLabel = (isTicket ? planKey.slice(3) : planKey);
  const tierLabelCap = tierLabel.charAt(0).toUpperCase() + tierLabel.slice(1);

  let fields;
  if (isTicket) {
    const reference = 'AI-' + planKey.toUpperCase() + '-' + Date.now();
    fields = {
      m1: serviceKey,
      m2: DEFAULT_VENDOR_KEY,
      p2: reference,
      p3: `NoaMark Maya ${tierLabelCap} Launch Ticket`,
      p4: amount.toFixed(2),
      Budget: 'Y',
      // m4/m5/m6 → Extra1/Extra2/Extra3 on the verified notify response
      // (confirmed via Netcash docs) — this is how handleNotify below
      // learns the tier/email/name for a ticket sale, with no listingId
      // involved anywhere.
      m4: planKey,
      m5: email,
      m6: name || '',
    };
  } else {
    // Same reference style as the Ozow side, for consistency across logs.
    const reference = 'NM-' + planKey.toUpperCase() + '-' + listingId + '-' + Date.now();
    fields = {
      m1: serviceKey,
      m2: DEFAULT_VENDOR_KEY,
      p2: reference,
      p3: `NoaMark ${tierLabelCap} Boost`,
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
  }

  return res.status(200).json({
    ok: true,
    postUrl: 'https://paynow.netcash.co.za/site/paynow.aspx',
    fields,
    planName: isTicket ? (tierLabelCap + ' Launch Ticket') : (tierLabelCap + ' Plan'),
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
  const planKey = verified.Extra1 || body.Extra1;
  // For a listing boost this is a listingId; for a launch ticket
  // (planKey starts with 'ai-') this is the buyer's email instead — see
  // the isTicket branch just below.
  const secondField = verified.Extra2 || body.Extra2;
  const thirdField = verified.Extra3 || body.Extra3;
  const amountPaid = parseFloat(verified.Amount || '0');
  const accepted = verified.TransactionAccepted === true || verified.TransactionAccepted === 'true';
  // -----------------------------------------------------------------

  if (!planKey || !PLAN_PRICES[planKey]) {
    console.warn('[netcash-notify] Missing/unknown planKey in payload:', planKey);
    return finish(200, 'OK');
  }

  // ── Maya launch ticket — completely separate path, never touches
  // `listings` ──
  if (planKey.startsWith('ai-')) {
    return handleTicketNotify({
      finish, planKey, email: secondField, name: thirdField, amountPaid, accepted,
      paymentRef: verified.Reference || body.Reference || requestTrace,
    });
  }

  const listingId = secondField;
  if (!listingId) {
    console.warn('[netcash-notify] Missing listingId in payload — cannot process.', body);
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

// ---------------------------------------------------------------------
// Maya launch-ticket confirmation — no listingId, no `listings` write.
// Issues a redemption code and emails it to the buyer AND to
// ADMIN_EMAIL, via the existing /api/send-email endpoint. The admin
// copy IS the durable record — no new Supabase table needed for this.
// ---------------------------------------------------------------------
async function handleTicketNotify({ finish, planKey, email, name, amountPaid, accepted, paymentRef }) {
  const tier = planKey.slice(3); // strip 'ai-'
  const tierLabel = tier.charAt(0).toUpperCase() + tier.slice(1);

  if (!email) {
    console.warn('[netcash-notify][ai-ticket] Missing email — cannot issue a code.', { planKey });
    return finish(200, 'OK');
  }
  if (!accepted) {
    console.log(`[netcash-notify][ai-ticket] Not accepted for ${planKey} — not issuing a code.`);
    return finish(200, 'OK');
  }
  const expectedAmount = PLAN_PRICES[planKey];
  if (Math.abs(amountPaid - expectedAmount) >= 0.01) {
    console.warn('[netcash-notify][ai-ticket] Amount mismatch — refusing to issue a code.', { planKey, amountPaid, expectedAmount });
    return finish(200, 'OK');
  }

  // ADDED: this is the real sale record the spot counter reads.
  await recordTicketSale({ tier, gateway: 'netcash', name, email, gatewayReference: paymentRef });

  const code = generateTicketCode();
  const greeting = name ? `Hi ${name},` : 'Hi,';

  await sendViaExistingEmailApi(
    email,
    `Your Maya launch ticket is confirmed — ${tierLabel}`,
    `${greeting}\n\nYour ${tierLabel} launch ticket for Maya, NoaMark's AI business agent, is confirmed.\n\nYour redemption code:\n${code}\n\nMaya launches on ${MAYA_LAUNCH_DATE_LABEL}. On that day, go to noamark.com, log in, and enter this code to activate Maya at your ${tierLabel} tier — no extra payment needed at that point.\n\nKeep this email — you'll need the code to activate.\n\n— NoaMark`
  );

  // The durable record: a copy to your own inbox with everything an
  // admin would need to look this ticket up later, without a database.
  await sendViaExistingEmailApi(
    ADMIN_EMAIL,
    `[Maya ticket] ${tierLabel} — ${email}`,
    `New Maya launch ticket sold via Netcash.\n\nTier: ${tierLabel}\nEmail: ${email}\nName: ${name || '(not given)'}\nAmount paid: R${amountPaid.toFixed(2)}\nPayment reference: ${paymentRef || '(none)'}\nRedemption code: ${code}\n\nKeep this email — it's the record used to grant access at launch.`
  );

  console.log(`[netcash-notify][ai-ticket] Ticket ${code} issued to ${email} (${tier}).`);
  return finish(200, 'OK');
}
