// /api/ozow-notify.js
//
// MERGED (Sep 2026): this file now does BOTH of Ozow's two jobs —
// starting a payment (?action=init, called by the browser) AND
// receiving Ozow's server-to-server settlement callback (no action,
// called by Ozow itself) — the same one-file-two-jobs pattern already
// used in /api/netcash-notify.js. This replaces the separate
// /api/ozow-initiate.js file, which no longer exists, to stay under
// Vercel's 12-serverless-function limit on the Hobby plan.
//
// IMPORTANT: Ozow's own dashboard has this exact URL saved as the
// NotifyUrl for your site, so this file's PATH can never change —
// only its content. The frontend call that used to hit
// /api/ozow-initiate now hits /api/ozow-notify?action=init instead
// (already updated in index.html and noamark-ai-agent.html).
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
//   OZOW_SITE_CODE         — from Ozow merchant admin → Sites (used by
//                            the ?action=init side)
//   OZOW_PRIVATE_KEY       — from Ozow merchant admin → Sites (keep
//                            secret; used by BOTH sides — signing on
//                            init, verifying on notify)
//   OZOW_TEST_MODE         — "true" while testing, "false" to actually
//                            charge real money (used by ?action=init)
//   SUPABASE_URL           — already set in this project (reused as-is)
//   SUPABASE_SERVICE_KEY   — already set in this project. This is
//                            Supabase's "Secret key" (what used to be
//                            called service_role) — NOT the publishable/
//                            anon key used in index.html. This one
//                            bypasses Row Level Security, which is
//                            exactly why it must only ever live here on
//                            the server, never in the browser.
//
// verifyHash covers the FULL 13-field notification hash, confirmed
// directly against Ozow's own published docs (ozow.com/integrations,
// Step 2 "Notification Response Post variables"): SiteCode,
// TransactionId, TransactionReference, Amount, Status, Optional1,
// Optional2, Optional3, Optional4, Optional5, CurrencyCode, IsTest,
// StatusMessage + private key, lowercased, SHA512. Still written to
// FAIL CLOSED on a bad hash — reject/ignore rather than trust anything
// that doesn't verify — so a stale field order blocks legitimate
// payments from activating rather than letting fake ones through.
//
// ── Maya AI-agent launch tickets ──
// This file ALSO receives Ozow's settlement call for Maya launch-ticket
// sales from noamark-ai-agent.html, and ALSO starts those same ticket
// payments via ?action=init — same site code, same private key. A
// ticket's planKey starts with 'ai-'; Optional2/3 then carry email/name
// instead of a listingId, and none of this ever touches `listings`.
// On confirmed payment, a redemption code is emailed to the buyer AND
// to ADMIN_EMAIL, AND a row is recorded in ai_ticket_sales (used by the
// real spot counter — see handleAvailability in /api/netcash-notify.js).

import crypto from 'crypto';

// Canonical prices — must match the boost tiers in index.html, plus the
// 'ai-' launch-ticket tiers used by noamark-ai-agent.html (same prices).
const PLAN_PRICES = {
  starter: 49.99,
  growth: 219.99,
  pro: 299.99,
  'ai-starter': 49.99,
  'ai-growth': 219.99,
  'ai-pro': 299.99,
};
const PLAN_NAMES = {
  starter: 'Starter Plan',
  growth: 'Growth Plan',
  pro: 'Pro Plan',
  'ai-starter': 'Starter Launch Ticket',
  'ai-growth': 'Growth Launch Ticket',
  'ai-pro': 'Pro Launch Ticket',
};
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
    console.error('[ozow-notify][ai-ticket] send-email call failed:', e);
    return { ok: false, reason: e.message };
  }
}

// Records one row in ai_ticket_sales per confirmed ticket — powers the
// real "X spots left" counter (read by handleAvailability in
// /api/netcash-notify.js). gateway_reference has a unique index (see
// the SQL migration), so a retried Ozow notification just no-ops
// instead of double-counting the sale.
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

async function handleTicketNotify(body) {
  const planKey = body.Optional1;
  const email = body.Optional2;
  const name = body.Optional3;
  const status = body.Status;
  const amountPaid = parseFloat(body.Amount || '0');
  const tier = planKey.slice(3); // strip 'ai-'
  const tierLabel = tier.charAt(0).toUpperCase() + tier.slice(1);

  if (!email) {
    console.warn('[ozow-notify][ai-ticket] verified but missing email in Optional2', body);
    return;
  }
  if (status !== 'Complete') {
    console.log(`[ozow-notify][ai-ticket] ${status} for ${planKey} — not issuing a code.`);
    return;
  }
  const expectedAmount = PLAN_PRICES[planKey];
  if (Math.abs(amountPaid - expectedAmount) >= 0.01) {
    console.warn('[ozow-notify][ai-ticket] Amount mismatch — refusing to issue a code.', { planKey, amountPaid, expectedAmount });
    return;
  }

  // This is the real sale record the spot counter reads.
  await recordTicketSale({
    tier,
    gateway: 'ozow',
    name,
    email,
    gatewayReference: body.TransactionId || body.TransactionReference || null,
  });

  const code = generateTicketCode();
  const greeting = name ? `Hi ${name},` : 'Hi,';

  await sendViaExistingEmailApi(
    email,
    `Your Maya launch ticket is confirmed — ${tierLabel}`,
    `${greeting}\n\nYour ${tierLabel} launch ticket for Maya, NoaMark's AI business agent, is confirmed.\n\nYour redemption code:\n${code}\n\nMaya launches on ${MAYA_LAUNCH_DATE_LABEL}. On that day, go to noamark.com, log in, and enter this code to activate Maya at your ${tierLabel} tier — no extra payment needed at that point.\n\nKeep this email — you'll need the code to activate.\n\n— NoaMark`
  );

  await sendViaExistingEmailApi(
    ADMIN_EMAIL,
    `[Maya ticket] ${tierLabel} — ${email}`,
    `New Maya launch ticket sold via Ozow.\n\nTier: ${tierLabel}\nEmail: ${email}\nName: ${name || '(not given)'}\nAmount paid: R${amountPaid.toFixed(2)}\nTransaction: ${body.TransactionId || body.TransactionReference || '(none)'}\nRedemption code: ${code}\n\nKeep this email — it's the record used to grant access at launch.`
  );

  console.log(`[ozow-notify][ai-ticket] Ticket ${code} issued to ${email} (${tier}) — transaction ${body.TransactionId}`);
}

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

function buildHash(fieldsInOrder, privateKey) {
  const raw = fieldsInOrder.join('') + privateKey;
  return crypto.createHash('sha512').update(raw.toLowerCase()).digest('hex');
}

// ---------------------------------------------------------------------
// JOB 1 (was /api/ozow-initiate.js): build the signed Pay Now request
// and hand the fields back to the browser to submit to Ozow.
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

  const siteCode = process.env.OZOW_SITE_CODE;
  const privateKey = process.env.OZOW_PRIVATE_KEY;
  const isTest = (process.env.OZOW_TEST_MODE || 'true').toLowerCase() === 'true';

  if (!siteCode || !privateKey) {
    console.warn('OZOW_SITE_CODE / OZOW_PRIVATE_KEY not set — boost payment not started.');
    return res.status(200).json({ ok: false, reason: 'Payments not configured yet' });
  }

  const origin = req.headers.origin || '';
  const amount = PLAN_PRICES[planKey].toFixed(2);
  const siteOrigin = origin || 'https://noamark.com';

  // TransactionReference is documented by Ozow as String(50) — max 50
  // characters — so listing boosts use a 12-char slice of the listing
  // UUID (plus a millisecond timestamp) rather than the full 36-char
  // UUID, to stay safely under that cap. "OZ-" prefix (not "NM-") is
  // how moderate.js tells a payment's gateway apart downstream.
  let transactionReference;
  if (isTicket) {
    transactionReference = 'OZ-' + planKey.toUpperCase() + '-' + Date.now();
  } else {
    const shortListingId = String(listingId).replace(/-/g, '').slice(0, 12);
    transactionReference = 'OZ-' + planKey.toUpperCase() + '-' + shortListingId + '-' + Date.now();
  }
  const bankReference = 'NoaMark'; // appears on the customer's bank statement

  // Custom pass-through data — Ozow echoes these back on return/notify.
  // For a listing boost: plan + listingId + email, same as always.
  // For a launch ticket: plan + email + name instead (no listingId).
  const optional1 = planKey;
  const optional2 = isTicket ? email : String(listingId);
  const optional3 = isTicket ? (name || '') : (email || '');

  // These must match EXACTLY what's whitelisted on Ozow's side for this
  // site (https://noamark.com/, no query string) — Ozow silently
  // rejects any request where these don't match character-for-character.
  const cancelUrl  = siteOrigin + '/';
  const errorUrl   = siteOrigin + '/';
  const successUrl = siteOrigin + '/';
  // Still points at THIS SAME FILE — now with no query string, which is
  // how the routing below tells Ozow's own callback apart from a
  // browser's ?action=init call.
  const notifyUrl  = siteOrigin.replace(/\/$/, '') + '/api/ozow-notify';

  // Field order below is confirmed directly against Ozow's own published
  // "Post variables" table (ozow.com/integrations, Step 1): SiteCode,
  // CountryCode, CurrencyCode, Amount, TransactionReference, BankReference,
  // Optional1-5, Customer, CancelUrl, ErrorUrl, SuccessUrl, NotifyUrl,
  // IsTest — 17 fixed fields in that exact order, always sent (blank or
  // not) since Ozow's hash covers the full fixed structure.
  const fields = {
    SiteCode: siteCode,
    CountryCode: 'ZA',
    CurrencyCode: 'ZAR',
    Amount: amount,
    TransactionReference: transactionReference,
    BankReference: bankReference,
    Optional1: optional1,
    Optional2: optional2,
    Optional3: optional3,
    Optional4: '',
    Optional5: '',
    Customer: name || '',
    CancelUrl: cancelUrl,
    ErrorUrl: errorUrl,
    SuccessUrl: successUrl,
    NotifyUrl: notifyUrl,
    IsTest: isTest ? 'true' : 'false',
  };

  const hashCheck = buildHash(Object.values(fields), privateKey);

  // DIAGNOSTIC LOGGING — logs everything actually sent EXCEPT the private
  // key itself (never logged) — safe to paste into a support ticket.
  console.log('[ozow-notify][action=init] Request built:', {
    transactionReference,
    transactionReferenceLength: transactionReference.length,
    siteCode,
    amount,
    isTest,
    cancelUrl, errorUrl, successUrl, notifyUrl,
    fieldsSentInOrder: Object.keys(fields),
  });

  return res.status(200).json({
    ok: true,
    postUrl: 'https://pay.ozow.com',
    fields: { ...fields, HashCheck: hashCheck },
    planName: PLAN_NAMES[planKey],
  });
}

// ---------------------------------------------------------------------
// JOB 2: receive Ozow's server-to-server settlement notification
// ---------------------------------------------------------------------
async function handleNotify(req, res) {
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

  const planKey = body.Optional1;

  if (!planKey) {
    console.warn('Ozow notify: verified but missing planKey in Optional1', body);
    return res.status(200).send('OK');
  }

  // ── Maya launch ticket — completely separate path, never touches
  // `listings` ──
  if (planKey.startsWith('ai-')) {
    await handleTicketNotify(body);
    return res.status(200).send('OK');
  }

  const listingId = body.Optional2;
  const status    = body.Status; // 'Complete' | 'Cancelled' | 'Error' | 'Pending'

  if (!listingId) {
    console.warn('Ozow notify: verified but missing listingId in Optional2', body);
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
        // AUTO-VERIFY (Pro plan only) — same rule as netcash-notify.js.
        // Deliberately only ever sets this to true here, never false.
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

// ---------------------------------------------------------------------
// Router — one file, two jobs, split by ?action= (both are POST):
//   POST /api/ozow-notify?action=init   → browser starting a payment
//   POST /api/ozow-notify                → Ozow's real settlement call
// ---------------------------------------------------------------------
export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigins = [
    'https://noamark.com',
    'https://www.noamark.com',
  ];
  const isVercelPreview = /\.vercel\.app$/.test(origin.replace(/^https?:\/\//, ''));
  if (allowedOrigins.includes(origin) || isVercelPreview) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).send('Method not allowed');
  }

  const action = req.query && req.query.action;
  if (action === 'init') {
    return handleInit(req, res);
  }

  return handleNotify(req, res);
}
