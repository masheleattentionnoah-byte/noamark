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
//
// ── ADDED: Maya AI-agent launch tickets ──
// This same file now ALSO receives Ozow's settlement call for Maya
// launch-ticket sales from noamark-ai-agent.html (via ozow-initiate.js,
// which sets NotifyUrl to this same file) — same private key, no new
// file. A ticket's planKey starts with 'ai-'; Optional2/3 then carry
// email/name instead of a listingId, and this never touches `listings`.
// Since there's no new Supabase table for tickets, the redemption code
// is emailed to the buyer AND to ADMIN_EMAIL via the existing
// /api/send-email endpoint — that admin copy is the durable record.

import crypto from 'crypto';

const PLAN_PRICES = {
  'ai-starter': 49.99,
  'ai-growth': 219.99,
  'ai-pro': 299.99,
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

  const listingId  = body.Optional2;
  const status     = body.Status; // 'Complete' | 'Cancelled' | 'Error' | 'Pending'

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
