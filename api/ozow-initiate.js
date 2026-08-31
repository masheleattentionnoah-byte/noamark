// /api/ozow-initiate.js
//
// Starts an Ozow "Hosted Payment Page" request. Mirrors the CORS/method
// pattern used in /api/send-email.js.
//
// WHY THIS HAS TO BE SERVER-SIDE:
// Ozow payment requests must be signed with a HashCheck built from your
// PRIVATE KEY. If that hashing happened in the browser (like the old
// PayFast scaffold used to do with its passphrase), the private key
// would be visible to anyone who opens dev tools — meaning anyone could
// forge their own valid, "paid" requests. This endpoint is the only
// place the private key is ever used, and it never leaves the server.
//
// It also re-derives the price from the plan key using PLAN_PRICES below,
// instead of trusting whatever "amount" the browser sends. The old
// PayFast scaffold trusted a client-supplied amount directly — that meant
// anyone could open dev tools and POST amount: 1 for a R299.99 plan.
//
// SETUP NEEDED IN VERCEL (Project Settings → Environment Variables):
//   OZOW_SITE_CODE     — from Ozow merchant admin → Sites
//   OZOW_PRIVATE_KEY   — from Ozow merchant admin → Sites (keep secret)
//   OZOW_TEST_MODE     — "true" while testing, "false" to actually charge
//                         real money. Your Ozow account is already live,
//                         so double check this is "false" before real
//                         customers pay, and "true" while you're testing.
//
// Until OZOW_SITE_CODE / OZOW_PRIVATE_KEY are set, this returns
// ok:false with a clear reason instead of crashing.

import crypto from 'crypto';

// Canonical prices — must match the boost tiers in index.html.
// Server-side so a tampered client request can never buy a plan cheap.
const PLAN_PRICES = {
  starter: 49.99,
  growth: 219.99,
  pro: 299.99,
};
const PLAN_NAMES = {
  starter: 'Starter Plan',
  growth: 'Growth Plan',
  pro: 'Pro Plan',
};

function buildHash(fieldsInOrder, privateKey) {
  const raw = fieldsInOrder.join('') + privateKey;
  return crypto.createHash('sha512').update(raw.toLowerCase()).digest('hex');
}

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
    return res.status(405).json({ ok: false, reason: 'Method not allowed' });
  }

  const { planKey, listingId, email, name } = req.body || {};

  if (!planKey || !PLAN_PRICES[planKey]) {
    return res.status(400).json({ ok: false, reason: 'Unknown or missing planKey' });
  }
  if (!listingId) {
    return res.status(400).json({ ok: false, reason: 'Missing listingId' });
  }

  const siteCode = process.env.OZOW_SITE_CODE;
  const privateKey = process.env.OZOW_PRIVATE_KEY;
  const isTest = (process.env.OZOW_TEST_MODE || 'true').toLowerCase() === 'true';

  if (!siteCode || !privateKey) {
    console.warn('OZOW_SITE_CODE / OZOW_PRIVATE_KEY not set — boost payment not started.');
    return res.status(200).json({ ok: false, reason: 'Payments not configured yet' });
  }

  const amount = PLAN_PRICES[planKey].toFixed(2);
  const siteOrigin = origin || 'https://noamark.com';
  // BUG THIS FIXES: TransactionReference is documented by Ozow as
  // String(50) — max 50 characters. The previous version used the FULL
  // listing UUID (36 characters), which pushed the total reference to 61
  // characters for a real attempt (confirmed via browser Network tab:
  // "NM-STARTER-7c63bc12-f8a6-4bd3-b962-ca8525db2de9-1787350352209").
  // Ozow silently rejects an oversized field — no record is even created
  // on their side, which is exactly why their support team couldn't find
  // the transaction when we gave them this exact reference. Using a
  // 12-character slice of the UUID (still effectively unique when
  // combined with a millisecond timestamp) keeps the total safely under
  // 50 characters for every plan name.
  const shortListingId = String(listingId).replace(/-/g, '').slice(0, 12);
  // "OZ-" prefix (not "NM-") — Netcash's own reference generation also
  // starts with "NM-", and moderate.js relies on this exact prefix to
  // tell the two gateways apart (e.g. deciding whether a real Netcash
  // subscription needs cancelling). Sharing a prefix meant a payment's
  // actual gateway couldn't be reliably identified anywhere downstream.
  const transactionReference = 'OZ-' + planKey.toUpperCase() + '-' + shortListingId + '-' + Date.now();
  const bankReference = 'NoaMark'; // appears on the customer's bank statement

  // Custom pass-through data — Ozow echoes these back on return/notify so
  // we know which plan and listing this payment was for, same role as
  // PayFast's custom_str1/2/3.
  const optional1 = planKey;
  const optional2 = String(listingId);
  const optional3 = email || '';

  // These must match EXACTLY what's whitelisted on Ozow's side for this
  // site (confirmed via their support email: https://noamark.com/, no
  // query string). Ozow silently rejects any request where these don't
  // match character-for-character — it won't even show up as a failed
  // transaction in their dashboard, which is what made this hard to debug.
  // We no longer need ?ozow_return=1&status=... on these, because the
  // frontend now tracks "a payment attempt is in progress" via
  // sessionStorage instead (set right before the redirect), and the
  // actual activation was always server-side via ozow-notify anyway.
  const cancelUrl  = siteOrigin + '/';
  const errorUrl   = siteOrigin + '/';
  const successUrl = siteOrigin + '/';
  const notifyUrl  = siteOrigin.replace(/\/$/, '') + '/api/ozow-notify';

  // Field order below is confirmed directly against Ozow's own published
  // "Post variables" table (ozow.com/integrations, Step 1): SiteCode,
  // CountryCode, CurrencyCode, Amount, TransactionReference, BankReference,
  // Optional1-5, Customer, CancelUrl, ErrorUrl, SuccessUrl, NotifyUrl,
  // IsTest — 17 fixed fields in that exact order, always.
  //
  // IMPORTANT: earlier versions of this file DROPPED blank Optional/Customer
  // fields entirely (not even sending them as empty strings), on a guess
  // that Ozow's hash only covers whatever was actually posted. That guess
  // is very likely what was causing "Payment unsuccessful — An error has
  // occurred" on Ozow's own page (request reaching Ozow, but hash not
  // matching). Ozow's table is a FIXED 17-field structure — every
  // reference implementation that documents the literal hash string
  // (e.g. Ozow's own Flutter SDKs) always includes Optional1-5 and
  // Customer, blank or not. So now: always send and hash all 17 fields,
  // using '' for anything not provided. Never omit a field.
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
  console.log('[ozow-initiate] Request built:', {
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
