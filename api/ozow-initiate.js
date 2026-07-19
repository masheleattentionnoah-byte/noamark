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
  starter: 'Starter Boost',
  growth: 'Growth Boost',
  pro: 'Pro Listing',
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
  const transactionReference = 'NM-' + planKey.toUpperCase() + '-' + listingId + '-' + Date.now();
  const bankReference = 'NoaMark'; // appears on the customer's bank statement

  // Custom pass-through data — Ozow echoes these back on return/notify so
  // we know which plan and listing this payment was for, same role as
  // PayFast's custom_str1/2/3.
  const optional1 = planKey;
  const optional2 = String(listingId);
  const optional3 = email || '';

  const cancelUrl  = siteOrigin + '/?ozow_return=1&status=cancel';
  const errorUrl   = siteOrigin + '/?ozow_return=1&status=error';
  const successUrl = siteOrigin + '/?ozow_return=1&status=success';
  const notifyUrl  = siteOrigin.replace(/\/$/, '') + '/api/ozow-notify';

  // Field order below matches Ozow's own documented hash-generation
  // example, cross-checked against Ozow's published integration guide
  // (SiteCode, CountryCode, CurrencyCode, Amount, TransactionReference,
  // BankReference, Customer, Optional1-5, NotifyUrl, SuccessUrl, ErrorUrl,
  // CancelUrl, IsTest) — this order is NOT arbitrary, Ozow will reject
  // the request (or just never generate a matching hash) if it's wrong.
  const fields = {
    SiteCode: siteCode,
    CountryCode: 'ZA',
    CurrencyCode: 'ZAR',
    Amount: amount,
    TransactionReference: transactionReference,
    BankReference: bankReference,
    Customer: name || '',
    Optional1: optional1,
    Optional2: optional2,
    Optional3: optional3,
    Optional4: '',
    Optional5: '',
    NotifyUrl: notifyUrl,
    SuccessUrl: successUrl,
    ErrorUrl: errorUrl,
    CancelUrl: cancelUrl,
    IsTest: isTest ? 'true' : 'false',
  };

  const hashCheck = buildHash(Object.values(fields), privateKey);

  return res.status(200).json({
    ok: true,
    postUrl: 'https://pay.ozow.com',
    fields: { ...fields, HashCheck: hashCheck },
    planName: PLAN_NAMES[planKey],
  });
}
