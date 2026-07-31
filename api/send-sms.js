// /api/send-sms.js
// Vercel serverless function — proxies SMS sending to BulkSMS so the
// BulkSMS Token ID / Token Secret never reach the browser.
//
// Set these in Vercel → Project → Settings → Environment Variables:
//   BULKSMS_TOKEN_ID
//   BULKSMS_TOKEN_SECRET
// Then redeploy.
//
// RATE LIMITING — WHY THIS EXISTS:
// This endpoint is called from several places in index.html, including by
// visitors who are NOT logged in (submitting an enquiry, requesting a
// booking) — so it can't require a login token the way
// netcash-payment-request.js does, without breaking those features.
// Instead this uses THREE layers, so a patient attacker who just waits
// out a short cooldown still can't grind you down over hours:
//   1. Burst cooldown — stops rapid-fire spam to one number/address.
//   2. Daily cap PER RECIPIENT — stops sustained harassment of one
//      person even if spread slowly across a whole day.
//   3. Daily GLOBAL cap — a hard ceiling on total sends per day across
//      everyone, so even a distributed attack (many numbers, many IPs)
//      can't run up an unbounded bill or flood your BulkSMS account.
// Best-effort in-memory only — resets whenever this function cold-starts
// on Vercel, so it's not a mathematically perfect guarantee against a
// determined attacker who can force/wait out cold starts, but it stops
// everything short of that. If NoaMark's traffic grows and this becomes
// a real concern, the upgrade path is persistent storage (Vercel KV /
// Upstash Redis) instead of in-memory Maps — worth revisiting later,
// not needed at current scale.

const _recentByRecipient = new Map();     // phone -> last send timestamp (burst)
const _dailyByRecipient = new Map();      // phone -> [timestamps in last 24h]
const _recentByIp = new Map();            // ip -> [timestamps in last hour]
const _dailyGlobal = [];                  // [timestamps in last 24h], all sends

const RECIPIENT_COOLDOWN_MS = 30 * 1000;      // burst: 1 SMS per number per 30s
const DAY_MS = 24 * 60 * 60 * 1000;
// A busy business's phone number can legitimately receive many real
// notifications in one day (new enquiries, booking requests, reschedule
// confirmations, etc.) — 40 gives generous headroom for real traffic
// while still stopping someone from deliberately flooding one number
// hundreds of times in a day.
const RECIPIENT_DAILY_MAX = 40;
const IP_WINDOW_MS = 60 * 60 * 1000;          // 1 hour window
const IP_MAX_PER_HOUR = 20;                   // max 20 SMS per IP per hour
const GLOBAL_DAILY_MAX = 1000;                // hard ceiling: max 1000 SMS/day, site-wide

function tooSoonForRecipient(key) {
  const now = Date.now();
  const last = _recentByRecipient.get(key);
  if (last && now - last < RECIPIENT_COOLDOWN_MS) return true;
  _recentByRecipient.set(key, now);
  return false;
}

function recipientDailyLimitHit(key) {
  const now = Date.now();
  const times = (_dailyByRecipient.get(key) || []).filter(t => now - t < DAY_MS);
  if (times.length >= RECIPIENT_DAILY_MAX) {
    _dailyByRecipient.set(key, times);
    return true;
  }
  times.push(now);
  _dailyByRecipient.set(key, times);
  return false;
}

function ipRateLimited(ip) {
  const now = Date.now();
  const times = (_recentByIp.get(ip) || []).filter(t => now - t < IP_WINDOW_MS);
  if (times.length >= IP_MAX_PER_HOUR) {
    _recentByIp.set(ip, times);
    return true;
  }
  times.push(now);
  _recentByIp.set(ip, times);
  return false;
}

function globalDailyLimitHit() {
  const now = Date.now();
  while (_dailyGlobal.length && now - _dailyGlobal[0] > DAY_MS) _dailyGlobal.shift();
  if (_dailyGlobal.length >= GLOBAL_DAILY_MAX) return true;
  _dailyGlobal.push(now);
  return false;
}

export default async function handler(req, res) {
  // Basic CORS lock-down — only allow calls from your own domain.
  // This MUST run before any method check below. Cross-origin POST
  // requests with a JSON body are "non-simple" requests, so the browser
  // sends a silent OPTIONS preflight first and only proceeds with the
  // real POST if that preflight succeeds. If the method check ran first
  // (as it used to), every OPTIONS preflight was rejected with 405
  // before ever reaching the OPTIONS-handling code below — so the
  // browser would refuse to even attempt the real request, and it would
  // fail completely silently on the frontend (caught by nmSendSMS's
  // try/catch, logged only to the console). Setting CORS headers and
  // answering OPTIONS first fixes that.
  const origin = req.headers.origin || '';
  const allowedOrigins = [
    'https://noamark.com',
    'https://www.noamark.com',
  ];
  // Allow Vercel preview deployments too (e.g. noamark-git-xxx.vercel.app)
  const isVercelPreview = /\.vercel\.app$/.test(origin.replace(/^https?:\/\//, ''));
  if (allowedOrigins.includes(origin) || isVercelPreview) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  // Only allow POST for the actual request
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, reason: 'method not allowed' });
  }

  try {
    const { to, message } = req.body || {};

    if (!to || !message) {
      return res.status(400).json({ ok: false, reason: 'missing to or message' });
    }
    if (typeof message !== 'string' || message.length > 1000) {
      return res.status(400).json({ ok: false, reason: 'invalid message' });
    }

    // Normalize to E.164 (South African default)
    const raw = String(to).replace(/[^0-9]/g, '');
    if (!raw || raw.length < 9) {
      return res.status(400).json({ ok: false, reason: 'bad number' });
    }
    const e164 = raw.startsWith('0') ? '+27' + raw.slice(1)
               : raw.startsWith('27') ? '+' + raw
               : ('+27' + raw);

    // ── Rate limiting — see comment at top of file ──
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
    if (tooSoonForRecipient(e164)) {
      return res.status(429).json({ ok: false, reason: 'This number was just messaged — please wait a moment.' });
    }
    if (recipientDailyLimitHit(e164)) {
      return res.status(429).json({ ok: false, reason: 'This number has reached its daily message limit.' });
    }
    if (ipRateLimited(ip)) {
      return res.status(429).json({ ok: false, reason: 'Too many requests — please try again later.' });
    }
    if (globalDailyLimitHit()) {
      console.error('send-sms: GLOBAL DAILY LIMIT reached — possible abuse in progress.');
      return res.status(429).json({ ok: false, reason: 'Daily message limit reached — please try again tomorrow.' });
    }

    const tokenId     = process.env.BULKSMS_TOKEN_ID;
    const tokenSecret = process.env.BULKSMS_TOKEN_SECRET;

    if (!tokenId || !tokenSecret) {
      console.error('BulkSMS credentials missing from environment');
      return res.status(500).json({ ok: false, reason: 'server not configured' });
    }

    const creds = Buffer.from(`${tokenId}:${tokenSecret}`).toString('base64');

    const bulkRes = await fetch('https://api.bulksms.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${creds}`,
      },
      body: JSON.stringify({ to: e164, body: message, routingGroup: 'STANDARD' }),
    });

    if (!bulkRes.ok) {
      const errText = await bulkRes.text().catch(() => '');
      console.error('BulkSMS error', bulkRes.status, errText);
      return res.status(200).json({ ok: false, status: bulkRes.status });
    }

    return res.status(200).json({ ok: true, status: bulkRes.status });
  } catch (err) {
    console.error('send-sms handler error:', err);
    return res.status(500).json({ ok: false, reason: 'server error' });
  }
}
