// /api/send-email.js
//
// Sends transactional emails via Resend (https://resend.com).
// Mirrors the pattern of /api/send-sms.js: credentials live ONLY in
// Vercel environment variables, never in index.html or the browser.
//
// SETUP NEEDED IN VERCEL (Project Settings → Environment Variables):
//   RESEND_API_KEY   — the API key Resend gives you after you verify
//                       your noamark.com domain
//   EMAIL_FROM       — e.g. "NoaMark <noreply@noamark.com>"
//                       (must use a verified domain in Resend)
//
// Until RESEND_API_KEY is set, this will return ok:false and the
// calling code in index.html (nmSendEmail) is written to fail silently,
// so nothing else breaks — approvals/payments still go through, you
// just won't get the email sent until this is configured.
//
// RATE LIMITING — WHY THIS EXISTS:
// This endpoint is called from several places in index.html, including by
// visitors who are NOT logged in (submitting an enquiry, requesting a
// booking) — so it can't require a login token everywhere without
// breaking those features. Instead this uses THREE layers, so a patient
// attacker who just waits out a short cooldown still can't grind you down
// over hours:
//   1. Burst cooldown — stops rapid-fire spam to one address.
//   2. Daily cap PER RECIPIENT — stops sustained harassment of one
//      person even if spread slowly across a whole day.
//   3. Daily GLOBAL cap — a hard ceiling on total sends per day across
//      everyone, so even a distributed attack can't run up an unbounded
//      Resend bill or get the domain flagged for abuse.
// Best-effort in-memory only — resets on cold start — but stops
// everything short of a determined attacker forcing/waiting out cold
// starts. Upgrade path if this ever becomes a real concern: persistent
// storage (Vercel KV / Upstash Redis) instead of in-memory Maps.

const _recentByRecipient = new Map();     // email -> last send timestamp (burst)
const _dailyByRecipient = new Map();      // email -> [timestamps in last 24h]
const _recentByIp = new Map();            // ip -> [timestamps in last hour]
const _dailyGlobal = [];                  // [timestamps in last 24h], all sends

const RECIPIENT_COOLDOWN_MS = 30 * 1000;      // burst: 1 email per address per 30s
const DAY_MS = 24 * 60 * 60 * 1000;
// Same reasoning as send-sms.js — a busy business's inbox can legitimately
// get many real notifications in one day. 60 gives generous headroom for
// real traffic while still stopping deliberate flooding of one address.
const RECIPIENT_DAILY_MAX = 60;
const IP_WINDOW_MS = 60 * 60 * 1000;          // 1 hour window
const IP_MAX_PER_HOUR = 30;                   // max 30 emails per IP per hour
const GLOBAL_DAILY_MAX = 3000;                // hard ceiling: max 3000 emails/day, site-wide

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
  // Same CORS/preflight handling as /api/send-sms.js — must run before
  // any method check, or a browser preflight (OPTIONS) gets rejected
  // with 405 before it ever reaches the code meant to answer it, and the
  // browser silently refuses to send the real request at all.
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

  const { to, subject, message } = req.body || {};

  if (!to || !subject || !message) {
    return res.status(400).json({ ok: false, reason: 'Missing to, subject, or message' });
  }

  // ── Rate limiting — see comment at top of file ──
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  const toKey = String(to).toLowerCase();
  if (tooSoonForRecipient(toKey)) {
    return res.status(429).json({ ok: false, reason: 'This address was just emailed — please wait a moment.' });
  }
  if (recipientDailyLimitHit(toKey)) {
    return res.status(429).json({ ok: false, reason: 'This address has reached its daily email limit.' });
  }
  if (ipRateLimited(ip)) {
    return res.status(429).json({ ok: false, reason: 'Too many requests — please try again later.' });
  }
  if (globalDailyLimitHit()) {
    console.error('send-email: GLOBAL DAILY LIMIT reached — possible abuse in progress.');
    return res.status(429).json({ ok: false, reason: 'Daily email limit reached — please try again tomorrow.' });
  }

  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM || 'NoaMark <onboarding@resend.dev>';

  if (!apiKey) {
    console.warn('RESEND_API_KEY not set — email not sent.');
    return res.status(200).json({ ok: false, reason: 'Email not configured yet' });
  }

  try {
    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from,
        to: [to],
        subject,
        // Plain-text message wrapped in a very simple HTML shell.
        // Feel free to swap this for a branded template later.
        html: `<div style="font-family:sans-serif;font-size:15px;color:#111;line-height:1.5;">
                 <p>${message.replace(/\n/g, '<br>')}</p>
                 <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
                 <p style="font-size:12px;color:#888;">NoaMark — noamark.com</p>
               </div>`
      })
    });

    const data = await resendRes.json().catch(() => ({}));

    if (!resendRes.ok) {
      console.error('Resend API error:', data);
      return res.status(200).json({ ok: false, reason: data.message || 'Resend API error' });
    }

    return res.status(200).json({ ok: true, id: data.id });
  } catch (e) {
    console.error('send-email error:', e);
    return res.status(200).json({ ok: false, reason: e.message });
  }
}
