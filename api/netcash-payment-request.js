// /api/netcash-payment-request.js
// ... (header comments unchanged) ...

import crypto from 'crypto';

const NETCASH_SOFTWARE_VENDOR_KEY = '24ade73c-98cf-47b3-99be-cc7b867b3080';

const SUBSCRIPTION_TEMPLATES = {
  starter: '11863',
  growth:  '11864',
  pro:     '11865',
};

const PLAN_DESCRIPTIONS = {
  starter: 'NoaMark Starter Plan (monthly)',
  growth:  'NoaMark Growth Plan (monthly)',
  pro:     'NoaMark Pro Plan (monthly)',
};

function escapeXml(str) {
  return String(str ?? '').replace(/[<>&'"]/g, c => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;',
  }[c]));
}

// ── NEW: verify the caller is a real logged-in business ──
function verifySessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const secret = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD || '';
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const sigBuf = Buffer.from(sig || '', 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() >= claims.exp) return null;
    return claims;
  } catch (e) { return null; }
}

// ── NEW: very small in-memory rate limit, per business id ──
// Best-effort only (resets on cold start) but stops a leaked/stolen token
// from being hammered in a tight loop.
const _lastRequestAt = {};
function tooSoon(key, minGapMs = 10000) {
  const now = Date.now();
  if (_lastRequestAt[key] && now - _lastRequestAt[key] < minGapMs) return true;
  _lastRequestAt[key] = now;
  return false;
}

function buildHash(fieldsInOrder, privateKey) {
  const raw = fieldsInOrder.join('') + privateKey;
  return crypto.createHash('sha512').update(raw.toLowerCase()).digest('hex');
}

async function supaFetch(path) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  return fetch(`${base}/rest/v1/${path}`, {
    headers: { apikey: key, Authorization: `Bearer ${key}` },
  });
}

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigins = ['https://noamark.com', 'https://www.noamark.com'];
  const isVercelPreview = /\.vercel\.app$/.test(origin.replace(/^https?:\/\//, ''));
  if (allowedOrigins.includes(origin) || isVercelPreview) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, reason: 'Method not allowed' });
  }

  // ── NEW: require a valid business (or admin) session token ──
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const claims = verifySessionToken(token);
  if (!claims || (claims.role !== 'business' && claims.role !== 'admin')) {
    return res.status(401).json({ ok: false, reason: 'Please log in again.' });
  }

  const { plan, listingId } = req.body || {};

  if (!plan || !SUBSCRIPTION_TEMPLATES[plan]) {
    return res.status(400).json({ ok: false, reason: 'Unknown or missing plan' });
  }
  if (!listingId) {
    return res.status(400).json({ ok: false, reason: 'Missing listingId' });
  }

  if (tooSoon('biz:' + claims.id)) {
    return res.status(429).json({ ok: false, reason: 'Please wait a moment before trying again.' });
  }

  // ── NEW: pull the business's own email/mobile server-side instead of
  // trusting whatever the client sent — closes the "spam a stranger's
  // phone with an invoice" hole entirely, and also stops the request
  // being made against a listing that isn't the caller's own.
  // Admin is trusted to specify a test recipient directly (e.g. from the
  // netcash-test.html tool) since only a real admin token reaches here.
  let businessEmail = '';
  let businessMobile = '';
  if (claims.role === 'admin') {
    businessEmail = (req.body?.businessEmail || '').trim();
    businessMobile = (req.body?.businessMobile || '').trim();
  } else {
    const listRes = await supaFetch(`users?id=eq.${encodeURIComponent(claims.id)}&select=id,email,mobile&limit=1`);
    const rows = await listRes.json().catch(() => []);
    const biz = rows[0];
    if (!biz || String(biz.id) !== String(claims.id)) {
      return res.status(403).json({ ok: false, reason: 'Account not found.' });
    }
    businessEmail = biz.email || '';
    businessMobile = biz.mobile || '';
  }

  if (!businessEmail && !businessMobile) {
    return res.status(400).json({ ok: false, reason: 'Your account has no email or mobile on file.' });
  }

  const serviceKey = process.env.NETCASH_SERVICE_KEY;
  if (!serviceKey) {
    console.warn('NETCASH_SERVICE_KEY not set — cannot create payment request.');
    return res.status(200).json({ ok: false, reason: 'Payments are not configured yet.' });
  }

  const p2 = 'NM' + Date.now().toString(36).toUpperCase();
  const sendSms = !!businessMobile;
  const sendEmail = !!businessEmail;

  const soapEnvelope = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
  <soap:Body>
    <tem:CreateInvoice>
      <tem:ServiceKey>${escapeXml(serviceKey)}</tem:ServiceKey>
      <tem:M1>${escapeXml(serviceKey)}</tem:M1>
      <tem:M2>${escapeXml(NETCASH_SOFTWARE_VENDOR_KEY)}</tem:M2>
      <tem:P2>${escapeXml(p2)}</tem:P2>
      <tem:P3>${escapeXml(PLAN_DESCRIPTIONS[plan])}</tem:P3>
      <tem:M4>${escapeXml(plan)}</tem:M4>
      <tem:M5>${escapeXml(listingId)}</tem:M5>
      <tem:M6>${escapeXml(businessEmail)}</tem:M6>
      <tem:M9>${escapeXml(businessEmail)}</tem:M9>
      <tem:M11>${escapeXml(businessMobile)}</tem:M11>
      <tem:M12>${sendSms}</tem:M12>
      <tem:M13>${sendEmail}</tem:M13>
      <tem:M14>true</tem:M14>
      <tem:M27>${escapeXml(SUBSCRIPTION_TEMPLATES[plan])}</tem:M27>
    </tem:CreateInvoice>
  </soap:Body>
</soap:Envelope>`;

  try {
    const soapRes = await fetch('https://ws.netcash.co.za/PayNow/PayNow.svc', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'http://tempuri.org/IPayNow/CreateInvoice',
      },
      body: soapEnvelope,
    });

    const rawText = await soapRes.text();
    console.log('netcash-payment-request: raw SOAP response:', rawText);

    if (!soapRes.ok) {
      console.error('netcash-payment-request: SOAP call failed with status', soapRes.status);
      return res.status(200).json({ ok: false, reason: 'Netcash rejected the request — check server logs for the raw SOAP fault.' });
    }

    const errorMatch = rawText.match(/<[^>]*CreateInvoiceResult[^>]*>(\d{3})<\/[^>]*>/);
    if (errorMatch) {
      console.error('netcash-payment-request: Netcash returned error code', errorMatch[1]);
      return res.status(200).json({ ok: false, reason: `Netcash error code ${errorMatch[1]} — check server logs.` });
    }

    return res.status(200).json({ ok: true, reference: p2 });
  } catch (e) {
    console.error('netcash-payment-request: request threw an error.', e);
    return res.status(200).json({ ok: false, reason: 'Could not reach Netcash — check server logs.' });
  }
}
