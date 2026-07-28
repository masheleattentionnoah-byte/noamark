// /api/netcash-payment-request.js
//
// Automates what was being done manually in the Netcash dashboard: creates
// a Payment Request (SMS + Email, containing a secure pay link) for a
// specific business, referencing one of the Subscription Templates already
// set up in your Netcash account (Starter/Growth/Pro), instead of you
// entering the customer's phone number by hand each time.
//
// HONESTY NOTE — READ BEFORE RELYING ON THIS IN PRODUCTION:
// This calls Netcash's "CreateInvoice" SOAP web service. The parameter
// list below (ServiceKey, M1, M2, Amount, P2, P3, M4-M6, M9, M11-M14, M27)
// is taken directly from Netcash's own published documentation and is
// solid. What is NOT independently confirmed is the exact SOAP envelope
// structure (namespace / SOAPAction) — Netcash's WSDL wasn't retrievable
// in a form I could verify with certainty. The envelope below follows the
// standard, extremely common convention for this class of older Microsoft
// web service (namespace defaulting to http://tempuri.org/), which is a
// reasonable best guess but genuinely may need one correction once tested
// against a real account. If it fails, check the raw response logged
// below — a SOAP fault message usually states exactly what's wrong
// (wrong namespace, wrong action, etc.), which turns this from a guess
// into a one-line fix rather than another round of guessing blind.
//
// SETUP NEEDED IN VERCEL (Project Settings → Environment Variables):
//   NETCASH_SERVICE_KEY — already set, reused here.

const NETCASH_SOFTWARE_VENDOR_KEY = '24ade73c-98cf-47b3-99be-cc7b867b3080';

// Subscription Template IDs — from your Netcash Merchant Admin →
// Services → Pay Now → Subscriptions → Manage subscription templates.
// If these ever change (template deleted/recreated), update the IDs here.
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

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigins = ['https://noamark.com', 'https://www.noamark.com'];
  const isVercelPreview = /\.vercel\.app$/.test(origin.replace(/^https?:\/\//, ''));
  if (allowedOrigins.includes(origin) || isVercelPreview) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, reason: 'Method not allowed' });
  }

  const { plan, listingId, businessEmail, businessMobile } = req.body || {};

  if (!plan || !SUBSCRIPTION_TEMPLATES[plan]) {
    return res.status(400).json({ ok: false, reason: 'Unknown or missing plan' });
  }
  if (!listingId) {
    return res.status(400).json({ ok: false, reason: 'Missing listingId' });
  }
  if (!businessEmail && !businessMobile) {
    return res.status(400).json({ ok: false, reason: 'Need an email or mobile number to send the payment request to' });
  }

  const serviceKey = process.env.NETCASH_SERVICE_KEY;
  if (!serviceKey) {
    console.warn('NETCASH_SERVICE_KEY not set — cannot create payment request.');
    return res.status(200).json({ ok: false, reason: 'Payments are not configured yet.' });
  }

  const p2 = 'NM' + Date.now().toString(36).toUpperCase(); // unique reference, must not repeat
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
      <tem:M6>${escapeXml(businessEmail || '')}</tem:M6>
      <tem:M9>${escapeXml(businessEmail || '')}</tem:M9>
      <tem:M11>${escapeXml(businessMobile || '')}</tem:M11>
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

    // Numeric error codes documented by Netcash (100/103/200/301/310) come
    // back inside the response body, not as an HTTP error — check for them.
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
