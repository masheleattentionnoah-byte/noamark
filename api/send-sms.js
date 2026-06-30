// /api/send-sms.js
// Vercel serverless function — proxies SMS sending to BulkSMS so the
// BulkSMS Token ID / Token Secret never reach the browser.
//
// Set these in Vercel → Project → Settings → Environment Variables:
//   BULKSMS_TOKEN_ID
//   BULKSMS_TOKEN_SECRET
// Then redeploy.

export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, reason: 'method not allowed' });
  }

  // Basic CORS lock-down — only allow calls from your own domain.
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
