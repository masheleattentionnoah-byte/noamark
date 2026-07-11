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
