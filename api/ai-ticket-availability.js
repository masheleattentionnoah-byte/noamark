// Place this file at /api/ai-ticket-availability.js
//
// GET /api/ai-ticket-availability
// Returns the real number of Starter spots left (cap 21) and the real
// number of combined Growth+Pro spots left (shared cap 126), based on
// confirmed rows in the ai_ticket_sales table (see
// /supabase/ai_ticket_sales.sql).
//
// Uses the SAME Supabase env vars already set for netcash-notify.js /
// ozow-notify.js: SUPABASE_URL and SUPABASE_SERVICE_KEY. No new env
// vars needed.

const STARTER_CAP = 21;
const GROWTH_PRO_CAP = 126; // shared pool between Growth and Pro

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).json({ ok: false, reason: 'Method not allowed' });
    return;
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_KEY;

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    res.status(500).json({ ok: false, reason: 'Supabase env vars not configured' });
    return;
  }

  try {
    const [starterCount, growthCount, proCount] = await Promise.all([
      countConfirmed('starter'),
      countConfirmed('growth'),
      countConfirmed('pro'),
    ]);

    const starterRemaining = Math.max(0, STARTER_CAP - starterCount);
    const growthProRemaining = Math.max(0, GROWTH_PRO_CAP - (growthCount + proCount));

    res.status(200).json({ ok: true, starterRemaining, growthProRemaining });
  } catch (e) {
    res.status(500).json({ ok: false, reason: e.message || 'Lookup failed' });
  }

  async function countConfirmed(tier) {
    const url =
      `${SUPABASE_URL}/rest/v1/ai_ticket_sales?tier=eq.${tier}&status=eq.confirmed&select=id`;
    const r = await fetch(url, {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        Prefer: 'count=exact',
      },
    });
    if (!r.ok) throw new Error(`Supabase count failed for ${tier}`);
    const contentRange = r.headers.get('content-range'); // "0-9/23"
    if (contentRange && contentRange.includes('/')) {
      return parseInt(contentRange.split('/')[1], 10) || 0;
    }
    const rows = await r.json();
    return Array.isArray(rows) ? rows.length : 0;
  }
};
