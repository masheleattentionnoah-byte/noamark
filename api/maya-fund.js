// Maya Fund: ONE file. Reads NoaMark's own account totals from Myfxbook (free "Auto Update").
//   GET /api/maya-fund  -> public totals only (no trades, no symbols)
// No database, no cron. Vercel caches the answer for 15 minutes, so Myfxbook is only
// contacted a few times an hour. CommonJS, no dependencies (Node 18+ global fetch).
//
// Env vars: MYFXBOOK_EMAIL, MYFXBOOK_PASSWORD
//   optional: MYFXBOOK_ACCOUNT_NUMBER (your MT5 login, only needed if you track several accounts)
// Notes from Myfxbook's API docs: sessions are bound to the IP that logged in, so we log in on
// every refresh and log out again; get-history only returns the last 50 trades, so we use
// get-my-accounts + get-data-daily instead; Myfxbook timestamps use the broker's time zone.

const DAY = 86400000;
const SAST = 2 * 3600000; // South Africa is UTC+2 all year (no DST)
const BASE = 'https://www.myfxbook.com/api';
const CACHE_MS = 15 * 60000;

const round = (n) => Math.round(n * 100) / 100;
let cache = null; // { at, body }

async function mfx(method, params) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE}/${method}.json?${qs}`, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`Myfxbook ${method} HTTP ${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(`Myfxbook ${method}: ${data.message || 'error'}`);
  return data;
}

// "MM/DD/YYYY[ HH:mm]" -> "YYYY-MM-DD"
const toISODate = (s) => {
  const m = /^(\d{2})\/(\d{2})\/(\d{4})/.exec(String(s || ''));
  return m ? `${m[3]}-${m[1]}-${m[2]}` : null;
};
const addDays = (iso, n) => new Date(Date.parse(iso + 'T00:00:00Z') + n * DAY).toISOString().slice(0, 10);

// ---------- STATS (pure function, easy to test) ----------
function computeStats(account, rows, nowMs = Date.now()) {
  const today = new Date(nowMs + SAST).toISOString().slice(0, 10);
  const dow = new Date(today + 'T00:00:00Z').getUTCDay();
  const week = addDays(today, -((dow + 6) % 7)); // Monday
  const month = today.slice(0, 8) + '01';

  const days = rows
    .map((r) => ({ d: toISODate(r.date), balance: Number(r.balance), profit: Number(r.profit || 0) }))
    .filter((r) => r.d)
    .sort((a, b) => (a.d < b.d ? -1 : 1));

  // closing balance on a date = last known balance on or before it (0 before the account existed)
  const balanceAt = (iso) => {
    let b = 0;
    for (const r of days) { if (r.d <= iso) b = r.balance; else break; }
    return b;
  };

  // money added/removed each day = balance change that profit does not explain
  let prev = 0;
  const flows = days.map((r) => {
    const f = r.balance - prev - r.profit;
    prev = r.balance;
    return { d: r.d, flow: Math.abs(f) >= 0.5 ? f : 0 };
  });

  const period = (startIso) => {
    const amount = days.filter((r) => r.d >= startIso).reduce((a, r) => a + r.profit, 0);
    const startBal = balanceAt(addDays(startIso, -1));
    const deposits = flows.filter((f) => f.d >= startIso && f.flow > 0).reduce((a, f) => a + f.flow, 0);
    const basis = startBal > 0 ? startBal : deposits;
    return { amount: round(amount), pct: basis > 0 ? round((amount / basis) * 100) : null };
  };

  const profit = Number(account.profit || 0);
  const deposited = Number(account.deposits || 0);
  const first = days[0];
  const firstFlow = first ? first.balance - first.profit : null;

  const series = [];
  for (let i = 89; i >= 0; i--) {
    const d = addDays(today, -i);
    series.push({ d, balance: round(balanceAt(d)) });
  }

  const balance = Number(account.balance);
  const updated = /^(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2})/.exec(String(account.lastUpdateDate || ''));
  // Myfxbook shows broker time; treat as UTC+2 (within an hour of JustMarkets' server time)
  const updatedAt = updated
    ? new Date(Date.UTC(+updated[3], +updated[1] - 1, +updated[2], +updated[4], +updated[5]) - SAST).toISOString()
    : null;

  return {
    currency: account.currency || 'USD',
    updatedAt,
    startedWith: firstFlow != null && firstFlow > 0 ? round(firstFlow) : null,
    deposited: deposited > 0 ? round(deposited) : null,
    balance: round(balance),
    periods: {
      today: period(today),
      week: period(week),
      month: period(month),
      all: { amount: round(profit), pct: deposited > 0 ? round((profit / deposited) * 100) : null },
    },
    series,
    // true when the daily history ends at the account's current balance
    reconciled: days.length ? Math.abs(balanceAt(today) - balance) < 0.5 : null,
  };
}

// ---------- LIVE FETCH ----------
async function loadStats() {
  const email = process.env.MYFXBOOK_EMAIL, password = process.env.MYFXBOOK_PASSWORD;
  if (!email || !password) throw new Error('Myfxbook credentials missing');
  const { session } = await mfx('login', { email, password });
  try {
    const { accounts } = await mfx('get-my-accounts', { session });
    const want = process.env.MYFXBOOK_ACCOUNT_NUMBER;
    const account = (want && accounts.find((a) => String(a.accountId) === String(want))) || accounts[0];
    if (!account) throw new Error('No Myfxbook account found');
    const start = toISODate(account.creationDate) || '2020-01-01';
    const end = addDays(new Date(Date.now() + SAST).toISOString().slice(0, 10), 1);
    const raw = await mfx('get-data-daily', { session, id: account.id, start: addDays(start, -1), end });
    const rows = (raw.dataDaily || []).flat(Infinity);
    return computeStats(account, rows);
  } finally {
    mfx('logout', { session }).catch(() => {}); // free the session; never block the response
  }
}

// ---------- HANDLER ----------
module.exports = async (req, res) => {
  try {
    if (!cache || Date.now() - cache.at > CACHE_MS) {
      try { cache = { at: Date.now(), body: await loadStats() }; }
      catch (e) { console.error('maya-fund refresh failed:', e.message); if (!cache) throw e; } // serve last good data
    }
    res.setHeader('Cache-Control', 'public, s-maxage=900, stale-while-revalidate=3600');
    return res.status(200).json(cache.body);
  } catch (e) {
    console.error('maya-fund failed:', e.message);
    return res.status(500).json({ error: 'unavailable' });
  }
};

module.exports.computeStats = computeStats; // for testing
