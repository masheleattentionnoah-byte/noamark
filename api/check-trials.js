// /api/check-trials.js
//
// Runs once daily (via Vercel Cron, see vercel.json) and enforces NoaMark's
// trial/subscription model:
//   - New listings get a 1-month free trial from signup (created_at).
//   - If no paid plan is chosen, a 3-day grace period follows, then the
//     listing is UNLISTED (status set to 'suspended') — NOT deleted. All
//     data (photos, description, hours, etc.) is kept intact, so paying
//     later restores the listing instantly instead of forcing the business
//     to redo their entire signup from scratch.
//   - Once a plan IS chosen (boost_tier != 'none'), it's treated as monthly
//     — same 1-month active window + 3-day grace on renewal, calculated
//     from boost_started_at instead of signup.
// This mirrors nmComputeSubStatus() in index.html exactly — if you change
// the trial/grace lengths there, change them here too, or the banner shown
// to businesses and what this job actually enforces will disagree.
//
// SETUP NEEDED IN VERCEL (Project Settings → Environment Variables):
//   SUPABASE_URL, SUPABASE_SERVICE_KEY — already set for ozow-notify.js,
//     reused here.
//   RESEND_API_KEY, EMAIL_FROM — already set for send-email.js, reused here.
//   CRON_SECRET — a random string you choose. Also add the exact same
//     value in vercel.json's cron config (see below) so Vercel's own
//     scheduler can call this endpoint, and set it as an env var here so
//     the endpoint can verify the request actually came from Vercel Cron
//     and not just anyone who finds the URL. Generate one with:
//     `openssl rand -hex 32` (or any long random string).
//
// OPTIONAL BUT RECOMMENDED SQL (Supabase SQL editor) — lets this job avoid
// re-sending the same warning email every day during a multi-day window.
// The job still works without it, it just can't dedupe notices:
//   ALTER TABLE listings ADD COLUMN IF NOT EXISTS trial_notice_sent text;

const TRIAL_DAYS = 30;
const GRACE_DAYS = 3;
const DAY = 24 * 60 * 60 * 1000;

function computeSubStatus(listing) {
  const now = Date.now();
  const created = listing.created_at ? new Date(listing.created_at).getTime() : now;

  if (listing.boost_tier && listing.boost_tier !== 'none') {
    const boostStart = listing.boost_started_at ? new Date(listing.boost_started_at).getTime() : created;
    const activeUntil = boostStart + TRIAL_DAYS * DAY;
    const graceUntil = activeUntil + GRACE_DAYS * DAY;
    if (now < activeUntil) return { state: 'active', daysLeft: Math.ceil((activeUntil - now) / DAY) };
    if (now < graceUntil) return { state: 'lapsed_grace', daysLeft: Math.ceil((graceUntil - now) / DAY) };
    return { state: 'expired' };
  } else {
    const trialUntil = created + TRIAL_DAYS * DAY;
    const graceUntil = trialUntil + GRACE_DAYS * DAY;
    if (now < trialUntil) return { state: 'trial', daysLeft: Math.ceil((trialUntil - now) / DAY) };
    if (now < graceUntil) return { state: 'trial_grace', daysLeft: Math.ceil((graceUntil - now) / DAY) };
    return { state: 'expired' };
  }
}

async function sendEmail(apiKey, from, to, subject, message) {
  if (!apiKey || !to) return;
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from,
        to: [to],
        subject,
        html: `<div style="font-family:sans-serif;font-size:15px;color:#111;line-height:1.5;">
                 <p>${message.replace(/\n/g, '<br>')}</p>
                 <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
                 <p style="font-size:12px;color:#888;">NoaMark — noamark.com</p>
               </div>`,
      }),
    });
  } catch (e) {
    console.error('check-trials: email send failed for', to, e.message);
  }
}

export default async function handler(req, res) {
  // Verify this request actually came from Vercel Cron, not a random visitor
  // who found this URL. Same principle as the admin-panel security fix —
  // never trust that a sensitive endpoint won't be called unless something
  // actually checks who's calling it.
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) {
    console.error('CRON_SECRET not set — refusing to run for safety.');
    return res.status(500).json({ ok: false, reason: 'CRON_SECRET not configured' });
  }
  if (req.headers.authorization !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ ok: false, reason: 'Unauthorized' });
  }

  const supaUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_KEY;
  const resendKey = process.env.RESEND_API_KEY;
  const emailFrom = process.env.EMAIL_FROM || 'NoaMark <onboarding@resend.dev>';

  if (!supaUrl || !serviceKey) {
    return res.status(500).json({ ok: false, reason: 'SUPABASE_URL / SUPABASE_SERVICE_KEY not configured' });
  }

  const headers = {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    'Content-Type': 'application/json',
  };

  // Only approved, currently-listed businesses are subject to trial/grace —
  // pending/rejected listings were never live so they don't need this.
  const listRes = await fetch(
    `${supaUrl}/rest/v1/listings?status=eq.approved&select=id,name,email,owner_email,boost_tier,boost_started_at,created_at,trial_notice_sent`,
    { headers }
  );
  if (!listRes.ok) {
    const text = await listRes.text();
    console.error('check-trials: failed to fetch listings', text);
    return res.status(500).json({ ok: false, reason: 'Failed to fetch listings' });
  }
  const listings = await listRes.json();

  const summary = { checked: listings.length, warned: 0, graceStarted: 0, suspended: 0, errors: 0 };

  for (const listing of listings) {
    try {
      const { state, daysLeft } = computeSubStatus(listing);
      const to = listing.owner_email || listing.email;
      const alreadySent = listing.trial_notice_sent;

      if (state === 'trial' && daysLeft <= 3 && alreadySent !== 'trial_warning') {
        await sendEmail(resendKey, emailFrom, to,
          `Your NoaMark free trial ends in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`,
          `Hi ${listing.name},\n\nYour free trial on NoaMark ends in ${daysLeft} day${daysLeft === 1 ? '' : 's'}. To keep ${listing.name} listed and visible to customers, choose a plan from your Business Portal before then.\n\nIf you don't choose a plan, your listing will enter a short grace period and then be removed.\n\nLog in and choose a plan: noamark.com`
        );
        await patchTrialNotice(supaUrl, headers, listing.id, 'trial_warning');
        summary.warned++;
      } else if (state === 'trial_grace' && alreadySent !== 'grace_started') {
        await sendEmail(resendKey, emailFrom, to,
          `Action needed: your NoaMark listing will be removed in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`,
          `Hi ${listing.name},\n\nYour free trial has ended. Your listing is still visible for a short grace period, but will be permanently removed in ${daysLeft} day${daysLeft === 1 ? '' : 's'} unless you choose a plan.\n\nChoose a plan now to keep your listing live: noamark.com`
        );
        await patchTrialNotice(supaUrl, headers, listing.id, 'grace_started');
        summary.graceStarted++;
      } else if (state === 'lapsed_grace' && alreadySent !== 'grace_started') {
        await sendEmail(resendKey, emailFrom, to,
          `Action needed: your NoaMark plan has expired`,
          `Hi ${listing.name},\n\nYour plan on NoaMark has expired. Your listing is still visible for a short grace period, but will be permanently removed in ${daysLeft} day${daysLeft === 1 ? '' : 's'} unless you renew.\n\nRenew now to keep your listing live: noamark.com`
        );
        await patchTrialNotice(supaUrl, headers, listing.id, 'grace_started');
        summary.graceStarted++;
      } else if (state === 'expired') {
        await sendEmail(resendKey, emailFrom, to,
          `Your NoaMark listing has been unlisted`,
          `Hi ${listing.name},\n\nYour grace period has ended and your listing for ${listing.name} has been unlisted from NoaMark, since no plan was chosen in time.\n\nGood news: nothing is lost. Your listing details, photos, and info are all still saved — just log back in and choose a plan to go live again instantly, no need to start over.\n\nnoamark.com`
        );
        // Soft-delete: unlist from the public marketplace by changing status,
        // but keep the row (and all its data) intact so paying later restores
        // it instantly instead of forcing the business to redo their entire
        // listing from scratch.
        const suspendRes = await fetch(`${supaUrl}/rest/v1/listings?id=eq.${listing.id}`, {
          method: 'PATCH',
          headers,
          body: JSON.stringify({ status: 'suspended' }),
        });
        if (!suspendRes.ok) throw new Error('Suspend failed: ' + (await suspendRes.text()));
        summary.suspended++;
      }
    } catch (e) {
      console.error('check-trials: error processing listing', listing.id, e.message);
      summary.errors++;
    }
  }

  console.log('check-trials summary:', JSON.stringify(summary));
  return res.status(200).json({ ok: true, summary });
}

async function patchTrialNotice(supaUrl, headers, id, value) {
  try {
    await fetch(`${supaUrl}/rest/v1/listings?id=eq.${id}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ trial_notice_sent: value }),
    });
  } catch (e) {
    // If the trial_notice_sent column doesn't exist yet (migration not run),
    // this fails silently — the job still works, it just can't dedupe
    // notices and may re-send a warning on the next run.
    console.warn('check-trials: could not update trial_notice_sent for', id, e.message);
  }
}
