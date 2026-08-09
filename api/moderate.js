// /api/moderate.js
//
// Combines what would otherwise be two separate serverless functions
// (admin-delete-listing + delete-review) into one, routed via a `mode`
// field in the request body — same consolidation pattern already used in
// auth.js, done for the same reason: Vercel's Hobby plan caps a project
// at 12 serverless functions total, and this project is already close to
// that limit. Nothing about the security model changes — same real
// session-token verification, same ownership checks, just one file
// instead of two.
//
// SECURITY FIX this file provides: both actions used to happen directly
// from the browser via the public Supabase key, protected only by RLS
// policies that were named as if they checked ownership/admin status but
// actually had `USING (true)` — meaning ANYONE could delete ANY listing
// or ANY review on the platform. Both actions now require a real, signed
// session token, verified server-side, plus a real ownership check for
// business-initiated review deletes.
//
// SETUP NEEDED IN VERCEL (already set for other endpoints, reused here):
//   SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_SESSION_SECRET / ADMIN_PASSWORD

import crypto from 'crypto';

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

// Same pbkdf2 verification as auth.js — duplicated here rather than
// imported, matching how verifySessionToken above is already duplicated
// across the split serverless files (see the top-of-file note on why
// this project is split the way it is).
function pbkdf2Hex(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}
function verifyStoredPassword(password, storedStr) {
  if (!storedStr || !storedStr.includes(':')) return storedStr === password;
  try {
    const [saltHex] = storedStr.split(':');
    return (saltHex + ':' + pbkdf2Hex(password, saltHex)) === storedStr;
  } catch (e) { return false; }
}

async function supaFetch(path, opts = {}) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  return fetch(`${base}/rest/v1/${path}`, {
    ...opts,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Prefer: opts.prefer || 'return=representation',
      ...(opts.headers || {}),
    },
  });
}

// ── mode: delete-listing (admin only) ──
async function handleDeleteListing(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const enq = await supaFetch(`enquiries?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!enq.ok) throw new Error('Failed deleting enquiries: ' + await enq.text());

    const bkg = await supaFetch(`bookings?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!bkg.ok) throw new Error('Failed deleting bookings: ' + await bkg.text());

    const notif = await supaFetch(`notifications?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!notif.ok) throw new Error('Failed deleting notifications: ' + await notif.text());

    const rev = await supaFetch(`reviews?listing_id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!rev.ok) throw new Error('Failed deleting reviews: ' + await rev.text());

    const lst = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!lst.ok) throw new Error('Failed deleting listing: ' + await lst.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-listing error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: delete-user (admin only) ──
// Deletes a business/subscriber/guest account. A business account owns
// listings, so those are removed first — via the exact same cascade as
// handleDeleteListing (enquiries/bookings/notifications/reviews, then the
// listing) — so nothing is left orphaned in Supabase after the user row
// is gone.
async function handleDeleteUser(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { userId } = body;
  if (!userId) return { status: 400, json: { ok: false, reason: 'Missing userId' } };

  try {
    const userRes = await supaFetch(`users?id=eq.${encodeURIComponent(userId)}&select=id,role,email&limit=1`);
    const userRows = await userRes.json();
    const user = userRows[0];
    if (!user) return { status: 404, json: { ok: false, reason: 'User not found.' } };

    if (user.role === 'admin') {
      return { status: 400, json: { ok: false, reason: 'The admin account cannot be deleted here.' } };
    }

    if (user.role === 'business' && user.email) {
      const listingsRes = await supaFetch(`listings?or=(email.ilike.${encodeURIComponent(user.email)},owner_email.ilike.${encodeURIComponent(user.email)})&select=id`);
      const listings = await listingsRes.json();
      for (const l of listings) {
        const result = await handleDeleteListing(claims, { listingId: l.id });
        if (!result.json.ok) throw new Error(`Failed deleting listing ${l.id}: ${result.json.reason}`);
      }
    }

    const delRes = await supaFetch(`users?id=eq.${encodeURIComponent(userId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!delRes.ok) throw new Error(await delRes.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-user error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: delete-own-account (business or subscriber, deleting THEMSELVES) ──
// The session token alone proves who's asking, but re-checking the
// account's own password here is a deliberate second factor — it stops
// a permanent, irreversible delete from firing off an unlocked device or
// a stray click on a stale page. Reuses handleDeleteListing's cascade for
// a business account's own listings, same as delete-user above — the
// only difference is WHO is allowed to trigger it and that no separate
// admin session is required.
async function handleDeleteOwnAccount(claims, body) {
  if (claims.role !== 'business' && claims.role !== 'subscriber') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { password } = body;
  if (!password) return { status: 400, json: { ok: false, reason: 'Please enter your password to confirm.' } };

  try {
    const userRes = await supaFetch(`users?id=eq.${encodeURIComponent(claims.id)}&select=id,role,email,password&limit=1`);
    const userRows = await userRes.json();
    const user = userRows[0];
    if (!user || user.role !== claims.role) return { status: 401, json: { ok: false, reason: 'Please log in again.' } };

    if (!verifyStoredPassword(password, user.password)) {
      return { status: 200, json: { ok: false, reason: 'Incorrect password.' } };
    }

    if (user.role === 'business' && user.email) {
      const listingsRes = await supaFetch(`listings?or=(email.ilike.${encodeURIComponent(user.email)},owner_email.ilike.${encodeURIComponent(user.email)})&select=id`);
      const listings = await listingsRes.json();
      for (const l of listings) {
        // Reuses the admin-gated cascade delete — safe here because we've
        // already verified this caller owns the account whose listings
        // these are, via password + the listing's own email match above.
        const result = await handleDeleteListing({ role: 'admin' }, { listingId: l.id });
        if (!result.json.ok) throw new Error(`Failed deleting listing ${l.id}: ${result.json.reason}`);
      }
    }

    const delRes = await supaFetch(`users?id=eq.${encodeURIComponent(claims.id)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!delRes.ok) throw new Error(await delRes.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-own-account error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-set-status (admin only) ──
// Approve / reject / suspend a listing. Replaces the direct client-side
// `_supa.from('listings').update({status: ...})` calls, which only worked
// because the listings table's RLS UPDATE policy was wide open to anyone —
// not just admin.
async function handleAdminSetStatus(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId, status } = body;
  const allowed = ['approved', 'rejected', 'suspended'];
  if (!listingId || !allowed.includes(status)) {
    return { status: 400, json: { ok: false, reason: 'Missing or invalid listingId/status.' } };
  }
  try {
    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/admin-set-status error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-remove-verified (admin only, REMOVE ONLY) ──
// There is deliberately no "grant" counterpart to this — verified can only
// ever be set to true by a confirmed Pro payment (ozow-notify.js /
// netcash-notify.js), never by an admin action. This mode exists purely to
// correct a mistake or handle a lapsed Pro plan that check-trials.js hasn't
// caught yet. The server enforces the remove-only rule itself here — it
// does not just trust that the admin panel's UI happens to only offer a
// "Remove Verified" button.
async function handleAdminRemoveVerified(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };
  try {
    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ verified: false }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/admin-remove-verified error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-set-boost (admin only) ──
// This is the server-side twin of admSetBoost() in index.html — the exact
// same anti-corruption rule (an admin can never directly swap a listing
// from one active PAID tier to another; must cancel to None first, as a
// separate step) is re-implemented and enforced HERE, not just trusted
// from the browser. The client-side version is still useful for a fast,
// friendly error message, but it was never real security — anyone calling
// this endpoint directly with a forged request hits the same rule.
// ── shared helper: cancel a listing's Netcash subscription, if it has one ──
// Used by handleAdminSetBoost (cancelling to 'none'), handleCancelOwnBoost
// (business self-cancel), and handleAdminConfirmCancellation (below) — one
// place, so all three cancellation paths behave identically rather than
// three copies that could quietly drift apart over time.
async function cancelNetcashSubscriptionIfAny(listing) {
  if (!(listing.boost_paid_at && listing.boost_payment_ref && listing.boost_payment_ref.startsWith('NM-'))) {
    return null; // not a real Netcash subscription — nothing to cancel
  }
  try {
    const cancelRes = await fetch('https://noamark.com/api/netcash-notify?action=cancel-subscription', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ p2Reference: listing.boost_payment_ref, boostStartedAt: listing.boost_started_at, planKey: listing.boost_tier }),
    });
    const cancelResult = await cancelRes.json().catch(() => ({ ok: false }));
    if (!cancelResult.ok) {
      console.error('cancelNetcashSubscriptionIfAny: cancel did not confirm success for', listing.id, cancelResult);
      return 'Cancelled here, but stopping the recurring Netcash billing did not confirm success — please verify in your Netcash dashboard that this subscription is actually deactivated.';
    }
    return null;
  } catch (e) {
    console.error('cancelNetcashSubscriptionIfAny: threw:', e.message);
    return 'Cancelled here, but could not reach Netcash to stop the recurring billing — please verify in your Netcash dashboard that this subscription is actually deactivated.';
  }
}

async function handleAdminSetBoost(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId, newTier } = body;
  const validTiers = ['none', 'starter', 'growth', 'pro'];
  if (!listingId || !validTiers.includes(newTier)) {
    return { status: 400, json: { ok: false, reason: 'Missing or invalid listingId/newTier.' } };
  }
  try {
    const curRes = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}&select=boost_tier,boost_paid_at,boost_payment_ref,boost_started_at&limit=1`);
    const curRows = await curRes.json();
    const current = curRows[0];
    if (!current) return { status: 404, json: { ok: false, reason: 'Listing not found.' } };
    const oldTier = current.boost_tier || 'none';

    if (oldTier === newTier) return { status: 200, json: { ok: true } }; // no-op

    if (oldTier !== 'none' && newTier !== 'none') {
      // Blocked: direct swap between two active tiers — same rule as the
      // client-side confirm dialog, enforced here so it can't be bypassed.
      return { status: 400, json: { ok: false, reason: `This listing has an active ${oldTier} boost. Set it to "none" first, then set ${newTier} as a separate step.` } };
    }

    // Cancelling a REAL Netcash-billed subscription (not a manual/unpaid
    // grant, and not an Ozow payment — Netcash references always start
    // with "NM-", see netcash-notify.js) needs to stop the actual
    // recurring billing too, not just our own database record. Without
    // this, Netcash keeps auto-charging the business's card every month
    // even after the boost is cancelled here.
    const netcashCancelWarning = newTier === 'none' ? await cancelNetcashSubscriptionIfAny({ ...current, id: listingId }) : null;

    const patch = { boost_tier: newTier };
    if (newTier === 'none') {
      patch.boost_started_at = null;
    } else {
      // Granting FROM none — the legitimate manual "agreement" path.
      // Deliberately does NOT set boost_paid_at (that column is what marks
      // a REAL payment) and deliberately does NOT touch verified — Pro's
      // verified badge only ever comes from a confirmed payment webhook.
      patch.boost_started_at = new Date().toISOString();
    }

    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true, warning: netcashCancelWarning } };
  } catch (e) {
    console.error('moderate/admin-set-boost error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-grant-grace (admin only) ──
// Server-side twin of admGrantGrace() in index.html. Same trick — backdate
// boost_started_at so the existing 30-day window ends exactly N days from
// now — reused here rather than duplicated with different logic, so this
// endpoint and check-trials.js stay in agreement about how a listing's
// active window is computed.
async function handleAdminGrantGrace(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId } = body;
  let { days } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };
  days = parseInt(days, 10);
  if (!Number.isFinite(days)) days = 3;
  days = Math.max(1, Math.min(30, days));

  try {
    const DAY = 24 * 60 * 60 * 1000;
    const backdatedStart = new Date(Date.now() - (30 - days) * DAY).toISOString();
    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'approved',
        boost_tier: 'starter',
        boost_started_at: backdatedStart,
        // Deliberately NOT setting boost_paid_at — unpaid agreement grant.
      }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/admin-grant-grace error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: update-own-listing (business owner editing THEIR OWN listing) ──
// Profile fields only (name, description, contact info, hours, photos,
// etc.) — deliberately strips out every sensitive field a business should
// never be able to set on themselves, even by accident: boost/verification/
// approval status, payment record fields, and the id itself. This is the
// real fix for the listings table's wide-open UPDATE policy — once the
// frontend is switched to call this instead of writing to Supabase
// directly, that policy can be removed rather than just left open "because
// the app needs it."
const OWN_LISTING_BLOCKED_FIELDS = [
  'id', 'status', 'verified', 'boost_tier', 'boost_started_at',
  'boost_paid_at', 'boost_payment_ref', 'boost_card_token',
  'boost_card_masked', 'boost_card_expiry', 'created_at', 'trial_notice_sent',
];
async function handleUpdateOwnListing(claims, body) {
  if (claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in as a business owner.' } };
  }
  const { listingId, updates } = body;
  if (!listingId || !updates || typeof updates !== 'object') {
    return { status: 400, json: { ok: false, reason: 'Missing listingId or updates.' } };
  }
  const owns = await businessOwnsListing(claims, listingId);
  if (!owns) {
    return { status: 403, json: { ok: false, reason: 'You can only edit your own listing.' } };
  }

  const cleanUpdates = {};
  for (const key of Object.keys(updates)) {
    if (!OWN_LISTING_BLOCKED_FIELDS.includes(key)) cleanUpdates[key] = updates[key];
  }
  if (Object.keys(cleanUpdates).length === 0) {
    return { status: 400, json: { ok: false, reason: 'No editable fields in that update.' } };
  }

  try {
    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify(cleanUpdates),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/update-own-listing error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: cancel-own-boost (business, their own listing only) ──
// Self-service "Cancel My Plan" — sets boost_tier back to none AND, if
// this was a real Netcash-billed subscription, stops the actual recurring
// billing too (same cancellation call as the admin path in
// handleAdminSetBoost, just triggered by the business themselves rather
// than requiring an admin to do it on their behalf).
async function handleCancelOwnBoost(claims, body) {
  if (claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in as a business owner.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };
  const owns = await businessOwnsListing(claims, listingId);
  if (!owns) {
    return { status: 403, json: { ok: false, reason: 'You can only cancel your own plan.' } };
  }

  try {
    const curRes = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}&select=boost_tier,boost_paid_at,boost_payment_ref,boost_started_at&limit=1`);
    const curRows = await curRes.json();
    const current = curRows[0];
    if (!current || !current.boost_tier || current.boost_tier === 'none') {
      return { status: 200, json: { ok: false, reason: 'No active plan to cancel.' } };
    }

    let netcashCancelWarning = await cancelNetcashSubscriptionIfAny({ ...current, id: listingId });

    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ boost_tier: 'none', boost_started_at: null }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true, warning: netcashCancelWarning } };
  } catch (e) {
    console.error('moderate/cancel-own-boost error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── shared helper: quick admin email alert (same Resend pattern as check-trials.js) ──
async function emailAdmin(subject, message) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM || 'NoaMark <onboarding@resend.dev>';
  const to = process.env.ADMIN_EMAIL;
  if (!apiKey || !to) { console.warn('emailAdmin: RESEND_API_KEY or ADMIN_EMAIL not set — skipping alert email.'); return; }
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from, to: [to], subject,
        html: `<div style="font-family:sans-serif;font-size:15px;color:#111;line-height:1.5;"><p>${message.replace(/\n/g, '<br>')}</p></div>`,
      }),
    });
  } catch (e) {
    console.error('emailAdmin: send failed', e.message);
  }
}

// ── mode: request-cancellation (business, own listing only) ──
// Does NOT suspend anything by itself — just flags the listing and alerts
// the admin by email. Suspension only happens once an admin confirms it
// (see admin-confirm-cancellation below), on purpose: a cancellation tied
// to a refund request needs a human conversation and a manual Netcash
// action either way, so there's no benefit to going dark before that.
async function handleRequestCancellation(claims, body) {
  if (claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in as a business owner.' } };
  }
  const { listingId, reason } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };
  const owns = await businessOwnsListing(claims, listingId);
  if (!owns) {
    return { status: 403, json: { ok: false, reason: 'You can only request cancellation for your own listing.' } };
  }

  try {
    const listRes = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}&select=name,boost_tier&limit=1`);
    const listRows = await listRes.json();
    const listing = listRows[0];

    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        cancellation_requested: true,
        cancellation_requested_at: new Date().toISOString(),
        cancellation_reason: (reason || '').slice(0, 1000) || null,
      }),
    });
    if (!res.ok) throw new Error(await res.text());

    await emailAdmin(
      `Cancellation requested: ${listing ? listing.name : listingId}`,
      `${listing ? listing.name : 'A business'} (${listing ? listing.boost_tier || 'no plan' : ''}) has requested cancellation${reason ? ' and refund' : ''}.\n\n` +
      (reason ? `Reason given: ${reason}\n\n` : '') +
      `Review and confirm in your admin panel — Businesses tab — before this listing is suspended. Confirming stops any future billing but does NOT process a refund; that's still a manual step in your Netcash dashboard.`
    );

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/request-cancellation error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-confirm-cancellation (admin only) ──
// Suspends the listing (soft — nothing deleted, same as check-trials.js's
// own suspend path) and, if it was on a real Netcash subscription, stops
// that too, reusing the exact same helper as every other cancel path.
async function handleAdminConfirmCancellation(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const curRes = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}&select=boost_tier,boost_paid_at,boost_payment_ref,boost_started_at&limit=1`);
    const curRows = await curRes.json();
    const current = curRows[0];
    if (!current) return { status: 404, json: { ok: false, reason: 'Listing not found.' } };

    const netcashCancelWarning = current.boost_tier && current.boost_tier !== 'none'
      ? await cancelNetcashSubscriptionIfAny({ ...current, id: listingId })
      : null;

    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'suspended',
        boost_tier: 'none',
        boost_started_at: null,
        cancellation_requested: false,
      }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true, warning: netcashCancelWarning } };
  } catch (e) {
    console.error('moderate/admin-confirm-cancellation error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-dismiss-cancellation (admin only) ──
// Clears the request without touching the listing — for when the admin
// resolves it another way (talked to the business, they changed their mind).
async function handleAdminDismissCancellation(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };
  try {
    const res = await supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ cancellation_requested: false }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/admin-dismiss-cancellation error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: update-own-profile (business or subscriber, own account only) ──
// Name/owner/email only — never password (that already has its own
// server-verified path via mode:'change-password' in auth.js) and never
// role/plan (admin-only, see below). Looks the caller's row up by their
// OWN token id, not by an email the client sends, so there's no way to
// point this at a different account.
const OWN_PROFILE_ALLOWED_FIELDS = ['name', 'owner', 'email'];
async function handleUpdateOwnProfile(claims, body) {
  if (claims.role !== 'business' && claims.role !== 'subscriber') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { updates } = body;
  if (!updates || typeof updates !== 'object') {
    return { status: 400, json: { ok: false, reason: 'Missing updates.' } };
  }
  const cleanUpdates = {};
  for (const key of Object.keys(updates)) {
    if (OWN_PROFILE_ALLOWED_FIELDS.includes(key)) cleanUpdates[key] = updates[key];
  }
  if (Object.keys(cleanUpdates).length === 0) {
    return { status: 400, json: { ok: false, reason: 'No editable fields in that update.' } };
  }
  // If the email is changing, make sure no OTHER account already has it —
  // same check the client used to do, now enforced server-side too.
  if (cleanUpdates.email) {
    const clashRes = await supaFetch(`users?email=ilike.${encodeURIComponent(cleanUpdates.email)}&select=id&limit=1`);
    const clashRows = await clashRes.json();
    if (clashRows[0] && String(clashRows[0].id) !== String(claims.id)) {
      return { status: 200, json: { ok: false, reason: 'That email is already used by another account.' } };
    }
  }
  try {
    const res = await supaFetch(`users?id=eq.${encodeURIComponent(claims.id)}`, {
      method: 'PATCH',
      body: JSON.stringify(cleanUpdates),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/update-own-profile error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-set-role (admin only) ──
async function handleAdminSetRole(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { userId, role } = body;
  const validRoles = ['business', 'subscriber', 'guest'];
  if (!userId || !validRoles.includes(role)) {
    return { status: 400, json: { ok: false, reason: 'Missing or invalid userId/role.' } };
  }
  try {
    const res = await supaFetch(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/admin-set-role error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: admin-set-plan (admin only) ──
// Used when approving/actioning a subscription_requests row — sets the
// subscriber's plan directly.
async function handleAdminSetPlan(claims, body) {
  if (claims.role !== 'admin') {
    return { status: 401, json: { ok: false, reason: 'Admin login required.' } };
  }
  const { userId, plan } = body;
  if (!userId || typeof plan !== 'string' || !plan) {
    return { status: 400, json: { ok: false, reason: 'Missing userId or plan.' } };
  }
  try {
    const res = await supaFetch(`users?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ plan }),
    });
    if (!res.ok) throw new Error(await res.text());
    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/admin-set-plan error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── shared helper: does this business (or admin) own the given listing? ──
// PERFORMANCE NOTE: these two lookups don't depend on each other — who the
// token belongs to, and who the listing belongs to — so they run in
// parallel instead of one-after-another. Same security checks, one fewer
// sequential round-trip on every guarded call.
async function businessOwnsListing(claims, listingId) {
  if (claims.role === 'admin') return true;
  if (claims.role !== 'business') return false;

  const [bizRes, listingRes] = await Promise.all([
    supaFetch(`users?id=eq.${encodeURIComponent(claims.id)}&select=email&limit=1`),
    supaFetch(`listings?id=eq.${encodeURIComponent(listingId)}&select=id,email,owner_email&limit=1`),
  ]);
  const bizRows = await bizRes.json();
  const businessEmail = bizRows[0]?.email || '';
  if (!businessEmail) return false;

  const listingRows = await listingRes.json();
  const listing = listingRows[0];
  if (!listing) return false;

  return (
    (listing.email || '').toLowerCase() === businessEmail.toLowerCase() ||
    (listing.owner_email || '').toLowerCase() === businessEmail.toLowerCase()
  );
}

// Looks up an enquiry and confirms the calling business owns the listing
// it belongs to. Returns { enquiry } on success or { error } on failure,
// so callers can just `if (error) return error;`.
async function getOwnedEnquiry(claims, enquiryId) {
  const enqRes = await supaFetch(`enquiries?id=eq.${encodeURIComponent(enquiryId)}&select=id,listing_id&limit=1`);
  const enqRows = await enqRes.json();
  const enquiry = enqRows[0];
  if (!enquiry) return { error: { status: 404, json: { ok: false, reason: 'Enquiry not found.' } } };

  const owns = await businessOwnsListing(claims, enquiry.listing_id);
  if (!owns) return { error: { status: 403, json: { ok: false, reason: 'You can only manage enquiries on your own listing.' } } };

  return { enquiry };
}

// ── mode: list-enquiries (admin, or business who owns the listing) ──
async function handleListEnquiries(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const owns = await businessOwnsListing(claims, listingId);
    if (!owns) return { status: 403, json: { ok: false, reason: 'You can only view enquiries on your own listing.' } };

    const res = await supaFetch(`enquiries?listing_id=eq.${encodeURIComponent(listingId)}&select=*&order=created_at.desc`);
    if (!res.ok) throw new Error(await res.text());
    const enquiries = await res.json();

    return { status: 200, json: { ok: true, enquiries } };
  } catch (e) {
    console.error('moderate/list-enquiries error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: reply-enquiry (admin, or business who owns the listing) ──
async function handleReplyEnquiry(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { enquiryId, replyText, smsSent, emailSent } = body;
  if (!enquiryId || !replyText) return { status: 400, json: { ok: false, reason: 'Missing enquiryId or replyText' } };

  try {
    const { error } = await getOwnedEnquiry(claims, enquiryId);
    if (error) return error;

    const upd = await supaFetch(`enquiries?id=eq.${encodeURIComponent(enquiryId)}`, {
      method: 'PATCH',
      prefer: 'return=minimal',
      body: JSON.stringify({ replied: true, reply: replyText, reply_sms_sent: !!smsSent, reply_email_sent: !!emailSent }),
    });
    if (!upd.ok) throw new Error(await upd.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/reply-enquiry error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: delete-enquiry (admin, or business who owns the listing) ──
async function handleDeleteEnquiry(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { enquiryId } = body;
  if (!enquiryId) return { status: 400, json: { ok: false, reason: 'Missing enquiryId' } };

  try {
    const { error } = await getOwnedEnquiry(claims, enquiryId);
    if (error) return error;

    const del = await supaFetch(`enquiries?id=eq.${encodeURIComponent(enquiryId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!del.ok) throw new Error(await del.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-enquiry error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// Looks up a booking and confirms the calling business owns the listing
// it belongs to. Returns { booking } on success or { error } on failure.
async function getOwnedBooking(claims, bookingId) {
  const bkRes = await supaFetch(
    `bookings?id=eq.${encodeURIComponent(bookingId)}&select=id,listing_id,customer_name,customer_phone,customer_email,booking_type,booking_date,booking_time,service&limit=1`
  );
  const bkRows = await bkRes.json();
  const booking = bkRows[0];
  if (!booking) return { error: { status: 404, json: { ok: false, reason: 'Booking not found.' } } };

  const owns = await businessOwnsListing(claims, booking.listing_id);
  if (!owns) return { error: { status: 403, json: { ok: false, reason: 'You can only manage bookings on your own listing.' } } };

  return { booking };
}

// ── mode: list-bookings (admin, or business who owns the listing) ──
async function handleListBookings(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const owns = await businessOwnsListing(claims, listingId);
    if (!owns) return { status: 403, json: { ok: false, reason: 'You can only view bookings on your own listing.' } };

    const res = await supaFetch(`bookings?listing_id=eq.${encodeURIComponent(listingId)}&select=*&order=created_at.desc`);
    if (!res.ok) throw new Error(await res.text());
    const bookings = await res.json();

    return { status: 200, json: { ok: true, bookings } };
  } catch (e) {
    console.error('moderate/list-bookings error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: update-booking-status (admin, or business who owns the listing) ──
// Used for Accept/Decline. Returns the customer's contact details so the
// browser can send the SMS/email notification through the existing
// nmSendSMS/nmSendEmail endpoints — this endpoint only touches the DB.
async function handleUpdateBookingStatus(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { bookingId, status } = body;
  const allowedStatuses = ['confirmed', 'declined', 'completed'];
  if (!bookingId || !allowedStatuses.includes(status)) {
    return { status: 400, json: { ok: false, reason: 'Missing bookingId or invalid status' } };
  }

  try {
    const { booking, error } = await getOwnedBooking(claims, bookingId);
    if (error) return error;

    const upd = await supaFetch(`bookings?id=eq.${encodeURIComponent(bookingId)}`, {
      method: 'PATCH',
      prefer: 'return=minimal',
      body: JSON.stringify({ status, updated_at: new Date().toISOString() }),
    });
    if (!upd.ok) throw new Error(await upd.text());

    return { status: 200, json: { ok: true, booking } };
  } catch (e) {
    console.error('moderate/update-booking-status error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: reschedule-booking (admin, or business who owns the listing) ──
async function handleRescheduleBooking(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { bookingId, newDate, newTime } = body;
  if (!bookingId || !newDate || !newTime) {
    return { status: 400, json: { ok: false, reason: 'Missing bookingId, newDate, or newTime' } };
  }

  try {
    const { booking, error } = await getOwnedBooking(claims, bookingId);
    if (error) return error;

    const upd = await supaFetch(`bookings?id=eq.${encodeURIComponent(bookingId)}`, {
      method: 'PATCH',
      prefer: 'return=minimal',
      body: JSON.stringify({ status: 'rescheduled', booking_date: newDate, booking_time: newTime, updated_at: new Date().toISOString() }),
    });
    if (!upd.ok) throw new Error(await upd.text());

    return { status: 200, json: { ok: true, booking } };
  } catch (e) {
    console.error('moderate/reschedule-booking error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: save-availability (admin, or business who owns the listing) ──
// Availability READS stay public (customers need to see hours to book),
// only the WRITE path needs guarding — this handles both the first-time
// insert and later updates as a single upsert.
async function handleSaveAvailability(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { listingId, day_0, day_1, day_2, day_3, day_4, day_5, day_6, open_time, close_time } = body;
  if (!listingId || !open_time || !close_time) {
    return { status: 400, json: { ok: false, reason: 'Missing listingId, open_time, or close_time' } };
  }

  try {
    const owns = await businessOwnsListing(claims, listingId);
    if (!owns) return { status: 403, json: { ok: false, reason: 'You can only update availability on your own listing.' } };

    const payload = {
      listing_id: listingId,
      day_0: !!day_0, day_1: !!day_1, day_2: !!day_2, day_3: !!day_3,
      day_4: !!day_4, day_5: !!day_5, day_6: !!day_6,
      open_time, close_time,
      updated_at: new Date().toISOString(),
    };

    const existingRes = await supaFetch(`business_availability?listing_id=eq.${encodeURIComponent(listingId)}&select=id&limit=1`);
    const existingRows = await existingRes.json();
    const row = existingRows[0];

    if (row) {
      const upd = await supaFetch(`business_availability?id=eq.${encodeURIComponent(row.id)}`, {
        method: 'PATCH', prefer: 'return=minimal', body: JSON.stringify(payload),
      });
      if (!upd.ok) throw new Error(await upd.text());
    } else {
      const ins = await supaFetch(`business_availability`, {
        method: 'POST', prefer: 'return=minimal', body: JSON.stringify(payload),
      });
      if (!ins.ok) throw new Error(await ins.text());
    }

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/save-availability error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// Looks up a notification and confirms the calling business owns the
// listing it belongs to. Returns { notif } on success or { error }.
async function getOwnedNotification(claims, notifId) {
  const res = await supaFetch(`notifications?id=eq.${encodeURIComponent(notifId)}&select=id,listing_id&limit=1`);
  const rows = await res.json();
  const notif = rows[0];
  if (!notif) return { error: { status: 404, json: { ok: false, reason: 'Notification not found.' } } };

  const owns = await businessOwnsListing(claims, notif.listing_id);
  if (!owns) return { error: { status: 403, json: { ok: false, reason: 'You can only manage notifications on your own listing.' } } };

  return { notif };
}

// ── mode: list-notifications (admin, or business who owns the listing) ──
async function handleListNotifications(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const owns = await businessOwnsListing(claims, listingId);
    if (!owns) return { status: 403, json: { ok: false, reason: 'You can only view notifications on your own listing.' } };

    const res = await supaFetch(`notifications?listing_id=eq.${encodeURIComponent(listingId)}&select=*&order=created_at.desc&limit=30`);
    if (!res.ok) throw new Error(await res.text());
    const notifications = await res.json();

    return { status: 200, json: { ok: true, notifications } };
  } catch (e) {
    console.error('moderate/list-notifications error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: notif-unread-count (admin, or business who owns the listing) ──
// Lightweight — powers just the bell badge, not the full panel.
async function handleNotifUnreadCount(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const owns = await businessOwnsListing(claims, listingId);
    if (!owns) return { status: 403, json: { ok: false, reason: 'You can only view notifications on your own listing.' } };

    const res = await supaFetch(`notifications?listing_id=eq.${encodeURIComponent(listingId)}&read=eq.false&select=id`);
    if (!res.ok) throw new Error(await res.text());
    const rows = await res.json();

    return { status: 200, json: { ok: true, count: rows.length } };
  } catch (e) {
    console.error('moderate/notif-unread-count error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: mark-notif-read (admin, or business who owns the listing) ──
async function handleMarkNotifRead(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { notifId } = body;
  if (!notifId) return { status: 400, json: { ok: false, reason: 'Missing notifId' } };

  try {
    const { error } = await getOwnedNotification(claims, notifId);
    if (error) return error;

    const upd = await supaFetch(`notifications?id=eq.${encodeURIComponent(notifId)}`, {
      method: 'PATCH', prefer: 'return=minimal', body: JSON.stringify({ read: true }),
    });
    if (!upd.ok) throw new Error(await upd.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/mark-notif-read error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: mark-all-notif-read (admin, or business who owns the listing) ──
async function handleMarkAllNotifRead(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { listingId } = body;
  if (!listingId) return { status: 400, json: { ok: false, reason: 'Missing listingId' } };

  try {
    const owns = await businessOwnsListing(claims, listingId);
    if (!owns) return { status: 403, json: { ok: false, reason: 'You can only manage notifications on your own listing.' } };

    const upd = await supaFetch(
      `notifications?listing_id=eq.${encodeURIComponent(listingId)}&read=eq.false`,
      { method: 'PATCH', prefer: 'return=minimal', body: JSON.stringify({ read: true }) }
    );
    if (!upd.ok) throw new Error(await upd.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/mark-all-notif-read error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── mode: delete-review (admin, or business who owns the listing) ──
async function handleDeleteReview(claims, body) {
  if (claims.role !== 'admin' && claims.role !== 'business') {
    return { status: 401, json: { ok: false, reason: 'Please log in again.' } };
  }
  const { reviewId } = body;
  if (!reviewId) return { status: 400, json: { ok: false, reason: 'Missing reviewId' } };

  try {
    const revRes = await supaFetch(`reviews?id=eq.${encodeURIComponent(reviewId)}&select=id,listing_id&limit=1`);
    const revRows = await revRes.json();
    const review = revRows[0];
    if (!review) return { status: 404, json: { ok: false, reason: 'Review not found.' } };

    if (claims.role === 'business') {
      const owns = await businessOwnsListing(claims, review.listing_id);
      if (!owns) {
        return { status: 403, json: { ok: false, reason: 'You can only delete reviews on your own listing.' } };
      }
    }

    const delRes = await supaFetch(`reviews?id=eq.${encodeURIComponent(reviewId)}`, { method: 'DELETE', prefer: 'return=minimal' });
    if (!delRes.ok) throw new Error(await delRes.text());

    return { status: 200, json: { ok: true } };
  } catch (e) {
    console.error('moderate/delete-review error:', e.message);
    return { status: 500, json: { ok: false, reason: e.message } };
  }
}

// ── entry point ──

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

  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const claims = verifySessionToken(token);
  if (!claims) {
    return res.status(401).json({ ok: false, reason: 'Please log in again.' });
  }

  const body = req.body || {};
  const mode = body.mode;

  try {
    let result;
    if (mode === 'delete-listing') result = await handleDeleteListing(claims, body);
    else if (mode === 'delete-user') result = await handleDeleteUser(claims, body);
    else if (mode === 'delete-own-account') result = await handleDeleteOwnAccount(claims, body);
    else if (mode === 'delete-review') result = await handleDeleteReview(claims, body);
    else if (mode === 'admin-set-status') result = await handleAdminSetStatus(claims, body);
    else if (mode === 'admin-remove-verified') result = await handleAdminRemoveVerified(claims, body);
    else if (mode === 'admin-set-boost') result = await handleAdminSetBoost(claims, body);
    else if (mode === 'admin-grant-grace') result = await handleAdminGrantGrace(claims, body);
    else if (mode === 'update-own-listing') result = await handleUpdateOwnListing(claims, body);
    else if (mode === 'cancel-own-boost') result = await handleCancelOwnBoost(claims, body);
    else if (mode === 'request-cancellation') result = await handleRequestCancellation(claims, body);
    else if (mode === 'admin-confirm-cancellation') result = await handleAdminConfirmCancellation(claims, body);
    else if (mode === 'admin-dismiss-cancellation') result = await handleAdminDismissCancellation(claims, body);
    else if (mode === 'update-own-profile') result = await handleUpdateOwnProfile(claims, body);
    else if (mode === 'admin-set-role') result = await handleAdminSetRole(claims, body);
    else if (mode === 'admin-set-plan') result = await handleAdminSetPlan(claims, body);
    else if (mode === 'list-enquiries') result = await handleListEnquiries(claims, body);
    else if (mode === 'reply-enquiry') result = await handleReplyEnquiry(claims, body);
    else if (mode === 'delete-enquiry') result = await handleDeleteEnquiry(claims, body);
    else if (mode === 'list-bookings') result = await handleListBookings(claims, body);
    else if (mode === 'update-booking-status') result = await handleUpdateBookingStatus(claims, body);
    else if (mode === 'reschedule-booking') result = await handleRescheduleBooking(claims, body);
    else if (mode === 'save-availability') result = await handleSaveAvailability(claims, body);
    else if (mode === 'list-notifications') result = await handleListNotifications(claims, body);
    else if (mode === 'notif-unread-count') result = await handleNotifUnreadCount(claims, body);
    else if (mode === 'mark-notif-read') result = await handleMarkNotifRead(claims, body);
    else if (mode === 'mark-all-notif-read') result = await handleMarkAllNotifRead(claims, body);
    else result = { status: 400, json: { ok: false, reason: 'Unknown or missing mode' } };

    return res.status(result.status).json(result.json);
  } catch (e) {
    console.error('moderate.js error:', e);
    return res.status(500).json({ ok: false, reason: 'Server error — please try again.' });
  }
}
