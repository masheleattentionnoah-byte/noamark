// api/netcash-notify.js
//
// ONE file handling BOTH jobs, to keep the repo file count down:
//
//   1. POST /api/netcash-notify?action=init
//      → called by your frontend when a customer clicks Upgrade.
//        Builds the locked Pay Now fields.
//
//   2. POST /api/netcash-notify   (no query string)
//      → called by Netcash itself, server-to-server, after a
//        transaction settles. This is the exact URL already saved in
//        your Netcash dashboard (Account profile > Service profiles >
//        NetConnector > Pay Now > Payment notifications > Notify URL),
//        so this filename/path must not change.
//
// IMPORTANT for the notify half: the incoming field names below
// (TransactionAccepted, Reference, etc.) are my best-confirmed mapping
// from the Netcash docs, but not yet confirmed against a real payload
// from your account. After deploying:
//   1. Run one test payment (test card 4000000000000002, any future
//      MM/YY, CVV 123).
//   2. Check Vercel logs for the line "[netcash-notify] raw payload:".
//   3. If any field names don't match, send me that log and I'll fix
//      the mapping in the same reply.
// A wrong field name here fails silently — Netcash gets its 200 and
// stops retrying, but the customer's boost never activates.

import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const DEFAULT_VENDOR_KEY = '24ade73c-98cf-47b3-99be-cc7b867b3080';

const PLAN_PRICES = {
  starter: 49.99,
  growth: 219.99,
  pro: 299.99,
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, reason: 'Method not allowed' });
  }

  const isInit = req.query && req.query.action === 'init';

  if (isInit) {
    return handleInit(req, res);
  }
  return handleNotify(req, res);
}

// ---------------------------------------------------------------------
// JOB 1: build the locked Pay Now form fields for the frontend redirect
// ---------------------------------------------------------------------
async function handleInit(req, res) {
  try {
    // Matches the shape /api/ozow-initiate already accepts, so the two
    // gateways can sit side by side without diverging conventions.
    const { planKey, listingId, email, name } = req.body || {};

    if (!planKey || !PLAN_PRICES[planKey]) {
      return res.status(400).json({ ok: false, reason: 'Invalid or missing plan' });
    }
    if (!listingId) {
      return res.status(400).json({ ok: false, reason: 'Missing listingId' });
    }

    const amount = PLAN_PRICES[planKey]; // locked server-side, never from the client
    const reference = `NM-${listingId}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;

    const { error: insertError } = await supabase.from('boost_payments').insert({
      reference,
      listing_id: listingId,
      plan: planKey,
      amount,
      status: 'pending',
      gateway: 'netcash',
      created_at: new Date().toISOString(),
    });

    if (insertError) {
      console.error('[netcash-notify:init] Failed to record pending payment:', insertError);
      return res.status(500).json({ ok: false, reason: 'Could not create payment record' });
    }

    const fields = {
      m1: process.env.NETCASH_SERVICE_KEY,
      m2: DEFAULT_VENDOR_KEY,
      p2: reference,
      p3: `NoaMark ${planKey.charAt(0).toUpperCase() + planKey.slice(1)} Boost`,
      p4: amount.toFixed(2),
      Budget: 'Y',
    };

    if (email) fields.m9 = email;
    fields.m10 = name || '';
    fields.m4 = listingId;

    return res.status(200).json({
      ok: true,
      reference,
      postUrl: 'https://paynow.netcash.co.za/site/paynow.aspx',
      fields,
    });
  } catch (err) {
    console.error('[netcash-notify:init] error:', err);
    return res.status(500).json({ ok: false, reason: 'Internal error' });
  }
}

// ---------------------------------------------------------------------
// JOB 2: receive Netcash's server-to-server settlement notification
// ---------------------------------------------------------------------
async function handleNotify(req, res) {
  const body = req.body || {};
  console.log('[netcash-notify] raw payload:', JSON.stringify(body));

  // --- Best-guess field mapping, to be confirmed against a real payload ---
  const reference = body.Reference || body.reference || body.p2;
  const amountPaid = parseFloat(body.Amount || body.amount || body.p4 || '0');
  const accepted =
    body.TransactionAccepted === 'true' ||
    body.TransactionAccepted === true ||
    body.Accepted === '1' ||
    body.transactionAccepted === true;
  const reasonCode = body.Reason || body.reason || body.ReasonCode || null;
  const extra1 = body.Extra1 || body.m4 || null;
  // -------------------------------------------------------------------

  if (!reference) {
    console.error('[netcash-notify] No reference found in payload — cannot process.');
    return res.status(200).send('OK');
  }

  try {
    const { data: payment, error: fetchError } = await supabase
      .from('boost_payments')
      .select('*')
      .eq('reference', reference)
      .single();

    if (fetchError || !payment) {
      console.error('[netcash-notify] No matching payment for reference:', reference);
      return res.status(200).send('OK');
    }

    if (payment.status === 'paid') {
      return res.status(200).send('OK');
    }

    const amountMatches = Math.abs(amountPaid - parseFloat(payment.amount)) < 0.01;

    if (!accepted || !amountMatches) {
      await supabase
        .from('boost_payments')
        .update({
          status: 'failed',
          reason: reasonCode || 'Not accepted or amount mismatch',
          updated_at: new Date().toISOString(),
        })
        .eq('reference', reference);

      console.warn('[netcash-notify] Payment not accepted or amount mismatch:', {
        reference, amountPaid, expected: payment.amount, accepted,
      });
      return res.status(200).send('OK');
    }

    await supabase
      .from('boost_payments')
      .update({ status: 'paid', paid_at: new Date().toISOString() })
      .eq('reference', reference);

    await supabase
      .from('listings')
      .update({
        boost_plan: payment.plan,
        boost_active: true,
        boost_activated_at: new Date().toISOString(),
      })
      .eq('id', payment.listing_id || extra1);

    console.log('[netcash-notify] Activated boost for listing:', payment.listing_id, payment.plan);
    return res.status(200).send('OK');
  } catch (err) {
    console.error('[netcash-notify] Unexpected error:', err);
    return res.status(200).send('OK');
  }
}
