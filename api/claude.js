// /api/claude.js
//
// AI proxy for the NoaMark business portal.
//
// IMPORTANT: despite the filename (and despite the client sending
// model: "claude-sonnet-4-6"), this endpoint has always called Google
// Gemini, not Anthropic's Claude — that field from the client is simply
// ignored below, exactly as it was in the previous version of this file.
// Nothing about the AI provider is changing here; only the safety layer
// around it.
//
// SECURITY FIX (Aug 2026): rate limiting previously trusted a `userId`
// the CLIENT sent in the request body — nothing verified it belonged to
// the caller. Anyone could rotate a fake userId on every request to dodge
// the per-user cap entirely (the per-IP cap was the only real backstop).
// This version verifies the SAME signed session token used everywhere
// else in the app (auth.js/moderate.js) — a real logged-in business or
// subscriber now gets rate-limited against their actual account, which
// can't be spoofed without the signing secret. Anyone without a valid
// token (guests, or a forged/expired one) falls back to IP-only limiting
// instead of being trusted on their word.
//
// Adds on top of the previous version:
//   1. Rate limiting     — per verified user AND per IP, via Supabase.
//   2. Daily token caps  — per verified user, rolling 24h, via Supabase.
//   3. Token streaming   — re-emits Gemini's stream as a simple
//                          { text: "..." } SSE format so the client
//                          doesn't need to know which provider is behind it.
//   4. Audit logging     — every call (success or failure) is written to
//                          Supabase with real token counts from Gemini's
//                          usageMetadata.
//
// ── Setup ──
// Environment variables already set (unchanged): GEMINI_API_KEY (or Gemini_API_Key)
// Environment variables needed (same ones auth.js/moderate.js already use):
//   SUPABASE_URL           - same project the rest of the app already uses
//   SUPABASE_SERVICE_KEY   - Supabase SERVICE ROLE key (server-only — do not
//                            reuse the public anon key, do not expose to client)
//   ADMIN_SESSION_SECRET    - same secret auth.js signs session tokens with
//
// Database: run api/ai_usage_log.sql once in the Supabase SQL editor before deploying.

import crypto from 'crypto';

const RATE_LIMIT_WINDOW_MS = 60 * 1000;     // 1 minute
const USER_RATE_LIMIT = 6;                  // max AI calls per verified user per minute
const IP_RATE_LIMIT = 20;                   // looser cap per IP — covers guests/shared devices
const DAILY_TOKEN_CAP = 40000;              // max total tokens per verified user per rolling 24h
const MAX_OUTPUT_TOKENS_CEILING = 1000;     // hard ceiling regardless of what the client requests
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash'; // unchanged default

// Same verification as auth.js/moderate.js — duplicated here rather than
// imported, matching how this project is already split across separate
// serverless files (see the top-of-file note in moderate.js on why).
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

async function supaFetch(path, opts = {}) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  return fetch(`${base}/rest/v1/${path}`, {
    ...opts,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Prefer: opts.prefer || 'return=minimal',
      ...(opts.headers || {})
    }
  });
}

async function checkLimits(trustedKey, isVerifiedUser, ip) {
  const since1min = new Date(Date.now() - RATE_LIMIT_WINDOW_MS).toISOString();
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  try {
    // Per-user limit only applies when we have a REAL verified identity —
    // an unverified caller (guest, or a forged token) has no trusted key
    // to check this against, so they rely on the per-IP limit below only.
    if (isVerifiedUser) {
      const userRecentRes = await supaFetch(
        `ai_usage_log?user_id=eq.${encodeURIComponent(trustedKey)}&created_at=gte.${since1min}&select=id`
      );
      const userRecent = userRecentRes.ok ? await userRecentRes.json() : [];
      if (userRecent.length >= USER_RATE_LIMIT) {
        return { blocked: true, status: 429, error: "You're sending requests too quickly. Please wait a minute and try again." };
      }

      const dailyRes = await supaFetch(
        `ai_usage_log?user_id=eq.${encodeURIComponent(trustedKey)}&created_at=gte.${since24h}&select=total_tokens`
      );
      const daily = dailyRes.ok ? await dailyRes.json() : [];
      const usedToday = daily.reduce((sum, r) => sum + (r.total_tokens || 0), 0);
      if (usedToday >= DAILY_TOKEN_CAP) {
        return { blocked: true, status: 429, error: "You've reached today's AI usage limit. It resets automatically — try again tomorrow, or contact support@noamark.com if you need more." };
      }
    }

    if (ip) {
      const ipRecentRes = await supaFetch(
        `ai_usage_log?ip=eq.${encodeURIComponent(ip)}&created_at=gte.${since1min}&select=id`
      );
      const ipRecent = ipRecentRes.ok ? await ipRecentRes.json() : [];
      if (ipRecent.length >= IP_RATE_LIMIT) {
        return { blocked: true, status: 429, error: 'Too many AI requests from this network right now. Please try again shortly.' };
      }
    }
  } catch (e) {
    // If Supabase is down, fail OPEN on limits (don't take the feature down),
    // but this is exactly the kind of event that should show up in Vercel logs.
    console.error('Rate-limit check failed, failing open:', e);
  }

  return { blocked: false };
}

async function logUsage({ trustedKey, ip, model, inputTokens, outputTokens, success, error }) {
  try {
    await supaFetch('ai_usage_log', {
      method: 'POST',
      body: JSON.stringify({
        user_id: trustedKey,
        ip,
        model,
        input_tokens: inputTokens || 0,
        output_tokens: outputTokens || 0,
        total_tokens: (inputTokens || 0) + (outputTokens || 0),
        success,
        error: error || null
      })
    });
  } catch (e) {
    console.error('Audit log write failed:', e);
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const apiKey = process.env.GEMINI_API_KEY || process.env.Gemini_API_Key;
  if (!apiKey) {
    return res.status(500).json({ error: 'API key not configured on server.' });
  }

  const { messages, max_tokens } = req.body || {};
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();

  // Verify the caller's actual identity from their session token — never
  // trust a userId the client claims in the request body. A real
  // logged-in business/subscriber gets rate-limited against their real
  // account (claims.id); anyone without a valid token falls back to
  // IP-only limiting in checkLimits() above.
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  const claims = verifySessionToken(token);
  const isVerifiedUser = !!(claims && claims.id);
  const trustedKey = isVerifiedUser ? String(claims.id) : (ip ? `ip:${ip}` : 'anon');

  if (!Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'No message provided.' });
  }

  const limitCheck = await checkLimits(trustedKey, isVerifiedUser, ip);
  if (limitCheck.blocked) {
    return res.status(limitCheck.status).json({ error: limitCheck.error });
  }

  const geminiBody = {
    contents: messages.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }]
    })),
    generationConfig: {
      maxOutputTokens: Math.min(max_tokens || 500, MAX_OUTPUT_TOKENS_CEILING)
    }
  };

  const geminiUrl =
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:streamGenerateContent?alt=sse&key=${apiKey}`;

  let geminiRes;
  try {
    geminiRes = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(geminiBody)
    });
  } catch (e) {
    console.error('Gemini proxy network error:', e);
    await logUsage({ trustedKey, ip, model: GEMINI_MODEL, success: false, error: 'network_error_calling_gemini' });
    return res.status(502).json({ error: 'Could not reach the AI service. Please try again shortly.' });
  }

  if (!geminiRes.ok) {
    let detail = '';
    try { detail = (await geminiRes.json())?.error?.message || ''; } catch (_) { /* ignore */ }
    console.error('Gemini proxy error:', geminiRes.status, detail);
    await logUsage({ trustedKey, ip, model: GEMINI_MODEL, success: false, error: `gemini_${geminiRes.status}: ${detail}` });
    if (geminiRes.status === 429) {
      return res.status(429).json({ error: 'The AI provider is temporarily rate-limited. Please try again in a moment.' });
    }
    return res.status(502).json({ error: 'Failed to reach AI service.' });
  }

  // Re-emit as a simple, provider-agnostic SSE stream: one { text: "..." } chunk at a time.
  // This keeps the frontend decoupled from whichever AI provider is behind this endpoint.
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive'
  });

  let inputTokens = 0, outputTokens = 0, streamError = null, fullText = '';
  const decoder = new TextDecoder();
  const reader = geminiRes.body.getReader();
  let buf = '';

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        const payload = line.slice(5).trim();
        if (!payload) continue;
        try {
          const chunk = JSON.parse(payload);
          const piece = chunk?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (piece) {
            fullText += piece;
            res.write(`data: ${JSON.stringify({ text: piece })}\n\n`);
          }
          if (chunk?.usageMetadata) {
            inputTokens = chunk.usageMetadata.promptTokenCount || inputTokens;
            outputTokens = chunk.usageMetadata.candidatesTokenCount || outputTokens;
          }
        } catch (_) { /* partial/invalid JSON fragment, ignore */ }
      }
    }
    if (!fullText) {
      // Matches the old behaviour's "No response." fallback, just streamed instead of returned in one shot.
      res.write(`data: ${JSON.stringify({ text: 'No response.' })}\n\n`);
    }
  } catch (e) {
    streamError = 'stream_interrupted';
  } finally {
    res.write('data: [DONE]\n\n');
    res.end();
    await logUsage({
      trustedKey, ip, model: GEMINI_MODEL,
      inputTokens, outputTokens,
      success: !streamError,
      error: streamError
    });
  }
}
