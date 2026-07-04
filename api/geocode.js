// /api/geocode.js
//
// Turns a free-text South African business address into latitude/longitude
// coordinates using OpenStreetMap's free Nominatim geocoding service.
//
// Called from the "Add/Edit Business" form on submit — never blocks the
// listing from saving if geocoding fails (see index.html's try/catch).
//
// Nominatim usage policy: max 1 request/sec, must send an identifying
// User-Agent. This function is only called once per listing submission
// (not in a loop), so it naturally stays well within that limit.
// Docs: https://operations.osmfoundation.org/policies/nominatim/

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { address, area, city, province } = req.body || {};

    if (![address, area, city, province].some(Boolean)) {
      return res.status(400).json({ error: 'Not enough address information to geocode' });
    }

    async function tryQuery(parts) {
      const query = parts.filter(Boolean).join(', ');
      if (!query) return null;
      const url = `https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=za&q=${encodeURIComponent(query)}`;
      const response = await fetch(url, {
        headers: {
          // Nominatim requires a real identifying User-Agent — replace the
          // contact email below if support@ ever changes.
          'User-Agent': 'NoaMark/1.0 (support@noamark.com)',
        },
      });
      if (!response.ok) return null;
      const results = await response.json();
      if (!Array.isArray(results) || results.length === 0) return null;
      return { latitude: parseFloat(results[0].lat), longitude: parseFloat(results[0].lon) };
    }

    // Try the full address first (most precise), then fall back to
    // progressively broader queries — many South African townships and
    // villages aren't mapped at street level, but the area/town usually is.
    // Approximate beats nothing for "Near Me Now" purposes.
    let result = await tryQuery([address, area, city, province, 'South Africa']);
    if (!result) result = await tryQuery([area, city, province, 'South Africa']);
    if (!result) result = await tryQuery([city, province, 'South Africa']);

    if (!result) {
      // Not an error — the address just couldn't be matched at any level.
      // The listing will save without coordinates and can be re-geocoded later.
      return res.status(200).json({ latitude: null, longitude: null, matched: false });
    }

    return res.status(200).json({
      latitude: result.latitude,
      longitude: result.longitude,
      matched: true,
    });
  } catch (err) {
    console.error('Geocode error:', err);
    return res.status(500).json({ error: 'Geocoding failed' });
  }
}
