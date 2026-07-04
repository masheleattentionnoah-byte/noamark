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

    const parts = [address, area, city, province, 'South Africa'].filter(Boolean);
    if (parts.length < 2) {
      return res.status(400).json({ error: 'Not enough address information to geocode' });
    }
    const query = parts.join(', ');

    const url = `https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=za&q=${encodeURIComponent(query)}`;

    const response = await fetch(url, {
      headers: {
        // Nominatim requires a real identifying User-Agent — replace the
        // contact email below if support@ ever changes.
        'User-Agent': 'NoaMark/1.0 (support@noamark.com)',
      },
    });

    if (!response.ok) {
      return res.status(502).json({ error: 'Geocoding service unavailable' });
    }

    const results = await response.json();

    if (!Array.isArray(results) || results.length === 0) {
      // Not an error — the address just couldn't be matched. The listing
      // will save without coordinates and can be re-geocoded later.
      return res.status(200).json({ latitude: null, longitude: null, matched: false });
    }

    const { lat, lon } = results[0];
    return res.status(200).json({
      latitude: parseFloat(lat),
      longitude: parseFloat(lon),
      matched: true,
    });
  } catch (err) {
    console.error('Geocode error:', err);
    return res.status(500).json({ error: 'Geocoding failed' });
  }
}
