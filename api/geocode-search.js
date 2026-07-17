// /api/geocode-search.js
//
// Powers the search box inside the manual pin-map picker on the Add/Edit
// Business form. This is deliberately different from /api/geocode.js:
// that file picks ONE best-guess coordinate and validates it automatically,
// which is exactly what fails silently for malls, informal townships, and
// plot numbers that OpenStreetMap's volunteer mappers haven't covered in
// detail — a validated-but-wrong "best guess" is how a business ends up
// pinned kilometers from where it actually is.
//
// This endpoint instead returns several named candidates and lets the
// business owner pick the right one themselves — a human recognizing
// "Thavhani Mall, Thohoyandou" in a list is far more reliable than any
// address-matching heuristic we can write.
//
// Same Nominatim usage-policy considerations as geocode.js: max 1 request/
// sec, identifying User-Agent, only called on explicit user action (a
// button press), never on every keystroke.
// Docs: https://operations.osmfoundation.org/policies/nominatim/

// Rough bounding boxes per SA province — used to BIAS results toward the
// right part of the country. Unlike geocode.js this is not "bounded": the
// owner is choosing from the list themselves, so there's no need to hard-
// exclude a correct result just because it sits slightly outside our rough
// box (e.g. a mall right on a provincial border).
const PROVINCE_VIEWBOX = {
  'limpopo':        [26.0, -22.0, 31.7, -25.6],
  'gauteng':        [27.0, -25.2, 28.9, -26.6],
  'mpumalanga':     [28.9, -24.0, 32.2, -27.0],
  'north west':     [22.4, -24.5, 28.1, -27.6],
  'kwazulu-natal':  [28.9, -26.7, 33.0, -31.1],
  'kwazulu natal':  [28.9, -26.7, 33.0, -31.1],
  'free state':     [23.9, -26.5, 29.9, -30.8],
  'eastern cape':   [22.4, -30.0, 30.1, -34.1],
  'western cape':   [17.4, -30.4, 24.1, -34.9],
  'northern cape':  [16.4, -24.0, 25.6, -34.1],
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { query, province } = req.body || {};
    if (!query || !query.trim()) {
      return res.status(400).json({ error: 'Search query required' });
    }

    const provinceKey = (province || '').toLowerCase().trim();
    const viewbox = PROVINCE_VIEWBOX[provinceKey];

    async function search(q) {
      const params = new URLSearchParams({
        format: 'json',
        limit: '6',
        countrycodes: 'za',
        addressdetails: '1',
        q,
      });
      if (viewbox) params.set('viewbox', viewbox.join(','));
      // Deliberately NOT setting bounded=1 here — see comment above.

      const url = `https://nominatim.openstreetmap.org/search?${params.toString()}`;
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'NoaMark/1.0 (support@noamark.com)',
        },
      });
      if (!response.ok) return [];

      const raw = await response.json();
      return (Array.isArray(raw) ? raw : [])
        .map(r => ({
          label: r.display_name,
          lat: parseFloat(r.lat),
          lon: parseFloat(r.lon),
        }))
        .filter(r => r.label && !isNaN(r.lat) && !isNaN(r.lon));
    }

    // Nominatim treats a comma-separated query as a structured address
    // (place, area, city...), and if any ONE part doesn't match anything
    // in OpenStreetMap — very common for informal township/section names,
    // hand-described street addresses ("Straight Road, house number 36"),
    // or plot numbers — the whole compound query can come back empty, even
    // when part of it would succeed on its own. Rather than requiring the
    // owner to know which wording will work, try the query several
    // different ways and use whichever one actually finds something:
    const trimmed = query.trim();
    const parts = trimmed.split(',').map(s => s.trim()).filter(Boolean);

    const attempts = [];
    attempts.push(trimmed);                              // exactly as typed
    if (parts.length > 1) {
      attempts.push(parts.join(' '));                    // same words, no commas —
                                                           // Nominatim's structured
                                                           // parser can reject a
                                                           // compound query that its
                                                           // free-text parser accepts
      attempts.push([parts[0], 'South Africa'].join(', ')); // most specific term + country
      if (parts.length > 2) attempts.push(parts.slice(0, -1).join(', ')); // drop broadest term
      // Try every remaining individual part on its own too — covers cases
      // where the FIRST part is the one OSM doesn't recognize (e.g. a
      // street name it doesn't have) but a later part (e.g. the suburb)
      // would succeed.
      for (const p of parts.slice(1)) attempts.push([p, 'South Africa'].join(', '));
    }

    let results = [];
    for (const attempt of attempts) {
      results = await search(attempt);
      if (results.length > 0) break;
    }

    return res.status(200).json({ results });
  } catch (err) {
    console.error('Geocode search error:', err);
    return res.status(500).json({ error: 'Search failed', results: [] });
  }
}
