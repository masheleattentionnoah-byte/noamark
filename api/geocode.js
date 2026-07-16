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
//
// ── WHY THIS FILE VALIDATES RESULTS ──
// Nominatim does fuzzy text matching and almost always returns SOMETHING
// for a query, even when it can't really find what you asked for — it just
// returns its best partial-word guess. Many South African malls, informal
// township names, and plot/stand numbers aren't mapped cleanly in
// OpenStreetMap, so a query like "Shop U23C, Thavhani Mall, Thohoyandou-J,
// Thohoyandou, Limpopo" can silently resolve to some unrelated place that
// happens to share a word or two — e.g. a different town entirely, still
// within the same province, which a province-only sanity check wouldn't
// even catch. Blindly trusting results[0] is how a business in Thohoyandou
// can end up geocoded to Giyani, ~70km away.
//
// The fix: request addressdetails from Nominatim and check that the
// returned city/town/suburb and province actually correspond to what the
// business owner typed before accepting the coordinates. If nothing in the
// fallback chain produces a validated match, we return null rather than a
// confident-looking wrong pin — matching this file's existing philosophy
// that no coordinates is better than bad ones (the listing still saves and
// can be re-geocoded later).

// Rough bounding boxes per SA province — used to bias Nominatim's search
// toward the right part of the country. Not survey-grade, just enough to
// stop results from wandering into a totally different region.
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

// Does this Nominatim result's address actually correspond to the city/
// province the business owner entered? Checks every address level
// Nominatim might have used (city/town/village/suburb/county) rather than
// assuming a specific one, since informal SA settlements get filed
// inconsistently across those fields.
function resultMatchesExpectedLocation(nominatimAddress, expectedCity, expectedArea, expectedProvince) {
  if (!nominatimAddress) return false;

  const norm = s => (s || '').toLowerCase().trim();
  const cityFields = [
    nominatimAddress.city, nominatimAddress.town, nominatimAddress.village,
    nominatimAddress.suburb, nominatimAddress.municipality, nominatimAddress.county,
    nominatimAddress.hamlet,
  ].filter(Boolean).map(norm);
  const stateFields = [nominatimAddress.state].filter(Boolean).map(norm);

  const expCity = norm(expectedCity);
  const expArea = norm(expectedArea);
  const expProvince = norm(expectedProvince);

  const fieldMatches = (fields, expected) =>
    !expected || fields.some(f => f.includes(expected) || expected.includes(f));

  // Accept if EITHER the city or the area/township lines up with something
  // Nominatim returned — different SA sources file the same place under
  // different address levels — but the province must always line up.
  const cityOk = fieldMatches(cityFields, expCity) || fieldMatches(cityFields, expArea);
  const provinceOk = fieldMatches(stateFields, expProvince);

  return cityOk && provinceOk;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { address, landmark, area, city, province } = req.body || {};

    if (![address, area, city, province].some(Boolean)) {
      return res.status(400).json({ error: 'Not enough address information to geocode' });
    }

    const provinceKey = (province || '').toLowerCase().trim();
    const viewbox = PROVINCE_VIEWBOX[provinceKey];

    async function tryQuery(parts) {
      const query = parts.filter(Boolean).join(', ');
      if (!query) return null;
      const params = new URLSearchParams({
        format: 'json',
        limit: '3',              // look at a few candidates, not just the top fuzzy guess
        countrycodes: 'za',
        addressdetails: '1',      // needed so we can validate city/province below
        q: query,
      });
      if (viewbox) {
        params.set('viewbox', viewbox.join(','));
        params.set('bounded', '1'); // restrict to the correct province, don't just bias toward it
      }
      const url = `https://nominatim.openstreetmap.org/search?${params.toString()}`;
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

      // Take the first candidate whose address actually matches the city/
      // province the owner entered — not just whichever came back first.
      const validated = results.find(r =>
        resultMatchesExpectedLocation(r.address, city, area, province)
      );
      if (!validated) return null;

      return { latitude: parseFloat(validated.lat), longitude: parseFloat(validated.lon) };
    }

    // Try the full address first (most precise), then fall back to
    // progressively broader queries — many South African townships and
    // villages aren't mapped at street level, but the area/town usually is.
    // Approximate beats nothing for "Near Me Now" purposes, but every level
    // still has to pass the city/province validation above — an
    // unvalidated broad match is worse than no match at all.
    let result = await tryQuery([address, landmark, area, city, province, 'South Africa']);
    if (!result) result = await tryQuery([landmark, area, city, province, 'South Africa']);
    if (!result) result = await tryQuery([area, city, province, 'South Africa']);
    if (!result) result = await tryQuery([city, province, 'South Africa']);

    if (!result) {
      // Not an error — the address just couldn't be matched (validated) at
      // any level. The listing will save without coordinates and can be
      // re-geocoded later, rather than saving a confident-looking wrong pin.
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
