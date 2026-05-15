export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Make sure the API key is configured
  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: 'API key not configured on server.' });
  }

  try {
    // Pull out what the HTML sends us (same format as before)
    const { messages, max_tokens } = req.body;

    // Convert to Gemini's format
    const geminiBody = {
      contents: messages.map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }]
      })),
      generationConfig: {
        maxOutputTokens: max_tokens || 500
      }
    };

    const geminiUrl =
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' +
      process.env.GEMINI_API_KEY;

    const response = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(geminiBody)
    });

    const data = await response.json();

    // Extract the text from Gemini's response
    const text =
      data?.candidates?.[0]?.content?.parts?.[0]?.text || 'No response.';

    // Return in the SAME format the HTML already expects (Anthropic format)
    // This means ZERO changes needed in index.html
    return res.status(200).json({
      content: [{ type: 'text', text }]
    });

  } catch (error) {
    console.error('Gemini proxy error:', error);
    return res.status(500).json({ error: 'Failed to reach AI service.' });
  }
}
