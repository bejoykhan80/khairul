// Telegram notification proxy — keeps TG_BOT_TOKEN server-side
module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const token = process.env.TG_BOT_TOKEN;
  const chatId = process.env.TG_CHAT_ID;

  // Silently succeed if not configured (notification is non-critical)
  if (!token || !chatId) return res.status(200).end();

  const { message } = req.body || {};
  if (!message || typeof message !== 'string') return res.status(400).end();
  if (message.length > 2000) return res.status(413).end();

  try {
    await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: '🔔 KI Portfolio\n\n' + message })
    });
  } catch (e) {
    // Silently fail — notification should never block the user flow
  }

  return res.status(200).end();
};
