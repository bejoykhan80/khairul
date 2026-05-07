// Gemini AI proxy — keeps GEMINI_KEY server-side
const SYS = 'তুমি Khairul Islam-এর AI assistant। তথ্য: Ethical Hacker & Web Developer, ২০১৯ থেকে কাজ করছেন, Dhaka। CEH v12, OSCP, CompTIA Security+, eJPT, AWS Security, PNPT সার্টিফাইড। Services: Pen Testing(৳১৫,০০০+), Web Dev(৳২০,০০০+), Security Audit(৳১০,০০০+), Bug Bounty, Training(৳৫,০০০/hr), OSINT(৳৮,০০০)। Pricing: Starter ৳৯,৯০০, Professional ৳১৫,০০০, Enterprise Custom। Telegram: https://t.me/Khairul_i, Email: khairul.cyber@proton.me, GitHub: https://github.com/bejoykhan80, Bugcrowd: https://bugcrowd.com/h/khairulislam5b75f040-4d84-4921-bd5a-8fdfbbb59ba7। বাংলায় লিখলে বাংলায়, English-এ লিখলে English-এ উত্তর দাও। সংক্ষিপ্ত উত্তর দাও।';

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const key = process.env.GEMINI_KEY;
  if (!key) return res.status(503).json({ error: 'AI not configured' });

  const { txt, history } = req.body || {};
  if (!txt || typeof txt !== 'string') return res.status(400).end();
  if (txt.length > 2000) return res.status(413).end();
  if (Array.isArray(history) && history.length > 40) return res.status(413).end();

  // Build message array server-side (system prompt never exposed to browser)
  const msgs = [];
  if (!history || history.length === 0) {
    msgs.push({ role: 'user', parts: [{ text: SYS + '\n\nUser: ' + txt }] });
  } else {
    msgs.push({ role: 'user', parts: [{ text: SYS }] });
    msgs.push({ role: 'model', parts: [{ text: 'বুঝেছি, আমি Khairul Islam-এর AI assistant হিসেবে সাহায্য করব।' }] });
    history.forEach(function(m) { msgs.push(m); });
    msgs.push({ role: 'user', parts: [{ text: txt }] });
  }

  try {
    const r = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' + key,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: msgs }) }
    );
    const data = await r.json();
    return res.status(r.status).json(data);
  } catch (e) {
    return res.status(502).json({ error: 'Upstream error' });
  }
};
