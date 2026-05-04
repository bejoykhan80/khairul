// Public config served from env vars — keeps all credentials out of source code
module.exports = function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  // Cache at edge for 1 hour — these values rarely change
  res.setHeader('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=86400');

  res.json({
    supaUrl:    process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '',
    supaKey:    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '',
    adminEmail: process.env.ADMIN_EMAIL || ''
  });
};
