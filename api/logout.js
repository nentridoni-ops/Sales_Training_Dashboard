import { clearSessionCookie } from '../lib/auth.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      error: 'method_not_allowed'
    });
  }

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Set-Cookie', clearSessionCookie());

  return res.status(200).json({ ok: true });
}
