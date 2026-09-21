import { getSession } from '../lib/auth.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');

  if (req.method !== 'GET') {
    return res.status(405).json({
      ok: false,
      error: 'method_not_allowed'
    });
  }

  try {
    const user = getSession(req);

    if (!user) {
      return res.status(401).json({
        ok: false,
        error: 'unauthorized'
      });
    }

    return res.status(200).json({
      ok: true,
      role: user.role,
      salesId: user.salesId || null,
      name: user.name || user.salesId || user.role,
      permissions: user.permissions || {},
      expiresAt: user.exp
    });
  } catch (error) {
    console.error('session API error', error);

    return res.status(500).json({
      ok: false,
      error: 'server_error',
      message: error?.message || 'Unknown error'
    });
  }
}
