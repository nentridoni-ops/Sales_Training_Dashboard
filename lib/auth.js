import { createHmac, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE = 'sstd_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;

function secret() {
  const value = process.env.SESSION_SECRET || '';
  if (value.length < 32) {
    throw new Error('SESSION_SECRET belum dikonfigurasi atau terlalu pendek. Gunakan minimal 32 karakter.');
  }
  return value;
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function sign(value) {
  return createHmac('sha256', secret()).update(value).digest('base64url');
}

export function createSession(user) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: user.salesId || 'admin',
    role: user.role,
    salesId: user.salesId || null,
    name: user.name || user.salesId || user.role,
    permissions: user.permissions || {},
    iat: now,
    exp: now + SESSION_TTL_SECONDS
  };

  const encoded = base64url(JSON.stringify(payload));
  return encoded + '.' + sign(encoded);
}

export function verifySession(token) {
  try {
    if (!token || typeof token !== 'string') return null;

    const [encoded, provided] = token.split('.');
    if (!encoded || !provided) return null;

    const expected = sign(encoded);
    const a = Buffer.from(provided);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

    const payload = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8')
    );

    if (!payload?.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export function getSession(req) {
  const cookieHeader = req.headers?.cookie || '';
  const cookies = {};

  cookieHeader.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;

    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();

    if (key) cookies[key] = decodeURIComponent(value);
  });

  return verifySession(cookies[SESSION_COOKIE]);
}

export function sessionCookie(token) {
  return SESSION_COOKIE + '=' + encodeURIComponent(token) +
    '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' +
    SESSION_TTL_SECONDS;
}

export function clearSessionCookie() {
  return SESSION_COOKIE +
    '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}

export function isSameOrigin(req) {
  const origin = req.headers?.origin;
  if (!origin) return true;

  try {
    const url = new URL(origin);
    const host = String(req.headers?.host || '').split(':')[0];
    return url.hostname === host;
  } catch {
    return false;
  }
}

export function unauthorized(
  res,
  message = 'Sesi login tidak valid atau sudah berakhir.'
) {
  return res.status(401).json({
    ok: false,
    error: 'unauthorized',
    message
  });
}
