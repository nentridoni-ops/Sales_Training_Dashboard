import { get, list, put } from '@vercel/blob';
import { createHash } from 'node:crypto';
import { getSession, isSameOrigin, unauthorized } from '../lib/auth.js';

const PREFIX = 'sales-training-dashboard/activities/';

function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const oidcToken = process.env.VERCEL_OIDC_TOKEN;
  const storeId = process.env.BLOB_STORE_ID;
  if (!storeId) throw new Error('BLOB_STORE_ID is not available in this deployment.');
  if (token) return { token, storeId };
  if (oidcToken) return { oidcToken, storeId };
  throw new Error('No Vercel Blob credentials are available in this deployment.');
}

function userPath(session) {
  const identity = String(session.salesId || session.sub || '');
  const key = createHash('sha256').update(identity).digest('hex').slice(0, 24);
  return `${PREFIX}${key}.json`;
}

async function readActivities(pathname) {
  const result = await list({ prefix: pathname, limit: 5, ...blobAuth() });
  const blob = result.blobs.find((entry) => entry.pathname === pathname);
  if (!blob) return [];
  const response = await get(blob.pathname, { access: 'private', ...blobAuth() });
  if (!response) return [];
  const text = await new Response(response.stream).text();
  const value = JSON.parse(text || '[]');
  if (!Array.isArray(value)) throw new Error('Format aktivitas cloud tidak valid.');
  return value;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Access-Control-Allow-Origin', 'null');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!['GET', 'POST'].includes(req.method)) {
    return res.status(405).json({ ok: false, error: 'method_not_allowed' });
  }

  try {
    const session = getSession(req);
    if (!session) return unauthorized(res);
    if (session.mustChangePassword && String(session.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({ ok: false, error: 'password_change_required' });
    }
    if (!isSameOrigin(req)) {
      return res.status(403).json({ ok: false, error: 'forbidden_origin' });
    }

    const role = String(session.role || '').toUpperCase();
    if (!['ADMIN', 'SPV', 'STORE TRAINER'].includes(role)) {
      return res.status(403).json({ ok: false, error: 'role_not_allowed' });
    }

    const pathname = userPath(session);
    if (req.method === 'GET') {
      return res.status(200).json({ activities: await readActivities(pathname) });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
    const activities = body.activities;
    if (!Array.isArray(activities) || activities.length > 5000) {
      return res.status(400).json({ ok: false, error: 'invalid_activities' });
    }
    const text = JSON.stringify(activities);
    if (text.length > 5 * 1024 * 1024) {
      return res.status(413).json({ ok: false, error: 'payload_too_large' });
    }

    await put(pathname, text, {
      access: 'private',
      addRandomSuffix: false,
      allowOverwrite: true,
      contentType: 'application/json',
      cacheControlMaxAge: 0,
      ...blobAuth()
    });
    return res.status(200).json({ ok: true, savedAt: new Date().toISOString() });
  } catch (error) {
    console.error('trainer activity API error', error);
    return res.status(500).json({
      ok: false,
      error: 'server_error',
      message: error?.message || 'Unknown error'
    });
  }
}
