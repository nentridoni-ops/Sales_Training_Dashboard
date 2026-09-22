import { get, put, list } from '@vercel/blob';
import { getSession, isSameOrigin, unauthorized } from '../lib/auth.js';

const STATE_PATH = 'sales-training-dashboard/state.json';

function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const oidcToken = process.env.VERCEL_OIDC_TOKEN;
  const storeId = process.env.BLOB_STORE_ID;

  if (!storeId) {
    throw new Error(
      'BLOB_STORE_ID is not available in this Vercel deployment.'
    );
  }

  if (token) return { token, storeId };
  if (oidcToken) return { oidcToken, storeId };

  throw new Error(
    'No Vercel Blob credentials are available in this deployment.'
  );
}

async function findStateBlob() {
  const result = await list({
    prefix: STATE_PATH,
    limit: 20,
    ...blobAuth()
  });

  return (
    result.blobs.find(blob => blob.pathname === STATE_PATH) ||
    null
  );
}

async function readState() {
  const blob = await findStateBlob();

  if (!blob) {
    return {};
  }

  const result = await get(blob.pathname, {
    access: 'private',
    ...blobAuth()
  });

  if (!result) {
    throw new Error('Tidak dapat membaca data dashboard.');
  }

  const text = await new Response(result.stream).text();

  try {
    return JSON.parse(text || '{}');
  } catch {
    throw new Error('State cloud bukan JSON valid.');
  }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Access-Control-Allow-Origin', 'null');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,OPTIONS'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type'
  );

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  try {
    const session = getSession(req);

    if (!session) {
      return unauthorized(res);
    }

    if (session.mustChangePassword && String(session.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({
        ok: false,
        error: 'password_change_required',
        message: 'Password harus diubah sebelum dashboard dapat digunakan.'
      });
    }

    if (!isSameOrigin(req)) {
      return res.status(403).json({
        ok: false,
        error: 'forbidden_origin',
        message: 'Permintaan berasal dari origin yang tidak diizinkan.'
      });
    }

    if (req.method === 'GET') {
      return res.status(200).json(await readState());
    }

    if (req.method === 'POST') {
      const role = String(session.role || '').toUpperCase();

      if (!['ADMIN', 'SPV', 'STORE TRAINER', 'KASIR'].includes(role)) {
        return res.status(403).json({
          ok: false,
          error: 'write_not_allowed',
          message: 'Role ini hanya dapat membaca data dashboard.'
        });
      }

      const body =
        typeof req.body === 'string'
          ? JSON.parse(req.body)
          : req.body || {};

      const payload = body?.payload;

      if (!payload || typeof payload !== 'object') {
        return res.status(400).json({
          error: 'missing_payload',
          message: 'POST harus memiliki payload object.'
        });
      }

      if (!payload.staffMaster || !payload.database) {
        return res.status(400).json({
          error: 'invalid_payload',
          message: 'Format dashboard tidak lengkap.'
        });
      }

      const text = JSON.stringify(payload);

      if (text.length > 20 * 1024 * 1024) {
        return res.status(413).json({
          error: 'payload_too_large',
          message: 'Data dashboard melebihi 20 MB.'
        });
      }

      const blob = await put(STATE_PATH, text, {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: 'application/json',
        cacheControlMaxAge: 0,
        ...blobAuth()
      });

      return res.status(200).json({
        ok: true,
        savedAt: new Date().toISOString(),
        pathname: blob.pathname
      });
    }

    return res.status(405).json({
      error: 'method_not_allowed'
    });
  } catch (error) {
    console.error('dashboard state API error', error);

    return res.status(500).json({
      error: 'server_error',
      message: error?.message || 'Unknown error'
    });
  }
}
