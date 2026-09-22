import { get, put, list } from '@vercel/blob';
import {
  getSession,
  isSameOrigin,
  unauthorized,
  USER_CREDENTIALS_PATH
} from '../lib/auth.js';

function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const oidcToken = process.env.VERCEL_OIDC_TOKEN;
  const storeId = process.env.BLOB_STORE_ID;

  if (!storeId) throw new Error('BLOB_STORE_ID tidak tersedia.');
  if (token) return { token, storeId };
  if (oidcToken) return { oidcToken, storeId };
  throw new Error('Credential Vercel Blob tidak tersedia.');
}

async function findBlob(path) {
  const result = await list({
    prefix: path,
    limit: 20,
    ...blobAuth()
  });
  return result.blobs.find(blob => blob.pathname === path) || null;
}

async function loadJson(path, fallback) {
  const blob = await findBlob(path);
  if (!blob) return fallback;

  const result = await get(blob.pathname, {
    access: 'private',
    useCache: false,
    ...blobAuth()
  });
  if (!result) return fallback;

  const text = await new Response(result.stream).text();
  try {
    const parsed = JSON.parse(text || '{}');
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      error: 'method_not_allowed'
    });
  }

  try {
    const session = getSession(req);
    if (!session) return unauthorized(res);

    if (!isSameOrigin(req)) {
      return res.status(403).json({
        ok: false,
        error: 'forbidden_origin',
        message: 'Permintaan berasal dari origin yang tidak diizinkan.'
      });
    }

    if (String(session.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({
        ok: false,
        error: 'admin_required',
        message: 'Hanya Administrator yang dapat melakukan reset password.'
      });
    }

    const body =
      typeof req.body === 'string'
        ? JSON.parse(req.body)
        : req.body || {};

    const salesId = String(body.salesId || '').trim();
    if (!salesId) {
      return res.status(400).json({
        ok: false,
        error: 'missing_sales_id',
        message: 'Sales ID wajib diisi.'
      });
    }

    const state = await loadJson(
      'sales-training-dashboard/state.json',
      { staffMaster: [] }
    );

    const staffMaster = Array.isArray(state.staffMaster)
      ? state.staffMaster
      : [];

    const staff = staffMaster.find(item =>
      String(item.salesId || item.id || '').trim() === salesId
    );

    if (!staff) {
      return res.status(404).json({
        ok: false,
        error: 'staff_not_found',
        message: 'Sales ID tidak ditemukan di Staff Master.'
      });
    }

    const role = String(staff.role || staff.status || 'STAFF')
      .trim()
      .toUpperCase();

    if (role === 'NON-STAFF') {
      return res.status(403).json({
        ok: false,
        error: 'non_staff_not_allowed',
        message: 'Akun NON-STAFF tidak memiliki credential login dashboard.'
      });
    }

    const credentials = await loadJson(
      USER_CREDENTIALS_PATH,
      { users: {} }
    );

    if (!credentials.users || typeof credentials.users !== 'object') {
      credentials.users = {};
    }

    /*
     * Menghapus credential membuat akun kembali ke kondisi
     * "belum pernah login": password sementara = Sales ID.
     * Password lama tidak dapat dipakai lagi.
     */
    delete credentials.users[salesId];

    await put(
      USER_CREDENTIALS_PATH,
      JSON.stringify(credentials),
      {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: 'application/json',
        cacheControlMaxAge: 0,
        ...blobAuth()
      }
    );

    return res.status(200).json({
      ok: true,
      salesId,
      name: staff.name || staff.staffName || salesId,
      role,
      resetToTemporaryPassword: true,
      message: 'Password berhasil di-reset. Password sementara adalah Sales ID.'
    });
  } catch (error) {
    console.error('reset-password API error', error);

    return res.status(500).json({
      ok: false,
      error: 'server_error',
      message: error?.message || 'Terjadi kesalahan pada server.'
    });
  }
}
