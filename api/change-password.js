import { get, put, list } from '@vercel/blob';
import { createHash } from 'node:crypto';
import { getSession, isSameOrigin, unauthorized, hashPassword, USER_CREDENTIALS_PATH, sessionCookie, createSession } from '../lib/auth.js';

function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const oidcToken = process.env.VERCEL_OIDC_TOKEN;
  const storeId = process.env.BLOB_STORE_ID;

  if (!storeId) throw new Error('BLOB_STORE_ID tidak tersedia.');
  if (token) return { token, storeId };
  if (oidcToken) return { oidcToken, storeId };
  throw new Error('Credential Vercel Blob tidak tersedia.');
}

async function findCredentialsBlob() {
  const result = await list({
    prefix: USER_CREDENTIALS_PATH,
    limit: 20,
    ...blobAuth()
  });
  return result.blobs.find(
    blob => blob.pathname === USER_CREDENTIALS_PATH
  ) || null;
}

async function loadCredentials() {
  const blob = await findCredentialsBlob();
  if (!blob) return { users: {} };

  const result = await get(blob.pathname, {
    access: 'private',
    useCache: false,
    ...blobAuth()
  });
  if (!result) return { users: {} };

  const text = await new Response(result.stream).text();
  try {
    const parsed = JSON.parse(text || '{}');
    return parsed && typeof parsed === 'object'
      ? parsed
      : { users: {} };
  } catch {
    return { users: {} };
  }
}

function lookupHash(value) {
  return createHash('sha256')
    .update(String(value))
    .digest('hex');
}

async function findStateBlob() {
  const result = await list({
    prefix: 'sales-training-dashboard/state.json',
    limit: 20,
    ...blobAuth()
  });
  return result.blobs.find(
    blob => blob.pathname === 'sales-training-dashboard/state.json'
  ) || null;
}

async function loadCloudState() {
  const blob = await findStateBlob();
  if (!blob) return { staffMaster: [] };

  const result = await get(blob.pathname, {
    access: 'private',
    ...blobAuth(),
    useCache: false
  });
  if (!result) return { staffMaster: [] };

  const text = await new Response(result.stream).text();
  try {
    const parsed = JSON.parse(text || '{}');
    return parsed && typeof parsed === 'object'
      ? parsed
      : { staffMaster: [] };
  } catch {
    return { staffMaster: [] };
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

    const role = String(session.role || '').toUpperCase();
    const salesId = String(session.salesId || '').trim();

    if (role === 'ADMIN' || !salesId) {
      return res.status(403).json({
        ok: false,
        error: 'not_applicable',
        message: 'Password Administrator dikelola melalui Vercel Environment Variables.'
      });
    }

    const body =
      typeof req.body === 'string'
        ? JSON.parse(req.body)
        : req.body || {};

    const newPassword = String(body.newPassword || '');

    if (newPassword.length < 4) {
      return res.status(400).json({
        ok: false,
        error: 'password_too_short',
        message: 'Password baru minimal 4 karakter.'
      });
    }

    if (newPassword.length > 128) {
      return res.status(400).json({
        ok: false,
        error: 'password_too_long',
        message: 'Password baru maksimal 128 karakter.'
      });
    }

    if (newPassword === salesId) {
      return res.status(400).json({
        ok: false,
        error: 'password_must_change',
        message: 'Password baru harus berbeda dari Sales ID.'
      });
    }

    const credentials = await loadCredentials();
    if (!credentials.users || typeof credentials.users !== 'object') {
      credentials.users = {};
    }

    const newLookupHash = lookupHash(newPassword);

    /*
     * Karena login staff menggunakan Role + Password tanpa
     * Sales ID, setiap password harus unik agar server dapat
     * menentukan identitas Sales ID secara pasti.
     */
    const duplicatePassword = Object.entries(credentials.users)
      .some(([id, credential]) =>
        String(id) !== salesId &&
        credential?.lookupHash === newLookupHash
      );

    if (duplicatePassword) {
      return res.status(409).json({
        ok: false,
        error: 'password_already_used',
        message: 'Password tersebut sudah digunakan akun lain. Silakan pilih password lain.'
      });
    }

    /*
     * Jangan memakai Sales ID milik staff lain sebagai password
     * baru karena Sales ID masih menjadi password sementara
     * untuk akun yang belum pernah login.
     */
    const state = await loadCloudState();
    const staffMaster = Array.isArray(state.staffMaster)
      ? state.staffMaster
      : [];

    const otherSalesId = staffMaster.some(item => {
      const otherId = String(item.salesId || item.id || '').trim();
      return otherId &&
        otherId !== salesId &&
        otherId === newPassword;
    });

    if (otherSalesId) {
      return res.status(409).json({
        ok: false,
        error: 'password_conflicts_with_sales_id',
        message: 'Password tersebut sama dengan Sales ID staff lain. Silakan pilih password lain.'
      });
    }

    credentials.users[salesId] = {
      passwordHash: hashPassword(newPassword),
      lookupHash: newLookupHash,
      updatedAt: new Date().toISOString()
    };

    const payload = JSON.stringify(credentials);

    if (payload.length > 2 * 1024 * 1024) {
      return res.status(413).json({
        ok: false,
        error: 'credentials_too_large',
        message: 'Data credential terlalu besar.'
      });
    }

    await put(USER_CREDENTIALS_PATH, payload, {
      access: 'private',
      addRandomSuffix: false,
      allowOverwrite: true,
      contentType: 'application/json',
      cacheControlMaxAge: 0,
      ...blobAuth()
    });

    const user = {
      role,
      salesId,
      name: session.name || salesId,
      permissions: session.permissions || {},
      mustChangePassword: false
    };

    res.setHeader('Set-Cookie', sessionCookie(createSession(user)));

    return res.status(200).json({
      ok: true,
      ...user,
      expiresAt: Math.floor(Date.now() / 1000) + 8 * 60 * 60
    });
  } catch (error) {
    console.error('change-password API error', error);
    return res.status(500).json({
      ok: false,
      error: 'server_error',
      message: error?.message || 'Terjadi kesalahan pada server.'
    });
  }
}
