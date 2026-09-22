import { list, get } from '@vercel/blob';
import { createHash } from 'node:crypto';
import { createSession, sessionCookie, isSameOrigin, verifyPassword, USER_CREDENTIALS_PATH } from '../lib/auth.js';

const STATE_PATH = 'sales-training-dashboard/state.json';

function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const oidcToken = process.env.VERCEL_OIDC_TOKEN;
  const storeId = process.env.BLOB_STORE_ID;

  if (!storeId) {
    throw new Error('BLOB_STORE_ID tidak tersedia.');
  }

  if (token) return { token, storeId };
  if (oidcToken) return { oidcToken, storeId };

  throw new Error('Credential Vercel Blob tidak tersedia.');
}

async function findStateBlob() {
  const result = await list({
    prefix: STATE_PATH,
    limit: 20,
    ...blobAuth()
  });

  return (
    result.blobs.find(
      blob => blob.pathname === STATE_PATH
    ) || null
  );
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

async function loadCloudState() {
  const blob = await findStateBlob();

  if (!blob) {
    throw new Error('Data dashboard belum ditemukan di cloud.');
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
    throw new Error('State cloud bukan JSON yang valid.');
  }
}

function hash(value) {
  return createHash('sha256')
    .update(String(value))
    .digest('hex');
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'POST,OPTIONS'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type'
  );

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      error: 'method_not_allowed'
    });
  }

  if (!isSameOrigin(req)) {
    return res.status(403).json({
      ok: false,
      error: 'forbidden_origin',
      message: 'Permintaan login berasal dari origin yang tidak diizinkan.'
    });
  }

  try {
    const body =
      typeof req.body === 'string'
        ? JSON.parse(req.body)
        : req.body || {};

    const username = String(
      body.username || ''
    ).trim();

    const password = String(
      body.password || ''
    );

    const requestedRole = String(
      body.role || ''
    ).trim().toUpperCase();

    if (!password || (requestedRole === 'ADMIN' && !username)) {
      return res.status(400).json({
        ok: false,
        error: 'missing_credentials',
        message: requestedRole === 'ADMIN'
          ? 'ID Administrator dan password wajib diisi.'
          : 'Password wajib diisi.'
      });
    }

    /*
     * =====================================================
     * ADMIN
     * =====================================================
     *
     * Credential Admin disimpan di Vercel Environment
     * Variables, bukan di GitHub.
     */

    const adminId =
      process.env.ADMIN_ID || 'admin';

    const adminPasswordHash =
      process.env.ADMIN_PASSWORD_HASH || '';

    if (username.toLowerCase() === adminId.toLowerCase()) {
      if (!adminPasswordHash) {
        return res.status(500).json({
          ok: false,
          error: 'admin_not_configured',
          message:
            'Credential Admin belum dikonfigurasi.'
        });
      }

      const valid =
        hash(password) ===
        String(adminPasswordHash).toLowerCase();

      if (!valid) {
        return res.status(401).json({
          ok: false,
          error: 'invalid_credentials',
          message: 'ID atau password salah.'
        });
      }

      const adminUser = {
        role: 'ADMIN',
        salesId: null,
        name: 'Administrator',
        permissions: {
          fullAccess: true,
          canEditSensitive: true
        },
        mustChangePassword: false
      };

      res.setHeader(
        'Set-Cookie',
        sessionCookie(createSession(adminUser))
      );

      return res.status(200).json({
        ok: true,
        ...adminUser
      });
    }

    /*
     * =====================================================
     * STAFF / KASIR / STORE TRAINER / SPV
     * =====================================================
     *
     * Login staff sengaja tidak meminta Sales ID.
     *
     * Identitas akun ditemukan dari kombinasi:
     *   1. Role yang dipilih
     *   2. Password
     *
     * Pada login pertama, password sementara = Sales ID.
     * Setelah password diganti, credential menyimpan lookupHash
     * sehingga password baru dapat menemukan Sales ID yang benar
     * tanpa menampilkan Sales ID pada layar login.
     */

    if (!requestedRole) {
      return res.status(400).json({
        ok: false,
        error: 'missing_role',
        message: 'Role login wajib dipilih.'
      });
    }

    const allowedRoles = [
      'SPV',
      'STORE TRAINER',
      'KASIR',
      'STAFF'
    ];

    if (!allowedRoles.includes(requestedRole)) {
      return res.status(403).json({
        ok: false,
        error: 'role_not_allowed',
        message: 'Role akun tidak memiliki akses login dashboard.'
      });
    }

    const state = await loadCloudState();

    const staffMaster = Array.isArray(state.staffMaster)
      ? state.staffMaster
      : [];

    const candidates = staffMaster.filter(item => {
      const role = String(item.role || item.status || 'STAFF')
        .trim()
        .toUpperCase();

      return role === requestedRole &&
        role !== 'NON-STAFF' &&
        String(item.salesId || item.id || '').trim();
    });

    const credentials = await loadCredentials();
    const users = credentials.users &&
      typeof credentials.users === 'object'
      ? credentials.users
      : {};

    const passwordLookupHash = hash(password);
    let matchedStaff = null;
    let matchedCredential = null;

    /*
     * Credential baru memakai lookupHash agar pencarian tetap
     * cepat. Jika ada credential lama yang belum memiliki
     * lookupHash, lakukan verifikasi scrypt sebagai fallback
     * untuk migrasi tanpa memutus akun yang sudah ada.
     */

    const lookupMatches = candidates.filter(item => {
      const salesId = String(item.salesId || item.id || '').trim();
      return users[salesId]?.lookupHash === passwordLookupHash;
    });

    if (lookupMatches.length === 1) {
      matchedStaff = lookupMatches[0];
      matchedCredential = users[
        String(matchedStaff.salesId || matchedStaff.id || '').trim()
      ];
    } else if (lookupMatches.length > 1) {
      return res.status(409).json({
        ok: false,
        error: 'ambiguous_credentials',
        message: 'Credential login terdeteksi ganda. Hubungi Administrator.'
      });
    }

    /*
     * Login pertama: password sementara adalah Sales ID.
     * Hanya akun yang belum memiliki credential yang boleh
     * memakai mekanisme ini.
     */
    if (!matchedStaff) {
      const initialMatches = candidates.filter(item => {
        const salesId = String(item.salesId || item.id || '').trim();
        return salesId &&
          !users[salesId]?.passwordHash &&
          password === salesId;
      });

      if (initialMatches.length === 1) {
        matchedStaff = initialMatches[0];
        matchedCredential = null;
      } else if (initialMatches.length > 1) {
        return res.status(409).json({
          ok: false,
          error: 'ambiguous_credentials',
          message: 'Password sementara terdeteksi ganda. Hubungi Administrator.'
        });
      }
    }

    /*
     * Fallback migrasi untuk credential lama yang belum punya
     * lookupHash. Ini hanya dipakai sampai akun tersebut login
     * dan mengganti password lagi.
     */
    if (!matchedStaff) {
      const legacyMatches = [];
      for (const item of candidates) {
        const salesId = String(item.salesId || item.id || '').trim();
        const credential = users[salesId];
        if (credential?.passwordHash && !credential.lookupHash &&
            verifyPassword(password, credential.passwordHash)) {
          legacyMatches.push({ item, credential });
        }
        if (legacyMatches.length > 1) break;
      }

      if (legacyMatches.length === 1) {
        matchedStaff = legacyMatches[0].item;
        matchedCredential = legacyMatches[0].credential;
      } else if (legacyMatches.length > 1) {
        return res.status(409).json({
          ok: false,
          error: 'ambiguous_credentials',
          message: 'Credential login terdeteksi ganda. Hubungi Administrator.'
        });
      }
    }

    if (!matchedStaff) {
      return res.status(401).json({
        ok: false,
        error: 'invalid_credentials',
        message: 'Password salah atau akun tidak ditemukan.'
      });
    }

    const salesId = String(
      matchedStaff.salesId || matchedStaff.id || ''
    ).trim();

    const role = String(
      matchedStaff.role || matchedStaff.status || 'STAFF'
    )
      .trim()
      .toUpperCase();

    if (!salesId || role === 'NON-STAFF' || !allowedRoles.includes(role)) {
      return res.status(403).json({
        ok: false,
        error: 'role_not_allowed',
        message: 'Akun tidak memiliki akses login dashboard.'
      });
    }

    const mustChangePassword = !matchedCredential?.passwordHash;

    const permissions = {
      fullAccess: false,
      canEditSensitive: false,
      canViewIncentive: true,
      canViewDailyData: true,
      canViewEngine: true,
      canViewOverride: true
    };

    /*
     * SPV / STORE TRAINER / KASIR
     *
     * Mereka dapat menjalankan pekerjaan harian tanpa
     * meminta Admin untuk setiap upload / engine / override.
     *
     * Perubahan sensitif tetap akan membutuhkan Admin.
     */

    if (
      role === 'SPV' ||
      role === 'STORE TRAINER' ||
      role === 'KASIR'
    ) {
      permissions.canOperateDaily = true;
      permissions.canRequestAdminApproval = true;
    }

    /*
     * STAFF
     *
     * Staff dapat melihat dashboard dan insentifnya sendiri,
     * tetapi tidak boleh mengedit data sensitif.
     */

    if (role === 'STAFF') {
      permissions.canOperateDaily = false;
      permissions.canRequestAdminApproval = false;
      permissions.canViewOwnIncentive = true;
      permissions.canEditIncentive = false;
    }

    const staffUser = {
      role,
      salesId,
      name:
        staff.name ||
        staff.staffName ||
        username,
      permissions,
      mustChangePassword
    };

    res.setHeader(
      'Set-Cookie',
      sessionCookie(createSession(staffUser))
    );

    return res.status(200).json({
      ok: true,
      ...staffUser
    });

  } catch (error) {
    console.error(
      'login API error',
      error
    );

    return res.status(500).json({
      ok: false,
      error: 'server_error',
      message:
        error?.message ||
        'Terjadi kesalahan pada server.'
    });
  }
}