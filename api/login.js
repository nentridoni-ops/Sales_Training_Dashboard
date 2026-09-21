import { list, get } from '@vercel/blob';
import { createHash } from 'node:crypto';

const STATE_PATH = 'dashboard/state.json';

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

    if (!username || !password) {
      return res.status(400).json({
        ok: false,
        error: 'missing_credentials',
        message: 'ID dan password wajib diisi.'
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

    if (
      username.toLowerCase() ===
      adminId.toLowerCase()
    ) {
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

      return res.status(200).json({
        ok: true,
        role: 'ADMIN',
        salesId: null,
        name: 'Administrator',
        permissions: {
          fullAccess: true,
          canEditSensitive: true
        }
      });
    }

    /*
     * =====================================================
     * STAFF / KASIR / STORE TRAINER / SPV
     * =====================================================
     *
     * Login menggunakan Sales ID.
     *
     * Password untuk sementara menggunakan Sales ID yang
     * sama. Setelah login pertama, mekanisme password dapat
     * kita tingkatkan tanpa mengubah Sales ID.
     */

    const state = await loadCloudState();

    const staffMaster = Array.isArray(state.staffMaster)
      ? state.staffMaster
      : [];

    const staff = staffMaster.find(
      item =>
        String(item.salesId || item.id || '').trim() ===
        username
    );

    if (!staff) {
      return res.status(401).json({
        ok: false,
        error: 'invalid_credentials',
        message: 'Sales ID tidak ditemukan.'
      });
    }

    const role = String(
      staff.role || staff.status || 'STAFF'
    )
      .trim()
      .toUpperCase();

    /*
     * Non-staff tidak boleh login sebagai user dashboard.
     */

    if (role === 'NON-STAFF') {
      return res.status(403).json({
        ok: false,
        error: 'non_staff',
        message:
          'Akun NON-STAFF tidak memiliki akses login dashboard.'
      });
    }

    /*
     * Untuk tahap awal:
     * password = Sales ID.
     *
     * Jadi staff tidak perlu menghafal password tambahan.
     */

    if (password !== username) {
      return res.status(401).json({
        ok: false,
        error: 'invalid_credentials',
        message: 'ID atau password salah.'
      });
    }

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

    return res.status(200).json({
      ok: true,
      role,
      salesId: username,
      name:
        staff.name ||
        staff.staffName ||
        username,
      permissions
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