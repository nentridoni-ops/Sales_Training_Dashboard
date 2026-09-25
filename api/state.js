import { get, put, list } from '@vercel/blob';
import { getSession, isSameOrigin, unauthorized } from '../lib/auth.js';
import { loadAuthorizationConfig } from '../lib/permissions.js';
import { normalizeRole } from '../lib/permission-catalog.js';
import { projectStateForUser } from '../lib/state-read.js';
import { hasValidExpectedStateVersion, isBlobPreconditionFailure, stateBlobWriteOptions, stateConflict, stateVersionMatches } from '../lib/state-concurrency.js';

const STATE_PATH = 'sales-training-dashboard/state.json';

export function legacyStateWriteAllowed(session) {
  return String(session?.role || '').toUpperCase() === 'ADMIN';
}

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
    return { state: {}, etag: null };
  }

  const result = await get(blob.pathname, {
    access: 'private',
    useCache: false,
    ...blobAuth()
  });

  if (!result) {
    throw new Error('Tidak dapat membaca data dashboard.');
  }

  const text = await new Response(result.stream).text();

  try {
    return { state: JSON.parse(text || '{}'), etag: result.blob?.etag || null };
  } catch {
    throw new Error('State cloud bukan JSON valid.');
  }
}

async function writeState(payload, expectedEtag) {
  return put(STATE_PATH, JSON.stringify(payload), {
    access: 'private',
    addRandomSuffix: false,
    ...stateBlobWriteOptions(expectedEtag),
    contentType: 'application/json',
    cacheControlMaxAge: 0,
    ...blobAuth()
  });
}

export function createStateHandler({
  getSession: readSession,
  isSameOrigin: checkOrigin,
  readState: loadState,
  writeState: saveState,
  loadConfig
}) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Access-Control-Allow-Origin', 'null');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(204).end();

    try {
      const session = readSession(req);
      if (!session) return unauthorized(res);
      if (session.mustChangePassword && String(session.role || '').toUpperCase() !== 'ADMIN') {
        return res.status(403).json({ ok: false, error: 'password_change_required', message: 'Password harus diubah sebelum dashboard dapat digunakan.' });
      }
      if (!checkOrigin(req)) {
        return res.status(403).json({ ok: false, error: 'forbidden_origin', message: 'Permintaan berasal dari origin yang tidak diizinkan.' });
      }

      if (req.method === 'GET') {
        if (!normalizeRole(session.role)) return res.status(403).json({ ok: false, error: 'forbidden' });
        const [{ state, etag }, loaded] = await Promise.all([loadState(), loadConfig()]);
        if (etag) res.setHeader('ETag', etag);
        return res.status(200).json(projectStateForUser(state, session, loaded.config));
      }

      if (req.method === 'POST') {
        if (!legacyStateWriteAllowed(session)) {
          return res.status(403).json({ ok: false, error: 'granular_api_required', message: 'Gunakan API domain/action yang sesuai permission; whole-state write hanya tersedia untuk Admin.' });
        }
        const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
        const payload = body?.payload;
        if (!hasValidExpectedStateVersion(body)) {
          return res.status(400).json({ ok: false, error: 'expected_state_version_required' });
        }
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
          return res.status(400).json({ error: 'missing_payload', message: 'POST harus memiliki payload object.' });
        }
        if (!payload.staffMaster || !payload.database) {
          return res.status(400).json({ error: 'invalid_payload', message: 'Format dashboard tidak lengkap.' });
        }
        const text = JSON.stringify(payload);
        if (text.length > 20 * 1024 * 1024) {
          return res.status(413).json({ error: 'payload_too_large', message: 'Data dashboard melebihi 20 MB.' });
        }
        const current = await loadState();
        if (!stateVersionMatches(current.etag, body.expectedEtag)) {
          return stateConflict(res);
        }
        try {
          const blob = await saveState(payload, current.etag);
          if (blob?.etag) res.setHeader('ETag', blob.etag);
          return res.status(200).json({ ok: true, savedAt: new Date().toISOString(), pathname: blob?.pathname || STATE_PATH });
        } catch (error) {
          if (isBlobPreconditionFailure(error)) return stateConflict(res);
          if (current.etag === null && (await loadState()).etag !== null) return stateConflict(res);
          throw error;
        }
      }
      return res.status(405).json({ error: 'method_not_allowed' });
    } catch (error) {
      console.error('dashboard state API error', error);
      return res.status(500).json({ error: 'server_error', message: error?.message || 'Unknown error' });
    }
  };
}

export default createStateHandler({
  getSession,
  isSameOrigin,
  readState,
  writeState,
  loadConfig: loadAuthorizationConfig
});
