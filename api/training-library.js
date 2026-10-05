import { get, list, put } from '@vercel/blob';
import { getSession, isSameOrigin } from '../lib/auth.js';
import { loadAuthorizationConfig } from '../lib/permissions.js';
import { createTrainingLibraryHandler } from '../lib/training-library-api.js';
import { isBlobPreconditionFailure, stateBlobWriteOptions } from '../lib/state-concurrency.js';

const STATE_PATH = 'sales-training-dashboard/state.json';
function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN, oidcToken = process.env.VERCEL_OIDC_TOKEN, storeId = process.env.BLOB_STORE_ID;
  if (!storeId) throw new Error('BLOB_STORE_ID is not available in this Vercel deployment.');
  if (token) return { token, storeId };
  if (oidcToken) return { oidcToken, storeId };
  throw new Error('No Vercel Blob credentials are available in this deployment.');
}
async function readState() {
  const auth = blobAuth(), result = await list({ prefix: STATE_PATH, limit: 20, ...auth });
  const blob = result.blobs.find(item => item.pathname === STATE_PATH);
  if (!blob) return { state: {}, etag: null };
  const stored = await get(blob.pathname, { access: 'private', useCache: false, ...auth });
  if (!stored) throw new Error('Tidak dapat membaca data dashboard.');
  return { state: JSON.parse(await new Response(stored.stream).text() || '{}'), etag: stored.blob?.etag || null };
}
async function writeState(state, expectedEtag) {
  const auth = blobAuth();
  try {
    return await put(STATE_PATH, JSON.stringify(state), { access: 'private', addRandomSuffix: false,
      ...stateBlobWriteOptions(expectedEtag), contentType: 'application/json', cacheControlMaxAge: 0, ...auth });
  } catch (error) {
    if (isBlobPreconditionFailure(error)) { const conflict = new Error('State changed during conditional write.'); conflict.code = 'STATE_CONFLICT'; throw conflict; }
    throw error;
  }
}
const handler = createTrainingLibraryHandler({ getSession, isSameOrigin, loadConfig: loadAuthorizationConfig, readState, writeState });
export default async function apiHandler(req, res) {
  try { return await handler(req, res); }
  catch (error) { console.error('training library API initialization failed', error); return res.status(500).json({ ok: false, error: 'server_error' }); }
}
