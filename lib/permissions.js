import { get, head, list, put } from '@vercel/blob';
import { getSession, unauthorized } from './auth.js';
import {
  buildDefaultAuthorizationConfig,
  hasPermission,
  validateAuthorizationConfig
} from './permission-catalog.js';

export const AUTHORIZATION_PATH = 'sales-training-dashboard/authorization.json';
export const AUTHORIZATION_AUDIT_PREFIX = 'sales-training-dashboard/authorization-audit/';

function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const oidcToken = process.env.VERCEL_OIDC_TOKEN;
  const storeId = process.env.BLOB_STORE_ID;

  if (!storeId) {
    throw new Error('BLOB_STORE_ID is not available in this Vercel deployment.');
  }
  if (token) return { token, storeId };
  if (oidcToken) return { oidcToken, storeId };
  throw new Error('No Vercel Blob credentials are available in this deployment.');
}

export function createAuthorizationStore(blobClient, getOptions) {
  async function findBlob(path) {
    const result = await blobClient.list({
      prefix: path,
      limit: 20,
      ...getOptions()
    });
    return result.blobs.find(blob => blob.pathname === path) || null;
  }

  async function readStoredConfig() {
    const blob = await findBlob(AUTHORIZATION_PATH);
    if (!blob) return null;

    const result = await blobClient.get(blob.pathname, {
      access: 'private',
      useCache: false,
      ...getOptions()
    });
    if (!result) throw new Error('Authorization configuration could not be read.');

    const text = await new Response(result.stream).text();
    let config;
    try {
      config = JSON.parse(text || '{}');
    } catch {
      throw new Error('Authorization configuration is not valid JSON.');
    }

    const validation = validateAuthorizationConfig(config);
    if (!validation.valid) {
      const error = new Error('Authorization configuration is invalid.');
      error.code = 'AUTH_CONFIG_INVALID';
      error.details = validation.errors;
      throw error;
    }
    return config;
  }

  async function loadAuthorizationConfig({ initialize = false } = {}) {
    const existing = await readStoredConfig();
    if (existing) return { config: existing, initialized: false };

    const defaults = buildDefaultAuthorizationConfig();
    if (!initialize) return { config: defaults, initialized: false };

    try {
      await blobClient.put(AUTHORIZATION_PATH, JSON.stringify(defaults), {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: false,
        contentType: 'application/json',
        cacheControlMaxAge: 0,
        ...getOptions()
      });
      return { config: defaults, initialized: true };
    } catch (error) {
      // Another request may have created the config after the initial list.
      const racedConfig = await readStoredConfig();
      if (racedConfig) return { config: racedConfig, initialized: false };
      throw error;
    }
  }

  async function saveAuthorizationConfig(config, expectedVersion) {
    const current = await readStoredConfig() || buildDefaultAuthorizationConfig();
    if (current.version !== expectedVersion) {
      const error = new Error('Authorization configuration version conflict.');
      error.code = 'AUTH_CONFIG_CONFLICT';
      throw error;
    }

    const validation = validateAuthorizationConfig(config);
    if (!validation.valid) {
      const error = new Error('Authorization configuration is invalid.');
      error.code = 'AUTH_CONFIG_INVALID';
      error.details = validation.errors;
      throw error;
    }

    const metadata = await blobClient.head(AUTHORIZATION_PATH, getOptions());
    try {
      return await blobClient.put(AUTHORIZATION_PATH, JSON.stringify(config), {
        access: 'private',
        addRandomSuffix: false,
        ifMatch: metadata.etag,
        contentType: 'application/json',
        cacheControlMaxAge: 0,
        ...getOptions()
      });
    } catch (error) {
      if (error?.name === 'BlobPreconditionFailedError' || error?.status === 412) {
        const conflict = new Error('Authorization configuration changed concurrently.');
        conflict.code = 'AUTH_CONFIG_CONFLICT';
        throw conflict;
      }
      throw error;
    }
  }

  async function appendAuditEvent(event) {
    const path = AUTHORIZATION_AUDIT_PREFIX + event.eventId + '.json';
    return blobClient.put(path, JSON.stringify(event), {
      access: 'private',
      addRandomSuffix: false,
      allowOverwrite: false,
      contentType: 'application/json',
      cacheControlMaxAge: 0,
      ...getOptions()
    });
  }

  return { loadAuthorizationConfig, saveAuthorizationConfig, appendAuditEvent };
}

const store = createAuthorizationStore(
  { get, head, list, put },
  blobAuth
);

export const loadAuthorizationConfig = store.loadAuthorizationConfig;
export const saveAuthorizationConfig = store.saveAuthorizationConfig;
export const appendAuthorizationAuditEvent = store.appendAuditEvent;

export async function requirePermission(req, permission, scope) {
  const user = getSession(req);
  if (!user) {
    return { ok: false, status: 401, response: unauthorized };
  }

  try {
    const { config } = await loadAuthorizationConfig();
    if (!hasPermission(config, user.role, permission, scope)) {
      return {
        ok: false,
        status: 403,
        response: (res) => res.status(403).json({
          ok: false,
          error: 'forbidden',
          message: 'Role ini tidak memiliki permission untuk aksi tersebut.'
        })
      };
    }
    return { ok: true, user, config };
  } catch (error) {
    console.error('authorization config load failed', error);
    return {
      ok: false,
      status: 500,
      response: (res) => res.status(500).json({
        ok: false,
        error: 'authorization_unavailable',
        message: 'Konfigurasi authorization tidak dapat dimuat.'
      })
    };
  }
}
