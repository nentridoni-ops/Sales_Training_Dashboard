import { randomUUID } from 'node:crypto';
import {
  PERMISSION_CATALOG,
  ROLE_KEYS,
  changedGrants,
  normalizeRole,
  validateAuthorizationConfig,
  validateGrantList
} from './permission-catalog.js';

function actorIdentifier(session) {
  return session.salesId || session.sub || session.name || 'unknown';
}

export function createAuthorizationHandler({
  getSession,
  isSameOrigin,
  loadConfig,
  saveConfig,
  appendAuditEvent,
  makeEventId = () => randomUUID(),
  now = () => new Date().toISOString()
}) {
  return async function authorizationHandler(req, res) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Allow', 'GET, PUT, OPTIONS');

    if (req.method === 'OPTIONS') return res.status(204).end();
    if (!['GET', 'PUT'].includes(req.method)) {
      return res.status(405).json({
        ok: false,
        error: 'method_not_allowed'
      });
    }

    const session = getSession(req);
    if (!session) {
      return res.status(401).json({
        ok: false,
        error: 'unauthorized',
        message: 'Sesi login tidak valid atau sudah berakhir.'
      });
    }

    if (normalizeRole(session.role) !== 'ADMIN') {
      return res.status(403).json({
        ok: false,
        error: 'admin_required',
        message: 'Hanya Admin yang dapat mengakses konfigurasi permission.'
      });
    }

    if (!isSameOrigin(req)) {
      return res.status(403).json({
        ok: false,
        error: 'forbidden_origin',
        message: 'Permintaan berasal dari origin yang tidak diizinkan.'
      });
    }

    try {
      const loaded = await loadConfig({ initialize: true, actor: session });
      const current = loaded.config;

      if (req.method === 'GET') {
        let auditLogged = true;
        if (loaded.initialized) {
          const grants = Object.entries(current.roles).flatMap(([role, value]) =>
            value.grants.map(grant => ({ role, ...grant }))
          );
          try {
            await appendAuditEvent({
              eventId: makeEventId(),
              timestamp: now(),
              actor: actorIdentifier(session),
              actorRole: 'ADMIN',
              action: 'authorization.initialize_defaults',
              targetRole: 'ALL_ROLES',
              previousVersion: 0,
              newVersion: current.version,
              changedPermissions: grants.map(grant => ({
                role: grant.role,
                permission: grant.permission,
                before: null,
                after: grant.scope ? { scope: grant.scope } : {}
              })),
              result: 'success'
            });
          } catch (error) {
            auditLogged = false;
            console.error('authorization initialization audit failed', error);
          }
        }

        return res.status(200).json({
          ok: true,
          config: current,
          catalog: PERMISSION_CATALOG,
          roles: ROLE_KEYS,
          auditLogged
        });
      }

      const body = typeof req.body === 'string'
        ? JSON.parse(req.body)
        : req.body || {};
      const role = normalizeRole(body.role);
      const expectedVersion = body.expectedVersion;

      if (!role) {
        return res.status(400).json({
          ok: false,
          error: 'invalid_role',
          message: 'Role tidak dikenal.'
        });
      }
      if (!Number.isInteger(expectedVersion) || expectedVersion < 1) {
        return res.status(400).json({
          ok: false,
          error: 'invalid_version',
          message: 'expectedVersion harus integer positif.'
        });
      }
      if (expectedVersion !== current.version) {
        return res.status(409).json({
          ok: false,
          error: 'version_conflict',
          message: 'Konfigurasi sudah berubah. Muat ulang sebelum menyimpan.'
        });
      }

      const grantErrors = validateGrantList(role, body.grants);
      if (grantErrors.length) {
        return res.status(400).json({
          ok: false,
          error: role === 'ADMIN' ? 'admin_full_access_required' : 'invalid_grants',
          message: 'Grant tidak valid.',
          details: grantErrors
        });
      }

      const next = {
        version: current.version + 1,
        roles: {
          ...current.roles,
          [role]: { grants: body.grants }
        }
      };
      const validation = validateAuthorizationConfig(next);
      if (!validation.valid) {
        return res.status(400).json({
          ok: false,
          error: role === 'ADMIN' ? 'admin_full_access_required' : 'invalid_configuration',
          message: 'Konfigurasi tidak valid.',
          details: validation.errors
        });
      }

      const changedPermissions = changedGrants(
        current.roles[role].grants,
        next.roles[role].grants
      );
      await saveConfig(next, expectedVersion);

      let auditLogged = true;
      try {
        await appendAuditEvent({
          eventId: makeEventId(),
          timestamp: now(),
          actor: actorIdentifier(session),
          actorRole: 'ADMIN',
          action: 'authorization.role_grants_update',
          targetRole: role,
          previousVersion: current.version,
          newVersion: next.version,
          changedPermissions,
          result: 'success'
        });
      } catch (error) {
        auditLogged = false;
        console.error('authorization update audit failed', error);
      }

      return res.status(200).json({
        ok: true,
        config: next,
        auditLogged
      });
    } catch (error) {
      if (error?.code === 'AUTH_CONFIG_CONFLICT') {
        return res.status(409).json({
          ok: false,
          error: 'version_conflict',
          message: 'Konfigurasi sudah berubah. Muat ulang sebelum menyimpan.'
        });
      }
      if (error?.code === 'AUTH_CONFIG_INVALID') {
        return res.status(500).json({
          ok: false,
          error: 'authorization_config_invalid',
          message: 'Konfigurasi authorization tersimpan tidak valid.'
        });
      }

      console.error('authorization API error', error);
      return res.status(500).json({
        ok: false,
        error: 'server_error',
        message: 'Authorization API mengalami kesalahan.'
      });
    }
  };
}
