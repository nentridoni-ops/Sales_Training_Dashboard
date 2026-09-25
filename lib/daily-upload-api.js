import { hasPermission } from './permission-catalog.js';
import { unauthorized } from './auth.js';
import { hasValidExpectedStateVersion, isBlobPreconditionFailure, stateConflict, stateVersionMatches } from './state-concurrency.js';

const DATE_PATTERN = /^\d{2}-\d{2}-\d{4}$/;

function json(res, status, body) {
  return res.status(status).json(body);
}

function validDate(value) {
  if (typeof value !== 'string' || !DATE_PATTERN.test(value)) return false;
  const [day, month, year] = value.split('-').map(Number);
  const date = new Date(year, month - 1, day);
  return date.getFullYear() === year && date.getMonth() === month - 1 && date.getDate() === day;
}

function isSameRows(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function createDailyUploadHandler({ getSession, isSameOrigin, loadConfig, readState, writeState }) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Access-Control-Allow-Origin', 'null');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(204).end();
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method_not_allowed' });

    const user = getSession(req);
    if (!user) return unauthorized(res);
    if (user.mustChangePassword && String(user.role || '').toUpperCase() !== 'ADMIN') {
      return json(res, 403, { ok: false, error: 'password_change_required' });
    }
    if (!isSameOrigin(req)) return json(res, 403, { ok: false, error: 'forbidden_origin' });

    let body;
    try {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch {
      return json(res, 400, { ok: false, error: 'invalid_json' });
    }
    if (!hasValidExpectedStateVersion(body)) {
      return json(res, 400, { ok: false, error: 'expected_state_version_required' });
    }
    if (!body || typeof body !== 'object' || Array.isArray(body) ||
        Object.keys(body).some(key => !['operations', 'expectedEtag'].includes(key)) ||
        !Array.isArray(body.operations) || body.operations.length < 1 || body.operations.length > 100) {
      return json(res, 400, { ok: false, error: 'invalid_operations' });
    }
    if (JSON.stringify(body).length > 20 * 1024 * 1024) {
      return json(res, 413, { ok: false, error: 'payload_too_large' });
    }

    try {
      const snapshot = await readState();
      const state = snapshot.state;
      if (!stateVersionMatches(snapshot.etag, body.expectedEtag)) return stateConflict(res);
      if (snapshot.etag === null) {
        return res.status(409).json({
          ok: false,
          error: 'state_not_initialized',
          code: 'STATE_NOT_INITIALIZED',
          message: 'State dashboard harus diinisialisasi Administrator sebelum Daily Upload.'
        });
      }
      const imports = state.imports && typeof state.imports === 'object' && !Array.isArray(state.imports)
        ? { ...state.imports }
        : {};
      const proposed = [];
      const seenDates = new Set();

      for (const operation of body.operations) {
        if (!operation || typeof operation !== 'object' || Array.isArray(operation)) {
          return json(res, 400, { ok: false, error: 'invalid_operation' });
        }
        const keys = Object.keys(operation);
        const isDelete = operation.delete === true;
        if (keys.some(key => !['date', 'rows', 'delete'].includes(key)) ||
            !validDate(operation.date) || seenDates.has(operation.date) ||
            (isDelete ? keys.length !== 2 || Object.hasOwn(operation, 'rows') :
              keys.length !== 2 || !Array.isArray(operation.rows))) {
          return json(res, 400, { ok: false, error: 'invalid_operation' });
        }
        seenDates.add(operation.date);
        const exists = Object.hasOwn(imports, operation.date);
        if (isDelete) {
          if (!exists) return json(res, 409, { ok: false, error: 'import_not_found', date: operation.date });
          proposed.push({ permission: 'daily_upload.delete', date: operation.date, delete: true });
        } else if (!exists) {
          proposed.push({ permission: 'daily_upload.upload', date: operation.date, rows: operation.rows });
        } else {
          if (isSameRows(imports[operation.date], operation.rows)) continue;
          proposed.push({ permission: 'daily_upload.edit', date: operation.date, rows: operation.rows });
        }
      }

      if (!proposed.length) return json(res, 200, { ok: true, changed: 0 });
      const { config } = await loadConfig();
      for (const item of proposed) {
        if (!hasPermission(config, user.role, item.permission)) {
          return json(res, 403, {
            ok: false,
            error: 'forbidden',
            permission: item.permission,
            message: 'Role ini tidak memiliki permission untuk aksi tersebut.'
          });
        }
      }

      for (const item of proposed) {
        if (item.delete) delete imports[item.date];
        else imports[item.date] = item.rows;
      }
      const nextState = { ...state, imports };
      const sortedDates = Object.keys(imports).sort((a, b) => {
        const [ad, am, ay] = a.split('-').map(Number);
        const [bd, bm, by] = b.split('-').map(Number);
        return new Date(ay, am - 1, ad) - new Date(by, bm - 1, bd);
      });
      if (proposed.some(item => !item.delete)) nextState.currentDate = sortedDates.at(-1) || '';
      else if (proposed.some(item => item.delete && item.date === state.currentDate)) nextState.currentDate = sortedDates.at(-1) || '';

      try {
        const saved = await writeState(nextState, snapshot.etag);
        if (saved?.etag) res.setHeader('ETag', saved.etag);
      } catch (error) {
        if (error?.code === 'STATE_CONFLICT' || isBlobPreconditionFailure(error)) return stateConflict(res);
        throw error;
      }
      return json(res, 200, { ok: true, changed: proposed.length });
    } catch (error) {
      console.error('daily upload API error', error);
      return json(res, 500, { ok: false, error: 'server_error' });
    }
  };
}
