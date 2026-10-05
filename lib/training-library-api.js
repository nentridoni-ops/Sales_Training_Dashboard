import { hasPermission } from './permission-catalog.js';
import { unauthorized } from './auth.js';
import { hasValidExpectedStateVersion, isBlobPreconditionFailure, stateConflict, stateVersionMatches } from './state-concurrency.js';

const CATEGORIES = new Set(['MacBook', 'iPhone', 'iPad', 'Apple Watch', 'Accessories', 'VAS', 'GENERAL']);
const FIELDS = new Set(['id', 'category', 'skill', 'material', 'level', 'priority', 'exercise', 'active']);

function json(res, status, body) { return res.status(status).json(body); }
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function validItem(item) {
  return item && typeof item === 'object' && !Array.isArray(item) &&
    Object.keys(item).every(key => FIELDS.has(key)) &&
    typeof item.id === 'string' && item.id.trim() &&
    CATEGORIES.has(item.category) &&
    typeof item.skill === 'string' && typeof item.material === 'string' && item.material.trim() &&
    typeof item.level === 'string' && Number.isFinite(Number(item.priority)) &&
    typeof item.exercise === 'string' && ['YES', 'NO'].includes(String(item.active).toUpperCase());
}

export function createTrainingLibraryHandler({ getSession, isSameOrigin, loadConfig, readState, writeState }) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Access-Control-Allow-Origin', 'null');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(204).end();
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method_not_allowed' });
    const user = getSession(req);
    if (!user) return unauthorized(res);
    if (user.mustChangePassword && String(user.role || '').toUpperCase() !== 'ADMIN') return json(res, 403, { ok: false, error: 'password_change_required' });
    if (!isSameOrigin(req)) return json(res, 403, { ok: false, error: 'forbidden_origin' });
    let body;
    try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
    catch { return json(res, 400, { ok: false, error: 'invalid_json' }); }
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(k => !['trainingLibrary', 'expectedEtag'].includes(k)) ||
        !hasValidExpectedStateVersion(body) || !Array.isArray(body.trainingLibrary) || body.trainingLibrary.length > 5000 || body.trainingLibrary.some(item => !validItem(item))) {
      return json(res, 400, { ok: false, error: 'invalid_training_library' });
    }
    try {
      const snapshot = await readState();
      if (!stateVersionMatches(snapshot.etag, body.expectedEtag)) return stateConflict(res);
      if (snapshot.etag === null) return json(res, 409, { ok: false, error: 'state_not_initialized' });
      const previous = Array.isArray(snapshot.state.trainingLibrary) ? snapshot.state.trainingLibrary : [];
      const oldById = new Map(previous.map(item => [String(item.id), item]));
      const nextById = new Map(body.trainingLibrary.map(item => [String(item.id), item]));
      if (oldById.size !== previous.length || nextById.size !== body.trainingLibrary.length) return json(res, 400, { ok: false, error: 'duplicate_training_material_id' });
      const actions = new Set();
      for (const [id, item] of nextById) {
        if (!oldById.has(id)) actions.add('training_library.create');
        else if (!same(oldById.get(id), item)) actions.add('training_library.edit');
      }
      for (const id of oldById.keys()) if (!nextById.has(id)) actions.add('training_library.delete');
      if (!actions.size) return json(res, 200, { ok: true, changed: false });
      const { config } = await loadConfig();
      for (const action of actions) if (!hasPermission(config, user.role, action)) return json(res, 403, { ok: false, error: 'forbidden', permission: action });
      const nextState = { ...snapshot.state, trainingLibrary: body.trainingLibrary };
      const saved = await writeState(nextState, snapshot.etag);
      if (saved?.etag) res.setHeader('ETag', saved.etag);
      return json(res, 200, { ok: true, changed: true });
    } catch (error) {
      if (error?.code === 'STATE_CONFLICT' || isBlobPreconditionFailure(error)) return stateConflict(res);
      console.error('training library API error', error);
      return json(res, 500, { ok: false, error: 'server_error' });
    }
  };
}
