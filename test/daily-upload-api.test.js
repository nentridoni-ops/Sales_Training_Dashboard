import test from 'node:test';
import assert from 'node:assert/strict';
import { createDailyUploadHandler } from '../lib/daily-upload-api.js';
import { buildDefaultAuthorizationConfig } from '../lib/permission-catalog.js';
import { legacyStateWriteAllowed } from '../api/state.js';

function makeResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
    end() { return this; }
  };
}

function harness(role, state = { imports: {}, currentDate: '' }, { missing = false, race = null } = {}) {
  let stored = missing ? null : structuredClone(state);
  let etag = missing ? null : '"state-v1"';
  let version = 1;
  let writes = 0;
  const handler = createDailyUploadHandler({
    getSession: () => role ? { role, salesId: role === 'STAFF' ? 'S-1' : null } : null,
    isSameOrigin: () => true,
    loadConfig: async () => ({ config: buildDefaultAuthorizationConfig() }),
    readState: async () => {
      if (race === 'parallel') await new Promise(resolve => setTimeout(resolve, 5));
      return { state: structuredClone(stored || {}), etag };
    },
    writeState: async (value, expectedEtag) => {
      if (race === 'etag-mismatch') {
        stored = { ...stored, concurrent: true };
        etag = '"concurrent-v2"';
        const error = new Error('ETag mismatch');
        error.name = 'BlobPreconditionFailedError';
        error.status = 412;
        throw error;
      }
      if (race === 'parallel') await new Promise(resolve => setTimeout(resolve, 10));
      if (expectedEtag !== etag) {
        const error = new Error('ETag mismatch');
        error.name = 'BlobPreconditionFailedError';
        error.status = 412;
        throw error;
      }
      if (etag === null && stored !== null) throw new Error('Blob already exists');
      writes++;
      stored = structuredClone(value);
      etag = `"state-v${++version}"`;
      return { etag };
    }
  });
  return { handler, state: () => stored, etag: () => etag, writes: () => writes };
}

async function post(h, body) {
  const payload = Object.hasOwn(body || {}, 'expectedEtag') ? body : { ...body, expectedEtag: h.etag() };
  const res = makeResponse();
  await h.handler({ method: 'POST', body: payload }, res);
  return res;
}

test('Admin and SPV can upload, edit, and delete imports through inferred permissions', async () => {
  for (const role of ['ADMIN', 'SPV']) {
    const h = harness(role, { imports: {'01-09-2026': [['old']]}, currentDate: '01-09-2026' });
    let res = await post(h, { operations: [{ date: '02-09-2026', rows: [['new']] }] });
    assert.equal(res.statusCode, 200, role + ' upload');
    assert.deepEqual(h.state().imports['02-09-2026'], [['new']]);
    res = await post(h, { operations: [{ date: '01-09-2026', rows: [['edited']] }] });
    assert.equal(res.statusCode, 200, role + ' edit');
    res = await post(h, { operations: [{ date: '02-09-2026', delete: true }] });
    assert.equal(res.statusCode, 200, role + ' delete');
  }
});

test('Store Trainer and Kasir can upload/edit but cannot delete daily imports', async () => {
  for (const role of ['STORE TRAINER', 'KASIR']) {
    const h = harness(role, { imports: {'01-09-2026': [['old']]}, currentDate: '01-09-2026' });
    assert.equal((await post(h, { operations: [{ date: '02-09-2026', rows: [['new']] }] })).statusCode, 200);
    assert.equal((await post(h, { operations: [{ date: '01-09-2026', rows: [['edited']] }] })).statusCode, 200);
    const before = h.state();
    const res = await post(h, { operations: [{ date: '01-09-2026', delete: true }] });
    assert.equal(res.statusCode, 403);
    assert.equal(res.body.permission, 'daily_upload.delete');
    assert.deepEqual(h.state(), before);
  }
});

test('Staff, unknown roles, and unauthenticated users are denied writes', async () => {
  for (const role of ['STAFF', 'UNKNOWN', null]) {
    const h = harness(role);
    const res = await post(h, { operations: [{ date: '01-09-2026', rows: [['new']] }] });
    assert.equal(res.statusCode, role === null ? 401 : 403, String(role));
    assert.equal(h.writes(), 0);
  }
});

test('whole-state injection and unknown operation fields are rejected without writes', async () => {
  const h = harness('SPV');
  const wholeState = await post(h, { payload: { staffMaster: [{ salesId: 'injected' }], imports: {} } });
  assert.equal(wholeState.statusCode, 400);
  const unknown = await post(h, { operations: [{ date: '01-09-2026', rows: [], permission: 'staff_master.edit' }] });
  assert.equal(unknown.statusCode, 400);
  assert.equal(h.writes(), 0);
  assert.deepEqual(h.state(), { imports: {}, currentDate: '' });
});

test('legacy whole-state write boundary is Admin-only', () => {
  for (const role of ['SPV', 'STORE TRAINER', 'KASIR', 'STAFF', 'UNKNOWN']) {
    assert.equal(legacyStateWriteAllowed({ role }), false, role);
  }
  assert.equal(legacyStateWriteAllowed({ role: 'ADMIN' }), true);
  assert.equal(legacyStateWriteAllowed(null), false);
});

test('batch validation is atomic when one operation is forbidden', async () => {
  const h = harness('STORE TRAINER', { imports: {'01-09-2026': [['old']]}, currentDate: '01-09-2026' });
  const res = await post(h, { operations: [
    { date: '02-09-2026', rows: [['new']] },
    { date: '01-09-2026', delete: true }
  ] });
  assert.equal(res.statusCode, 403);
  assert.equal(h.writes(), 0);
  assert.deepEqual(h.state(), { imports: {'01-09-2026': [['old']]}, currentDate: '01-09-2026' });
});

test('invalid dates, invalid rows, and nonexistent deletes fail closed', async () => {
  const h = harness('SPV');
  assert.equal((await post(h, { operations: [{ date: '31-02-2026', rows: [] }] })).statusCode, 400);
  assert.equal((await post(h, { operations: [{ date: '01-09-2026', rows: {} }] })).statusCode, 400);
  assert.equal((await post(h, { operations: [{ date: '01-09-2026', delete: true }] })).statusCode, 409);
  assert.equal(h.writes(), 0);
});

test('Daily Upload rejects a stale client before changing state', async () => {
  const h = harness('SPV');
  const before = h.state();
  const res = await post(h, { expectedEtag: '"older"', operations: [{ date: '01-09-2026', rows: [['new']] }] });
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.code, 'STATE_CONFLICT');
  assert.equal(h.writes(), 0);
  assert.deepEqual(h.state(), before);
});

test('Daily Upload refuses to initialize an incomplete state when the Blob is missing', async () => {
  const h = harness('ADMIN', undefined, { missing: true });
  const res = await post(h, { expectedEtag: null, operations: [{ date: '01-09-2026', rows: [['new']] }] });
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.code, 'STATE_NOT_INITIALIZED');
  assert.equal(h.state(), null);
  assert.equal(h.writes(), 0);
});

test('two parallel Daily Upload writes using one ETag allow only one winner', async () => {
  const h = harness('SPV', undefined, { race: 'parallel' });
  const bodyA = { expectedEtag: h.etag(), operations: [{ date: '01-09-2026', rows: [['A']] }] };
  const bodyB = { expectedEtag: h.etag(), operations: [{ date: '02-09-2026', rows: [['B']] }] };
  const [a, b] = await Promise.all([post(h, bodyA), post(h, bodyB)]);
  assert.deepEqual([a.statusCode, b.statusCode].sort(), [200, 409]);
  assert.equal(h.writes(), 1);
  assert.equal(Object.keys(h.state().imports).length, 1);
});

test('Daily Upload maps ifMatch failure to conflict and preserves concurrent state', async () => {
  const h = harness('SPV', undefined, { race: 'etag-mismatch' });
  const res = await post(h, { operations: [{ date: '01-09-2026', rows: [['stale']] }] });
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.code, 'STATE_CONFLICT');
  assert.equal(h.state().concurrent, true);
  assert.equal(h.state().imports['01-09-2026'], undefined);
  assert.equal(h.writes(), 0);
});

test('permission rules still apply after a matching state ETag', async () => {
  const h = harness('STORE TRAINER');
  const res = await post(h, { operations: [{ date: '01-09-2026', delete: true }] });
  assert.equal(res.statusCode, 409); // date does not exist, so delete is rejected before permission lookup
  const seeded = harness('STORE TRAINER', { imports: { '01-09-2026': [['old']] }, currentDate: '01-09-2026' });
  const denied = await post(seeded, { operations: [{ date: '01-09-2026', delete: true }] });
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.body.permission, 'daily_upload.delete');
});
