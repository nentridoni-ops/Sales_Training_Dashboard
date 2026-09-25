import test from 'node:test';
import assert from 'node:assert/strict';
import { createStateHandler } from '../api/state.js';
import { buildDefaultAuthorizationConfig } from '../lib/permission-catalog.js';
import { stateBlobWriteOptions } from '../lib/state-concurrency.js';

function response() {
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

const storeState = {
  staffMaster: [
    { salesId: '100', name: 'Ayu', status: 'STAFF' },
    { salesId: '200', name: 'Budi', status: 'STAFF' }
  ],
  database: [{ barcode: 'SKU-1' }],
  categoryOverride: [{ keyword: 'case', category: 'Accessories' }],
  trainingLibrary: [{ material: 'Shared material', active: 'YES' }],
  trainingPlan: [{ category: 'iPhone', material1: 'Plan' }],
  imports: {
    '01-09-2026': [
      ['100/Ayu', '', null], ['iPhone 17', 'SKU-1', null], ['iPhone 17', 'ORDER-A', 100], ['Total For Ayu', '', 100],
      ['200/Budi', '', null], ['iPhone 17', 'SKU-1', null], ['iPhone 17', 'ORDER-B', 200], ['Total For Budi', '', 200]
    ]
  },
  returns: {
    '01-09-2026': {
      '100||ORDER-A||SKU-1||100': { reason: 'return A' },
      '200||ORDER-B||SKU-1||200': { reason: 'return B' }
    }
  },
  currentDate: '01-09-2026',
  incentiveSettings: { deviceRates: { iPhone: 15000 } },
  enhancedTrainingV2: {
    targets: { iPhone: { value: 10, note: 'store target' } },
    trainingRecords: [{ staff: 'Ayu', date: '01-09-2026' }, { staff: 'Budi', date: '01-09-2026' }]
  },
  unknownPrivateDomain: { secret: true }
};

function makeHandler(user, state = storeState, config = buildDefaultAuthorizationConfig()) {
  return createStateHandler({
    getSession: () => user,
    isSameOrigin: () => true,
    readState: async () => ({ state: structuredClone(state), etag: '"state-v1"' }),
    writeState: async () => ({ pathname: 'mock' }),
    loadConfig: async () => ({ config })
  });
}

async function getState(user, state, config) {
  const res = response();
  await makeHandler(user, state, config)({ method: 'GET' }, res);
  return res;
}

function stateWriteHarness({ user = { role: 'ADMIN' }, state = storeState, missing = false, race = null } = {}) {
  let currentState = missing ? null : structuredClone(state);
  let etag = missing ? null : '"state-v1"';
  let version = 1;
  let writes = 0;
  const handler = createStateHandler({
    getSession: () => user,
    isSameOrigin: () => true,
    readState: async () => {
      if (race === 'parallel') await new Promise(resolve => setTimeout(resolve, 5));
      return { state: structuredClone(currentState || {}), etag };
    },
    writeState: async (next, expectedEtag) => {
      if (race === 'etag-mismatch') {
        currentState = { ...currentState, concurrent: true };
        etag = '"concurrent-v2"';
        const error = new Error('Vercel Blob: Precondition failed: ETag mismatch.');
        throw error;
      }
      if (race === 'parallel') await new Promise(resolve => setTimeout(resolve, 10));
      if (expectedEtag !== etag) {
        const error = new Error('precondition failed');
        error.name = 'BlobPreconditionFailedError';
        error.status = 412;
        throw error;
      }
      if (expectedEtag === null && currentState !== null) throw new Error('Blob already exists');
      writes++;
      currentState = structuredClone(next);
      etag = `"state-v${++version}"`;
      return { pathname: 'mock-state', etag };
    },
    loadConfig: async () => ({ config: buildDefaultAuthorizationConfig() })
  });
  const invoke = async (method, body) => {
    const res = response();
    await handler({ method, body }, res);
    return res;
  };
  return { invoke, state: () => currentState, etag: () => etag, writes: () => writes };
}

function validStatePayload(extra = {}) {
  return { ...structuredClone(storeState), ...extra };
}

test('direct GET returns Admin all state and role-approved ALL domains', async () => {
  const admin = await getState({ role: 'ADMIN' });
  assert.equal(admin.headers.ETag, '"state-v1"');
  assert.deepEqual(admin.body, storeState);

  for (const role of ['SPV', 'STORE TRAINER']) {
    const res = await getState({ role });
    assert.equal(res.statusCode, 200, role);
    for (const key of ['imports', 'returns', 'staffMaster', 'database', 'categoryOverride', 'trainingLibrary', 'trainingPlan', 'incentiveSettings']) {
      assert.deepEqual(res.body[key], storeState[key], role + ' keeps ALL ' + key);
    }
    assert.deepEqual(res.body.enhancedTrainingV2, storeState.enhancedTrainingV2);
    assert.equal(Object.hasOwn(res.body, 'unknownPrivateDomain'), false);
  }

  const cashier = await getState({ role: 'KASIR' });
  for (const key of ['imports', 'returns', 'staffMaster', 'database', 'categoryOverride', 'incentiveSettings']) {
    assert.deepEqual(cashier.body[key], storeState[key], 'KASIR keeps ALL ' + key);
  }
  assert.equal(Object.hasOwn(cashier.body, 'trainingLibrary'), false);
  assert.equal(Object.hasOwn(cashier.body, 'trainingPlan'), false);
  assert.deepEqual(cashier.body.enhancedTrainingV2, { targets: storeState.enhancedTrainingV2.targets });
});

test('Admin whole-state write succeeds with the current ETag and returns the next ETag', async () => {
  const h = stateWriteHarness();
  const res = await h.invoke('POST', { payload: validStatePayload({ marker: 'saved' }), expectedEtag: '"state-v1"' });
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers.ETag, '"state-v2"');
  assert.equal(h.state().marker, 'saved');
  assert.equal(h.writes(), 1);
});

test('Admin whole-state write rejects stale client without changing state', async () => {
  const h = stateWriteHarness();
  const before = h.state();
  const res = await h.invoke('POST', { payload: validStatePayload({ marker: 'stale' }), expectedEtag: '"older"' });
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.code, 'STATE_CONFLICT');
  assert.deepEqual(h.state(), before);
  assert.equal(h.writes(), 0);
});

test('Admin whole-state write maps Blob ifMatch mismatch to conflict without overwriting concurrent state', async () => {
  const h = stateWriteHarness({ race: 'etag-mismatch' });
  const res = await h.invoke('POST', { payload: validStatePayload({ marker: 'stale' }), expectedEtag: '"state-v1"' });
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.code, 'STATE_CONFLICT');
  assert.equal(res.body.reloadRequired, true);
  assert.equal(h.state().concurrent, true);
  assert.equal(h.state().marker, undefined);
  assert.equal(h.writes(), 0);
});

test('two parallel Admin state writes from one ETag have one winner', async () => {
  const h = stateWriteHarness({ race: 'parallel' });
  const [a, b] = await Promise.all([
    h.invoke('POST', { payload: validStatePayload({ marker: 'A' }), expectedEtag: '"state-v1"' }),
    h.invoke('POST', { payload: validStatePayload({ marker: 'B' }), expectedEtag: '"state-v1"' })
  ]);
  assert.deepEqual([a.statusCode, b.statusCode].sort(), [200, 409]);
  assert.equal(h.writes(), 1);
});

test('Admin can create missing state with create-only write', async () => {
  const h = stateWriteHarness({ missing: true });
  const res = await h.invoke('POST', { payload: validStatePayload(), expectedEtag: null });
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers.ETag, '"state-v2"');
  assert.equal(h.writes(), 1);
});

test('concurrent Admin initialization allows only one create and does not overwrite it', async () => {
  const h = stateWriteHarness({ missing: true, race: 'parallel' });
  const [a, b] = await Promise.all([
    h.invoke('POST', { payload: validStatePayload({ initializer: 'A' }), expectedEtag: null }),
    h.invoke('POST', { payload: validStatePayload({ initializer: 'B' }), expectedEtag: null })
  ]);
  assert.deepEqual([a.statusCode, b.statusCode].sort(), [200, 409]);
  assert.equal(h.writes(), 1);
  assert.ok(['A', 'B'].includes(h.state().initializer));
});

test('non-Admin whole-state POST remains forbidden even with a valid ETag', async () => {
  const h = stateWriteHarness({ user: { role: 'SPV' } });
  const res = await h.invoke('POST', { payload: validStatePayload({ injected: true }), expectedEtag: '"state-v1"' });
  assert.equal(res.statusCode, 403);
  assert.equal(h.writes(), 0);
  assert.equal(h.state().injected, undefined);
});

test('Blob write options use ifMatch for existing state and create-only for missing state', () => {
  assert.deepEqual(stateBlobWriteOptions('"state-v7"'), { ifMatch: '"state-v7"', allowOverwrite: true });
  assert.deepEqual(stateBlobWriteOptions(null), { allowOverwrite: false });
});

test('direct GET for Staff A returns only proven Sales ID A ownership', async () => {
  const res = await getState({ role: 'STAFF', salesId: '100', name: 'Ayu' });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body.staffMaster, [storeState.staffMaster[0]]);
  assert.deepEqual(res.body.imports['01-09-2026'], storeState.imports['01-09-2026'].slice(0, 4));
  assert.deepEqual(res.body.returns, { '01-09-2026': { '100||ORDER-A||SKU-1||100': { reason: 'return A' } } });
  const serialized = JSON.stringify(res.body);
  assert.equal(serialized.includes('Budi'), false);
  assert.equal(serialized.includes('200/'), false);
  assert.equal(serialized.includes('ORDER-B'), false);
  assert.equal(serialized.includes('return B'), false);
  assert.deepEqual(res.body.database, storeState.database);
  assert.deepEqual(res.body.trainingLibrary, storeState.trainingLibrary);
  assert.deepEqual(res.body.incentiveSettings, storeState.incentiveSettings);
  assert.deepEqual(res.body.enhancedTrainingV2, { targets: storeState.enhancedTrainingV2.targets });
  assert.equal(Object.hasOwn(res.body, 'categoryOverride'), false);
  assert.equal(Object.hasOwn(res.body, 'trainingPlan'), false);
  assert.equal(Object.hasOwn(res.body, 'unknownPrivateDomain'), false);
});

test('Staff without a Sales ID receives no OWN transaction, return, or profile rows', async () => {
  const res = await getState({ role: 'STAFF', salesId: null });
  assert.deepEqual(res.body.imports, {});
  assert.deepEqual(res.body.returns, {});
  assert.deepEqual(res.body.staffMaster, []);
});

test('role projection returns an empty scoped enhanced object when storage has none', async () => {
  const state = { ...storeState };
  delete state.enhancedTrainingV2;
  const staff = await getState({ role: 'STAFF', salesId: '100' }, state);
  assert.deepEqual(staff.body.enhancedTrainingV2, { targets: {} });
  assert.equal(Object.hasOwn(staff.body.enhancedTrainingV2, 'trainingRecords'), false);
  const trainer = await getState({ role: 'STORE TRAINER' }, state);
  assert.deepEqual(trainer.body.enhancedTrainingV2, { targets: {}, trainingRecords: [] });
});

test('direct GET denies missing sessions and unknown roles', async () => {
  const noSession = await getState(null);
  assert.equal(noSession.statusCode, 401);
  const unknown = await getState({ role: 'UNKNOWN' });
  assert.equal(unknown.statusCode, 403);
});
