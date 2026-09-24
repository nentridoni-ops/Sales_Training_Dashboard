import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDefaultAuthorizationConfig,
  effectivePermissions,
  hasPermission,
  KNOWN_PERMISSION_KEYS,
  PERMISSION_CATALOG,
  ROLE_KEYS,
  validateAuthorizationConfig
} from '../lib/permission-catalog.js';
import { createAuthorizationHandler } from '../lib/authorization-api.js';
import { createAuthorizationStore, AUTHORIZATION_PATH, AUTHORIZATION_AUDIT_PREFIX } from '../lib/permissions.js';
import { createSession, verifySession } from '../lib/auth.js';

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

function makeApiHarness(overrides = {}) {
  let config = buildDefaultAuthorizationConfig();
  const audit = [];
  let saveCount = 0;
  let loadCount = 0;
  const deps = {
    getSession: () => ({ role: 'ADMIN', sub: 'admin', name: 'Administrator' }),
    isSameOrigin: () => true,
    loadConfig: async () => {
      loadCount += 1;
      return { config: structuredClone(config), initialized: false };
    },
    saveConfig: async next => {
      saveCount += 1;
      config = structuredClone(next);
    },
    appendAuditEvent: async event => { audit.push(structuredClone(event)); },
    makeEventId: () => 'test-event-id',
    now: () => '2026-09-24T00:00:00.000Z',
    ...overrides
  };
  return {
    handler: createAuthorizationHandler(deps),
    audit,
    getConfig: () => config,
    getSaveCount: () => saveCount,
    getLoadCount: () => loadCount
  };
}

test('permission catalog has the complete approved permission key set', () => {
  assert.equal(PERMISSION_CATALOG.length, KNOWN_PERMISSION_KEYS.length);
  assert.equal(new Set(KNOWN_PERMISSION_KEYS).size, KNOWN_PERMISSION_KEYS.length);
  for (const key of [
    'dashboard.view',
    'transactions.export',
    'daily_upload.export',
    'staff_master.role_manage',
    'backup.restore',
    'access.manage'
  ]) assert.ok(KNOWN_PERMISSION_KEYS.includes(key), key);
});

test('default configuration defines only the five approved roles and validates', () => {
  const config = buildDefaultAuthorizationConfig();
  assert.deepEqual(Object.keys(config.roles), ROLE_KEYS);
  assert.deepEqual(validateAuthorizationConfig(config), { valid: true, errors: [] });
});

test('Admin has every catalog grant with ALL scope where scope applies', () => {
  const config = buildDefaultAuthorizationConfig();
  assert.deepEqual(Object.keys(effectivePermissions(config, 'ADMIN')), KNOWN_PERMISSION_KEYS);
  assert.ok(hasPermission(config, 'ADMIN', 'access.manage'));
  assert.ok(hasPermission(config, 'ADMIN', 'backup.restore'));
  assert.ok(hasPermission(config, 'ADMIN', 'dashboard.view', 'ALL'));
  assert.ok(hasPermission(config, 'ADMIN', 'transactions.view', 'ALL'));
});

test('SPV defaults match the approved operational grants', () => {
  const config = buildDefaultAuthorizationConfig();
  assert.ok(hasPermission(config, 'SPV', 'daily_upload.delete'));
  assert.ok(hasPermission(config, 'SPV', 'daily_upload.export'));
  assert.ok(hasPermission(config, 'SPV', 'staff_master.delete'));
  assert.ok(hasPermission(config, 'SPV', 'store_targets.approve'));
  assert.ok(!hasPermission(config, 'SPV', 'backup.restore'));
  assert.ok(!hasPermission(config, 'SPV', 'access.manage'));
});

test('Store Trainer has upload but not delete or Staff Master mutation', () => {
  const config = buildDefaultAuthorizationConfig();
  assert.ok(hasPermission(config, 'STORE TRAINER', 'daily_upload.upload'));
  assert.ok(hasPermission(config, 'STORE TRAINER', 'daily_upload.export'));
  assert.ok(!hasPermission(config, 'STORE TRAINER', 'daily_upload.delete'));
  assert.ok(hasPermission(config, 'STORE TRAINER', 'staff_master.view'));
  assert.ok(!hasPermission(config, 'STORE TRAINER', 'staff_master.edit'));
  assert.ok(!hasPermission(config, 'STORE TRAINER', 'store_targets.edit'));
});

test('Kasir defaults allow operational read/upload/edit but no delete or training', () => {
  const config = buildDefaultAuthorizationConfig();
  assert.ok(hasPermission(config, 'KASIR', 'transactions.export'));
  assert.ok(hasPermission(config, 'KASIR', 'daily_upload.edit'));
  assert.ok(!hasPermission(config, 'KASIR', 'daily_upload.delete'));
  assert.ok(hasPermission(config, 'KASIR', 'product_database.view'));
  assert.ok(!hasPermission(config, 'KASIR', 'product_database.edit'));
  assert.ok(!hasPermission(config, 'KASIR', 'training_library.view'));
});

test('Staff defaults use OWN for personal data and ALL for store targets', () => {
  const config = buildDefaultAuthorizationConfig();
  for (const key of [
    'dashboard.view', 'transactions.view', 'transactions.search',
    'transactions.filter', 'training_management.view',
    'training_results.export', 'incentives.view'
  ]) assert.ok(hasPermission(config, 'STAFF', key, 'OWN'), key);
  assert.ok(!hasPermission(config, 'STAFF', 'transactions.view', 'ALL'));
  assert.ok(!hasPermission(config, 'STAFF', 'transactions.export'));
  assert.ok(hasPermission(config, 'STAFF', 'store_targets.view'));
  assert.ok(!hasPermission(config, 'STAFF', 'daily_upload.upload'));
});

test('unknown roles and permission keys are denied by default', () => {
  const config = buildDefaultAuthorizationConfig();
  assert.ok(hasPermission(config, 'PIC', 'dashboard.view'));
  assert.ok(hasPermission(config, 'SPV / PIC', 'dashboard.view'));
  assert.deepEqual(Object.keys(config.roles), ROLE_KEYS);
  assert.ok(!hasPermission(config, 'STAFF', 'made_up.permission'));
});

test('unauthenticated authorization API access returns 401', async () => {
  const harness = makeApiHarness({ getSession: () => null });
  const response = makeResponse();
  await harness.handler({ method: 'GET' }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(response.body.error, 'unauthorized');
  assert.equal(harness.getLoadCount(), 0);
});

test('non-Admin authorization API access returns 403', async () => {
  const harness = makeApiHarness({
    getSession: () => ({ role: 'STAFF', salesId: 'S001' })
  });
  const response = makeResponse();
  await harness.handler({ method: 'GET' }, response);
  assert.equal(response.statusCode, 403);
  assert.equal(response.body.error, 'admin_required');
  assert.equal(harness.getLoadCount(), 0);
});

test('Admin GET returns configuration and initializes defaults with an audit event', async () => {
  const harness = makeApiHarness({
    loadConfig: async () => ({
      config: buildDefaultAuthorizationConfig(),
      initialized: true
    })
  });
  const response = makeResponse();
  await harness.handler({ method: 'GET' }, response);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(Object.keys(response.body.config.roles), ROLE_KEYS);
  assert.ok(response.body.catalog.some(item => item.key === 'daily_upload.export'));
  assert.equal(response.body.auditLogged, true);
  assert.equal(harness.audit.length, 1);
  assert.equal(harness.audit[0].action, 'authorization.initialize_defaults');
  assert.equal(harness.audit[0].result, 'success');
});

test('unknown permission in Admin PUT is rejected without changing config', async () => {
  const harness = makeApiHarness();
  const grants = structuredClone(harness.getConfig().roles.SPV.grants);
  grants.push({ permission: 'made_up.permission' });
  const response = makeResponse();
  await harness.handler({
    method: 'PUT',
    body: { expectedVersion: 1, role: 'SPV', grants }
  }, response);
  assert.equal(response.statusCode, 400);
  assert.equal(harness.getSaveCount(), 0);
  assert.equal(harness.getConfig().version, 1);
  assert.equal(harness.audit.length, 0);
});

test('Admin cannot remove access.manage or any other full-access grant', async () => {
  for (const key of ['access.manage', 'backup.restore']) {
    const harness = makeApiHarness();
    const grants = harness.getConfig().roles.ADMIN.grants
      .filter(grant => grant.permission !== key);
    const response = makeResponse();
    await harness.handler({
      method: 'PUT',
      body: { expectedVersion: 1, role: 'ADMIN', grants }
    }, response);
    assert.equal(response.statusCode, 400, key);
    assert.equal(harness.getSaveCount(), 0, key);
    assert.ok(hasPermission(harness.getConfig(), 'ADMIN', key), key);
  }
});

test('valid Admin PUT increments version and records changed grants', async () => {
  const harness = makeApiHarness();
  const grants = harness.getConfig().roles.SPV.grants
    .filter(grant => grant.permission !== 'staff_master.delete');
  const response = makeResponse();
  await harness.handler({
    method: 'PUT',
    body: { expectedVersion: 1, role: 'SPV', grants }
  }, response);

  assert.equal(response.statusCode, 200);
  assert.equal(response.body.config.version, 2);
  assert.equal(harness.getSaveCount(), 1);
  assert.equal(response.body.auditLogged, true);
  assert.equal(harness.audit.length, 1);
  assert.equal(harness.audit[0].targetRole, 'SPV');
  assert.equal(harness.audit[0].previousVersion, 1);
  assert.equal(harness.audit[0].newVersion, 2);
  assert.deepEqual(harness.audit[0].changedPermissions, [{
    permission: 'staff_master.delete',
    before: {},
    after: null
  }]);
  assert.equal(harness.audit[0].result, 'success');
});

test('stale expectedVersion is rejected and does not save', async () => {
  const harness = makeApiHarness();
  const response = makeResponse();
  await harness.handler({
    method: 'PUT',
    body: { expectedVersion: 2, role: 'SPV', grants: harness.getConfig().roles.SPV.grants }
  }, response);
  assert.equal(response.statusCode, 409);
  assert.equal(harness.getSaveCount(), 0);
});

test('existing signed session format remains verifiable', () => {
  const previousSecret = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = 'test-session-secret-that-is-longer-than-32';
  try {
    const token = createSession({
      role: 'STAFF',
      salesId: 'S001',
      name: 'Test Staff',
      permissions: { canViewOwnIncentive: true }
    });
    const session = verifySession(token);
    assert.equal(session.role, 'STAFF');
    assert.equal(session.salesId, 'S001');
    assert.equal(session.permissions.canViewOwnIncentive, true);
    assert.ok(session.exp > session.iat);
  } finally {
    if (previousSecret === undefined) delete process.env.SESSION_SECRET;
    else process.env.SESSION_SECRET = previousSecret;
  }
});

test('authorization Blob store seeds once without overwriting existing config', async () => {
  const objects = new Map();
  const calls = [];
  const fakeBlob = {
    async list({ prefix }) {
      return {
        blobs: [...objects.keys()]
          .filter(path => path.startsWith(prefix))
          .map(pathname => ({ pathname }))
      };
    },
    async get(path) {
      if (!objects.has(path)) return null;
      return { stream: new Response(objects.get(path).body).body };
    },
    async head(path) {
      return { etag: objects.get(path).etag };
    },
    async put(path, body, options) {
      calls.push({ path, options });
      const existing = objects.get(path);
      if (existing && !options.allowOverwrite && !options.ifMatch) {
        const error = new Error('already exists');
        error.name = 'BlobAlreadyExistsError';
        throw error;
      }
      if (options.ifMatch && existing?.etag !== options.ifMatch) {
        const error = new Error('etag mismatch');
        error.name = 'BlobPreconditionFailedError';
        error.status = 412;
        throw error;
      }
      objects.set(path, { body: String(body), etag: 'etag-' + (objects.size + calls.length) });
      return { pathname: path, etag: objects.get(path).etag };
    }
  };
  const store = createAuthorizationStore(fakeBlob, () => ({ token: 'test', storeId: 'store_test' }));
  const first = await store.loadAuthorizationConfig({ initialize: true });
  assert.equal(first.initialized, true);
  assert.equal(first.config.version, 1);
  assert.equal(calls[0].path, AUTHORIZATION_PATH);
  assert.equal(calls[0].options.access, 'private');
  assert.equal(calls[0].options.allowOverwrite, false);

  const before = objects.get(AUTHORIZATION_PATH).body;
  const second = await store.loadAuthorizationConfig({ initialize: true });
  assert.equal(second.initialized, false);
  assert.equal(objects.get(AUTHORIZATION_PATH).body, before);
  assert.equal(calls.length, 1);
});

test('authorization audit event is stored as a private unique Blob object', async () => {
  const objects = new Map();
  let savedOptions;
  const fakeBlob = {
    async list() { return { blobs: [] }; },
    async get() { return null; },
    async put(path, body, options) {
      objects.set(path, { body: String(body) });
      savedOptions = options;
      return { pathname: path };
    }
  };
  const store = createAuthorizationStore(fakeBlob, () => ({ token: 'test', storeId: 'store_test' }));
  const event = {
    eventId: 'event-123',
    timestamp: '2026-09-24T00:00:00.000Z',
    actor: 'admin',
    actorRole: 'ADMIN',
    action: 'authorization.role_grants_update',
    targetRole: 'KASIR',
    previousVersion: 1,
    newVersion: 2,
    changedPermissions: [],
    result: 'success'
  };
  await store.appendAuditEvent(event);
  assert.deepEqual(JSON.parse(objects.get(AUTHORIZATION_AUDIT_PREFIX + 'event-123.json').body), event);
  assert.equal(savedOptions.access, 'private');
  assert.equal(savedOptions.allowOverwrite, false);
});

test('authorization config update uses Blob ETag precondition to reject concurrent writes', async () => {
  const objects = new Map();
  let etagNumber = 0;
  let changeAfterHead = true;
  const fakeBlob = {
    async list({ prefix }) {
      return { blobs: [...objects.keys()].filter(path => path.startsWith(prefix)).map(pathname => ({ pathname })) };
    },
    async get(path) {
      const item = objects.get(path);
      return item ? { stream: new Response(item.body).body } : null;
    },
    async head(path) {
      const item = objects.get(path);
      const etag = item.etag;
      if (changeAfterHead) {
        objects.set(path, { ...item, etag: 'concurrent-' + etag });
        changeAfterHead = false;
      }
      return { etag };
    },
    async put(path, body, options) {
      const existing = objects.get(path);
      if (options.ifMatch && options.ifMatch !== existing?.etag) {
        const error = new Error('etag mismatch');
        error.name = 'BlobPreconditionFailedError';
        error.status = 412;
        throw error;
      }
      etagNumber += 1;
      objects.set(path, { body: String(body), etag: 'etag-' + etagNumber });
      return { pathname: path, etag: 'etag-' + etagNumber };
    }
  };
  const store = createAuthorizationStore(fakeBlob, () => ({ token: 'test', storeId: 'store_test' }));
  const { config } = await store.loadAuthorizationConfig({ initialize: true });
  const next = structuredClone(config);
  next.version = 2;
  next.roles.SPV.grants = next.roles.SPV.grants
    .filter(grant => grant.permission !== 'staff_master.delete');

  await assert.rejects(
    store.saveAuthorizationConfig(next, 1),
    error => error.code === 'AUTH_CONFIG_CONFLICT'
  );
  assert.equal(JSON.parse(objects.get(AUTHORIZATION_PATH).body).version, 1);
});
