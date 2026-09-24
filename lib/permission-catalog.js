export const ROLE_KEYS = Object.freeze([
  'ADMIN',
  'SPV',
  'STORE TRAINER',
  'KASIR',
  'STAFF'
]);

export const ROLE_LABELS = Object.freeze({
  ADMIN: 'Admin',
  SPV: 'SPV / PIC',
  'STORE TRAINER': 'Store Trainer',
  KASIR: 'Kasir',
  STAFF: 'Staff'
});

const scopeableKeys = new Set([
  'dashboard.view',
  'transactions.view',
  'transactions.search',
  'transactions.filter',
  'training_management.view',
  'training_results.export',
  'incentives.view'
]);

const definitions = [
  ['dashboard.view', 'dashboard', 'view', 'View dashboard performance'],

  ['transactions.view', 'transactions', 'view', 'View transactions'],
  ['transactions.search', 'transactions', 'search', 'Search transactions'],
  ['transactions.filter', 'transactions', 'filter', 'Filter transactions'],
  ['transactions.export', 'transactions', 'export', 'Export transactions'],

  ['daily_upload.view', 'daily_upload', 'view', 'View daily upload'],
  ['daily_upload.upload', 'daily_upload', 'upload', 'Upload salespersonwise'],
  ['daily_upload.edit', 'daily_upload', 'edit', 'Edit daily data'],
  ['daily_upload.delete', 'daily_upload', 'delete', 'Delete daily data'],
  ['daily_upload.export', 'daily_upload', 'export', 'Export daily data'],

  ['product_database.view', 'product_database', 'view', 'View product database'],
  ['product_database.create', 'product_database', 'create', 'Create product records'],
  ['product_database.edit', 'product_database', 'edit', 'Edit product records'],
  ['product_database.delete', 'product_database', 'delete', 'Delete product records'],

  ['category_override.view', 'category_override', 'view', 'View category overrides'],
  ['category_override.create', 'category_override', 'create', 'Create category overrides'],
  ['category_override.edit', 'category_override', 'edit', 'Edit category overrides'],
  ['category_override.delete', 'category_override', 'delete', 'Delete category overrides'],

  ['training_library.view', 'training_library', 'view', 'View training materials'],
  ['training_library.create', 'training_library', 'create', 'Create training materials'],
  ['training_library.edit', 'training_library', 'edit', 'Edit training materials'],
  ['training_library.delete', 'training_library', 'delete', 'Delete training materials'],

  ['training_management.view', 'training_management', 'view', 'View training management/results'],
  ['training_assessment.create', 'training_assessment', 'create', 'Create assessments'],
  ['training_assessment.edit', 'training_assessment', 'edit', 'Edit assessments'],
  ['training_results.input', 'training_results', 'input', 'Input training results'],
  ['training_results.export', 'training_results', 'export', 'Export training results'],

  ['staff_master.view', 'staff_master', 'view', 'View Staff Master'],
  ['staff_master.create', 'staff_master', 'create', 'Create Staff Master records'],
  ['staff_master.edit', 'staff_master', 'edit', 'Edit Staff Master records'],
  ['staff_master.delete', 'staff_master', 'delete', 'Delete Staff Master records'],
  ['staff_master.role_manage', 'staff_master', 'role_manage', 'Manage staff roles'],
  ['staff_master.password_reset', 'staff_master', 'password_reset', 'Reset staff passwords'],

  ['incentives.view', 'incentives', 'view', 'View incentives'],
  ['incentives.rate_manage', 'incentives', 'rate_manage', 'Manage incentive rates'],
  ['incentives.calculation_manage', 'incentives', 'calculation_manage', 'Manage incentive calculations'],

  ['store_targets.view', 'store_targets', 'view', 'View store targets'],
  ['store_targets.create', 'store_targets', 'create', 'Create store targets'],
  ['store_targets.edit', 'store_targets', 'edit', 'Edit store targets'],
  ['store_targets.approve', 'store_targets', 'approve', 'Approve store targets'],

  ['backup.export', 'backup', 'export', 'Export/backup dashboard data'],
  ['backup.restore', 'backup', 'restore', 'Restore dashboard data'],

  ['access.manage', 'access', 'manage', 'Manage role permissions']
];

export const PERMISSION_CATALOG = Object.freeze(
  definitions.map(([key, module, action, description]) => Object.freeze({
    key,
    module,
    action,
    description,
    supportsScope: scopeableKeys.has(key)
  }))
);

const permissionByKey = new Map(PERMISSION_CATALOG.map(item => [item.key, item]));
const allPermissionKeys = PERMISSION_CATALOG.map(item => item.key);

const roleDefaults = {
  ADMIN: allPermissionKeys,
  SPV: [
    'dashboard.view',
    'transactions.view', 'transactions.search', 'transactions.filter', 'transactions.export',
    'daily_upload.view', 'daily_upload.upload', 'daily_upload.edit', 'daily_upload.delete', 'daily_upload.export',
    'product_database.view', 'product_database.create', 'product_database.edit', 'product_database.delete',
    'category_override.view', 'category_override.create', 'category_override.edit', 'category_override.delete',
    'training_library.view', 'training_library.create', 'training_library.edit', 'training_library.delete',
    'training_management.view', 'training_assessment.create', 'training_assessment.edit',
    'training_results.input', 'training_results.export',
    'staff_master.view', 'staff_master.create', 'staff_master.edit', 'staff_master.delete',
    'incentives.view',
    'store_targets.view', 'store_targets.create', 'store_targets.edit', 'store_targets.approve'
  ],
  'STORE TRAINER': [
    'dashboard.view',
    'transactions.view', 'transactions.search', 'transactions.filter', 'transactions.export',
    'daily_upload.view', 'daily_upload.upload', 'daily_upload.edit', 'daily_upload.export',
    'product_database.view', 'product_database.create', 'product_database.edit', 'product_database.delete',
    'category_override.view', 'category_override.create', 'category_override.edit', 'category_override.delete',
    'training_library.view', 'training_library.create', 'training_library.edit', 'training_library.delete',
    'training_management.view', 'training_assessment.create', 'training_assessment.edit',
    'training_results.input', 'training_results.export',
    'staff_master.view',
    'incentives.view',
    'store_targets.view'
  ],
  KASIR: [
    'dashboard.view',
    'transactions.view', 'transactions.search', 'transactions.filter', 'transactions.export',
    'daily_upload.view', 'daily_upload.upload', 'daily_upload.edit', 'daily_upload.export',
    'product_database.view',
    'category_override.view',
    'staff_master.view',
    'incentives.view',
    'store_targets.view'
  ],
  STAFF: [
    'dashboard.view',
    'transactions.view', 'transactions.search', 'transactions.filter',
    'product_database.view',
    'training_library.view',
    'training_management.view', 'training_results.export',
    'incentives.view',
    'store_targets.view'
  ]
};

const ownDefaults = new Set([
  'dashboard.view',
  'transactions.view',
  'transactions.search',
  'transactions.filter',
  'training_management.view',
  'training_results.export',
  'incentives.view'
]);

export function normalizeRole(role) {
  const value = String(role || '').trim().toUpperCase();
  if (value === 'PIC' || value === 'SPV / PIC') return 'SPV';
  return ROLE_KEYS.includes(value) ? value : null;
}

function grantFor(role, key) {
  if (role === 'ADMIN') {
    return scopeableKeys.has(key)
      ? { permission: key, scope: 'ALL' }
      : { permission: key };
  }
  if (scopeableKeys.has(key)) {
    return { permission: key, scope: role === 'STAFF' && ownDefaults.has(key) ? 'OWN' : 'ALL' };
  }
  return { permission: key };
}

export function buildDefaultAuthorizationConfig() {
  const roles = {};
  for (const role of ROLE_KEYS) {
    roles[role] = {
      grants: roleDefaults[role].map(key => grantFor(role, key))
    };
  }
  return { version: 1, roles };
}

export function validateGrantList(role, grants) {
  const errors = [];
  if (!ROLE_KEYS.includes(role)) errors.push('Role tidak dikenal.');
  if (!Array.isArray(grants)) return ['Grants harus berupa array.'];

  const seen = new Set();
  for (const grant of grants) {
    if (!grant || typeof grant !== 'object' || Array.isArray(grant)) {
      errors.push('Setiap grant harus berupa object.');
      continue;
    }

    const key = grant.permission;
    const definition = permissionByKey.get(key);
    if (!definition) {
      errors.push('Permission tidak dikenal: ' + String(key));
      continue;
    }
    if (seen.has(key)) errors.push('Permission duplikat: ' + key);
    seen.add(key);

    if (definition.supportsScope) {
      if (!['ALL', 'OWN'].includes(grant.scope)) {
        errors.push('Scope ALL atau OWN wajib untuk permission: ' + key);
      }
    } else if (Object.hasOwn(grant, 'scope')) {
      errors.push('Scope tidak berlaku untuk permission: ' + key);
    }

    for (const prop of Object.keys(grant)) {
      if (!['permission', 'scope'].includes(prop)) {
        errors.push('Properti grant tidak dikenal: ' + prop);
      }
    }
  }

  if (role === 'ADMIN') {
    for (const key of allPermissionKeys) {
      if (!seen.has(key)) errors.push('Admin harus memiliki permission: ' + key);
    }
    for (const grant of grants) {
      if (scopeableKeys.has(grant?.permission) && grant.scope !== 'ALL') {
        errors.push('Admin harus memiliki scope ALL: ' + grant.permission);
      }
    }
  }

  return errors;
}

export function validateAuthorizationConfig(config) {
  const errors = [];
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { valid: false, errors: ['Konfigurasi harus berupa object.'] };
  }

  if (!Number.isInteger(config.version) || config.version < 1) {
    errors.push('Version harus integer positif.');
  }

  for (const prop of Object.keys(config)) {
    if (!['version', 'roles'].includes(prop)) {
      errors.push('Properti konfigurasi tidak dikenal: ' + prop);
    }
  }

  if (!config.roles || typeof config.roles !== 'object' || Array.isArray(config.roles)) {
    errors.push('Roles harus berupa object.');
    return { valid: false, errors };
  }

  for (const role of ROLE_KEYS) {
    const roleConfig = config.roles[role];
    if (!roleConfig || typeof roleConfig !== 'object' || Array.isArray(roleConfig)) {
      errors.push('Role configuration tidak ditemukan: ' + role);
      continue;
    }
    for (const prop of Object.keys(roleConfig)) {
      if (prop !== 'grants') errors.push('Properti role tidak dikenal: ' + role + '.' + prop);
    }
    errors.push(...validateGrantList(role, roleConfig.grants));
  }

  for (const role of Object.keys(config.roles)) {
    if (!ROLE_KEYS.includes(role)) errors.push('Role tidak dikenal: ' + role);
  }

  return { valid: errors.length === 0, errors };
}

export function getGrant(config, roleValue, permission) {
  const role = normalizeRole(roleValue);
  if (!role || !permissionByKey.has(permission)) return null;
  if (role === 'ADMIN') return grantFor('ADMIN', permission);

  const grants = config?.roles?.[role]?.grants;
  if (!Array.isArray(grants)) return null;
  return grants.find(item => item?.permission === permission) || null;
}

export function hasPermission(config, roleValue, permission, requestedScope) {
  const role = normalizeRole(roleValue);
  const definition = permissionByKey.get(permission);
  if (!role || !definition) return false;

  const grant = getGrant(config, role, permission);
  if (!grant) return false;

  if (requestedScope !== undefined) {
    if (!definition.supportsScope || !['ALL', 'OWN'].includes(requestedScope)) return false;
    if (requestedScope === 'ALL' && grant.scope !== 'ALL') return false;
    if (requestedScope === 'OWN' && !['ALL', 'OWN'].includes(grant.scope)) return false;
  }

  return true;
}

export function effectivePermissions(config, roleValue) {
  const role = normalizeRole(roleValue);
  if (!role) return {};
  const result = {};
  for (const { key, supportsScope } of PERMISSION_CATALOG) {
    const grant = getGrant(config, role, key);
    if (!grant) continue;
    result[key] = supportsScope ? grant.scope : true;
  }
  return result;
}

export function changedGrants(before, after) {
  const byPermission = grants => new Map(
    (grants || []).map(item => [item.permission, item.scope ? { scope: item.scope } : {}])
  );
  const oldMap = byPermission(before);
  const newMap = byPermission(after);
  const keys = new Set([...oldMap.keys(), ...newMap.keys()]);
  return [...keys]
    .filter(key => JSON.stringify(oldMap.get(key) ?? null) !== JSON.stringify(newMap.get(key) ?? null))
    .sort()
    .map(permission => ({
      permission,
      before: oldMap.has(permission) ? oldMap.get(permission) : null,
      after: newMap.has(permission) ? newMap.get(permission) : null
    }));
}

export const KNOWN_PERMISSION_KEYS = Object.freeze([...allPermissionKeys]);
