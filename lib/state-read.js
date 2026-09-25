import { getGrant, hasPermission, normalizeRole } from './permission-catalog.js';

function salesIdOf(user) {
  return String(user?.salesId || '').trim();
}

function isSalesHeader(row) {
  const value = row?.[0];
  if (typeof value !== 'string' || !value.includes('/')) return false;
  const left = value.slice(0, value.indexOf('/')).trim();
  return left !== '' && !Number.isNaN(Number(left)) && !value.trim().startsWith('Total For');
}

function ownImports(imports, salesId) {
  const filtered = {};
  for (const [date, rows] of Object.entries(imports || {})) {
    if (!Array.isArray(rows)) continue;
    const ownRows = [];
    let inOwnBlock = false;
    for (const row of rows) {
      if (isSalesHeader(row)) {
        const raw = String(row[0]).slice(0, String(row[0]).indexOf('/')).trim();
        inOwnBlock = raw === salesId;
        if (inOwnBlock) ownRows.push(row);
        continue;
      }
      const isTotal = typeof row?.[0] === 'string' && row[0].trim().startsWith('Total For');
      if (inOwnBlock) ownRows.push(row);
      if (isTotal) inOwnBlock = false;
    }
    if (ownRows.length) filtered[date] = ownRows;
  }
  return filtered;
}

function ownReturns(returns, salesId) {
  const prefix = salesId + '||';
  const filtered = {};
  for (const [date, entries] of Object.entries(returns || {})) {
    if (!entries || typeof entries !== 'object' || Array.isArray(entries)) continue;
    const ownEntries = Object.fromEntries(Object.entries(entries).filter(([key]) => key.startsWith(prefix)));
    if (Object.keys(ownEntries).length) filtered[date] = ownEntries;
  }
  return filtered;
}

function can(config, role, permission, scope) {
  return scope === undefined
    ? hasPermission(config, role, permission)
    : hasPermission(config, role, permission, scope);
}

export function projectStateForUser(stateValue, user, config) {
  const state = stateValue && typeof stateValue === 'object' && !Array.isArray(stateValue) ? stateValue : {};
  const role = normalizeRole(user?.role);
  if (!role) return {};
  if (role === 'ADMIN') return state;

  const out = {};
  const transactionGrant = getGrant(config, role, 'transactions.view');
  if (transactionGrant) {
    const scope = transactionGrant.scope;
    if (scope === 'ALL') {
      if (Object.hasOwn(state, 'imports')) out.imports = state.imports;
      if (Object.hasOwn(state, 'returns')) out.returns = state.returns;
    } else if (scope === 'OWN') {
      const salesId = salesIdOf(user);
      if (salesId) {
        out.imports = ownImports(state.imports, salesId);
        out.returns = ownReturns(state.returns, salesId);
      } else {
        out.imports = {};
        out.returns = {};
      }
    }
    if (Object.hasOwn(state, 'currentDate')) out.currentDate = state.currentDate;
  }

  if (can(config, role, 'staff_master.view')) {
    if (Object.hasOwn(state, 'staffMaster')) out.staffMaster = state.staffMaster;
  } else if (can(config, role, 'dashboard.view', 'OWN')) {
    const salesId = salesIdOf(user);
    out.staffMaster = salesId
      ? (Array.isArray(state.staffMaster) ? state.staffMaster.filter(item => String(item?.salesId || '').trim() === salesId) : [])
      : [];
  }

  if (can(config, role, 'product_database.view')) {
    if (Object.hasOwn(state, 'database')) out.database = state.database;
  }
  if (can(config, role, 'category_override.view')) {
    if (Object.hasOwn(state, 'categoryOverride')) out.categoryOverride = state.categoryOverride;
  }
  if (can(config, role, 'training_library.view')) {
    if (Object.hasOwn(state, 'trainingLibrary')) out.trainingLibrary = state.trainingLibrary;
  }
  if (can(config, role, 'training_management.view', 'ALL')) {
    if (Object.hasOwn(state, 'trainingPlan')) out.trainingPlan = state.trainingPlan;
  }
  if (can(config, role, 'incentives.view')) {
    if (Object.hasOwn(state, 'incentiveSettings')) out.incentiveSettings = state.incentiveSettings;
  }

  // Store target values have a separate ALL view grant. Training records are withheld here;
  // their current `staff` field is a display name and is not a proven Sales ID owner key.
  if (can(config, role, 'store_targets.view')) {
    const targets = state.enhancedTrainingV2?.targets;
    out.enhancedTrainingV2 = { targets: targets && typeof targets === 'object' ? targets : {} };
  }
  if (can(config, role, 'training_management.view', 'ALL')) {
    out.enhancedTrainingV2 = state.enhancedTrainingV2 && typeof state.enhancedTrainingV2 === 'object'
      ? state.enhancedTrainingV2
      : { targets: {}, trainingRecords: [] };
  }

  return out;
}
