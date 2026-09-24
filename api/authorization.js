import {
  appendAuthorizationAuditEvent,
  loadAuthorizationConfig,
  saveAuthorizationConfig
} from '../lib/permissions.js';
import { getSession, isSameOrigin } from '../lib/auth.js';
import { createAuthorizationHandler } from '../lib/authorization-api.js';

export default createAuthorizationHandler({
  getSession,
  isSameOrigin,
  loadConfig: loadAuthorizationConfig,
  saveConfig: saveAuthorizationConfig,
  appendAuditEvent: appendAuthorizationAuditEvent
});
