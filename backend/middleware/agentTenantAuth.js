import { verifyAgentCredential, touchAgentCredential } from '../services/agentCredential.service.js';

const authenticateTenantAgent = (allowExpired = false, requiredFeature = null, includeEntitlements = false) => async (req, res, next) => {
  try {
    const token = req.headers['x-api-key'] || '';
    const agent = await verifyAgentCredential(token, { allowExpired, includeEntitlements: includeEntitlements || !!requiredFeature });
    if (!agent) return res.status(401).json({ error: 'Invalid, revoked, or inactive agent credential' });

    const claimedEndpoint = String(
      req.headers['x-endpoint-id'] || req.body?.source || req.body?.endpoint || '',
    ).trim();
    if (claimedEndpoint && claimedEndpoint !== agent.endpointId) {
      return res.status(403).json({ error: 'Agent credential is not authorized for this endpoint' });
    }
    if (requiredFeature && agent.features?.[requiredFeature] !== true) {
      return res.status(403).json({ error: `The active company plan does not include ${requiredFeature}` });
    }

    req.agent = agent;
    req.organizationId = agent.organizationId;
    req.endpointId = agent.endpointId;
    if (allowExpired) {
      await touchAgentCredential(agent.credentialId, {
        ip: req.ip,
        platform: req.body?.platform || req.headers['x-agent-platform'] || agent.platform,
      });
    }
    return next();
  } catch (err) {
    return next(err);
  }
};

/** Tenant-bound auth for data/action agent routes; expired licenses fail closed. */
export const validateTenantAgentCredential = authenticateTenantAgent(false);
export const validateTenantAgentCommand = authenticateTenantAgent(false, 'responseActions');

/** Minimal heartbeat survives expiry and reports current plan entitlements. */
export const validateTenantAgentHeartbeat = authenticateTenantAgent(true, null, true);
