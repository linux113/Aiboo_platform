import express from 'express';
import { protect, authorize } from '../middleware/auth.js';
import { requireOrganization } from '../middleware/tenant.js';
import logger from '../utils/logger.js';
import {
  issueAgentCredential,
  listAgentCredentials,
  revokeAgentCredential,
} from '../services/agentCredential.service.js';

const router = express.Router();
router.use(protect, requireOrganization, authorize('admin'));

router.get('/', async (req, res, next) => {
  try {
    const credentials = await listAgentCredentials(req.organizationId);
    // Avoid browser/proxy caching of account-security metadata.
    res.set('Cache-Control', 'no-store');
    res.json({ credentials });
  } catch (err) { next(err); }
});

router.post('/', async (req, res, next) => {
  try {
    const { endpointId, label, platform } = req.body || {};
    if (!endpointId || !platform) {
      return res.status(400).json({ message: 'endpointId and platform (windows or linux) are required' });
    }
    const credential = await issueAgentCredential({
      organizationId: req.organizationId,
      endpointId,
      label,
      platform,
      createdBy: req.user.id,
    });
    logger.info(`Agent credential issued for ${credential.endpointId} in organization ${req.organizationId}`);
    // Contains the one-time plaintext key. Do not log this response or cache it.
    res.set('Cache-Control', 'no-store');
    res.status(201).json({ ok: true, credential, warning: 'Copy the key now; it cannot be displayed again.' });
  } catch (err) {
    const status = err.statusCode || 500;
    if (status >= 500) logger.error(`Agent credential issue failed: ${err.message}`);
    res.status(status).json({ message: status >= 500 ? 'Could not issue agent credential' : err.message });
  }
});

router.delete('/:id', async (req, res, next) => {
  try {
    const revoked = await revokeAgentCredential({
      organizationId: req.organizationId,
      credentialId: req.params.id,
    });
    if (!revoked) return res.status(404).json({ message: 'Active endpoint credential not found in this company' });
    logger.info(`Agent credential revoked in organization ${req.organizationId}`);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

export default router;
