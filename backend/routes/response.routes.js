import express from 'express';
import {
  isolateCtrl,
  blockCtrl,
  lockCtrl,
  elevateCtrl,
  autoRespondCtrl,
  responseLogCtrl,
} from '../controllers/response.controller.js';
import { protect, authorize } from '../middleware/auth.js';
import { requireOrganization } from '../middleware/tenant.js';

const router = express.Router();
router.use(protect, requireOrganization, (req, res, next) => {
  if (!req.organization?.isLegacy) return res.status(503).json({ message: 'Response actions are paused for company workspaces until endpoint command routing is tenant-scoped' });
  next();
});

router.post('/isolate', protect, authorize('admin', 'analyst'), isolateCtrl);
router.post('/block', protect, authorize('admin', 'analyst'), blockCtrl);
router.post('/lock', protect, authorize('admin', 'analyst'), lockCtrl);
router.post('/escalate', protect, authorize('admin', 'analyst'), elevateCtrl);
router.post('/auto', protect, authorize('admin', 'analyst'), autoRespondCtrl);
router.get('/log', protect, responseLogCtrl);

export default router;