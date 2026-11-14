import express from 'express';
import { protect } from '../middleware/auth.js';
import { requireOrganization } from '../middleware/tenant.js';
import { analyzeCtrl, explainCtrl, chatCtrl } from '../controllers/ai.controller.js';

const router = express.Router();
router.use(protect, requireOrganization, (req, res, next) => {
  if (!req.organization?.isLegacy) return res.status(503).json({ message: 'AI analysis is paused for company workspaces until its data sources are tenant-scoped' });
  next();
});
router.get('/analyze', protect, analyzeCtrl);
router.post('/explain', protect, explainCtrl);
router.post('/chat', protect, chatCtrl);

export default router;
