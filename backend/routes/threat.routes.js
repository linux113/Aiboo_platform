import express from 'express';
import {
  getThreats,
  postThreat,
  patchThreat,
  getThreat,
} from '../controllers/threat.controller.js';
import { protect, authorize } from '../middleware/auth.js';
import { requireOrganization } from '../middleware/tenant.js';

const router = express.Router();
router.use(protect, requireOrganization);

router.get('/', getThreats);
router.post('/', authorize('admin', 'analyst'), postThreat);
router.patch('/:id', authorize('admin', 'analyst'), patchThreat);
router.get('/:id', getThreat);

export default router;