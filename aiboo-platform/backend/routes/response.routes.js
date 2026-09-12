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

const router = express.Router();

router.post('/isolate', protect, authorize('admin', 'analyst'), isolateCtrl);
router.post('/block', protect, authorize('admin', 'analyst'), blockCtrl);
router.post('/lock', protect, authorize('admin', 'analyst'), lockCtrl);
router.post('/escalate', protect, authorize('admin', 'analyst'), elevateCtrl);
router.post('/auto', protect, authorize('admin', 'analyst'), autoRespondCtrl);
router.get('/log', protect, responseLogCtrl);

export default router;