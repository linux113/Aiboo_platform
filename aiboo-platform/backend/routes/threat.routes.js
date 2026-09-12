import express from 'express';
import {
  getThreats,
  postThreat,
  patchThreat,
  getThreat,
} from '../controllers/threat.controller.js';
import { protect, authorize } from '../middleware/auth.js';

const router = express.Router();

router.get('/', protect, getThreats);
router.post('/', protect, authorize('admin', 'analyst'), postThreat);
router.patch('/:id', protect, authorize('admin', 'analyst'), patchThreat);
router.get('/:id', protect, getThreat);

export default router;