import express from 'express';
import {
  getIdentities,
  getIdentityById,
  patchIdentity,
} from '../controllers/identity.controller.js';
import { protect, authorize } from '../middleware/auth.js';

const router = express.Router();

router.get('/', protect, getIdentities);
router.get('/:id', protect, getIdentityById);
router.patch('/:id', protect, authorize('admin', 'analyst'), patchIdentity);

export default router;