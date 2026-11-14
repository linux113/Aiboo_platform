import express from 'express';
import {
  getIdentities,
  getIdentityById,
  patchIdentity,
} from '../controllers/identity.controller.js';
import { protect, authorize } from '../middleware/auth.js';
import { requireOrganization } from '../middleware/tenant.js';

const router = express.Router();
router.use(protect, requireOrganization);

router.get('/', getIdentities);
router.get('/:id', getIdentityById);
router.patch('/:id', authorize('admin', 'analyst'), patchIdentity);

export default router;