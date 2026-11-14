import express from 'express';
import {
  getAssets,
  postAsset,
  runAssetScan,
  getVulnerabilities,
} from '../controllers/asset.controller.js';
import { protect, authorize } from '../middleware/auth.js';
import { requireOrganization } from '../middleware/tenant.js';

const router = express.Router();
router.use(protect, requireOrganization);

router.get('/', getAssets);
router.post('/', authorize('admin', 'analyst'), postAsset);
router.post('/scan/run/:assetId', authorize('admin', 'analyst'), runAssetScan);
router.get('/vulnerabilities', getVulnerabilities);

export default router;