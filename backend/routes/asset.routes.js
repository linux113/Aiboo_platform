import express from 'express';
import {
  getAssets,
  postAsset,
  runAssetScan,
  getVulnerabilities,
} from '../controllers/asset.controller.js';
import { protect, authorize } from '../middleware/auth.js';

const router = express.Router();

router.get('/', protect, getAssets);
router.post('/', protect, authorize('admin', 'analyst'), postAsset);
router.post('/scan/run/:assetId', protect, authorize('admin', 'analyst'), runAssetScan);
router.get('/vulnerabilities', protect, getVulnerabilities);

export default router;