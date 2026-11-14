import express from 'express';
import { protect, authorize } from '../middleware/auth.js';
import { requireOrganization } from '../middleware/tenant.js';
import { validateTenantAgentCredential } from '../middleware/agentTenantAuth.js';
import {
  getCameras, addCamera, updateCamera, deleteCamera, toggleCamera,
  getDetections, postDetection, ackDetection, escalateDetection, triggerDetection
} from '../controllers/camera.controller.js';

const router = express.Router();
const tenantUser = [protect, requireOrganization];

// Camera CRUD
router.get('/',         ...tenantUser, getCameras);
router.post('/',        ...tenantUser, authorize('admin','analyst'), addCamera);
router.put('/:id',      ...tenantUser, authorize('admin','analyst'), updateCamera);
router.delete('/:id',   ...tenantUser, authorize('admin'), deleteCamera);
router.patch('/:id/toggle', ...tenantUser, authorize('admin','analyst'), toggleCamera);

// Detections — no auth on POST so CV service can post without token issues
router.get('/detections',                   ...tenantUser, getDetections);
// Machine ingestion must use an issued endpoint credential; no public writes.
router.post('/detections', validateTenantAgentCredential, postDetection);
router.patch('/detections/:id/ack',         ...tenantUser, ackDetection);
router.patch('/detections/:id/escalate',    ...tenantUser, escalateDetection);

// Trigger simulated AI detection
router.post('/:id/detect', ...tenantUser, triggerDetection);

export default router;
