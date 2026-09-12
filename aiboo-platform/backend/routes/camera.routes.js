import express from 'express';
import { protect, authorize } from '../middleware/auth.js';
import {
  getCameras, addCamera, updateCamera, deleteCamera, toggleCamera,
  getDetections, postDetection, ackDetection, escalateDetection, triggerDetection
} from '../controllers/camera.controller.js';

const router = express.Router();

// Camera CRUD
router.get('/',         protect, getCameras);
router.post('/',        protect, authorize('admin','analyst'), addCamera);
router.put('/:id',      protect, authorize('admin','analyst'), updateCamera);
router.delete('/:id',   protect, authorize('admin'), deleteCamera);
router.patch('/:id/toggle', protect, authorize('admin','analyst'), toggleCamera);

// Detections — no auth on POST so CV service can post without token issues
router.get('/detections',                   protect, getDetections);
router.post('/detections',                           postDetection);   // CV service posts here
router.patch('/detections/:id/ack',         protect, ackDetection);
router.patch('/detections/:id/escalate',    protect, escalateDetection);

// Trigger simulated AI detection
router.post('/:id/detect', protect, triggerDetection);

export default router;
