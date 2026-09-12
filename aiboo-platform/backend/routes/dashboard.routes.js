import express from 'express';
import { getKPIsCtrl } from '../controllers/dashboard.controller.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

router.get('/kpis', protect, getKPIsCtrl);

export default router;