import express from 'express';
import { protect } from '../middleware/auth.js';
import { analyzeCtrl, explainCtrl, chatCtrl } from '../controllers/ai.controller.js';

const router = express.Router();
router.get('/analyze', protect, analyzeCtrl);
router.post('/explain', protect, explainCtrl);
router.post('/chat', protect, chatCtrl);

export default router;
