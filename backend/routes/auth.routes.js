import express from 'express';
import { registerCtrl, loginCtrl, meCtrl, changePasswordCtrl } from '../controllers/auth.controller.js';
import { protect } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimiter.js';

const router = express.Router();

router.post('/register', authLimiter, registerCtrl);
router.post('/login', authLimiter, loginCtrl);
router.get('/me', protect, meCtrl);
router.post('/change-password', authLimiter, protect, changePasswordCtrl);

export default router;
