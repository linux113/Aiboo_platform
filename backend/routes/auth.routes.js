import express from 'express';
import { registerCtrl, loginCtrl, meCtrl, changePasswordCtrl } from '../controllers/auth.controller.js';
import { protect, authorize } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimiter.js';

const router = express.Router();

// Creating an account is an ADMIN action (Settings -> Users in the dashboard,
// or `npm run add-user` on the server). It used to be public and accepted a
// role, so anyone who found the login page could register themselves an admin.
router.post('/register', authLimiter, protect, authorize('admin'), registerCtrl);
router.post('/login', authLimiter, loginCtrl);
router.get('/me', protect, meCtrl);
router.post('/change-password', authLimiter, protect, changePasswordCtrl);

export default router;
