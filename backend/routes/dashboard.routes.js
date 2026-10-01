import express from 'express';
import { getKPIsCtrl } from '../controllers/dashboard.controller.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

router.get('/kpis', protect, getKPIsCtrl);

// GET /api/dashboard/services - is the optional camera (CV) service up?
// Checked from the backend so it works no matter which computer the
// dashboard is opened on (the browser used to call localhost:5050 itself).
router.get('/services', protect, async (req, res) => {
  const cvUrl = (process.env.CV_SERVICE_URL || 'http://localhost:5050').replace(/\/+$/, '');
  let cv = false;
  try {
    const r = await fetch(`${cvUrl}/health`, { signal: AbortSignal.timeout(2000) });
    cv = r.ok;
  } catch {
    cv = false;
  }
  res.json({ cv: { online: cv, url: cvUrl } });
});

export default router;