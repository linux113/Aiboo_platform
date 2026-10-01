// backend/routes/analytics.routes.js
// Executive dashboard, charts and security trends  (/api/analytics)
//   GET /overview?days=30&tz=Asia/Kolkata   KPIs, posture score, breakdowns, top lists, trend
//   GET /trends?days=30&tz=...              daily alert counts per severity + compliance score per day
import express from 'express';
import { protect } from '../middleware/auth.js';
import { buildAnalytics } from '../services/reportData.js';

const router = express.Router();
router.use(protect);

router.get('/overview', async (req, res) => {
  try {
    const { alerts, ...data } = await buildAnalytics({ days: req.query.days, tz: req.query.tz });
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

router.get('/trends', async (req, res) => {
  try {
    const a = await buildAnalytics({ days: req.query.days, tz: req.query.tz });
    res.json({ days: a.days, tz: a.tz, alerts: a.trend, compliance: a.compliance.trend });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

export default router;
