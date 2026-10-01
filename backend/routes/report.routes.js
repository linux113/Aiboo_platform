// backend/routes/report.routes.js
// Downloadable reports  (/api/reports)
//   GET /                          list of report types
//   GET /:type?format=pdf|csv|json&days=30&tz=Asia/Kolkata
//        type = risk | compliance | executive
import express from 'express';
import { protect } from '../middleware/auth.js';
import { buildAnalytics } from '../services/reportData.js';
import { REPORT_TYPES, toCsv, toPdf } from '../services/reportRender.js';
import logger from '../utils/logger.js';

const router = express.Router();
router.use(protect);

router.get('/', (req, res) => {
  res.json(Object.entries(REPORT_TYPES).map(([id, title]) => ({ id, title, formats: ['pdf', 'csv', 'json'] })));
});

router.get('/:type', async (req, res) => {
  const { type } = req.params;
  if (!REPORT_TYPES[type]) {
    return res.status(400).json({ ok: false, error: `type must be one of ${Object.keys(REPORT_TYPES).join(', ')}` });
  }
  const format = String(req.query.format || 'json').toLowerCase();
  if (!['pdf', 'csv', 'json'].includes(format)) {
    return res.status(400).json({ ok: false, error: 'format must be pdf, csv or json' });
  }
  try {
    const data = await buildAnalytics({ days: req.query.days, tz: req.query.tz });
    const stamp = new Date().toISOString().slice(0, 10);
    const name = `aiboo-${type}-report-${stamp}`;
    logger.info(`Report ${type}.${format} (${data.days} days) for ${req.user?.email || 'user'}`);
    if (format === 'json') {
      if (type === 'compliance') {
        const { alerts, ...rest } = data;
        return res.json({ type, ...rest });
      }
      return res.json({ type, ...data });
    }
    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${name}.csv"`);
      return res.send(toCsv(type, data));
    }
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${name}.pdf"`);
    return toPdf(type, data, res);
  } catch (err) {
    logger.error(`Report ${type} failed: ${err.message}`);
    if (!res.headersSent) return res.status(500).json({ ok: false, error: err.message });
    return res.end();
  }
});

export default router;
