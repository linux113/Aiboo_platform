// backend/routes/alert.routes.js
// Alert Management API  (/api/alerts)
//   GET    /                 list + filter  (?status=open,acknowledged&severity=high&kind=trigate&q=&assignee=&days=30&sort=newest|severity|risk|oldest&page=&limit=)
//   GET    /:id              one alert with full history and notes
//   POST   /:id/acknowledge  { note? }
//   POST   /:id/assign       { assignee }      ('' = unassign)
//   POST   /:id/close        { reason: resolved|false_positive|duplicate|accepted_risk, note? }
//   POST   /:id/reopen       { note? }
//   POST   /:id/notes        { text }
//   POST   /bulk             { ids:[], action: acknowledge|close|assign, reason?, assignee?, note? }
// Everyone logged in can read; only admin / analyst can change alerts.
import express from 'express';
import { protect, authorize } from '../middleware/auth.js';
import {
  listAlerts, getAlert, changeStatus, assign, addNote, storageKind, CLOSE_REASONS,
} from '../services/alertStore.js';

const router = express.Router();
const canEdit = authorize('admin', 'analyst');

const wrap = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (err) {
    res.status(err.statusCode || 500).json({ ok: false, error: err.message || 'Internal error' });
  }
};

router.use(protect);

router.get('/', wrap(async (req, res) => {
  res.json(await listAlerts(req.query));
}));

router.get('/meta', (req, res) => {
  res.json({ storage: storageKind(), closeReasons: CLOSE_REASONS, statuses: ['open', 'acknowledged', 'closed'] });
});

router.post('/bulk', canEdit, wrap(async (req, res) => {
  const { ids, action, reason, assignee, note } = req.body || {};
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ ok: false, error: 'ids[] is required' });
  if (ids.length > 200) return res.status(400).json({ ok: false, error: 'At most 200 alerts at once' });
  const results = [];
  for (const id of ids.map(String)) {
    try {
      let doc;
      if (action === 'acknowledge') doc = await changeStatus(id, 'acknowledged', req.user, { note });
      else if (action === 'close') doc = await changeStatus(id, 'closed', req.user, { note, reason });
      else if (action === 'assign') doc = await assign(id, assignee ?? '', req.user);
      else return res.status(400).json({ ok: false, error: 'action must be acknowledge, close or assign' });
      results.push({ id, ok: true, status: doc.status });
    } catch (err) {
      results.push({ id, ok: false, error: err.message });
    }
  }
  res.json({ ok: true, updated: results.filter((r) => r.ok).length, results });
}));

router.get('/:id', wrap(async (req, res) => {
  const a = await getAlert(req.params.id);
  if (!a) return res.status(404).json({ ok: false, error: 'Alert not found' });
  res.json(a);
}));

router.post('/:id/acknowledge', canEdit, wrap(async (req, res) => {
  res.json(await changeStatus(req.params.id, 'acknowledged', req.user, { note: req.body?.note }));
}));

router.post('/:id/assign', canEdit, wrap(async (req, res) => {
  if (typeof req.body?.assignee !== 'string') return res.status(400).json({ ok: false, error: 'assignee (text) is required' });
  res.json(await assign(req.params.id, req.body.assignee, req.user));
}));

router.post('/:id/close', canEdit, wrap(async (req, res) => {
  const reason = String(req.body?.reason || 'resolved');
  res.json(await changeStatus(req.params.id, 'closed', req.user, { note: req.body?.note, reason }));
}));

router.post('/:id/reopen', canEdit, wrap(async (req, res) => {
  res.json(await changeStatus(req.params.id, 'open', req.user, { note: req.body?.note }));
}));

router.post('/:id/notes', canEdit, wrap(async (req, res) => {
  res.json(await addNote(req.params.id, req.body?.text, req.user));
}));

export default router;
