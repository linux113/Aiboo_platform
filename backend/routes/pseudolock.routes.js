// backend/routes/pseudolock.routes.js
// PseudoLock: pending approvals, multi-step playbooks and playbook runs.
// Everyone logged in may look; only admin / analyst may approve, run or edit.
//
//   GET    /api/pseudolock/catalog                 actions, variables, settings (for the editor)
//   GET    /api/pseudolock/approvals?status=pending|all|done,...
//   GET    /api/pseudolock/approvals/count         { pending }
//   POST   /api/pseudolock/approvals               ask for approval of one action
//   POST   /api/pseudolock/approvals/:id/approve   { note }
//   POST   /api/pseudolock/approvals/:id/reject    { note }
//   GET    /api/pseudolock/playbooks               built-in + your own
//   POST   /api/pseudolock/playbooks               create      (body from the editor)
//   PUT    /api/pseudolock/playbooks/:id           change
//   DELETE /api/pseudolock/playbooks/:id           delete
//   POST   /api/pseudolock/playbooks/:id/run       { endpoint, vars: {ip,user,pid,badge}, alertId }
//   GET    /api/pseudolock/runs                    recent runs
//   GET    /api/pseudolock/runs/:id
//   POST   /api/pseudolock/runs/:id/cancel
//   GET    /api/pseudolock/rules                   response rules, in the order they are checked
//   POST   /api/pseudolock/rules                   create      (body from the rule editor)
//   PUT    /api/pseudolock/rules/:id               change
//   POST   /api/pseudolock/rules/:id/enabled       { enabled }  (on / off switch)
//   DELETE /api/pseudolock/rules/:id
//   POST   /api/pseudolock/rules/reorder           { ids: [first, second, ...] }
//   POST   /api/pseudolock/rules/preview           rule body (+ days) -> old alerts it would have matched
//   GET    /api/pseudolock/rules/activity?ruleId=&limit=
import express from 'express';
import { getIO } from '../config/socket.js';
import { protect, authorize } from '../middleware/auth.js';
import logger from '../utils/logger.js';
import {
  catalog, listApprovals, pendingCount, createApproval, decideApproval, getApproval,
  listPlaybooks, getPlaybook, savePlaybook, deletePlaybook, startRun, listRuns, getRun, cancelRun,
  setPseudoLockEmitter, whoIs,
} from '../services/pseudolock.service.js';
import {
  rulesCatalog, listRules, getRule, saveRule, setRuleEnabled, deleteRule, reorderRules, previewRule, ruleActivity,
} from '../services/responseRules.service.js';

const router = express.Router();
const editors = authorize('admin', 'analyst');

setPseudoLockEmitter((ev, data) => {
  try { getIO().emit(ev, data); } catch { /* socket not started (tests) */ }
});

const handle = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) logger.error(`PseudoLock ${req.method} ${req.originalUrl}: ${err.stack || err.message}`);
    res.status(status).json({ ok: false, error: status >= 500 ? 'Server error - see backend log' : err.message, ...(err.errors ? { errors: err.errors } : {}) });
  }
};

router.get('/catalog', protect, handle(async (req, res) => res.json({ ...catalog(), rules: rulesCatalog() })));

// ---- approvals
router.get('/approvals', protect, handle(async (req, res) => {
  res.json(await listApprovals({ status: req.query.status || 'all', limit: req.query.limit }));
}));
router.get('/approvals/count', protect, handle(async (req, res) => res.json({ pending: await pendingCount() })));
router.get('/approvals/:id', protect, handle(async (req, res) => {
  const a = await getApproval(req.params.id);
  if (!a) return res.status(404).json({ ok: false, error: 'Approval not found' });
  res.json(a);
}));
router.post('/approvals', protect, editors, handle(async (req, res) => {
  const b = req.body || {};
  let r;
  try {
    r = await createApproval({
      action: b.action, target: b.target, params: b.params, endpoint: b.endpoint, reason: b.reason,
      alertId: b.alertId, expiresMinutes: b.expiresMinutes, origin: 'manual', requestedBy: whoIs(req.user),
      risk: b.risk, level: b.level,
    });
  } catch (err) { err.status = err.status || 400; throw err; }
  res.status(r.created ? 201 : 200).json(r.approval);
}));
router.post('/approvals/:id/approve', protect, editors, handle(async (req, res) => {
  res.json(await decideApproval(req.params.id, 'approve', req.user, req.body?.note));
}));
router.post('/approvals/:id/reject', protect, editors, handle(async (req, res) => {
  res.json(await decideApproval(req.params.id, 'reject', req.user, req.body?.note));
}));

// ---- playbooks
router.get('/playbooks', protect, handle(async (req, res) => res.json(await listPlaybooks())));
router.get('/playbooks/:id', protect, handle(async (req, res) => {
  const p = await getPlaybook(req.params.id);
  if (!p) return res.status(404).json({ ok: false, error: 'Playbook not found' });
  res.json(p);
}));
router.post('/playbooks', protect, editors, handle(async (req, res) => res.status(201).json(await savePlaybook(null, req.body, req.user))));
router.put('/playbooks/:id', protect, editors, handle(async (req, res) => res.json(await savePlaybook(req.params.id, req.body, req.user))));
router.delete('/playbooks/:id', protect, editors, handle(async (req, res) => {
  const users = (await listRules()).filter((r) => r.playbookId === req.params.id);
  if (users.length) return res.status(409).json({ ok: false, error: `Rule "${users[0].name}" uses this playbook - change or delete the rule first` });
  await deletePlaybook(req.params.id);
  res.json({ ok: true });
}));
router.post('/playbooks/:id/run', protect, editors, handle(async (req, res) => {
  const b = req.body || {};
  res.status(202).json(await startRun(req.params.id, { endpoint: b.endpoint, vars: b.vars, alertId: b.alertId }, req.user));
}));

// ---- runs
router.get('/runs', protect, handle(async (req, res) => res.json(await listRuns({ limit: req.query.limit, status: req.query.status }))));
router.get('/runs/:id', protect, handle(async (req, res) => {
  const r = await getRun(req.params.id);
  if (!r) return res.status(404).json({ ok: false, error: 'Run not found' });
  res.json(r);
}));
router.post('/runs/:id/cancel', protect, editors, handle(async (req, res) => res.json(await cancelRun(req.params.id, req.user))));

// ---- Response rules ("WHEN this happens -> THEN run this playbook") ----
router.get('/rules', protect, handle(async (req, res) => res.json(await listRules())));
router.get('/rules/activity', protect, handle(async (req, res) =>
  res.json(await ruleActivity({ limit: req.query.limit, ruleId: req.query.ruleId }))));
router.post('/rules/preview', protect, handle(async (req, res) => res.json(await previewRule(req.body, req.body?.days))));
router.post('/rules/reorder', protect, editors, handle(async (req, res) => res.json(await reorderRules(req.body?.ids))));
router.post('/rules', protect, editors, handle(async (req, res) => {
  const r = await saveRule(null, req.body, req.user);
  logger.info(`Response rule "${r.name}" created by ${whoIs(req.user)}`);
  res.status(201).json(r);
}));
router.get('/rules/:id', protect, handle(async (req, res) => {
  const r = await getRule(req.params.id);
  if (!r) return res.status(404).json({ message: 'Rule not found' });
  res.json(r);
}));
router.put('/rules/:id', protect, editors, handle(async (req, res) => res.json(await saveRule(req.params.id, req.body, req.user))));
router.post('/rules/:id/enabled', protect, editors, handle(async (req, res) =>
  res.json(await setRuleEnabled(req.params.id, req.body?.enabled, req.user))));
router.delete('/rules/:id', protect, editors, handle(async (req, res) => {
  await deleteRule(req.params.id);
  logger.info(`Response rule ${req.params.id} deleted by ${whoIs(req.user)}`);
  res.json({ ok: true });
}));

export default router;
