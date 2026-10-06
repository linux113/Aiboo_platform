// User administration. Every route here is admin-only: an analyst or viewer
// must never be able to create an account or hand themselves a new role.
import express from 'express';
import { protect, authorize } from '../middleware/auth.js';
import {
  listUsers, register, updateUser, disableUser, ROLES,
} from '../services/auth.service.js';

const router = express.Router();

const fail = (res, err) => {
  const code = err.statusCode || 500;
  res.status(code).json({ message: err.message || 'User request failed' });
};

router.use(protect, authorize('admin'));

// GET /api/users - who can log in, and with which role
router.get('/', async (req, res) => {
  try {
    res.json({ users: await listUsers(), roles: ROLES });
  } catch (err) { fail(res, err); }
});

// POST /api/users - create an account (name, email, password, role)
router.post('/', async (req, res) => {
  try {
    const { user } = await register(req.body || {}, req.user);
    res.status(201).json({ ok: true, user });
  } catch (err) { fail(res, err); }
});

// PATCH /api/users/:id - change role, reset password, rename, enable/disable
router.patch('/:id', async (req, res) => {
  try {
    const user = await updateUser(req.params.id, req.body || {}, req.user);
    res.json({ ok: true, user });
  } catch (err) { fail(res, err); }
});

// DELETE /api/users/:id - soft delete (the account is disabled, not removed)
router.delete('/:id', async (req, res) => {
  try {
    const user = await disableUser(req.params.id, req.user);
    res.json({ ok: true, user, note: 'Account disabled (history is kept)' });
  } catch (err) { fail(res, err); }
});

export default router;
