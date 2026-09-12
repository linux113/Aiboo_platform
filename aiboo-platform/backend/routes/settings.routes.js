import express from 'express';
import Setting from '../models/Setting.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

// Settings are per-user — require a real authenticated user (JWT), not a service key.
const requireUser = (req, res, next) => {
  if (!req.user?.id) return res.status(401).json({ message: 'User authentication required' });
  next();
};

// GET /api/settings — all sections for the logged-in user
router.get('/', protect, requireUser, async (req, res, next) => {
  try {
    const docs = await Setting.find({ userId: req.user.id }).lean();
    const out = {};
    docs.forEach((d) => { out[d.section] = d.data; });
    res.json(out);
  } catch (err) { next(err); }
});

// GET /api/settings/:section — one section
router.get('/:section', protect, requireUser, async (req, res, next) => {
  try {
    const doc = await Setting.findOne({ userId: req.user.id, section: req.params.section }).lean();
    res.json(doc ? doc.data : {});
  } catch (err) { next(err); }
});

// POST /api/settings/:section — upsert a section (frontend calls this for alerts/voice/etc.)
router.post('/:section', protect, requireUser, async (req, res, next) => {
  try {
    const { section } = req.params;
    const doc = await Setting.findOneAndUpdate(
      { userId: req.user.id, section },
      { userId: req.user.id, section, data: req.body || {} },
      { new: true, upsert: true, runValidators: true }
    );
    res.json({ ok: true, section, data: doc.data });
  } catch (err) { next(err); }
});

// PUT /api/settings/profile — profile upsert (frontend's save() calls this)
router.put('/profile', protect, requireUser, async (req, res, next) => {
  try {
    const doc = await Setting.findOneAndUpdate(
      { userId: req.user.id, section: 'profile' },
      { userId: req.user.id, section: 'profile', data: req.body || {} },
      { new: true, upsert: true, runValidators: true }
    );
    res.json({ ok: true, section: 'profile', data: doc.data });
  } catch (err) { next(err); }
});

export default router;
