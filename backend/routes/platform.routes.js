import express from 'express';
import { protect } from '../middleware/auth.js';
import { requireSuperAdmin } from '../middleware/tenant.js';
import Plan from '../models/Plan.js';

const router = express.Router();
router.use(protect, requireSuperAdmin);

router.get('/plans', async (_req, res, next) => {
  try {
    const plans = await Plan.find({}).sort({ code: 1 }).lean();
    res.json({ plans });
  } catch (err) { next(err); }
});

// Prices are stored in paise (₹1 = 100 paise). Tier limits/features remain
// fixed to the agreed package definitions; only a Super Admin can set prices.
router.put('/plans/:code/pricing', async (req, res, next) => {
  try {
    const patch = {};
    for (const cycle of ['monthly', 'yearly']) {
      if (!(cycle in (req.body || {}))) continue;
      const value = req.body[cycle];
      if (value !== null && (!Number.isSafeInteger(value) || value < 100 || value > 10000000000)) {
        return res.status(400).json({ message: `${cycle} must be null or a whole-number amount in paise from 100 to 10000000000.` });
      }
      patch[`${cycle}AmountPaise`] = value;
    }
    if (!Object.keys(patch).length) return res.status(400).json({ message: 'Set monthly and/or yearly pricing.' });
    const plan = await Plan.findOneAndUpdate(
      { code: req.params.code },
      { $set: patch },
      { new: true, runValidators: true },
    ).lean();
    if (!plan) return res.status(404).json({ message: 'Plan not found.' });
    res.json({ plan });
  } catch (err) { next(err); }
});

export default router;
