import express from 'express';
import { protect, authorize } from '../middleware/auth.js';
import { requireBillingOrganization } from '../middleware/tenant.js';
import { authLimiter } from '../middleware/rateLimiter.js';
import logger from '../utils/logger.js';
import {
  listPublicPlans,
  signupCompany,
  createCheckout,
  verifyCheckoutPayment,
  processRazorpayWebhook,
  getBillingOverview,
} from '../services/billing.service.js';

const router = express.Router();
const handleError = (res, err, label) => {
  const status = err.statusCode || 500;
  if (status >= 500) logger.error(`${label}: ${err.stack || err.message}`);
  return res.status(status).json({ message: status >= 500 ? 'Billing request could not be completed.' : err.message });
};

// Public plan cards disclose only fields intended for prospective customers.
router.get('/plans', async (_req, res) => {
  try { res.json({ plans: await listPublicPlans() }); }
  catch (err) { handleError(res, err, 'List billing plans failed'); }
});

// Company self-signup: creates an inactive workspace; payment confirmation is
// the only path that marks it active.
router.post('/signup', authLimiter, async (req, res) => {
  try {
    const result = await signupCompany(req.body || {});
    res.status(201).json(result);
  } catch (err) { handleError(res, err, 'Company signup failed'); }
});

// Billing portal is available to authenticated company users even when the
// subscription is pending or expired. Only admins can initiate/verify charges.
router.get('/', protect, requireBillingOrganization, async (req, res) => {
  try { res.json(await getBillingOverview(req.organizationId)); }
  catch (err) { handleError(res, err, 'Billing overview failed'); }
});

router.post('/checkout', protect, requireBillingOrganization, authorize('admin'), async (req, res) => {
  try {
    const checkout = await createCheckout({
      organizationId: req.organizationId,
      email: req.user.email,
      planCode: req.body?.planCode,
      billingCycle: req.body?.billingCycle,
    });
    res.status(201).json(checkout);
  } catch (err) { handleError(res, err, 'Create billing checkout failed'); }
});

router.post('/verify', protect, requireBillingOrganization, authorize('admin'), async (req, res) => {
  try {
    const result = await verifyCheckoutPayment({
      organizationId: req.organizationId,
      orderId: req.body?.razorpay_order_id,
      paymentId: req.body?.razorpay_payment_id,
      signature: req.body?.razorpay_signature,
    });
    res.json(result);
  } catch (err) { handleError(res, err, 'Verify checkout payment failed'); }
});

// The server attaches the exact JSON request bytes before parsing. Razorpay
// retries are idempotent by event ID, and signatures are checked server-side.
router.post('/webhooks/razorpay', async (req, res) => {
  try {
    const result = await processRazorpayWebhook({
      rawBody: req.rawBody,
      signature: req.headers['x-razorpay-signature'],
      eventId: req.headers['x-razorpay-event-id'],
      eventType: req.body?.event,
      payload: req.body?.payload,
    });
    res.json(result);
  } catch (err) { handleError(res, err, 'Razorpay webhook failed'); }
});

export default router;
