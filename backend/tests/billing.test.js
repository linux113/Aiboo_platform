import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.JWT_SECRET = 'billing-test-jwt-secret';
process.env.RAZORPAY_KEY_ID = 'rzp_test_key';
process.env.RAZORPAY_KEY_SECRET = 'billing-test-secret';
process.env.RAZORPAY_WEBHOOK_SECRET = 'billing-webhook-secret';

const Organization = (await import('../models/Organization.js')).default;
const User = (await import('../models/User.js')).default;
const Plan = (await import('../models/Plan.js')).default;
const Subscription = (await import('../models/Subscription.js')).default;
const { signupCompany, verifyCheckoutPayment, processRazorpayWebhook } = await import('../services/billing.service.js');
const { requireOrganization } = await import('../middleware/tenant.js');

const docQuery = (value) => ({ select() { return this; }, then(resolve, reject) { return Promise.resolve(value).then(resolve, reject); } });
const responseStub = () => ({ code: 200, body: null, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });
const jsonResponse = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, async json() { return data; } });


test('signup remains pending until provider-confirmed capture; payment activates only the matching paid order', async () => {
  const previousFetch = globalThis.fetch;
  const previousApiBaseUrl = process.env.RAZORPAY_API_BASE_URL;
  process.env.RAZORPAY_API_BASE_URL = 'https://razorpay-test.invalid/api/v1/';
  let orderRequest;
  globalThis.fetch = async (url, options = {}) => {
    if (String(url).endsWith('/orders')) {
      orderRequest = { url: String(url), options };
      return jsonResponse({ id: 'order_test_123', amount: 50000, currency: 'INR' }, 200);
    }
    if (String(url).endsWith('/payments/pay_test_123')) {
      return jsonResponse({ id: 'pay_test_123', order_id: 'order_test_123', amount: 50000, currency: 'INR', status: 'captured' }, 200);
    }
    throw new Error(`Unexpected provider URL: ${url}`);
  };

  const organization = {
    _id: '650000000000000000000088', name: 'Example Co', billingEmail: 'owner@example.com',
    status: 'pending_payment', currentSubscription: null, subscriptionExpiresAt: null, isLegacy: false,
    async save() {},
  };
  const user = { _id: '650000000000000000000089', name: 'Owner', email: 'owner@example.com', role: 'admin' };
  const plan = { _id: '650000000000000000000090', code: 'basic', name: 'Basic', monthlyAmountPaise: 50000, yearlyAmountPaise: 500000 };
  const subscription = {
    _id: '650000000000000000000091', organization: organization._id, plan: plan._id, planCode: 'basic',
    billingCycle: 'monthly', status: 'pending_payment', providerOrderId: '', metadata: {}, lastPaymentId: '',
    async save() {},
  };

  Organization.exists = async () => false;
  Organization.create = async () => organization;
  Organization.findById = () => docQuery(organization);
  User.exists = async () => false;
  User.create = async () => user;
  Plan.findOne = () => docQuery(plan);
  Subscription.create = async () => subscription;
  Subscription.findOne = (query) => docQuery(query.providerOrderId ? subscription : null);

  try {
    const signup = await signupCompany({
      companyName: 'Example Co', name: 'Owner', email: 'owner@example.com', password: 'securePass123',
      planCode: 'basic', billingCycle: 'monthly',
    });
    assert.equal(signup.checkout.orderId, 'order_test_123');
    assert.equal(signup.checkout.amount, 50000);
    assert.equal(orderRequest.url, 'https://razorpay-test.invalid/api/v1/orders');
    assert.equal(organization.status, 'pending_payment');
    assert.equal(subscription.status, 'pending_payment');
    assert.equal(orderRequest.options.headers.Authorization, `Basic ${Buffer.from('rzp_test_key:billing-test-secret').toString('base64')}`);

    const signature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update('order_test_123|pay_test_123').digest('hex');
    const result = await verifyCheckoutPayment({
      organizationId: organization._id, orderId: 'order_test_123', paymentId: 'pay_test_123', signature,
    });
    assert.equal(result.ok, true);
    assert.equal(organization.status, 'active');
    assert.ok(organization.subscriptionExpiresAt > new Date());
    assert.equal(subscription.status, 'active');
    assert.equal(subscription.lastPaymentId, 'pay_test_123');
  } finally {
    globalThis.fetch = previousFetch;
    if (previousApiBaseUrl === undefined) delete process.env.RAZORPAY_API_BASE_URL;
    else process.env.RAZORPAY_API_BASE_URL = previousApiBaseUrl;
  }
});


test('paid tenant middleware blocks pending/expired workspaces and permits only current subscriptions or legacy', async () => {
  const originalFindById = Organization.findById;
  const orgId = '650000000000000000000099';
  const req = { user: { id: 'user', role: 'admin', organization: orgId, tenantVerified: true } };
  const expiredOrg = { _id: orgId, status: 'active', isLegacy: false, subscriptionExpiresAt: new Date(Date.now() - 1000) };
  Organization.findById = () => docQuery(expiredOrg);

  try {
    let calledNext = false;
    let res = responseStub();
    await requireOrganization(req, res, () => { calledNext = true; });
    assert.equal(calledNext, false);
    assert.equal(res.code, 402);

    const currentOrg = { ...expiredOrg, subscriptionExpiresAt: new Date(Date.now() + 86400000) };
    Organization.findById = () => docQuery(currentOrg);
    req.organization = undefined;
    calledNext = false;
    res = responseStub();
    await requireOrganization(req, res, () => { calledNext = true; });
    assert.equal(calledNext, true);

    Organization.findById = () => docQuery({ _id: orgId, status: 'legacy', isLegacy: true, subscriptionExpiresAt: null });
    req.organization = undefined;
    calledNext = false;
    res = responseStub();
    await requireOrganization(req, res, () => { calledNext = true; });
    assert.equal(calledNext, true);
  } finally {
    Organization.findById = originalFindById;
  }
});


test('webhook rejects a bad signature before processing payment data', async () => {
  await assert.rejects(
    processRazorpayWebhook({
      rawBody: Buffer.from('{"event":"payment.captured"}'),
      signature: 'not-a-valid-signature', eventId: 'evt_test_1', eventType: 'payment.captured', payload: {},
    }),
    /Invalid webhook signature/,
  );
});
